// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// State is the OCI runtime state — passed on stdin at createRuntime stage.
type State struct {
	ID     string `json:"id"`
	Bundle string `json:"bundle"`
}

// Config is a partial OCI config.json — only the fields we inspect.
type Config struct {
	Hostname    string            `json:"hostname"`
	Annotations map[string]string `json:"annotations"`
	Process     struct {
		Args            []string `json:"args"`
		NoNewPrivileges *bool    `json:"noNewPrivileges"`
		User            struct {
			AdditionalGids []uint32 `json:"additionalGids"`
		} `json:"user"`
		Rlimits []struct {
			Type string `json:"type"`
			Hard uint64 `json:"hard"`
		} `json:"rlimits"`
		Capabilities struct {
			Bounding    []string `json:"bounding"`
			Effective   []string `json:"effective"`
			Inheritable []string `json:"inheritable"`
			Permitted   []string `json:"permitted"`
			Ambient     []string `json:"ambient"`
		} `json:"capabilities"`
	} `json:"process"`
	Linux struct {
		Namespaces []struct {
			Type string `json:"type"`
			Path string `json:"path"`
		} `json:"namespaces"`
		Devices []struct {
			Path string `json:"path"`
		} `json:"devices"`
		Seccomp           *json.RawMessage  `json:"seccomp"`
		MaskedPaths       []string          `json:"maskedPaths"`
		ReadonlyPaths     []string          `json:"readonlyPaths"`
		Sysctl            map[string]string `json:"sysctl"`
		RootfsPropagation string            `json:"rootfsPropagation"`
	} `json:"linux"`
	Mounts []struct {
		Source      string   `json:"source"`
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Options     []string `json:"options"`
	} `json:"mounts"`
}

// policyError is returned by check functions when a container
// violates security policy. Code is the errno to exit with.
type policyError struct {
	Code int
	Msg  string
}

func (e *policyError) Error() string { return e.Msg }

// we enforce unprivileged containers, blocking all dangerous capabilities.
var deniedCaps = []string{
	"CAP_AUDIT_CONTROL",
	"CAP_BPF",
	"CAP_DAC_READ_SEARCH",
	"CAP_LINUX_IMMUTABLE",
	"CAP_MAC_ADMIN",
	"CAP_MAC_OVERRIDE",
	"CAP_MKNOD",
	"CAP_NET_ADMIN",
	"CAP_NET_RAW",
	"CAP_PERFMON",
	"CAP_SYS_ADMIN",
	"CAP_SYS_BOOT",
	"CAP_SYS_CHROOT",
	"CAP_SYS_MODULE",
	"CAP_SYS_PTRACE",
	"CAP_SYS_RAWIO",
	"CAP_SYS_RESOURCE",
	"CAP_SYS_TIME",
}

// and we require containers to not use un-namespaced resources.
var requiredNamespaces = []string{"pid", "network", "ipc", "mount", "cgroup", "uts"}

// Sensitive /proc and /sys paths that must be hidden from containers.
// Primary enforcement is containers.conf volumes on the sidecar's read-only
// rootfs: /dev/null for files, /empty for directories.
// This applies uniformly to both podman run and podman build.
// The agent cannot override these because:
//   - The sidecar rootfs is read-only (containers.conf can't be modified).
//   - CONTAINERS_CONF env can't be set (agent doesn't control sidecar env).
//   - An explicit -v at the same destination replaces one mask with another
//     (the real procfs/sysfs entry remains underneath, inaccessible).
//     and mounts outside of workdir are blocked.
//   - --security-opt unmask= only affects OCI maskedPaths, not bind volumes.
//
// checkMaskedPaths validates defense-in-depth: each path must be covered by
// either OCI maskedPaths OR a /dev/null or /.empty bind mount in the spec.
var requiredMaskedPaths = []string{
	"/proc/cmdline",
	"/proc/kallsyms",
	"/proc/kcore",
	"/proc/modules",
	"/proc/sysrq-trigger",
	"/proc/version",
	"/sys/devices/virtual/dmi",
	"/sys/fs/bpf",
	"/sys/kernel/debug",
	"/sys/kernel/security",
	"/sys/kernel/tracing",
	"/sys/kernel/vmcoreinfo",
	"/sys/module",
}

// /proc/sysrq-trigger is in readonlyPaths, not maskedPaths. maskedPaths
// bind-mounts /dev/null which is a device node — writes bypass the ro mount
// flag. readonlyPaths bind-mounts the real proc entry read-only, which does
// block writes.
var requiredReadonlyPaths = []string{
	"/proc/bus",
	"/proc/fs",
	"/proc/irq",
	"/proc/sys",
	"/proc/sysrq-trigger",
}

var deniedPropagation = []string{"shared", "rshared", "slave", "rslave"}

// infraMountPrefixes lists paths always allowed as bind mount sources.
// %CID% is replaced with the container ID from the OCI state in main().
var infraMountPrefixes = []string{
	"/var/lib/containers/storage/overlay-containers/%CID%",
	"/var/run/containers/storage/overlay-containers/%CID%",
	"/var/cache/containers",
	"/run/credentials",
	"/dev/null",
	"/empty",
}

// isValidVolumeMount checks if a source path is a valid named volume data dir.
// Accepts /var/lib/containers/storage/volumes/<name>/_data (and subpaths).
// Rejects the volumes root, traversal attempts, and anything not matching
// the <name>/_data structure.
func isValidVolumeMount(source string) bool {
	const prefix = "/var/lib/containers/storage/volumes/"
	source = filepath.Clean(source)
	if !strings.HasPrefix(source, prefix) {
		return false
	}
	rel := strings.TrimPrefix(source, prefix)
	parts := strings.SplitN(rel, "/", 3)
	if len(parts) < 2 {
		return false
	}
	if parts[0] == "" || parts[0] == "." || parts[0] == ".." {
		return false
	}
	return parts[1] == "_data"
}

// logf writes to the sidecar's PID 1 stderr so output appears in
// `podman logs <sidecar>` on the host. Hook stderr is captured by
// crun into a pipe and never reaches the container log stream.
func logf(format string, args ...any) {
	msg := fmt.Sprintf("clampdown: %s security-policy: "+format+"\n",
		append([]any{time.Now().UTC().Format(time.RFC3339)}, args...)...)
	f, err := os.OpenFile("/proc/1/fd/2", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		fmt.Fprint(os.Stderr, msg)
		return
	}
	defer f.Close()
	fmt.Fprint(f, msg)
}

func blocked(code int, format string, args ...any) *policyError {
	return &policyError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

func isSubPath(base, path string) bool {
	rel, err := filepath.Rel(base, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func hasOpt(opts []string, name string) bool {
	return slices.Contains(opts, name)
}

func parseState(data []byte) (State, error) {
	var s State
	err := json.Unmarshal(data, &s)
	return s, err
}

func parseConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	err = json.Unmarshal(raw, &c)
	return c, err
}

func checkCaps(config Config) error {
	caps := make(map[string]bool)
	for _, list := range [][]string{
		config.Process.Capabilities.Bounding,
		config.Process.Capabilities.Effective,
		config.Process.Capabilities.Inheritable,
		config.Process.Capabilities.Permitted,
		config.Process.Capabilities.Ambient,
	} {
		for _, c := range list {
			caps[c] = true
		}
	}
	for _, denied := range deniedCaps {
		if caps[denied] {
			return blocked(int(syscall.EPERM), "%s not permitted in nested containers", denied)
		}
	}
	return nil
}

// clampdownSeccompPath is the path to the clampdown seccomp profile.
// Overridable in tests.
var clampdownSeccompPath = "/etc/containers/seccomp_nested.json"

// seccompRule represents a single syscall rule for comparison.
// Two rules match if they have the same action, sorted names, and args.
type seccompRule struct {
	Names    []string     `json:"names"`
	Action   string       `json:"action"`
	ErrnoRet *uint        `json:"errnoRet,omitempty"`
	Args     []seccompArg `json:"args,omitempty"`
}

type seccompArg struct {
	Index    uint32 `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo"`
	Op       string `json:"op"`
}

type seccompProfile struct {
	DefaultAction string        `json:"defaultAction"`
	Syscalls      []seccompRule `json:"syscalls"`
}

// seccompRuleKey returns a canonical string key for a rule.
// The OCI translation strips comments but preserves names, action,
// errnoRet, and args unchanged.
func seccompRuleKey(r seccompRule) string {
	names := make([]string, len(r.Names))
	copy(names, r.Names)
	slices.Sort(names)
	data, _ := json.Marshal(struct {
		Names    []string     `json:"n"`
		Action   string       `json:"a"`
		ErrnoRet *uint        `json:"e,omitempty"`
		Args     []seccompArg `json:"r,omitempty"`
	}{names, r.Action, r.ErrnoRet, r.Args})
	return string(data)
}

func checkSeccomp(config Config) error {
	if config.Linux.Seccomp == nil {
		return blocked(int(syscall.EPERM), "seccomp=unconfined not permitted in nested containers")
	}

	clampdownData, err := os.ReadFile(clampdownSeccompPath)
	if err != nil {
		return blocked(int(syscall.EPERM), "cannot read clampdown seccomp profile: %v", err)
	}
	var clampdownProfile seccompProfile
	err = json.Unmarshal(clampdownData, &clampdownProfile)
	if err != nil {
		return blocked(int(syscall.EPERM), "cannot parse clampdown seccomp profile: %v", err)
	}

	var containerProfile seccompProfile
	err = json.Unmarshal(*config.Linux.Seccomp, &containerProfile)
	if err != nil {
		return blocked(int(syscall.EPERM), "invalid seccomp profile: %v", err)
	}

	if containerProfile.DefaultAction != clampdownProfile.DefaultAction {
		return blocked(int(syscall.EPERM),
			"seccomp defaultAction '%s' does not match clampdown profile '%s'",
			containerProfile.DefaultAction, clampdownProfile.DefaultAction)
	}

	requiredRules := make(map[string]bool, len(clampdownProfile.Syscalls))
	deniedSyscalls := make(map[string]bool)
	for _, rule := range clampdownProfile.Syscalls {
		if len(rule.Names) == 0 {
			continue
		}
		requiredRules[seccompRuleKey(rule)] = true
		if rule.Action == "SCMP_ACT_ALLOW" {
			continue
		}
		for _, syscallName := range rule.Names {
			deniedSyscalls[syscallName] = true
		}
	}

	for _, rule := range containerProfile.Syscalls {
		if len(rule.Names) == 0 {
			continue
		}
		ruleKey := seccompRuleKey(rule)
		if requiredRules[ruleKey] {
			delete(requiredRules, ruleKey)
			continue
		}
		if rule.Action != "SCMP_ACT_ALLOW" {
			continue
		}
		for _, syscallName := range rule.Names {
			if deniedSyscalls[syscallName] {
				return blocked(int(syscall.EPERM),
					"seccomp profile contains extra ALLOW rule for syscall '%s' denied by the clampdown profile",
					syscallName)
			}
		}
	}

	if len(requiredRules) > 0 {
		return blocked(int(syscall.EPERM),
			"seccomp profile is missing %d rules from the clampdown profile: custom profiles not permitted",
			len(requiredRules))
	}

	return nil
}

func checkNamespaces(config Config) error {
	nsTypes := make(map[string]bool)
	nsPaths := make(map[string]string)
	for _, ns := range config.Linux.Namespaces {
		nsTypes[ns.Type] = true
		if ns.Path != "" {
			nsPaths[ns.Type] = ns.Path
		}
	}
	for _, required := range requiredNamespaces {
		if !nsTypes[required] {
			return blocked(
				int(syscall.EOPNOTSUPP),
				"namespace '%s' must be isolated (--%s=host not permitted)",
				required, required,
			)
		}
		nsPath, joined := nsPaths[required]
		if joined {
			resolved := nsPath
			r, resolveErr := filepath.EvalSymlinks(nsPath)
			if resolveErr == nil {
				resolved = r
			}
			if isSubPath("/proc", resolved) || isSubPath("/proc", nsPath) {
				return blocked(
					int(syscall.EOPNOTSUPP),
					"namespace '%s' must not join a process namespace (path '%s' not permitted)",
					required, nsPath,
				)
			}
		}
	}
	return nil
}

func checkMounts(config Config) error {
	workdir := os.Getenv("SANDBOX_WORKDIR")

	for _, m := range config.Mounts {
		source := m.Source
		if !strings.HasPrefix(source, "/") {
			continue
		}
		resolved, resolveErr := filepath.EvalSymlinks(source)
		if resolveErr == nil {
			source = resolved
		}
		if isSubPath(workdir, source) ||
			source == "/sandbox-seal" || source == "/rename_exdev_shim.so" {
			continue
		}
		allowed := false
		for _, prefix := range infraMountPrefixes {
			if isSubPath(prefix, source) {
				allowed = true
				break
			}
		}
		if !allowed && isValidVolumeMount(source) {
			allowed = true
		}
		if !allowed {
			return blocked(
				int(syscall.EACCES),
				"mount of '%s' not permitted in nested containers (not under workdir)",
				source,
			)
		}
	}
	return nil
}

func checkImageRef(config Config) error {
	mode := os.Getenv("SANDBOX_REQUIRE_DIGEST")
	if mode == "" {
		mode = "block"
	}

	ref := config.Annotations["io.containers.rawImageName"]
	if ref == "" {
		logf("image-ref: annotation io.containers.rawImageName not found, skipping check")
		return nil
	}

	if strings.Contains(ref, "@sha256:") || strings.Contains(ref, "@sha384:") || strings.Contains(ref, "@sha512:") {
		return nil
	}

	if mode == "block" {
		return blocked(
			int(syscall.EACCES),
			"tag-only image reference '%s' not permitted — use @sha256:DIGEST (pull by tag, then inspect digest)",
			ref,
		)
	}
	logf("image-ref: WARNING tag-only reference '%s' — consider pinning by digest", ref)
	return nil
}

func checkNoNewPrivileges(config Config) error {
	if config.Process.NoNewPrivileges != nil && !*config.Process.NoNewPrivileges {
		return blocked(int(syscall.EPERM), "no_new_privileges=false not permitted in nested containers")
	}
	return nil
}

// checkMACDisabled blocks containers that disable Mandatory Access Control.
func checkMACDisabled(config Config) error {
	labelOpt := config.Annotations["io.podman.annotations.label"]
	if labelOpt == "disable" {
		return blocked(int(syscall.EPERM),
			"--security-opt label=disable not permitted in nested containers")
	}
	apparmorOpt := config.Annotations["io.podman.annotations.apparmor"]
	if apparmorOpt == "unconfined" {
		return blocked(int(syscall.EPERM),
			"--security-opt apparmor=unconfined not permitted in nested containers")
	}
	return nil
}

func checkReadonlyPaths(config Config) error {
	if len(config.Process.Args) == 0 || config.Process.Args[0] != "/.sandbox/seal" {
		return nil
	}
	present := make(map[string]bool, len(config.Linux.ReadonlyPaths))
	for _, p := range config.Linux.ReadonlyPaths {
		present[p] = true
	}
	for _, required := range requiredReadonlyPaths {
		if !present[required] {
			return blocked(int(syscall.EPERM),
				"readonly path '%s' was removed — unmask not permitted in nested containers",
				required,
			)
		}
	}
	return nil
}

func checkSysctl(config Config) error {
	for key := range config.Linux.Sysctl {
		// net.* sysctls are namespace-scoped (kernel enforces per-netns).
		// checkNamespaces mandates network namespace isolation, so these
		// only affect the container's own network stack.
		// Everything else (kernel.*, vm.*, fs.*) is blocked — CVE-2022-0811.
		if strings.HasPrefix(key, "net.") {
			continue
		}
		return blocked(int(syscall.EPERM), "sysctl '%s' not permitted in nested containers", key)
	}
	return nil
}

func checkMountPropagation(config Config) error {
	for _, m := range config.Mounts {
		for _, opt := range m.Options {
			if slices.Contains(deniedPropagation, opt) {
				return blocked(int(syscall.EPERM),
					"mount propagation '%s' on '%s' not permitted in nested containers",
					opt, m.Destination,
				)
			}
		}
	}
	return nil
}

func checkRootfsPropagation(config Config) error {
	prop := config.Linux.RootfsPropagation
	if prop == "" || prop == "private" || prop == "rprivate" {
		return nil
	}
	return blocked(int(syscall.EPERM),
		"rootfsPropagation '%s' not permitted in nested containers (must be private or rprivate)",
		prop,
	)
}

var runtimeMountDests = map[string]bool{
	"/etc/resolv.conf":   true,
	"/etc/hostname":      true,
	"/etc/hosts":         true,
	"/run/.containerenv": true,
	"/dev/console":       true,
}

func checkMountOptions(config Config) error {
	workdir := os.Getenv("SANDBOX_WORKDIR")
	for _, m := range config.Mounts {
		if !strings.HasPrefix(m.Source, "/") {
			continue
		}
		if runtimeMountDests[m.Destination] {
			continue
		}
		if strings.HasPrefix(m.Destination, "/dev/") {
			continue
		}
		source := m.Source
		resolved, symErr := filepath.EvalSymlinks(source)
		if symErr == nil {
			source = resolved
		}
		if source == "/sandbox-seal" || source == "/rename_exdev_shim.so" {
			continue
		}

		if isSubPath(workdir, source) {
			continue
		}
		isInfra := false
		for _, prefix := range infraMountPrefixes {
			if isSubPath(prefix, source) {
				isInfra = true
				break
			}
		}
		if !isInfra && isValidVolumeMount(source) {
			isInfra = true
		}
		if isInfra {
			continue
		}
		if hasOpt(m.Options, "ro") {
			continue
		}
		if !hasOpt(m.Options, "nosuid") {
			return blocked(int(syscall.EACCES),
				"writable mount '%s' missing nosuid — not permitted in nested containers",
				m.Destination,
			)
		}
		if !hasOpt(m.Options, "nodev") {
			return blocked(int(syscall.EACCES),
				"writable mount '%s' missing nodev — not permitted in nested containers",
				m.Destination,
			)
		}
	}
	return nil
}

func checkRlimits(config Config) error {
	for _, rl := range config.Process.Rlimits {
		if rl.Type == "RLIMIT_CORE" && rl.Hard > 0 {
			return blocked(int(syscall.EPERM),
				"RLIMIT_CORE hard limit must be 0 in nested containers (got %d)",
				rl.Hard,
			)
		}
	}
	return nil
}

// checkProcMount validates that /proc is mounted as procfs (type "proc"),
// not as a bind mount. A malicious image could ship /proc as a symlink;
// if the runtime bind-mounts instead of mounting procfs, path-based
// security checks on /proc entries can be bypassed (CVE-2023-28642).
func checkProcMount(config Config) error {
	for _, m := range config.Mounts {
		if m.Destination != "/proc" {
			continue
		}
		if m.Type != "proc" {
			return blocked(int(syscall.EPERM),
				"/proc mount type is '%s', must be 'proc' (bind-mounted /proc not permitted)",
				m.Type,
			)
		}
		return nil
	}
	return nil // no /proc mount in spec — runtime may add it later
}

// allowedGids are the default supplementary groups podman assigns to
// containers from /etc/group (root, bin, daemon, sys, adm, tty, disk,
// lp, mem, kmem, wheel, cdrom, mail, man, dialout, floppy, games,
// tape, video, ftp, lock, audio, nobody, users, utmp, utempter, input,
// kvm, render, sgx, systemd-journal). Only the numeric GIDs that appear
// in the default OCI config are allowed. This blocks supplementary
// group escalation (CVE-2022-2989, CVE-2022-2990) where unexpected
// groups could grant access to files in overlay storage.
var allowedGids = map[uint32]bool{
	0: true, 1: true, 2: true, 3: true, 4: true,
	6: true, 10: true, 11: true, 20: true, 26: true, 27: true,
}

// checkAdditionalGids validates that supplementary groups in the OCI
// config are within the allowed set. Rejects containers requesting
// unexpected groups that could grant unintended file access.
func checkAdditionalGids(config Config) error {
	for _, gid := range config.Process.User.AdditionalGids {
		if !allowedGids[gid] {
			return blocked(int(syscall.EPERM),
				"supplementary group %d not in allowed set — unexpected groups not permitted in nested containers",
				gid,
			)
		}
	}
	return nil
}

// checkMaskedPaths verifies that every required sensitive path is hidden
// by either OCI maskedPaths or a read-only bind mount whose source is
// /dev/null (for files) or an empty directory (for dirs).
// containers.conf volumes are the primary mechanism; this check is defense-in-depth.
func checkMaskedPaths(config Config) error {
	covered := make(map[string]bool, len(config.Linux.MaskedPaths))
	for _, p := range config.Linux.MaskedPaths {
		covered[p] = true
	}

	for _, m := range config.Mounts {
		if !hasOpt(m.Options, "ro") {
			continue
		}
		if isDevNull(m.Source) || isEmptyDir(m.Source) {
			covered[m.Destination] = true
		}
	}

	for _, required := range requiredMaskedPaths {
		if !covered[required] {
			return blocked(int(syscall.EPERM),
				"sensitive path '%s' is neither in maskedPaths nor covered by a /dev/null or empty-dir bind mount",
				required,
			)
		}
	}
	return nil
}

// isDevNull returns true if path is /dev/null or a bind-mount of it
func isDevNull(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	// Character device check: mode has S_IFCHR set.
	if st.Mode&syscall.S_IFCHR == 0 {
		return false
	}
	// /dev/null is major 1, minor 3.
	major := (st.Rdev >> 8) & 0xff
	minor := st.Rdev & 0xff
	return major == 1 && minor == 3
}

// isEmptyDir returns true if path is an empty directory.
func isEmptyDir(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || !fi.IsDir() {
		return false
	}
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) == 0
}

func checkDevices(config Config) error {
	if len(config.Linux.Devices) > 0 {
		return blocked(int(syscall.EACCES), "device access not permitted in nested containers")
	}
	return nil
}

// checkMountReadonly blocks RW bind mounts whose source falls on or under
// a read-only mount point in the sidecar. This prevents nested containers
// from re-mounting protected paths (e.g., .git/hooks, .envrc) as writable
// by explicitly passing -v source:dest without :ro.
func checkMountReadonly(config Config) error {
	roMounts := parseMountInfo("/proc/self/mountinfo", os.Getenv("SANDBOX_WORKDIR"))
	return verifyMountReadonly(config, roMounts)
}

// parseMountInfo reads a mountinfo file and returns the set of mount points
// that are read-only and under the workdir. Only workdir sub-mounts represent
// protected paths (e.g., .git/hooks, .envrc). Mounts outside workdir are
// forbidden anyway.
func parseMountInfo(path, workdir string) map[string]bool {
	data, err := os.ReadFile(path)
	if err != nil {
		logf("parseMountInfo: %v", err)
		return nil
	}
	ro := make(map[string]bool)
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mountpoint := fields[4]
		if !isSubPath(workdir, mountpoint) || mountpoint == workdir {
			continue
		}
		opts := fields[5]
		for opt := range strings.SplitSeq(opts, ",") {
			if opt == "ro" {
				ro[mountpoint] = true
				break
			}
		}
	}
	return ro
}

func verifyMountReadonly(config Config, roMounts map[string]bool) error {
	for _, m := range config.Mounts {
		if !strings.HasPrefix(m.Source, "/") {
			continue
		}

		// RO is ok, harmless
		if hasOpt(m.Options, "ro") {
			continue
		}
		source := m.Source
		resolved, symErr := filepath.EvalSymlinks(source)
		if symErr == nil {
			source = resolved
		}
		for roPath := range roMounts {
			if isSubPath(roPath, source) {
				return blocked(int(syscall.EACCES),
					"mount of '%s' not permitted as writable — path is read-only in sidecar (protected by '%s')",
					m.Source, roPath,
				)
			}
		}
	}
	return nil
}

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		logf("read state: %v", err)
		os.Exit(int(syscall.EINVAL))
	}

	state, err := parseState(data)
	if err != nil {
		logf("parse state: %v", err)
		os.Exit(int(syscall.EINVAL))
	}

	config, err := parseConfig(state.Bundle + "/config.json")
	if err != nil {
		logf("read/parse config: %v", err)
		os.Exit(int(syscall.ENOENT))
	}

	if os.Getenv("SANDBOX_WORKDIR") == "" {
		logf("SANDBOX_WORKDIR not set — cannot enforce policy")
		os.Exit(int(syscall.EINVAL))
	}

	cid := state.ID
	if len(cid) > 12 {
		cid = cid[:12]
	}
	name := config.Hostname
	image := config.Annotations["org.opencontainers.image.ref.name"]
	if image == "" {
		image = "-"
	}
	cmd := "-"
	if len(config.Process.Args) > 0 {
		cmd = strings.Join(config.Process.Args, " ")
	}

	// Resolve %CID% placeholder in infraMountPrefixes so only THIS
	// container's runtime plumbing (resolv.conf, hosts, etc.) is allowed.
	for i, p := range infraMountPrefixes {
		infraMountPrefixes[i] = strings.ReplaceAll(p, "%CID%", state.ID)
	}

	checks := []func(Config) error{
		checkCaps,
		checkSeccomp,
		checkNoNewPrivileges,
		checkMACDisabled,
		checkNamespaces,
		checkMounts,
		checkMountOptions,
		checkMountPropagation,
		checkRootfsPropagation,
		checkDevices,
		checkMaskedPaths,
		checkReadonlyPaths,
		checkSysctl,
		checkRlimits,
		checkImageRef,
		checkMountReadonly,
		checkProcMount,
		checkAdditionalGids,
	}
	for _, check := range checks {
		err = check(config)
		if err != nil {
			var pv *policyError
			if !errors.As(err, &pv) {
				logf("check error: %v", err)
				os.Exit(1)
			}
			logf("BLOCKED: container=%s name=%s image=%s cmd=%q %s", cid, name, image, cmd, pv.Msg)
			os.Exit(pv.Code)
		}
	}

	logf("PASS: container=%s name=%s image=%s cmd=%q checks=%d", cid, name, image, cmd, len(checks))
}
