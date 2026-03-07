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
)

// State is the OCI runtime state — passed on stdin at createRuntime stage.
type State struct {
	Bundle string `json:"bundle"`
}

const hookLog = "/tmp/hook.log"

// Config is a partial OCI config.json — only the fields we inspect.
type Config struct {
	Annotations map[string]string `json:"annotations"`
	Process     struct {
		Args            []string `json:"args"`
		NoNewPrivileges *bool    `json:"noNewPrivileges"`
		Rlimits         []struct {
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
var requiredNamespaces = []string{"pid", "network", "ipc", "mount", "cgroup"}

// Sensitive paths that must stay masked (bind-mounted to /dev/null).
// Injected by seal-inject (precreate hook); validated here to catch
// --security-opt unmask=, unmask=ALL, or other stripping attempts.
var requiredMaskedPaths = []string{
	"/sys/kernel/debug",
	"/sys/kernel/tracing",
	"/sys/kernel/security",
	"/sys/kernel/vmcoreinfo",
	"/sys/fs/bpf",
	"/sys/module",
	"/sys/devices/virtual/dmi",
	"/proc/kallsyms",
	"/proc/kcore",
	"/proc/config.gz",
	"/proc/modules",
	"/proc/version",
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

// Podman infrastructure paths — overlay layers, resolv.conf, etc.
// Mounts from subdirectories of these are always allowed.
var infraMountPrefixes = []string{
	"/var/lib/containers/storage",
	"/var/run/containers/storage",
	"/var/cache/containers",
	"/run/credentials",
}

func logf(format string, args ...any) {
	f, err := os.OpenFile(hookLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format+"\n", args...)
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

func checkSeccomp(config Config) error {
	if config.Linux.Seccomp == nil {
		return blocked(int(syscall.EPERM), "seccomp=unconfined not permitted in nested containers")
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
		if workdir != "" && isSubPath(workdir, source) ||
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
			for _, denied := range deniedPropagation {
				if opt == denied {
					return blocked(int(syscall.EPERM),
						"mount propagation '%s' on '%s' not permitted in nested containers",
						opt, m.Destination,
					)
				}
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

		if workdir != "" && isSubPath(workdir, source) {
			continue
		}
		isInfra := false
		for _, prefix := range infraMountPrefixes {
			if isSubPath(prefix, source) {
				isInfra = true
				break
			}
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

func checkMaskedPaths(config Config) error {
	if len(config.Process.Args) == 0 || config.Process.Args[0] != "/.sandbox/seal" {
		return nil
	}
	present := make(map[string]bool, len(config.Linux.MaskedPaths))
	for _, p := range config.Linux.MaskedPaths {
		present[p] = true
	}
	for _, required := range requiredMaskedPaths {
		if !present[required] {
			return blocked(int(syscall.EPERM),
				"masked path '%s' was removed — unmask not permitted in nested containers",
				required,
			)
		}
	}
	return nil
}

func checkDevices(config Config) error {
	if len(config.Linux.Devices) > 0 {
		return blocked(int(syscall.EACCES), "device access not permitted in nested containers")
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

	checks := []func(Config) error{
		checkCaps,
		checkSeccomp,
		checkNoNewPrivileges,
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
	}
	for _, check := range checks {
		err = check(config)
		if err != nil {
			var pv *policyError
			if !errors.As(err, &pv) {
				logf("check error: %v", err)
				os.Exit(1)
			}
			logf("BLOCKED: %s", pv.Msg)
			os.Exit(pv.Code)
		}
	}
}
