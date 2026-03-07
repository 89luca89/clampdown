// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// precreate hook: reads OCI config from stdin, injects sandbox-seal as
// the entrypoint wrapper, derives and injects Landlock policy as an env
// var, writes modified config to stdout.

const hookLog = "/tmp/hook.log"

const (
	sealBinary = "/sandbox-seal"
	sealDest   = "/.sandbox/seal"
	policyEnv  = "SANDBOX_POLICY"
)

type landlockPolicy struct {
	ReadExec    []string `json:"read_exec"`
	ReadOnly    []string `json:"read_only"`
	WriteNoExec []string `json:"write_noexec"`
	WriteExec   []string `json:"write_exec"`
	ConnectTCP []uint16 `json:"connect_tcp"`
}

type mount struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Type        string   `json:"type,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// Sensitive /sys subtrees to mask in nested containers. The OCI runtime
// replaces these with empty tmpfs mounts, preventing information disclosure.
// Landlock exempts sysfs — mount-level masking is the only option.
//   - /sys/kernel/debug: kernel debugfs (ftrace, kprobes, memory state).
//   - /sys/kernel/tracing: ftrace tracing interface.
//   - /sys/kernel/security: LSM policy files (AppArmor, SELinux, Landlock).
//   - /sys/fs/bpf: pinned eBPF maps/programs (CVE-2021-3490 class).
//   - /sys/module: loaded kernel module parameters.
//   - /sys/devices/virtual/dmi: hardware fingerprint (DMI/SMBIOS data).
var sysMaskedPaths = []string{
	"/sys/kernel/debug",
	"/sys/kernel/tracing",
	"/sys/kernel/security",
	"/sys/kernel/vmcoreinfo",
	"/sys/fs/bpf",
	"/sys/module",
	"/sys/devices/virtual/dmi",
}

// procMaskedPaths are sensitive /proc paths masked to prevent info disclosure
// that aids kernel exploit development (KASLR bypass, module enumeration).
//
// /proc/sysrq-trigger is intentionally NOT listed here. maskedPaths bind-mounts
// /dev/null over the path, and writes to device nodes bypass the ro mount flag
// (kernel routes writes to the device driver, not the filesystem). The default
// OCI readonlyPaths already includes /proc/sysrq-trigger, which bind-mounts
// the real proc entry read-only — that DOES block writes.
var procMaskedPaths = []string{
	"/proc/kallsyms",  // Kernel symbol addresses (KASLR bypass).
	"/proc/kcore",     // Physical memory in ELF format.
	"/proc/config.gz", // Kernel configuration (reveals security feature status).
	"/proc/modules",   // Loaded kernel modules (attack surface enumeration).
	"/proc/version",   // Kernel version string (fingerprinting for exploit selection).
}

// credentialSpecs defines opt-in host credential forwarding. The launcher
// mounts credentials into the sidecar at /run/credentials/*. For each spec,
// if the source exists in the sidecar filesystem, a read-only bind mount
// and optional env var are injected into the nested container.
var credentialSpecs = []struct {
	source string // path in sidecar
	dest   string // path in nested container
	env    string // env var name ("" if none)
	envVal string // env var value
}{
	{"/run/credentials/gitconfig", "/etc/gitconfig", "", ""},
	{"/run/credentials/gh", "/run/credentials/gh", "GH_CONFIG_DIR", "/run/credentials/gh"},
	{"/run/credentials/ssh-agent.sock", "/run/ssh-agent.sock", "SSH_AUTH_SOCK", "/run/ssh-agent.sock"},
}

var infraMountPrefixes = []string{
	"/var/lib/containers/storage",
	"/var/run/containers/storage",
	"/var/cache/containers",
}


func logf(format string, args ...any) {
	f, err := os.OpenFile(hookLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format+"\n", args...)
}

func isSubPath(base, path string) bool {
	rel, err := filepath.Rel(base, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// Runtime plumbing paths injected by podman/crun — not user mounts.
var runtimeMountDests = map[string]bool{
	"/etc/resolv.conf":   true,
	"/etc/hostname":      true,
	"/etc/hosts":         true,
	"/run/.containerenv": true,
}

// isInfraMount returns true for podman infrastructure bind mounts
// (overlay storage, runtime plumbing) that aren't user-provided.
func isInfraMount(m mount) bool {
	if runtimeMountDests[m.Destination] {
		return true
	}
	source := m.Source
	resolved, err := filepath.EvalSymlinks(source)
	if err == nil {
		source = resolved
	}
	for _, prefix := range infraMountPrefixes {
		if isSubPath(prefix, source) {
			return true
		}
	}
	return false
}

func hasOption(opts []string, name string) bool {
	for _, o := range opts {
		if o == name {
			return true
		}
	}
	return false
}

func derivePolicy(mounts []mount) landlockPolicy {
	policy := landlockPolicy{
		// Standard binary/library dirs — always read+exec.
		// /.sandbox holds injected binaries (rename shim .so) that
		// the dynamic linker needs to mmap(PROT_EXEC) via LD_PRELOAD.
		ReadExec: []string{
			"/bin", "/sbin",
			"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64",
			"/usr/libexec", "/usr/local",
			"/lib", "/lib64",
			"/.sandbox",
		},
		ReadOnly: []string{"/"},
		// Common scratch paths — writable regardless of mount config.
		// These live on the overlay rootfs (covered by ReadOnly on "/")
		// but containers need to write to them for normal operation.
		// More specific rules override the ReadOnly on "/".
		WriteNoExec: []string{
			"/dev", "/proc",
			"/tmp", "/var/tmp",
			"/run",
			"/var/log", "/var/cache", "/var/lib",
		},
		// Home dirs need write+exec: build tools install and run
		// binaries from ~/.local/bin, ~/.cargo/bin, etc.
		WriteExec: []string{"/home"},
	}

	for _, m := range mounts {
		// Type mounts (proc, sysfs, tmpfs, devtmpfs) use non-absolute
		// sources. Landlock can't restrict pseudo-filesystems anyway.
		if !strings.HasPrefix(m.Source, "/") {
			// tmpfs mounts have type "tmpfs" and absolute destinations.
			// Classify by options.
			if m.Type == "tmpfs" {
				if hasOption(m.Options, "noexec") {
					policy.WriteNoExec = append(policy.WriteNoExec, m.Destination)
				} else {
					policy.WriteExec = append(policy.WriteExec, m.Destination)
				}
			}
			continue
		}
		if m.Source == sealBinary {
			continue
		}
		if isInfraMount(m) {
			continue
		}

		// User bind mount — classify by OCI mount options.
		ro := hasOption(m.Options, "ro")
		noexec := hasOption(m.Options, "noexec")
		switch {
		case ro:
			// Read-only bind mounts are already covered by
			// ReadOnly on "/". Skip to avoid duplicates.
		case noexec:
			policy.WriteNoExec = append(policy.WriteNoExec, m.Destination)
		default:
			policy.WriteExec = append(policy.WriteExec, m.Destination)
		}
	}

	return policy
}

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		logf("seal-inject: read stdin: %v", err)
		os.Exit(1)
	}

	// Preserve all fields — only touch process.args, process.env, mounts.
	var config map[string]json.RawMessage
	err = json.Unmarshal(input, &config)
	if err != nil {
		logf("seal-inject: parse config: %v", err)
		os.Exit(1)
	}

	var process map[string]json.RawMessage
	err = json.Unmarshal(config["process"], &process)
	if err != nil {
		logf("seal-inject: parse process: %v", err)
		os.Exit(1)
	}

	// Enforce non-root user. UID/GID are written by the entrypoint
	// to /run/sandbox/ (hooks don't inherit the sidecar's env vars).
	// Build containers (podman build / buildah) skip precreate hooks
	// entirely, so this only affects `podman run` containers.
	uidBytes, readErr := os.ReadFile("/run/sandbox/uid")
	if readErr == nil {
		uidStr := strings.TrimSpace(string(uidBytes))
		var user map[string]json.RawMessage
		if process["user"] != nil {
			_ = json.Unmarshal(process["user"], &user)
		}
		if user == nil {
			user = make(map[string]json.RawMessage)
		}
		uid, uidErr := strconv.Atoi(uidStr)
		if uidErr != nil || uid == 0 {
			logf("seal-inject: invalid uid %q from /run/sandbox/uid", uidStr)
			os.Exit(1)
		}
		user["uid"], _ = json.Marshal(uid)
		gidStr := uidStr
		gidBytes, gidErr := os.ReadFile("/run/sandbox/gid")
		if gidErr == nil {
			gidStr = strings.TrimSpace(string(gidBytes))
		}
		gid, gidParseErr := strconv.Atoi(gidStr)
		if gidParseErr != nil {
			logf("seal-inject: invalid gid %q from /run/sandbox/gid", gidStr)
			os.Exit(1)
		}
		user["gid"], _ = json.Marshal(gid)
		process["user"], _ = json.Marshal(user)
	}

	// Prepend seal to process.args.
	var args []string

	err = json.Unmarshal(process["args"], &args)
	if err != nil {
		logf("seal-inject: parse process: %v", err)
		os.Exit(1)
	}

	args = append([]string{sealDest, "--"}, args...)
	process["args"], _ = json.Marshal(args)

	// Parse mounts for policy derivation.
	var mounts []mount

	err = json.Unmarshal(config["mounts"], &mounts)
	if err != nil {
		logf("seal-inject: parse process: %v", err)
		os.Exit(1)
	}

	// Derive policy and inject as env var.
	policy := derivePolicy(mounts)
	policyJSON, _ := json.Marshal(policy)

	var env []string
	if process["env"] != nil {
		err = json.Unmarshal(process["env"], &env)
		if err != nil {
			logf("seal-inject: parse process: %v", err)
			os.Exit(1)
		}
	}
	env = append(env, policyEnv+"="+string(policyJSON))

	// Add seal bind mount. Re-read raw mounts to preserve all fields.
	var rawMounts []json.RawMessage

	err = json.Unmarshal(config["mounts"], &rawMounts)
	if err != nil {
		logf("seal-inject: parse process: %v", err)
		os.Exit(1)
	}

	// Add hidepid=2 to proc mounts so nested container processes can
	// only see their own /proc/[pid] entries. Blocks /proc-based info
	// disclosure of conmon, crun, and other runtime processes.
	for i, raw := range rawMounts {
		var m mount
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		if m.Type != "proc" {
			continue
		}
		if !hasOption(m.Options, "hidepid=2") {
			m.Options = append(m.Options, "hidepid=2")
			rawMounts[i], _ = json.Marshal(m)
		}
	}

	// Mask sensitive /sys subtrees. Landlock exempts sysfs, so OCI
	// maskedPaths (empty tmpfs overlays) is the only enforcement path.
	var linux map[string]json.RawMessage
	if config["linux"] != nil {
		_ = json.Unmarshal(config["linux"], &linux)
	}
	if linux == nil {
		linux = make(map[string]json.RawMessage)
	}
	var maskedPaths []string
	if linux["maskedPaths"] != nil {
		_ = json.Unmarshal(linux["maskedPaths"], &maskedPaths)
	}
	maskedPaths = append(maskedPaths, sysMaskedPaths...)
	maskedPaths = append(maskedPaths, procMaskedPaths...)
	linux["maskedPaths"], _ = json.Marshal(maskedPaths)
	config["linux"], _ = json.Marshal(linux)

	sealMount, _ := json.Marshal(mount{
		Source:      sealBinary,
		Destination: sealDest,
		Type:        "bind",
		Options:     []string{"bind", "ro", "nosuid", "nodev"},
	})
	rawMounts = append(rawMounts, json.RawMessage(sealMount))

	// Inject opt-in host credentials. Presence-based: if the sidecar
	// has the credential mounted at /run/credentials/*, forward it
	// into the nested container with appropriate env vars.
	envSeen := make(map[string]bool)
	for _, ig := range credentialSpecs {
		_, statErr := os.Stat(ig.source)
		if statErr != nil {
			continue
		}
		igMount, _ := json.Marshal(mount{
			Source:      ig.source,
			Destination: ig.dest,
			Type:        "bind",
			Options:     []string{"bind", "ro", "nosuid", "nodev"},
		})
		rawMounts = append(rawMounts, json.RawMessage(igMount))
		if ig.env != "" && !envSeen[ig.env] {
			env = append(env, ig.env+"="+ig.envVal)
			envSeen[ig.env] = true
		}
	}
	process["env"], _ = json.Marshal(env)
	config["process"], _ = json.Marshal(process)
	config["mounts"], _ = json.Marshal(rawMounts)

	output, err := json.Marshal(config)
	if err != nil {
		logf("seal-inject: marshal: %v", err)
		os.Exit(1)
	}

	os.Stdout.Write(output)
}
