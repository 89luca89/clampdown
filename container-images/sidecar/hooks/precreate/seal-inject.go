// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// precreate hook: reads OCI config from stdin, injects sandbox-seal as
// the entrypoint wrapper, derives and injects Landlock policy as an env
// var, writes modified config to stdout.

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
	ConnectTCP  []uint16 `json:"connect_tcp,omitempty"`
	BindTCP     []uint16 `json:"bind_tcp,omitempty"`
}

type mount struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Type        string   `json:"type,omitempty"`
	Options     []string `json:"options,omitempty"`
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

// deniedGids are supplementary groups that grant privileged access.
var deniedGids = map[uint32]string{
	0:  "root",
	10: "wheel",
	27: "sudo",
}

var infraMountPrefixes = []string{
	"/var/lib/containers/storage",
	"/var/run/containers/storage",
	"/var/cache/containers",
}

// logf writes to the sidecar's PID 1 stderr so output appears in
// `podman logs <sidecar>` on the host. Hook stderr is captured by
// crun into a pipe and never reaches the container log stream.
func logf(format string, args ...any) {
	msg := fmt.Sprintf("clampdown: %s seal-inject: "+format+"\n",
		append([]any{time.Now().UTC().Format(time.RFC3339)}, args...)...)
	f, err := os.OpenFile("/proc/1/fd/2", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		fmt.Fprint(os.Stderr, msg)
		return
	}
	defer f.Close()
	fmt.Fprint(f, msg)
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
	return slices.Contains(opts, name)
}

// filterAdditionalGids removes privileged supplementary groups.
func filterAdditionalGids(gids []uint32) []uint32 {
	filtered := make([]uint32, 0, len(gids))
	for _, g := range gids {
		name, denied := deniedGids[g]
		if denied {
			logf("WARN: filtering supplementary group %d (%s) from additionalGids", g, name)
			continue
		}
		filtered = append(filtered, g)
	}
	return filtered
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
			"/opt",
			"/.sandbox",
		},
		ReadOnly: []string{"/"},
		// Common scratch paths — writable regardless of mount config.
		// These live on the overlay rootfs (covered by ReadOnly on "/")
		// but containers need to write to them for normal operation.
		// More specific rules override the ReadOnly on "/".
		WriteNoExec: []string{
			"/dev", "/proc",
			"/run",
			"/var/log", "/var/cache", "/var/lib",
		},
		// Home and temp dirs need write+exec: build tools install and
		// run binaries from ~/.local/bin, ~/.cargo/bin, etc. Compilers
		// (Go, GCC, Haskell, Nim, R) execute intermediate files from
		// $TMPDIR which defaults to /tmp.
		WriteExec: []string{"/home", "/tmp", "/var/tmp"},
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
	if readErr != nil {
		logf("FATAL: cannot read /run/sandbox/uid: %v", readErr)
		os.Exit(1)
	}
	uidStr := strings.TrimSpace(string(uidBytes))
	var user map[string]json.RawMessage
	if process["user"] != nil {
		err = json.Unmarshal(process["user"], &user)
		if err != nil {
			logf("seal-inject: parse process.user: %v", err)
			os.Exit(1)
		}
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

	if user["additionalGids"] != nil {
		var additionalGids []uint32
		err = json.Unmarshal(user["additionalGids"], &additionalGids)
		if err != nil {
			logf("seal-inject: parse additionalGids: %v", err)
			os.Exit(1)
		}
		user["additionalGids"], _ = json.Marshal(filterAdditionalGids(additionalGids))
	}
	process["user"], _ = json.Marshal(user)

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

	// Ensure the original entrypoint is executable under Landlock.
	if len(args) > 2 {
		entrypoint := args[2] // args[0]="/.sandbox/seal", args[1]="--", args[2]=original
		if filepath.IsAbs(entrypoint) {
			policy.ReadExec = append(policy.ReadExec, entrypoint)
		}
	}

	policyJSON, _ := json.Marshal(policy)

	var env []string
	if process["env"] != nil {
		err = json.Unmarshal(process["env"], &env)
		if err != nil {
			logf("seal-inject: parse process: %v", err)
			os.Exit(1)
		}
	}

	// Filter any existing SANDBOX_POLICY to prevent user override.
	env = slices.DeleteFunc(env, func(e string) bool {
		return strings.HasPrefix(e, policyEnv+"=")
	})
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

	// Resolve symlinks in bind mount sources so crun and createRuntime
	// see the same resolved path — eliminates the TOCTOU window where
	// a symlink target could change between hook check and mount time.
	for i, raw := range rawMounts {
		var m mount
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		if m.Type != "bind" || !strings.HasPrefix(m.Source, "/") {
			continue
		}
		resolved, resolveErr := filepath.EvalSymlinks(m.Source)
		if resolveErr != nil || resolved == m.Source {
			continue
		}
		m.Source = resolved
		rawMounts[i], _ = json.Marshal(m)
	}

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
		logf("marshal: %v", err)
		os.Exit(1)
	}

	// Log successful injection with container name and policy summary.
	var name string
	if config["hostname"] != nil {
		_ = json.Unmarshal(config["hostname"], &name)
	}
	logf("PASS: name=%s write_exec=%v connect_tcp=%v bind_tcp=%v",
		name, policy.WriteExec, policy.ConnectTCP, policy.BindTCP)

	os.Stdout.Write(output)
}
