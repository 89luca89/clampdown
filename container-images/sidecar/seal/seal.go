// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// policy matches the JSON written by the security-policy OCI hook.
//
// Four filesystem access tiers, from least to most permissive:
//   - read_only:     read files + list dirs. No execute.
//   - read_exec:     read_only + execute files. For binary/library dirs.
//   - write_noexec:  read_only + write/delete/create. No execute, no device nodes.
//   - write_exec:    write_noexec + execute + cross-dir rename. For workdir.
//
// connect_tcp: allowed outbound TCP ports.
//   - Non-empty: restrict to listed ports (V4+).
//   - Empty/nil: don't restrict TCP (no network domain created).
type policy struct {
	ReadExec    []string `json:"read_exec"`
	ReadOnly    []string `json:"read_only"`
	WriteNoExec []string `json:"write_noexec"`
	WriteExec   []string `json:"write_exec"`
	ConnectTCP  []uint16 `json:"connect_tcp"`
}

const policyEnv = "SANDBOX_POLICY"

// Landlock access sets — each tier grants a specific combination of rights.
// MakeChar and MakeBlock are excluded from all write tiers: nested
// containers never need to create device nodes.
//
// Directory and file access sets are separate because Landlock rejects
// directory-only rights (ReadDir, RemoveDir, MakeDir, etc.) on file paths.
const (
	// Directory access sets.
	accessReadOnly = llsyscall.AccessFSReadFile |
		llsyscall.AccessFSReadDir

	accessReadExec = accessReadOnly |
		llsyscall.AccessFSExecute

	accessWriteNoExec = accessReadOnly |
		llsyscall.AccessFSWriteFile |
		llsyscall.AccessFSRemoveDir |
		llsyscall.AccessFSRemoveFile |
		llsyscall.AccessFSMakeDir |
		llsyscall.AccessFSMakeReg |
		llsyscall.AccessFSMakeSock |
		llsyscall.AccessFSMakeFifo |
		llsyscall.AccessFSMakeSym |
		llsyscall.AccessFSTruncate |
		llsyscall.AccessFSIoctlDev

	accessWriteExec = accessWriteNoExec |
		llsyscall.AccessFSExecute

	// File-only access sets — no dir operations.
	accessFileReadOnly  = llsyscall.AccessFSReadFile
	accessFileReadExec  = accessFileReadOnly | llsyscall.AccessFSExecute
	accessFileWriteOnly = accessFileReadOnly |
		llsyscall.AccessFSWriteFile |
		llsyscall.AccessFSTruncate |
		llsyscall.AccessFSIoctlDev
	accessFileWriteExec = accessFileWriteOnly |
		llsyscall.AccessFSExecute
)

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sandbox-seal: "+format+"\n", args...)
	os.Exit(1)
}

func loadPolicy() policy {
	data := os.Getenv(policyEnv)
	if data == "" {
		fatalf("SANDBOX_POLICY not set — refusing to start without policy")
	}
	var p policy
	err := json.Unmarshal([]byte(data), &p)
	if err != nil {
		fatalf("bad SANDBOX_POLICY: %v", err)
	}
	return p
}

// cleanEnv returns os.Environ() with SANDBOX_POLICY stripped.
// Only SANDBOX_POLICY is removed — it carries the Landlock policy JSON
// that was already consumed. Other env vars (including other SANDBOX_*
// keys like SANDBOX_SESSION) are preserved for the child process.
func cleanEnv() []string {
	var out []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "SANDBOX_POLICY=") {
			out = append(out, e)
		}
	}
	return out
}

// splitPaths partitions paths into directories and regular files.
// Missing paths go into dirs (IgnoreIfMissing handles them).
func splitPaths(paths []string) (dirs, files []string) {
	for _, p := range paths {
		info, err := os.Lstat(p)
		if err != nil {
			dirs = append(dirs, p) // missing — IgnoreIfMissing will skip
			continue
		}
		if info.IsDir() {
			dirs = append(dirs, p)
		} else {
			files = append(files, p)
		}
	}
	return dirs, files
}

func applyLandlock(p policy) error {
	// Hard-fail if Landlock is unavailable or too old. BestEffort degrades
	// individual features silently, but running without filesystem access
	// control at all is a security regression we must not allow.
	//
	// Minimum: ABI V3 (kernel 6.2+). Provides:
	//   V1: filesystem access control (the core defense)
	//   V2: Refer (prevents EXDEV across rule boundaries)
	//   V3: Truncate
	// V4+ (TCP connect, IoctlDev, IPC scoping) degrade via BestEffort.
	abi, err := llsyscall.LandlockGetABIVersion()
	if err != nil {
		return fmt.Errorf("Landlock not available (kernel < 5.13) — refusing to run without filesystem access control")
	}
	if abi < 3 {
		return fmt.Errorf("Landlock ABI V%d too old (need V%d+, kernel 6.2+) — refusing to run without Refer and Truncate support", abi, 3)
	}

	var fsRules []landlock.Rule

	// Filesystem rules. Each tier is split into dir and file paths
	// because Landlock rejects directory-only access rights on files.
	// Refer is added via WithRefer(), not in the bitmask — so BestEffort
	// doesn't downgrade the entire rule to "do nothing" on V1 kernels.
	// All tiers get Refer to prevent spurious EXDEV when renames cross
	// Landlock rule boundaries (e.g., overlay rootfs ↔ bind mount).
	// ReadOnly+Refer is safe: rename still needs RemoveFile on the
	// source, which ReadOnly doesn't grant.
	if len(p.ReadOnly) > 0 {
		dirs, files := splitPaths(p.ReadOnly)
		if len(dirs) > 0 {
			fsRules = append(fsRules,
				landlock.PathAccess(landlock.AccessFSSet(accessReadOnly), dirs...).IgnoreIfMissing().WithRefer())
		}
		if len(files) > 0 {
			fsRules = append(fsRules,
				landlock.PathAccess(landlock.AccessFSSet(accessFileReadOnly), files...).IgnoreIfMissing())
		}
	}
	if len(p.ReadExec) > 0 {
		dirs, files := splitPaths(p.ReadExec)
		if len(dirs) > 0 {
			fsRules = append(fsRules,
				landlock.PathAccess(landlock.AccessFSSet(accessReadExec), dirs...).IgnoreIfMissing().WithRefer())
		}
		if len(files) > 0 {
			fsRules = append(fsRules,
				landlock.PathAccess(landlock.AccessFSSet(accessFileReadExec), files...).IgnoreIfMissing())
		}
	}
	if len(p.WriteNoExec) > 0 {
		dirs, files := splitPaths(p.WriteNoExec)
		if len(dirs) > 0 {
			fsRules = append(fsRules,
				landlock.PathAccess(landlock.AccessFSSet(accessWriteNoExec), dirs...).IgnoreIfMissing().WithRefer())
		}
		if len(files) > 0 {
			fsRules = append(fsRules,
				landlock.PathAccess(landlock.AccessFSSet(accessFileWriteOnly), files...).IgnoreIfMissing())
		}
	}
	if len(p.WriteExec) > 0 {
		dirs, files := splitPaths(p.WriteExec)
		if len(dirs) > 0 {
			fsRules = append(fsRules,
				landlock.PathAccess(landlock.AccessFSSet(accessWriteExec), dirs...).IgnoreIfMissing().WithRefer())
		}
		if len(files) > 0 {
			fsRules = append(fsRules,
				landlock.PathAccess(landlock.AccessFSSet(accessFileWriteExec), files...).IgnoreIfMissing())
		}
	}

	// V7 config — BestEffort degrades gracefully on older kernels.
	// Each Restrict* call creates a layered Landlock domain; the
	// kernel intersects all layers.
	//
	// The first Restrict* call also sets prctl(PR_SET_NO_NEW_PRIVS, 1)
	// — setuid bits and file capabilities are ignored on exec. Irrevocable.
	// Prevents SUID/setcap escalation, CVE-2023-0386 (OverlayFS SUID smuggling).
	cfg := landlock.V7.BestEffort().
		DisableLoggingForOriginatingProcess().
		EnableLoggingForSubprocesses()

	// Filesystem (V1+).
	err = cfg.RestrictPaths(fsRules...)
	if err != nil {
		return fmt.Errorf("restrict paths: %w", err)
	}

	// IPC scoping (V6+): blocks abstract unix socket connections and
	// signals to processes outside this Landlock domain.
	err = cfg.RestrictScoped()
	if err != nil {
		return fmt.Errorf("restrict scoped: %w", err)
	}

	// TCP connect (V4+) — only when ports are listed. Empty means
	// "don't restrict TCP" (no network domain created, avoids
	// denying all connect).
	if len(p.ConnectTCP) > 0 {
		var netRules []landlock.Rule
		for _, port := range p.ConnectTCP {
			netRules = append(netRules, landlock.ConnectTCP(port))
		}
		err = cfg.RestrictNet(netRules...)
		if err != nil {
			return fmt.Errorf("restrict net: %w", err)
		}
	}

	return nil
}

// closeExtraFDs marks all file descriptors >= 3 as close-on-exec.
// The kernel closes them atomically during syscall.Exec — not before,
// so Go's runtime (epoll FD, signal pipe, etc.) stays intact until
// the process image is replaced.
// Eliminates leaked runtime FDs (CVE-2024-21626 class) from reaching
// the child process.
func closeExtraFDs() {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd < 3 {
			continue
		}
		syscall.CloseOnExec(fd)
	}
}

func main() {
	// Parse args: sandbox-seal -- <command> [args...]
	// podman --init passes: /dev/init -- <original-entrypoint> [args...]
	args := os.Args[1:]
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || sep >= len(args)-1 {
		fatalf("usage: sandbox-seal -- <command> [args...]")
	}
	command := args[sep+1:]

	p := loadPolicy()

	err := applyLandlock(p)
	if err != nil {
		fatalf("landlock: %v", err)
	}

	binary, err := exec.LookPath(command[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox-seal: %v\n", err)
		os.Exit(127)
	}

	// Close all file descriptors >= 3 before exec. Prevents leaked
	// runtime FDs (CVE-2024-21626 class) from reaching the child process.
	closeExtraFDs()

	err = syscall.Exec(binary, command, cleanEnv())
	fatalf("exec %s: %v", binary, err)
}
