// SPDX-License-Identifier: GPL-3.0-only

// All seccomp-notif handler functions. Each handles one or more syscall
// numbers dispatched by the supervisor loop in supervisor.go.

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// IPT_SO_SET_REPLACE is the setsockopt optname for replacing iptables
// rules. Not exported by golang.org/x/sys/unix. Same value for IPv4
// (IPT_SO_SET_REPLACE) and IPv6 (IP6T_SO_SET_REPLACE).
const iptSOSetReplace = 64

// allowedBindSources lists path prefixes from which bind mount sources
// are permitted.
var allowedBindSources = []string{
	// infra mounts for namespace setup
	"/proc/self",
	"/proc/thread-self",
	"/run/user/0",
	"/run/netns",
	"/dev/char",
	"/dev/pts",
	// infra mounts for container storage, cache, logs
	"/run/containers",
	"/var/cache/containers",
	"/var/lib/containers/storage",
	"/var/run/containers/storage",
	// buildah staging dirs for podman build
	"/var/tmp",
	// credential forwarding
	"/run/credentials",
}

// allowedBindSourceFiles lists individual rootfs files that may be
// bind-mounted into nested containers.
var allowedBindSourceFiles = []string{
	"/dev/full",
	"/dev/null",
	"/dev/random",
	"/dev/tty",
	"/dev/urandom",
	"/dev/zero",
	"/empty",
	"/rename_exdev_shim.so",
	"/sandbox-seal",
}

// isAllowedBindSource checks whether a bind mount source is permitted.
func isAllowedBindSource(source, workdir string) bool {
	if source == "" {
		return true
	}

	if workdir != "" && isSubPath(workdir, source) {
		return true
	}

	for _, prefix := range allowedBindSources {
		if isSubPath(prefix, source) {
			return true
		}
	}

	return slices.Contains(allowedBindSourceFiles, source)
}

// allowedFsTypes lists filesystem types permitted for non-bind mounts
// from the sidecar PID namespace. crun only uses these types during
// container setup.
var allowedFsTypes = map[string]bool{
	"cgroup2": true,
	"devpts":  true,
	"mqueue":  true,
	"none":    true,
	"overlay": true,
	"sysfs":   true,
	"tmpfs":   true,
}

// procSuperMagic is the f_type returned by statfs(2) for procfs.
const procSuperMagic = 0x9fa0

// procSensitive lists procfs paths the supervisor blocks at openat.
var procSensitive = []string{
	// /proc/1/* (sidecar PID NS, any access)
	"/proc/1/auxv",
	"/proc/1/cwd",
	"/proc/1/environ",
	"/proc/1/exe",
	"/proc/1/io",
	"/proc/1/maps",
	"/proc/1/mem",
	"/proc/1/pagemap",
	"/proc/1/root",
	"/proc/1/stack",
	"/proc/1/syscall",
	// Host-affecting kernel control files (any context, write only)
	"/proc/sysrq-trigger",
	"/proc/sys/kernel/core_pattern",
	"/proc/sys/kernel/core_uses_pid",
	"/proc/sys/kernel/hotplug",
	"/proc/sys/kernel/modprobe",
	"/proc/sys/kernel/sysrq",
	"/proc/sys/kernel/unprivileged_userns_clone",
	"/proc/sys/fs/binfmt_misc/register",
	"/proc/sys/vm/drop_caches",
	"/proc/sys/vm/panic_on_oom",
	"/proc/sys/net/core/bpf_jit_enable",
	"/proc/sys/net/core/bpf_jit_harden",
	"/proc/sys/net/core/bpf_jit_kallsyms",
}

// ---------------------------------------------------------------------------
// Mount-family handlers
// ---------------------------------------------------------------------------

// handleProtectedPathOp blocks a syscall if its path argument resolves to
// a protected mount point. Used for umount2, mount_setattr, move_mount,
// unlinkat, and symlinkat — all share the pattern: read one path arg,
// resolve it, block if protected.
func handleProtectedPathOp(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	protected map[string]bool,
	notifFD int,
	argIdx int,
	errCode int32,
	name string,
) {
	raw, err := readStringFromPID(pid, notif.Data.Args[argIdx])
	if err != nil {
		resp.Error = -syscallErrno(err)
		logf("BLOCKED %s: cannot read path pid=%d: %v", name, pid, err)
		return
	}
	path := resolvePath(raw, pid)

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if isProtected(path, protected) {
		resp.Error = -errCode
		logf("BLOCKED %s path=%s pid=%d bin=%s", name, path, pid, exePath(pid))
	} else {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	}
}

// handleMount applies policy to all mount() calls.
// mount(source, target, fstype, flags, data):
//
//	arg0 = source, arg1 = target, arg2 = fstype, arg3 = flags.
//
// Policy:
//   - Target is a protected/masked path -> BLOCK (prevents overlay/remount)
//   - MS_BIND without MS_REC and source contains the workdir -> BLOCK
//     (prevents non-recursive bind that strips /dev/null sub-mounts)
//   - Procfs mount from sidecar PID namespace -> BLOCK
//     (prevents mounting new procfs to access /proc/1/mem)
//   - Otherwise -> ALLOW
func handleMount(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	protected map[string]bool,
	workdir, myPIDNS string,
	notifFD int,
) {
	target, err := readStringFromPID(pid, notif.Data.Args[1])
	if err != nil {
		resp.Error = -syscallErrno(err)
		logf("BLOCKED mount: cannot read target pid=%d: %v", pid, err)
		return
	}
	target = resolvePath(target, pid)

	flags := notif.Data.Args[3]

	// For bind mounts, also read the source.
	var source string
	if flags&unix.MS_BIND != 0 {
		source, err = readStringFromPID(pid, notif.Data.Args[0])
		if err != nil {
			resp.Error = -syscallErrno(err)
			logf("BLOCKED mount: cannot read source pid=%d: %v", pid, err)
			return
		}
		source = resolvePath(source, pid)
	}

	// Read filesystem type for procfs check (arg2, may be NULL for bind/remount).
	var fstype string
	if notif.Data.Args[2] != 0 {
		fstype, err = readStringFromPID(pid, notif.Data.Args[2])
		if err != nil {
			resp.Error = -syscallErrno(err)
			logf("BLOCKED mount: cannot read fstype pid=%d: %v", pid, err)
			return
		}
	}

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	// Block any mount targeting a protected path (overlay, remount, tmpfs, bind over it).
	if isProtected(target, protected) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED mount target=%s pid=%d flags=0x%x bin=%s", target, pid, flags, exePath(pid))
		return
	}

	// Block bind mounts from disallowed sources. This is the syscall-level
	// equivalent of the OCI hook's checkMounts()
	if flags&unix.MS_BIND != 0 && flags&unix.MS_REMOUNT == 0 && !isAllowedBindSource(source, workdir) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED mount(MS_BIND) source=%s target=%s pid=%d bin=%s (source not allowed)",
			source, target, pid, exePath(pid))
		return
	}

	// Block non-recursive bind mount where the source is the workdir, an
	// ancestor, or a child of it. A non-recursive bind of any path that
	// overlaps the workdir doesn't carry /dev/null sub-mounts, exposing
	// masked files.
	if workdir != "" && flags&unix.MS_BIND != 0 && flags&unix.MS_REC == 0 && source != "" {
		if source == workdir || isSubPath(source, workdir) || isSubPath(workdir, source) {
			resp.Error = -int32(unix.EPERM)
			logf(
				"BLOCKED mount(MS_BIND) source=%s target=%s pid=%d bin=%s (non-recursive workdir bind)",
				source,
				target,
				pid,
				exePath(pid),
			)
			return
		}
	}

	// Block non-bind mounts with disallowed filesystem types from the
	// sidecar PID namespace.
	if fstype != "" && flags&unix.MS_BIND == 0 && flags&unix.MS_REMOUNT == 0 &&
		isSidecarPIDNS(pid, myPIDNS) && !allowedFsTypes[fstype] {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED mount(fstype=%s) target=%s pid=%d bin=%s (fstype not allowed)",
			fstype, target, pid, exePath(pid))
		return
	}

	resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

// handleOpenTree blocks non-recursive open_tree clones of the workdir
// or any ancestor. open_tree(dirfd, path, flags): arg1 = path, arg2 = flags.
// A non-recursive OPEN_TREE_CLONE strips sub-mounts (like non-recursive bind),
// exposing masked file contents at the detached mount.
//
// Recursive clones and clones of non-workdir paths are allowed — crun uses
// open_tree(CLONE) from the sidecar PID NS for bind mount preparation
// (get_bind_mount in prepare_and_send_mount_mounts).
func handleOpenTree(notif *seccompNotif, resp *seccompNotifResp, pid uint32, workdir string, notifFD int) {
	flags := notif.Data.Args[2]

	// Non-clone open_tree is harmless — just an O_PATH open.
	// Recursive clones preserve sub-mounts — safe.
	if flags&unix.OPEN_TREE_CLONE == 0 || flags&unix.AT_RECURSIVE != 0 {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	path, err := readStringFromPID(pid, notif.Data.Args[1])
	if err != nil {
		resp.Error = -syscallErrno(err)
		logf("BLOCKED open_tree: cannot read path pid=%d: %v", pid, err)
		return
	}
	path = resolvePath(path, pid)

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	// Block non-recursive clone of workdir, ancestor, or child (strips sub-mounts).
	if workdir != "" && (path == workdir || isSubPath(path, workdir) || isSubPath(workdir, path)) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED open_tree(CLONE) path=%s pid=%d bin=%s (non-recursive workdir clone)", path, pid, exePath(pid))
		return
	}

	resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

// handleSidecarPIDNSBlock blocks a syscall from the sidecar PID namespace.
// Nested container processes (different PID NS) get CONTINUE.
func handleSidecarPIDNSBlock(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	myPIDNS string,
	notifFD int,
	name string,
) {
	if !isSidecarPIDNS(pid, myPIDNS) {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	detail := ""
	if name == "fsopen" {
		detail, _ = readStringFromPID(pid, notif.Data.Args[0])
	}

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	resp.Error = -int32(unix.EPERM)
	if detail != "" {
		logf("BLOCKED %s(%s) pid=%d bin=%s (sidecar PID namespace)", name, detail, pid, exePath(pid))
	} else {
		logf("BLOCKED %s pid=%d bin=%s (sidecar PID namespace)", name, pid, exePath(pid))
	}
}

// ---------------------------------------------------------------------------
// PID 1 protection
// ---------------------------------------------------------------------------

// handlePIDCheck blocks ptrace/process_vm_readv/process_vm_writev
// targeting PID 1 (the supervisor process).
//
//	ptrace(op, pid, ...):     arg1 = target pid
//	process_vm_readv(pid, ...):  arg0 = target pid
//	process_vm_writev(pid, ...): arg0 = target pid
func handlePIDCheck(
	notif *seccompNotif,
	resp *seccompNotifResp,
	callerPID uint32,
	myPID uint64,
	nr int32,
	notifFD int,
) {
	targetPID := notif.Data.Args[0]
	if nr == int32(unix.SYS_PTRACE) {
		targetPID = notif.Data.Args[1]
	}

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if targetPID == myPID {
		resp.Error = -int32(unix.EPERM)
		name := "ptrace"
		if nr == int32(unix.SYS_PROCESS_VM_READV) {
			name = "process_vm_readv"
		} else if nr == int32(unix.SYS_PROCESS_VM_WRITEV) {
			name = "process_vm_writev"
		}
		logf("BLOCKED %s targeting PID 1 from pid=%d bin=%s", name, callerPID, exePath(callerPID))
	} else {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	}
}

// ---------------------------------------------------------------------------
// Protected-path operations
// ---------------------------------------------------------------------------

// handleOpenat applies policy to openat() calls.
func handleOpenat(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	myPIDNS string,
	notifFD int,
) {
	pathname, err := readStringFromPID(pid, notif.Data.Args[1])
	if err != nil {
		resp.Error = -syscallErrno(err)
		logf("BLOCKED openat: cannot read path pid=%d: %v", pid, err)
		return
	}

	flags := notif.Data.Args[2]
	path := resolvePath(pathname, pid)

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	// Skip the slice walk for paths that obviously can't match.
	if !strings.HasPrefix(path, "/proc/") {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	// /proc/1/* sensitive paths: block any access from sidecar PID NS.
	// In a nested container's PID namespace /proc/1 refers to its own
	// init process, not the supervisor.
	if strings.HasPrefix(path, "/proc/1/") && slices.Contains(procSensitive, path) {
		if !isSidecarPIDNS(pid, myPIDNS) {
			resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
			return
		}
		resp.Error = -int32(unix.EACCES)
		logf("BLOCKED openat path=%s pid=%d bin=%s", path, pid, exePath(pid))
		return
	}

	// Host-affecting kernel control files: block writes from any
	// context. These are global, not PID-NS-scoped -- a write changes
	// host kernel behavior regardless of which container the writer
	// lives in. Verify the resolved path is actually on procfs in the
	// caller's mount namespace -- a placeholder file at the same name
	// inside a chrooted build rootfs (buildah copier ensure) is on
	// overlayfs and harmless.
	accMode := flags & uint64(unix.O_ACCMODE)
	if accMode != uint64(unix.O_RDONLY) && slices.Contains(procSensitive, path) {
		if !pathOnProcfs(pid, pathname) {
			resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
			return
		}
		resp.Error = -int32(unix.EACCES)
		logf("BLOCKED openat(write) path=%s pid=%d flags=0x%x bin=%s",
			path, pid, flags, exePath(pid))
		return
	}

	resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

// pathOnProcfs returns true when the openat path argument, resolved
// through the caller's mount namespace, lives on procfs. Falls back
// to the parent directory when the file does not exist yet (the
// O_CREAT|O_EXCL pattern that buildah's copier uses for mount-target
// setup).
func pathOnProcfs(pid uint32, raw string) bool {
	if raw == "" {
		return false
	}
	p := raw
	if p[0] != '/' {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil {
			return false
		}
		p = filepath.Join(cwd, p)
	}
	p = filepath.Clean(p)

	target := fmt.Sprintf("/proc/%d/root%s", pid, p)
	var fs unix.Statfs_t
	err := unix.Statfs(target, &fs)
	if err == nil {
		return uint64(fs.Type) == procSuperMagic
	}
	parent := fmt.Sprintf("/proc/%d/root%s", pid, filepath.Dir(p))
	err = unix.Statfs(parent, &fs)
	if err == nil {
		return uint64(fs.Type) == procSuperMagic
	}
	return false
}

// checkDualPathProtected is the common logic for linkat and renameat2:
// read two paths from args[1] and args[3], block if either is protected.
func checkDualPathProtected(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	protected map[string]bool,
	notifFD int,
	syscallName string,
) {
	oldpath, err := readStringFromPID(pid, notif.Data.Args[1])
	if err != nil {
		resp.Error = -syscallErrno(err)
		logf("BLOCKED %s: cannot read oldpath pid=%d: %v", syscallName, pid, err)
		return
	}
	newpath, err := readStringFromPID(pid, notif.Data.Args[3])
	if err != nil {
		resp.Error = -syscallErrno(err)
		logf("BLOCKED %s: cannot read newpath pid=%d: %v", syscallName, pid, err)
		return
	}

	src := resolvePath(oldpath, pid)
	dst := resolvePath(newpath, pid)

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if isProtected(src, protected) || isProtected(dst, protected) {
		resp.Error = -int32(unix.EACCES)
		logf("BLOCKED %s oldpath=%s newpath=%s pid=%d bin=%s",
			syscallName, src, dst, pid, exePath(pid))
	} else {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	}
}

// handleLinkat blocks hardlink creation to/from protected paths.
//
//	linkat(olddirfd, oldpath, newdirfd, newpath, flags)
//	args[0]=olddirfd, args[1]=oldpath ptr, args[2]=newdirfd, args[3]=newpath ptr
func handleLinkat(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	protected map[string]bool,
	notifFD int,
) {
	checkDualPathProtected(notif, resp, pid, protected, notifFD, "linkat")
}

// handleRenameat2 blocks renaming into/out of protected paths.
//
//	renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
//	args[0]=olddirfd, args[1]=oldpath ptr, args[2]=newdirfd, args[3]=newpath ptr
func handleRenameat2(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	protected map[string]bool,
	notifFD int,
) {
	checkDualPathProtected(notif, resp, pid, protected, notifFD, "renameat2")
}

// ---------------------------------------------------------------------------
// Firewall lock (netfilter modification)
// ---------------------------------------------------------------------------

// netfilterBin is the only binary that legitimately calls netfilter APIs.
// All iptables symlinks resolve to this binary.
const netfilterBin = "/usr/sbin/xtables-nft-multi"

// netfilterParent is the only allowed parent for netfilter operations.
// netavark is podman's network manager — it exec's xtables-nft-multi
// to configure per-container bridge rules. It does not expose a CLI
// for arbitrary rule manipulation.
const netfilterParent = "/usr/local/lib/podman/netavark"

// readPPID returns the parent PID of a process by parsing /proc/<pid>/status.
// Returns 0 on error.
func readPPID(pid uint32) uint32 {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "PPid:\t") {
			continue
		}
		v, parseErr := strconv.ParseUint(strings.TrimPrefix(line, "PPid:\t"), 10, 32)
		if parseErr != nil {
			return 0
		}
		return uint32(v)
	}
	// Scanner failures (line too long, read error) are treated identically
	// to "no PPid line found" -- caller gets 0 either way.
	_ = scanner.Err()
	return 0
}

// isNetfilterAllowed checks whether a process is xtables-nft-multi
// spawned by netavark. This is the only legitimate path for netfilter
// modification inside the sidecar. The caller (xtables) is blocked
// waiting for the supervisor, so neither it nor its parent (netavark,
// waiting for the child) can exit during this check — no PID reuse race.
func isNetfilterAllowed(pid uint32) bool {
	if exePath(pid) != netfilterBin {
		return false
	}
	ppid := readPPID(pid)
	if ppid == 0 {
		return false
	}
	return exePath(ppid) == netfilterParent
}

// handleSetsockopt blocks IPT_SO_SET_REPLACE for sidecar processes
// unless the caller is xtables-nft-multi spawned by netavark.
// Legitimate firewall changes from the host arrive via `podman exec`,
// which does NOT inherit the seccomp-notif filter (setns, not fork).
// Integer args only — zero TOCTOU.
//
//	setsockopt(fd, level, optname, optval, optlen)
//	args[1]=level, args[2]=optname
func handleSetsockopt(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	myPIDNS string,
	notifFD int,
) {
	if !isSidecarPIDNS(pid, myPIDNS) {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	level := notif.Data.Args[1]
	optname := notif.Data.Args[2]

	isNF := (level == unix.SOL_IP || level == unix.SOL_IPV6) && optname == iptSOSetReplace
	if !isNF {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if isNetfilterAllowed(pid) {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	resp.Error = -int32(unix.EPERM)
	logf("BLOCKED setsockopt(IPT_SO_SET_REPLACE) pid=%d level=%d bin=%s parent=%s",
		pid, level, exePath(pid), exePath(readPPID(pid)))
}

// handleSocket blocks creation of NETLINK_NETFILTER sockets for sidecar
// processes unless the caller is xtables-nft-multi spawned by netavark.
// Legitimate firewall changes from the host arrive via `podman exec`,
// which does NOT inherit the seccomp-notif filter.
// Integer args only — zero TOCTOU.
//
//	socket(domain, type, protocol)
//	args[0]=domain, args[2]=protocol
func handleSocket(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	myPIDNS string,
	notifFD int,
) {
	if !isSidecarPIDNS(pid, myPIDNS) {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	domain := notif.Data.Args[0]
	protocol := notif.Data.Args[2]

	if domain != unix.AF_NETLINK || protocol != unix.NETLINK_NETFILTER {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if isNetfilterAllowed(pid) {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	resp.Error = -int32(unix.EPERM)
	logf("BLOCKED socket(AF_NETLINK, NETLINK_NETFILTER) pid=%d bin=%s parent=%s",
		pid, exePath(pid), exePath(readPPID(pid)))
}
