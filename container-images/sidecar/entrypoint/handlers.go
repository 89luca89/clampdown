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

// shallowInfraBindSources lists infra storage/cache paths that have no
// legitimate use as an MS_BIND source: binding any of them into a
// nested container hands R+W access to the sidecar's container-storage
// tree (e.g. `podman build --volume /var/lib/containers/storage:/x`).
// The OCI runtime only binds deeper, ID-scoped paths
// (overlay/<layer>/merged for rootfs, overlay-containers/<CID>/userdata/*
// for /etc/hosts and friends), so exact-matching these shallow paths
// blocks the escape without touching legitimate container setup.
var shallowInfraBindSources = map[string]bool{
	"/run/containers":                                   true,
	"/var/cache/containers":                             true,
	"/var/lib/containers/storage":                       true,
	"/var/lib/containers/storage/libpod":                true,
	"/var/lib/containers/storage/overlay":               true,
	"/var/lib/containers/storage/overlay-containers":    true,
	"/var/lib/containers/storage/overlay-images":        true,
	"/var/lib/containers/storage/overlay-layers":        true,
	"/var/lib/containers/storage/volumes":               true,
	"/var/run/containers/storage":                       true,
	"/var/run/containers/storage/overlay":               true,
	"/var/run/containers/storage/overlay-containers":    true,
}

// isShallowInfraBindSource reports whether a bind source matches one of
// the shallow infra paths that must never be bound into a nested
// container.
func isShallowInfraBindSource(source string) bool {
	return shallowInfraBindSources[source]
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
// a protected mount point. Used for umount2, mount_setattr, unlinkat, and
// symlinkat — all share the pattern: read one path arg, resolve it, block
// if protected.
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

	// Block bind mounts whose source is a shallow infra storage/cache
	// path AND whose target differs from the source. Podman self-binds
	// paths like /var/lib/containers/storage/overlay onto themselves at
	// startup (same source and target) to pin the subtree as a mount
	// point before changing propagation — these must pass. A buildah
	// --volume of the same source always sets target to a path inside
	// the nested container's rootfs (crun's prep path), so source !=
	// target reliably separates attack from self-bind. Legitimate
	// OCI-runtime binds use ID-scoped sub-paths (overlay/<layer>/merged,
	// overlay-containers/<CID>/userdata/*) that are not in the shallow
	// list and pass regardless.
	if flags&unix.MS_BIND != 0 && flags&unix.MS_REMOUNT == 0 &&
		source != target && isShallowInfraBindSource(source) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED mount(MS_BIND) source=%s target=%s pid=%d bin=%s (shallow infra storage bound to different target)",
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

// handleOpenTree validates open_tree(dirfd, path, flags) (arg1=path,
// arg2=flags). The fd is attached via move_mount, so from untrusted
// callers the source must be in the bind allowlist. Sidecar binaries
// (crun) are trusted; crun's legitimate open_tree set during OCI setup
// is too broad to enumerate. Non-recursive workdir clones are rejected
// regardless -- they strip /dev/null sub-mounts.
func handleOpenTree(notif *seccompNotif, resp *seccompNotifResp, pid uint32, workdir string, allowlist *execAllowlist, notifFD int) {
	flags := notif.Data.Args[2]

	if flags&unix.OPEN_TREE_CLONE == 0 || allowlist.isSidecarBinary(pid) {
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

	if !isAllowedBindSource(path, workdir) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED open_tree(CLONE) path=%s pid=%d bin=%s (source not allowed)",
			path, pid, exePath(pid))
		return
	}

	if flags&unix.AT_RECURSIVE == 0 && workdir != "" &&
		(path == workdir || isSubPath(path, workdir) || isSubPath(workdir, path)) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED open_tree(CLONE) path=%s pid=%d bin=%s (non-recursive workdir clone)", path, pid, exePath(pid))
		return
	}

	resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

// handleMoveMount validates move_mount(from_dfd, from_pathname, to_dfd,
// to_pathname, flags). Sidecar binaries (crun) are trusted; they attach
// fsmount'd and anonymous open_tree'd fds whose sources are not
// representable as a bind-source path. For untrusted callers target must
// not be protected and source must be in the bind allowlist (recovered
// from from_dfd via mountRootFromFD when MOVE_MOUNT_F_EMPTY_PATH).
func handleMoveMount(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	protected map[string]bool,
	workdir string,
	allowlist *execAllowlist,
	notifFD int,
) {
	if allowlist.isSidecarBinary(pid) {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	toRaw, err := readStringFromPID(pid, notif.Data.Args[3])
	if err != nil {
		resp.Error = -syscallErrno(err)
		logf("BLOCKED move_mount: cannot read target pid=%d: %v", pid, err)
		return
	}
	target := resolvePath(toRaw, pid)

	fromRaw, err := readStringFromPID(pid, notif.Data.Args[1])
	if err != nil {
		resp.Error = -syscallErrno(err)
		logf("BLOCKED move_mount: cannot read source pid=%d: %v", pid, err)
		return
	}

	var source string
	if fromRaw == "" {
		source = mountRootFromFD(pid, int32(notif.Data.Args[0]))
	} else {
		source = resolvePath(fromRaw, pid)
	}

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if isProtected(target, protected) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED move_mount target=%s pid=%d bin=%s (protected target)",
			target, pid, exePath(pid))
		return
	}

	if source == "" {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED move_mount: cannot resolve source fd=%d target=%s pid=%d bin=%s",
			int32(notif.Data.Args[0]), target, pid, exePath(pid))
		return
	}

	if !isAllowedBindSource(source, workdir) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED move_mount source=%s target=%s pid=%d bin=%s (source not allowed)",
			source, target, pid, exePath(pid))
		return
	}

	resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

// mountRootFromFD returns the mount root (mountinfo field 4) for an fd
// that references a mount. Reads /proc/<pid>/fdinfo/<fd> for mnt_id, then
// looks it up in /proc/<pid>/mountinfo. Returns "" on any failure so the
// caller can fail closed.
func mountRootFromFD(pid uint32, fd int32) string {
	info, err := os.Open(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))
	if err != nil {
		return ""
	}
	defer info.Close()

	var mntID string
	scanner := bufio.NewScanner(info)
	for scanner.Scan() {
		rest, ok := strings.CutPrefix(scanner.Text(), "mnt_id:")
		if ok {
			mntID = strings.TrimSpace(rest)
			break
		}
	}
	if mntID == "" {
		return ""
	}

	mi, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return ""
	}
	defer mi.Close()

	scanner = bufio.NewScanner(mi)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == mntID {
			return fields[3]
		}
	}
	return ""
}

// handleFsmount validates fsmount(fs_fd, flags, attr_flags). Sidecar
// binaries (crun) are trusted; untrusted callers get the bind allowlist
// via mountRootFromFD on the fs_fd. An fsopen'd context has no backing
// mount so resolution fails closed -- only crun reaches this legitimately.
func handleFsmount(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	workdir string,
	allowlist *execAllowlist,
	notifFD int,
) {
	if allowlist.isSidecarBinary(pid) {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	fsFd := int32(notif.Data.Args[0])
	source := mountRootFromFD(pid, fsFd)

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if source == "" {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED fsmount: cannot resolve source fd=%d pid=%d bin=%s",
			fsFd, pid, exePath(pid))
		return
	}

	if !isAllowedBindSource(source, workdir) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED fsmount source=%s pid=%d bin=%s (source not allowed)",
			source, pid, exePath(pid))
		return
	}

	resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

// handleFspick validates fspick(dirfd, path, flags). Sidecar binaries
// are trusted; untrusted callers get the bind allowlist. Source is the
// path arg, or the mount referenced by dirfd (FSPICK_EMPTY_PATH).
func handleFspick(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	workdir string,
	allowlist *execAllowlist,
	notifFD int,
) {
	if allowlist.isSidecarBinary(pid) {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	pathRaw, err := readStringFromPID(pid, notif.Data.Args[1])
	if err != nil {
		resp.Error = -syscallErrno(err)
		logf("BLOCKED fspick: cannot read path pid=%d: %v", pid, err)
		return
	}

	var source string
	if pathRaw == "" {
		source = mountRootFromFD(pid, int32(notif.Data.Args[0]))
	} else {
		source = resolvePath(pathRaw, pid)
	}

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if source == "" {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED fspick: cannot resolve source pid=%d bin=%s",
			pid, exePath(pid))
		return
	}

	if !isAllowedBindSource(source, workdir) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED fspick source=%s pid=%d bin=%s (source not allowed)",
			source, pid, exePath(pid))
		return
	}

	resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

// handleSidecarPIDNSBlock blocks fsopen/fsconfig from the sidecar PID
// namespace; nested PID NS gets CONTINUE. fsmount/fspick land in their
// own handlers with source checks.
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

// ---------------------------------------------------------------------------
// Firewall lock (netfilter modification)
// ---------------------------------------------------------------------------

// netfilterBin is the only binary that legitimately calls netfilter APIs.
// All iptables symlinks resolve to this binary.
var netfilterBins = []string{
	"/usr/sbin/xtables-nft-multi",
	"/usr/sbin/nft",
}

// netfilterParent is the only allowed parent for netfilter operations.
// netavark is podman's network manager — it exec's one of netfilterBins
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

// isNetfilterAllowed checks whether a process is one of netfilterBins
// spawned by netavark. This is the only legitimate path for netfilter
// modification inside the sidecar. The caller is blocked waiting for
// the supervisor, so neither it nor its parent (netavark, waiting for
// the child) can exit during this check — no PID reuse race.
func isNetfilterAllowed(pid uint32) bool {
	if !slices.Contains(netfilterBins, exePath(pid)) {
		return false
	}
	ppid := readPPID(pid)
	if ppid == 0 {
		return false
	}
	return exePath(ppid) == netfilterParent
}

// handleSetsockopt blocks IPT_SO_SET_REPLACE for sidecar processes
// unless the caller is a netfilterBins entry spawned by netavark.
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
// processes unless the caller is a netfilterBins entry spawned by
// netavark. Legitimate firewall changes from the host arrive via
// `podman exec`, which does NOT inherit the seccomp-notif filter.
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
