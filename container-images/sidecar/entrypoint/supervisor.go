// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// logf writes a timestamped audit line to stderr.
func logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "clampdown: %s seccomp-notif: %s\n",
		time.Now().UTC().Format(time.RFC3339), msg)
}

// readStringFromPID reads a NUL-terminated string from another process's
// memory via /proc/<pid>/mem at the given address.
func readStringFromPID(pid uint32, addr uint64) (string, error) {
	if addr == 0 {
		return "", nil
	}
	path := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, 4096)
	n, err := f.ReadAt(buf, int64(addr))
	if n == 0 {
		return "",
			fmt.Errorf("read %s at 0x%x: %w", path, addr, err)
	}

	idx := bytes.IndexByte(buf[:n], 0)
	if idx < 0 {
		return "",
			fmt.Errorf("%w: no NUL terminator in %d bytes at 0x%x",
				unix.ENAMETOOLONG, n, addr)
	}
	return string(buf[:idx]), nil
}

// syscallErrno extracts the syscall errno from any error.
func syscallErrno(err error) int32 {
	var errno unix.Errno
	if errors.As(err, &errno) {
		return int32(errno)
	}
	return int32(unix.EIO)
}

// exePath returns the executable path for a process, or "" on error.
func exePath(pid uint32) string {
	result, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	return result
}

// resolvePath cleans a path, resolves relative paths using the process's
// cwd, and resolves symlinks through the process's mount namespace.
func resolvePath(raw string, pid uint32) string {
	if raw == "" {
		return ""
	}
	if raw[0] != '/' {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err == nil {
			raw = filepath.Join(cwd, raw)
		}
	}
	clean := filepath.Clean(raw)
	// Resolve symlinks through /proc/<pid>/root to use the caller's
	// mount namespace, not the supervisor's. Prevents symlink-to-
	// protected-path bypass (kernel follows symlinks on mount/umount).
	root, err := os.Readlink(fmt.Sprintf("/proc/%d/root", pid))
	if err != nil {
		return clean
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, clean))
	if err != nil {
		return clean
	}
	if root != "/" && strings.HasPrefix(resolved, root) {
		return resolved[len(root):]
	}
	return resolved
}

// readPIDNS returns the PID namespace identifier for a process
// (e.g., "pid:[4026531836]"). Used to distinguish sidecar processes
// from nested container processes.
func readPIDNS(pid int) string {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		return ""
	}
	return link
}

// isSidecarPIDNS checks whether a process is in the sidecar's PID namespace.
// Compares /proc/<pid>/ns/pid (a symlink like "pid:[4026531836]") against
// PID 1's cached value. A match means the caller sees the sidecar's PID 1
// in its procfs -- mounting proc would expose /proc/1/mem. A mismatch means
// the caller is in a nested container's PID namespace (security-policy
// requires PID isolation), where procfs only shows its own processes.
func isSidecarPIDNS(pid uint32, myPIDNS string) bool {
	if myPIDNS == "" {
		return true // conservative: if we can't read our own NS, block
	}
	ns := readPIDNS(int(pid))
	return ns == "" || ns == myPIDNS
}

// runSupervisor handles seccomp notifications on the notification FD.
// It applies path-based policy for mount operations, PID-based policy
// for ptrace/process_vm_* targeting PID 1, hash-verified exec allowlist,
// protected-path operations, and firewall lock.
func runSupervisor(notifFD int, protected map[string]bool, workdir string, allowlist *execAllowlist) {
	myPID := uint64(os.Getpid())
	myPIDNS := readPIDNS(int(myPID))

	for {
		var notif seccompNotif
		var resp seccompNotifResp

		_, _, errno := unix.Syscall(unix.SYS_IOCTL,
			uintptr(notifFD),
			unix.SECCOMP_IOCTL_NOTIF_RECV,
			uintptr(unsafe.Pointer(&notif)))
		if errno != 0 {
			if errno == unix.EBADF || errno == unix.ENODEV {
				return
			}
			if errno == unix.EINTR {
				continue
			}
			logf("RECV error: %v", errno)
			continue
		}

		resp.ID = notif.ID
		pid := notif.PID
		nr := notif.Data.NR

		switch nr {
		// Mount-family handlers.
		case int32(unix.SYS_UMOUNT2):
			handleProtectedPathOp(&notif, &resp, pid, protected, notifFD, 0, int32(unix.EPERM), "umount2")
		case int32(unix.SYS_MOUNT):
			handleMount(&notif, &resp, pid, protected, workdir, myPIDNS, notifFD)
		case int32(unix.SYS_MOUNT_SETATTR):
			handleProtectedPathOp(&notif, &resp, pid, protected, notifFD, 1, int32(unix.EPERM), "mount_setattr")
		case int32(unix.SYS_MOVE_MOUNT):
			handleProtectedPathOp(&notif, &resp, pid, protected, notifFD, 3, int32(unix.EPERM), "move_mount")
		case int32(unix.SYS_OPEN_TREE):
			handleOpenTree(&notif, &resp, pid, workdir, notifFD)
		case int32(unix.SYS_FSOPEN):
			handleSidecarPIDNSBlock(&notif, &resp, pid, myPIDNS, notifFD, "fsopen")
		case int32(unix.SYS_FSCONFIG):
			handleSidecarPIDNSBlock(&notif, &resp, pid, myPIDNS, notifFD, "fsconfig")
		case int32(unix.SYS_FSMOUNT):
			handleSidecarPIDNSBlock(&notif, &resp, pid, myPIDNS, notifFD, "fsmount")

		// PID 1 protection.
		case int32(unix.SYS_PTRACE), int32(unix.SYS_PROCESS_VM_READV), int32(unix.SYS_PROCESS_VM_WRITEV):
			handlePIDCheck(&notif, &resp, pid, myPID, nr, notifFD)

		// Exec allowlist (hash-verified).
		case int32(unix.SYS_EXECVE):
			handleExecve(&notif, &resp, pid, allowlist, myPIDNS, notifFD)
		case int32(unix.SYS_EXECVEAT):
			handleExecveat(&notif, &resp, pid, allowlist, myPIDNS, notifFD)

		// Protected-path operations.
		case int32(unix.SYS_OPENAT):
			handleOpenat(&notif, &resp, pid, myPIDNS, notifFD)
		case int32(unix.SYS_UNLINKAT):
			handleProtectedPathOp(&notif, &resp, pid, protected, notifFD, 1, int32(unix.EACCES), "unlinkat")
		case int32(unix.SYS_SYMLINKAT):
			handleProtectedPathOp(&notif, &resp, pid, protected, notifFD, 2, int32(unix.EACCES), "symlinkat")
		case int32(unix.SYS_LINKAT):
			handleLinkat(&notif, &resp, pid, protected, notifFD)
		case int32(unix.SYS_RENAMEAT2):
			handleRenameat2(&notif, &resp, pid, protected, notifFD)

		// Firewall lock (netfilter modification).
		case int32(unix.SYS_SETSOCKOPT):
			handleSetsockopt(&notif, &resp, pid, myPIDNS, notifFD)
		case int32(unix.SYS_SOCKET):
			handleSocket(&notif, &resp, pid, myPIDNS, notifFD)

		default:
			resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		}

		sendResp(notifFD, &resp)
	}
}
