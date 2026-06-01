// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// forwardSignals relays SIGTERM/SIGINT to the child process and reaps
// zombies on SIGCHLD. Runs until the channel is closed.
func forwardSignals(cmd *exec.Cmd, done <-chan struct{}) {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, unix.SIGTERM, unix.SIGINT, unix.SIGCHLD)
	defer signal.Stop(sigs)

	for {
		select {
		case <-done:
			return
		case sig := <-sigs:
			if sig == unix.SIGCHLD {
				reapZombies()
				continue
			}
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}
}

// reapZombies calls waitpid(-1, WNOHANG) in a loop to collect orphaned
// child processes. As PID 1 in the container, we inherit orphans.
func reapZombies() {
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
		if pid <= 0 || err != nil {
			break
		}
	}
}

// interceptedSyscalls is the list of syscalls supervised via seccomp-notif.
//
//   - mount, umount2, mount_setattr, move_mount -- protect masked/RO paths
//   - open_tree -- block non-recursive clones that strip sub-mounts
//   - fsopen, fsconfig, fsmount -- block new mount API procfs bypass
//   - ptrace, process_vm_readv, process_vm_writev -- protect PID 1
//   - execve, execveat -- hash-verified exec allowlist
//   - openat -- block /proc/1/* opens from sidecar PID NS
//   - unlinkat, symlinkat, linkat, renameat2 -- protect RO/masked paths
//   - setsockopt, socket -- firewall lock (netfilter modification)
var interceptedSyscalls = []uint32{
	unix.SYS_UMOUNT2,
	unix.SYS_MOUNT,
	unix.SYS_MOUNT_SETATTR,
	unix.SYS_MOVE_MOUNT,
	unix.SYS_OPEN_TREE,
	unix.SYS_FSOPEN,
	unix.SYS_FSCONFIG,
	unix.SYS_FSMOUNT,
	unix.SYS_PTRACE,
	unix.SYS_PROCESS_VM_READV,
	unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_EXECVE,
	unix.SYS_EXECVEAT,
	unix.SYS_OPENAT,
	unix.SYS_UNLINKAT,
	unix.SYS_SYMLINKAT,
	unix.SYS_LINKAT,
	unix.SYS_RENAMEAT2,
	unix.SYS_SETSOCKOPT,
	unix.SYS_SOCKET,
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: entrypoint <command> [args...]")
	}

	// Unmount whatever the runtime placed over /proc/sys and remount read-only.
	// Prevents /proc/sys/kernel/core_pattern write (host code execution via
	// core dumps) and /proc/sys/kernel/modprobe write (arbitrary module load).
	// Fails if nothing is mounted -- not an error.
	err := unix.Unmount("/proc/sys", unix.MNT_DETACH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: unmount /proc/sys: %v\n", err)
	}

	// /proc/sys is now real procfs -- writable, namespace-scoped.
	// Lock it all down read-only.
	err = unix.Mount("/proc/sys", "/proc/sys", "", unix.MS_BIND, "")
	if err != nil {
		fatalf("bind /proc/sys: %v", err)
	}
	err = unix.Mount("", "/proc/sys", "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
	if err != nil {
		fatalf("remount ro /proc/sys: %v", err)
	}

	// Punch a writable hole for /proc/sys/net only (namespace-scoped, safe)
	err = unix.Mount("/proc/sys/net", "/proc/sys/net", "", unix.MS_BIND, "")
	if err != nil {
		fatalf("bind /proc/sys/net: %v", err)
	}
	err = unix.Mount("", "/proc/sys/net", "", unix.MS_BIND|unix.MS_REMOUNT, "")
	if err != nil {
		fatalf("remount rw /proc/sys/net: %v", err)
	}

	// Bootstrap cgroup v2 hierarchy for nested container support.
	err = bootstrapCgroups()
	if err != nil {
		fatalf("cgroup bootstrap: %v", err)
	}

	// Set up egress firewall (agent OUTPUT + pod FORWARD chains).
	err = bootstrapFirewall()
	if err != nil {
		fatalf("firewall: %v", err)
	}

	// Write sandbox identity for OCI hooks (hooks don't inherit env vars).
	// Hooks read /run/sandbox/ files to enforce non-root on nested containers.
	// Directory is bind-mounted read-only after writing so an escaped process
	// can't modify the UID/GID to escalate privileges.
	writeSandboxIdentity()

	// Mask sensitive /proc and /sys paths before discovering protected
	// mounts.
	maskSensitivePaths()

	workdir := os.Getenv("SANDBOX_WORKDIR")
	protected := discoverProtectedPaths(workdir)
	fmt.Fprintf(os.Stderr, "clampdown: %s seccomp-notif: protecting %d mount points\n",
		time.Now().UTC().Format(time.RFC3339), len(protected))

	// Build the exec allowlist BEFORE installing the filter. The walk
	// calls stat/open on files, which should not be intercepted.
	allowlist, count := buildExecAllowlist()
	logExecAllowlist(count)

	// Harden PID 1 BEFORE installing the filter. The bind mount on
	// /proc/1/mem must happen without interception -- once the filter
	// is active, the supervisor would block it (/proc/1 is protected).
	hardenPID1()

	// Lock the OS thread BEFORE installing the filter. Without TSYNC,
	// only this thread gets the filter. The child (podman) must be
	// spawned from this same thread so it inherits the filter via clone().
	runtime.LockOSThread()

	verifyNotifStructSizes()

	filter := buildNotifFilter(auditArch, interceptedSyscalls)
	notifFD := installFilter(filter)

	if notifFD < 0 {
		runtime.UnlockOSThread()
		fatalf("seccomp-notif: failed to exec (no supervisor)")
	}

	go runSupervisor(notifFD, protected, workdir, allowlist)

	cmd := exec.CommandContext(context.Background(), os.Args[1], os.Args[2:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	done := make(chan struct{})
	go forwardSignals(cmd, done)

	err = cmd.Start()
	runtime.UnlockOSThread()
	if err != nil {
		fatalf("start %s: %v", os.Args[1], err)
	}

	err = cmd.Wait()
	close(done)

	unix.Close(notifFD)
	reapZombies()

	exitCode := 0
	if err != nil {
		exitCode = cmd.ProcessState.ExitCode()
		if exitCode < 0 {
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}
