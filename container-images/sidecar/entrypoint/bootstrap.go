// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	iptables  = "/usr/sbin/iptables"
	ip6tables = "/usr/sbin/ip6tables"
)

// iptRun executes an iptables/ip6tables command, forwarding stderr.
func iptRun(bin string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), bin, args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// bootstrapCgroups prepares the cgroup v2 hierarchy for nested container use.
//
// After mounting a fresh cgroup2 filesystem, PID 1 (this process) sits in the
// root cgroup. Cgroup v2's "no internal processes" rule prevents enabling
// controllers in subtree_control when processes exist in the cgroup. We must:
//  1. Create a leaf cgroup and move ourselves into it
//  2. Enable all available controllers in the root's subtree_control
//
// This makes the full controller set available to podman for nested containers.
func bootstrapCgroups() error {
	const cgRoot = "/sys/fs/cgroup"

	// Unmount Docker/podman's read-only bind mount of the host cgroup tree.
	err := unix.Unmount(cgRoot, unix.MNT_DETACH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: unmount %s: %v\n", cgRoot, err)
	}

	// Mount a fresh cgroup2 scoped to this container's private cgroupns.
	err = unix.Mount("cgroup2", cgRoot, "cgroup2", 0, "nsdelegate")
	if err != nil {
		// Retry without nsdelegate for older kernels (<5.2).
		err = unix.Mount("cgroup2", cgRoot, "cgroup2", 0, "")
		if err != nil {
			return fmt.Errorf("mount cgroup2: %w", err)
		}
	}

	// Read which controllers the parent delegated to us.
	data, err := os.ReadFile(cgRoot + "/cgroup.controllers")
	if err != nil {
		return fmt.Errorf("read controllers: %w", err)
	}
	controllers := strings.Fields(strings.TrimSpace(string(data)))
	if len(controllers) == 0 {
		// No controllers delegated. Podman will run in a degraded mode
		// (no resource limits on nested containers) but won't crash.
		fmt.Fprintln(os.Stderr, "warning: no cgroup controllers delegated by host runtime")
		return nil
	}

	// Create a leaf cgroup for the entrypoint/podman process.
	initCgroup := cgRoot + "/init"
	err = os.MkdirAll(initCgroup, 0o755)
	if err != nil {
		return fmt.Errorf("mkdir %s: %w", initCgroup, err)
	}

	// Move ourselves (PID 1) into the leaf.
	pid := fmt.Sprintf("%d\n", os.Getpid())
	err = os.WriteFile(initCgroup+"/cgroup.procs", []byte(pid), 0o644)
	if err != nil {
		return fmt.Errorf("move pid to init cgroup: %w", err)
	}

	// Enable all available controllers in the root's subtree_control.
	// This makes them available to child cgroups (libpod_parent, etc.).
	var enables []string
	for _, c := range controllers {
		enables = append(enables, "+"+c)
	}

	enableStr := strings.Join(enables, " ") + "\n"
	err = os.WriteFile(cgRoot+"/cgroup.subtree_control", []byte(enableStr), 0o644)
	if err != nil {
		// Some controllers may fail individually (e.g. cpuset not delegated).
		// Try them one at a time so partial enablement works.
		fmt.Fprintf(os.Stderr, "warning: bulk controller enable failed (%v), trying individually\n", err)
		for _, c := range controllers {
			entry := "+" + c + "\n"
			err = os.WriteFile(cgRoot+"/cgroup.subtree_control", []byte(entry), 0o644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not enable controller %s: %v\n", c, err)
			}
		}
	}

	return nil
}

// bootstrapFirewall sets a default-deny baseline. OUTPUT gets REJECT
// (immediate failure), FORWARD gets DROP. Only loopback and established
// connections are allowed. The launcher applies the full ruleset
// (agent allowlist, pod chains) after the sidecar API is ready.
func bootstrapFirewall() error {
	for _, bin := range []string{iptables, ip6tables} {
		rejectType := "icmp-port-unreachable"
		if bin == ip6tables {
			rejectType = "icmp6-port-unreachable"
		}

		// filter/OUTPUT: REJECT all, allow loopback + established.
		err := iptRun(bin, "-F", "OUTPUT")
		if err != nil {
			return fmt.Errorf("%s flush OUTPUT: %w", bin, err)
		}
		err = iptRun(bin, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("%s loopback: %w", bin, err)
		}
		err = iptRun(bin, "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("%s established: %w", bin, err)
		}
		err = iptRun(bin, "-A", "OUTPUT", "-j", "REJECT", "--reject-with", rejectType)
		if err != nil {
			return fmt.Errorf("%s terminal reject: %w", bin, err)
		}

		// mangle/FORWARD: DROP all, allow loopback + established.
		err = iptRun(bin, "-t", "mangle", "-F", "FORWARD")
		if err != nil {
			return fmt.Errorf("%s flush FORWARD: %w", bin, err)
		}
		err = iptRun(
			bin,
			"-t",
			"mangle",
			"-A",
			"FORWARD",
			"-m",
			"state",
			"--state",
			"ESTABLISHED,RELATED",
			"-j",
			"ACCEPT",
		)
		if err != nil {
			return fmt.Errorf("%s FORWARD established: %w", bin, err)
		}
		err = iptRun(bin, "-t", "mangle", "-A", "FORWARD", "-o", "lo", "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("%s FORWARD loopback: %w", bin, err)
		}
		err = iptRun(bin, "-t", "mangle", "-A", "FORWARD", "-j", "DROP")
		if err != nil {
			return fmt.Errorf("%s FORWARD terminal drop: %w", bin, err)
		}
	}

	fmt.Fprintln(os.Stderr, "firewall: baseline deny-all set")
	return nil
}

// writeSandboxIdentity writes the host UID/GID to /run/sandbox/ for OCI
// hooks to read. After writing, the directory is bind-mounted read-only
// so an escaped process cannot modify the UID to escalate privileges
// in future nested containers.
func writeSandboxIdentity() {
	const dir = "/run/sandbox"

	uid := os.Getenv("SANDBOX_UID")
	if uid == "" {
		return
	}
	gid := os.Getenv("SANDBOX_GID")
	if gid == "" {
		gid = uid
	}

	err := os.MkdirAll(dir, 0o500)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: mkdir %s: %v\n", dir, err)
		return
	}
	err = os.WriteFile(dir+"/uid", []byte(uid), 0o400)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: write %s/uid: %v\n", dir, err)
	}
	err = os.WriteFile(dir+"/gid", []byte(gid), 0o400)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: write %s/gid: %v\n", dir, err)
	}

	// Bind-mount the directory read-only so an escaped process
	// cannot modify the UID to escalate privileges in future
	// nested containers.
	err = unix.Mount(dir, dir, "", unix.MS_BIND, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: bind mount %s: %v\n", dir, err)
		return
	}
	err = unix.Mount("", dir, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: remount ro %s: %v\n", dir, err)
	}
}

// hardenPID1 makes PID 1 harder to tamper with via /proc/1/mem.
// PR_SET_DUMPABLE=0 prevents /proc/1/mem access from processes
// without CAP_SYS_PTRACE.
func hardenPID1() {
	// PR_SET_DUMPABLE=0: partial defense (CAP_SYS_PTRACE overrides).
	err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: prctl(PR_SET_DUMPABLE, 0): %v\n", err)
	}

	// Mask /proc/1/mem -- blocks all memory access to PID 1.
	err = unix.Mount("/dev/null", "/proc/1/mem", "", unix.MS_BIND, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: mask /proc/1/mem: %v\n", err)
	}
}
