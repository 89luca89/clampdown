// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	chainAgentAllow = "AGENT_ALLOW"
	chainAgentBlock = "AGENT_BLOCK"
	chainPodAllow   = "POD_ALLOW"
	chainPodBlock   = "POD_BLOCK"
)

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func bindMount(path string) error {
	return syscall.Mount(path, path, "", syscall.MS_BIND, "")
}

func remountRO(path string) error {
	return syscall.Mount("", path, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, "")
}

func remountRW(path string) error {
	return syscall.Mount("", path, "", syscall.MS_BIND|syscall.MS_REMOUNT, "")
}

// iptRun executes an iptables/ip6tables command, forwarding stderr.
func iptRun(bin string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), bin, args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// classifyIPs splits a list of IP/CIDR entries into IPv4 and IPv6 buckets.
func classifyIPs(entries []string) ([]string, []string) {
	var ip4s, ip6s []string
	seen := make(map[string]bool)
	for _, entry := range entries {
		if seen[entry] {
			continue
		}
		seen[entry] = true

		// CIDR.
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				fmt.Fprintf(os.Stderr, "firewall: warning: bad CIDR %s\n", entry)
				continue
			}
			if ipNet.IP.To4() != nil {
				ip4s = append(ip4s, ipNet.String())
			} else {
				ip6s = append(ip6s, ipNet.String())
			}
			continue
		}
		// Bare IP.
		ip := net.ParseIP(entry)
		if ip == nil {
			fmt.Fprintf(os.Stderr, "firewall: warning: skipping non-IP entry %s\n", entry)
			continue
		}
		if ip.To4() != nil {
			ip4s = append(ip4s, entry)
		} else {
			ip6s = append(ip6s, entry)
		}
	}
	return ip4s, ip6s
}

// privateRanges returns CIDRs to block for the given iptables binary.
// Prevents LAN scanning, cloud metadata theft, and local network attacks.
func privateRanges(bin string) []string {
	if strings.Contains(bin, "ip6") {
		return []string{
			"::1/128",
			"fc00::/7",
			"fe80::/10",
		}
	}
	return []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
	}
}

// ensureChain flushes and recreates a user-defined chain. Flush and delete
// fail on first run (chain doesn't exist yet) — that's expected.
// Create must succeed.
func ensureChain(bin, table, chain string) error {
	_ = iptRun(bin, "-t", table, "-F", chain)
	_ = iptRun(bin, "-t", table, "-X", chain)
	err := iptRun(bin, "-t", table, "-N", chain)
	if err != nil {
		return fmt.Errorf("%s create chain %s/%s: %w", bin, table, chain, err)
	}
	return nil
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
	err := syscall.Unmount(cgRoot, syscall.MNT_DETACH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: unmount %s: %v\n", cgRoot, err)
	}

	// Mount a fresh cgroup2 scoped to this container's private cgroupns.
	err = syscall.Mount("cgroup2", cgRoot, "cgroup2", 0, "nsdelegate")
	if err != nil {
		// Retry without nsdelegate for older kernels (<5.2).
		err = syscall.Mount("cgroup2", cgRoot, "cgroup2", 0, "")
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

// bootstrapFirewall sets up iptables rules for both agent and pod policies.
//
// Agent policy (filter/OUTPUT): controls agent/sidecar egress.
// Pod policy (mangle/FORWARD): controls nested container egress.
//
// Each policy can be "allow" (default accept, block specific) or "deny"
// (default drop, allow specific). Agent defaults to deny, pod defaults to allow.
func bootstrapFirewall() error {
	agentPolicy := os.Getenv("SANDBOX_AGENT_POLICY")
	if agentPolicy == "" {
		agentPolicy = "deny"
	}
	podPolicy := os.Getenv("SANDBOX_POD_POLICY")
	if podPolicy == "" {
		podPolicy = "allow"
	}

	var agentIPs []string
	allow := os.Getenv("SANDBOX_AGENT_ALLOW")
	if allow != "" {
		for e := range strings.SplitSeq(allow, ",") {
			e = strings.TrimSpace(e)
			if e != "" {
				agentIPs = append(agentIPs, e)
			}
		}
	}

	ip4s, ip6s := classifyIPs(agentIPs)

	for _, bin := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} {
		var dests []string
		if strings.Contains(bin, "ip6") {
			dests = ip6s
		} else {
			dests = ip4s
		}
		err := buildAgentChain(bin, agentPolicy, dests)
		if err != nil {
			return fmt.Errorf("agent chain (%s): %w", bin, err)
		}
		err = buildPodChain(bin, podPolicy)
		if err != nil {
			return fmt.Errorf("pod chain (%s): %w", bin, err)
		}
	}

	fmt.Fprintf(os.Stderr, "firewall: agent=%s (%d IPv4, %d IPv6), pod=%s\n",
		agentPolicy, len(ip4s), len(ip6s), podPolicy)
	return nil
}

// buildAgentChain configures filter/OUTPUT for agent egress.
//
// deny mode: loopback → established → private CIDRs DROP → DNS ACCEPT →
//
//	static TCP 443 per-IP → AGENT_ALLOW → DROP
//
// allow mode: loopback → established → AGENT_ALLOW → private CIDRs DROP →
//
//	AGENT_BLOCK → ACCEPT
func buildAgentChain(bin, policy string, staticIPs []string) error {
	err := ensureChain(bin, "filter", chainAgentAllow)
	if err != nil {
		return err
	}
	err = ensureChain(bin, "filter", chainAgentBlock)
	if err != nil {
		return err
	}

	err = iptRun(bin, "-F", "OUTPUT")
	if err != nil {
		return fmt.Errorf("flush OUTPUT: %w", err)
	}

	err = iptRun(bin, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("loopback: %w", err)
	}
	err = iptRun(bin, "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("established: %w", err)
	}

	if policy == "deny" {
		for _, cidr := range privateRanges(bin) {
			err = iptRun(bin, "-A", "OUTPUT", "!", "-o", "lo", "-d", cidr, "-j", "DROP")
			if err != nil {
				return fmt.Errorf("private %s: %w", cidr, err)
			}
		}
		// DNS (port 53) is always allowed, enabling DNS tunneling
		// for data exfiltration (dnscat2, iodine). Rate limiting mitigates but
		// does not eliminate the risk.
		err = iptRun(bin, "-A", "OUTPUT", "-p", "udp", "--dport", "53",
			"-m", "limit", "--limit", "10/s", "--limit-burst", "20", "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("dns udp: %w", err)
		}
		err = iptRun(bin, "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DROP")
		if err != nil {
			return fmt.Errorf("dns udp drop: %w", err)
		}
		err = iptRun(bin, "-A", "OUTPUT", "-p", "tcp", "--dport", "53",
			"-m", "limit", "--limit", "10/s", "--limit-burst", "20", "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("dns tcp: %w", err)
		}
		err = iptRun(bin, "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "DROP")
		if err != nil {
			return fmt.Errorf("dns tcp drop: %w", err)
		}
		for _, dest := range staticIPs {
			err = iptRun(bin, "-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-d", dest, "-j", "ACCEPT")
			if err != nil {
				return fmt.Errorf("allow %s: %w", dest, err)
			}
		}
		err = iptRun(bin, "-A", "OUTPUT", "-j", chainAgentAllow)
		if err != nil {
			return fmt.Errorf("jump %s: %w", chainAgentAllow, err)
		}
		err = iptRun(bin, "-A", "OUTPUT", "-j", "DROP")
		if err != nil {
			return fmt.Errorf("terminal drop: %w", err)
		}

		return nil
	}

	err = iptRun(bin, "-A", "OUTPUT", "-j", chainAgentAllow)
	if err != nil {
		return fmt.Errorf("jump %s: %w", chainAgentAllow, err)
	}
	for _, cidr := range privateRanges(bin) {
		err = iptRun(bin, "-A", "OUTPUT", "!", "-o", "lo", "-d", cidr, "-j", "DROP")
		if err != nil {
			return fmt.Errorf("private %s: %w", cidr, err)
		}
	}
	err = iptRun(bin, "-A", "OUTPUT", "-j", chainAgentBlock)
	if err != nil {
		return fmt.Errorf("jump %s: %w", chainAgentBlock, err)
	}
	err = iptRun(bin, "-A", "OUTPUT", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("terminal accept: %w", err)
	}

	return nil
}

// buildPodChain configures mangle/FORWARD for nested container egress.
//
// allow mode: established → loopback → POD_ALLOW → private CIDRs DROP →
//
//	POD_BLOCK → ACCEPT
//
// deny mode: established → loopback → DNS ACCEPT → POD_ALLOW → DROP.
func buildPodChain(bin, policy string) error {
	err := ensureChain(bin, "mangle", chainPodAllow)
	if err != nil {
		return err
	}
	err = ensureChain(bin, "mangle", chainPodBlock)
	if err != nil {
		return err
	}

	err = iptRun(bin, "-t", "mangle", "-F", "FORWARD")
	if err != nil {
		return fmt.Errorf("flush FORWARD: %w", err)
	}

	err = iptRun(bin, "-t", "mangle", "-A", "FORWARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("established: %w", err)
	}
	err = iptRun(bin, "-t", "mangle", "-A", "FORWARD", "-o", "lo", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("loopback: %w", err)
	}

	if policy == "allow" {
		err = iptRun(bin, "-t", "mangle", "-A", "FORWARD", "-j", chainPodAllow)
		if err != nil {
			return fmt.Errorf("jump %s: %w", chainPodAllow, err)
		}
		for _, cidr := range privateRanges(bin) {
			err = iptRun(bin, "-t", "mangle", "-A", "FORWARD", "!", "-o", "lo", "-d", cidr, "-j", "DROP")
			if err != nil {
				return fmt.Errorf("private %s: %w", cidr, err)
			}
		}
		err = iptRun(bin, "-t", "mangle", "-A", "FORWARD", "-j", chainPodBlock)
		if err != nil {
			return fmt.Errorf("jump %s: %w", chainPodBlock, err)
		}
		err = iptRun(bin, "-t", "mangle", "-A", "FORWARD", "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("terminal accept: %w", err)
		}

		return nil
	}

	err = iptRun(bin, "-t", "mangle", "-A", "FORWARD", "-p", "udp", "--dport", "53", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("dns udp: %w", err)
	}
	err = iptRun(bin, "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("dns tcp: %w", err)
	}
	err = iptRun(bin, "-t", "mangle", "-A", "FORWARD", "-j", chainPodAllow)
	if err != nil {
		return fmt.Errorf("jump %s: %w", chainPodAllow, err)
	}
	// Terminal DROP covers all remaining traffic, including private CIDRs.
	// In allow mode, private CIDRs are blocked explicitly before the terminal
	// ACCEPT; here they are implicitly covered by this DROP — same effect.
	err = iptRun(bin, "-t", "mangle", "-A", "FORWARD", "-j", "DROP")
	if err != nil {
		return fmt.Errorf("terminal drop: %w", err)
	}

	return nil
}

// setImmutable sets the immutable flag (chattr +i) on a file via ioctl.
func setImmutable(path string) {
	const iocGetFlags = 0x80086601 // FS_IOC_GETFLAGS
	const iocSetFlags = 0x40086602 // FS_IOC_SETFLAGS
	const immutable = 0x00000010   // FS_IMMUTABLE_FL

	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: chattr +i %s: open: %v\n", path, err)
		return
	}
	defer f.Close()

	var flags int
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), iocGetFlags, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "warning: chattr +i %s: getflags: %v\n", path, errno)
		return
	}
	flags |= immutable
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), iocSetFlags, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "warning: chattr +i %s: setflags: %v\n", path, errno)
	}
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

	// Make identity files immutable (chattr +i). An attacker who
	// compromises the sidecar could remount / read-write and bypass
	// the bind-mount RO protection below, but the immutable flag
	// requires CAP_LINUX_IMMUTABLE in the init user namespace to
	// clear — which rootless containers don't have.
	setImmutable(dir + "/uid")
	setImmutable(dir + "/gid")

	// Bind-mount the directory read-only as a secondary defense.
	err = bindMount(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: bind mount %s: %v\n", dir, err)
		return
	}
	err = remountRO(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: remount ro %s: %v\n", dir, err)
	}
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: entrypoint <command> [args...]")
	}

	// Unmount whatever the runtime placed over /proc/sys and remount read-only.
	// Prevents /proc/sys/kernel/core_pattern write (host code execution via
	// core dumps) and /proc/sys/kernel/modprobe write (arbitrary module load).
	// Fails if nothing is mounted — not an error.
	err := syscall.Unmount("/proc/sys", syscall.MNT_DETACH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: unmount /proc/sys: %v\n", err)
	}

	// /proc/sys is now real procfs — writable, namespace-scoped.
	// Lock it all down read-only.
	err = bindMount("/proc/sys")
	if err != nil {
		fatalf("bind /proc/sys: %v", err)
	}
	err = remountRO("/proc/sys")
	if err != nil {
		fatalf("remount ro /proc/sys: %v", err)
	}

	// Punch a writable hole for /proc/sys/net only (namespace-scoped, safe)
	err = bindMount("/proc/sys/net")
	if err != nil {
		fatalf("bind /proc/sys/net: %v", err)
	}
	err = remountRW("/proc/sys/net")
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

	// exec the command — replaces this process.
	err = syscall.Exec(os.Args[1], os.Args[1:], os.Environ())
	if err != nil {
		fatalf("exec %s: %v", os.Args[1], err)
	}
}
