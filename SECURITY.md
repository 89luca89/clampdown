<\!-- SPDX-License-Identifier: GPL-3.0-only -->

# Security policy

## Reporting a vulnerability

Report security issues via **GitHub Security Advisories** on this repository
not as public issues. This keeps details private until a fix is ready.

Navigate to the **Security** tab → **Advisories** → **New draft security advisory**.

Include:
- Description of the issue
- Steps to reproduce
- Affected components (launcher, sidecar, sandbox-seal, OCI hooks, network policy)
- Whether you have a suggested fix

## Threat model

Clampdown runs an AI coding agent inside a hardened container sandbox. The sandbox is designed to isolate the agent from:

- **Host filesystem** — Landlock filesystem MAC + read-only rootfs + protected `.git` and config paths
- **Network exfiltration** — iptables default-deny allowlist scoped to required API domains
- **Privilege escalation** — `cap-drop=ALL`, `no-new-privileges`, seccomp (~150 blocked syscalls)
- **Host modification** — sidecar UID mapping + host-side inotify tripwire (snapshot + restore)
- **Nested container breakout** — OCI hooks enforce 18 security checks on every `podman run`, seccomp profile validated against canonical rules
- **Kernel exploit primitives** — seccomp blocks io_uring, eBPF, MSG_OOB, MAP_GROWSDOWN, POSIX MQ, TTY line discipline change, splice/vmsplice,
  memfd_create, all namespace creation flags, all filesystem-admin ioctls
- **Info disclosure** — sensitive /proc and /sys paths masked with /dev/null in all containers (agent, sidecar, proxy, nested); storage mount scoped to container ID

For a complete description of all defense layers, see [`DIAGRAM.md`](DIAGRAM.md).

## Known limitations

These are accepted design constraints, not bugs. They are disclosed here so users can make informed trust decisions.

**Build containers skip Landlock.**
`podman build` uses buildah internally, which does not invoke the `precreate` OCI hook. Build containers receive seccomp enforcement,
the `createRuntime` security-policy checks (18 checks), and sensitive path masking via containers.conf volumes, but not Landlock filesystem MAC or UID enforcement via seal-inject.
This is a limitation of the OCI hook specification — `precreate` is a podman extension not implemented in buildah.

**Egress filtering is IP-based, not domain-based.**
The agent firewall resolves the domain allowlist to IP addresses at session startup and installs iptables rules for those IPs.
A sufficiently motivated agent could exfiltrate data via DNS queries (rate-limited to 10/s) or by using allowlisted IP addresses
after connecting through them. A DNS-intercepting proxy would close this gap but is not currently implemented.

**No kernel isolation boundary (containers share the VM/host kernel).**
Clampdown uses containers, not hypervisor VMs. On native Linux, the agent
shares the host kernel.
A kernel exploit could break out of container-level protections within the Linux
kernel the containers run on. This section documents exactly what clampdown
can and cannot prevent.
It is possible to use a VM backend (podman machine, colima),
so the host kernel is not exposed.

*What clampdown mitigates.*

The seccomp profiles eliminate the exploit
primitive required by the majority of **known** kernel escape CVEs.
That's the point, it cannot prevent unknown CVEs at the moment.

*What clampdown cannot prevent at all.*

Three kernel bug classes use only
syscalls that every container workload requires. No seccomp profile, no
capabilities, no Landlock, no namespaces can block them:

| Bug class | Syscalls | Why unfilterable |
|-----------|----------|-----------------|
| futex UAF | `futex()` | Required for all threading (pthreads, Go, Node.js) |
| AF_UNIX GC race | `socket(AF_UNIX)`, `sendmsg(SCM_RIGHTS)`, `recvmsg(MSG_PEEK)` | Required for all container IPC |
| Dirty COW class | `mmap()`, `madvise()`, `write()` to `/proc/self/mem` | Required for memory management; /proc/self/mem unmaskable |

The host-side inotify tripwire detects post-exploitation host file
modifications and restores from sha256-verified snapshots. It cannot
prevent the exploit — it detects and contains the damage after the fact.

### VM-level isolation

When using a VM backend (podman machine, colima), clampdown runs inside
a Linux VM. The host kernel is never exposed to the agent. A kernel
exploit inside the VM cannot reach the host, it is contained by the
hypervisor boundary.

On native Linux (no VM), containers share the host kernel directly. Users
who want stronger isolation can use podman machine or colima even on Linux.
Advisable for profiles where isolation from the host kernel is paramount.

## Kernel requirements

These apply to the Linux kernel the containers run on — the host kernel
on native Linux, or the VM kernel on macOS (podman machine / colima).

| Requirement | Minimum kernel | Behavior if absent |
|-------------|---------------|---------------------|
| Landlock V3 (filesystem + Truncate) | 6.2 | Hard fail — session refuses to start |
| Landlock V4 (TCP connect) | 6.7 | BestEffort — TCP port restriction unavailable |
| Landlock V5 (IoctlDev) | 6.10 | BestEffort — device ioctl control unavailable |
| Landlock V6 (IPC scoping) | 6.12 | Warning — abstract unix socket + signal isolation degraded |
| Landlock V7 (audit logging) | 6.15 | BestEffort — denied access logging unavailable |
| cgroup v2 | 5.2 | Required for `pids_limit` enforcement |

### VM backend security properties

When running via podman machine or colima, the VM boundary provides
additional isolation that native Linux containers lack:

- The host kernel is not exposed to the agent (hypervisor boundary).
- A kernel exploit inside the VM is contained by the hypervisor.
- The VM kernel (Fedora / Ubuntu) ships with full Landlock support.
- Docker Desktop is explicitly blocked at the moment: its `fakeowner` FUSE filesystem
  is incompatible with Landlock enforcement. Use colima or podman machine
  instead.
