<\!-- SPDX-License-Identifier: GPL-3.0-only -->

# Security policy

## Reporting a vulnerability

Report security issues via **GitHub Security Advisories** on this repository — not as public issues. This keeps details private until a fix is ready.

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
- **Privilege escalation** — `cap-drop=ALL`, `no-new-privileges`, seccomp (~115 blocked syscalls)
- **Host modification** — sidecar UID mapping + host-side inotify tripwire (snapshot + restore)
- **Nested container breakout** — OCI hooks enforce 15 security checks on every `podman run`

For a complete description of all defense layers, see [`DIAGRAM.md`](DIAGRAM.md).

## Known limitations

These are accepted design constraints, not bugs. They are disclosed here so users can make informed trust decisions.

**Build containers skip Landlock.**
`podman build` uses buildah internally, which does not invoke the `precreate` OCI hook. Build containers receive seccomp enforcement and the `createRuntime` security-policy checks, but not Landlock filesystem MAC or UID enforcement via seal-inject. This is a limitation of the OCI hook specification — `precreate` is a podman extension not implemented in buildah.

**Egress filtering is IP-based, not domain-based.**
The agent firewall resolves the domain allowlist to IP addresses at session startup and installs iptables rules for those IPs. A sufficiently motivated agent could exfiltrate data via DNS queries (rate-limited to 10/s) or by using allowlisted IP addresses after connecting through them. A DNS-intercepting proxy would close this gap but is not currently implemented.

**No kernel isolation boundary.**
Clampdown uses containers, not virtual machines. The agent shares the host kernel. A kernel exploit executed by the agent could break out of all container-level protections. The seccomp profiles eliminate the majority of known kernel exploit primitives (io_uring, userfaultfd, splice/tee, bpf, perf_event_open, etc.), but this is defense-in-depth, not a hard boundary. For workloads requiring kernel-level isolation, a VM-based backend is required.

**Kernel CVEs.**
Syscalls that remain allowed (file I/O, networking, process management) may be affected by kernel CVEs that cannot be blocked at the container layer. Monitor your kernel version against known CVEs.

## Kernel requirements

| Requirement | Minimum kernel | Behavior if absent |
|-------------|---------------|---------------------|
| Landlock V3 (filesystem MAC) | 6.2 | Hard fail — session refuses to start |
| Landlock V4 (TCP connect, ioctl) | 6.7 | BestEffort — degraded silently |
| Landlock V6 (IPC scoping) | 6.7 | Warning — abstract unix socket isolation degraded |
| Landlock V7 | 6.10 | BestEffort — optional rights degrade silently |
| cgroup v2 | 5.2 | Required for `pids_limit` enforcement |
