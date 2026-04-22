<!-- SPDX-License-Identifier: GPL-3.0-only -->

# clampdown Security Model

## Container Topology

```
┌──────────────────────────────────────────────────────────────────────────┐
│ HOST                                                                     │
│                                                                          │
│  ┌───────────────┐                                                       │
│  │  Launcher     │  clampdown CLI (Go binary)                            │
│  │  (host PID)   │  Checks Landlock LSM, resolves DNS allowlists,        │
│  │               │  writes seccomp, starts sidecar, proxy, agent.        │
│  └──────┬────────┘                                                       │
│         │                                                                │
│         │  podman run (rootless)                                         │
│         │                                                                │
│  ┌──────▼───────────────────────────────────────────────────────────┐    │
│  │ SIDECAR CONTAINER  (FROM scratch, read-only rootfs)              │    │
│  │                                                                  │    │
│  │  PID 1: /entrypoint (persistent supervisor)                      │    │
│  │    1. Harden /proc/sys (bind-mount read-only)                    │    │
│  │    2. Bootstrap cgroup v2 (nsdelegate, controllers)              │    │
│  │    3. Build iptables firewall (agent + pod chains)               │    │
│  │    4. Write /run/sandbox/{uid,gid}, bind-mount RO                │    │
│  │    5. Discover protected paths, harden PID 1                     │    │
│  │    6. Install seccomp-notif filter -> supervisor goroutine       │    │
│  │    7. Start podman system service as child process               │    │
│  │                                                                  │    │
│  │  Storage: native kernel overlay (no /dev/fuse, no fuse-overlayfs)│    │
│  │  Masked /proc paths: devices, diskstats, kallsyms, kcore,        │    │
│  │    modules, partitions, version, sysrq-trigger, vmcoreinfo       │    │
│  │                                                                  │    │
│  │  Seccomp: seccomp_sidecar.json (denylist, ~100 blocked)          │    │
│  │    Blocks: io_uring, perf_event_open, userfaultfd, modify_ldt,   │    │
│  │    kcmp, process_madvise, kexec_*, init/delete/finit_module,     │    │
│  │    add_key, request_key, splice/tee/vmsplice (pipe exploitation),│    │
│  │    open_by_handle_at, name_to_handle_at, swapoff/swapon, acct,   │    │
│  │    vhangup, reboot, quotactl, fanotify_init/mark,                │    │
│  │    adjtimex/clock_adjtime*, remap_file_pages,                    │    │
│  │    ioperm/iopl, clock_settime, personality (arg-filtered),       │    │
│  │    TIOCSTI/TIOCLINUX/TIOCSETD, SIOCATMARK,                       │    │
│  │    IOC_WATCH_QUEUE_SET_FILTER (watch queue class),               │    │
│  │    MSG_OOB arg-filtered (AF_UNIX UAF class), mq_* (mq_notify     │    │
│  │    UAF class), MAP_GROWSDOWN (VMA stack expansion class),        │    │
│  │    FS_IOC_FIEMAP (physical block offset disclosure),             │    │
│  │    all btrfs/DM/loop/f2fs/nilfs2/reiserfs/bcachefs/FUSE ioctls,  │    │
│  │    XFS/ext4/fscrypt/fsverity/blkdev admin ioctls,                │    │
│  │    socket family >= 17, obsolete syscalls.                       │    │
│  │    Allows: mount, bpf, clone3, seccomp, keyctl, ptrace           │    │
│  │    -- needed by podman/crun for container management.            │    │
│  │                                                                  │    │
│  │  Seccomp-notif supervisor (entrypoint filter, on top of above):  │    │
│  │    Intercepts 20 syscalls via SECCOMP_RET_USER_NOTIF:            │    │
│  │    mount, umount2, mount_setattr, move_mount, open_tree,         │    │
│  │    fsopen, fsconfig, fsmount, ptrace, process_vm_readv/writev,   │    │
│  │    execve, execveat, openat, unlinkat, symlinkat, linkat,        │    │
│  │    renameat2, setsockopt, socket.                                │    │
│  │    Policy: BLOCK mount/umount targeting protected paths,         │    │
│  │    BLOCK bind sources not in allowlist (workdir, %CID%-scoped    │    │
│  │      runtime plumbing, validated named volumes, rootfs files),   │    │
│  │    BLOCK non-recursive bind stripping /dev/null sub-mounts,      │    │
│  │    BLOCK procfs mount from sidecar PID namespace,                │    │
│  │    BLOCK ptrace/process_vm_* targeting PID 1,                    │    │
│  │    BLOCK execve/execveat not in SHA-256 startup allowlist        │    │
│  │      (sidecar PID NS only; nested containers skip),              │    │
│  │    BLOCK openat of /proc/1/* sensitive paths from sidecar PID NS,│    │
│  │    BLOCK unlinkat/symlinkat/linkat/renameat2 on protected paths, │    │
│  │    BLOCK setsockopt(IPT_SO_SET_REPLACE) except                   │    │
│  │      xtables-nft-multi spawned by netavark,                      │    │
│  │    BLOCK socket(AF_NETLINK, NETLINK_NETFILTER) except            │    │
│  │      xtables-nft-multi spawned by netavark.                      │    │
│  │    ALLOW otherwise.                                              │    │
│  │    Inherited by all children (podman, crun, nested containers).  │    │
│  │    For agent/nested: workload profile returns ERRNO for mount    │    │
│  │    (stricter than USER_NOTIF), so supervisor only handles        │    │
│  │    sidecar-level processes that legitimately need mount().       │    │
│  │                                                                  │    │
│  │  OCI Hooks (intercept nested container lifecycle):               │    │
│  │    precreate:    seal-inject (policy, UID, seal mount)           │    │
│  │    createRuntime: security-policy (18 checks)                    │    │
│  │                                                                  │    │
│  │  ┌─────────────────────────────────────────────────────────┐     │    │
│  │  │ NESTED CONTAINERS  (podman run/build inside sidecar)    │     │    │
│  │  │                                                         │     │    │
│  │  │  Seccomp: workload profile (~150 blocked)               │     │    │
│  │  │  Entrypoint: sandbox-seal -- <original command>         │     │    │
│  │  │  Landlock V7 (derived from mounts by seal-inject)       │     │    │
│  │  │  LD_PRELOAD: rename_exdev_shim.so (EXDEV fallback)      │     │    │
│  │  └─────────────────────────────────────────────────────────┘     │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │ AUTH PROXY CONTAINER  (FROM scratch, read-only rootfs)           │    │
│  │                                                                  │    │
│  │  Entrypoint: sandbox-seal -- auth-proxy                          │    │
│  │  Listens: 127.0.0.1:2376 -> upstream API (rewrites auth header)  │    │
│  │                                                                  │    │
│  │  Seccomp: workload profile (~150 blocked)                        │    │
│  │  Landlock: ReadOnly:[/], ReadExec:[/usr/local/bin]               │    │
│  │           ConnectTCP:[443, 53]                                   │    │
│  │  cap-drop=ALL, ulimit core=0:0, 128m, 512 PIDs                   │    │
│  │  No workdir, no HOME, no devices, no shell                       │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │ AGENT CONTAINER  (Alpine, --network container:SIDECAR)           │    │
│  │                                                                  │    │
│  │  Entrypoint: sandbox-seal -- <agent binary>                      │    │
│  │  Seccomp: workload profile (~150 blocked)                        │    │
│  │  Landlock: workdir RWX, rootfs RO, ConnectTCP:[443,2375,2376]    │    │
│  │  cap-drop=ALL, no-new-privileges, read-only rootfs               │    │
│  │                                                                  │    │
│  │  API keys: sk-proxy (dummy), BASE_URL=http://localhost:2376      │    │
│  │  Protected paths: .git/hooks, .mcp.json, etc. (RO)               │    │
│  │  Masked paths: .env, .envrc, .npmrc, .clampdownrc (/dev/null)    │    │
│  │  Inter-container comm: podman networks (not -p port publishing)  │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

## Network Policy

```
                    ┌─────────────────────────┐
                    │      INTERNET           │
                    └────────┬────────────────┘
                             │
              ┌──────────────▼────────────────┐
              │  SIDECAR NETWORK NAMESPACE    │
              │  (shared by proxy + agent)    │
              │                               │
              │  127.0.0.1:2375  podman API   │
              │  127.0.0.1:2376  auth proxy   │
              │                               │
              │  filter/OUTPUT (agent egress) │
              │  ┌────────────────────────┐   │
              │  │ 1. ACCEPT loopback     │   │
              │  │ 2. ACCEPT established  │   │
              │  │ 3. ACCEPT DNS :53      │   │
              │  │    (10/s burst 20)     │   │
              │  │ 4. ACCEPT allowlist    │   │
              │  │    host:port           │   │
              │  │ 5. REJECT private CIDRs│   │
              │  │ 6. -> AGENT_ALLOW      │   │
              │  │ 7. REJECT (default)    │   │
              │  └────────────────────────┘   │
              │                               │
              │  mangle/FORWARD (pod egress)  │
              │  ┌────────────────────────┐   │
              │  │ 1. ACCEPT established  │   │
              │  │ 2. ACCEPT loopback     │   │
              │  │ 3. -> POD_ALLOW        │   │
              │  │ 4. DROP private CIDRs  │   │
              │  │ 5. -> POD_BLOCK        │   │
              │  │ 6. ACCEPT (default)    │   │
              │  └────────────────────────┘   │
              └───────────────────────────────┘

Blocked CIDRs (IPv4):              Blocked CIDRs (IPv6):
  10.0.0.0/8                         ::1/128
  172.16.0.0/12                      fc00::/7
  192.168.0.0/16                     fe80::/10
  127.0.0.0/8
  169.254.0.0/16 (cloud metadata)
```

## API Key Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────────┐
│   AGENT     │     │  AUTH PROXY  │     │   UPSTREAM API      │
│             │     │              │     │                     │
│ API_KEY=    │     │ Holds real   │     │ api.anthropic.com   │
│ "sk-proxy"  │────▶│ API key      │────▶│                     │
│             │     │              │     │                     │
│ BASE_URL=   │     │ Strips dummy │     │ Receives real       │
│ localhost:  │     │ key, injects │     │ x-api-key header    │
│ 2376        │     │ real key     │     │                     │
└─────────────┘     └──────────────┘     └─────────────────────┘
```

## Capability Model

```
                    Host caps
                        │
           ┌────────────▼────────────┐
           │  SIDECAR (16 caps)      │
           │  SYS_ADMIN  NET_ADMIN   │
           │  SYS_CHROOT SYS_PTRACE  │
           │  SYS_RESOURCE           │
           │  CHOWN  DAC_OVERRIDE    │
           │  FOWNER FSETID  KILL    │
           │  MKNOD  SETFCAP         │
           │  SETGID SETUID SETPCAP  │
           │  NET_BIND_SERVICE       │
           └────────────┬────────────┘
                        │
           ┌────────────▼────────────┐
           │  PROXY + AGENT (0 caps) │
           │  cap-drop=ALL           │
           └────────────┬────────────┘
                        │
           ┌────────────▼────────────┐
           │  NESTED (10 default)    │
           │  CHOWN DAC_OVERRIDE     │
           │  FOWNER FSETID KILL     │
           │  NET_BIND_SERVICE       │
           │  SETFCAP SETGID SETPCAP │
           │  SETUID                 │
           │                         │
           │  Effective: empty       │
           │  (non-root + no ambient │
           │   + no_new_privileges)  │
           └─────────────────────────┘
```

## OCI Hook Pipeline

```
podman run ...
     │
     ▼
┌──────────────────────────────────────────────┐
│  PRECREATE: seal-inject                      │
│                                              │
│  1. Overwrite process.user -> sandbox UID/GID│
│  2. Prepend /.sandbox/seal -- to args        │
│  3. Derive Landlock policy from mounts       │
│  4. Inject SANDBOX_POLICY env var            │
│  5. Add /.sandbox/seal bind mount            │
│  6. Add hidepid=2 to proc mount              │
│  7. Inject opt-in credentials                │
└──────────────────┬───────────────────────────┘
                   │
     container created (crun)
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│  CREATERUNTIME: security-policy (18 checks)     │
│                                                 │
│   1. checkCaps             -> EPERM             │
│   2. checkSeccomp (rules match canonical) EPERM │
│   3. checkNoNewPrivileges  -> EPERM             │
│   4. checkMACDisabled      -> EPERM             │
│   5. checkNamespaces       -> EOPNOTSUPP        │
│   6. checkMounts           -> EACCES            │
│   7. checkMountOptions     -> EACCES            │
│   8. checkMountPropagation -> EPERM             │
│   9. checkRootfsPropagation-> EPERM             │
│  10. checkDevices          -> EACCES            │
│  11. checkMaskedPaths      -> EPERM             │
│  12. checkReadonlyPaths    -> EPERM             │
│  13. checkSysctl           -> EPERM             │
│  14. checkRlimits          -> EPERM             │
│  15. checkImageRef         -> EACCES/warn       │
│  16. checkMountReadonly    -> EACCES            │
│  17. checkProcMount        -> EPERM             │
│  18. checkAdditionalGids   -> EPERM             │
└──────────────────┬──────────────────────────────┘
                   │
     container process starts
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  sandbox-seal (PID 1 of nested container)   │
│                                             │
│  1. Parse SANDBOX_POLICY                    │
│  2. applyLandlock (V7 BestEffort)           │
│     -> Filesystem (4 tiers + Refer)         │
│     -> IoctlDev in write tiers (V5+)        │
│     -> IPC scoping (V6+)                    │
│     -> ConnectTCP (V4+, if specified)       │
│  3. closeExtraFDs (>= 3 -> close-on-exec)   │
│  4. exec -> original entrypoint             │
└─────────────────────────────────────────────┘
```

---

## How It Works

### Startup sequence

The launcher runs on the host as a normal user process. Before starting
any containers, it verifies that Landlock is available in the kernel and
warns if Yama ptrace scope is too permissive or the runtime is rootful.
It resolves the agent's domain allowlist to IP addresses, writes seccomp
profiles to disk, and cleans up stale containers from previous sessions.

The sidecar starts first in detached mode. Its entrypoint hardens
/proc/sys, bootstraps cgroup v2, builds the iptables firewall, writes
the sandbox identity files (UID/GID, bind-mounted read-only), discovers
protected paths from /proc/self/mountinfo, hardens PID 1
(PR_SET_DUMPABLE=0, /proc/1/mem masked with /dev/null), builds the
exec allowlist (SHA-256 hashes of every rootfs executable), installs
a seccomp-notif filter that intercepts 20 syscalls (mount, exec, path
ops, firewall, ptrace — with bind source allowlist scoped to the
container ID), and starts the supervisor goroutine. The entrypoint
then starts podman system service
as a child process (not exec -- the supervisor must remain as PID 1 to
handle notifications).

Once the sidecar's podman API responds, the launcher checks whether an
API key is available (from the host environment or .clampdownrc). If a
key is found, the auth proxy starts in detached mode. The launcher waits
for the "proxy: ready" log line, then starts the agent in detached mode.
If no key is found, the agent starts without a proxy and a warning is
printed.

The sidecar and proxy run with `--restart=unless-stopped` and the agent
with `--restart=on-failure` -- they persist across terminal disconnects
and the agent restarts automatically on crash. The launcher then attaches to the
agent container (`podman attach --detach-keys=ctrl-]`). The user can
detach with `ctrl+]` and reattach later with `clampdown attach -s <id>`.

Sessions are identified by a 6-character random hex ID (not the
launcher PID). Session state is persisted to `$STATE/session-<id>.json`
for stop/delete operations.

`clampdown stop` stops all containers for a session.
`clampdown delete` removes stopped containers and cleans up temp files.

### API key isolation

The agent never receives real API credentials. The launcher gives it a
dummy key (`sk-proxy`) and overrides the API base URL to point at the
local proxy on port 2376. The proxy receives the agent's request, strips
the dummy auth header, injects the real API key, and forwards the
request to the upstream API. The proxy logs every request with model
name, method, path, status, sizes, and duration to stderr using the
`clampdown:` prefix for audit trail integration.

Keys are resolved from two sources: the host environment and
.clampdownrc. Neither source is forwarded into the agent container.

For Claude, the SDK reads `ANTHROPIC_BASE_URL` directly. For OpenCode,
most providers do not support a base URL environment variable. The
launcher instead injects `OPENCODE_CONFIG_CONTENT` with the proxy URL,
which OpenCode deep-merges at highest precedence over all other config.
Each agent uses one provider at a time -- the first matching key wins.

Even if the agent connects to the upstream API directly on port 443
(allowed by Landlock for infrastructure like models.dev and telemetry),
it sends `sk-proxy` as the key and gets 401. The real key only exists
inside the proxy container, which has no shell, no writable filesystem,
no capabilities, and core dumps disabled.

### Landlock enforcement

sandbox-seal is the Landlock enforcement binary. It runs as the
entrypoint wrapper for the agent, the proxy, and all nested containers.
It reads a JSON policy from `SANDBOX_POLICY`, applies Landlock V7
filesystem rules (four access tiers with IoctlDev for TTY operations),
IPC scoping, and optional TCP port restriction, closes leaked file
descriptors, then execs the real entrypoint.

The agent's policy is built by the launcher from its mount
configuration. The proxy gets a minimal read-only policy with TCP
restricted to ports 443 and 53. Nested container policies are derived
at runtime by the seal-inject OCI hook from each container's mount list.

Landlock requires kernel 6.2+ (ABI V3). Features from V4-V7 degrade
gracefully via BestEffort. Landlock cannot be applied to the sidecar
because mount() internally triggers Landlock path hooks (EPERM).

### Sidecar supervisor

The sidecar cannot use Landlock (mount() triggers Landlock path hooks
internally -> EPERM). The seccomp-notif supervisor compensates by
intercepting 20 syscalls at the kernel level, covering mount
operations (including bind source allowlist with %CID%-scoped
infrastructure mounts and validated named volumes), exec
verification, protected-path file operations, process targeting,
and firewall modification.

The entrypoint installs a seccomp BPF filter using
`SECCOMP_RET_USER_NOTIF` for 20 syscalls. When any sidecar-level
process invokes these, the kernel suspends the caller and delivers
the notification to the supervisor goroutine, which evaluates the
call against policy and either continues the syscall or returns an
error.

Protected paths are discovered dynamically from `/proc/self/mountinfo`
at startup: all read-only bind mounts under the workdir (protected
files like `.git/hooks`), all `/dev/null` mounts (masked files like
`.env`), plus `/proc/sys` and `/proc/1` unconditionally.

**Mount supervision** (mount, umount2, mount_setattr, move_mount,
open_tree, fsopen, fsconfig, fsmount):
- `umount2` on any protected or masked path
- `mount` targeting a protected path (prevents overlay, remount, tmpfs over it)
- Non-recursive `mount(MS_BIND)` where the source is the workdir or an
  ancestor (strips `/dev/null` sub-mounts, exposing masked file contents)
- `mount("proc")` from the sidecar's PID namespace (new procfs would
  expose `/proc/1/mem` without the `/dev/null` mask)
- Bind mount sources not in the allowlist (workdir, container-specific
  runtime plumbing at `/var/run/containers/storage/overlay-containers/%CID%`,
  named volumes validated via `isValidVolumeMount()`, credential forwarding,
  and rootfs files). Blocks `-v /var/lib/containers/storage:/x` (V-02).
- `mount_setattr` / `move_mount` on protected paths
- Non-recursive `open_tree(OPEN_TREE_CLONE)` of the workdir or ancestors
  (same sub-mount stripping attack as non-recursive bind)
- `fsopen("proc")` from the sidecar's PID namespace
- All filesystem-admin ioctls blocked at seccomp level (btrfs, DM, loop,
  XFS, ext4, f2fs, nilfs2, reiserfs, bcachefs, FUSE — via magic-byte
  matching; FICLONE/FICLONERANGE explicitly allowed for cp --reflink)

**Exec allowlist** (execve, execveat):
At startup, the supervisor walks the rootfs (same device only, skipping
mount points) and SHA-256 hashes every executable file, storing the
hash alongside stat metadata (dev, ino, size, mtime) in an immutable
map. On execve/execveat from sidecar PID NS processes: the path is
resolved (symlinks, cwd, dirfd, AT_EMPTY_PATH for execveat), then
verified against the allowlist via a fast path (stat metadata match)
or slow path (re-hash on metadata mismatch). Binaries not in the
startup snapshot are blocked with EACCES. Nested container processes
(different PID NS) skip the check entirely -- their exec is governed
by Landlock and the workload seccomp profile.

**Protected-path operations** (openat, unlinkat, symlinkat, linkat,
renameat2):
- `openat` of `/proc/1/{mem,environ,maps,root,cwd,exe,stack,syscall,
  io,auxv,pagemap}` from sidecar PID NS (defense-in-depth behind the
  `/dev/null` mask on `/proc/1/mem` and the mount supervisor blocking
  unmounts)
- `unlinkat` / `symlinkat` / `linkat` / `renameat2` targeting any
  protected or masked path (prevents deletion, replacement, or renaming
  of files the mount supervisor protects)

**PID 1 protection** (ptrace, process_vm_readv, process_vm_writev):
- `ptrace` / `process_vm_readv` / `process_vm_writev` targeting PID 1

**Firewall lock** (setsockopt, socket):
- `setsockopt(IPT_SO_SET_REPLACE)` blocked unless the caller is
  `/usr/sbin/xtables-nft-multi` with parent `/usr/local/lib/podman/netavark`.
  This is the only legitimate path for netfilter modification inside
  the sidecar (netavark configures per-container bridge rules).
- `socket(AF_NETLINK, NETLINK_NETFILTER)` same policy -- blocks
  creation of netfilter sockets except from the netavark->xtables chain.
- Integer args only (level, optname, domain, protocol) -- zero TOCTOU.
- Key property: `podman exec` from the host enters via `setns()`, not
  `fork()`, so it does NOT inherit the seccomp-notif filter. Legitimate
  firewall changes from the launcher (`clampdown network`) are exempt.
  Only children of PID 1 (spawned by podman inside the sidecar) inherit
  the filter and are subject to the firewall lock.

**Filter inheritance:** The BPF filter is inherited by all children
(kernel guarantee). For agent and nested containers, the workload
seccomp profile returns ERRNO for mount/umount/execveat (stricter than
USER_NOTIF -- the kernel picks the strictest). So the supervisor
effectively only handles sidecar-level processes (podman, crun) that
legitimately need these syscalls for container operations.

**TOCTOU mitigation:** After reading paths from the caller's memory,
the supervisor calls `SECCOMP_IOCTL_NOTIF_ID_VALID` to verify the
notification is still active (the caller hasn't been killed/replaced).
The firewall lock handlers use integer args only (no pointer reads),
eliminating TOCTOU entirely for those checks.

### Network policy

The sidecar, proxy, and agent share one network namespace. Agent egress
is default-deny with a per-IP allowlist resolved from domain names at
startup. DNS is rate-limited to 10 queries/second. Private CIDRs
(RFC 1918, link-local, cloud metadata) are always blocked.

Nested container (pod) egress is default-allow minus private CIDRs.
Dynamic rules can be added at runtime via `clampdown network`.

### OCI hooks

When the agent runs `podman run` inside the sidecar, two OCI hooks
intercept the container lifecycle before the workload starts.

seal-inject (precreate) overwrites the user to the sandbox UID, prepends
sandbox-seal to the entrypoint, derives a Landlock policy from the mount
list, injects credential mounts if present, and adds hidepid=2 to procfs.
Sensitive /proc and /sys paths are masked via containers.conf volumes
(not seal-inject), which applies to both `podman run` and `podman build`.
seal-inject does not run for build containers.

security-policy (createRuntime) validates the container against 17
checks covering capabilities, seccomp (validates profile rules match
the canonical seccomp_nested.json — rejects permissive or gutted
profiles), namespaces, mounts (container-ID-scoped infrastructure
mount allowlist, validated named volume paths), devices, masked paths
(verifies /dev/null or empty-dir bind mounts), readonly paths, sysctls,
rlimits, image refs, mount propagation, /proc mount type, and
supplementary groups. Each violation blocks the container with a
specific errno.

### Host-side tripwire

The launcher monitors all read-only host paths via inotify. Before the
session starts, it snapshots file content and permissions. Any
modification kills the session immediately. On exit, it restores
modified files and removes unexpected ones.

This is the last defense layer. The sidecar's UID mapping prevents
writes (container uid 0 maps to a sub-UID that doesn't own the files),
but a full escape to the host user would bypass in-container protections.
The tripwire runs outside all namespaces and catches that. Enabled with
`--tripwire` (off by default). The tripwire is active only while the
launcher is attached to the session.

### Audit trail

Every session produces a structured audit log. All components emit lines
prefixed with `clampdown: <RFC3339> <source>:` so they can be filtered,
merged, and sorted chronologically across containers.

**Sources:**
- **OCI hooks** (security-policy, seal-inject) -- write to `/proc/1/fd/2`
  (sidecar PID 1 stderr). Log PASS/BLOCKED with container ID, hostname,
  image, command, and Landlock policy summary.
- **Auth proxy** -- logs every API request with model name, method, path,
  status, request/response sizes, and duration.
- **Launcher** -- writes START, STOP, SIGNAL, TAMPER events via the `/log`
  sidecar binary. Firewall changes (allow/block/reset) and image pushes
  are also logged.
- **Tripwire** -- writes TAMPER events directly to the audit file.

The `/log` binary is a standalone static Go binary in the sidecar
(FROM scratch, stdlib only). The launcher calls it via
`podman exec <sidecar> /log <source> <message>` to inject lines into
the sidecar's log stream.

On session end, the launcher reads sidecar and proxy container logs,
filters for `clampdown:` lines, strips the runtime timestamp prefix,
and writes them to a persistent audit file at
`$STATE/audit-<session>.log`. This file survives `clampdown delete`.

`clampdown logs -s <session>` merges and sorts all container logs
chronologically. The agent's full conversation (tool calls, responses,
errors) is also captured in the container logs. Use
`--dump-agent-conversation` to include it -- the output is cleaned of
ANSI escapes and TUI noise, with runtime timestamps preserved for
correlation with audit events.

---

## Agent Guidance (not a security feature)

The sandbox enforces restrictions via kernel mechanisms (seccomp, Landlock,
iptables, capabilities). Those are the security boundary. Nothing below
is part of it.

The guidance layer exists because AI agents waste tokens and rounds hitting
sandbox walls repeatedly. ECONNREFUSED doesn't tell an agent *why* the
connection was refused or *what to do instead*. These helpers translate
kernel errors into actionable instructions at the point of failure.

**Four layers, one message: "use containers."**

```
┌──────────────────────────────────────────────────────────────────┐
│  SANDBOX PROMPT  (sandboxPromptTemplate in agent.go)             │
│                                                                  │
│  Pre-failure prevention. Names specific tools that will fail     │
│  (WebFetch, webfetch, web_fetch, read_url). Maps error codes     │
│  to actions. Read by the model at conversation start.            │
│  Weakest layer -- agents forget under context pressure.          │
├──────────────────────────────────────────────────────────────────┤
│  CLAMPDOWN SKILL  (~/.claude/skills/clampdown/ + ~/.agents/...)  │
│                                                                  │
│  Cross-platform skill (AgentSkills.io). Written at session start │
│  to both directories for Claude Code, Codex, Gemini, OpenCode.   │
│  Invocable via /clampdown when agent forgets constraints.        │
│  Auto-invoke triggers on ECONNREFUSED, permission denied, etc.   │
├──────────────────────────────────────────────────────────────────┤
│  COMMAND HELPER  (sandbox_command_helper.sh, via BASH_ENV)       │
│                                                                  │
│  Shell functions that replace commands which always fail:        │
│  curl, wget, ping, su, sudo, apk + command_not_found_handle.     │
│  Fires before the real command runs. Bash-only (not sh/ash).     │
├──────────────────────────────────────────────────────────────────┤
│  NETWORK HELPER  (sandbox_network_helper.so, via LD_PRELOAD)     │
│                                                                  │
│  Stateless connect()/getsockopt() interceptor. Prints guidance   │
│  to stderr on ECONNREFUSED/ETIMEDOUT from non-loopback hosts.    │
│  Catches everything the shell helper misses: pip, npm, cargo,    │
│  git, python scripts, Node.js HTTP -- any libc connect() caller. │
│  Does NOT intercept Go (raw syscalls) or Bun (io_uring).         │
└──────────────────────────────────────────────────────────────────┘
```

Prompt and skill are AI-level guidance. Helpers are OS-level fallbacks.
All layers return error codes unchanged -- they add guidance, not behavior.
Removing them changes nothing about what the agent can or cannot do.

---

## Reference

### Seccomp profiles

Two profiles exist. The **sidecar profile** (~100 blocked syscalls) is a
denylist that blocks what the container engine never needs while allowing
mount, bpf, ptrace, and clone for podman. The kernel inherits it to all
child processes. Includes all filesystem-admin ioctls (btrfs, DM, loop,
f2fs, nilfs2, reiserfs, bcachefs, FUSE, XFS, ext4, fscrypt, fsverity,
block device admin — blocked via magic-byte matching and individual
rules), FS_IOC_FIEMAP, name_to_handle_at, reboot, quotactl, fanotify,
and clock adjustment syscalls.

The **workload profile** (~150 blocked syscalls) is stricter, applied to
the agent, proxy, and nested containers. It blocks container escape
primitives (mount/umount/setns/pivot_root/chroot), the new mount API
(fsopen/fsconfig/fsmount/fspick/mount_setattr), device creation,
kernel exploit primitives (io_uring, bpf, userfaultfd,
splice/tee/vmsplice, perf_event_open, memfd_create), all namespace
creation flags (CLONE_NEWUSER/NEWNS/NEWPID/NEWNET/NEWUTS/NEWIPC/
NEWCGROUP arg-filtered on clone/unshare, clone3 fully blocked),
privilege escalation (ptrace, process_vm_*, pidfd_open, pidfd_getfd,
execveat), kernel keyring, system disruption, hardware I/O, time
manipulation, SysV IPC, POSIX message queues (mq_notify UAF class),
terminal injection (TIOCSTI/TIOCLINUX/TIOCSETD), SIOCATMARK (OOB mark
ioctl), MSG_OOB arg-filtered on send*/recv* (AF_UNIX UAF class),
MAP_GROWSDOWN (VMA stack expansion class), all filesystem-admin ioctls,
FS_IOC_FIEMAP, mount enumeration (listmount/statmount),
prctl(PR_SET_DUMPABLE) arg-filtered (prevents core dump re-enable),
prctl(PR_SET_PTRACER) (prevents Yama ptrace_scope bypass),
and socket families >= 17. For nested containers it layers on
top of the sidecar profile.

### Landlock filesystem tiers (nested containers)

| Tier | Rights | Typical paths |
|------|--------|---------------|
| read_exec | read, execute | /bin, /sbin, /usr, /lib, /.sandbox |
| read_only | read | / (entire rootfs) |
| write_noexec | read, write, create, delete, IoctlDev | /dev, /proc, /run, /var |
| write_exec | read, write, create, delete, execute, IoctlDev | /home, /tmp, /var/tmp, workdir |

All tiers include Refer (prevents EXDEV). MakeChar/MakeBlock excluded.

### Workdir paths (agent + nested containers)

Two categories are applied to the workdir, distinct from the system-wide
masks below. Masked paths (`UniversalMaskedPaths`) use a `/dev/null` bind
for files and an empty bind for directories, applied unconditionally
whether present or not. Defaults are `.env`, `.envrc`, `.npmrc`, and
`.clampdownrc`. Protected paths (`UniversalProtectedPaths`) are read-only
binds if present. Absent files become `/dev/null`, and absent directories
become an empty read-only bind. Materialization at session start prevents
host writes from leaking through during the session. Defaults are
`.git/config`, `.git/hooks`, `.gitmodules`, `.claude`, `.codex`,
`.devcontainer`, `.idea`, and `.mcp.json`.

Agent and sidecar specs are built from one source of truth so they
cannot diverge. User `--protect` and `--mask` paths follow the same
rules. Mask wins over protection if both apply.

### Masked paths (all containers -- run + build)

Enforced via containers.conf volumes on the sidecar's read-only rootfs.
Files are masked with /dev/null bind mounts; directories with /.empty
bind mounts. Applies uniformly to both `podman run` and `podman build`.
The agent cannot override these -- see VECTORS.md for the full bypass
analysis.

security-policy `checkMaskedPaths` validates defense-in-depth: each path
must be covered by either OCI maskedPaths or a /dev/null/empty-dir bind
mount. The check verifies mount sources are genuinely /dev/null (char
device major 1, minor 3) or empty directories -- not attacker-controlled
files.

| Path | Type | Where | Reason |
|------|------|-------|--------|
| /proc/devices | file | all* | Device list (attack surface enumeration) |
| /proc/diskstats | file | all* | Disk I/O statistics |
| /proc/kallsyms | file | all* | Kernel symbol addresses (KASLR bypass) |
| /proc/kcore | file | all* | Physical memory dump |
| /proc/modules | file | all* | Loaded modules (attack surface enumeration) |
| /proc/partitions | file | all* | Partition table |
| /proc/version | file | all* | Kernel version (exploit selection) |
| /proc/sysrq-trigger | file | all* | System request trigger (DoS) |
| /proc/cmdline | file | all* | Boot parameters (KASLR status, kernel config) |
| /sys/kernel/vmcoreinfo | file | all* | Crash dump format layout |
| /sys/kernel/debug | dir | nested | ftrace, kprobes |
| /sys/kernel/tracing | dir | nested | ftrace tracing interface |
| /sys/kernel/security | dir | nested | LSM policy files |
| /sys/fs/bpf | dir | nested | Pinned eBPF maps/programs |
| /sys/module | dir | nested | Kernel module parameters |
| /sys/devices/virtual/dmi | dir | nested | Hardware fingerprint |

\* "all" = agent, sidecar, proxy (via `hardenedMounts` in config.go) +
nested containers (via containers.conf volumes). "nested" = nested
containers only (EmptyRO tmpfs via containers.conf; not applied to
agent/sidecar/proxy due to sysfs mount constraints).

### File provenance

All Go binaries are static (CGO_ENABLED=0), immune to LD_PRELOAD.
Base images pinned by SHA256 digest.

| Image | File | Notes |
|-------|------|-------|
| Sidecar | /entrypoint | Go, static (seccomp-notif supervisor, 20 syscalls, CID-scoped mount allowlist) |
| Sidecar | /sandbox-seal | Go, static (go-landlock, x/sys, psx) |
| Sidecar | /rename_exdev_shim.so | C, musl -nostdlib (O_EXCL+O_NOFOLLOW+random suffix) |
| Sidecar | seal-inject, security-policy | Go, static, stdlib only |
| Sidecar | /usr/local/bin/podman | podman-static v5.8.1 (fuse-overlayfs removed) |
| Proxy | /usr/local/bin/auth-proxy | Go, static, stdlib only |
| Proxy | ca-certificates.crt | Alpine CA bundle |
