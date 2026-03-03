<\!-- SPDX-License-Identifier: GPL-3.0-only -->

# clampdown Security Model

## Container Topology

```
┌──────────────────────────────────────────────────────────────────────────┐
│ HOST                                                                     │
│                                                                          │
│  ┌───────────────┐                                                       │
│  │  Launcher     │  clampdown CLI (Go binary)                            │
│  │  (host PID)   │  Checks Landlock LSM, resolves DNS allowlists,        │
│  │               │  writes seccomp, starts sidecar, waits, starts agent. │
│  └──────┬────────┘                                                       │
│         │                                                                │
│         │  podman run (rootless)                                         │
│         │                                                                │
│  ┌──────▼───────────────────────────────────────────────────────────┐    │
│  │ SIDECAR CONTAINER  (FROM scratch, read-only rootfs)              │    │
│  │                                                                  │    │
│  │  PID 1: /entrypoint                                              │    │
│  │    1. Harden /proc/sys (bind-mount read-only)                    │    │
│  │    2. Bootstrap cgroup v2 (nsdelegate, controllers)              │    │
│  │    3. Build iptables firewall (agent + pod chains)               │    │
│  │    4. Write /run/sandbox/{uid,gid}, chattr +i, bind-mount RO     │    │
│  │    5. exec → podman system service tcp:127.0.0.1:2375            │    │
│  │                                                                  │    │
│  │  Seccomp: seccomp_sidecar.json (denylist, ~70 blocked)           │    │
│  │    Blocks: io_uring, perf_event_open, userfaultfd, modify_ldt,   │    │
│  │    kcmp, process_madvise, kexec_*, init/delete/finit_module,     │    │
│  │    add_key, request_key, splice/tee/vmsplice (Dirty Pipe),       │    │
│  │    open_by_handle_at, swapoff/swapon, acct, vhangup,             │    │
│  │    ioperm/iopl, clock_settime, setdomainname/sethostname,        │    │
│  │    personality (arg-filtered), TIOCSTI/TIOCLINUX,                │    │
│  │    IOC_WATCH_QUEUE_SET_FILTER (CVE-2022-0995),                   │    │
│  │    socket family ≥ 17, obsolete syscalls.                        │    │
│  │    Allows: mount, bpf, clone3, seccomp, keyctl, ptrace           │    │
│  │    — needed by podman/crun for container management.             │    │
│  │                                                                  │    │
│  │  OCI Hooks (intercept nested container lifecycle):               │    │
│  │    precreate:    seal-inject (policy, UID, seal mount, masking)  │    │
│  │    createRuntime: security-policy (14 checks — see Layer 4)      │    │
│  │                                                                  │    │
│  │  ┌─────────────────────────────────────────────────────────┐     │    │
│  │  │ NESTED CONTAINERS  (podman run/build inside sidecar)    │     │    │
│  │  │                                                         │     │    │
│  │  │  Seccomp: seccomp_nested.json (via containers.conf)     │     │    │
│  │  │    Blocks ~115 dangerous syscalls workloads never need: │     │    │
│  │  │    mount, pivot_root, setns, chroot, ptrace, bpf,       │     │    │
│  │  │    io_uring, splice/tee/vmsplice, clone3, seccomp,      │     │    │
│  │  │    keyctl, init/delete_module, reboot, swapon/off,      │     │    │
│  │  │    ioperm/iopl, clock_settime, SysV IPC, mknod,         │     │    │
│  │  │    new mount API (fsopen/fsmount/move_mount/...), etc.  │     │    │
│  │  │    Identical to agent seccomp (unified workload profile)│     │    │
│  │  │    Layered ON TOP of inherited sidecar seccomp.         │     │    │
│  │  │                                                         │     │    │
│  │  │  Entrypoint: /.sandbox/seal -- <original command>       │     │    │
│  │  │    • Apply Landlock V7 (fs + net + IPC)                 │     │    │
│  │  │    • Close FDs ≥ 3 (close-on-exec)                      │     │    │
│  │  │    • exec → original entrypoint                         │     │    │
│  │  │                                                         │     │    │
│  │  │  LD_PRELOAD: /.sandbox/rename_exdev_shim.so             │     │    │
│  │  │    • Intercepts rename/renameat/renameat2               │     │    │
│  │  │    • Falls back to copy+unlink on EXDEV                 │     │    │
│  │  └─────────────────────────────────────────────────────────┘     │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │ AGENT CONTAINER  (Alpine, --network container:SIDECAR)           │    │
│  │                                                                  │    │
│  │  Seccomp: seccomp_agent.json (identical to seccomp_nested.json)  │    │
│  │    Blocks ~115 dangerous syscalls (unified workload profile)     │    │
│  │                                                                  │    │
│  │  Entrypoint: /usr/local/bin/sandbox-seal -- claude               │    │
│  │    • Landlock: workdir RWX, rootfs RO, binaries RX               │    │
│  │    • cap-drop=ALL, no-new-privileges, read-only rootfs           │    │
│  │    • Shares sidecar's network namespace (firewalled)             │    │
│  │    • Uses sidecar's podman API to spawn nested containers        │    │
│  │                                                                  │    │
│  │  Web access:                                                     │    │
│  │    • WebSearch: allowed (API domain allowlisted)                 │    │
│  │    • WebFetch: blocked (agent firewall)                          │    │
│  │    • Workaround: podman run alpine wget (pod egress is open)     │    │
│  │                                                                  │    │
│  │  Protected paths (read-only or masked):                          │    │
│  │    .git/hooks  .git/config  .gitmodules  .vscode                 │    │
│  │    .idea  .devcontainer  .envrc  .mcp.json                       │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

## Defense Layers

```
Pre-launch: Launcher checks (hard-fail before any containers start)
  │  checkLandlock: /sys/kernel/security/lsm must contain "landlock"
  │    Absent + readable → hard error (session refuses to start)
  │    Unreadable → warn (let seal enforce inside container)
  │    Kernel < 6.7 → warn (Landlock V6 IPC scoping unavailable)
  │  checkYama: /proc/sys/kernel/yama/ptrace_scope
  │    Unreadable → warn (Yama LSM not detected)
  │    Value 0 → warn (permissive, recommend ptrace_scope=1)
  │    Advisory only — ptrace blocked by seccomp independently
  │  warnIfRootful: rootful runtime → warning
  │
Layer 0: Host
  │  Rootless podman, userns=keep-id
  │  Seccomp profiles (sidecar + agent + nested)
  │  AppArmor unconfined / SELinux container_engine_t <- sidecar
  │  AppArmor confined / SELinux container_t <- agent
  │
Layer 1: Sidecar Entrypoint
  │  /proc/sys read-only (except /proc/sys/net)
  │  cgroup v2 with nsdelegate
  │  iptables firewall (agent OUTPUT + pod FORWARD)
  │  /run/sandbox/{uid,gid} immutable (chattr +i) + bind-mount RO
  │
Layer 2: Sidecar Seccomp (seccomp_sidecar.json)
  │  Denylist — blocks dangerous syscalls NOT used by podman
  │  Validated against syscalls.log (podman's full syscall set)
  │  No excludes.caps (sidecar has SYS_ADMIN — would skip rules)
  │  Inherited by ALL child processes (agent + nested containers)
  │
Layer 3: Workload Seccomp (seccomp_agent.json = seccomp_nested.json)
  │  Unified profile — identical for agent and nested containers
  │  Denylist — blocks ~115 dangerous syscalls workloads never need
  │  13 categories: container escape, new mount API, device creation,
  │  kernel code, kernel exploits, privilege escalation, keyring,
  │  system disruption, hardware I/O, time, SysV IPC, NUMA, obsolete
  │  Agent: applied at container start via --security-opt seccomp=
  │  Nested: applied via containers.conf seccomp_profile directive
  │  Nested layered on top of sidecar seccomp (kernel intersects both)
  │  Cannot be bypassed — security-policy hook blocks seccomp=unconfined
  │
Layer 4: OCI Hooks (nested containers)
  │  precreate: seal-inject
  │    UID/GID enforcement (non-root)
  │    sandbox-seal injected as entrypoint wrapper
  │    Landlock policy derived from mounts
  │    /proc masking (kallsyms, kcore, config.gz, modules)
  │    /sys masking (debug, tracing, security, bpf, module, dmi)
  │    hidepid=2 on procfs
  │    NOTE: /proc/sysrq-trigger is NOT in maskedPaths — it's in
  │    default readonlyPaths. maskedPaths uses /dev/null, and writes
  │    to device nodes bypass ro mount flags (kernel routes to driver).
  │
  │  createRuntime: security-policy (14 checks)
  │    checkCaps:              18 dangerous capabilities blocked
  │    checkSeccomp:           seccomp=unconfined blocked
  │    checkNoNewPrivileges:   no-new-privileges=false blocked (CVE-2023-0386)
  │    checkNamespaces:        5 namespace types required, host joins blocked
  │    checkMounts:            mount sources restricted to workdir + infra
  │    checkMountOptions:      nosuid + nodev required on writable bind mounts
  │    checkMountPropagation:  shared/rshared/slave/rslave blocked (CVE-2025-52881)
  │    checkRootfsPropagation: non-private rootfs propagation blocked
  │    checkDevices:           all device access blocked
  │    checkMaskedPaths:       unmask of 10 custom masked paths blocked
  │    checkReadonlyPaths:     unmask of /proc/sys, /proc/bus, /proc/fs, /proc/irq,
  │                            /proc/sysrq-trigger blocked
  │    checkSysctl:            all kernel parameter changes blocked (CVE-2022-0811)
  │    checkRlimits:           RLIMIT_CORE override blocked (memory disclosure)
  │    checkImageRef:          tag-only image refs warned or blocked
  │
Layer 5: sandbox-seal (per-process)
  │  Hard-fails if Landlock ABI < V3 (kernel < 6.2)
  │  Landlock V7 filesystem MAC (4 tiers), BestEffort for V4+
  │  Landlock IPC scoping (V6+, BestEffort)
  │  PR_SET_NO_NEW_PRIVS (via Landlock)
  │  FD ≥ 3 close-on-exec
  │
  │  NOTE: Landlock cannot be applied to the sidecar itself.
  │  mount() internally triggers Landlock path hooks (EPERM).
  │
  │  NOTE: seal does NOT do cap pruning. Cap enforcement is handled
  │  by containers.conf (10 default caps) + security-policy hook
  │  (18 denied caps). seal-inject sets non-root UID →
  │  no_new_privileges empties the effective set on exec.
  │  Bounding caps are unreachable without effective caps.
  │
Layer 6: containers.conf (static defaults)
  │  seccomp_profile = seccomp_nested.json
  │  no_new_privileges = true
  │  pids_limit = 256
  │  default_capabilities (10 safe caps)
  │  ulimit core=0:0
  │  LD_PRELOAD rename shim (EXDEV fix)
  │
Layer 7: Host-side Watcher (tripwire)
     Runs on the HOST, outside all container namespaces
     inotify (fsnotify) on all RO-mounted host paths
     Snapshots content + permissions before session start
     Any write/create/delete/move → context cancel → kill session
     On exit: restore modified files (sha256 compare), remove unexpected files
     Disabled with --disable-tripwire
     Last line of defense: sidecar UID mapping (uid 0 → subuid) prevents
     writes, but a full escape to host uid 1000 bypasses in-container layers.
     The watcher catches that.
```

## Seccomp Architecture (three-profile model)

```
┌─────────────────────────────────────────────────────────────────┐
│  SIDECAR SECCOMP (seccomp_sidecar.json)                         │
│  Applied at: container start (--security-opt seccomp=...)       │
│  Scope: sidecar + ALL children (inherited by kernel)            │
│  Approach: denylist (SCMP_ACT_ALLOW default)                    │
│  Validated against: syscalls.log (podman's known syscall set)   │
│  Aligned with: containers/common default seccomp profile        │
│                                                                 │
│  Blocks (~70 syscalls):                                         │
│    io_uring_*, perf_event_open, userfaultfd, modify_ldt,        │
│    kcmp, process_madvise, add_key, request_key,                 │
│    kexec_load/file_load, init/delete/finit_module,              │
│    splice/tee/vmsplice (Dirty Pipe), open_by_handle_at,         │
│    swapoff/swapon, acct, vhangup, ioperm/iopl,                  │
│    clock_settime/clock_settime64, setdomainname/sethostname,    │
│    personality (arg-filtered), lookup_dcookie,                  │
│    move_pages, migrate_pages, settimeofday, stime,              │
│    quotactl_fd, socket(family≥17),                              │
│    mmap/mmap2/mprotect/pkey_mprotect(PROT_WRITE+PROT_EXEC),     │
│    ioctl(TIOCSTI/TIOCLINUX/IOC_WATCH_QUEUE_SET_FILTER),         │
│    obsolete (20+), arch-specific (6), newer APIs (5)            │
│                                                                 │
│  Allows (needed by podman/crun):                                │
│    mount, umount2, pivot_root, setns, clone, clone3,            │
│    unshare, chroot, bpf, seccomp, keyctl, ptrace,               │
│    execveat, quotactl, reboot, SysV IPC                         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  WORKLOAD SECCOMP (seccomp_agent.json = seccomp_nested.json)    │
│  Applied at: agent start + nested containers (containers.conf)  │
│  Scope: all workload processes (agent + nested containers)      │
│  Approach: denylist (SCMP_ACT_ALLOW default)                    │
│  Layered: nested runs ON TOP of inherited sidecar seccomp       │
│  Both files are identical — unified workload profile            │
│                                                                 │
│  Blocks (~120 syscalls, 15 categories):                         │
│    Container escape:  mount, umount*, pivot_root, setns,        │
│                       chroot, open_by_handle_at,                │
│                       clone(CLONE_NEWUSER), clone3,             │
│                       unshare(CLONE_NEWUSER)                    │
│    New mount API:     open_tree, move_mount, fsopen, fsconfig,  │
│                       fsmount, mount_setattr                    │
│    Device creation:   mknod, mknodat                            │
│    Kernel code exec:  init/finit/delete_module, kexec_*         │
│    Kernel exploits:   bpf, io_uring, userfaultfd, splice/tee,   │
│                       vmsplice, modify_ldt, personality,        │
│                       seccomp, fanotify_*, remap_file_pages     │
│    W^X enforcement:   mmap/mmap2/mprotect/pkey_mprotect         │
│                       (PROT_WRITE+PROT_EXEC blocked)            │
│    Privilege escal:   ptrace, process_vm_*, kcmp, execveat      │
│    Kernel keyring:    keyctl, add_key, request_key              │
│    System disruption: reboot, swap*, acct, quotactl*, vhangup,  │
│                       syslog                                    │
│    Hardware I/O:      ioperm, iopl, pciconfig_*                 │
│    Time manipulation: clock_settime*, adjtimex, settimeofday    │
│    SysV IPC:          shm*, sem*, msg* (12 syscalls)            │
│    Terminal inject:   ioctl(TIOCSTI), ioctl(TIOCLINUX)          │
│    watch_queue:      ioctl(IOC_WATCH_QUEUE_SET_FILTER)          │
│    NUMA:              move_pages, migrate_pages                 │
│    Newer APIs:        cachestat, futex_requeue/wait/waitv/wake  │
│    Obsolete:          bdflush, nfsservctl, uselib, vm86, ...    │
│    Socket families:   AF_PACKET, AF_TIPC, AF_ALG, AF_VSOCK      │
│                                                                 │
│  Allows (workloads need):                                       │
│    All file I/O, networking (AF_UNIX/INET/INET6/NETLINK),       │
│    process management (fork, execve, wait), memory management,  │
│    signals, scheduling, timers, epoll/poll, inotify, xattr,     │
│    memfd_create (JIT), getrandom, statx, pidfd_*, landlock_*    │
└─────────────────────────────────────────────────────────────────┘
```

## Network Policy

```
                    ┌─────────────────────────┐
                    │      INTERNET           │
                    └────────┬────────────────┘
                             │
              ┌──────────────▼────────────────┐
              │  SIDECAR NETWORK NAMESPACE    │
              │  (shared by agent container)  │
              │                               │
              │  filter/OUTPUT (agent egress) │
              │  ┌────────────────────────┐   │
              │  │ 1. ACCEPT loopback     │   │
              │  │ 2. ACCEPT established  │   │
              │  │ 3. DROP private CIDRs  │   │
              │  │ 4. ACCEPT DNS :53      │   │
              │  │    (10/s burst 20)     │   │
              │  │ 5. ACCEPT allowlist IPs│   │
              │  │ 6. → AGENT_ALLOW       │   │
              │  │ 7. DROP (default deny) │   │
              │  └────────────────────────┘   │
              │                               │
              │  mangle/FORWARD (pod egress)  │
              │  ┌────────────────────────┐   │
              │  │ 1. ACCEPT established  │   │
              │  │ 2. ACCEPT loopback     │   │
              │  │ 3. → POD_ALLOW         │   │
              │  │ 4. DROP private CIDRs  │   │
              │  │ 5. → POD_BLOCK         │   │
              │  │ 6. ACCEPT (default)    │   │
              │  └────────────────────────┘   │
              └───────────────────────────────┘

Blocked CIDRs (IPv4):              Blocked CIDRs (IPv6):
  10.0.0.0/8                         ::1/128
  172.16.0.0/12                      fc00::/7
  192.168.0.0/16                     fe80::/10
  127.0.0.0/8
  169.254.0.0/16 (cloud metadata)

Agent allowlist (resolved at startup):
  api.anthropic.com    claude.ai    platform.claude.com
  sentry.io            statsig.anthropic.com
  + container registries (docker.io, ghcr.io, quay.io, ...)
  + user-provided domains

Agent web access:
  WebSearch: allowed (routes through API)
  WebFetch: blocked by agent firewall (use pod wget instead)
```

## Landlock Filesystem Policy (nested containers)

```
Tier        Access Rights                     Paths
──────────  ────────────────────────────────  ──────────────────────────
read_exec   read + execute                    /bin /sbin /usr/bin /usr/sbin
                                              /usr/lib /usr/lib64 /usr/libexec
                                              /usr/local /lib /lib64
                                              /.sandbox

read_only   read (no execute)                 / (entire rootfs)

write_noexec read + write + create/delete     /dev /proc /tmp /var/tmp
             (no execute, no device nodes)    /run /var/log /var/cache /var/lib

write_exec  read + write + create/delete      /home
            + execute                         + user bind mounts (workdir)

All tiers include Refer (prevents spurious EXDEV across rule boundaries).
MakeChar and MakeBlock excluded from all write tiers.
```

## Capability Model

```
                    Host caps
                        │
           ┌────────────▼────────────┐
           │  SIDECAR (17 caps)      │
           │  SYS_ADMIN  NET_ADMIN   │
           │  SYS_CHROOT SYS_PTRACE  │
           │  SYS_RESOURCE           │
           │  LINUX_IMMUTABLE        │
           │  CHOWN  DAC_OVERRIDE    │
           │  FOWNER FSETID  KILL    │
           │  MKNOD  SETFCAP         │
           │  SETGID SETUID SETPCAP  │
           │  NET_BIND_SERVICE       │
           └────────────┬────────────┘
                        │
           ┌────────────▼────────────┐
           │  AGENT (0 caps)         │
           │  cap-drop=ALL           │
           └────────────┬────────────┘
                        │
           ┌────────────▼────────────┐
           │  NESTED (10 default)    │
           │  containers.conf:       │
           │  CHOWN DAC_OVERRIDE     │
           │  FOWNER FSETID KILL     │
           │  NET_BIND_SERVICE       │
           │  SETFCAP SETGID SETPCAP │
           │  SETUID                  │
           │                         │
           │  Bounding: 10 caps      │
           │  Effective: empty       │
           │  (non-root + no ambient │
           │   + no_new_privileges)  │
           └─────────────────────────┘

createRuntime hook BLOCKS (any set, 18 caps):
  CAP_AUDIT_CONTROL  CAP_BPF  CAP_DAC_READ_SEARCH
  CAP_LINUX_IMMUTABLE  CAP_MAC_ADMIN  CAP_MAC_OVERRIDE
  CAP_MKNOD  CAP_NET_ADMIN  CAP_NET_RAW  CAP_PERFMON
  CAP_SYS_ADMIN  CAP_SYS_BOOT  CAP_SYS_CHROOT
  CAP_SYS_MODULE  CAP_SYS_PTRACE  CAP_SYS_RAWIO
  CAP_SYS_RESOURCE  CAP_SYS_TIME
```

## OCI Hook Pipeline (nested container lifecycle)

```
podman run ...
     │
     ▼
┌──────────────────────────────────────────────┐
│  PRECREATE: seal-inject                      │
│  (reads OCI config from stdin,               │
│   writes modified config to stdout)          │
│                                              │
│  1. Overwrite process.user → sandbox UID/GID │
│  2. Prepend /.sandbox/seal -- to args        │
│  3. Derive Landlock policy from mounts       │
│  4. Inject SANDBOX_POLICY env var            │
│  5. Add /.sandbox/seal bind mount            │
│  6. Add hidepid=2 to proc mount              │
│  7. Append masked paths (/proc + /sys)       │
│  8. Inject opt-in credentials                │
│     (/run/credentials/* → nested container)  │
└──────────────────┬───────────────────────────┘
                   │
     container created (crun)
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  CREATERUNTIME: security-policy             │
│  (reads OCI state from stdin,               │
│   reads config.json from bundle)            │
│                                             │
│  Validates — blocks container on violation: │
│   1. checkCaps             → EPERM          │
│   2. checkSeccomp          → EPERM          │
│   3. checkNoNewPrivileges  → EPERM          │
│   4. checkNamespaces       → EOPNOTSUPP     │
│   5. checkMounts           → EACCES         │
│   6. checkMountOptions     → EACCES         │
│   7. checkMountPropagation → EPERM          │
│   8. checkRootfsPropagation→ EPERM          │
│   9. checkDevices          → EACCES         │
│  10. checkMaskedPaths      → EPERM          │
│  11. checkReadonlyPaths    → EPERM          │
│  12. checkSysctl           → EPERM          │
│  13. checkRlimits          → EPERM          │
│  14. checkImageRef         → EACCES/warn    │
└──────────────────┬──────────────────────────┘
                   │
     container process starts
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  sandbox-seal (PID 1 of nested container)   │
│                                             │
│  1. Parse SANDBOX_POLICY                    │
│  2. applyLandlock (V7 BestEffort)           │
│     → Hard-fail if ABI < V3 (kernel < 6.2)  │
│     → PR_SET_NO_NEW_PRIVS set               │
│     → Filesystem rules (4 tiers + Refer)    │
│     → IPC scoping (V6+, BestEffort)         │
│  3. closeExtraFDs (≥ 3 → close-on-exec)     │
│  4. exec → original entrypoint              │
└──────────────────┬──────────────────────────┘
                   │
     container runs (seccomp_nested + Landlock + caps active)
```

## Masked and Read-only Paths

```
maskedPaths (seal-inject, bind /dev/null — hides content):
  /proc/kallsyms       Kernel symbol addresses (KASLR bypass)
  /proc/kcore          Physical memory in ELF format
  /proc/config.gz      Kernel config (reveals security features)
  /proc/modules        Loaded modules (attack surface enumeration)

  /sys/kernel/debug      ftrace, kprobes, memory state
  /sys/kernel/tracing    ftrace tracing interface
  /sys/kernel/security   LSM policy files
  /sys/kernel/vmcoreinfo Kernel crash dump format layout
  /sys/fs/bpf            Pinned eBPF maps/programs
  /sys/module            Kernel module parameters
  /sys/devices/virtual/dmi   Hardware fingerprint (DMI/SMBIOS)

requiredReadonlyPaths (security-policy validates presence):
  /proc/bus            PCI/USB device enumeration
  /proc/fs             Filesystem driver parameters
  /proc/irq            Interrupt routing
  /proc/sys            Kernel tunables (sysctl)
  /proc/sysrq-trigger  Host crash/reboot

  NOTE: /proc/sysrq-trigger uses readonlyPaths, NOT maskedPaths.
  maskedPaths bind-mounts /dev/null (a device node) — writes to device
  nodes bypass the ro mount flag (kernel routes to driver, not filesystem).
  readonlyPaths bind-mounts the real proc entry read-only, which does
  block writes.

/proc mount options:
  hidepid=2    Process sees only its own /proc/[pid] entries
```

## File Provenance

```
Sidecar image (FROM scratch):
  /entrypoint                              Go, static (CGO_ENABLED=0)
  /sandbox-seal                            Go, static (CGO_ENABLED=0)
  /rename_exdev_shim.so                    C, musl -nostdlib (no DT_NEEDED)
  /usr/libexec/oci/hooks.d/seal-inject     Go, static
  /usr/libexec/oci/hooks.d/security-policy Go, static
  /usr/local/bin/podman                    podman-static v5.8.0
  /etc/containers/containers.conf          Hardened defaults + seccomp_profile
  /etc/containers/seccomp_nested.json      Nested container seccomp profile
  /etc/containers/policy.json              Image pull allowlist

All Go binaries: CGO_ENABLED=0 → immune to LD_PRELOAD.
The rename shim: -nostdlib → no libc DT_NEEDED, works on musl + glibc.
Base images: pinned by SHA256 digest.
```

## Security Audit Notes

Known false positives and expected findings from third-party audit tools
(am-i-isolated, CDK, amicontained, DEEPCE, LinPEAS, linux-exploit-suggester).
Last validated: 2026-03-02.

```
False positives:
  LinPEAS "/proc/kallsyms readable"
    open() succeeds because the mask is /dev/null (a device node), but
    read returns empty — no kernel symbols are disclosed. Same device-node
    behavior as /proc/sysrq-trigger (addressed via readonlyPaths).

  LinPEAS "Modules can be loaded"
    init_module, finit_module, and delete_module are blocked by seccomp
    in both sidecar and workload profiles. The check reads /proc/sys but
    cannot act on it.

  am-i-isolated "Yama LSM not present"
    /proc/kallsyms is masked (/dev/null), hiding the kernel symbol table
    that the tool uses to detect Yama. The host has Yama active
    (ptrace_scope=3 on Fedora 42). ptrace is independently blocked by
    seccomp in workload profiles.

  DEEPCE "Inside Container: No"
    Detection heuristic does not recognize clampdown's nested container
    layout (sidecar + nested). Not a security gap.

Kernel CVEs (monitor only):
  CVE-2025-38236 (AF_UNIX MSG_OOB UAF)
    Flagged by LinPEAS kernel CVE registry for kernel 6.18.9.
    Kernel-level — cannot be fixed from inside the container.
    Low practical risk: requires AF_UNIX MSG_OOB which is uncommon in
    agent workloads. Wait for upstream kernel patch.

  CVE-2022-2586, CVE-2021-22555 (netfilter)
    Flagged by linux-exploit-suggester as "less probable". Both require
    CAP_NET_ADMIN via unprivileged user namespaces. Mitigated: seccomp
    blocks clone(CLONE_NEWUSER) and unshare(CLONE_NEWUSER) in workload
    profiles, preventing capability acquisition via user namespaces.
```
