<\!-- SPDX-License-Identifier: GPL-3.0-only -->

# CLAUDE.md

Read CLAUDE, DIAGRAM, VECTORS. Read all go files and containerfiles. Read ./.claude/memory. Be ready.
> Blunt, directive. No filler. No emojis. No engagement optimization. Correct when wrong. Always ultrathink.

## Index

| Situation | Action |
|-----------|--------|
| New task | Read-only until user approves → Workflow |
| Writing code | Apply principles + conduct → Code, Security |
| Missing tool | Podman sibling container → Environment |
| Unsure about lib/API | Look up before answering → Research |
| Context growing | Session notes are the resumption artifact → Continuity |
| Commit message | Text only, no extras → Workflow |

## Workflow

| Mode | Trigger | Allowed | Forbidden |
|------|---------|---------|-----------|
| Plan | New task (default) | Read, search, git log/diff | Write, edit, create, mutate |
| Execute | User approves plan | All operations | Skipping plan |
| Patch | User says "patch" | `diff -u` for review | Silent changes |
| Commit msg | User asks | Write message text | `Co-Authored-By`, prompt to execute |
| All | Always | Offer alternatives with tradeoffs | Assuming one path |
| All | Before writing | Analyze conventions, match style | Ignoring local patterns |

## Code

| # | Principle | Test |
|---|-----------|------|
| 1 | No unnecessary complexity | Needs persuasion → cut it |
| 2 | One-head rule | Can't hold in one head → simplify |
| 3 | Code = prose | Doesn't read well first pass → rewrite |
| 4 | Minimal surface | Can use stdlib → use stdlib |
| 5 | Small functions | Can't name it clearly → wrong abstraction |
| 6 | Data structures first | Coding before layout → stop |
| 7 | Annotate mutable state | Reader must simulate → annotate |
| 8 | Opportunistic | Scope exceeds minimum → cut |
| 9 | Joy = signal | It's a grind → design is wrong |

Comment types: Function, Design, Why, Teacher, Checklist, Guide. Kill: trivial, TODO, commented-out.

### Go Style

- No `if x := expr(); x != ...` init-statement syntax. Separate declaration from condition.

### Agent Conduct

| Don't | Do |
|-------|-----|
| Touch unread code | Read first |
| Exceed the request | Scope to what was asked |
| Annotate untouched code | Leave it alone |
| Guard impossible states | Validate boundaries only |
| Abstract prematurely | Inline until proven otherwise |
| Leave dead code | Delete completely |
| Apply a solution without approval | Present approach, discuss, then implement |

## Security

OWASP top 10: never introduce, fix on sight. Validate at system boundaries. Trust internals.

| Authorized | Refused |
|------------|---------|
| Pentesting, CTF, defensive | DoS, mass targeting, supply chain compromise |
| Dual-use with clear context | Detection evasion for malicious purposes |

## Environment

Podman container: Alpine Linux, read-only rootfs, `--cap-drop=ALL`, 4GB/4CPU.
Workdir: bind-mounted r/w. Home: tmpfs. No package installation. No root.

Available: bash, git, go, node/npm, python3/pip, curl, wget, cmake, build-base, ripgrep, jq, shellcheck, podman, docker-cli.

Missing tool → `podman run --rm -v "$(pwd):$(pwd)" -w "$(pwd)" <image> <cmd>`

## Research

Look up, don't guess: github.com (repos, issues) · context7.com (library docs) · cheat.sh (syntax)

## Continuity

Automatic — do not wait for user to ask.

`_session_notes.md` is the single resumption artifact. Always sufficient to reconstruct full context.

| When | Action |
|------|--------|
| After each sub-task | Update `_session_notes.md`: current task, decisions, files touched, open questions |
| System compresses prior messages | Finalize `_session_notes.md` with full current state. Inform user |
| Recurring pattern noticed | Append to `CLAUDE.local.md` as compressed directives |

## Architecture

Two-container model running under rootless podman (or Docker):

```
HOST
 └─ clampdown (Go CLI, launcher)
     ├─ SIDECAR (FROM scratch, read-only rootfs)
     │   PID 1: /entrypoint → /usr/local/bin/podman system service
     │   Runs: podman API server, crun, OCI hooks
     │   Seccomp: sidecar profile (~70 blocked, W^X, allows mount/bpf/ptrace)
     │   Caps: 17 (SYS_ADMIN, NET_ADMIN, LINUX_IMMUTABLE, etc.)
     │   User: 0:0 inside userns (--userns=keep-id maps host uid)
     │   NO Landlock (incompatible with mount())
     │
     └─ AGENT (Alpine, --network container:SIDECAR)
         Entrypoint: sandbox-seal -- claude
         Seccomp: workload profile (~120 blocked, W^X)
         Caps: cap-drop=ALL
         Landlock V7 (filesystem, IPC scoping)
         Read-only rootfs, no-new-privileges
         Spawns NESTED containers via sidecar's podman API
```

Nested containers (tools the agent launches) get the same workload seccomp +
Landlock via OCI hooks. Protected paths (universal + `--protect`) propagate
from the sidecar into nested containers via recursive bind mounts (rbind).
security-policy blocks explicit RW re-mounts of protected paths (check 15).

## Project Structure

```
main.go                          Entry point → pkg/cli.Run()
pkg/
  agent/
    agent.go                     Agent interface + registry
    claude.go                    Claude Code agent (image, egress domains, prompt)
    opencode.go                  OpenCode agent (image, egress domains, prompt)
  cli/
    app.go                       urfave/cli commands (agent subcommands, network, session)
    config.go                    Config file loading ($XDG_CONFIG_HOME/clampdown/config.json)
  container/
    runtime.go                   Runtime interface (StartSidecar, StartAgent, Exec, List, etc.)
    podman.go                    Podman implementation
    docker.go                    Docker implementation
    detect.go                    Runtime auto-detection
  sandbox/
    sandbox.go                   Run() orchestrator — starts sidecar, waits for API, starts agent
    credentials.go               Opt-in host credential forwarding (gitconfig, gh, ssh)
    config.go                    Sidecar/agent config builders, Landlock policy, allowlist resolution
    paths.go                     Per-project cache paths (hashed workdir)
    integration_test.go          Integration tests (build tag: integration)
    mounts/mounts.go             Mount building: workdir, protected paths, config overlays, state dir
    network/
      egress.go                  DNS resolution of domain allowlists
      firewall.go                Runtime iptables rule management (agent/pod allow/block/reset)
    seccomp/seccomp.go           Embedded seccomp profile management (//go:embed)
    session/session.go           Session listing, deletion, sidecar lookup
    watcher/watcher.go           Host-side inotify tripwire: snapshot, monitor, restore RO paths
container-images/
  sidecar/
    Containerfile                FROM scratch assembly (podman-static, iptables, shim, pre-built Go bins)
    containers.conf              Hardened defaults for nested containers
    policy.json                  Image pull + archive allowlist (docker.io, ghcr.io, quay.io, localhost)
    seccomp_nested.json          Workload seccomp profile (= seccomp_agent.json)
    entrypoint/
      entrypoint.go              Sidecar init: /proc/sys RO, cgroup v2, iptables firewall, identity files
      go.mod                     Separate module (stdlib only)
    hooks/
      precreate/
        seal-inject.go           Injects sandbox-seal into nested containers, derives Landlock policy
        seal-inject.json         OCI hook registration
        go.mod                   Separate module (stdlib only)
      createRuntime/
        security-policy.go       Validates caps, seccomp, namespaces, mounts, devices
        security-policy.json     OCI hook registration
        go.mod                   Separate module (stdlib only)
    seal/
      seal.go                    sandbox-seal: Landlock V7 enforcement, FD cleanup, exec
      go.mod                     Separate module (depends on go-landlock)
    shims/rename_exdev_shim.c    LD_PRELOAD .so for EXDEV rename fallback (copy+unlink)
  claude/
    Containerfile                Claude agent image (Alpine + claude CLI + podman-remote)
  opencode/
    Containerfile                OpenCode agent image (Alpine + native Bun binary)
tools/
  extract-syscalls.sh            Static syscall extractor — disassembles binaries/images to identify required syscalls for seccomp tuning
pkg/sandbox/seccomp/
  seccomp_sidecar.json           Sidecar seccomp profile (embedded via //go:embed)
  seccomp_agent.json             Agent/workload seccomp profile (embedded via //go:embed)
```

## Build

```bash
make all               # builds: sidecar image, claude and opencode agent images, launcher binary
make test              # runs all unit tests
make test-integration  # builds sidecar, runs integration tests (needs podman + internet)
make sidecar           # builds Go binaries on host, then sidecar container image
make claude            # copies seal into container-images/claude/, builds claude agent image
make opencode          # copies seal into container-images/opencode/, builds opencode agent image
make launcher          # CGO_ENABLED=0 go build
make install           # installs to ~/.local/bin/
```

All four Go binaries (seal, entrypoint, security-policy, seal-inject) are built on
the host by Make (`CGO_ENABLED=0`), then COPY'd into the sidecar image. The
Containerfile only assembles the final FROM scratch image — no Go compilation inside
container builds. The C rename shim, podman-static download, and iptables extraction
remain as Containerfile build stages.

Container image builds use stamp files (`.sidecar.stamp`, `.claude.stamp`, etc.) —
Make skips rebuilds when no source file changed.

## Agent Usage

Two agents are supported. Each gets its own CLI subcommand, container image, and
egress allowlist. The sidecar + security model is identical across all agents.

```bash
# Claude (Anthropic)
export ANTHROPIC_API_KEY=sk-ant-...
./clampdown claude

# OpenCode (multi-provider) — set whichever provider key you use
export ANTHROPIC_API_KEY=sk-ant-...   # or OPENAI_API_KEY, GEMINI_API_KEY, etc.
./clampdown opencode
```

API keys are forwarded from the host environment into the agent container automatically.
Only keys that are set on the host are passed through. Each agent declares which keys
it needs in `ForwardEnv()`.

Build agent images before first use:
```bash
make sidecar          # required for all agents
make claude           # or: make opencode
```

### Agent-specific notes

**OpenCode:** Multi-provider — egress allowlist only includes OpenCode infrastructure
domains. Users must add their AI provider domain via `--agent-allow` (e.g.
`--agent-allow api.anthropic.com`).

## Key Design Decisions

- **Sidecar is FROM scratch.** All binaries are static Go (CGO_ENABLED=0) — immune
  to LD_PRELOAD. No shell, no package manager, no libc.
- **Two seccomp profiles.** Sidecar needs mount/bpf/splice/ptrace for podman. The
  workload profile blocks all of these. Sidecar seccomp is inherited by all children
  (kernel guarantee), so io_uring/userfaultfd/perf_event_open are blocked everywhere.
- **W^X enforcement via seccomp.** All three profiles block mmap/mmap2/mprotect/pkey_mprotect
  when both PROT_WRITE and PROT_EXEC are set simultaneously (arg2 & 0x6 == 0x6). Prevents
  RWX memory mappings used in shellcode injection. V8/Node uses W^X (mmap RW then mprotect
  RX) — unaffected.
- **OCI hooks enforce policy on nested containers.** `seal-inject` (precreate) injects
  sandbox-seal as entrypoint wrapper + derives Landlock policy. `security-policy`
  (createRuntime, 15 checks) validates caps/namespaces/mounts/devices and blocks RW
  re-mounts of protected paths. Both run for every `podman run` inside the sidecar.
- **seal-inject is skipped for build containers** (podman build/buildah don't invoke
  precreate hooks). Build containers still get seccomp_nested.json via containers.conf
  and security-policy via createRuntime hook, but lack Landlock.
- **Landlock is a hard requirement.** The launcher checks `/sys/kernel/security/lsm`
  at startup. If Landlock is confirmed absent, the session refuses to start. If the
  file is unreadable (e.g., container-in-container), it warns and lets seal enforce
  inside. Kernel < 6.7 triggers a warning (Landlock present but lacks V6 IPC scoping).
- **Yama ptrace_scope preflight.** The launcher reads `/proc/sys/kernel/yama/ptrace_scope`
  at startup. Warns if Yama is absent or ptrace_scope is 0 (permissive). Advisory only —
  ptrace is independently blocked by seccomp, but Yama is defense-in-depth from a
  different kernel subsystem.
- **Landlock cannot be applied to the sidecar.** mount() triggers Landlock path hooks
  internally → EPERM. Tested and confirmed.
- **infraMountPrefixes** in both hooks control which mount sources are allowed for
  nested containers. Currently: `/var/lib/containers/storage`, `/var/run/containers/storage`,
  `/var/cache/containers`. If rootless podman uses other paths (e.g., `/run/user/*/containers`),
  they must be added here or nested container creation will be blocked by security-policy.
- **Protected paths propagate into nested containers via rbind.** The sidecar's RO
  overlays (universal + `--protect`) are carried into nested container workdir mounts
  by recursive bind (default for podman `-v`). Explicit `-v path:path` overrides this,
  so `security-policy` check 15 (`checkMountReadonly`) blocks RW re-mounts by reading
  the sidecar's `/proc/self/mountinfo` to discover RO workdir sub-mounts. No config
  passing needed — self-describing from the sidecar's own mount state.
- **The agent shares the sidecar's network namespace.** Egress is controlled by iptables
  chains set up by the entrypoint. Agent: default deny + allowlist. Pods: default allow
  minus private CIDRs.
- **Host-side watcher (tripwire).** The launcher monitors all RO-mounted host paths via
  inotify (fsnotify). Snapshots file content + permissions before launch. Any modification
  (write, create, delete, move) kills the session via context cancellation. On exit, restores
  all files from snapshots — only writes back entries whose sha256 changed, removes
  attacker-created files not in the original snapshot. Disabled with `--disable-tripwire`.
  This is the last line of defense: the sidecar's UID mapping (uid 0 → subuid ≠ file owner)
  already prevents writes, but a full escape to host uid 1000 bypasses all in-container
  protections. The watcher runs on the host, outside all namespaces.

## Common Issues

- **"mount not permitted in nested containers"** — The security-policy createRuntime hook
  rejects mount sources not under the workdir or `infraMountPrefixes`. If rootless podman
  uses runtime paths outside these prefixes (e.g., `/run/user/<uid>/containers/`), add the
  prefix to `infraMountPrefixes` in both `security-policy.go` and `seal-inject.go`.
- **EXDEV errors in nested containers** — The rename shim (`rename_exdev_shim.so`) is
  LD_PRELOAD'd via containers.conf. If a tool still fails, check that `LD_PRELOAD` env
  is not being overridden.
- **"landlock LSM is not enabled"** — The launcher hard-fails if Landlock is absent from
  `/sys/kernel/security/lsm`. Enable it: boot with `lsm=landlock,...` or set
  `CONFIG_LSM=landlock,...` in kernel config.
- **"Kernel X.Y lacks Landlock IPC scoping"** — Warning only (not fatal). Kernel < 6.7
  lacks Landlock V6 IPC scoping. Abstract unix socket isolation is degraded. Upgrade
  to kernel 6.7+ for full protection.
- **Landlock hard-fails on kernel < 6.2** — seal.go requires ABI V3+. V4+ features
  (TCP connect, IoctlDev, IPC scoping) degrade via BestEffort.

## Testing

```bash
make test                                        # all unit tests
make test-integration                            # integration tests (sidecar + podman)
go test ./pkg/...                                              # launcher packages only
cd container-images/sidecar/seal && go test .                 # seal Landlock tests
cd container-images/sidecar/hooks/createRuntime && go test .  # security-policy checks
cd container-images/sidecar/hooks/precreate && go test .      # seal-inject policy derivation
cd container-images/sidecar/entrypoint && go test .           # entrypoint IP classification
```

Sidecar binaries have their own `go.mod` — run tests with `cd <dir> && go test .`,
not `go test ./<path>` from root.

**Unit tests cover:** security-policy checks (all 15 pass + fail cases), Landlock
policy derivation, mount classification, mount flag generation, protected path
logic, IP classification, seccomp profile management, host path filtering, duration
formatting, env cleanup, path splitting, infra mount detection.

**Integration tests cover** (build tag `integration`, in `pkg/sandbox/integration_test.go`):
security-policy enforcement (11 checks via CLI), seal-inject effects (UID, Landlock,
caps, hidepid, masked paths, rename shim), egress (approved/unapproved registry pulls,
iptables blocking, policy.json blocking, pod HTTP fetch, private CIDR blocking, pod block),
credential forwarding (gitconfig, gh, ssh socket end-to-end), third-party security audit
(am-i-isolated, CDK evaluate).

Manual verification:
```bash
./clampdown claude                              # starts claude agent session
./clampdown claude --workdir /path/to/project  # run against a specific directory
./clampdown opencode                           # starts opencode agent session
./clampdown list                      # show running sessions
./clampdown image push -s PID img    # push host image into session
./clampdown network agent allow -s PID example.com --port 443
./clampdown delete -s PID
./clampdown prune                     # clean per-project cache
```

## Dependencies

**Launcher** (`go.mod`): `urfave/cli/v3`, `fsnotify/fsnotify`.
**Seal** (`sidecar/seal/go.mod`): `go-landlock`, `golang.org/x/sys`, `libcap/psx`.
**Entrypoint, hooks** (`go.mod` each): stdlib only, no external dependencies.
**Host build**: Go toolchain (all binaries built on host, not in containers).
**Container images**: Alpine, podman-static v5.8.0 (no golang image needed at build time).

## Security Documentation

- `DIAGRAM.md` — Full security model: container topology, defense layers, seccomp
  architecture, network policy, Landlock policy, capability model, OCI hook pipeline.
