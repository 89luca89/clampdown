<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Clampdown

<p align="center"><img src="assets/clampdown-icon.png" width="250" alt="clampdown icon" /></p>

Run AI coding agents in hardened container sandboxes.

AI coding agents run arbitrary code on your machine. clampdown confines them to a
hardened container sandbox: filesystem access is restricted to your project, network
egress is limited to the APIs the agent needs, and every tool container the agent
spawns gets the same enforcement.

![clampdown architecture](assets/clampdown-diagram.png)

> **Blue** = sidecar. **Yellow** = agent. **Green** = tool containers.
> **Red text** = untrusted egress. **Green text** = trusted egress.
> **Border color** = namespace trust level (see legend in diagram).

---

## Container overview

clampdown runs three container types with different privilege levels:

| | Sidecar | Agent | Tool (nested) |
|---|---|---|---|
| Purpose | Container runtime + firewall | AI agent process | Tools the agent spawns |
| Base image | `FROM scratch` (no shell, no libc) | Alpine | User-chosen |
| Capabilities | 17 (`SYS_ADMIN`, `NET_ADMIN`, ...) | 0 (`cap-drop=ALL`) | 10 default (effective set empty) |
| Seccomp | ~70 blocked | ~115 blocked | ~115 blocked + inherited sidecar |
| Landlock | No (incompatible with `mount()`) | workdir RW, rootfs RO | Derived from bind mounts |
| Secrets | Registry credentials (opt-in) | API keys | None |
| Network egress | N/A | Deny + allowlist only | Allow, private CIDRs blocked |
| Rootfs | Read-only | Read-only | Read-only |
| Runs as | root (userns-mapped) | Non-root | Non-root (hook-enforced) |
| SELinux | `container_engine_t` | `container_t` | `container_t` |
| AppArmor | unconfined | confined | confined |

- The sidecar is privileged enough to run podman and enforce firewall rules, but has no
shell and no libc so it cannot be repurposed.  
- The agent holds API keys and can reach its provider's endpoints, but nothing else.  
- Tool containers have open egress to the public internet but hold no secrets: 
they cannot reach private networks, and credentials are never forwarded unless explicitly opted in.

---

## Threat model

clampdown treats the agent as an untrusted process. Not because current models are
malicious, but because the attack surface is real: prompt injection can hijack an
agent's actions, jailbreaks can override its instructions, and even well-behaved
models run arbitrary code that may do things you didn't ask for. If the agent can
`curl`, `cat ~/.ssh`, or `podman run --privileged`, the question is when — not
whether — something goes wrong.

Every defense in clampdown enforces from outside the agent's process. Filesystem
restrictions are kernel-level Landlock rulesets applied before the agent binary starts.
Network policy is iptables chains installed by the sidecar, in a network namespace the
agent shares but cannot configure. Seccomp profiles are inherited from the container
runtime — the agent cannot modify or remove them. OCI hooks validate every container
the agent creates before its entrypoint runs, and there is no flag to skip them.

None of these controls depend on the agent cooperating. A fully compromised agent —
one that ignores its system prompt entirely and tries to escape — hits the same
kernel-enforced walls as one following instructions. That's the point.

---

## Security model

### Nested container enforcement

The agent runs inside a zero-capability container: `cap-drop=ALL`, read-only rootfs,
`no-new-privileges`, and a seccomp profile that blocks ~115 syscalls including all
known kernel exploit primitives (io_uring, userfaultfd, BPF, perf_event, splice/tee).
When the agent needs to run a tool — a compiler, a test runner, a shell command — it
sends a `podman run` request to the sidecar's API socket. The sidecar intercepts every
container creation through two OCI hooks that run synchronously before the container
process starts:

**precreate** (`seal-inject`): rewrites the container entrypoint to `sandbox-seal`,
which applies Landlock and cleans up unsafe file descriptors before execing the real
command. The hook also assigns a non-root UID mapped outside the container's user
namespace, mounts `hidepid=2` on `/proc`, and injects masked paths over sensitive
kernel interfaces (`/proc/kcore`, `/proc/sysrq-trigger`, and nine others).

**createRuntime** (`security-policy`): validates the final OCI config against 15
security checks — blocking privileged mode, disallowed capabilities, host namespace
sharing, unsafe bind mounts, dangerous devices, and RW re-mounts of protected paths.
A container that fails any check is killed before its entrypoint runs.

Both hooks apply to every `podman run` the agent issues. There is no opt-out.

### Landlock filesystem isolation

[Landlock](https://landlock.io/) is a Linux kernel LSM that enforces filesystem
access control at the kernel level, beneath and independent of container bind mounts
and Unix permission bits.

`sandbox-seal` applies a Landlock ruleset inside the agent process just before it
execs the agent binary. The rules cannot be lifted after exec — Landlock policies are
inherited across exec and can only be made more restrictive, never relaxed.

Agent policy:
- **Read-write + execute**: your working directory (the project being edited)
- **Read + execute**: system directories (`/usr`, `/bin`, `/lib`, `/etc`, …)
- **No access**: everything else — host home, other projects, sensitive kernel paths

Tool containers launched by the agent get a derived policy based on their mount list:
writable access is granted only to paths explicitly bind-mounted into the container.

Landlock V3 (kernel ≥ 6.2) is a hard requirement. The launcher refuses to start if
Landlock is absent. Kernel ≥ 6.7 is recommended for full IPC namespace scoping.

### Network isolation

The agent container shares the sidecar's network namespace. All egress is controlled
by iptables rules the sidecar installs at startup — not by application-layer filtering
that the agent could bypass.

**Agent (default: deny)**: outbound connections are blocked except for an explicit
allowlist of domains required by the agent (API endpoints, auth, telemetry). The
allowlist is resolved to IPs at session startup and installed as iptables ACCEPT rules.
DNS queries are rate-limited to 10 requests per second.

**Tool containers (default: allow)**: outbound is open to the public internet, but all
RFC 1918 addresses, loopback, link-local, and IPv6 ULA ranges are permanently blocked.
Tool containers cannot reach the host, the sidecar, or other containers by internal IP.

Private CIDRs are blocked for both the agent and tool containers regardless of policy.
Both defaults are configurable (`--agent-policy`, `--pod-policy`), and rules can be
adjusted at runtime without restarting the session — see
[Runtime network control](#runtime-network-control).

For the full technical reference — seccomp profile tables, iptables chains, Landlock
access sets, capability lists, OCI hook pipeline, and masked path inventory — see
[DIAGRAM.md](DIAGRAM.md).

---

## Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| Linux | — | Landlock is Linux-only |
| Kernel | ≥ 6.2 | Hard requirement. Session refuses to start below this. |
| Kernel | ≥ 6.7 | Recommended. IPC namespace scoping (Landlock V6) requires 6.7+. |
| rootless podman | any recent | or Docker (rootful with a warning) or nerdctl |
| Go | ≥ 1.23 | Build-time only |

Verify Landlock is active on your kernel:

```sh
cat /sys/kernel/security/lsm   # must contain "landlock"
```

---

## Install

```sh
git clone https://github.com/89luca89/clampdown
cd clampdown
make all      # builds sidecar image, agent images, and launcher binary
make install  # copies binary to ~/.local/bin/clampdown
```

`make all` builds three container images (`clampdown-sidecar`, `clampdown-claude`,
`clampdown-opencode`) and the `clampdown` launcher binary. Images are rebuilt only when
their source changes (stamp files).

---

## Quick start

Store API keys in `~/.config/clampdown/clampdownrc` (created once, used by all sessions):

```sh
# ~/.config/clampdown/clampdownrc
ANTHROPIC_API_KEY=sk-ant-...
```

Per-project overrides go in `.clampdownrc` at the root of each project. Project values
take precedence over the global file:

```sh
# /path/to/project/.clampdownrc
ANTHROPIC_API_KEY=sk-ant-...   # project-specific key
```

Then run:

```sh
clampdown claude

# OpenCode (supports multiple providers)
clampdown opencode

# Run against a specific directory (defaults to $PWD)
clampdown claude --workdir /path/to/project

# Pass flags through to the agent
clampdown claude -- --model claude-opus-4-5
```

Alternatively, pass keys via environment:

```sh
ANTHROPIC_API_KEY=sk-ant-... clampdown claude
```

The first run pulls base images and builds a per-project container storage cache under
`~/.cache/clampdown/`. Subsequent runs start faster.

---

## Agents

| Agent | Command | Provider keys forwarded |
|-------|---------|------------------------|
| Claude Code | `clampdown claude` | `ANTHROPIC_API_KEY` |
| OpenCode | `clampdown opencode` | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GROQ_API_KEY`, `DEEPSEEK_API_KEY`, `MISTRAL_API_KEY`, `XAI_API_KEY`, `OPENROUTER_API_KEY`, `OPENCODE_API_KEY` |

Only keys that are set in the host environment are forwarded. Unset keys are not passed.

---

## Options

All options can be set on the CLI, in `config.json`, or (for environment-variable-mapped
options) via env.

```
clampdown [options] <agent> [-- agent-flags...]
```

### Network

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--agent-policy` | `deny` | `SANDBOX_AGENT_POLICY` | Agent egress default: `deny` (allowlist only) or `allow` |
| `--agent-allow` | — | `SANDBOX_AGENT_ALLOW` | Extra domains for the agent allowlist (comma-separated) |
| `--pod-policy` | `allow` | `SANDBOX_POD_POLICY` | Tool container egress default: `allow` or `deny` |

The agent's egress allowlist includes the domains required by the agent (API endpoints,
auth, telemetry). Private CIDRs (RFC 1918, loopback, link-local, IPv6 ULA) are always
blocked for both agent and tool containers, regardless of policy.

### Filesystem

| Flag | Default | Description |
|------|---------|-------------|
| `--allow-hooks` | off | Allow agent to modify `.git/hooks/` (read-only by default) |
| `--protect` | — | Additional paths to protect read-only (repeatable; trailing `/` = directory) |

Protected paths are always read-only inside the agent and nested containers, regardless
of flags: `.git/config`, `.gitmodules`, `.clampdownrc`, `.devcontainer`, `.envrc`,
`.idea`, `.mcp.json`, `.vscode`. User `--protect` paths get the same enforcement.
Protected paths propagate into nested containers via recursive bind mounts; explicit
RW re-mounts are blocked by the security-policy hook.

### Resources

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--memory` | `4g` | `SANDBOX_MEMORY` | Memory limit for agent and tool containers |
| `--cpus` | `4` | `SANDBOX_CPUS` | CPU limit |

### Credentials

Credentials are opt-in. Nothing is forwarded by default.

| Flag | Description |
|------|-------------|
| `--gitconfig` | Forward `~/.gitconfig` read-only into tool containers |
| `--gh` | Forward `~/.config/gh` read-only into tool containers (GitHub CLI auth) |
| `--ssh` | Forward `SSH_AUTH_SOCK` into tool containers |

### Registry

| Flag | Default | Env | Description |
|------|---------|-----|-------------|
| `--registry-auth` | off | `SANDBOX_REGISTRY_AUTH` | Forward host registry credentials to the agent |
| `--require-digest` | `warn` | `SANDBOX_REQUIRE_DIGEST` | Image digest enforcement: `warn` or `block` |

### Other

| Flag | Default | Description |
|------|---------|-------------|
| `--runtime` | auto | Container runtime: `podman`, `docker`, `nerdctl` |
| `--disable-tripwire` | off | Don't kill session on protected path modification (still restores on exit) |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |

---

## Session management

```sh
# List all running sessions
clampdown list

# Stop a session and clean up its containers
clampdown delete -s <session-id>

# Remove all cached container storage for the current project
clampdown prune
```

---

## Runtime network control

Network rules can be adjusted while a session is running:

```sh
# Allow the agent to reach a host on a specific port
clampdown network agent allow -s <session-id> example.com --port 443

# Block a host
clampdown network agent block -s <session-id> example.com --port 443

# Remove all dynamic agent rules (returns to startup state)
clampdown network agent reset -s <session-id>

# Same commands for tool containers (pod)
clampdown network pod allow -s <session-id> db.internal --port 5432
clampdown network pod reset -s <session-id>

# Show current rules for a session
clampdown network list -s <session-id>
```

Targets can be hostnames, IP addresses, or CIDRs. Hostnames are resolved to IPs at the
time the rule is applied.

---

## Pushing images into a session

Tool containers pull from the sidecar's isolated registry. To make a local host image
available inside the sandbox:

```sh
clampdown image push -s <session-id> myimage:latest
```

Images already present in the sidecar (same image ID) are skipped.

---

## Configuration

### config.json

Persistent defaults live in `$XDG_CONFIG_HOME/clampdown/config.json` (typically
`~/.config/clampdown/config.json`). Any CLI option can be set here.

```json
{
  "agent_policy": "deny",
  "agent_allow": "registry.mycompany.com",
  "gitconfig": true,
  "gh": true,
  "memory": "8g",
  "cpus": "8",
  "require_digest": "block"
}
```

### .clampdownrc

`KEY=VALUE` environment files for injecting additional env vars into the agent. Two
locations are merged; project overrides global:

- `~/.clampdownrc` — global
- `$workdir/.clampdownrc` — per-project

```sh
# ~/.clampdownrc
ANTHROPIC_API_KEY=sk-ant-...

# myproject/.clampdownrc
SOME_PROJECT_TOKEN=abc123
```

Lines starting with `#` are comments. Values may be quoted with `"` or `'`.

---

## Building from source

```sh
make all               # sidecar image + agent images + launcher
make test              # all unit tests (no podman required)
make test-integration  # integration tests (requires podman + internet)
make sidecar           # sidecar image only
make claude            # claude agent image only
make opencode          # opencode agent image only
make launcher          # launcher binary only
make install           # install launcher to ~/.local/bin/
make clean             # remove built images and binaries
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution guidelines.

---

# Future work

**VM backend** 
  - lima/colima-based runtime that isolates at the hypervisor boundary.
    - Required for workloads needing `NET_ADMIN`, KVM, or GPU access. 
    - One long-lived VM per user, multiple agent sessions sharing it.

**Structured audit trail** 
  - a tamper-evident JSONL event log written by the sidecar
  (outside agent reach): every podman API call, OCI hook decision (allow/deny/mutate),
  iptables egress hit, and tripwire trigger. SHA-256 hash chain per entry. Queryable
  from the host, with optional webhook notifications (Slack/HTTP) on deny or kill events.

**More agents** 
  - Gemini CLI 
  - OpenAI Codex. 

**macOS support**
  - depends on the VM backend; Landlock and iptables are Linux-only.

---

# License

[GNU General Public License v3.0](COPYING.md)
