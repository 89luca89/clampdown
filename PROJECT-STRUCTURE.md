<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Project Structure

```
main.go                          Entry point → pkg/cli.Run()
pkg/
  agent/
    agent.go                     Agent interface + registry
    claude.go                    Claude Code agent (image, egress domains, prompt)
    codex.go                     OpenAI Codex agent (API proxy + ChatGPT auth cache prep)
    opencode.go                  OpenCode agent (image, egress domains, prompt)
    skill.go                     Sandbox skill template + skill directory helpers
  cli/
    app.go                       urfave/cli commands (agent subcommands, network, session)
    config.go                    Config file loading ($XDG_CONFIG_HOME/clampdown/config.json)
  container/
    runtime.go                   Runtime interface (StartSidecar, StartProxy, StartAgent, AttachAgent, Exec, List, NudgeTerminal)
    podman.go                    Podman implementation
    docker.go                    Docker implementation
    detect.go                    Runtime auto-detection
  sandbox/
    sandbox.go                   Start()/Attach() orchestrator — starts sidecar, proxy, agent; SessionState persistence
    config.go                    Sidecar/agent/proxy config builders, Landlock policy, proxy routing
    credentials.go               Opt-in host credential forwarding (gitconfig, gh, ssh)
    gitignore.go                 .git/info/exclude management for protected/masked paths
    log.go                       Audit log and terminal output processing (timestamp stripping, ANSI cleanup)
    paths.go                     Per-project cache paths (hashed workdir)
    rcfile.go                    .clampdownrc loading (global + per-project KEY=VALUE)
    integration_test.go          Integration tests (build tag: integration)
    mounts/mounts.go             Mount building: workdir, protected paths, config overlays, state dir
    network/
      egress.go                  DNS resolution of domain allowlists (parallel, multi-resolver)
      firewall.go                Runtime iptables rule management (agent/pod allow/block/reset)
    seccomp/
      seccomp.go                 Embedded seccomp profile management (//go:embed)
      seccomp_sidecar.json       Sidecar seccomp profile (embedded via //go:embed)
      seccomp_agent.json         Agent/workload seccomp profile (embedded via //go:embed)
    session/session.go           Session listing, stop, deletion, sidecar/agent lookup
    tripwire/tripwire.go         Host-side inotify tripwire: snapshot, monitor, restore RO paths
container-images/
  sidecar/
    Containerfile                FROM scratch assembly (podman-static, iptables, shim, pre-built Go bins)
    containers.conf              Hardened defaults for nested containers
    policy.json                  Image pull + archive allowlist (docker.io, ghcr.io, quay.io, localhost)
    registries.conf              Registry mirror/search configuration
    seccomp_nested.json          Workload seccomp profile (= seccomp_agent.json)
    storage.conf                 Container storage driver configuration
    entrypoint/
      entrypoint.go              Sidecar init: /proc/sys RO, cgroup v2, iptables firewall, identity files
      bootstrap.go               Pre-startup kernel configuration and boot checks
      filter.go                  Seccomp-notif filtering and syscall analysis
      handlers.go                Syscall interceptors for mount/exec/path operations
      protect.go                 RO mount overlay and mask enforcement
      supervisor.go              Signal handling and child process management
      execallow.go               Hash-verified exec allowlist enforcement
      go.mod                     Separate module (stdlib only)
    log/
      log.go                     /log binary: audit trail injection into sidecar stderr
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
    shims/
      rename_exdev_shim.c        LD_PRELOAD .so for EXDEV rename fallback (copy+unlink)
      test_shim.c                Shim unit test (C)
      test.sh                    Shim integration test
  helpers/
    sandbox_command_helper.sh    Shell functions replacing commands that always fail (curl, wget, sudo, apk)
    sandbox_network_helper.c     LD_PRELOAD connect() interceptor: prints guidance on ECONNREFUSED/ETIMEDOUT
  claude/
    Containerfile                Claude agent image (Alpine + claude CLI + podman-remote)
  codex/
    Containerfile                Codex agent image (Alpine + native Codex CLI binary)
  opencode/
    Containerfile                OpenCode agent image (Alpine + native Bun binary)
  proxy/
    proxy.go                     Auth proxy: reverse proxy with API key injection (stdlib only)
    Containerfile                FROM scratch proxy image (seal + auth-proxy + CA certs)
    go.mod                       Separate module (stdlib only)
tools/
  extract-syscalls.sh            Static syscall extractor — disassembles binaries/images to identify required syscalls for seccomp tuning
  security-audit/
    sandbox-escape-audit.md      Escape vector checklist
    security-audit.sh            Full security audit script
    security-audit-project.sh    Project-level security audit
    security-audit-sandbox.sh    Sandbox-specific security audit
```
