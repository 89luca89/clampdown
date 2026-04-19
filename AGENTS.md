<\!-- SPDX-License-Identifier: GPL-3.0-only -->

@DIAGRAM.md
@PROJECT-STRUCTURE.md
@README.md
@SECURITY.md
@SUPERVISOR-DIAGRAM.md

## Behavior

- Blunt, directive.
- No filler.
- No emojis.
- No engagement optimization.
- Correct when wrong.
- Always ultrathink.

## Rules (mandatory, zero exceptions)

1. **Read before edit.** Never modify a file you haven't Read in this conversation. Inlined content and training data are not current state — read the file.
2. **Plan before execute.** New task → read, search, analyze. No writes until user approves.
3. **Scope to the request.** Do what was asked. No drive-by fixes, no extra features, no touching adjacent code.
4. **Match existing style.** Read surrounding code before first edit in a file. Match naming, formatting, patterns exactly.
5. **Approve before apply.** Present approach with alternatives and tradeoffs. Implement after user confirms.
6. **Never guess.** Unsure what a file contains or how it's structured? Read it. Don't reconstruct from memory or training data.
7. **Never commit automatically** Only do what you are explicitly asked to do.

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

### Writing Style

- Do not use arrows, bullet points, or special symbols in the output.
- Provide the answer in plain text only, avoiding all unicode symbols (like →, ⇒, etc.)
- Use only alphanumeric characters and standard punctuation.
- Format the output as a simple paragraph, no arrows or structural markers.

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

## Build

```bash
make all               # builds: sidecar, proxy, claude, opencode images + launcher binary
make test              # runs all unit tests
make test-integration  # builds sidecar, runs integration tests (needs podman + internet)
make sidecar           # builds Go binaries on host, then sidecar container image
make proxy             # builds proxy auth image
make claude            # copies seal into container-images/claude/, builds claude agent image
make opencode          # copies seal into container-images/opencode/, builds opencode agent image
make launcher          # CGO_ENABLED=0 go build
make install           # installs to ~/.local/bin/
```

All five Go binaries (seal, entrypoint, security-policy, seal-inject, auth-proxy)
are built on the host by Make (`CGO_ENABLED=0`), then COPY'd into their respective
FROM scratch images. No Go compilation inside container builds. The C rename shim,
podman-static download, and iptables extraction remain as Containerfile build stages.

Container image builds use stamp files (`.sidecar.stamp`, `.claude.stamp`, etc.) —
Make skips rebuilds when no source file changed.

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

**Unit tests cover:** security-policy checks (all 17 pass + fail cases), Landlock
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
./clampdown list --all                # show running + stopped sessions
./clampdown attach -s <id>           # reattach to running session
./clampdown stop -s <id>             # stop all session containers
./clampdown image push -s <id> img   # push host image into session
./clampdown network agent allow -s <id> example.com --port 443
./clampdown delete -s <id>           # remove stopped session
./clampdown prune                     # clean per-project cache
```

## Dependencies

**Launcher** (`go.mod`): `urfave/cli/v3`, `fsnotify/fsnotify`.
**Seal** (`sidecar/seal/go.mod`): `go-landlock`, `golang.org/x/sys`, `libcap/psx`.
**Proxy** (`proxy/go.mod`): stdlib only, no external dependencies.
**Entrypoint, hooks** (`go.mod` each): stdlib only, no external dependencies.
**Host build**: Go toolchain (all binaries built on host, not in containers).
**Container images**: Alpine, podman-static v5.8.1 (no golang image needed at build time).
