<\!-- SPDX-License-Identifier: GPL-3.0-only -->

# Contributing to Clampdown

Bug reports, fixes, and improvements are welcome. This document covers how to contribute.

## Getting started

1. Fork the repository and create a branch from `main`.
2. Build everything: `make all` (requires Go and podman or docker).
3. Run tests: `make test`.
4. Submit a pull request.

## Modules

Clampdown has five Go modules — each built and tested independently:

| Module | Location |
|--------|----------|
| Launcher | root (`go.mod`) |
| sandbox-seal | `container-images/sidecar/seal/` |
| entrypoint | `container-images/sidecar/entrypoint/` |
| security-policy | `container-images/sidecar/hooks/createRuntime/` |
| seal-inject | `container-images/sidecar/hooks/precreate/` |

Run `make all` to build all binaries and container images. Run `make test` to test all modules. 
Run `make test-integration` to run integration tests.

## Testing

All changes must include or maintain passing tests.

Unit tests run without podman (fast, no external deps):

```bash
make test
```

Integration tests require a working podman installation and internet access:

```bash
make test-integration
```

Tests live in `_test.go` files using external test packages (`package foo_test`). 
Unexported symbols needed by tests are exposed via `export_test.go`. 
Test logic with branches — do not write tests for constants, trivial getters, or data that can't fail.

## Code style

- Standard `gofmt`. No `if x := expr(); x != ...` init-statement syntax — separate assignment from condition.
- Comment only when necessary: non-obvious design decisions, security rationale, or behavioral edge cases. 
- Keep functions small and clearly named. If you can't name it, the abstraction is wrong.
- No premature abstraction. Inline until a pattern proves itself.

## Submitting changes

- One logical change per pull request.
- If you added code, add or update tests.
- If you changed the security model (seccomp profiles, Landlock policy, OCI hooks, firewall rules), update `DIAGRAM.md`.
- Ensure `make test` passes before opening a PR.
- Describe *why* in the PR description, not just what changed.

## License

By contributing, you agree your contributions will be licensed under the GNU General Public License v3.
