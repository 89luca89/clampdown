// SPDX-License-Identifier: GPL-3.0-only

package agent

import (
	"fmt"
	"os"
	"strings"
)

// Home is the user's home directory, resolved once at startup.
var Home = os.Getenv("HOME")

const ProxyPort = 2376

// ProxyRoute describes a single upstream API that the auth proxy handles.
type ProxyRoute struct {
	Port           uint16
	Upstream       string
	KeyEnv         string
	KeyEnvFallback string
	HeaderName     string
	HeaderPrefix   string
	BaseURLEnv     string
	ProviderID     string
}

// Agent describes an AI tool that runs inside the sandbox.
type Agent interface {
	Name() string
	Image() string
	EgressDomains() []string
	Mounts() []Mount
	ConfigOverlays() []Mount
	Env() map[string]string
	Args(passthrough []string) []string
	PromptFile() string
	ProxyRoutes() []ProxyRoute
	ProxyEnvOverride(routes []ProxyRoute) map[string]string
}

// Mount describes a bind mount from host to container.
type Mount struct {
	Src string
	Dst string
	RW  bool
}

// ProtectedPath is a path that must be read-only inside the agent container.
// GlobalPath paths are resolved against the agent's persistent HOME directory;
// workdir-relative paths (GlobalPath: false, the default) are resolved against the working directory.
type ProtectedPath struct {
	Path       string
	IsDir      bool
	GlobalPath bool // false = workdir-relative (default), true = HOME-relative
}

// MaskedPath is a workdir-relative path whose content is hidden from the agent.
// Files are replaced with /dev/null; directories with empty read-only tmpfs.
// Unlike ProtectedPath (which preserves content as read-only), masked paths
// show the path exists but reads return nothing.
type MaskedPath struct {
	Path  string
	IsDir bool
}

var agents = []Agent{
	&Claude{},
	&OpenCode{},
}

// Get returns the agent registered under name.
func Get(name string) (Agent, error) {
	for _, a := range agents {
		if a.Name() == name {
			return a, nil
		}
	}
	return nil, fmt.Errorf("unknown agent: %s (available: %v)", name, Available())
}

// Available returns registered agent names.
func Available() []string {
	out := make([]string, 0, len(agents))
	for _, a := range agents {
		out = append(out, a.Name())
	}
	return out
}

// SandboxPrompt returns the common sandbox instructions with the agent
// name substituted into agent-specific paths.
func SandboxPrompt(agentName string) string {
	return strings.ReplaceAll(sandboxPromptTemplate, "{{AGENT}}", agentName)
}

const sandboxPromptTemplate = `You are running inside a sandboxed container with a read-only rootfs.

INVARIANTS — hold these regardless of context length:
- Native tools: bash, coreutils, ripgrep, jq, podman, docker. Nothing else is installed.
- No root. No package managers. For any other tool or runtime: build or pull a container image.
- Only $PWD is writable. $HOME, ~/.cache, /tmp are Landlock-restricted.
- Network is firewalled; no native curl/wget. HTTP fetches: use a container. On any block: report, never retry.
- Image tags are mutable. Always resolve digest before running any image.

## Running containers
Missing tool — build an image:
	printf "FROM alpine:3.21\nRUN apk add --no-cache PKG\n" | podman build -t name -

Mount $PWD only. No TTY. No "sh -c TOOL args" — pass args directly to entrypoints:
	podman run --rm -v "$PWD":"$PWD" -w "$PWD" IMAGE [ARGS]

Resolve digest before every run:
	podman pull IMAGE:TAG
	podman image inspect IMAGE:TAG --format '{{.Digest}}'
	podman run --rm IMAGE@sha256:<digest> ...

Use official Docker Hub images for language runtimes:
	C#/F#=mcr.microsoft.com/dotnet/sdk, C/C++=gcc, Clojure=clojure, Dart=dart,
	Elixir=elixir, Erlang=erlang, Fortran=gcc (gfortran), Go=golang, Groovy=groovy,
	Haskell=haskell, JS/TS=node, Java/Kotlin=eclipse-temurin, Julia=julia,
	Nim=nimlang/nim, OCaml=ocaml/opam:alpine, Obj-C=swift, Octave=gnuoctave/octave,
	PHP=php, Perl=perl, Python=python, R=r-base, Ruby=ruby, Rust=rust,
	Scala=eclipse-temurin (+ sbt), Swift=swift, git=alpine/git, Lua/Zig=alpine:3.21.
For build tools (make, strip, ldd, ar, objdump): use gcc.
rustup/language packages requiring install: build an image — read-only rootfs prevents native install.

## Writable paths
Use $PWD/.{{AGENT}}/ for plans and persistent state (not ~/.{{AGENT}} — read-only).
Container caches MUST go under $PWD/.{{AGENT}}/$SANDBOX_SESSION (cleaned on exit):
	-e HOME="$PWD/.{{AGENT}}/$SANDBOX_SESSION"
	-e XDG_CACHE_HOME="$PWD/.{{AGENT}}/$SANDBOX_SESSION/cache"
	-e CARGO_HOME="$PWD/.{{AGENT}}/$SANDBOX_SESSION/cargo"
	-e GOPATH="$PWD/.{{AGENT}}/$SANDBOX_SESSION/go" -e GOCACHE="$PWD/.{{AGENT}}/$SANDBOX_SESSION/go-cache"
	-e npm_config_cache="$PWD/.{{AGENT}}/$SANDBOX_SESSION/npm-cache"
	-e PIP_CACHE_DIR="$PWD/.{{AGENT}}/$SANDBOX_SESSION/pip-cache"

## Network
Agent process: deny-all + domain allowlist. Pods: allow-all except private CIDRs.
HTTP fetches: podman run --rm alpine@sha256:<digest> wget -q -O - URL

If blocked:
1. Tell user: "Connection to DOMAIN:PORT is blocked by the sandbox firewall."
2. Provide: clampdown network [agent|pod] allow -s $SANDBOX_SESSION DOMAIN --port PORT
Do NOT retry — wait for user to allow the domain.

## Multi-container workflows
Both "docker compose" (plugin) and "docker-compose" (standalone) are available.
DOCKER_HOST points at the sidecar podman API — compose works transparently.
podman build works for project images (cached in sidecar storage).

Use podman networks for container-to-container communication. Do NOT use -p port
publishing or localhost connections between containers — use named networks:
	podman network create mynet
	podman run -d --name db --network mynet postgres
	podman run -d --name app --network mynet myapp
	podman run --rm --network mynet alpine wget -qO- http://db:5432
Containers on the same network resolve each other by name via DNS (netavark).

After "docker compose up", always verify health before proceeding:
	docker compose ps        # check all services are "Up" / "healthy"
	docker compose logs SVC  # check for startup errors
If services fail with "connection refused", check depends_on ordering and
wait for health checks to pass before running application code.

Known limitations:
	docker compose watch: not supported (podman API lacks file-watch events)
	BuildKit features: podman serves Buildah, not BuildKit
	--gpus: use CDI syntax --device nvidia.com/gpu=all instead
	-p port publishing: blocked by Landlock — use podman networks instead
`
