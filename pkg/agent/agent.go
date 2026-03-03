// SPDX-License-Identifier: GPL-3.0-only

package agent

import (
	"fmt"
	"os"
	"strings"
)

// Home is the user's home directory, resolved once at startup.
var Home = os.Getenv("HOME")

// Agent describes an AI tool that runs inside the sandbox.
type Agent interface {
	Name() string
	Image() string
	EgressDomains() []string
	Mounts() []Mount
	ConfigOverlays() []Mount
	Env() map[string]string
	Args(passthrough []string) []string
	// PromptFile returns the container-side path where the launcher
	// should write the sandbox instructions. The agent reads this file
	// via its native prompt discovery mechanism:
	//   Claude:   --append-system-prompt-file (passed via Args)
	//   OpenCode: ~/.config/opencode/instructions.md (auto-discovered)
	// Return "" if the agent has no prompt file mechanism.
	PromptFile() string
	// ForwardEnv returns host environment variable names to forward into
	// the agent container. Used for API keys and auth tokens. Only
	// variables that are set on the host are forwarded.
	ForwardEnv() []string
}

// Mount describes a bind mount from host to container.
type Mount struct {
	Src string
	Dst string
	RW  bool
}

// ProtectedPath is a workdir-relative path that must be
// read-only inside the agent container.
type ProtectedPath struct {
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

## Available tools
bash, coreutils, ripgrep, jq, podman, docker.

## Running containers
You are NOT root. Package managers (apk, apt) fail at runtime — build images:
	printf "FROM alpine:3.21\nRUN apk add --no-cache PKG\n" | podman build -t name -
Built images are cached; subsequent runs are instant.

Mounts restricted to $PWD only:
	podman run --rm -v "$PWD":"$PWD" -w "$PWD" IMAGE [ARGS]
No TTY — do NOT use -t. Pass args directly to entrypoints, not "sh -c TOOL args".

ALWAYS resolve image digests before running (tags are mutable):
	podman pull IMAGE:TAG
	podman image inspect IMAGE:TAG --format '{{.Digest}}'
	podman run --rm IMAGE@sha256:<digest> ...
Use official Docker Hub images for language runtimes:
	C#/F#=mcr.microsoft.com/dotnet/sdk,
	C/C++=gcc,
	Clojure=clojure
	Dart=dart,
	Elixir=elixir
	Erlang=erlang,
	Fortran=gcc (gfortran)
	Go=golang
	Groovy=groovy
	Haskell=haskell
	JS/TS=node
	Java/Kotlin=eclipse-temurin
	Julia=julia
	Nim=nimlang/nim
	OCaml=ocaml/opam:alpine
	Obj-C=swift,
	Octave=gnuoctave/octave
	PHP=php
	Perl=perl
	Python=python
	R=r-base
	Ruby=ruby
	Rust=rust
	Scala=eclipse-temurin (+ sbt),
	Swift=swift
	git=alpine/git.
	Lua/Zig: build from alpine:3.21.
For build tools (make, strip, ldd, ar, objdump): use gcc.
rustup component add <component> cannot install into /usr/local/rustup at runtime (read-only rootfs),
build an image with those tools if needed. This is true for other language packages too.
For anything else, build from alpine.

## Writable paths
$HOME, ~/.cache, /tmp are Landlock-restricted. Only $PWD is writable.
Use $PWD/.{{AGENT}}/ for plans and persistent state (not ~/.{{AGENT}} — read-only).

Container tool caches MUST go under $PWD/.{{AGENT}}/$SANDBOX_SESSION (cleaned on exit).
Redirect home and cache for every container you run:
	-e HOME="$PWD/.{{AGENT}}/$SANDBOX_SESSION"
	-e XDG_CACHE_HOME="$PWD/.{{AGENT}}/$SANDBOX_SESSION/cache"
For language-specific caches, redirect similarly:
	-e CARGO_HOME="$PWD/.{{AGENT}}/$SANDBOX_SESSION/cargo"
	-e GOPATH="$PWD/.{{AGENT}}/$SANDBOX_SESSION/go" -e GOCACHE="$PWD/.{{AGENT}}/$SANDBOX_SESSION/go-cache"
	-e npm_config_cache="$PWD/.{{AGENT}}/$SANDBOX_SESSION/npm-cache"
	-e PIP_CACHE_DIR="$PWD/.{{AGENT}}/$SANDBOX_SESSION/pip-cache"

## Network
Agent process: deny-all + domain allowlist. Pods: allow-all except private CIDRs.
For HTTP fetches use:
	podman run --rm alpine@sha256:<digest> wget -q -O - URL

If blocked:
1. Tell user: "Connection to DOMAIN:PORT is blocked by the sandbox firewall."
2. Provide: clampdown network [agent|pod] allow -s $SANDBOX_SESSION DOMAIN --port PORT
Do NOT retry — wait for user to allow the domain.

## Multi-container workflows
Both "docker compose" (plugin) and "docker-compose" (standalone) are available.
DOCKER_HOST points at the sidecar podman API — compose works transparently.
Start service dependencies: podman run -d --name db postgres, redis, mysql, etc.
Container-to-container DNS works on podman bridge networks (netavark).
podman build works for project images (cached in sidecar storage).

After "docker compose up", always verify health before proceeding:
	docker compose ps        # check all services are "Up" / "healthy"
	docker compose logs SVC  # check for startup errors
If services fail with "connection refused", check depends_on ordering and
wait for health checks to pass before running application code.

Known limitations:
	docker compose watch: not supported (podman API lacks file-watch events)
	BuildKit features: podman serves Buildah, not BuildKit
	--gpus: use CDI syntax --device nvidia.com/gpu=all instead
`
