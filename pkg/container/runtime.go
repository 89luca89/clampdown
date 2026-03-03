// SPDX-License-Identifier: GPL-3.0-only

package container

import (
	"context"
)

// SidecarAPI is the endpoint where the sidecar's podman service listens.
const SidecarAPI = "tcp://localhost:2375"

// Runtime abstracts container operations across podman/docker/nerdctl.
type Runtime interface {
	CleanStale(ctx context.Context, prefix string)
	Exec(ctx context.Context, container string, cmd []string, env map[string]string) ([]byte, error)
	ImageID(ctx context.Context, image string) (string, error)
	IsRootless(ctx context.Context) (bool, error)
	List(ctx context.Context, labels map[string]string) ([]Info, error)
	Logs(ctx context.Context, container string) ([]byte, error)
	Name() string
	Prune(ctx context.Context, projectDir string) error
	PushImage(ctx context.Context, sidecar string, images []string) error
	Remove(ctx context.Context, names ...string) error
	StartAgent(ctx context.Context, cfg AgentContainerConfig) error
	StartSidecar(ctx context.Context, cfg SidecarContainerConfig) error
}

// Info holds the subset of container metadata needed for session listing.
type Info struct {
	Name      string
	Labels    map[string]string
	State     string
	StartedAt int64
}

// RegistryDomains lists domains needed by the sidecar for container image pulls.
// Resolved to IPs at startup via DNS.
//
// Docker Hub: https://docs.docker.com/desktop/setup/allow-list/
// Quay.io:    https://access.redhat.com/articles/7084334
// ghcr.io:    https://github.com/orgs/community/discussions/118629
var RegistryDomains = []string{
	// Docker Hub
	"auth.docker.io",
	"docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
	"production.cloudflare.docker.com",
	"registry-1.docker.io",
	// Quay.io
	"cdn.quay.io",
	"cdn01.quay.io",
	"cdn02.quay.io",
	"cdn03.quay.io",
	"cdn04.quay.io",
	"cdn05.quay.io",
	"cdn06.quay.io",
	"quay.io",
	// ghcr.io
	"ghcr.io",
	"pkg-containers.githubusercontent.com",
}

// SidecarContainerConfig describes the sidecar container. Not agent-specific.
type SidecarContainerConfig struct {
	AuthFile       string
	CacheDir       string
	Capabilities   []string
	Devices        []string
	Env            map[string]string
	Image          string
	Labels         map[string]string
	Name           string
	Mounts         []MountSpec // Credential forwarding mounts (gitconfig, ssh socket, etc.)
	ProtectedPaths []MountSpec // Read-only overlays on sensitive workdir paths
	Resources      Resources
	SeccompProfile string
	StorageDir     string
	TempDir        string
	Workdir        string
}

// AgentContainerConfig describes the agent container.
type AgentContainerConfig struct {
	EntrypointArgs []string
	Env            map[string]string
	Image          string
	Labels         map[string]string
	Mounts         []MountSpec
	Name           string
	Resources      Resources
	SeccompProfile string
	SidecarName    string
	Tmpfs          []TmpfsSpec
	Workdir        string
}

// Resources defines container resource limits.
type Resources struct {
	CPUs       string
	Memory     string
	PIDLimit   int
	UlimitCore string
}

// MountSpec describes a container mount.
type MountSpec struct {
	Dest     string
	Hardened bool // Bind mount with nosuid,nodev (prevents setuid escalation and device node creation)
	RO       bool
	Source   string
	Type     MountType
}

// MountType selects the mount mechanism.
type MountType int

const (
	Bind    MountType = iota // Host path bind mount
	DevNull                  // Mount /dev/null over target
	EmptyRO                  // RO tmpfs with size=0, mode=000
)

// TmpfsSpec describes a tmpfs mount.
type TmpfsSpec struct {
	NoExec bool
	NoSuid bool
	Path   string
	Size   string
}
