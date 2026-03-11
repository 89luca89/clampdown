// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/89luca89/clampdown/pkg/agent"
	"github.com/89luca89/clampdown/pkg/container"
	"github.com/89luca89/clampdown/pkg/sandbox/mounts"
	"github.com/89luca89/clampdown/pkg/sandbox/network"
)

// Infrastructure container images. Agent images are per-agent (Agent.Image()).
const (
	SidecarImage = "clampdown-sidecar:latest"
	ProxyImage   = "clampdown-proxy:latest"
)

// LandlockPolicy matches the JSON expected by sandbox-seal.
type LandlockPolicy struct {
	ReadExec    []string `json:"read_exec"`
	ReadOnly    []string `json:"read_only"`
	WriteNoExec []string `json:"write_noexec"`
	WriteExec   []string `json:"write_exec"`
	ConnectTCP  []uint16 `json:"connect_tcp"`
}

func labels(session int, role string, ag agent.Agent, opts Options) map[string]string {
	return map[string]string{
		"clampdown":              AppName,
		"clampdown.agent":        ag.Name(),
		"clampdown.agent_policy": opts.AgentPolicy,
		"clampdown.pod_policy":   opts.PodPolicy,
		"clampdown.role":         role,
		"clampdown.session":      strconv.Itoa(session),
		"clampdown.workdir":      opts.Workdir,
	}
}

func sidecarConfig(
	name string, session int, opts Options, p ProjectPaths,
	seccompPath string, ag agent.Agent, masked []agent.MaskedPath,
) container.SidecarContainerConfig {
	var authFile string
	if opts.RegistryAuth {
		authFile = findAuthFile()
	}

	return container.SidecarContainerConfig{
		AuthFile:       authFile,
		Labels:         labels(session, "sidecar", ag, opts),
		Name:           name,
		Image:          SidecarImage,
		Workdir:        opts.Workdir,
		StorageDir:     p.Storage,
		CacheDir:       p.Cache,
		TempDir:        p.Temp,
		ProtectedPaths: SidecarProtectedPaths(opts.Workdir, opts.AllowHooks, opts.ProtectPaths, masked),
		Capabilities: []string{
			"CHOWN",
			"DAC_OVERRIDE",
			"FOWNER",
			"FSETID",
			"KILL",
			"LINUX_IMMUTABLE",
			"MKNOD",
			"NET_ADMIN",
			"NET_BIND_SERVICE",
			"SETFCAP",
			"SETGID",
			"SETPCAP",
			"SETUID",
			"SYS_ADMIN",
			"SYS_CHROOT",
			"SYS_PTRACE",
			"SYS_RESOURCE",
		},
		Devices:        []string{"/dev/fuse"},
		SeccompProfile: seccompPath,
		Resources:      container.Resources{Memory: opts.Memory, CPUs: opts.CPUs, PIDLimit: sidecarPIDLimit},
		Env: map[string]string{
			"SANDBOX_AGENT_ALLOW":    agentAllowlist(ag, opts.AgentAllow),
			"SANDBOX_AGENT_POLICY":   opts.AgentPolicy,
			"SANDBOX_POD_POLICY":     opts.PodPolicy,
			"SANDBOX_REQUIRE_DIGEST": opts.RequireDigest,
			"SANDBOX_UID":            strconv.Itoa(os.Getuid()),
			"SANDBOX_GID":            strconv.Itoa(os.Getgid()),
			"SANDBOX_WORKDIR":        opts.Workdir,
		},
	}
}

func agentConfig(
	name, sidecarName string, session int, opts Options,
	ag agent.Agent,
	mounts []container.MountSpec, seccompPath string,
	homeDir string, route *agent.ProxyRoute,
) container.AgentContainerConfig {
	tmpfs := []container.TmpfsSpec{
		{Path: "/run", Size: "256m", NoExec: true, NoSuid: true},
		{Path: "/tmp", Size: "512m", NoExec: true, NoSuid: true},
		{Path: "/var/tmp", Size: "512m", NoExec: true, NoSuid: true},
	}

	// HOME is a persistent bind mount (nosuid+nodev), not a tmpfs.
	// Agent state survives across sessions per-project.
	homeMnt := container.MountSpec{
		Source: homeDir, Dest: Home, Type: container.Bind, Hardened: true,
	}
	allMounts := append([]container.MountSpec{homeMnt}, mounts...)

	// When a proxy route is active, the agent gets dummy keys and the proxy
	// holds the real ones.
	connectPorts := []uint16{443, 2375}
	var keyEnv map[string]string
	if route != nil {
		connectPorts = append(connectPorts, route.Port)
		keyEnv = proxyAgentEnv(ag, route)
	}

	policyJSON := AgentLandlockPolicy(allMounts, tmpfs, connectPorts)

	return container.AgentContainerConfig{
		Name:           name,
		Image:          ag.Image(),
		Labels:         labels(session, "agent", ag, opts),
		SidecarName:    sidecarName,
		Workdir:        opts.Workdir,
		Mounts:         allMounts,
		SeccompProfile: seccompPath,
		Resources: container.Resources{
			Memory: opts.Memory, CPUs: opts.CPUs,
			PIDLimit: agentPIDLimit, UlimitCore: "0:0",
		},
		Env: MergeEnv(map[string]string{
			"CONTAINER_HOST":  container.SidecarAPI,
			"DOCKER_HOST":     container.SidecarAPI,
			"HOME":            Home,
			"SANDBOX_POLICY":  policyJSON,
			"SANDBOX_SESSION": strconv.Itoa(session),
			"TERM":            os.Getenv("TERM"),
		}, ag.Env(), keyEnv),
		Tmpfs:          tmpfs,
		EntrypointArgs: ag.Args(opts.AgentArgs),
	}
}

// AgentLandlockPolicy derives the Landlock policy from the agent's
// mount and tmpfs configuration. Mirrors what seal-inject does for
// nested containers, but driven by the launcher's own config rather
// than OCI config.json.
// connectPorts restricts outbound TCP to listed ports only (V4+).
func AgentLandlockPolicy(
	mounts []container.MountSpec, tmpfs []container.TmpfsSpec,
	connectPorts []uint16,
) string {
	p := LandlockPolicy{
		ReadExec: []string{
			"/bin", "/sbin", "/usr/bin", "/usr/sbin",
			"/lib", "/lib64", "/usr/lib", "/usr/lib64",
			"/usr/local",
		},
		ReadOnly: []string{"/"},
		// /dev and /proc are separate mounts (devtmpfs/procfs) not
		// covered by ReadOnly on "/". Agent needs /dev/null, /dev/urandom,
		// and /proc/self/* for normal operation.
		WriteNoExec: []string{"/dev", "/proc"},
		ConnectTCP:  connectPorts,
	}

	for _, t := range tmpfs {
		if t.NoExec {
			p.WriteNoExec = append(p.WriteNoExec, t.Path)
		} else {
			p.WriteExec = append(p.WriteExec, t.Path)
		}
	}

	for _, m := range mounts {
		if m.Type == container.Bind && !m.RO {
			p.WriteExec = append(p.WriteExec, m.Dest)
		}
	}

	data, _ := json.Marshal(p)
	return string(data)
}

func agentAllowlist(ag agent.Agent, extra string) string {
	var domains []string
	domains = append(domains, container.RegistryDomains...)
	domains = append(domains, ag.EgressDomains()...)
	if extra != "" {
		for d := range strings.SplitSeq(extra, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				domains = append(domains, d)
			}
		}
	}

	resolved := network.ResolveAllowlist(domains)
	return strings.Join(resolved, ",")
}

// findAuthFile returns the first existing registry auth file on the host.
func findAuthFile() string {
	candidates := []string{
		os.Getenv("REGISTRY_AUTH_FILE"),
		filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "containers", "auth.json"),
		filepath.Join(Home, ".config", "containers", "auth.json"),
		filepath.Join(Home, ".docker", "config.json"),
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		_, err := os.Stat(p)
		if err == nil {
			return p
		}
	}
	return ""
}

// SidecarProtectedPaths builds read-only mount specs for sensitive workdir
// paths in the sidecar container. Merges the universal protection list with
// user-specified --protect paths. Applied to the sidecar so a compromised
// runtime can't modify .git/hooks (host code execution on next git op),
// .envrc (credential theft), .mcp.json (config tampering), etc.
//
// The sidecar's RO overlays also propagate into nested containers via
// recursive bind mounts (rbind), so nested containers inherit protection
// without needing seal-inject changes.
func SidecarProtectedPaths(workdir string, allowHooks bool, extra []string, masked []agent.MaskedPath) []container.MountSpec {
	paths := mounts.MergeProtection(allowHooks)
	for _, raw := range extra {
		paths = append(paths, agent.ProtectedPath{
			Path: strings.TrimSuffix(raw, "/"),
		})
	}

	// Build set of masked paths so we skip them (mask wins over protection).
	maskedSet := make(map[string]bool, len(masked))
	for _, m := range masked {
		maskedSet[filepath.Join(workdir, m.Path)] = true
	}

	var specs []container.MountSpec
	for _, p := range paths {
		if p.GlobalPath {
			continue
		}
		abs := filepath.Join(workdir, p.Path)
		if maskedSet[abs] {
			continue
		}
		_, err := os.Stat(abs)
		if err != nil {
			continue // doesn't exist, nothing to protect
		}
		// Existing path (file or directory) — bind-mount read-only.
		// Content stays visible, only writes are blocked.
		specs = append(specs, container.MountSpec{
			Source: abs, Dest: abs, RO: true, Type: container.Bind,
		})
	}
	return specs
}

// SidecarMaskedPaths builds DevNull/EmptyRO mount specs for sensitive workdir
// paths in the sidecar container. Creates host placeholders for missing paths
// so the mount overlay can be applied. Returns specs and created paths for cleanup.
func SidecarMaskedPaths(workdir string, masked []agent.MaskedPath) ([]container.MountSpec, []string) {
	var specs []container.MountSpec
	var created []string
	for _, m := range masked {
		abs := filepath.Join(workdir, m.Path)
		spec, path, err := mounts.MaskMount(abs, m.IsDir)
		if err != nil || spec == nil {
			continue
		}
		specs = append(specs, *spec)
		if path != "" {
			created = append(created, path)
		}
	}
	return specs, created
}

// WriteSandboxPrompt writes the sandbox instructions to the agent's
// PromptFile() path inside the persistent HOME directory on the host.
// The file is written only if missing or stale (content changed).
// Each agent discovers this file via its native mechanism:
//   - Claude: --append-system-prompt-file (passed via Args)
//   - OpenCode: ~/.config/opencode/instructions.md (auto-discovered)
func WriteSandboxPrompt(ag agent.Agent, homeDir string) error {
	// Claude requires onboarding to be marked complete before it accepts
	// API key auth. Ensure the flag is set in .claude.json.
	if ag.Name() == "claude" {
		ensureClaudeOnboarding(filepath.Join(homeDir, ".claude.json"))
	}

	containerPath := ag.PromptFile()
	if containerPath == "" {
		return nil
	}

	// Map container path to host path inside the persistent HOME dir.
	// PromptFile() always returns filepath.Join(Home, ...) — Rel can't fail.
	rel, _ := filepath.Rel(Home, containerPath)
	hostPath := filepath.Join(homeDir, rel)

	prompt := agent.SandboxPrompt(ag.Name())

	// Write only if missing or content changed.
	existing, readErr := os.ReadFile(hostPath)
	if readErr == nil && string(existing) == prompt {
		return nil
	}

	err := os.MkdirAll(filepath.Dir(hostPath), 0o750)
	if err != nil {
		return fmt.Errorf("create prompt dir: %w", err)
	}
	return os.WriteFile(hostPath, []byte(prompt), 0o644)
}

// ensureClaudeOnboarding makes sure .claude.json has hasCompletedOnboarding: true.
// Reads existing file if present, sets the key if missing, writes back.
func ensureClaudeOnboarding(path string) {
	var state map[string]any

	data, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(data, &state)
	}
	if state == nil {
		state = make(map[string]any)
	}

	if state["hasCompletedOnboarding"] == true {
		return
	}

	state["hasCompletedOnboarding"] = true
	out, _ := json.Marshal(state)
	_ = os.WriteFile(path, append(out, '\n'), 0o644)
}

// resolveKey looks up an API key by name, checking the host environment
// first, then rcEnv (.clampdownrc). Returns the value and true if found.
func resolveKey(name string, rcEnv map[string]string) (string, bool) {
	if v := os.Getenv(name); v != "" {
		return v, true
	}
	if v := rcEnv[name]; v != "" {
		return v, true
	}
	return "", false
}

func MergeEnv(envs ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, m := range envs {
		maps.Copy(out, m)
	}
	return out
}

// ActiveProxyRoute returns the first proxy route whose key is set on the
// host or in rcEnv.
func ActiveProxyRoute(ag agent.Agent, rcEnv map[string]string) *agent.ProxyRoute {
	for _, r := range ag.ProxyRoutes() {
		_, ok := resolveKey(r.KeyEnv, rcEnv)
		if ok {
			return &r
		}
		if r.KeyEnvFallback != "" {
			_, ok = resolveKey(r.KeyEnvFallback, rcEnv)
			if ok {
				r.KeyEnv, r.KeyEnvFallback = r.KeyEnvFallback, r.KeyEnv
				return &r
			}
		}
	}
	return nil
}

// ProxyConfig builds the container config for the auth proxy.
// The route configuration and API key are passed as individual env vars.
func ProxyConfig(
	name, sidecarName string, session int, opts Options,
	ag agent.Agent, route *agent.ProxyRoute, seccompPath string,
	rcEnv map[string]string,
) container.ProxyContainerConfig {
	// ActiveProxyRoute already resolved KeyEnvFallback into KeyEnv.
	keyValue, _ := resolveKey(route.KeyEnv, rcEnv)

	env := map[string]string{
		"PROXY_PORT":          fmt.Sprintf("%d", route.Port),
		"PROXY_UPSTREAM":      route.Upstream,
		"PROXY_HEADER_NAME":   route.HeaderName,
		"PROXY_HEADER_PREFIX": route.HeaderPrefix,
		"PROXY_KEY":           keyValue,
		"GOMAXPROCS": "2",
	}

	// Landlock policy for the proxy: read-only filesystem, execute
	// only its own binary, TCP connect restricted to port 443.
	proxyPolicy := LandlockPolicy{
		ReadExec:   []string{"/usr/local/bin"},
		ReadOnly:   []string{"/"},
		ConnectTCP: []uint16{443, 53},
	}
	data, _ := json.Marshal(proxyPolicy)
	env["SANDBOX_POLICY"] = string(data)

	return container.ProxyContainerConfig{
		Name:           name,
		Image:          ProxyImage,
		Labels:         labels(session, "proxy", ag, opts),
		SidecarName:    sidecarName,
		Env:            env,
		SeccompProfile: seccompPath,
		Resources: container.Resources{
			Memory: "128m", CPUs: "1", PIDLimit: 32,
		},
	}
}

func proxyAgentEnv(ag agent.Agent, route *agent.ProxyRoute) map[string]string {
	env := make(map[string]string, 4)
	if route.BaseURLEnv != "" {
		env[route.BaseURLEnv] = fmt.Sprintf("http://localhost:%d", route.Port)
	}
	// Set dummy key so SDK key-presence validation passes.
	env[route.KeyEnv] = "sk-proxy"
	// If this route was resolved from a fallback, also set the original
	// primary key env so the SDK finds it regardless of which name it
	// checks first (e.g., GOOGLE_GENERATIVE_AI_API_KEY and GEMINI_API_KEY).
	if route.KeyEnvFallback != "" {
		env[route.KeyEnvFallback] = "sk-proxy"
	}

	// Agent-specific overrides (e.g., OPENCODE_CONFIG_CONTENT).
	override := ag.ProxyEnvOverride([]agent.ProxyRoute{*route})
	maps.Copy(env, override)

	return env
}
