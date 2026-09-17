// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/89luca89/clampdown/pkg/agent"
	"github.com/89luca89/clampdown/pkg/container"
	"github.com/89luca89/clampdown/pkg/sandbox/mounts"
	"github.com/89luca89/clampdown/pkg/sandbox/network"
)

// Infrastructure container images. Agent images are per-agent (Agent.Image()).
// These are the defaults; all three can be overridden via Options.
const (
	SidecarImage = "ghcr.io/89luca89/clampdown-sidecar:latest"
	ProxyImage   = "ghcr.io/89luca89/clampdown-proxy:latest"
)

func orDefault(override, def string) string {
	if override != "" {
		return override
	}
	return def
}

// LandlockPolicy matches the JSON expected by sandbox-seal.
type LandlockPolicy struct {
	ReadExec    []string `json:"read_exec"`
	ReadOnly    []string `json:"read_only"`
	WriteNoExec []string `json:"write_noexec"`
	WriteExec   []string `json:"write_exec"`
	ConnectTCP  []uint16 `json:"connect_tcp,omitempty"`
	BindTCP     []uint16 `json:"bind_tcp,omitempty"`
}

func labels(session string, role string, ag agent.Agent, opts Options) map[string]string {
	return map[string]string{
		"clampdown":              AppName,
		"clampdown.agent":        ag.Name(),
		"clampdown.agent_policy": opts.AgentPolicy,
		"clampdown.pod_policy":   opts.PodPolicy,
		"clampdown.role":         role,
		"clampdown.session":      session,
		"clampdown.workdir":      opts.Workdir,
	}
}

func sidecarConfig(
	name string, session string, opts Options, p ProjectPaths,
	seccompPath string, ag agent.Agent,
	protectedPaths []container.MountSpec,
) container.SidecarContainerConfig {
	var authFile string
	if opts.RegistryAuth {
		authFile = findAuthFile()
	}

	return container.SidecarContainerConfig{
		AuthFile:       authFile,
		Labels:         labels(session, "sidecar", ag, opts),
		Name:           name,
		Image:          orDefault(opts.SidecarImage, SidecarImage),
		Workdir:        opts.Workdir,
		StorageVolume:  p.Storage,
		CacheVolume:    p.Cache,
		TempVolume:     p.Temp,
		ProtectedPaths: protectedPaths,
		Capabilities: []string{
			"CHOWN",
			"DAC_OVERRIDE",
			"FOWNER",
			"FSETID",
			"KILL",
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
		SeccompProfile: seccompPath,
		Resources:      container.Resources{Memory: opts.Memory, CPUs: opts.CPUs, PIDLimit: sidecarPIDLimit},
		Env: map[string]string{
			"SANDBOX_REQUIRE_DIGEST": opts.RequireDigest,
			"SANDBOX_UID":            strconv.Itoa(os.Getuid()),
			"SANDBOX_GID":            strconv.Itoa(os.Getgid()),
			"SANDBOX_WORKDIR":        opts.Workdir,
		},
	}
}

func agentConfig(
	name, sidecarName string, session string, opts Options,
	ag agent.Agent,
	mounts []container.MountSpec, seccompPath string,
	homeDir string, route *agent.ProxyRoute,
	allowEntries []network.AllowEntry,
	rcEnv map[string]string,
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

	// we need to allow also additional port from allow entries.
	for _, e := range allowEntries {
		if e.Port == 0 {
			continue
		}
		port := uint16(e.Port)
		if slices.Contains(connectPorts, port) {
			continue
		}
		connectPorts = append(connectPorts, port)
	}

	policyJSON := AgentLandlockPolicy(allMounts, tmpfs, connectPorts)

	return container.AgentContainerConfig{
		Name:           name,
		Image:          orDefault(opts.AgentImage, ag.Image()),
		Labels:         labels(session, "agent", ag, opts),
		SidecarName:    sidecarName,
		Workdir:        opts.Workdir,
		Mounts:         allMounts,
		SeccompProfile: seccompPath,
		Resources: container.Resources{
			Memory: opts.Memory, CPUs: opts.CPUs,
			PIDLimit: agentPIDLimit, UlimitCore: "0:0",
		},
		// Merge order (last wins): host terminal vars, clampdown infra vars,
		// agent defaults, injectable .clampdownrc vars, proxy vars. User rc
		// vars override agent defaults (e.g. model names) but never the proxy
		// wiring or clampdown's infra vars, which the per-agent allowlist in
		// injectableRCEnv never admits.
		Env: MergeEnv(hostTerminalEnv(), map[string]string{
			"CONTAINER_HOST":  container.SidecarAPI,
			"DOCKER_HOST":     container.SidecarAPI,
			"HOME":            Home,
			"SANDBOX_CACHE":   filepath.Join(opts.Workdir, "."+ag.Name(), session),
			"SANDBOX_POLICY":  policyJSON,
			"SANDBOX_SESSION": session,
		}, ag.Env(), injectableRCEnv(ag, rcEnv), keyEnv),
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

	data, err := json.Marshal(p)
	if err != nil {
		slog.Warn("marshal agent landlock policy", "error", err)
		return "{}"
	}
	return string(data)
}

func agentAllowEntries(ag agent.Agent, extra string) []network.AllowEntry {
	var specs []string
	specs = append(specs, container.RegistryDomains...)
	specs = append(specs, ag.EgressDomains()...)
	if extra != "" {
		for d := range strings.SplitSeq(extra, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				specs = append(specs, d)
			}
		}
	}
	return network.ResolveAllowEntries(specs)
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
func SidecarProtectedPaths(
	workdir string,
	allowHooks bool,
	extra []string,
	masked []agent.MaskedPath,
) []container.MountSpec {
	paths := mounts.MergeProtection(allowHooks)
	for _, raw := range extra {
		paths = append(paths, agent.ProtectedPath{
			Path:  strings.TrimSuffix(raw, "/"),
			IsDir: strings.HasSuffix(raw, "/"),
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
		if err == nil {
			// Existing path (file or directory) — bind-mount read-only.
			// Content stays visible, only writes are blocked.
			specs = append(specs, container.MountSpec{
				Source: abs, Dest: abs, RO: true, Type: container.Bind,
			})
			continue
		}
		// Absent path — check if parent exists. No host placeholder needed:
		// DevNull and EmptyRO are handled natively by the container runtime.
		_, parentErr := os.Stat(filepath.Dir(abs))
		if parentErr != nil {
			continue
		}
		if p.IsDir {
			specs = append(specs, container.MountSpec{Dest: abs, Type: container.EmptyRO})
			continue
		}

		specs = append(specs, container.MountSpec{Dest: abs, Type: container.DevNull})
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
// appendPrompt, if non-empty, is appended after the sandbox instructions
// so it becomes part of the injected system prompt for every agent.
// The clampdown skill is always folded in between the base instructions and
// appendPrompt, so its guidance is loaded every session for every agent.
// The file is written only if missing or stale (content changed).
// Each agent discovers this file via its native mechanism:
//   - Claude: --append-system-prompt-file (passed via Args)
//   - OpenCode: ~/.config/opencode/instructions.md (auto-discovered)
//   - Codex: ~/.codex/config.toml -> model_instructions_file
//   - Pi: ~/.pi/agent/APPEND_SYSTEM.md (auto-discovered)
func WriteSandboxPrompt(ag agent.Agent, homeDir, appendPrompt string) error {
	// Claude requires onboarding to be marked complete before it accepts
	// API key auth. Ensure the flag is set in .claude.json.
	if ag.Name() == "claude" {
		agent.EnsureClaudeOnboarding(homeDir)
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
	prompt = prompt + "\n\n" + agent.SandboxSkill(ag.Name()) + "\n"
	if appendPrompt != "" {
		prompt = prompt + "\n\n" + appendPrompt + "\n"
	}

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

// WriteSkills writes the clampdown skill to both .claude/skills/ and .agents/skills/
// directories for cross-platform agent discovery.
func WriteSkills(ag agent.Agent, homeDir string) error {
	skill := agent.SandboxSkill(ag.Name())

	for _, dir := range agent.SkillDirs() {
		skillDir := filepath.Join(homeDir, dir, agent.SkillName)
		skillPath := filepath.Join(skillDir, "SKILL.md")

		// Write only if missing or content changed.
		existing, readErr := os.ReadFile(skillPath)
		if readErr == nil && string(existing) == skill {
			continue
		}

		err := os.MkdirAll(skillDir, 0o750)
		if err != nil {
			return fmt.Errorf("create skill dir %s: %w", skillDir, err)
		}
		err = os.WriteFile(skillPath, []byte(skill), 0o644)
		if err != nil {
			return fmt.Errorf("write skill %s: %w", skillPath, err)
		}
	}
	return nil
}

// resolveKey looks up an API key by name in the host environment and in rcEnv
// (.clampdownrc). An empty value means unset wherever it appears: a variable
// exported blank cancels an rc entry, and an empty rc entry cancels a variable
// exported in the shell, so `ANTHROPIC_API_KEY=` turns a provider off with no
// other edit. Otherwise the environment wins over the rc file.
func resolveKey(name string, rcEnv map[string]string) (string, bool) {
	rcValue, inRC := rcEnv[name]
	if inRC && rcValue == "" {
		return "", false
	}

	envValue, inEnv := os.LookupEnv(name)
	if !inEnv {
		return rcValue, rcValue != ""
	}
	return envValue, envValue != ""
}

func MergeEnv(envs ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, m := range envs {
		maps.Copy(out, m)
	}
	return out
}

// upstreamOverrideEnv is the agent-agnostic .clampdownrc var that repoints the
// auth proxy's upstream for routes that declare no BaseURLEnv (e.g. Codex). It
// is consumed by resolveProxyUpstream and never injected into the agent.
const upstreamOverrideEnv = "CLAMPDOWN_UPSTREAM"

// injectableRCEnv returns the .clampdownrc entries injected into the agent
// container. A name must be admitted by the agent's EnvAllowlist (its config
// namespaces); everything else -- including clampdown's infra vars like
// SANDBOX_POLICY and the CLAMPDOWN_UPSTREAM control var -- matches no allowlist
// entry and is dropped. Admitted names are filtered further: proxy-managed
// provider credentials and base URLs belong to the auth proxy, and any
// remaining credential- or endpoint-shaped name (e.g. ANTHROPIC_AUTH_TOKEN,
// ANTHROPIC_BEDROCK_BASE_URL) is stripped so it cannot ride in on a namespace
// prefix.
func injectableRCEnv(ag agent.Agent, rcEnv map[string]string) map[string]string {
	allow := ag.EnvAllowlist()
	proxyManaged := agent.ProxyManagedEnvNames()
	out := make(map[string]string, len(rcEnv))
	for k, v := range rcEnv {
		// An empty entry is an unset instruction, not a value to forward: a
		// present but blank variable reads as set to tools that check for
		// presence.
		if v == "" {
			continue
		}
		if !allow.Allows(k) {
			continue
		}
		if proxyManaged[k] {
			continue
		}
		if isSensitiveEnvName(k) {
			slog.Warn("ignoring credential-shaped env var from .clampdownrc", "key", k)
			continue
		}
		out[k] = v
	}
	return out
}

// sensitiveEnvSuffixes name-match secrets and network destinations. A config
// namespace prefix (e.g. ANTHROPIC_) admits names it should not carry into the
// agent, such as ANTHROPIC_AUTH_TOKEN or ANTHROPIC_VERTEX_BASE_URL; matching
// one of these suffixes strips them.
var sensitiveEnvSuffixes = []string{
	"_API_KEY", "_AUTH_TOKEN", "_OAUTH_TOKEN", "_TOKEN",
	"_SECRET", "_PASSWORD", "_PASSPHRASE", "_CREDENTIALS",
	"_PRIVATE_KEY", "_KEY", "_CERT", "_CERTIFICATE", "_BASE_URL",
}

func isSensitiveEnvName(name string) bool {
	for _, s := range sensitiveEnvSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// hostTerminalEnv returns terminal identification vars from the host.
// Empty values are dropped so the container sees no key rather than a
// blank one, which some tools read as "capability present".
func hostTerminalEnv() map[string]string {
	keys := []string{
		"TERM", "COLORTERM",
		"TERM_PROGRAM", "TERM_PROGRAM_VERSION",
		"COLORFGBG",
		"LANG", "LC_ALL", "LC_CTYPE",
		"LS_COLORS",
		"NO_COLOR", "FORCE_COLOR",
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		v := os.Getenv(k)
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// ActiveProxyRoute returns the first proxy route whose key is set on the
// host or in rcEnv and whose upstream can be built.
func ActiveProxyRoute(ag agent.Agent, rcEnv map[string]string) *agent.ProxyRoute {
	for _, r := range ag.ProxyRoutes() {
		_, ok := resolveKey(r.KeyEnv, rcEnv)
		if !ok {
			_, ok = resolveKey(r.KeyEnvFallback, rcEnv)
			if ok {
				r.KeyEnv, r.KeyEnvFallback = r.KeyEnvFallback, r.KeyEnv
			}
		}
		if !ok {
			continue
		}
		// A route that needs a region or account id the environment does not
		// provide would start a proxy that forwards nowhere.
		if resolveProxyUpstream(&r, rcEnv) == "" {
			slog.Warn("proxy route has an unresolvable upstream, skipping",
				"provider", r.ProviderID, "key", r.KeyEnv, "needs", r.UpstreamEnv)
			continue
		}
		return &r
	}
	return nil
}

// resolveProxyUpstream returns the URL the auth proxy forwards to. A base-URL
// var in .clampdownrc repoints it: the active route's BaseURLEnv (e.g.
// ANTHROPIC_BASE_URL) when the route declares one, or the agent-agnostic
// CLAMPDOWN_UPSTREAM fallback for routes without a BaseURLEnv (e.g. Codex and
// OpenCode's provider-id routes). Routes whose endpoint embeds a region or
// account id derive it from UpstreamEnv. The built-in route.Upstream is used
// when none applies or the override is not a valid https URL.
func resolveProxyUpstream(route *agent.ProxyRoute, rcEnv map[string]string) string {
	override := ""
	if route.BaseURLEnv != "" && rcEnv[route.BaseURLEnv] != "" {
		override = rcEnv[route.BaseURLEnv]
	} else if v := rcEnv[upstreamOverrideEnv]; v != "" {
		override = v
	} else if v, ok := resolveUpstreamEnv(route, rcEnv); ok {
		override = v
	}
	if override == "" {
		return route.Upstream
	}

	u, err := url.Parse(override)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		slog.Warn("ignoring invalid upstream override from .clampdownrc",
			"value", override, "key", route.KeyEnv)
		return route.Upstream
	}
	return override
}

// resolveUpstreamEnv expands a route's UpstreamEnv into an upstream URL. The
// value is read from the host environment or .clampdownrc, whichever is set,
// letting a regional or account-scoped endpoint be built without hardcoding it.
func resolveUpstreamEnv(route *agent.ProxyRoute, rcEnv map[string]string) (string, bool) {
	if route.UpstreamEnv == "" {
		return "", false
	}
	value, ok := resolveKey(route.UpstreamEnv, rcEnv)
	if !ok {
		return "", false
	}
	if route.UpstreamTemplate == "" {
		return value, true
	}
	return fmt.Sprintf(route.UpstreamTemplate, value), true
}

// repointedUpstreamHost returns the host of a .clampdownrc upstream override so
// the proxy's egress to it can be allowlisted. Returns "" when the upstream is
// the built-in default (already covered by the agent's egress domains).
func repointedUpstreamHost(route *agent.ProxyRoute, rcEnv map[string]string) string {
	resolved := resolveProxyUpstream(route, rcEnv)
	if resolved == route.Upstream {
		return ""
	}
	u, err := url.Parse(resolved)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// ProxyConfig builds the container config for the auth proxy.
// The route configuration and API key are passed as individual env vars.
func ProxyConfig(
	name, sidecarName string, session string, opts Options,
	ag agent.Agent, route *agent.ProxyRoute, seccompPath string,
	rcEnv map[string]string,
) container.ProxyContainerConfig {
	// ActiveProxyRoute already resolved KeyEnvFallback into KeyEnv.
	keyValue, _ := resolveKey(route.KeyEnv, rcEnv)

	env := map[string]string{
		"PROXY_PORT":          strconv.FormatUint(uint64(route.Port), 10),
		"PROXY_UPSTREAM":      resolveProxyUpstream(route, rcEnv),
		"PROXY_HEADER_NAME":   route.HeaderName,
		"PROXY_HEADER_PREFIX": route.HeaderPrefix,
		"PROXY_KEY":           keyValue,
		"GOMAXPROCS":          "2",
	}

	// Landlock policy for the proxy: read-only filesystem, execute
	// only its own binary, TCP connect restricted to port 443,
	// bind restricted to its listen port.
	proxyPolicy := LandlockPolicy{
		ReadExec:   []string{"/usr/local/bin"},
		ReadOnly:   []string{"/"},
		ConnectTCP: []uint16{443, 53},
		BindTCP:    []uint16{route.Port},
	}
	data, err := json.Marshal(proxyPolicy)
	if err != nil {
		slog.Warn("marshal proxy landlock policy", "error", err)
	}

	env["SANDBOX_POLICY"] = string(data)

	return container.ProxyContainerConfig{
		Name:           name,
		Image:          orDefault(opts.ProxyImage, ProxyImage),
		Labels:         labels(session, "proxy", ag, opts),
		SidecarName:    sidecarName,
		Env:            env,
		SeccompProfile: seccompPath,
		Resources: container.Resources{
			Memory: "128m", CPUs: 1, PIDLimit: proxyPIDLimit,
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
