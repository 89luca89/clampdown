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
	seccompPath string, ag agent.Agent,
) container.SidecarContainerConfig {
	var authFile string
	if opts.RegistryAuth {
		authFile = findAuthFile()
	}

	return container.SidecarContainerConfig{
		AuthFile:       authFile,
		Labels:         labels(session, "sidecar", ag, opts),
		Name:           name,
		Image:          "clampdown-sidecar:latest",
		Workdir:        opts.Workdir,
		StorageDir:     p.Storage,
		CacheDir:       p.Cache,
		TempDir:        p.Temp,
		ProtectedPaths: SidecarProtectedPaths(opts.Workdir, opts.AllowHooks),
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
	homeDir string, rcEnv map[string]string,
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

	policyJSON := AgentLandlockPolicy(allMounts, tmpfs)

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
		}, ag.Env(), forwardEnv(ag), rcEnv),
		Tmpfs:          tmpfs,
		EntrypointArgs: ag.Args(opts.AgentArgs),
	}
}

// AgentLandlockPolicy derives the Landlock policy from the agent's
// mount and tmpfs configuration. Mirrors what seal-inject does for
// nested containers, but driven by the launcher's own config rather
// than OCI config.json.
//
// No TCP restrictions — iptables handles network.
func AgentLandlockPolicy(mounts []container.MountSpec, tmpfs []container.TmpfsSpec) string {
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
// paths in the sidecar container. Same paths as the agent's universal
// protection, applied to the sidecar so a compromised runtime can't modify
// .git/hooks (host code execution on next git op), .envrc (credential theft),
// .mcp.json (config tampering), etc.
func SidecarProtectedPaths(workdir string, allowHooks bool) []container.MountSpec {
	var specs []container.MountSpec
	for _, p := range mounts.MergeProtection(allowHooks) {
		abs := filepath.Join(workdir, p.Path)
		info, err := os.Stat(abs)
		if err != nil {
			continue // doesn't exist, nothing to protect
		}
		if info.IsDir() {
			// Existing directory — bind-mount read-only.
			specs = append(specs, container.MountSpec{
				Source: abs, Dest: abs, RO: true, Type: container.Bind,
			})
		} else {
			// Existing file — overlay with /dev/null.
			specs = append(specs, container.MountSpec{
				Dest: abs, Type: container.DevNull,
			})
		}
	}
	return specs
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

// forwardEnv reads host environment variables listed in ag.ForwardEnv()
// and returns a map of those that are set. Used for API keys.
func forwardEnv(ag agent.Agent) map[string]string {
	names := ag.ForwardEnv()
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		val := os.Getenv(name)
		if val != "" {
			out[name] = val
		}
	}
	return out
}

func MergeEnv(envs ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, m := range envs {
		maps.Copy(out, m)
	}
	return out
}
