// SPDX-License-Identifier: GPL-3.0-only

package agent

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

// OpenCode implements Agent for the OpenCode CLI (anomalyco/opencode).
type OpenCode struct{}

func (o *OpenCode) Name() string  { return "opencode" }
func (o *OpenCode) Image() string { return "ghcr.io/89luca89/clampdown-opencode:latest" }

func (o *OpenCode) EgressDomains() []string {
	return []string{
		// OpenCode infrastructure
		"opencode.ai",
		"models.dev",
		"mcp.exa.ai",
		"registry.npmjs.org",
		// AI provider APIs (multi-provider agent)
		"api.anthropic.com",
		"api.openai.com",
		"generativelanguage.googleapis.com",
		"api.groq.com",
		"api.deepseek.com",
		"api.mistral.ai",
		"api.x.ai",
		"openrouter.ai",
	}
}

func (o *OpenCode) Mounts() []Mount { return nil }

func (o *OpenCode) ConfigOverlays() []Mount {
	cfgDir := filepath.Join(Home, ".config", "opencode")
	return []Mount{
		{Src: filepath.Join(cfgDir, "opencode.json"), Dst: filepath.Join(cfgDir, "opencode.json")},
		{Src: filepath.Join(cfgDir, "opencode.jsonc"), Dst: filepath.Join(cfgDir, "opencode.jsonc")},
	}
}

// Env redirects TMPDIR because Bun-compiled binaries extract and dlopen native
// .so files at startup. Default /tmp is mounted noexec, causing a silent hang.
func (o *OpenCode) Env() map[string]string {
	return map[string]string{
		"TMPDIR": filepath.Join(Home, ".config", "opencode", "tmp"),
	}
}

func (o *OpenCode) Args(passthrough []string) []string {
	return passthrough
}

// PromptFile returns ~/.config/opencode/AGENTS.md — OpenCode
// auto-discovers AGENTS.md from ~/.config/opencode/ as global rules.
func (o *OpenCode) PromptFile() string {
	return filepath.Join(Home, ".config", "opencode", "AGENTS.md")
}

// ProxyRoutes returns upstream API routes for all supported providers.
func (o *OpenCode) ProxyRoutes() []ProxyRoute {
	return []ProxyRoute{
		{Port: ProxyPort, Upstream: "https://api.anthropic.com/v1",
			KeyEnv: "ANTHROPIC_API_KEY", HeaderName: "x-api-key",
			BaseURLEnv: "ANTHROPIC_BASE_URL"},
		{Port: ProxyPort, Upstream: "https://api.openai.com/v1",
			KeyEnv: "OPENAI_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			BaseURLEnv: "OPENAI_BASE_URL"},
		{Port: ProxyPort, Upstream: "https://generativelanguage.googleapis.com",
			KeyEnv: "GOOGLE_GENERATIVE_AI_API_KEY", KeyEnvFallback: "GEMINI_API_KEY",
			HeaderName: "x-goog-api-key",
			ProviderID: "google"},
		{Port: ProxyPort, Upstream: "https://api.groq.com/openai/v1",
			KeyEnv: "GROQ_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "groq"},
		{Port: ProxyPort, Upstream: "https://api.deepseek.com/v1",
			KeyEnv: "DEEPSEEK_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "deepseek"},
		{Port: ProxyPort, Upstream: "https://api.mistral.ai/v1",
			KeyEnv: "MISTRAL_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "mistral"},
		{Port: ProxyPort, Upstream: "https://api.x.ai/v1",
			KeyEnv: "XAI_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "xai"},
		{Port: ProxyPort, Upstream: "https://openrouter.ai/api/v1",
			KeyEnv: "OPENROUTER_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "openrouter"},
		{Port: ProxyPort, Upstream: "https://opencode.ai/zen/v1",
			KeyEnv: "OPENCODE_API_KEY", HeaderName: "Authorization", HeaderPrefix: "Bearer ",
			ProviderID: "opencode"},
	}
}

// ProxyEnvOverride builds OPENCODE_CONFIG_CONTENT for providers whose SDK
// doesn't read a *_BASE_URL env var. The JSON is deep-merged by OpenCode
// at highest precedence — no clobbering of user config.
func (o *OpenCode) ProxyEnvOverride(routes []ProxyRoute) map[string]string {
	providers := make(map[string]any)
	for _, r := range routes {
		if r.ProviderID == "" {
			continue
		}
		providers[r.ProviderID] = map[string]any{
			"options": map[string]any{
				"baseURL": fmt.Sprintf("http://localhost:%d", r.Port),
			},
		}
	}
	if len(providers) == 0 {
		return nil
	}

	cfg := map[string]any{"provider": providers}
	data, _ := json.Marshal(cfg)
	return map[string]string{"OPENCODE_CONFIG_CONTENT": string(data)}
}

// EnvAllowlist admits only OPENCODE_MODEL. The other OPENCODE_ vars repoint the
// CLI at a different config (OPENCODE_CONFIG, OPENCODE_CONFIG_DIR) or are owned
// by the sandbox (OPENCODE_CONFIG_CONTENT wires the proxy), and provider keys
// are owned by the auth proxy.
func (o *OpenCode) EnvAllowlist() EnvAllow {
	return EnvAllow{Names: []string{"OPENCODE_MODEL"}}
}
