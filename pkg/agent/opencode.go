// SPDX-License-Identifier: GPL-3.0-only

package agent

import "path/filepath"

// OpenCode implements Agent for the OpenCode CLI (anomalyco/opencode).
type OpenCode struct{}

func (o *OpenCode) Name() string  { return "opencode" }
func (o *OpenCode) Image() string { return "clampdown-opencode:latest" }

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

func (o *OpenCode) ForwardEnv() []string {
	// OpenCode is multi-provider. Forward all common provider keys —
	// only those set on the host are passed through.
	return []string{
		"ANTHROPIC_API_KEY",
		"OPENAI_API_KEY",
		"GEMINI_API_KEY",
		"OPENROUTER_API_KEY",
		"GROQ_API_KEY",
		"DEEPSEEK_API_KEY",
		"MISTRAL_API_KEY",
		"XAI_API_KEY",
		"OPENCODE_API_KEY",
	}
}
