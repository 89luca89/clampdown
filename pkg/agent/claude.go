// SPDX-License-Identifier: GPL-3.0-only

package agent

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
)

// Claude implements Agent for the Claude Code CLI.
type Claude struct{}

func (c *Claude) Name() string  { return "claude" }
func (c *Claude) Image() string { return "ghcr.io/89luca89/clampdown-claude:latest" }

func (c *Claude) EgressDomains() []string {
	return []string{
		// API
		"api.anthropic.com",
		// OAuth login
		"claude.ai",
		"platform.claude.com",
		// Telemetry
		"sentry.io",
		"statsig.anthropic.com",
		"statsig.com",
	}
}

func (c *Claude) Mounts() []Mount { return nil }

func (c *Claude) ConfigOverlays() []Mount {
	claudeDir := filepath.Join(Home, ".claude")
	return []Mount{
		{Src: filepath.Join(claudeDir, "agents"), Dst: filepath.Join(claudeDir, "agents")},
		{Src: filepath.Join(claudeDir, "commands"), Dst: filepath.Join(claudeDir, "commands")},
		{Src: filepath.Join(claudeDir, "settings.json"), Dst: filepath.Join(claudeDir, "settings.json")},
		{Src: filepath.Join(claudeDir, "skills"), Dst: filepath.Join(claudeDir, "skills")},
	}
}

func (c *Claude) Env() map[string]string {
	return map[string]string{
		"IS_SANDBOX": "1",
		// Suppress non-essential egress (auto-updater, telemetry, error
		// reporting, plugin-marketplace fetch) the agent firewall blocks.
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
	}
}

func (c *Claude) Args(passthrough []string) []string {
	return append([]string{"--append-system-prompt-file", c.PromptFile()}, passthrough...)
}

func (c *Claude) PromptFile() string {
	return filepath.Join(Home, ".claude", "CLAUDE-clampdown.md")
}

func (c *Claude) ProxyRoutes() []ProxyRoute {
	return []ProxyRoute{
		{
			Port:       ProxyPort,
			Upstream:   "https://api.anthropic.com",
			KeyEnv:     "ANTHROPIC_API_KEY",
			HeaderName: "x-api-key",
			BaseURLEnv: "ANTHROPIC_BASE_URL",
		},
		{
			Port:         ProxyPort,
			Upstream:     "https://api.anthropic.com",
			KeyEnv:       "CLAUDE_CODE_OAUTH_TOKEN",
			HeaderName:   "Authorization",
			HeaderPrefix: "Bearer ",
			BaseURLEnv:   "ANTHROPIC_BASE_URL",
			OAuth:        true,
		},
	}
}

func (c *Claude) ProxyEnvOverride(_ []ProxyRoute) map[string]string { return nil }

// EnsureClaudeOnboarding makes sure .claude.json has hasCompletedOnboarding: true.
// Reads existing file if present, sets the key if missing, writes back.
func EnsureClaudeOnboarding(homeDir string) {
	path := filepath.Join(homeDir, ".claude.json")
	var state map[string]any

	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &state)
		if err != nil {
			slog.Warn("parse claude config", "path", path, "error", err)
		}
	}
	if state == nil {
		state = make(map[string]any)
	}

	if state["hasCompletedOnboarding"] == true {
		return
	}

	state["hasCompletedOnboarding"] = true
	out, err := json.Marshal(state)
	if err != nil {
		slog.Warn("marshal claude config", "error", err)
		return
	}
	err = os.WriteFile(path, append(out, '\n'), 0o644)
	if err != nil {
		slog.Warn("write claude config", "path", path, "error", err)
	}
}
