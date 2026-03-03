// SPDX-License-Identifier: GPL-3.0-only

package agent

import "path/filepath"

// Claude implements Agent for the Claude Code CLI.
type Claude struct{}

func (c *Claude) Name() string  { return "claude" }
func (c *Claude) Image() string { return "clampdown-claude:latest" }

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
	}
}

func (c *Claude) Args(passthrough []string) []string {
	return append([]string{"--append-system-prompt-file", c.PromptFile()}, passthrough...)
}

func (c *Claude) PromptFile() string {
	return filepath.Join(Home, ".claude", "CLAUDE-clampdown.md")
}

func (c *Claude) ForwardEnv() []string {
	return []string{"ANTHROPIC_API_KEY"}
}
