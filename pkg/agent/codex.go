// SPDX-License-Identifier: GPL-3.0-only

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Codex implements Agent for the OpenAI Codex CLI.
type Codex struct{}

func (c *Codex) Name() string  { return "codex" }
func (c *Codex) Image() string { return "ghcr.io/89luca89/clampdown-codex:latest" }

func (c *Codex) EgressDomains() []string {
	return []string{
		"api.openai.com",
		"auth.openai.com",
		"chatgpt.com",
	}
}

func (c *Codex) Mounts() []Mount { return nil }

func (c *Codex) ConfigOverlays() []Mount { return nil }

func (c *Codex) Env() map[string]string {
	return map[string]string{
		"CODEX_HOME": filepath.Join(Home, ".codex"),
	}
}

func (c *Codex) Args(passthrough []string) []string {
	return append([]string{"--dangerously-bypass-approvals-and-sandbox"}, passthrough...)
}

func (c *Codex) PromptFile() string {
	return filepath.Join(Home, ".codex", "AGENTS-clampdown.md")
}

func (c *Codex) ProxyRoutes() []ProxyRoute {
	return []ProxyRoute{
		{
			Port:         ProxyPort,
			Upstream:     "https://api.openai.com/v1",
			KeyEnv:       "OPENAI_API_KEY",
			HeaderName:   "Authorization",
			HeaderPrefix: "Bearer ",
		},
	}
}

func (c *Codex) ProxyEnvOverride(_ []ProxyRoute) map[string]string { return nil }

// EnvAllowlist is empty: Codex is configured through the config.toml clampdown
// writes and through passthrough CLI args, not environment variables. Its only
// env vars are CODEX_HOME (set by the sandbox) and provider credentials (owned
// by the auth proxy).
func (c *Codex) EnvAllowlist() EnvAllow { return EnvAllow{} }

// PrepareCodexHome seeds the Codex auth/config files inside the agent's
// persistent HOME directory. In subscription mode the host's
// ~/.codex/auth.json is copied in once per session (or refreshed when
// newer), never bind-mounted. The source path is fixed — not configurable
// — to eliminate a project-.clampdownrc exfiltration primitive.
func PrepareCodexHome(homeDir string, route *ProxyRoute) error {
	codexDir := filepath.Join(homeDir, ".codex")
	err := os.MkdirAll(codexDir, 0o700)
	if err != nil {
		return fmt.Errorf("create codex dir: %w", err)
	}

	if route == nil {
		err = seedCodexAuthFile(filepath.Join(codexDir, "auth.json"))
		if err != nil {
			return err
		}
	}

	return writeCodexConfig(filepath.Join(codexDir, "config.toml"), route)
}

func seedCodexAuthFile(dst string) error {
	src := filepath.Join(Home, ".codex", "auth.json")
	info, err := os.Stat(src)
	if err != nil {
		// Missing host auth cache is not an error — Codex can still start
		// and prompt for login inside the sandbox if the user wants that flow.
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("codex auth file %s: %w", src, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("codex auth file is not a regular file: %s", src)
	}
	return copyFileIfNewer(src, dst)
}

func copyFileIfNewer(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	dstInfo, err := os.Stat(dst)
	if err == nil && !srcInfo.ModTime().After(dstInfo.ModTime()) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Dir(dst), 0o700)
	if err != nil {
		return err
	}

	return os.WriteFile(dst, data, 0o600)
}

func writeCodexConfig(path string, route *ProxyRoute) error {
	var lines []string
	lines = append(lines,
		`analytics.enabled = false`,
		`check_for_update_on_startup = false`,
		`cli_auth_credentials_store = "file"`,
		fmt.Sprintf(`model_instructions_file = %q`, filepath.Join(Home, ".codex", "AGENTS-clampdown.md")),
	)

	if route != nil {
		lines = append(lines,
			`forced_login_method = "api"`,
			fmt.Sprintf(`openai_base_url = "http://localhost:%d/v1"`, route.Port),
		)
	} else {
		lines = append(lines, `forced_login_method = "chatgpt"`)
	}

	content := strings.Join(lines, "\n") + "\n"
	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == content {
		return nil
	}

	err = os.MkdirAll(filepath.Dir(path), 0o700)
	if err != nil {
		return fmt.Errorf("create codex config dir: %w", err)
	}

	err = os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		return fmt.Errorf("write codex config: %w", err)
	}
	return nil
}
