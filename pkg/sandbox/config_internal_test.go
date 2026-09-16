// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import (
	"testing"

	"github.com/89luca89/clampdown/pkg/agent"
)

func TestInjectableRCEnv(t *testing.T) {
	rcEnv := map[string]string{
		"ANTHROPIC_API_KEY":            "sk-real",     // proxy key -> excluded
		"ANTHROPIC_BASE_URL":           "https://x",   // base-url -> excluded
		"ANTHROPIC_AUTH_TOKEN":         "tok",         // credential-shaped in allowed prefix -> excluded
		"OPENAI_API_KEY":               "sk-other",    // not in Claude allowlist -> excluded
		"SANDBOX_POLICY":               "{}",          // infra, no allowlist match -> excluded
		"HOME":                         "/evil",       // infra -> excluded
		"CLAMPDOWN_UPSTREAM":           "https://ctl", // control var, not allowlisted -> excluded
		"FOO":                          "bar",         // not allowlisted -> excluded
		"ANTHROPIC_DEFAULT_OPUS_MODEL": "minimax-m3",  // allowed prefix -> injected
		"DISABLE_TELEMETRY":            "1",           // allowed prefix -> injected
	}

	got := injectableRCEnv(&agent.Claude{}, rcEnv)

	want := map[string]string{
		"ANTHROPIC_DEFAULT_OPUS_MODEL": "minimax-m3",
		"DISABLE_TELEMETRY":            "1",
	}
	if len(got) != len(want) {
		t.Fatalf("injectableRCEnv returned %d keys, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("injectableRCEnv[%q] = %q, want %q", k, got[k], v)
		}
	}
	for _, excluded := range []string{
		"ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN",
		"OPENAI_API_KEY", "SANDBOX_POLICY", "HOME", "CLAMPDOWN_UPSTREAM", "FOO",
	} {
		if _, ok := got[excluded]; ok {
			t.Errorf("%q should be excluded from agent injection", excluded)
		}
	}
}

// injectableRCEnv is per-agent: OpenCode admits only OPENCODE_MODEL, Codex
// admits nothing (it is config-file driven).
func TestInjectableRCEnvPerAgent(t *testing.T) {
	rcEnv := map[string]string{
		"OPENCODE_MODEL":               "anthropic/claude-x", // opencode: allowed
		"OPENCODE_CONFIG_CONTENT":      "{}",                 // opencode: sandbox-owned, not allowed
		"OPENCODE_THEME":               "dark",               // opencode: not allowlisted
		"ANTHROPIC_DEFAULT_OPUS_MODEL": "m",                  // claude-only var
	}

	oc := injectableRCEnv(&agent.OpenCode{}, rcEnv)
	if oc["OPENCODE_MODEL"] != "anthropic/claude-x" {
		t.Errorf("OpenCode should inject OPENCODE_MODEL, got %v", oc)
	}
	for _, k := range []string{"OPENCODE_CONFIG_CONTENT", "OPENCODE_THEME", "ANTHROPIC_DEFAULT_OPUS_MODEL"} {
		if _, ok := oc[k]; ok {
			t.Errorf("OpenCode should not inject %q", k)
		}
	}

	cx := injectableRCEnv(&agent.Codex{}, rcEnv)
	if len(cx) != 0 {
		t.Errorf("Codex allowlist is empty, injected %v", cx)
	}
}

func TestIsSensitiveEnvName(t *testing.T) {
	for _, k := range []string{
		"ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BEDROCK_BASE_URL",
		"CLAUDE_CODE_CLIENT_KEY", "NVIDIA_API_KEY", "X_CERTIFICATE",
	} {
		if !isSensitiveEnvName(k) {
			t.Errorf("%q should be treated as sensitive", k)
		}
	}
	for _, k := range []string{
		"ANTHROPIC_MODEL", "MAX_THINKING_TOKENS", "DISABLE_TELEMETRY", "OPENCODE_MODEL",
	} {
		if isSensitiveEnvName(k) {
			t.Errorf("%q should not be treated as sensitive", k)
		}
	}
}

func TestResolveProxyUpstream(t *testing.T) {
	claude := &agent.ProxyRoute{
		Upstream: "https://api.anthropic.com", KeyEnv: "ANTHROPIC_API_KEY",
		BaseURLEnv: "ANTHROPIC_BASE_URL",
	}
	// Codex-style route: no BaseURLEnv, so only CLAMPDOWN_UPSTREAM can repoint.
	codex := &agent.ProxyRoute{
		Upstream: "https://api.openai.com/v1", KeyEnv: "OPENAI_API_KEY",
	}

	tests := []struct {
		name  string
		route *agent.ProxyRoute
		rcEnv map[string]string
		want  string
	}{
		{"default", claude, nil, "https://api.anthropic.com"},
		{"base-url override", claude,
			map[string]string{"ANTHROPIC_BASE_URL": "https://opencode.ai/zen/go"},
			"https://opencode.ai/zen/go"},
		{"base-url beats generic", claude,
			map[string]string{"ANTHROPIC_BASE_URL": "https://a.example", "CLAMPDOWN_UPSTREAM": "https://b.example"},
			"https://a.example"},
		{"non-https rejected", claude,
			map[string]string{"ANTHROPIC_BASE_URL": "http://insecure.example"},
			"https://api.anthropic.com"},
		{"garbage rejected", claude,
			map[string]string{"ANTHROPIC_BASE_URL": "not a url"},
			"https://api.anthropic.com"},
		{"generic fallback for route without base-url env", codex,
			map[string]string{"CLAMPDOWN_UPSTREAM": "https://opencode.ai/zen/v1"},
			"https://opencode.ai/zen/v1"},
		{"base-url env ignored when route lacks it", codex,
			map[string]string{"ANTHROPIC_BASE_URL": "https://opencode.ai/zen/go"},
			"https://api.openai.com/v1"},
	}
	for _, tt := range tests {
		got := resolveProxyUpstream(tt.route, tt.rcEnv)
		if got != tt.want {
			t.Errorf("%s: resolveProxyUpstream = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestRepointedUpstreamHost(t *testing.T) {
	claude := &agent.ProxyRoute{
		Upstream: "https://api.anthropic.com", KeyEnv: "ANTHROPIC_API_KEY",
		BaseURLEnv: "ANTHROPIC_BASE_URL",
	}

	if host := repointedUpstreamHost(claude, nil); host != "" {
		t.Errorf("no override should yield empty host, got %q", host)
	}
	got := repointedUpstreamHost(claude, map[string]string{"ANTHROPIC_BASE_URL": "https://opencode.ai/zen/go"})
	if got != "opencode.ai" {
		t.Errorf("repointedUpstreamHost = %q, want opencode.ai", got)
	}
	// Host extraction strips an explicit port.
	got = repointedUpstreamHost(claude, map[string]string{"ANTHROPIC_BASE_URL": "https://proxy.internal:8443/v1"})
	if got != "proxy.internal" {
		t.Errorf("repointedUpstreamHost = %q, want proxy.internal", got)
	}
}

func TestProxyManagedEnvNames(t *testing.T) {
	names := agent.ProxyManagedEnvNames()

	for _, want := range []string{
		"ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN",
		"OPENAI_API_KEY", "OPENAI_BASE_URL", "GEMINI_API_KEY", "OPENCODE_API_KEY",
	} {
		if !names[want] {
			t.Errorf("%q should be proxy-managed", want)
		}
	}
	for _, absent := range []string{"FOO", "ANTHROPIC_DEFAULT_OPUS_MODEL", "SANDBOX_POLICY"} {
		if names[absent] {
			t.Errorf("%q should not be proxy-managed", absent)
		}
	}
}
