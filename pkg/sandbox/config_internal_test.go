// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/89luca89/clampdown/pkg/agent"
)

// unsetEnv removes names from the process environment for the duration of the
// test. Blanking a variable is not the same thing: an exported but empty
// variable is itself an unset instruction, so a test that wants an rc value to
// win has to take the name out of the environment.
func unsetEnv(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		prev, had := os.LookupEnv(name)
		os.Unsetenv(name)
		t.Cleanup(func() {
			if had {
				os.Setenv(name, prev)
			} else {
				os.Unsetenv(name)
			}
		})
	}
}

func TestInjectableRCEnv(t *testing.T) {
	rcEnv := map[string]string{
		"ANTHROPIC_API_KEY":             "sk-real",     // proxy key -> excluded
		"ANTHROPIC_BASE_URL":            "https://x",   // base-url -> excluded
		"ANTHROPIC_AUTH_TOKEN":          "tok",         // credential-shaped in allowed prefix -> excluded
		"OPENAI_API_KEY":                "sk-other",    // not in Claude allowlist -> excluded
		"SANDBOX_POLICY":                "{}",          // infra, no allowlist match -> excluded
		"HOME":                          "/evil",       // infra -> excluded
		"CLAMPDOWN_UPSTREAM":            "https://ctl", // control var, not allowlisted -> excluded
		"FOO":                           "bar",         // not allowlisted -> excluded
		"ANTHROPIC_DEFAULT_OPUS_MODEL":  "minimax-m3",  // allowed prefix -> injected
		"ANTHROPIC_DEFAULT_HAIKU_MODEL": "",            // allowed, but empty -> unset, not forwarded
		"DISABLE_TELEMETRY":             "1",           // allowed prefix -> injected
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

// Routes whose endpoint embeds a region or account id build it from
// UpstreamEnv at resolve time instead of hardcoding it.
func TestResolveProxyUpstreamFromEnv(t *testing.T) {
	cloudflare := &agent.ProxyRoute{
		KeyEnv: "CLOUDFLARE_API_KEY", HeaderName: "Authorization",
		UpstreamEnv:      "CLOUDFLARE_ACCOUNT_ID",
		UpstreamTemplate: "https://api.cloudflare.com/client/v4/accounts/%s/ai/v1",
	}
	azure := &agent.ProxyRoute{
		KeyEnv: "AZURE_OPENAI_API_KEY", HeaderName: "api-key",
		UpstreamEnv: "AZURE_OPENAI_BASE_URL",
	}

	tests := []struct {
		name  string
		route *agent.ProxyRoute
		env   map[string]string
		want  string
	}{
		{"template expands the account id", cloudflare,
			map[string]string{"CLOUDFLARE_ACCOUNT_ID": "abc123"},
			"https://api.cloudflare.com/client/v4/accounts/abc123/ai/v1"},
		{"template without the value stays unresolved", cloudflare, nil, ""},
		{"no template: the value is the url", azure,
			map[string]string{"AZURE_OPENAI_BASE_URL": "https://res.openai.azure.com/openai/deployments/dep"},
			"https://res.openai.azure.com/openai/deployments/dep"},
		{"endpoint without the value stays unresolved", azure, nil, ""},
		// The account id is path material: it cannot move the request to
		// another host, only address another resource on Cloudflare's.
		{"account id stays in the path", cloudflare,
			map[string]string{"CLOUDFLARE_ACCOUNT_ID": "evil.com/x"},
			"https://api.cloudflare.com/client/v4/accounts/evil.com/x/ai/v1"},
	}
	for _, tt := range tests {
		unsetEnv(t, "CLOUDFLARE_ACCOUNT_ID", "AZURE_OPENAI_BASE_URL")
		got := resolveProxyUpstream(tt.route, tt.env)
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
