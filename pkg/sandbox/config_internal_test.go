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
		"ANTHROPIC_DEFAULT_HAIKU_MODEL",
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

// An empty value is an unset instruction on both sides of the lookup: an empty
// rc entry cancels a key exported in the shell, and a shell variable exported
// blank cancels an rc entry. Anything else keeps the environment ahead of the
// rc file.
func TestResolveKeyEmptyMasksBothWays(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		envSet   bool
		rcEnv    map[string]string
		want     string
		wantOK   bool
	}{
		{"rc value alone", "", false,
			map[string]string{"K": "sk-rc"}, "sk-rc", true},
		{"environment wins over rc", "sk-env", true,
			map[string]string{"K": "sk-rc"}, "sk-env", true},
		{"empty rc entry cancels the environment", "sk-env", true,
			map[string]string{"K": ""}, "", false},
		{"empty environment cancels the rc entry", "", true,
			map[string]string{"K": "sk-rc"}, "", false},
		{"neither source sets it", "", false,
			map[string]string{}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unsetEnv(t, "K")
			if tt.envSet {
				t.Setenv("K", tt.envValue)
			}

			value, ok := resolveKey("K", tt.rcEnv)
			if ok != tt.wantOK || value != tt.want {
				t.Errorf("resolveKey = (%q, %v), want (%q, %v)", value, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// anthropic sits first in pi's route table, so a key exported in the shell
// takes the session away from the provider the rc file asks for unless the rc
// entry set to empty wins.
func TestActiveProxyRouteEmptyRCKeyMasksHostEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-host")
	rcEnv := map[string]string{
		"ANTHROPIC_API_KEY": "",
		"OPENCODE_API_KEY":  "sk-rc",
	}

	route := ActiveProxyRoute(&agent.Pi{}, rcEnv)
	if route == nil {
		t.Fatal("no active route")
	}
	if route.ProviderID != "opencode-go" {
		t.Errorf("active provider = %q, want opencode-go", route.ProviderID)
	}
}

// The whole decision path, from the files on disk to the route: a global rc
// that sets the anthropic key, a project rc that cancels it and sets the
// opencode one, and a shell that exports the anthropic key anyway.
func TestRCEmptyKeyFlipsRouteWithHostEnvSet(t *testing.T) {
	configDir := t.TempDir()
	orig := ConfigDir
	ConfigDir = configDir
	defer func() { ConfigDir = orig }()

	workdir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "clampdownrc"),
		[]byte("ANTHROPIC_API_KEY=sk-global\nANTHROPIC_BASE_URL=https://opencode.ai/zen/go\n"), 0o600)
	os.WriteFile(filepath.Join(workdir, ".clampdownrc"),
		[]byte("ANTHROPIC_API_KEY=\nOPENCODE_API_KEY=sk-opencode\n"), 0o600)

	unsetEnv(t, "OPENCODE_API_KEY")
	t.Setenv("ANTHROPIC_API_KEY", "sk-host")

	rcEnv, err := LoadRC(workdir, "")
	if err != nil {
		t.Fatalf("LoadRC: %v", err)
	}
	route := ActiveProxyRoute(&agent.Pi{}, rcEnv)
	if route == nil {
		t.Fatal("no active route")
	}
	if route.ProviderID != "opencode-go" {
		t.Errorf("active provider = %q, want opencode-go", route.ProviderID)
	}
	if got := resolveProxyUpstream(route, rcEnv); got != "https://opencode.ai/zen/go/v1" {
		t.Errorf("proxy upstream = %q", got)
	}
}

// A route that cannot assemble its upstream must not activate: the proxy would
// start and forward requests nowhere.
func TestActiveProxyRouteRequiresUpstream(t *testing.T) {
	pi := &agent.Pi{}
	for _, r := range pi.ProxyRoutes() {
		unsetEnv(t, r.KeyEnv)
		if r.KeyEnvFallback != "" {
			unsetEnv(t, r.KeyEnvFallback)
		}
	}

	azure := map[string]string{"AZURE_OPENAI_API_KEY": "k"}
	if route := ActiveProxyRoute(pi, azure); route != nil {
		t.Fatalf("route without an upstream should stay inactive, got %+v", route)
	}

	azure["AZURE_OPENAI_BASE_URL"] = "https://res.openai.azure.com/openai/deployments/dep"
	route := ActiveProxyRoute(pi, azure)
	if route == nil || route.ProviderID != "azure-openai-responses" {
		t.Fatalf("route with an upstream should activate, got %+v", route)
	}
	// The endpoint is per-resource, so its host must reach the egress allowlist.
	if host := repointedUpstreamHost(route, azure); host != "res.openai.azure.com" {
		t.Errorf("egress host = %q, want res.openai.azure.com", host)
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
