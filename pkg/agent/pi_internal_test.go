// SPDX-License-Identifier: GPL-3.0-only

package agent

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A provider's host missing from the egress allowlist fails the session at the
// first request, with the proxy firewalled off from its own upstream.
func TestPiUpstreamsAreAllowlisted(t *testing.T) {
	pi := &Pi{}
	allowed := make(map[string]bool)
	for _, d := range pi.EgressDomains() {
		allowed[d] = true
	}

	for _, r := range pi.ProxyRoutes() {
		target := r.Upstream
		if target == "" {
			// Derive the host from the template, using a stand-in for the
			// value the environment supplies at resolve time.
			target = strings.ReplaceAll(r.UpstreamTemplate, "%s", "placeholder")
		}
		if target == "" {
			// The whole endpoint comes from the environment (azure), so there
			// is no built-in host to check. repointedUpstreamHost adds it to
			// the allowlist at session start.
			if r.UpstreamEnv == "" {
				t.Errorf("%s: route has neither an upstream nor a template", r.ProviderID)
			}
			continue
		}
		u, err := url.Parse(target)
		if err != nil {
			t.Errorf("%s: unparseable upstream %q: %v", r.ProviderID, target, err)
			continue
		}
		if !allowed[u.Hostname()] {
			t.Errorf("%s: upstream host %q is not in EgressDomains", r.ProviderID, u.Hostname())
		}
	}
}

// pi learns about models newer than its bundled catalogue only from pi.dev, so
// the host has to be reachable and PI_OFFLINE has to stay unset: either one
// missing silently drops the picker back to the versions built into the image.
func TestPiCatalogueRefresh(t *testing.T) {
	pi := &Pi{}

	allowed := false
	for _, d := range pi.EgressDomains() {
		if d == "pi.dev" {
			allowed = true
		}
	}
	if !allowed {
		t.Error("pi.dev missing from EgressDomains: the catalogue refresh is firewalled")
	}

	env := pi.Env()
	if _, ok := env["PI_OFFLINE"]; ok {
		t.Error("PI_OFFLINE set: pi skips the catalogue refresh")
	}
	for _, name := range []string{"PI_SKIP_VERSION_CHECK", "PI_TELEMETRY"} {
		if env[name] == "" {
			t.Errorf("%s not set: startup traffic the sandbox has no use for stays on", name)
		}
	}
}

func TestPreparePiHome(t *testing.T) {
	pi := &Pi{}
	routes := pi.ProxyRoutes()

	// opencode-go is the route a bare OPENCODE_API_KEY activates; opencode
	// (zen) shares that key, anthropic does not.
	var active *ProxyRoute
	for i := range routes {
		if routes[i].ProviderID == "opencode-go" {
			active = &routes[i]
		}
	}
	if active == nil {
		t.Fatal("no opencode-go route in the table")
	}

	home := t.TempDir()
	err := PreparePiHome(home, routes, active)
	if err != nil {
		t.Fatalf("PreparePiHome: %v", err)
	}

	path := filepath.Join(home, ".pi", "agent", "models.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat models.json: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("models.json mode = %o, want 600", perm)
	}

	var cfg struct {
		Providers map[string]struct {
			BaseURL string `json:"baseUrl"`
		} `json:"providers"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read models.json: %v", err)
	}
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		t.Fatalf("unmarshal models.json: %v", err)
	}

	want := "http://127.0.0.1:2376"
	for _, id := range []string{"opencode-go", "opencode"} {
		if cfg.Providers[id].BaseURL != want {
			t.Errorf("provider %s baseUrl = %q, want %q", id, cfg.Providers[id].BaseURL, want)
		}
	}
	if cfg.Providers["anthropic"].BaseURL != "" {
		t.Errorf("anthropic shares no key with the active route, got %q", cfg.Providers["anthropic"].BaseURL)
	}

	// A session without a key must not leave a stale proxy endpoint behind.
	err = PreparePiHome(home, routes, nil)
	if err != nil {
		t.Fatalf("PreparePiHome without a route: %v", err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("models.json should be removed without an active route, stat err = %v", err)
	}
}
