// SPDX-License-Identifier: GPL-3.0-only

package network_test

import (
	"testing"

	"github.com/89luca89/clampdown/pkg/sandbox/network"
)

// TestResolveAllowEntriesLiterals covers the parse + literal-passthrough paths
// without touching DNS. Hostnames are not exercised here to keep the test
// hermetic.
func TestResolveAllowEntriesLiterals(t *testing.T) {
	entries := network.ResolveAllowEntries([]string{
		"192.168.1.14:8080",
		"100.71.163.14:11434",
		"10.0.0.0/8",
		"[::1]:443",
		"::1",
		"1.2.3.4:0",
	})
	want := map[string]int{
		"192.168.1.14":  8080,
		"100.71.163.14": 11434,
		"10.0.0.0/8":    443,
		"::1":           443,
		"1.2.3.4":       0,
	}
	got := make(map[string]int, len(entries))
	for _, e := range entries {
		got[e.Target] = e.Port
	}
	for target, port := range want {
		p, ok := got[target]
		if !ok {
			t.Errorf("missing target %q", target)
			continue
		}
		if p != port {
			t.Errorf("target %q port = %d, want %d", target, p, port)
		}
	}
}
