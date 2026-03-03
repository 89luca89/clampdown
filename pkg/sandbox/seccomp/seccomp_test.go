// SPDX-License-Identifier: GPL-3.0-only

package seccomp_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/89luca89/clampdown/pkg/sandbox/seccomp"
)

func TestEnsureProfiles_Creates(t *testing.T) {
	dir := t.TempDir()
	sidecar, agent, err := seccomp.EnsureProfiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if sidecar == "" || agent == "" {
		t.Fatal("returned empty paths")
	}
	if _, err = os.Stat(sidecar); err != nil {
		t.Errorf("sidecar profile not created: %v", err)
	}
	if _, err = os.Stat(agent); err != nil {
		t.Errorf("agent profile not created: %v", err)
	}
}

func TestEnsureProfiles_Idempotent(t *testing.T) {
	dir := t.TempDir()
	s1, a1, err := seccomp.EnsureProfiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	info1, _ := os.Stat(s1)
	mod1 := info1.ModTime()

	// Second call should not rewrite (sha256 matches).
	s2, a2, err := seccomp.EnsureProfiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s1 != s2 || a1 != a2 {
		t.Error("paths should be stable")
	}
	info2, _ := os.Stat(s2)
	if !info2.ModTime().Equal(mod1) {
		t.Error("file should not be rewritten when content matches")
	}
}

func TestEnsureProfiles_RewritesStale(t *testing.T) {
	dir := t.TempDir()
	_, _, err := seccomp.EnsureProfiles(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the sidecar profile.
	sidecarPath := filepath.Join(dir, "seccomp", "sidecar.json")
	err = os.WriteFile(sidecarPath, []byte("corrupted"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	// Should rewrite.
	_, _, err = seccomp.EnsureProfiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(sidecarPath)
	if string(content) == "corrupted" {
		t.Error("stale profile should have been rewritten")
	}
}
