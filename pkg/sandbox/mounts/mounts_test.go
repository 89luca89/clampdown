// SPDX-License-Identifier: GPL-3.0-only

package mounts_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/89luca89/clampdown/pkg/agent"
	"github.com/89luca89/clampdown/pkg/container"
	"github.com/89luca89/clampdown/pkg/sandbox/mounts"
)

func TestMergeProtection_WithHooks(t *testing.T) {
	paths := mounts.MergeProtection(false)
	found := false
	for _, p := range paths {
		if p.Path == ".git/hooks" {
			found = true
		}
	}
	if !found {
		t.Error(".git/hooks should be present when allowHooks=false")
	}
}

func TestMergeProtection_WithoutHooks(t *testing.T) {
	paths := mounts.MergeProtection(true)
	for _, p := range paths {
		if p.Path == ".git/hooks" {
			t.Error(".git/hooks should be removed when allowHooks=true")
		}
	}
}

func TestMergeProtection_IncludesClampdownrc(t *testing.T) {
	paths := mounts.MergeProtection(false)
	found := false
	for _, p := range paths {
		if p.Path == ".clampdownrc" {
			found = true
		}
	}
	if !found {
		t.Error(".clampdownrc should be in UniversalProtectedPaths")
	}
}

func TestProtectMount_ExistingDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hooks")
	err := os.Mkdir(target, 0o750)
	if err != nil {
		t.Fatal(err)
	}

	m, created, err := mounts.ProtectMount(target, true)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("expected mount spec")
	}
	if m.Type != container.Bind || !m.RO {
		t.Errorf("type=%v, RO=%v, want Bind+RO", m.Type, m.RO)
	}
	if created != "" {
		t.Error("existing dir should not report as created")
	}
}

func TestProtectMount_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ".envrc")
	err := os.WriteFile(target, []byte("SECRET=x"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	m, created, err := mounts.ProtectMount(target, false)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("expected mount spec")
	}
	if m.Type != container.Bind || !m.RO {
		t.Errorf("type=%v, RO=%v, want Bind+RO", m.Type, m.RO)
	}
	if created != "" {
		t.Error("existing file should not report as created")
	}
}

func TestProtectMount_MissingDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hooks")

	m, created, err := mounts.ProtectMount(target, true)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("expected mount spec for created dir")
	}
	if m.Type != container.EmptyRO {
		t.Errorf("type=%v, want EmptyRO", m.Type)
	}
	if created == "" {
		t.Error("should report created path")
	}
	// Cleanup.
	os.RemoveAll(created)
}

func TestProtectMount_MissingFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ".envrc")

	m, created, err := mounts.ProtectMount(target, false)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("expected mount spec for created file")
	}
	if m.Type != container.DevNull {
		t.Errorf("type=%v, want DevNull", m.Type)
	}
	if created == "" {
		t.Error("should report created path")
	}
	os.Remove(created)
}

func TestProtectMount_MissingParent(t *testing.T) {
	m, _, err := mounts.ProtectMount("/nonexistent/parent/.envrc", false)
	if err != nil {
		t.Fatal(err)
	}
	if m != nil {
		t.Error("should return nil when parent doesn't exist")
	}
}

// testAgent implements agent.Agent for testing.
type testAgent struct {
	mounts   []agent.Mount
	overlays []agent.Mount
}

func (a *testAgent) Name() string                       { return "test" }
func (a *testAgent) Image() string                      { return "test:latest" }
func (a *testAgent) EgressDomains() []string            { return nil }
func (a *testAgent) Mounts() []agent.Mount              { return a.mounts }
func (a *testAgent) ConfigOverlays() []agent.Mount      { return a.overlays }
func (a *testAgent) Env() map[string]string             { return nil }
func (a *testAgent) Args(passthrough []string) []string { return passthrough }
func (a *testAgent) PromptFile() string                 { return "" }
func (a *testAgent) ForwardEnv() []string               { return nil }

func TestBuild_ProtectionMounts(t *testing.T) {
	workdir := t.TempDir()
	ag := &testAgent{}

	// Create .envrc so protection mount triggers.
	err := os.WriteFile(filepath.Join(workdir, ".envrc"), []byte("x"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	protection := []agent.ProtectedPath{
		{Path: ".envrc", IsDir: false},
	}
	mnts, created, err := mounts.Build(workdir, t.TempDir(), t.TempDir(), ag, protection)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, p := range created {
			os.RemoveAll(p)
		}
	}()

	found := false
	for _, m := range mnts {
		if m.Dest == filepath.Join(workdir, ".envrc") {
			found = true
			if !m.RO {
				t.Error(".envrc mount should be RO")
			}
		}
	}
	if !found {
		t.Error(".envrc protection mount not found")
	}
}

func TestBuild_CreatesNonExistingProtectedPaths(t *testing.T) {
	workdir := t.TempDir()
	ag := &testAgent{}

	protection := []agent.ProtectedPath{
		{Path: ".mcp.json", IsDir: false},
	}
	_, created, err := mounts.Build(workdir, t.TempDir(), t.TempDir(), ag, protection)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, p := range created {
			os.RemoveAll(p)
		}
	}()

	if len(created) != 1 {
		t.Fatalf("expected 1 created path, got %d", len(created))
	}
	if created[0] != filepath.Join(workdir, ".mcp.json") {
		t.Errorf("created = %s, want .mcp.json", created[0])
	}
}

func TestBuild_HostConfigTrue_IncludesMountsAndOverlays(t *testing.T) {
	workdir := t.TempDir()
	src := filepath.Join(t.TempDir(), "config.toml")
	os.WriteFile(src, []byte("x"), 0o600)

	ag := &testAgent{
		mounts:   []agent.Mount{{Src: src, Dst: "/home/test/.config", RW: true}},
		overlays: []agent.Mount{{Src: src, Dst: "/home/test/.overlay"}},
	}

	mnts, _, err := mounts.Build(workdir, t.TempDir(), t.TempDir(), ag, nil)
	if err != nil {
		t.Fatal(err)
	}
	foundMount, foundOverlay := false, false
	for _, m := range mnts {
		if m.Dest == "/home/test/.config" {
			foundMount = true
		}
		if m.Dest == "/home/test/.overlay" {
			foundOverlay = true
			if !m.RO {
				t.Error("overlay should be RO")
			}
		}
	}
	if !foundMount {
		t.Error("agent mount not found when hostConfig=true")
	}
	if !foundOverlay {
		t.Error("config overlay not found when hostConfig=true")
	}
}

func TestBuild_HostConfigTrue_SkipsMissingSources(t *testing.T) {
	workdir := t.TempDir()
	ag := &testAgent{
		mounts:   []agent.Mount{{Src: "/nonexistent/mount", Dst: "/dst"}},
		overlays: []agent.Mount{{Src: "/nonexistent/overlay", Dst: "/dst2"}},
	}

	mnts, _, err := mounts.Build(workdir, t.TempDir(), t.TempDir(), ag, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Only workdir should be present.
	if len(mnts) != 1 {
		t.Errorf("expected 1 mount (workdir only), got %d", len(mnts))
	}
}
