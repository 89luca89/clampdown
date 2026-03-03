// SPDX-License-Identifier: GPL-3.0-only

package sandbox_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/89luca89/clampdown/pkg/container"
	"github.com/89luca89/clampdown/pkg/sandbox"
)

func TestAgentLandlockPolicy(t *testing.T) {
	mounts := []container.MountSpec{
		{Source: "/work", Dest: "/work", Type: container.Bind},
		{Source: "/cfg", Dest: "/cfg", RO: true, Type: container.Bind},
		{Dest: "/masked", Type: container.DevNull},
	}
	tmpfs := []container.TmpfsSpec{
		{Path: "/tmp", NoExec: true},
		{Path: "/home", NoExec: false},
	}

	raw := sandbox.AgentLandlockPolicy(mounts, tmpfs)

	var p sandbox.LandlockPolicy
	err := json.Unmarshal([]byte(raw), &p)
	if err != nil {
		t.Fatal(err)
	}

	// RW bind -> WriteExec
	found := false
	for _, path := range p.WriteExec {
		if path == "/work" {
			found = true
		}
	}
	if !found {
		t.Error("/work should be in WriteExec")
	}

	// RO bind -> covered by ReadOnly, not in any write tier
	for _, path := range p.WriteExec {
		if path == "/cfg" {
			t.Error("/cfg (RO) should not be in WriteExec")
		}
	}

	// noexec tmpfs -> WriteNoExec
	found = false
	for _, path := range p.WriteNoExec {
		if path == "/tmp" {
			found = true
		}
	}
	if !found {
		t.Error("/tmp should be in WriteNoExec")
	}

	// exec tmpfs -> WriteExec
	found = false
	for _, path := range p.WriteExec {
		if path == "/home" {
			found = true
		}
	}
	if !found {
		t.Error("/home should be in WriteExec")
	}
}

func TestSidecarProtectedPaths_ExistingDir(t *testing.T) {
	workdir := t.TempDir()
	err := os.MkdirAll(filepath.Join(workdir, ".git", "hooks"), 0o750)
	if err != nil {
		t.Fatal(err)
	}

	specs := sandbox.SidecarProtectedPaths(workdir, false)

	found := false
	for _, s := range specs {
		if s.Dest == filepath.Join(workdir, ".git", "hooks") {
			found = true
			if s.Type != container.Bind || !s.RO {
				t.Errorf(".git/hooks: type=%v, RO=%v, want Bind+RO", s.Type, s.RO)
			}
		}
	}
	if !found {
		t.Error(".git/hooks should be in protected paths")
	}
}

func TestSidecarProtectedPaths_ExistingFile(t *testing.T) {
	workdir := t.TempDir()
	err := os.WriteFile(filepath.Join(workdir, ".envrc"), []byte("SECRET=x"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	specs := sandbox.SidecarProtectedPaths(workdir, false)

	found := false
	for _, s := range specs {
		if s.Dest == filepath.Join(workdir, ".envrc") {
			found = true
			if s.Type != container.DevNull {
				t.Errorf(".envrc: type=%v, want DevNull", s.Type)
			}
		}
	}
	if !found {
		t.Error(".envrc should be in protected paths")
	}
}

func TestSidecarProtectedPaths_AllowHooks(t *testing.T) {
	workdir := t.TempDir()
	err := os.MkdirAll(filepath.Join(workdir, ".git", "hooks"), 0o750)
	if err != nil {
		t.Fatal(err)
	}

	specs := sandbox.SidecarProtectedPaths(workdir, true)

	for _, s := range specs {
		if s.Dest == filepath.Join(workdir, ".git", "hooks") {
			t.Error(".git/hooks should be excluded when allowHooks=true")
		}
	}
}

func TestSidecarProtectedPaths_MissingPaths(t *testing.T) {
	workdir := t.TempDir()
	// Empty workdir — no .git, no .envrc, nothing.
	specs := sandbox.SidecarProtectedPaths(workdir, false)
	if len(specs) != 0 {
		t.Errorf("expected 0 specs for empty workdir, got %d", len(specs))
	}
}
