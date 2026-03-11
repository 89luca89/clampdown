// SPDX-License-Identifier: GPL-3.0-only

package sandbox_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/89luca89/clampdown/pkg/agent"
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

	raw := sandbox.AgentLandlockPolicy(mounts, tmpfs, nil)

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

	// nil connectPorts -> no ConnectTCP restriction
	if len(p.ConnectTCP) != 0 {
		t.Errorf("ConnectTCP should be empty with nil ports, got %v", p.ConnectTCP)
	}
}

func TestAgentLandlockPolicy_WithConnectTCP(t *testing.T) {
	mounts := []container.MountSpec{
		{Source: "/work", Dest: "/work", Type: container.Bind},
	}
	tmpfs := []container.TmpfsSpec{
		{Path: "/tmp", NoExec: true},
	}
	ports := []uint16{2375, 8001}

	raw := sandbox.AgentLandlockPolicy(mounts, tmpfs, ports)

	var p sandbox.LandlockPolicy
	err := json.Unmarshal([]byte(raw), &p)
	if err != nil {
		t.Fatal(err)
	}

	if len(p.ConnectTCP) != 2 {
		t.Fatalf("ConnectTCP: want 2 ports, got %d", len(p.ConnectTCP))
	}
	if p.ConnectTCP[0] != 2375 {
		t.Errorf("ConnectTCP[0] = %d, want 2375", p.ConnectTCP[0])
	}
	if p.ConnectTCP[1] != 8001 {
		t.Errorf("ConnectTCP[1] = %d, want 8001", p.ConnectTCP[1])
	}
}

func TestSidecarProtectedPaths_ExistingDir(t *testing.T) {
	workdir := t.TempDir()
	err := os.MkdirAll(filepath.Join(workdir, ".git", "hooks"), 0o750)
	if err != nil {
		t.Fatal(err)
	}

	specs := sandbox.SidecarProtectedPaths(workdir, false, nil, nil)

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
	err := os.MkdirAll(filepath.Join(workdir, ".git"), 0o750)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(workdir, ".git", "config"), []byte("[core]"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	specs := sandbox.SidecarProtectedPaths(workdir, false, nil, nil)

	found := false
	for _, s := range specs {
		if s.Dest == filepath.Join(workdir, ".git", "config") {
			found = true
			if s.Type != container.Bind || !s.RO {
				t.Errorf(".git/config: type=%v, RO=%v, want Bind+RO", s.Type, s.RO)
			}
		}
	}
	if !found {
		t.Error(".git/config should be in protected paths")
	}
}

func TestSidecarMaskedPaths_ExistingFile(t *testing.T) {
	workdir := t.TempDir()
	err := os.WriteFile(filepath.Join(workdir, ".envrc"), []byte("SECRET=x"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	masked := []agent.MaskedPath{{Path: ".envrc"}}
	specs, created := sandbox.SidecarMaskedPaths(workdir, masked)

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
		t.Error(".envrc should be in masked paths")
	}
	if len(created) != 0 {
		t.Error("existing file should not report as created")
	}
}

func TestSidecarProtectedPaths_AllowHooks(t *testing.T) {
	workdir := t.TempDir()
	err := os.MkdirAll(filepath.Join(workdir, ".git", "hooks"), 0o750)
	if err != nil {
		t.Fatal(err)
	}

	specs := sandbox.SidecarProtectedPaths(workdir, true, nil, nil)

	for _, s := range specs {
		if s.Dest == filepath.Join(workdir, ".git", "hooks") {
			t.Error(".git/hooks should be excluded when allowHooks=true")
		}
	}
}

func TestSidecarProtectedPaths_MissingPaths(t *testing.T) {
	workdir := t.TempDir()
	// Empty workdir — no .git, no .envrc, nothing.
	specs := sandbox.SidecarProtectedPaths(workdir, false, nil, nil)
	if len(specs) != 0 {
		t.Errorf("expected 0 specs for empty workdir, got %d", len(specs))
	}
}

func TestSidecarProtectedPaths_UserExtraDir(t *testing.T) {
	workdir := t.TempDir()
	err := os.MkdirAll(filepath.Join(workdir, "secrets"), 0o750)
	if err != nil {
		t.Fatal(err)
	}

	specs := sandbox.SidecarProtectedPaths(workdir, false, []string{"secrets/"}, nil)

	found := false
	for _, s := range specs {
		if s.Dest == filepath.Join(workdir, "secrets") {
			found = true
			if s.Type != container.Bind || !s.RO {
				t.Errorf("secrets: type=%v, RO=%v, want Bind+RO", s.Type, s.RO)
			}
		}
	}
	if !found {
		t.Error("user --protect secrets/ should be in protected paths")
	}
}

func TestSidecarProtectedPaths_UserExtraFile(t *testing.T) {
	workdir := t.TempDir()
	err := os.WriteFile(filepath.Join(workdir, "creds.json"), []byte(`{}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	specs := sandbox.SidecarProtectedPaths(workdir, false, []string{"creds.json"}, nil)

	found := false
	for _, s := range specs {
		if s.Dest == filepath.Join(workdir, "creds.json") {
			found = true
			if s.Type != container.Bind || !s.RO {
				t.Errorf("creds.json: type=%v, RO=%v, want Bind+RO", s.Type, s.RO)
			}
		}
	}
	if !found {
		t.Error("user --protect creds.json should be in protected paths")
	}
}

func TestSidecarProtectedPaths_UserExtraMissing(t *testing.T) {
	workdir := t.TempDir()
	// Path doesn't exist — should be skipped.
	specs := sandbox.SidecarProtectedPaths(workdir, false, []string{"nonexistent"}, nil)

	for _, s := range specs {
		if s.Dest == filepath.Join(workdir, "nonexistent") {
			t.Error("nonexistent path should not appear in protected paths")
		}
	}
}

func TestSidecarProtectedPaths_MaskedExcluded(t *testing.T) {
	workdir := t.TempDir()
	// Create a file that would normally be protected.
	err := os.MkdirAll(filepath.Join(workdir, ".git"), 0o750)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(workdir, ".git", "config"), []byte("[core]"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	masked := []agent.MaskedPath{{Path: ".git/config"}}
	specs := sandbox.SidecarProtectedPaths(workdir, false, nil, masked)

	for _, s := range specs {
		if s.Dest == filepath.Join(workdir, ".git", "config") {
			t.Error(".git/config should be excluded from protection when masked")
		}
	}
}
