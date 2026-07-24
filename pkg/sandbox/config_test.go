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

	// BindTCP always empty for agent (unrestricted bind)
	if len(p.BindTCP) != 0 {
		t.Errorf("BindTCP should be empty for agent, got %v", p.BindTCP)
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

	// ConnectTCP does not imply BindTCP
	if len(p.BindTCP) != 0 {
		t.Errorf("BindTCP should be empty even with ConnectTCP set, got %v", p.BindTCP)
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
	// Empty workdir — paths whose parent is workdir get DevNull/EmptyRO;
	// paths whose parent doesn't exist (e.g. .git/hooks) are skipped.
	specs := sandbox.SidecarProtectedPaths(workdir, false, nil, nil)

	specMap := make(map[string]container.MountSpec, len(specs))
	for _, s := range specs {
		specMap[s.Dest] = s
	}

	// Absent file with workdir as parent — DevNull.
	s, ok := specMap[filepath.Join(workdir, ".mcp.json")]
	if !ok {
		t.Fatal(".mcp.json should be in specs (absent file, parent exists)")
	}
	if s.Type != container.DevNull {
		t.Errorf(".mcp.json: type=%v, want DevNull", s.Type)
	}

	// Absent dir with workdir as parent — EmptyRO.
	s, ok = specMap[filepath.Join(workdir, ".idea")]
	if !ok {
		t.Fatal(".idea should be in specs (absent dir, parent exists)")
	}
	if s.Type != container.EmptyRO {
		t.Errorf(".idea: type=%v, want EmptyRO", s.Type)
	}

	// Absent path with missing parent — skipped.
	if _, ok = specMap[filepath.Join(workdir, ".git", "hooks")]; ok {
		t.Error(".git/hooks should be skipped (parent .git doesn't exist)")
	}
	if _, ok = specMap[filepath.Join(workdir, ".git", "config")]; ok {
		t.Error(".git/config should be skipped (parent .git doesn't exist)")
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

func TestSidecarProtectedPaths_UserExtraMissingFile(t *testing.T) {
	workdir := t.TempDir()
	// Absent file with workdir as parent — DevNull.
	specs := sandbox.SidecarProtectedPaths(workdir, false, []string{"creds.json"}, nil)

	found := false
	for _, s := range specs {
		if s.Dest == filepath.Join(workdir, "creds.json") {
			found = true
			if s.Type != container.DevNull {
				t.Errorf("creds.json: type=%v, want DevNull", s.Type)
			}
		}
	}
	if !found {
		t.Error("absent --protect creds.json should be in specs as DevNull")
	}
}

func TestSidecarProtectedPaths_UserExtraMissingDir(t *testing.T) {
	workdir := t.TempDir()
	// Absent dir with workdir as parent — EmptyRO.
	specs := sandbox.SidecarProtectedPaths(workdir, false, []string{"secrets/"}, nil)

	found := false
	for _, s := range specs {
		if s.Dest == filepath.Join(workdir, "secrets") {
			found = true
			if s.Type != container.EmptyRO {
				t.Errorf("secrets: type=%v, want EmptyRO", s.Type)
			}
		}
	}
	if !found {
		t.Error("absent --protect secrets/ should be in specs as EmptyRO")
	}
}

func TestSidecarProtectedPaths_MissingParent(t *testing.T) {
	workdir := t.TempDir()
	// Parent doesn't exist — should be skipped entirely.
	specs := sandbox.SidecarProtectedPaths(workdir, false, []string{"missing/child"}, nil)

	for _, s := range specs {
		if s.Dest == filepath.Join(workdir, "missing", "child") {
			t.Error("path with missing parent should not appear in specs")
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

func TestWriteSandboxPrompt_Append(t *testing.T) {
	home := t.TempDir()
	ag := &agent.OpenCode{} // non-claude: skips the onboarding write path

	// WriteSandboxPrompt maps the container PromptFile() into homeDir the
	// same way, via filepath.Rel(agent.Home, ...).
	rel, err := filepath.Rel(agent.Home, ag.PromptFile())
	if err != nil {
		t.Fatal(err)
	}
	promptPath := filepath.Join(home, rel)
	base := agent.SandboxPrompt(ag.Name()) + "\n\n" + agent.SandboxSkill(ag.Name()) + "\n"

	// Empty append -> file equals the base prompt exactly.
	err = sandbox.WriteSandboxPrompt(ag, home, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != base {
		t.Error("empty append: file should equal base prompt")
	}

	// Non-empty append -> base prompt followed by the appended text.
	const extra = "House rule: no force pushes."
	want := base + "\n\n" + extra + "\n"
	err = sandbox.WriteSandboxPrompt(ag, home, extra)
	if err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(promptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("append: got %q, want %q", got, want)
	}

	// Idempotent: same input rewrites to identical content.
	err = sandbox.WriteSandboxPrompt(ag, home, extra)
	if err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(promptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("idempotent append: got %q, want %q", got, want)
	}
}
