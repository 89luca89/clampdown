// SPDX-License-Identifier: GPL-3.0-only

package sandbox_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/89luca89/clampdown/pkg/container"
	"github.com/89luca89/clampdown/pkg/sandbox"
)

func TestCredentialMountsGitConfig(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	gitconfig := filepath.Join(tmp, ".gitconfig")
	err := os.WriteFile(gitconfig, []byte("[user]\nname = test\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	mnts := sandbox.CredentialMounts(sandbox.Options{GitConfig: true})

	if len(mnts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(mnts))
	}
	if mnts[0].Source != gitconfig {
		t.Errorf("source = %q, want %q", mnts[0].Source, gitconfig)
	}
	if mnts[0].Dest != "/run/credentials/gitconfig" {
		t.Errorf("dest = %q, want /run/credentials/gitconfig", mnts[0].Dest)
	}
	if !mnts[0].RO {
		t.Error("mount should be read-only")
	}
}

func TestCredentialMountsGitConfigMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	mnts := sandbox.CredentialMounts(sandbox.Options{GitConfig: true})
	if len(mnts) != 0 {
		t.Fatalf("got %d mounts, want 0 (file missing)", len(mnts))
	}
}

func TestCredentialMountsGH(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	ghDir := filepath.Join(tmp, ".config", "gh")
	err := os.MkdirAll(ghDir, 0o755)
	if err != nil {
		t.Fatal(err)
	}

	mnts := sandbox.CredentialMounts(sandbox.Options{GH: true})

	if len(mnts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(mnts))
	}
	if mnts[0].Source != ghDir {
		t.Errorf("source = %q, want %q", mnts[0].Source, ghDir)
	}
	if mnts[0].Dest != "/run/credentials/gh" {
		t.Errorf("dest = %q, want /run/credentials/gh", mnts[0].Dest)
	}
}

func TestCredentialMountsGHMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	mnts := sandbox.CredentialMounts(sandbox.Options{GH: true})
	if len(mnts) != 0 {
		t.Fatalf("got %d mounts, want 0 (dir missing)", len(mnts))
	}
}

func TestCredentialMountsSSH(t *testing.T) {
	tmp := t.TempDir()
	sock := filepath.Join(tmp, "agent.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Setenv("SSH_AUTH_SOCK", sock)

	mnts := sandbox.CredentialMounts(sandbox.Options{SSH: true})

	if len(mnts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(mnts))
	}
	if mnts[0].Source != sock {
		t.Errorf("source = %q, want %q", mnts[0].Source, sock)
	}
	if mnts[0].Dest != "/run/credentials/ssh-agent.sock" {
		t.Errorf("dest = %q, want /run/credentials/ssh-agent.sock", mnts[0].Dest)
	}
}

func TestCredentialMountsSSHNoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	mnts := sandbox.CredentialMounts(sandbox.Options{SSH: true})
	if len(mnts) != 0 {
		t.Fatalf("got %d mounts, want 0 (no agent)", len(mnts))
	}
}

func TestCredentialMountsSSHSocketMissing(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/nonexistent/agent.sock")

	mnts := sandbox.CredentialMounts(sandbox.Options{SSH: true})
	if len(mnts) != 0 {
		t.Fatalf("got %d mounts, want 0 (socket missing)", len(mnts))
	}
}

func TestCredentialMountsNoneEnabled(t *testing.T) {
	mnts := sandbox.CredentialMounts(sandbox.Options{})
	if len(mnts) != 0 {
		t.Fatalf("got %d mounts, want 0", len(mnts))
	}
}

func TestCredentialMountsAllTypes(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	err := os.WriteFile(filepath.Join(tmp, ".gitconfig"), []byte("[user]\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	err = os.MkdirAll(filepath.Join(tmp, ".config", "gh"), 0o755)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(tmp, "agent.sock")
	ln, listenErr := net.Listen("unix", sock)
	if listenErr != nil {
		t.Fatal(listenErr)
	}
	defer ln.Close()
	t.Setenv("SSH_AUTH_SOCK", sock)

	mnts := sandbox.CredentialMounts(sandbox.Options{
		GitConfig: true,
		GH:        true,
		SSH:       true,
	})

	if len(mnts) != 3 {
		t.Fatalf("got %d mounts, want 3", len(mnts))
	}
	for _, m := range mnts {
		if m.Type != container.Bind {
			t.Errorf("mount %q: type = %v, want Bind", m.Dest, m.Type)
		}
		if !m.RO {
			t.Errorf("mount %q: should be read-only", m.Dest)
		}
	}
}

func TestCredentialMountsEmptyHome(t *testing.T) {
	t.Setenv("HOME", "")

	mnts := sandbox.CredentialMounts(sandbox.Options{
		GitConfig: true,
		GH:        true,
		SSH:       true,
	})
	if len(mnts) != 0 {
		t.Fatalf("got %d mounts, want 0 (HOME empty)", len(mnts))
	}
}
