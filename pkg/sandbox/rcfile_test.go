// SPDX-License-Identifier: GPL-3.0-only

package sandbox_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/89luca89/clampdown/pkg/sandbox"
)

func TestParseRC_Valid(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rc")
	os.WriteFile(f, []byte("FOO=bar\nBAZ=qux\n"), 0o600)

	m, err := sandbox.ParseRC(f)
	if err != nil {
		t.Fatal(err)
	}
	if m["FOO"] != "bar" || m["BAZ"] != "qux" {
		t.Errorf("got %v", m)
	}
}

func TestParseRC_Comments(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rc")
	os.WriteFile(f, []byte("# comment\nKEY=val\n"), 0o600)

	m, err := sandbox.ParseRC(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m["KEY"] != "val" {
		t.Errorf("got %v", m)
	}
}

func TestParseRC_BlankLines(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rc")
	os.WriteFile(f, []byte("\n\nA=1\n\n"), 0o600)

	m, err := sandbox.ParseRC(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 {
		t.Errorf("expected 1 entry, got %d", len(m))
	}
}

func TestParseRC_MissingFile(t *testing.T) {
	m, err := sandbox.ParseRC("/nonexistent/path")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}

func TestParseRC_NoEquals(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rc")
	os.WriteFile(f, []byte("BADLINE\n"), 0o600)

	_, err := sandbox.ParseRC(f)
	if err == nil {
		t.Fatal("expected error for missing '='")
	}
}

func TestParseRC_EmptyKey(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rc")
	os.WriteFile(f, []byte("=value\n"), 0o600)

	_, err := sandbox.ParseRC(f)
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestParseRC_ValueWithEquals(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rc")
	os.WriteFile(f, []byte("TOKEN=abc=def==\n"), 0o600)

	m, err := sandbox.ParseRC(f)
	if err != nil {
		t.Fatal(err)
	}
	if m["TOKEN"] != "abc=def==" {
		t.Errorf("got %q, want abc=def==", m["TOKEN"])
	}
}

func TestParseRC_Whitespace(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rc")
	os.WriteFile(f, []byte("  KEY  =  val  \n"), 0o600)

	m, err := sandbox.ParseRC(f)
	if err != nil {
		t.Fatal(err)
	}
	if m["KEY"] != "val" {
		t.Errorf("got %q, want 'val'", m["KEY"])
	}
}

func TestParseRC_DoubleQuotes(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rc")
	os.WriteFile(f, []byte(`KEY="hello world"`+"\n"), 0o600)

	m, err := sandbox.ParseRC(f)
	if err != nil {
		t.Fatal(err)
	}
	if m["KEY"] != "hello world" {
		t.Errorf("got %q, want 'hello world'", m["KEY"])
	}
}

func TestParseRC_SingleQuotes(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rc")
	os.WriteFile(f, []byte("KEY='hello world'\n"), 0o600)

	m, err := sandbox.ParseRC(f)
	if err != nil {
		t.Fatal(err)
	}
	if m["KEY"] != "hello world" {
		t.Errorf("got %q, want 'hello world'", m["KEY"])
	}
}

func TestParseRC_UnmatchedQuotesUntouched(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rc")
	os.WriteFile(f, []byte(`KEY="hello`+"\n"), 0o600)

	m, err := sandbox.ParseRC(f)
	if err != nil {
		t.Fatal(err)
	}
	if m["KEY"] != `"hello` {
		t.Errorf("got %q, want '\"hello'", m["KEY"])
	}
}

func TestLoadRC_GlobalOnly(t *testing.T) {
	configDir := t.TempDir()
	orig := sandbox.ConfigDir
	sandbox.ConfigDir = configDir
	defer func() { sandbox.ConfigDir = orig }()

	os.WriteFile(filepath.Join(configDir, "clampdownrc"), []byte("G=1\n"), 0o600)

	m, err := sandbox.LoadRC(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if m["G"] != "1" {
		t.Errorf("got %v", m)
	}
}

func TestLoadRC_ProjectOnly(t *testing.T) {
	orig := sandbox.ConfigDir
	sandbox.ConfigDir = t.TempDir()
	defer func() { sandbox.ConfigDir = orig }()

	workdir := t.TempDir()
	os.WriteFile(filepath.Join(workdir, ".clampdownrc"), []byte("P=2\n"), 0o600)

	m, err := sandbox.LoadRC(workdir)
	if err != nil {
		t.Fatal(err)
	}
	if m["P"] != "2" {
		t.Errorf("got %v", m)
	}
}

func TestLoadRC_ProjectOverridesGlobal(t *testing.T) {
	configDir := t.TempDir()
	orig := sandbox.ConfigDir
	sandbox.ConfigDir = configDir
	defer func() { sandbox.ConfigDir = orig }()

	workdir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "clampdownrc"), []byte("KEY=global\nONLY_G=g\n"), 0o600)
	os.WriteFile(filepath.Join(workdir, ".clampdownrc"), []byte("KEY=project\nONLY_P=p\n"), 0o600)

	m, err := sandbox.LoadRC(workdir)
	if err != nil {
		t.Fatal(err)
	}
	if m["KEY"] != "project" {
		t.Errorf("KEY = %q, want 'project'", m["KEY"])
	}
	if m["ONLY_G"] != "g" {
		t.Errorf("ONLY_G missing")
	}
	if m["ONLY_P"] != "p" {
		t.Errorf("ONLY_P missing")
	}
}

func TestLoadRC_Neither(t *testing.T) {
	orig := sandbox.ConfigDir
	sandbox.ConfigDir = t.TempDir()
	defer func() { sandbox.ConfigDir = orig }()

	m, err := sandbox.LoadRC(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}
