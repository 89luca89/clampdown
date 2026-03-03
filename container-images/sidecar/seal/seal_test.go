// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanEnv(t *testing.T) {
	t.Setenv("SANDBOX_POLICY", `{"read_only":["/"]}`)
	t.Setenv("OTHER_VAR", "keep")

	env := cleanEnv()

	for _, e := range env {
		if strings.HasPrefix(e, "SANDBOX_POLICY=") {
			t.Error("cleanEnv should strip SANDBOX_POLICY")
		}
	}

	found := false
	for _, e := range env {
		if strings.HasPrefix(e, "OTHER_VAR=") {
			found = true
		}
	}
	if !found {
		t.Error("cleanEnv should keep OTHER_VAR")
	}
}

func TestSplitPaths_DirsAndFiles(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "subdir")
	err := os.Mkdir(dir, 0o750)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(tmp, "file.txt")
	err = os.WriteFile(file, nil, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	dirs, files := splitPaths([]string{dir, file})

	if len(dirs) != 1 || dirs[0] != dir {
		t.Errorf("dirs = %v, want [%s]", dirs, dir)
	}
	if len(files) != 1 || files[0] != file {
		t.Errorf("files = %v, want [%s]", files, file)
	}
}

func TestSplitPaths_Missing(t *testing.T) {
	dirs, files := splitPaths([]string{"/nonexistent/path"})
	// Missing paths go to dirs (IgnoreIfMissing handles them).
	if len(dirs) != 1 {
		t.Errorf("dirs = %v, want 1 entry for missing path", dirs)
	}
	if len(files) != 0 {
		t.Errorf("files = %v, want empty", files)
	}
}

