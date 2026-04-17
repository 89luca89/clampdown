// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateGitExclude_NonGitRepo(t *testing.T) {
	dir := t.TempDir()

	UpdateGitExclude(dir, nil, nil)

	// Should not create .git/info/exclude in non-git repo.
	excludePath := filepath.Join(dir, ".git", "info", "exclude")
	if _, err := os.Stat(excludePath); err == nil {
		t.Error("should not create exclude file in non-git repo")
	}
}

func TestUpdateGitExclude_CreatesSection(t *testing.T) {
	dir := t.TempDir()

	// Create .git directory to simulate git repo.
	gitDir := filepath.Join(dir, ".git", "info")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	UpdateGitExclude(dir, nil, nil)

	excludePath := filepath.Join(gitDir, "exclude")
	content, err := os.ReadFile(excludePath)
	if err != nil {
		t.Fatalf("failed to read exclude: %v", err)
	}

	// Should include universal protected and masked paths.
	if !strings.Contains(string(content), "# clampdown-start") {
		t.Error("should have clampdown section")
	}
	if !strings.Contains(string(content), ".env") {
		t.Error("should include .env from universal masked paths")
	}
	if !strings.Contains(string(content), "CLAUDE.md") {
		t.Error("should include CLAUDE.md from universal protected paths")
	}
}

func TestUpdateGitExclude_PreservesUserPatterns(t *testing.T) {
	dir := t.TempDir()

	gitDir := filepath.Join(dir, ".git", "info")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write existing user patterns.
	excludePath := filepath.Join(gitDir, "exclude")
	existing := "# My patterns\n*.log\n*.tmp\n"
	if err := os.WriteFile(excludePath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	UpdateGitExclude(dir, nil, nil)

	content, err := os.ReadFile(excludePath)
	if err != nil {
		t.Fatalf("failed to read exclude: %v", err)
	}

	// User patterns should be preserved.
	if !strings.Contains(string(content), "# My patterns") {
		t.Error("user patterns should be preserved")
	}
	if !strings.Contains(string(content), "*.log") {
		t.Error("user patterns should be preserved")
	}
}

func TestUpdateGitExclude_ReplacesExistingSection(t *testing.T) {
	dir := t.TempDir()

	gitDir := filepath.Join(dir, ".git", "info")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write existing content with old clampdown section.
	excludePath := filepath.Join(gitDir, "exclude")
	existing := "# User stuff\n*.log\n# clampdown-start\n.old\n# clampdown-end\n# More user stuff\n*.bak\n"
	if err := os.WriteFile(excludePath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	UpdateGitExclude(dir, nil, nil)

	content, err := os.ReadFile(excludePath)
	if err != nil {
		t.Fatalf("failed to read exclude: %v", err)
	}

	// Old custom pattern should be gone.
	if strings.Contains(string(content), ".old") {
		t.Error(".old should be replaced")
	}

	// Universal patterns should be present.
	if !strings.Contains(string(content), ".env") {
		t.Error(".env should be present")
	}

	// User patterns should be preserved.
	if !strings.Contains(string(content), "# User stuff") {
		t.Error("user patterns before section should be preserved")
	}
	if !strings.Contains(string(content), "# More user stuff") {
		t.Error("user patterns after section should be preserved")
	}
}

func TestUpdateGitExclude_ExtraProtectPaths(t *testing.T) {
	dir := t.TempDir()

	gitDir := filepath.Join(dir, ".git", "info")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	UpdateGitExclude(dir, []string{"custom/protected.txt"}, nil)

	excludePath := filepath.Join(gitDir, "exclude")
	content, err := os.ReadFile(excludePath)
	if err != nil {
		t.Fatalf("failed to read exclude: %v", err)
	}

	if !strings.Contains(string(content), "custom/protected.txt") {
		t.Error("extra protect path should be included")
	}
}

func TestUpdateGitExclude_ExtraMaskPaths(t *testing.T) {
	dir := t.TempDir()

	gitDir := filepath.Join(dir, ".git", "info")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	UpdateGitExclude(dir, nil, []string{".secrets/"})

	excludePath := filepath.Join(gitDir, "exclude")
	content, err := os.ReadFile(excludePath)
	if err != nil {
		t.Fatalf("failed to read exclude: %v", err)
	}

	// Trailing slash should be trimmed.
	if !strings.Contains(string(content), ".secrets") {
		t.Error("extra mask path should be included")
	}
}

func TestUpdateGitExclude_Idempotent(t *testing.T) {
	dir := t.TempDir()

	gitDir := filepath.Join(dir, ".git", "info")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Run twice.
	UpdateGitExclude(dir, nil, nil)
	UpdateGitExclude(dir, nil, nil)

	excludePath := filepath.Join(gitDir, "exclude")
	content, err := os.ReadFile(excludePath)
	if err != nil {
		t.Fatalf("failed to read exclude: %v", err)
	}

	// Should only have one section.
	count := strings.Count(string(content), "# clampdown-start")
	if count != 1 {
		t.Errorf("expected 1 clampdown section, got %d", count)
	}
}

func TestUpdateGitExclude_Sorted(t *testing.T) {
	dir := t.TempDir()

	gitDir := filepath.Join(dir, ".git", "info")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	UpdateGitExclude(dir, nil, nil)

	excludePath := filepath.Join(gitDir, "exclude")
	content, err := os.ReadFile(excludePath)
	if err != nil {
		t.Fatalf("failed to read exclude: %v", err)
	}

	// Patterns should be sorted (.env before .envrc, both before AGENTS.md).
	envIdx := strings.Index(string(content), ".env\n")
	envrcIdx := strings.Index(string(content), ".envrc")
	agentsIdx := strings.Index(string(content), "AGENTS.md")
	if envIdx > envrcIdx || envrcIdx > agentsIdx {
		t.Error("patterns should be sorted alphabetically")
	}
}
