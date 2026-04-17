// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/89luca89/clampdown/pkg/sandbox/mounts"
)

const (
	gitignoreMarkerStart = "# clampdown-start"
	gitignoreMarkerEnd   = "# clampdown-end"
)

// UpdateGitExclude updates .git/info/exclude in the workdir with patterns for
// clampdown-managed paths (protected + masked). Manages a marked section that
// is rewritten on each session start. Non-destructive: only touches the marked
// section, preserving user patterns.
func UpdateGitExclude(workdir string, extraProtect, extraMask []string) {
	// Skip if not a git repo.
	gitDir := filepath.Join(workdir, ".git")
	_, err := os.Stat(gitDir)
	if err != nil {
		return
	}

	path := filepath.Join(gitDir, "info", "exclude")

	// Collect all workdir-relative patterns.
	patterns := make(map[string]bool)

	// Universal protected paths (workdir-relative only).
	for _, p := range mounts.UniversalProtectedPaths {
		if !p.GlobalPath {
			patterns[p.Path] = true
		}
	}

	// User --protect paths.
	for _, raw := range extraProtect {
		patterns[strings.TrimSuffix(raw, "/")] = true
	}

	// Universal masked paths.
	for _, m := range mounts.UniversalMaskedPaths {
		patterns[m.Path] = true
	}

	// User --mask paths.
	for _, raw := range extraMask {
		patterns[strings.TrimSuffix(raw, "/")] = true
	}

	if len(patterns) == 0 {
		return
	}

	// Sort for deterministic output.
	var sorted []string
	for p := range patterns {
		sorted = append(sorted, p)
	}
	slices.Sort(sorted)

	// Ensure parent directory exists.
	dir := filepath.Dir(path)
	err = os.MkdirAll(dir, 0o750)
	if err != nil {
		return
	}

	// Read existing content.
	existing, _ := os.ReadFile(path)
	content := string(existing)

	// Build new section.
	var section strings.Builder
	section.WriteString(gitignoreMarkerStart)
	section.WriteString("\n")
	for _, p := range sorted {
		section.WriteString(p)
		section.WriteString("\n")
	}
	section.WriteString(gitignoreMarkerEnd)
	newSection := section.String()

	// Find and replace existing section, or append.
	startIdx := strings.Index(content, gitignoreMarkerStart)
	endIdx := strings.Index(content, gitignoreMarkerEnd)

	var updated string
	if startIdx >= 0 && endIdx > startIdx {
		// Replace existing section.
		endIdx += len(gitignoreMarkerEnd)
		// Skip trailing newline if present.
		if endIdx < len(content) && content[endIdx] == '\n' {
			endIdx++
		}
		updated = content[:startIdx] + newSection + "\n" + content[endIdx:]
	} else {
		// Append new section.
		if len(content) > 0 && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		updated = content + newSection + "\n"
	}

	// Write back only if changed.
	if updated != string(existing) {
		_ = os.WriteFile(path, []byte(updated), 0o644)
	}
}
