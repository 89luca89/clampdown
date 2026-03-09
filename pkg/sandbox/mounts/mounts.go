// SPDX-License-Identifier: GPL-3.0-only

package mounts

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/89luca89/clampdown/pkg/agent"
	"github.com/89luca89/clampdown/pkg/container"
)

// UniversalProtectedPaths are paths that are always read-only in the agent
// container, regardless of which agent is running.
//
// Workdir-relative entries (GlobalPath: false, the default) cover project
// secrets, IDE config, and instruction files for all supported agents.
// HOME-relative entries (GlobalPath: true) cover the sandbox prompt files
// the launcher writes and agent-native global instruction files.
var UniversalProtectedPaths = []agent.ProtectedPath{
	// ---- workdir-relative ----
	{Path: ".clampdownrc",                    IsDir: false},
	{Path: ".claude/CLAUDE.md",               IsDir: false},
	{Path: ".claude/rules",                   IsDir: true},
	{Path: ".cursor/rules",                   IsDir: true},
	{Path: ".devcontainer",                   IsDir: true},
	{Path: ".env",                            IsDir: false},
	{Path: ".envrc",                          IsDir: false},
	{Path: ".git/config",                     IsDir: false},
	{Path: ".git/hooks",                      IsDir: true},
	{Path: ".github/copilot-instructions.md", IsDir: false},
	{Path: ".gitmodules",                     IsDir: false},
	{Path: ".idea",                           IsDir: true},
	{Path: ".mcp.json",                       IsDir: false},
	{Path: ".opencode/AGENTS.md",             IsDir: false},
	{Path: ".vscode",                         IsDir: true},
	{Path: ".windsurfrules",                  IsDir: false},
	{Path: "AGENTS.md",                       IsDir: false},
	{Path: "CLAUDE.local.md",                 IsDir: false},
	{Path: "CLAUDE.md",                       IsDir: false},
	// ---- HOME-relative ----
	// Sandbox prompts we write (must be RO so agent cannot alter its instructions).
	{Path: ".claude/CLAUDE-clampdown.md",  IsDir: false, GlobalPath: true},
	{Path: ".config/opencode/AGENTS.md",   IsDir: false, GlobalPath: true},
	// Agent-native global instruction files auto-discovered from HOME.
	{Path: ".claude/CLAUDE.md",            IsDir: false, GlobalPath: true},
	{Path: ".claude/rules",                IsDir: true,  GlobalPath: true},
}

// MergeProtection returns the universal protected paths, removing .git/hooks
// if allowHooks is set.
func MergeProtection(allowHooks bool) []agent.ProtectedPath {
	var out []agent.ProtectedPath
	for _, p := range UniversalProtectedPaths {
		if allowHooks && p.Path == ".git/hooks" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Build returns mount specs and a list of paths created on the host
// (for non-existing protected paths). The caller must clean up created paths.
// hostHome is the agent's persistent HOME directory on the host.
// containerHome is the path where hostHome is mounted inside the container.
// Both are used to resolve GlobalPath entries: Source comes from hostHome,
// Dest from containerHome (they differ because the agent's persistent cache
// dir is bind-mounted at the container-side $HOME, not at the same path).
func Build(
	workdir, hostHome, containerHome string, ag agent.Agent,
	protection []agent.ProtectedPath,
) ([]container.MountSpec, []string, error) {
	var mounts []container.MountSpec
	var created []string

	// Workdir bind mount.
	mounts = append(mounts, container.MountSpec{
		Source: workdir, Dest: workdir, Type: container.Bind,
	})

	// Protection mounts.
	for _, p := range protection {
		var abs string
		if p.GlobalPath {
			abs = filepath.Join(hostHome, p.Path)
		} else {
			abs = filepath.Join(workdir, p.Path)
		}
		m, path, err := ProtectMount(abs, p.IsDir)
		if err != nil {
			return nil, created, fmt.Errorf("protect %s: %w", p.Path, err)
		}
		if m == nil {
			continue
		}
		// GlobalPath entries: source is under hostHome but the container sees
		// the directory mounted at containerHome, so remap Dest accordingly.
		if p.GlobalPath {
			rel, _ := filepath.Rel(hostHome, m.Dest)
			m.Dest = filepath.Join(containerHome, rel)
		}
		mounts = append(mounts, *m)
		if path != "" {
			created = append(created, path)
		}
	}

	// Agent-specific mounts (skip if source doesn't exist).
	for _, m := range ag.Mounts() {
		_, err := os.Stat(m.Src)
		if err != nil {
			continue
		}
		mounts = append(mounts, container.MountSpec{
			Source: m.Src, Dest: m.Dst, RO: !m.RW, Type: container.Bind,
		})
	}

	// Host config overlays (read-only).
	for _, m := range ag.ConfigOverlays() {
		_, err := os.Stat(m.Src)
		if err != nil {
			continue
		}
		mounts = append(mounts, container.MountSpec{
			Source: m.Src, Dest: m.Dst, RO: true, Type: container.Bind,
		})
	}

	return mounts, created, nil
}

// ProtectMount returns a mount spec and optionally the path created on the
// host (empty string if the path already existed). Returns nil if the parent
// directory doesn't exist (nothing to protect, caller should skip).
func ProtectMount(abs string, isDir bool) (*container.MountSpec, string, error) {
	_, err := os.Stat(abs)
	if err == nil {
		return &container.MountSpec{
			Source: abs, Dest: abs, RO: true, Type: container.Bind,
		}, "", nil
	}

	// Parent doesn't exist — nothing to protect.
	_, statErr := os.Stat(filepath.Dir(abs))
	if statErr != nil {
		return nil, "", nil //nolint:nilerr // missing parent is not an error, just skip
	}

	if isDir {
		err = os.Mkdir(abs, 0o750)
		if err != nil {
			return nil, "", err
		}
		return &container.MountSpec{Dest: abs, Type: container.EmptyRO}, abs, nil
	}

	err = os.WriteFile(abs, nil, 0o600)
	if err != nil {
		return nil, "", err
	}
	return &container.MountSpec{Dest: abs, Type: container.DevNull}, abs, nil
}
