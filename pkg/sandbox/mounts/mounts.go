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
var UniversalProtectedPaths = []agent.ProtectedPath{
	{Path: ".clampdownrc", IsDir: false},
	{Path: ".devcontainer", IsDir: true},
	{Path: ".envrc", IsDir: false},
	{Path: ".git/config", IsDir: false},
	{Path: ".git/hooks", IsDir: true},
	{Path: ".gitmodules", IsDir: false},
	{Path: ".idea", IsDir: true},
	{Path: ".mcp.json", IsDir: false},
	{Path: ".vscode", IsDir: true},
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
func Build(
	workdir string, ag agent.Agent,
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
		abs := filepath.Join(workdir, p.Path)
		m, path, err := ProtectMount(abs, p.IsDir)
		if err != nil {
			return nil, created, fmt.Errorf("protect %s: %w", p.Path, err)
		}
		if m == nil {
			continue
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
