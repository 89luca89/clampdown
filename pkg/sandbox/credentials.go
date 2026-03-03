// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/89luca89/clampdown/pkg/container"
)

// CredentialMounts resolves opt-in host credential forwarding and returns
// sidecar bind mounts at /run/credentials/*. seal-inject detects these
// by presence and propagates them into nested containers.
func CredentialMounts(opts Options) []container.MountSpec {
	home := os.Getenv("HOME")
	if home == "" {
		if opts.GitConfig || opts.GH || opts.SSH {
			slog.Warn("HOME not set, skipping credential forwarding")
		}
		return nil
	}

	var mounts []container.MountSpec

	if opts.GitConfig {
		src := filepath.Join(home, ".gitconfig")
		if fileExists(src) {
			mounts = append(mounts, container.MountSpec{
				Source: src,
				Dest:   "/run/credentials/gitconfig",
				RO:     true,
				Type:   container.Bind,
			})
		} else {
			slog.Warn("--gitconfig: ~/.gitconfig not found, skipping")
		}
	}

	if opts.GH {
		src := filepath.Join(home, ".config", "gh")
		if dirExists(src) {
			mounts = append(mounts, container.MountSpec{
				Source: src,
				Dest:   "/run/credentials/gh",
				RO:     true,
				Type:   container.Bind,
			})
		} else {
			slog.Warn("--gh: ~/.config/gh not found, skipping")
		}
	}

	if opts.SSH {
		sock := os.Getenv("SSH_AUTH_SOCK")
		switch {
		case sock == "":
			slog.Warn("--ssh: SSH_AUTH_SOCK not set, skipping")
		case !fileExists(sock):
			slog.Warn("--ssh: socket not found", "path", sock)
		default:
			mounts = append(mounts, container.MountSpec{
				Source: sock,
				Dest:   "/run/credentials/ssh-agent.sock",
				RO:     true,
				Type:   container.Bind,
			})
		}
	}

	return mounts
}

// fileExists uses Lstat intentionally: detects the path as-is without
// following symlinks. A symlink to a missing target would pass Stat but
// is a broken reference — Lstat catches it. Correct for files and sockets.
func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// dirExists uses Stat to verify the path both exists and resolves to a
// directory. Symlinks to directories are valid (e.g. ~/.config/gh → some
// XDG path), so following them here is intentional.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
