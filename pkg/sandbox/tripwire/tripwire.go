// SPDX-License-Identifier: GPL-3.0-only

package tripwire

import (
	"crypto/sha256"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"

	"github.com/89luca89/clampdown/pkg/container"
)

// Tripwire is the last line of defense for host filesystem integrity.
//
// The sandbox mounts sensitive paths (.git/hooks, .envrc, .mcp.json, etc.)
// read-only into containers.
//
// But if an attacker gains execution inside the sidecar (runtime CVE,
// kernel exploit) and umounts the RO overlays, or escapes to the host
// as uid 1000 (the file owner), those layers are bypassed. This tripwire
// runs on the host, outside all container namespaces, monitoring the real
// files via inotify. Any modification — write, create, delete, move —
// triggers immediate session termination. The attacker may breach the
// container, but they cannot silently tamper with host files.
//
// On Stop(), all watched paths are restored from in-memory snapshots
// taken before the session started. This undoes any tampering that
// occurred in the window between detection and session kill.
type Tripwire struct {
	fsw       *fsnotify.Watcher
	done      chan struct{}
	snapshots map[string]fileEntry // absolute path → snapshot
}

type fileEntry struct {
	Content []byte
	Hash    [sha256.Size]byte
	Mode    os.FileMode
	IsDir   bool
}

// ErrNoPathsToWatch is returned when no watchable paths exist.
var ErrNoPathsToWatch = errors.New("no paths to watch")

// HostPaths extracts the host-side paths from mount specs that are
// read-only. These are the paths the tripwire should monitor:
// bind mounts use Source, DevNull/EmptyRO use Dest (the real host file).
func HostPaths(mounts []container.MountSpec) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, m := range mounts {
		var hostPath string
		switch {
		case m.Type == container.Bind && m.RO:
			hostPath = m.Source
		case m.Type == container.DevNull || m.Type == container.EmptyRO:
			hostPath = m.Dest
		default:
			continue // writable bind mounts are the agent's workspace — not monitored
		}
		if hostPath == "" || seen[hostPath] {
			continue
		}
		seen[hostPath] = true
		paths = append(paths, hostPath)
	}
	return paths
}

// Start creates a tripwire that monitors the given host paths via inotify.
// Before watching, it snapshots all files (including directory contents)
// so they can be restored on Stop(). Any event calls onTamper with the
// affected path.
func Start(paths []string, onTamper func(path string)) (*Tripwire, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	tw := &Tripwire{
		fsw:       fsw,
		done:      make(chan struct{}),
		snapshots: make(map[string]fileEntry),
	}

	added := 0
	for _, abs := range paths {
		info, statErr := os.Lstat(abs)
		if statErr != nil {
			continue
		}

		if info.IsDir() {
			tw.snapshotDir(abs)
		} else {
			tw.snapshotFile(abs, info)
		}

		addErr := fsw.Add(abs)
		if addErr != nil {
			slog.Warn("tripwire: add failed", "path", abs, "error", addErr)
			continue
		}
		added++
	}

	if added == 0 {
		fsw.Close()
		return nil, ErrNoPathsToWatch
	}

	slog.Info("tripwire active", "paths", added, "snapshots", len(tw.snapshots))
	go tw.loop(onTamper)
	return tw, nil
}

// Stop closes the tripwire, stops the event loop, and restores all
// watched paths from their pre-session snapshots.
func (tw *Tripwire) Stop() {
	select {
	case <-tw.done:
		return
	default:
	}
	close(tw.done)
	tw.fsw.Close()
	tw.restore()
}

func (tw *Tripwire) snapshotFile(abs string, info fs.FileInfo) {
	content, err := os.ReadFile(abs)
	if err != nil {
		slog.Warn("tripwire: snapshot read failed", "path", abs, "error", err)
		return
	}
	tw.snapshots[abs] = fileEntry{
		Content: content,
		Hash:    sha256.Sum256(content),
		Mode:    info.Mode().Perm(),
	}
}

func (tw *Tripwire) snapshotDir(dir string) {
	tw.snapshots[dir] = fileEntry{IsDir: true, Mode: 0}

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fs.SkipDir
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return fs.SkipDir
		}
		if d.IsDir() {
			tw.snapshots[path] = fileEntry{
				IsDir: true,
				Mode:  info.Mode().Perm(),
			}
		} else if d.Type().IsRegular() {
			tw.snapshotFile(path, info)
		}
		return nil
	})
}

// restore compares current state against snapshots and fixes differences.
// Only writes files whose content changed, removes files that were not
// in the original snapshot, and recreates deleted entries.
func (tw *Tripwire) restore() {
	restored := 0

	// Pass 1: ensure all directories exist.
	for path, entry := range tw.snapshots {
		if !entry.IsDir {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			err = os.MkdirAll(path, entry.Mode)
			if err != nil {
				slog.Debug("tripwire: restore mkdir failed", "path", path, "error", err)
			}
			restored++
			continue
		}
		if info.Mode().Perm() != entry.Mode {
			_ = os.Chmod(path, entry.Mode)
			restored++
		}
	}

	// Pass 2: restore modified/missing files and remove unexpected entries.
	for path, entry := range tw.snapshots {
		if entry.IsDir {
			restored += tw.cleanDir(path)
			continue
		}
		current, err := os.ReadFile(path)
		if err != nil {
			// File deleted — restore it.
			err = os.WriteFile(path, entry.Content, entry.Mode)
			if err != nil {
				slog.Debug("tripwire: restore write failed", "path", path, "error", err)
			}
			restored++
			continue
		}
		if sha256.Sum256(current) != entry.Hash {
			// Content changed — restore it.
			err = os.WriteFile(path, entry.Content, entry.Mode)
			if err != nil {
				slog.Debug("tripwire: restore write failed", "path", path, "error", err)
			}
			restored++
		}
	}

	if restored > 0 {
		slog.Warn("tripwire: restored protected paths", "count", restored)
	}
}

// cleanDir removes files inside a watched directory that were not in
// the original snapshot. Returns the number of entries removed.
func (tw *Tripwire) cleanDir(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		abs := filepath.Join(dir, e.Name())
		_, known := tw.snapshots[abs]
		if !known {
			err = os.RemoveAll(abs)
			if err != nil {
				slog.Debug("tripwire: remove unexpected file", "path", abs, "error", err)
			}
			removed++
		}
	}
	return removed
}

func (tw *Tripwire) loop(onTamper func(string)) {
	for {
		select {
		case event, ok := <-tw.fsw.Events:
			if !ok {
				return
			}
			// Ignore Chmod — podman's SELinux relabeling (:z mount flag)
			// changes xattrs during container creation, causing false positives.
			if event.Op == fsnotify.Chmod {
				continue
			}
			onTamper(event.Name)
			return
		case watchErr, ok := <-tw.fsw.Errors:
			if !ok {
				return
			}
			slog.Warn("tripwire: inotify error", "error", watchErr)
		case <-tw.done:
			return
		}
	}
}
