// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

func isSubPath(base, path string) bool {
	rel, err := filepath.Rel(base, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// isProtected checks whether a path matches any entry in the protected set.
// Matches exact paths and sub-paths (e.g., /proc/sys/kernel matches /proc/sys).
func isProtected(path string, protected map[string]bool) bool {
	clean := filepath.Clean(path)

	if protected[clean] {
		return true
	}

	for p := range protected {
		if isSubPath(p, clean) {
			return true
		}
	}
	return false
}

// discoverProtectedPaths parses /proc/self/mountinfo to find all mount
// points under workdir that are read-only bind mounts or /dev/null mounts
// (masked paths). Also protects /proc/sys and /proc/1 unconditionally.
// Self-describing from the sidecar's own mount state -- no config passing.
func discoverProtectedPaths(workdir string) map[string]bool {
	return parseMountInfo("/proc/self/mountinfo", workdir)
}

// parseMountInfo reads a mountinfo file and returns mount points that
// should be protected from umount/remount. A mount is protected if:
//   - It is under the workdir and is read-only, OR
//   - It is under the workdir and its mount source is /dev/null, OR
//   - It is /proc/sys or /proc/1 (hardcoded)
func parseMountInfo(path, workdir string) map[string]bool {
	protected := make(map[string]bool)

	// /proc/sys is always protected -- prevents core_pattern and modprobe writes.
	protected["/proc/sys"] = true

	// /proc/1 is always protected -- prevents unmasking /proc/1/mem (which
	// has a /dev/null bind) and accessing supervisor memory/state.
	protected["/proc/1"] = true

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: parseMountInfo: %v\n", err)
		return protected
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mountpoint := fields[4]

		if mountpoint == "/proc/sys" {
			protected[mountpoint] = true
			continue
		}

		// Only workdir sub-mounts are interesting.
		if workdir == "" || !isSubPath(workdir, mountpoint) || mountpoint == workdir {
			continue
		}

		opts := fields[5]
		isRO := slices.Contains(strings.Split(opts, ","), "ro")

		// Find mount source -- it's after the " - " separator.
		isDevNull := false
		sepIdx := -1
		for i, f := range fields {
			if f == "-" {
				sepIdx = i
				break
			}
		}
		if sepIdx >= 0 && sepIdx+2 < len(fields) {
			source := fields[sepIdx+2]
			if source == "/dev/null" {
				isDevNull = true
			}
		}

		if isRO || isDevNull {
			protected[mountpoint] = true
		}
	}

	return protected
}

// maskSensitivePaths masks /proc and /sys files that aid kernel exploit
// development. Bind-mounts /dev/null over each path. Skips paths that
// don't exist on this kernel.
func maskSensitivePaths() {
	for _, p := range []string{
		"/proc/cmdline",
		"/proc/devices",
		"/proc/diskstats",
		"/proc/kallsyms",
		"/proc/kcore",
		"/proc/modules",
		"/proc/partitions",
		"/proc/sysrq-trigger",
		"/proc/version",
		"/sys/kernel/vmcoreinfo",
	} {
		_, err := os.Stat(p)
		if err != nil {
			continue
		}
		err = unix.Mount("/dev/null", p, "", unix.MS_BIND, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: mask %s: %v\n", p, err)
		}
	}
}
