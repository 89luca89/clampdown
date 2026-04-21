// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// execEntry holds the immutable snapshot of one executable file taken at startup.
type execEntry struct {
	Hash [32]byte      // SHA-256 of file contents
	Dev  uint64        // stat device
	Ino  uint64        // stat inode
	Size int64         // stat size
	Mtim unix.Timespec // stat modification time (nsec precision)
}

// execAllowlist maps resolved absolute paths to their startup snapshots.
// Built once at startup. Read-only after construction.
type execAllowlist struct {
	entries map[string]execEntry
}

// check verifies an exec path against the allowlist.
//
// Fast path: stat the file, compare (dev, ino, size, mtime) against
// the stored snapshot. If all match, the binary hasn't changed.
//
// Slow path: on stat mismatch, re-hash and compare. Should never
// trigger on a read-only rootfs unless something is deeply wrong.
func (al *execAllowlist) check(path string) bool {
	entry, ok := al.entries[path]
	if !ok {
		return false
	}

	var st unix.Stat_t
	if unix.Stat(path, &st) != nil {
		return false
	}

	// Fast path: metadata match means content is unchanged.
	if st.Dev == entry.Dev &&
		st.Ino == entry.Ino &&
		st.Size == entry.Size &&
		st.Mtim.Sec == entry.Mtim.Sec &&
		st.Mtim.Nsec == entry.Mtim.Nsec {
		return true
	}

	// Slow path: metadata changed — re-hash to verify content.
	h, herr := hashFile(path)
	if herr != nil {
		return false
	}
	return h == entry.Hash
}

// buildExecAllowlist walks the rootfs and hashes every executable file.
// Must be called before the seccomp-notif filter is installed.
func buildExecAllowlist() (*execAllowlist, int) {
	var rootSt unix.Stat_t
	if unix.Stat("/", &rootSt) != nil {
		logf("WARNING: exec allowlist: cannot stat /")
		return &execAllowlist{entries: map[string]execEntry{}}, 0
	}

	entries, count := walkAndHash("/", rootSt.Dev)
	return &execAllowlist{entries: entries}, count
}

// walkAndHash walks a directory tree, hashing every executable file
// on the same device as rootDev. Directories on different devices
// (mount points) are skipped. Symlinks are resolved to canonical paths.
func walkAndHash(root string, rootDev uint64) (map[string]execEntry, int) {
	entries := make(map[string]execEntry)
	count := 0

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil //nolint:nilerr // skip unreadable entries, continue walk
		}

		// Skip directories on a different device (mount points).
		if d.IsDir() && path != root {
			var dirSt unix.Stat_t
			if unix.Stat(path, &dirSt) != nil || dirSt.Dev != rootDev {
				return fs.SkipDir
			}
			return nil
		}

		// Only hash regular files with any execute bit.
		if !d.Type().IsRegular() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil //nolint:nilerr // skip unreadable entries, continue walk
		}
		if info.Mode()&0o111 == 0 {
			return nil
		}

		// Resolve symlinks in parent components to get the canonical path.
		canonical, evalErr := filepath.EvalSymlinks(path)
		if evalErr != nil {
			return nil //nolint:nilerr // skip unresolvable entries, continue walk
		}

		// Skip if already hashed (multiple paths to same canonical file).
		_, exists := entries[canonical]
		if exists {
			return nil
		}

		// Verify the canonical path is on the rootfs device.
		var fileSt unix.Stat_t
		if unix.Stat(canonical, &fileSt) != nil || fileSt.Dev != rootDev {
			return nil //nolint:nilerr // skip cross-device files, continue walk
		}

		h, hashErr := hashFile(canonical)
		if hashErr != nil {
			logf("WARNING: exec allowlist: cannot hash %s: %v", canonical, hashErr)
			return nil
		}

		entries[canonical] = execEntry{
			Hash: h,
			Dev:  fileSt.Dev,
			Ino:  fileSt.Ino,
			Size: fileSt.Size,
			Mtim: fileSt.Mtim,
		}
		count++

		logf("exec allowlist: %s sha256=%s", canonical, hex.EncodeToString(h[:]))
		return nil
	})

	return entries, count
}

// hashFile returns the SHA-256 digest of a file's contents.
func hashFile(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil {
		return [32]byte{}, err
	}

	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func resolveViaProcRoot(path string, pid uint32) (string, error) {
	clean := filepath.Clean(path)
	root, err := os.Readlink(fmt.Sprintf("/proc/%d/root", pid))
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, clean))
	if err != nil {
		return "", err
	}
	if root != "/" && strings.HasPrefix(resolved, root) {
		return resolved[len(root):], nil
	}
	return resolved, nil
}

// resolveExecPath resolves a pathname for exec verification.
// Handles relative paths (via the caller's cwd) and evaluates symlinks.
func resolveExecPath(raw string, pid uint32) (string, error) {
	if raw == "" {
		return "", nil
	}

	path := raw
	if path[0] != '/' {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil {
			return "", err
		}
		path = filepath.Join(cwd, path)
	}

	return resolveViaProcRoot(path, pid)
}

// resolveExecveatPath resolves the path for an execveat() syscall.
//
//	execveat(dirfd, pathname, argv, envp, flags)
//	args[0]=dirfd, args[1]=pathname ptr, args[4]=flags
//
// Resolution rules:
//   - AT_EMPTY_PATH (0x1000): exec the fd itself.
//   - Absolute pathname: dirfd ignored.
//   - dirfd == AT_FDCWD: relative to cwd.
//   - Otherwise: relative to dirfd.
func resolveExecveatPath(pid uint32, dirfd, pathnameAddr, flags uint64) (string, error) {
	pathname, err := readStringFromPID(pid, pathnameAddr)
	if err != nil {
		return "", err
	}

	// AT_EMPTY_PATH: exec the fd directly.
	if flags&unix.AT_EMPTY_PATH != 0 {
		return evalFdLink(pid, dirfd)
	}

	// Absolute path: dirfd is irrelevant.
	if pathname != "" && pathname[0] == '/' {
		return resolveViaProcRoot(pathname, pid)
	}

	// Relative path: resolve base directory.
	var base string
	if int32(dirfd) == int32(unix.AT_FDCWD) {
		base, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	} else {
		base, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
	}
	if err != nil {
		return "", err
	}

	return resolveViaProcRoot(filepath.Join(base, pathname), pid)
}

// evalFdLink resolves /proc/<pid>/fd/<fd> to a canonical path.
func evalFdLink(pid uint32, fd uint64) (string, error) {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return "", err
	}
	return resolveViaProcRoot(target, pid)
}

// handleExecve handles execve(pathname, argv, envp) notifications.
//
//	args[0] = pathname pointer
//
// Policy: sidecar PID NS → hash-verified allowlist. Other → CONTINUE.
func handleExecve(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	allowlist *execAllowlist,
	myPIDNS string,
	notifFD int,
) {
	if !isSidecarPIDNS(pid, myPIDNS) {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	pathname, err := readStringFromPID(pid, notif.Data.Args[0])
	if err != nil {
		resp.Error = -syscallErrno(err)
		logf("BLOCKED execve: cannot read path pid=%d: %v", pid, err)
		return
	}

	resolved, err := resolveExecPath(pathname, pid)
	if err != nil {
		resp.Error = -syscallErrno(err)
		return
	}
	if resolved == "" {
		resp.Error = -int32(unix.ENOENT)
		return
	}

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if allowlist.check(resolved) {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	} else {
		resp.Error = -int32(unix.EACCES)
		logf("BLOCKED execve path=%s resolved=%s pid=%d bin=%s",
			pathname, resolved, pid, exePath(pid))
	}
}

// handleExecveat handles execveat(dirfd, pathname, argv, envp, flags).
//
//	args[0]=dirfd, args[1]=pathname ptr, args[4]=flags
//
// Policy: same as handleExecve but with dirfd resolution.
func handleExecveat(
	notif *seccompNotif,
	resp *seccompNotifResp,
	pid uint32,
	allowlist *execAllowlist,
	myPIDNS string,
	notifFD int,
) {
	if !isSidecarPIDNS(pid, myPIDNS) {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	resolved, err := resolveExecveatPath(pid, notif.Data.Args[0], notif.Data.Args[1], notif.Data.Args[4])
	if err != nil {
		resp.Error = -syscallErrno(err)
		logf("BLOCKED execveat: cannot read path pid=%d: %v", pid, err)
		return
	}
	if resolved == "" {
		resp.Error = -int32(unix.ENOENT)
		return
	}

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if allowlist.check(resolved) {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	} else {
		resp.Error = -int32(unix.EACCES)
		logf("BLOCKED execveat resolved=%s pid=%d dirfd=%d flags=0x%x bin=%s",
			resolved, pid, notif.Data.Args[0], notif.Data.Args[4], exePath(pid))
	}
}

// logExecAllowlist prints the allowlist summary at startup for the audit trail.
func logExecAllowlist(count int) {
	logf("exec allowlist: %d binaries hashed", count)
}
