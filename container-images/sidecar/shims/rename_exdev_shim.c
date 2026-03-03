// SPDX-License-Identifier: GPL-3.0-only
/*
 * LD_PRELOAD shim: transparent EXDEV fallback for rename operations.
 *
 * Overlayfs returns EXDEV (errno 18) when rename() crosses filesystem
 * boundaries — common in nested containers where /tmp, $HOME, and the
 * workdir live on different mounts.  This breaks cargo, rustc, pip, and
 * other tools that expect same-filesystem renames to work.
 *
 * Intercepts rename/renameat/renameat2.  On EXDEV, falls back to
 * copy + unlink.  Uses direct syscalls internally to avoid
 * self-interposition (no dlsym/RTLD_NEXT, no -ldl dependency).
 *
 * Limitations vs kernel rename (inherent to copy+unlink):
 *   - Not atomic: window where both src and dst exist.
 *   - New inode: existing fds to src still reference the old inode.
 *   - Directories and symlinks are not supported (returns EXDEV as-is).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* Direct SYS_renameat2 — bypasses our interposed rename symbols. */
static long kern_renameat2(int olddirfd, const char *oldpath, int newdirfd,
			   const char *newpath, unsigned int flags)
{
	return syscall(SYS_renameat2, olddirfd, oldpath, newdirfd, newpath,
		       flags);
}

/* Direct SYS_newfstatat — bypasses fstat/lstat libc wrappers.
 * glibc < 2.33 doesn't export fstat/lstat as symbols (they expand
 * to __fxstat/__lxstat macros).  SYS_newfstatat works on both
 * x86_64 (262) and aarch64 (79). */
static int kern_fstat(int fd, struct stat *st)
{
	return syscall(SYS_newfstatat, fd, "", st, AT_EMPTY_PATH);
}

static int kern_lstat(const char *path, struct stat *st)
{
	return syscall(SYS_newfstatat, AT_FDCWD, path, st,
		       AT_SYMLINK_NOFOLLOW);
}

/* Compatibility with pre-5.10 kernel */
#define SENDFILE_MAX ((size_t)0x7ffff000)
static int copy_data(int dstfd, int srcfd, off_t size)
{
	off_t off = 0;

	while (off < size) {
		size_t chunk = (size_t)(size - off);
		ssize_t sent;

		if (chunk > SENDFILE_MAX)
			chunk = SENDFILE_MAX;

		sent = sendfile(dstfd, srcfd, &off, chunk);
		if (sent < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (sent == 0) {
			errno = EIO;
			return -1;
		}
	}
	return 0;
}

/* Copy a regular file to a temp path next to dst, restore metadata,
 * fsync, then atomic same-fs rename into place.  O_NOFOLLOW on src
 * rejects symlinks; fstat after open avoids the stat/open TOCTOU. */
static int copy_reg_and_unlink(const char *src, const char *dst)
{
	struct stat st;
	struct timespec times[2];
	int srcfd = -1, dstfd = -1, err = 0;
	char tmppath[PATH_MAX];
	int n;

	srcfd = open(src, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (srcfd < 0)
		return -1;

	if (kern_fstat(srcfd, &st) < 0) {
		err = errno;
		goto fail_src;
	}
	if (!S_ISREG(st.st_mode)) {
		err = EXDEV;
		goto fail_src;
	}

	n = snprintf(tmppath, sizeof(tmppath), "%s.exdev.%d", dst,
		     (int)getpid());
	if (n < 0 || (size_t)n >= sizeof(tmppath)) {
		err = ENAMETOOLONG;
		goto fail_src;
	}

	/* Create with 0600; fchmod below sets the real mode, defeating umask. */
	dstfd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (dstfd < 0) {
		err = errno;
		goto fail_src;
	}

	if (copy_data(dstfd, srcfd, st.st_size) < 0) {
		err = errno;
		goto fail_both;
	}

	/* fchmod is critical (umask).  fchown/futimens are best-effort —
	 * they fail in unprivileged containers. */
	if (fchmod(dstfd, st.st_mode) < 0) {
		err = errno;
		goto fail_both;
	}
	(void)fchown(dstfd, st.st_uid, st.st_gid);

	times[0] = st.st_atim;
	times[1] = st.st_mtim;
	(void)futimens(dstfd, times);

	if (fsync(dstfd) < 0) {
		err = errno;
		goto fail_both;
	}

	/* close() catches deferred write errors (NFS, etc). */
	if (close(dstfd) < 0) {
		err = errno;
		dstfd = -1;
		goto fail_tmp;
	}
	dstfd = -1;
	close(srcfd);
	srcfd = -1;

	/* Same-fs rename into place.  Uses kern_renameat2 to avoid
	 * recursion through our interposed rename(). */
	if (kern_renameat2(AT_FDCWD, tmppath, AT_FDCWD, dst, 0) < 0) {
		err = errno;
		goto fail_tmp;
	}

	unlink(src);
	return 0;

fail_both:
	close(dstfd);
fail_tmp:
	unlink(tmppath);
fail_src:
	if (srcfd >= 0)
		close(srcfd);
	errno = err;
	return -1;
}

/* Turn a dirfd + relative path into an absolute path via
 * /proc/self/fd/N readlink.  Returns path as-is when already
 * absolute or dirfd == AT_FDCWD.  NULL on failure. */
static const char *resolve_dirfd(int dirfd, const char *path, char *buf,
				 size_t bufsz)
{
	char fdlink[64];
	ssize_t dirlen;
	size_t pathlen;
	int n;

	if (dirfd == AT_FDCWD || path[0] == '/')
		return path;

	n = snprintf(fdlink, sizeof(fdlink), "/proc/self/fd/%d", dirfd);
	if (n < 0 || (size_t)n >= sizeof(fdlink))
		return NULL;

	dirlen = readlink(fdlink, buf, bufsz - 1);
	if (dirlen < 0)
		return NULL;

	pathlen = strlen(path);
	if ((size_t)dirlen + 1 + pathlen >= bufsz)
		return NULL;

	buf[dirlen] = '/';
	memcpy(buf + dirlen + 1, path, pathlen + 1);
	return buf;
}

/* Resolve dirfd paths, lstat to classify file type, dispatch to the
 * right copy helper.  Only regular files are supported; everything
 * else gets EXDEV back so callers see the original error. */
static int exdev_fallback(int olddirfd, const char *oldpath, int newdirfd,
			  const char *newpath)
{
	char oldabs[PATH_MAX], newabs[PATH_MAX];
	const char *src, *dst;
	struct stat st;

	src = resolve_dirfd(olddirfd, oldpath, oldabs, sizeof(oldabs));
	dst = resolve_dirfd(newdirfd, newpath, newabs, sizeof(newabs));
	if (!src || !dst) {
		errno = EXDEV;
		return -1;
	}

	if (kern_lstat(src, &st) < 0)
		return -1;

	if (S_ISREG(st.st_mode))
		return copy_reg_and_unlink(src, dst);

	errno = EXDEV;
	return -1;
}

/* --- Interposed libc symbols ---
 *
 * Try the real syscall first.  On EXDEV, fall back to copy + unlink.
 * Forward-declare renameat2 (glibc >= 2.28 has it, musl does not). */

int renameat2(int olddirfd, const char *oldpath, int newdirfd,
	      const char *newpath, unsigned int flags);

int rename(const char *oldpath, const char *newpath)
{
	if (kern_renameat2(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0) == 0)
		return 0;
	if (errno == EXDEV)
		return exdev_fallback(AT_FDCWD, oldpath, AT_FDCWD, newpath);
	return -1;
}

int renameat(int olddirfd, const char *oldpath, int newdirfd,
	     const char *newpath)
{
	if (kern_renameat2(olddirfd, oldpath, newdirfd, newpath, 0) == 0)
		return 0;
	if (errno == EXDEV)
		return exdev_fallback(olddirfd, oldpath, newdirfd, newpath);
	return -1;
}

/* RENAME_EXCHANGE / RENAME_NOREPLACE can't be emulated with
 * copy+unlink, so only plain renames (flags == 0) get the fallback. */
int renameat2(int olddirfd, const char *oldpath, int newdirfd,
	      const char *newpath, unsigned int flags)
{
	if (kern_renameat2(olddirfd, oldpath, newdirfd, newpath, flags) == 0)
		return 0;
	if (errno == EXDEV && flags == 0)
		return exdev_fallback(olddirfd, oldpath, newdirfd, newpath);
	return -1;
}
