// SPDX-License-Identifier: GPL-3.0-only
/*
 * Cross-filesystem rename shim test suite.
 *
 * Expects /tmp to be a separate filesystem from cwd (tmpfs vs overlay/bind).
 * Run with LD_PRELOAD=<shim.so> — all cross-fs tests should pass.
 * Run without — cross-fs tests should fail with EXDEV.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int passed, failed;

static void ok(const char *name)
{
	printf("  PASS  %s\n", name);
	passed++;
}

static void fail(const char *name, const char *detail)
{
	printf("  FAIL  %s: %s\n", name, detail);
	failed++;
}

static void failf(const char *name, const char *fmt, int val)
{
	char buf[256];
	snprintf(buf, sizeof(buf), fmt, val);
	fail(name, buf);
}

static int write_file(const char *path, const char *data, mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (fd < 0)
		return -1;
	if (data[0])
		write(fd, data, strlen(data));
	close(fd);
	return 0;
}

static ssize_t read_file(const char *path, char *buf, size_t bufsz)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;
	if (fd < 0)
		return -1;
	n = read(fd, buf, bufsz - 1);
	close(fd);
	if (n >= 0)
		buf[n] = '\0';
	return n;
}

/* --- Tests --- */

static void test_cross_fs_rename(void)
{
	const char *name = "cross-fs rename()";
	char buf[64];

	write_file("/tmp/t_xfs", "cross-fs\n", 0644);
	if (rename("/tmp/t_xfs", "t_xfs_dst") < 0) {
		failf(name, "errno=%d", errno);
		unlink("/tmp/t_xfs");
		return;
	}
	if (read_file("t_xfs_dst", buf, sizeof(buf)) < 0 ||
	    strcmp(buf, "cross-fs\n") != 0)
		fail(name, "content mismatch");
	else
		ok(name);
	unlink("t_xfs_dst");
}

static void test_same_fs_rename(void)
{
	const char *name = "same-fs rename()";
	char buf[64];

	write_file("t_same_src", "same-fs\n", 0644);
	if (rename("t_same_src", "t_same_dst") < 0) {
		failf(name, "errno=%d", errno);
		unlink("t_same_src");
		return;
	}
	if (read_file("t_same_dst", buf, sizeof(buf)) < 0 ||
	    strcmp(buf, "same-fs\n") != 0)
		fail(name, "content mismatch");
	else
		ok(name);
	unlink("t_same_dst");
}

static void test_mode_preserved(void)
{
	const char *name = "mode preserved";
	struct stat st;

	write_file("/tmp/t_mode", "mode\n", 0751);
	if (rename("/tmp/t_mode", "t_mode_dst") < 0) {
		failf(name, "errno=%d", errno);
		unlink("/tmp/t_mode");
		return;
	}
	if (stat("t_mode_dst", &st) < 0)
		fail(name, "stat failed");
	else if ((st.st_mode & 0777) != 0751)
		failf(name, "mode=0%o, expected 0751", st.st_mode & 0777);
	else
		ok(name);
	unlink("t_mode_dst");
}

static void test_empty_file(void)
{
	const char *name = "empty file";
	struct stat st;

	write_file("/tmp/t_empty", "", 0644);
	if (rename("/tmp/t_empty", "t_empty_dst") < 0) {
		failf(name, "errno=%d", errno);
		unlink("/tmp/t_empty");
		return;
	}
	if (stat("t_empty_dst", &st) < 0 || st.st_size != 0)
		fail(name, "not empty");
	else
		ok(name);
	unlink("t_empty_dst");
}

static void test_large_file(void)
{
	const char *name = "large file (1 MiB)";
	struct stat st;
	char block[4096];
	int fd, i;

	fd = open("/tmp/t_large", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		fail(name, "create");
		return;
	}
	memset(block, 'A', sizeof(block));
	for (i = 0; i < 256; i++)
		write(fd, block, sizeof(block));
	close(fd);

	if (rename("/tmp/t_large", "t_large_dst") < 0) {
		failf(name, "errno=%d", errno);
		unlink("/tmp/t_large");
		return;
	}
	if (stat("t_large_dst", &st) < 0 || st.st_size != 256 * 4096)
		fail(name, "size mismatch");
	else
		ok(name);
	unlink("t_large_dst");
}

static void test_renameat_fdcwd(void)
{
	const char *name = "renameat(AT_FDCWD)";
	char buf[64];

	write_file("/tmp/t_at", "at_fdcwd\n", 0644);
	if (renameat(AT_FDCWD, "/tmp/t_at", AT_FDCWD, "t_at_dst") < 0) {
		failf(name, "errno=%d", errno);
		unlink("/tmp/t_at");
		return;
	}
	if (read_file("t_at_dst", buf, sizeof(buf)) < 0 ||
	    strcmp(buf, "at_fdcwd\n") != 0)
		fail(name, "content mismatch");
	else
		ok(name);
	unlink("t_at_dst");
}

static void test_renameat_dirfd(void)
{
	const char *name = "renameat(dirfd)";
	char buf[64];
	int tmpfd, cwdfd;

	write_file("/tmp/t_dirfd", "dirfd\n", 0644);

	tmpfd = open("/tmp", O_RDONLY | O_DIRECTORY);
	cwdfd = open(".", O_RDONLY | O_DIRECTORY);
	if (tmpfd < 0 || cwdfd < 0) {
		fail(name, "open dirfd");
		unlink("/tmp/t_dirfd");
		if (tmpfd >= 0) close(tmpfd);
		if (cwdfd >= 0) close(cwdfd);
		return;
	}

	if (renameat(tmpfd, "t_dirfd", cwdfd, "t_dirfd_dst") < 0) {
		failf(name, "errno=%d", errno);
		unlink("/tmp/t_dirfd");
	} else if (read_file("t_dirfd_dst", buf, sizeof(buf)) < 0 ||
		   strcmp(buf, "dirfd\n") != 0) {
		fail(name, "content mismatch");
	} else {
		ok(name);
	}
	close(tmpfd);
	close(cwdfd);
	unlink("t_dirfd_dst");
}

static void test_src_missing(void)
{
	const char *name = "missing src -> ENOENT";

	if (rename("/tmp/t_nonexistent", "whatever") == 0) {
		fail(name, "should have failed");
		unlink("whatever");
		return;
	}
	if (errno == ENOENT)
		ok(name);
	else
		failf(name, "errno=%d, expected ENOENT", errno);
}

static void test_src_unlinked(void)
{
	const char *name = "src unlinked after rename";
	struct stat st;

	write_file("/tmp/t_unlink", "unlink\n", 0644);
	if (rename("/tmp/t_unlink", "t_unlink_dst") < 0) {
		failf(name, "errno=%d", errno);
		unlink("/tmp/t_unlink");
		return;
	}
	if (stat("/tmp/t_unlink", &st) == 0)
		fail(name, "src still exists");
	else if (errno == ENOENT)
		ok(name);
	else
		failf(name, "stat errno=%d", errno);
	unlink("t_unlink_dst");
}

static void test_overwrite_dst(void)
{
	const char *name = "overwrite existing dst";
	char buf[64];

	write_file("t_over_dst", "old\n", 0644);
	write_file("/tmp/t_over_src", "new\n", 0644);
	if (rename("/tmp/t_over_src", "t_over_dst") < 0) {
		failf(name, "errno=%d", errno);
		unlink("/tmp/t_over_src");
		unlink("t_over_dst");
		return;
	}
	if (read_file("t_over_dst", buf, sizeof(buf)) < 0 ||
	    strcmp(buf, "new\n") != 0)
		fail(name, "content mismatch");
	else
		ok(name);
	unlink("t_over_dst");
}

int main(void)
{
	const char *preload = getenv("LD_PRELOAD");

	printf("rename shim tests (LD_PRELOAD=%s)\n\n",
	       preload ? preload : "(none)");

	test_cross_fs_rename();
	test_same_fs_rename();
	test_mode_preserved();
	test_empty_file();
	test_large_file();
	test_renameat_fdcwd();
	test_renameat_dirfd();
	test_src_missing();
	test_src_unlinked();
	test_overwrite_dst();

	printf("\n%d passed, %d failed\n", passed, failed);
	return failed ? 1 : 0;
}
