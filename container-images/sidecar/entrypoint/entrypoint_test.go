// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBuildNotifFilter(t *testing.T) {
	syscalls := interceptedSyscalls
	filter := buildNotifFilter(auditArch, syscalls)

	// 4 preamble (load arch, check, kill, load NR) + len(syscalls) checks + 2 returns (ALLOW, USER_NOTIF)
	expectedLen := 4 + len(syscalls) + 2
	if len(filter) != expectedLen {
		t.Fatalf("expected %d instructions, got %d", expectedLen, len(filter))
	}

	// Verify arch check is first.
	if filter[0].K != dataOffArch {
		t.Errorf("instruction 0: expected load arch offset %d, got %d", dataOffArch, filter[0].K)
	}

	// Verify arch constant.
	if filter[1].K != auditArch {
		t.Errorf("instruction 1: expected arch %#x, got %#x", auditArch, filter[1].K)
	}

	// Verify KILL_PROCESS on arch mismatch.
	if filter[2].K != unix.SECCOMP_RET_KILL_PROCESS {
		t.Errorf("instruction 2: expected KILL_PROCESS %#x, got %#x", unix.SECCOMP_RET_KILL_PROCESS, filter[2].K)
	}

	// Verify all intercepted syscall numbers are present.
	found := make(map[uint32]bool)
	for i := 4; i < 4+len(syscalls); i++ {
		found[filter[i].K] = true
	}
	for _, nr := range syscalls {
		if !found[nr] {
			t.Errorf("syscall nr=%d not in filter", nr)
		}
	}

	// Verify ALLOW and USER_NOTIF returns.
	allowIdx := 4 + len(syscalls)
	notifIdx := allowIdx + 1
	if filter[allowIdx].K != unix.SECCOMP_RET_ALLOW {
		t.Errorf("instruction %d: expected ALLOW %#x, got %#x", allowIdx, unix.SECCOMP_RET_ALLOW, filter[allowIdx].K)
	}
	if filter[notifIdx].K != unix.SECCOMP_RET_USER_NOTIF {
		t.Errorf(
			"instruction %d: expected USER_NOTIF %#x, got %#x",
			notifIdx,
			unix.SECCOMP_RET_USER_NOTIF,
			filter[notifIdx].K,
		)
	}

	// Verify all jumps target USER_NOTIF.
	for i := 4; i < 4+len(syscalls); i++ {
		expectedJt := uint8(notifIdx - i - 1)
		if filter[i].Jt != expectedJt {
			t.Errorf("instruction %d: expected Jt=%d (-> USER_NOTIF), got %d", i, expectedJt, filter[i].Jt)
		}
		if filter[i].Jf != 0 {
			t.Errorf("instruction %d: expected Jf=0 (fall through), got %d", i, filter[i].Jf)
		}
	}
}

func TestSerializeFilter(t *testing.T) {
	filter := buildNotifFilter(auditArch, interceptedSyscalls)
	buf := serializeFilter(filter)
	if len(buf) != len(filter)*8 {
		t.Fatalf("expected %d bytes, got %d", len(filter)*8, len(buf))
	}
}

func TestParseMountInfo_Empty(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mountinfo")
	err := os.WriteFile(f, []byte(""), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	got := parseMountInfo(f, "/workdir")
	if !got["/proc/sys"] {
		t.Error("expected /proc/sys to be protected")
	}
	if !got["/proc/1"] {
		t.Error("expected /proc/1 to be protected")
	}
	if len(got) != 2 {
		t.Errorf("expected 2 protected paths, got %d", len(got))
	}
}

func TestParseMountInfo_ROBindUnderWorkdir(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mountinfo")
	content := `25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
100 25 8:1 /workdir/.env /workdir/.env ro,relatime - ext4 /dev/sda1 rw
101 25 8:1 /workdir/.git/hooks /workdir/.git/hooks ro,relatime - ext4 /dev/sda1 rw
102 25 0:5 / /workdir/.npmrc ro,relatime - devtmpfs /dev/null rw
103 25 8:1 /workdir /workdir rw,relatime - ext4 /dev/sda1 rw
`
	err := os.WriteFile(f, []byte(content), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	got := parseMountInfo(f, "/workdir")

	expected := map[string]bool{
		"/proc/sys":           true,
		"/workdir/.env":       true,
		"/workdir/.git/hooks": true,
		"/workdir/.npmrc":     true,
	}
	for path := range expected {
		if !got[path] {
			t.Errorf("expected %s to be protected", path)
		}
	}

	if got["/workdir"] {
		t.Error("/workdir should not be protected (it is the workdir itself)")
	}
}

func TestParseMountInfo_DevNullMount(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mountinfo")
	content := `25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
200 25 0:6 / /workdir/.envrc rw,relatime - devtmpfs /dev/null rw
`
	err := os.WriteFile(f, []byte(content), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	got := parseMountInfo(f, "/workdir")
	if !got["/workdir/.envrc"] {
		t.Error("expected /workdir/.envrc to be protected (devnull mount)")
	}
}

func TestParseMountInfo_RWNotProtected(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mountinfo")
	content := `25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
300 25 8:1 /workdir/src /workdir/src rw,relatime - ext4 /dev/sda1 rw
`
	err := os.WriteFile(f, []byte(content), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	got := parseMountInfo(f, "/workdir")
	if got["/workdir/src"] {
		t.Error("/workdir/src should not be protected (RW, not devnull)")
	}
}

func TestParseMountInfo_MissingFile(t *testing.T) {
	got := parseMountInfo("/nonexistent/mountinfo", "/workdir")
	if !got["/proc/sys"] {
		t.Error("expected /proc/sys even when file missing")
	}
	if len(got) != 2 {
		t.Errorf("expected 2 protected paths on error, got %d", len(got))
	}
}

func TestParseMountInfo_Proc1AlwaysProtected(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mountinfo")
	err := os.WriteFile(f, []byte(""), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	got := parseMountInfo(f, "/workdir")
	if !got["/proc/1"] {
		t.Error("expected /proc/1 to be protected")
	}
	// Verify sub-paths are also protected via isProtected.
	if !isProtected("/proc/1/mem", got) {
		t.Error("expected /proc/1/mem to be protected (sub-path of /proc/1)")
	}
	if !isProtected("/proc/1/maps", got) {
		t.Error("expected /proc/1/maps to be protected")
	}
}

func TestParseMountInfo_ProcSysAlwaysProtected(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mountinfo")
	content := `25 1 0:1 / /proc/sys ro,relatime - proc proc rw
`
	err := os.WriteFile(f, []byte(content), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	got := parseMountInfo(f, "/workdir")
	if !got["/proc/sys"] {
		t.Error("expected /proc/sys to be protected")
	}
}

func TestIsProtected(t *testing.T) {
	protected := map[string]bool{
		"/proc/sys":           true,
		"/workdir/.env":       true,
		"/workdir/.git/hooks": true,
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/proc/sys", true},
		{"/proc/sys/kernel/core_pattern", true},
		{"/proc/sys/net", true},
		{"/workdir/.env", true},
		{"/workdir/.git/hooks", true},
		{"/workdir/.git/hooks/pre-commit", true},
		{"/workdir/src", false},
		{"/tmp/foo", false},
		{"/proc/sys/../sys/kernel", true},
		{".", false},
	}
	for _, tt := range tests {
		got := isProtected(tt.path, protected)
		if got != tt.want {
			t.Errorf("isProtected(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsSubPath(t *testing.T) {
	tests := []struct {
		base, path string
		want       bool
	}{
		{"/a", "/a", true},
		{"/a", "/a/b", true},
		{"/a", "/a/b/c", true},
		{"/a", "/b", false},
		{"/a", "/ab", false},
		{"/a/b", "/a", false},
		{"/a", "/", false},
		{"/", "/a", true},
	}
	for _, tt := range tests {
		got := isSubPath(tt.base, tt.path)
		if got != tt.want {
			t.Errorf("isSubPath(%q, %q) = %v, want %v", tt.base, tt.path, got, tt.want)
		}
	}
}

func TestResolvePath_Absolute(t *testing.T) {
	pid := uint32(os.Getpid())
	got := resolvePath("/usr/bin", pid)
	if got != "/usr/bin" {
		t.Errorf("resolvePath(/usr/bin) = %q, want /usr/bin", got)
	}
}

func TestResolvePath_Empty(t *testing.T) {
	got := resolvePath("", uint32(os.Getpid()))
	if got != "" {
		t.Errorf("resolvePath(\"\") = %q, want \"\"", got)
	}
}

func TestResolvePath_Symlink(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	pid := uint32(os.Getpid())
	got := resolvePath(link, pid)
	if got != target {
		t.Errorf("resolvePath(%q) = %q, want %q (resolved symlink)", link, got, target)
	}
}

func TestResolvePath_NonexistentFallback(t *testing.T) {
	pid := uint32(os.Getpid())
	got := resolvePath("/nonexistent/path", pid)
	if got != "/nonexistent/path" {
		t.Errorf("resolvePath(/nonexistent/path) = %q, want /nonexistent/path (fallback)", got)
	}
}

// ---------------------------------------------------------------------------
// Exec allowlist tests
// ---------------------------------------------------------------------------

func TestHashFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test")
	content := []byte("hello world\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(content)
	if got != want {
		t.Errorf("hash mismatch: got %x, want %x", got, want)
	}
}

func TestHashFile_Missing(t *testing.T) {
	_, err := hashFile("/nonexistent/file")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestWalkAndHash_Discovery(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "mybin"), []byte("#!/bin/sh\necho hi"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "data.txt"), []byte("just data"), 0o644); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(tmp, "sub")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "tool"), []byte("#!/bin/sh\ntool"), 0o755); err != nil {
		t.Fatal(err)
	}

	var rootSt unix.Stat_t
	if err := unix.Stat(tmp, &rootSt); err != nil {
		t.Fatal(err)
	}
	entries, count := walkAndHash(tmp, rootSt.Dev)
	if count != 2 {
		t.Errorf("expected 2 executables, got %d", count)
	}
	if _, ok := entries[filepath.Join(tmp, "mybin")]; !ok {
		t.Error("expected mybin in allowlist")
	}
	if _, ok := entries[filepath.Join(subDir, "tool")]; !ok {
		t.Error("expected sub/tool in allowlist")
	}
	if _, ok := entries[filepath.Join(tmp, "data.txt")]; ok {
		t.Error("non-executable data.txt should not be in allowlist")
	}
}

func TestWalkAndHash_ResolvesSymlinks(t *testing.T) {
	tmp := t.TempDir()
	realBin := filepath.Join(tmp, "real-bin")
	if err := os.WriteFile(realBin, []byte("binary content"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realBin, filepath.Join(tmp, "link-bin")); err != nil {
		t.Fatal(err)
	}

	var rootSt unix.Stat_t
	if err := unix.Stat(tmp, &rootSt); err != nil {
		t.Fatal(err)
	}
	entries, count := walkAndHash(tmp, rootSt.Dev)
	if count != 1 {
		t.Errorf("expected 1 unique executable (resolved), got %d", count)
	}
	if _, ok := entries[realBin]; !ok {
		t.Error("expected real binary path in allowlist")
	}
}

func TestExecAllowlistCheck_FastPath(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bin")
	content := []byte("fast-path binary")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	al := &execAllowlist{entries: map[string]execEntry{
		path: {Hash: sha256.Sum256(content), Dev: st.Dev, Ino: st.Ino, Size: st.Size, Mtim: st.Mtim},
	}}
	if !al.check(path) {
		t.Error("expected allowlist check to pass (fast path)")
	}
}

func TestExecAllowlistCheck_SlowPath(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bin")
	content := []byte("slow-path binary")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	al := &execAllowlist{entries: map[string]execEntry{
		path: {Hash: sha256.Sum256(content), Size: int64(len(content))},
	}}
	if !al.check(path) {
		t.Error("expected allowlist check to pass (slow path, same hash)")
	}
}

func TestExecAllowlistCheck_Modified(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bin")
	if err := os.WriteFile(path, []byte("original"), 0o755); err != nil {
		t.Fatal(err)
	}
	al := &execAllowlist{entries: map[string]execEntry{
		path: {Hash: sha256.Sum256([]byte("original"))},
	}}
	if err := os.WriteFile(path, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if al.check(path) {
		t.Error("expected allowlist check to fail (content modified)")
	}
}

func TestExecAllowlistCheck_Missing(t *testing.T) {
	al := &execAllowlist{entries: map[string]execEntry{
		"/nonexistent": {Hash: [32]byte{1}},
	}}
	if al.check("/nonexistent") {
		t.Error("expected check to fail for missing file")
	}
}

func TestExecAllowlistCheck_NotInList(t *testing.T) {
	al := &execAllowlist{entries: map[string]execEntry{}}
	if al.check("/usr/bin/something") {
		t.Error("expected check to fail for path not in allowlist")
	}
}

func TestResolveExecPath_Absolute(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "mybin")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolveExecPath(bin, uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("resolveExecPath(%q) error: %v", bin, err)
	}
	if got != bin {
		t.Errorf("resolveExecPath(%q) = %q, want %q", bin, got, bin)
	}
}

func TestResolveExecPath_Empty(t *testing.T) {
	got, err := resolveExecPath("", uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("resolveExecPath(\"\") error: %v", err)
	}
	if got != "" {
		t.Errorf("resolveExecPath(\"\") = %q, want \"\"", got)
	}
}

func TestReadPPID(t *testing.T) {
	ppid := readPPID(uint32(os.Getpid()))
	if ppid == 0 {
		t.Error("expected non-zero parent PID for current process")
	}
	// Our parent should exist.
	if exePath(ppid) == "" {
		t.Error("expected parent to have a valid exe path")
	}
}

func TestReadPPID_Missing(t *testing.T) {
	ppid := readPPID(99999999)
	if ppid != 0 {
		t.Errorf("expected 0 for nonexistent PID, got %d", ppid)
	}
}

// ---------------------------------------------------------------------------
// Filesystem type allowlist tests
// ---------------------------------------------------------------------------

func TestAllowedFsTypes(t *testing.T) {
	tests := []struct {
		fstype string
		want   bool
	}{
		// Legitimate crun types.
		{"cgroup2", true},
		{"devpts", true},
		{"mqueue", true},
		{"overlay", true},
		{"sysfs", true},
		{"tmpfs", true},

		// Propagation changes (mount --make-rshared).
		{"none", true},

		// proc intentionally blocked (exposes /proc/1/mem).
		{"proc", false},

		// not used types that must be blocked to avoid host disk/device
		// remounts to get info escaping.
		{"btrfs", false},
		{"devtmpfs", false},
		{"ext4", false},
		{"fuse", false},
		{"nfs", false},
		{"xfs", false},

		// Empty fstype (bind/remount) — not checked via allowlist,
		// but verify the map returns false for it.
		{"", false},
	}
	for _, tt := range tests {
		got := allowedFsTypes[tt.fstype]
		if got != tt.want {
			t.Errorf("allowedFsTypes[%q] = %v, want %v", tt.fstype, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// procSensitive coverage
// ---------------------------------------------------------------------------

func TestProcSensitive_HostKernelControlFiles(t *testing.T) {
	// Each path must appear in procSensitive so handleOpenat blocks
	// writes to it from any context. CVE-2025-52881 is the canonical
	// reproducer for this class of bug.
	hostKernel := []string{
		"/proc/sysrq-trigger",
		"/proc/sys/kernel/core_pattern",
		"/proc/sys/kernel/core_uses_pid",
		"/proc/sys/kernel/hotplug",
		"/proc/sys/kernel/modprobe",
		"/proc/sys/kernel/sysrq",
		"/proc/sys/kernel/unprivileged_userns_clone",
		"/proc/sys/fs/binfmt_misc/register",
		"/proc/sys/vm/drop_caches",
		"/proc/sys/vm/panic_on_oom",
		"/proc/sys/net/core/bpf_jit_enable",
		"/proc/sys/net/core/bpf_jit_harden",
		"/proc/sys/net/core/bpf_jit_kallsyms",
	}
	for _, path := range hostKernel {
		if !slices.Contains(procSensitive, path) {
			t.Errorf("procSensitive missing host-kernel control file: %q", path)
		}
	}
}

// ---------------------------------------------------------------------------
// Bind mount source allowlist tests
// ---------------------------------------------------------------------------

func TestIsAllowedBindSource(t *testing.T) {
	workdir := "/home/user/project"
	tests := []struct {
		source string
		want   bool
	}{
		// Workdir and children.
		{"/home/user/project", true},
		{"/home/user/project/src", true},
		{"/home/user/project/.git/hooks", true},

		// Infrastructure storage.
		{"/var/lib/containers/storage/overlay/abc/merged", true},
		{"/var/run/containers/storage/abc", true},
		{"/var/cache/containers/blob-cache/sha256/abc", true},
		{"/run/containers/storage/abc", true},
		{"/run/credentials/gh", true},

		// Device files.
		{"/dev/null", true},
		{"/dev/zero", true},
		{"/dev/shm/foo", false},

		// Temp dirs.
		{"/tmp/buildah123", false},
		{"/var/tmp/foo", true},           // allowed for buildah staging

		// Special rootfs files.
		{"/sandbox-seal", true},
		{"/rename_exdev_shim.so", true},
		{"/empty", true},

		// Empty source (remount).
		{"", true},

		// ATTACK: rootfs paths that must be blocked.
		{"/", false},
		{"/etc", false},
		{"/etc/containers", false},
		{"/etc/containers/containers.conf", false},
		{"/usr", false},
		{"/usr/share/containers/hooks.d", false},
		{"/usr/libexec/oci/hooks.d/security-policy", false},
		{"/bin", false},
		{"/home/user", false}, // parent of workdir, not under it
		{"/proc", false},
		{"/sys", false},
		{"/opt", false},
		{"/entrypoint", false},
	}
	for _, tt := range tests {
		got := isAllowedBindSource(tt.source, workdir)
		if got != tt.want {
			t.Errorf("isAllowedBindSource(%q, %q) = %v, want %v", tt.source, workdir, got, tt.want)
		}
	}
}
