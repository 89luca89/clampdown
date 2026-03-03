// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/json"
	"testing"
)

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

func seccompPtr() *json.RawMessage {
	raw := json.RawMessage(`{}`)
	return &raw
}

func boolPtr(v bool) *bool { return &v }

// baseConfig returns a Config that passes all checks.
func baseConfig() Config {
	var c Config
	c.Process.Args = []string{"/.sandbox/seal", "--", "sh"}
	c.Process.Capabilities.Bounding = []string{"CAP_CHOWN", "CAP_FOWNER"}
	c.Linux.Seccomp = seccompPtr()
	c.Linux.Namespaces = []struct {
		Type string `json:"type"`
		Path string `json:"path"`
	}{
		{Type: "pid"}, {Type: "network"}, {Type: "ipc"}, {Type: "mount"}, {Type: "cgroup"},
	}
	c.Linux.MaskedPaths = append([]string{}, requiredMaskedPaths...)
	c.Linux.ReadonlyPaths = append([]string{}, requiredReadonlyPaths...)
	c.Linux.RootfsPropagation = "private"
	return c
}

func TestCheckCaps_DeniedInBounding(t *testing.T) {
	c := baseConfig()
	c.Process.Capabilities.Bounding = []string{"CAP_SYS_ADMIN"}
	err := checkCaps(c)
	if err == nil {
		t.Fatal("expected error for CAP_SYS_ADMIN")
	}
}

func TestCheckCaps_DeniedInEffective(t *testing.T) {
	c := baseConfig()
	c.Process.Capabilities.Effective = []string{"CAP_NET_RAW"}
	err := checkCaps(c)
	if err == nil {
		t.Fatal("expected error for CAP_NET_RAW")
	}
}

func TestCheckCaps_DeniedInAmbient(t *testing.T) {
	c := baseConfig()
	c.Process.Capabilities.Ambient = []string{"CAP_BPF"}
	err := checkCaps(c)
	if err == nil {
		t.Fatal("expected error for CAP_BPF")
	}
}

func TestCheckSeccomp_Unconfined(t *testing.T) {
	c := baseConfig()
	c.Linux.Seccomp = nil
	err := checkSeccomp(c)
	if err == nil {
		t.Fatal("expected error for nil seccomp")
	}
}

func TestCheckNoNewPrivileges_Pass_True(t *testing.T) {
	c := baseConfig()
	c.Process.NoNewPrivileges = boolPtr(true)
	err := checkNoNewPrivileges(c)
	if err != nil {
		t.Errorf("expected pass for true, got: %v", err)
	}
}

func TestCheckNoNewPrivileges_Block_False(t *testing.T) {
	c := baseConfig()
	c.Process.NoNewPrivileges = boolPtr(false)
	err := checkNoNewPrivileges(c)
	if err == nil {
		t.Fatal("expected error for false")
	}
}

func TestCheckNamespaces_MissingPid(t *testing.T) {
	c := baseConfig()
	c.Linux.Namespaces = c.Linux.Namespaces[1:] // remove pid
	err := checkNamespaces(c)
	if err == nil {
		t.Fatal("expected error for missing pid namespace")
	}
}

func TestCheckNamespaces_JoinedViaPath(t *testing.T) {
	c := baseConfig()
	c.Linux.Namespaces[0].Path = "/proc/1/ns/pid"
	err := checkNamespaces(c)
	if err == nil {
		t.Fatal("expected error for joined namespace")
	}
}

func TestCheckMounts_Pass(t *testing.T) {
	t.Setenv("SANDBOX_WORKDIR", "/home/user/project")
	c := baseConfig()
	c.Mounts = []struct {
		Source      string   `json:"source"`
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Options     []string `json:"options"`
	}{
		{Source: "proc", Destination: "/proc", Type: "proc"},
		{Source: "/home/user/project/src", Destination: "/src"},
		{Source: "/var/lib/containers/storage/overlay/abc", Destination: "/merged"},
		{Source: "/sandbox-seal", Destination: "/.sandbox/seal"},
	}
	err := checkMounts(c)
	if err != nil {
		t.Errorf("expected pass, got: %v", err)
	}
}

func TestCheckMounts_UnknownSource(t *testing.T) {
	t.Setenv("SANDBOX_WORKDIR", "/home/user/project")
	c := baseConfig()
	c.Mounts = []struct {
		Source      string   `json:"source"`
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Options     []string `json:"options"`
	}{
		{Source: "/etc/shadow", Destination: "/etc/shadow"},
	}
	err := checkMounts(c)
	if err == nil {
		t.Fatal("expected error for /etc/shadow mount")
	}
}

func TestCheckMountOptions_Pass_RO(t *testing.T) {
	t.Setenv("SANDBOX_WORKDIR", "/work")
	c := baseConfig()
	c.Mounts = []struct {
		Source      string   `json:"source"`
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Options     []string `json:"options"`
	}{
		{Source: "/some/path", Destination: "/mnt", Options: []string{"bind", "ro"}},
	}
	err := checkMountOptions(c)
	if err != nil {
		t.Errorf("expected pass for RO mount, got: %v", err)
	}
}

func TestCheckMountOptions_Pass_NosuidNodev(t *testing.T) {
	t.Setenv("SANDBOX_WORKDIR", "/work")
	c := baseConfig()
	c.Mounts = []struct {
		Source      string   `json:"source"`
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Options     []string `json:"options"`
	}{
		{Source: "/some/path", Destination: "/mnt", Options: []string{"bind", "nosuid", "nodev"}},
	}
	err := checkMountOptions(c)
	if err != nil {
		t.Errorf("expected pass, got: %v", err)
	}
}

func TestCheckMountOptions_MissingNosuid(t *testing.T) {
	t.Setenv("SANDBOX_WORKDIR", "/work")
	c := baseConfig()
	c.Mounts = []struct {
		Source      string   `json:"source"`
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Options     []string `json:"options"`
	}{
		{Source: "/some/path", Destination: "/mnt", Options: []string{"bind", "nodev"}},
	}
	err := checkMountOptions(c)
	if err == nil {
		t.Fatal("expected error for missing nosuid")
	}
}

func TestCheckMountOptions_SkipWorkdir(t *testing.T) {
	t.Setenv("SANDBOX_WORKDIR", "/work")
	c := baseConfig()
	c.Mounts = []struct {
		Source      string   `json:"source"`
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Options     []string `json:"options"`
	}{
		{Source: "/work/subdir", Destination: "/app", Options: []string{"bind"}},
	}
	err := checkMountOptions(c)
	if err != nil {
		t.Errorf("expected pass for workdir mount, got: %v", err)
	}
}

func TestCheckMountPropagation_Shared(t *testing.T) {
	c := baseConfig()
	c.Mounts = []struct {
		Source      string   `json:"source"`
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Options     []string `json:"options"`
	}{
		{Source: "/a", Destination: "/b", Options: []string{"bind", "shared"}},
	}
	err := checkMountPropagation(c)
	if err == nil {
		t.Fatal("expected error for shared propagation")
	}
}

func TestCheckRootfsPropagation_Pass(t *testing.T) {
	for _, prop := range []string{"", "private", "rprivate"} {
		c := baseConfig()
		c.Linux.RootfsPropagation = prop
		err := checkRootfsPropagation(c)
		if err != nil {
			t.Errorf("expected pass for %q, got: %v", prop, err)
		}
	}
}

func TestCheckRootfsPropagation_Shared(t *testing.T) {
	c := baseConfig()
	c.Linux.RootfsPropagation = "shared"
	err := checkRootfsPropagation(c)
	if err == nil {
		t.Fatal("expected error for shared rootfs propagation")
	}
}

func TestCheckDevices_HasDevice(t *testing.T) {
	c := baseConfig()
	c.Linux.Devices = []struct {
		Path string `json:"path"`
	}{{Path: "/dev/sda"}}
	err := checkDevices(c)
	if err == nil {
		t.Fatal("expected error for device access")
	}
}

func TestCheckMaskedPaths_Removed(t *testing.T) {
	c := baseConfig()
	c.Linux.MaskedPaths = c.Linux.MaskedPaths[:len(c.Linux.MaskedPaths)-1]
	err := checkMaskedPaths(c)
	if err == nil {
		t.Fatal("expected error for removed masked path")
	}
}

func TestCheckMaskedPaths_SkipWithoutSeal(t *testing.T) {
	c := baseConfig()
	c.Process.Args = []string{"sh"}
	c.Linux.MaskedPaths = nil
	err := checkMaskedPaths(c)
	if err != nil {
		t.Errorf("expected pass without seal entrypoint, got: %v", err)
	}
}

func TestCheckReadonlyPaths_Removed(t *testing.T) {
	c := baseConfig()
	c.Linux.ReadonlyPaths = c.Linux.ReadonlyPaths[:1]
	err := checkReadonlyPaths(c)
	if err == nil {
		t.Fatal("expected error for removed readonly path")
	}
}

func TestCheckReadonlyPaths_SkipWithoutSeal(t *testing.T) {
	c := baseConfig()
	c.Process.Args = []string{"sh"}
	c.Linux.ReadonlyPaths = nil
	err := checkReadonlyPaths(c)
	if err != nil {
		t.Errorf("expected pass without seal entrypoint, got: %v", err)
	}
}

func TestCheckSysctl_HasEntry(t *testing.T) {
	c := baseConfig()
	c.Linux.Sysctl = map[string]string{"kernel.core_pattern": "|/exploit"}
	err := checkSysctl(c)
	if err == nil {
		t.Fatal("expected error for sysctl entry")
	}
}

func TestCheckSysctl_NetAllowed(t *testing.T) {
	c := baseConfig()
	c.Linux.Sysctl = map[string]string{
		"net.ipv4.ip_forward":          "1",
		"net.ipv6.conf.all.forwarding": "1",
		"net.core.somaxconn":           "1024",
	}
	err := checkSysctl(c)
	if err != nil {
		t.Errorf("expected pass for net.* sysctls, got: %v", err)
	}
}

func TestCheckSysctl_MixedBlocked(t *testing.T) {
	c := baseConfig()
	c.Linux.Sysctl = map[string]string{
		"net.ipv4.ip_forward": "1",
		"vm.max_map_count":    "262144",
	}
	err := checkSysctl(c)
	if err == nil {
		t.Fatal("expected error for vm.* sysctl mixed with net.*")
	}
}

func TestCheckRlimits_CoreNonzero(t *testing.T) {
	c := baseConfig()
	c.Process.Rlimits = []struct {
		Type string `json:"type"`
		Hard uint64 `json:"hard"`
	}{{Type: "RLIMIT_CORE", Hard: 1024}}
	err := checkRlimits(c)
	if err == nil {
		t.Fatal("expected error for nonzero RLIMIT_CORE")
	}
}

func TestCheckRlimits_CoreZero(t *testing.T) {
	c := baseConfig()
	c.Process.Rlimits = []struct {
		Type string `json:"type"`
		Hard uint64 `json:"hard"`
	}{{Type: "RLIMIT_CORE", Hard: 0}}
	err := checkRlimits(c)
	if err != nil {
		t.Errorf("expected pass for zero core, got: %v", err)
	}
}

func TestCheckImageRef_DigestPass(t *testing.T) {
	t.Setenv("SANDBOX_REQUIRE_DIGEST", "block")
	c := baseConfig()
	c.Annotations = map[string]string{
		"io.containers.rawImageName": "alpine@sha256:abc123",
	}
	err := checkImageRef(c)
	if err != nil {
		t.Errorf("expected pass for digest ref, got: %v", err)
	}
}

func TestCheckImageRef_TagOnlyWarn(t *testing.T) {
	t.Setenv("SANDBOX_REQUIRE_DIGEST", "warn")
	c := baseConfig()
	c.Annotations = map[string]string{
		"io.containers.rawImageName": "alpine:latest",
	}
	err := checkImageRef(c)
	if err != nil {
		t.Errorf("expected pass (warn mode), got: %v", err)
	}
}

func TestCheckImageRef_TagOnlyBlock(t *testing.T) {
	t.Setenv("SANDBOX_REQUIRE_DIGEST", "block")
	c := baseConfig()
	c.Annotations = map[string]string{
		"io.containers.rawImageName": "alpine:latest",
	}
	err := checkImageRef(c)
	if err == nil {
		t.Fatal("expected error for tag-only in block mode")
	}
}

func TestCheckImageRef_MissingAnnotation(t *testing.T) {
	t.Setenv("SANDBOX_REQUIRE_DIGEST", "block")
	c := baseConfig()
	err := checkImageRef(c)
	if err != nil {
		t.Errorf("expected pass for missing annotation, got: %v", err)
	}
}

// TestAllChecksPass verifies a well-formed config passes all checks.
func TestAllChecksPass(t *testing.T) {
	t.Setenv("SANDBOX_WORKDIR", "/work")
	t.Setenv("SANDBOX_REQUIRE_DIGEST", "warn")
	c := baseConfig()
	checks := []struct {
		name  string
		check func(Config) error
	}{
		{"caps", checkCaps},
		{"seccomp", checkSeccomp},
		{"noNewPrivileges", checkNoNewPrivileges},
		{"namespaces", checkNamespaces},
		{"mounts", checkMounts},
		{"mountOptions", checkMountOptions},
		{"mountPropagation", checkMountPropagation},
		{"rootfsPropagation", checkRootfsPropagation},
		{"devices", checkDevices},
		{"maskedPaths", checkMaskedPaths},
		{"readonlyPaths", checkReadonlyPaths},
		{"sysctl", checkSysctl},
		{"rlimits", checkRlimits},
		{"imageRef", checkImageRef},
	}
	for _, tc := range checks {
		err := tc.check(c)
		if err != nil {
			t.Errorf("%s: expected pass, got: %v", tc.name, err)
		}
	}
}
