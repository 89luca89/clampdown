// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"slices"
	"testing"
)

func TestIsSubPath(t *testing.T) {
	tests := []struct {
		base, path string
		want       bool
	}{
		{"/a", "/a", true},
		{"/a", "/a/b", true},
		{"/a", "/b", false},
		{"/a", "/ab", false},
		{"/a/b", "/a", false},
	}
	for _, tt := range tests {
		got := isSubPath(tt.base, tt.path)
		if got != tt.want {
			t.Errorf("isSubPath(%q, %q) = %v, want %v", tt.base, tt.path, got, tt.want)
		}
	}
}

func TestDerivePolicy_WorkdirBind(t *testing.T) {
	mounts := []mount{
		{
			Source: "/home/user/project", Destination: "/home/user/project",
			Type: "bind", Options: []string{"bind", "rw"},
		},
	}
	p := derivePolicy(mounts)

	found := false
	for _, path := range p.WriteExec {
		if path == "/home/user/project" {
			found = true
		}
	}
	if !found {
		t.Error("RW bind mount should be in WriteExec")
	}
}

func TestDerivePolicy_ROBind(t *testing.T) {
	mounts := []mount{
		{Source: "/cfg", Destination: "/cfg", Type: "bind", Options: []string{"bind", "ro"}},
	}
	p := derivePolicy(mounts)

	for _, path := range p.WriteExec {
		if path == "/cfg" {
			t.Error("RO bind should NOT be in WriteExec")
		}
	}
	for _, path := range p.WriteNoExec {
		if path == "/cfg" {
			t.Error("RO bind should NOT be in WriteNoExec")
		}
	}
}

func TestDerivePolicy_TmpfsNoExec(t *testing.T) {
	mounts := []mount{
		{Source: "tmpfs", Destination: "/tmp", Type: "tmpfs", Options: []string{"noexec", "nosuid"}},
	}
	p := derivePolicy(mounts)

	found := false
	for _, path := range p.WriteNoExec {
		if path == "/tmp" {
			found = true
		}
	}
	if !found {
		t.Error("noexec tmpfs should be in WriteNoExec")
	}
}

func TestDerivePolicy_TmpfsExec(t *testing.T) {
	mounts := []mount{
		{Source: "tmpfs", Destination: "/run", Type: "tmpfs", Options: []string{"nosuid"}},
	}
	p := derivePolicy(mounts)

	found := false
	for _, path := range p.WriteExec {
		if path == "/run" {
			found = true
		}
	}
	if !found {
		t.Error("exec tmpfs should be in WriteExec")
	}
}

func TestDerivePolicy_SealBinarySkipped(t *testing.T) {
	mounts := []mount{
		{Source: sealBinary, Destination: sealDest, Type: "bind", Options: []string{"bind", "ro"}},
	}
	p := derivePolicy(mounts)

	for _, path := range p.WriteExec {
		if path == sealDest {
			t.Error("seal binary should be skipped")
		}
	}
}

func TestDerivePolicy_InfraSkipped(t *testing.T) {
	mounts := []mount{
		{
			Source:      "/var/lib/containers/storage/overlay/abc/merged",
			Destination: "/", Type: "bind", Options: []string{"bind"},
		},
	}
	p := derivePolicy(mounts)

	for _, path := range p.WriteExec {
		if path == "/" {
			t.Error("infra mount should be skipped, / should not be in WriteExec")
		}
	}
}

func TestIsInfraMount_StoragePrefix(t *testing.T) {
	m := mount{
		Source:      "/var/lib/containers/storage/overlay/abc/merged",
		Destination: "/",
	}
	if !isInfraMount(m) {
		t.Error("overlay storage mount should be infra")
	}
}

func TestIsInfraMount_CachePrefix(t *testing.T) {
	m := mount{
		Source:      "/var/cache/containers/blob-cache/sha256/abc",
		Destination: "/layer",
	}
	if !isInfraMount(m) {
		t.Error("cache mount should be infra")
	}
}

func TestIsInfraMount_UserMount(t *testing.T) {
	m := mount{
		Source:      "/home/user/project",
		Destination: "/work",
	}
	if isInfraMount(m) {
		t.Error("user workdir mount should NOT be infra")
	}
}

func TestIsInfraMount_NonAbsoluteSource(t *testing.T) {
	m := mount{Source: "proc", Destination: "/proc", Type: "proc"}
	// Non-absolute sources don't match infra prefixes and aren't in
	// runtimeMountDests. isInfraMount returns false (correctly —
	// derivePolicy handles type mounts separately).
	if isInfraMount(m) {
		t.Error("proc mount should NOT be infra")
	}
}

func TestFilterAdditionalGids_Passthrough(t *testing.T) {
	got := filterAdditionalGids([]uint32{1, 2, 100, 1000})
	want := []uint32{1, 2, 100, 1000}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestFilterAdditionalGids_StripsPrivileged(t *testing.T) {
	got := filterAdditionalGids([]uint32{0, 1, 10, 27, 1000})
	want := []uint32{1, 1000}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestFilterAdditionalGids_Empty(t *testing.T) {
	got := filterAdditionalGids(nil)
	if len(got) != 0 {
		t.Errorf("got %v, want empty slice", got)
	}
}

func TestFilterAdditionalGids_AllPrivileged(t *testing.T) {
	got := filterAdditionalGids([]uint32{0, 10, 27})
	if len(got) != 0 {
		t.Errorf("got %v, want empty slice", got)
	}
}
