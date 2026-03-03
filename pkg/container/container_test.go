// SPDX-License-Identifier: GPL-3.0-only

package container_test

import (
	"testing"

	"github.com/89luca89/clampdown/pkg/container"
)

func TestMountFlags_Bind_RO(t *testing.T) {
	cfg := container.AgentContainerConfig{
		Mounts: []container.MountSpec{
			{Source: "/src", Dest: "/dst", RO: true, Type: container.Bind},
		},
	}
	p := &container.Podman{}
	flags := p.MountFlags(cfg)
	if len(flags) != 2 {
		t.Fatalf("len = %d, want 2", len(flags))
	}
	if flags[1] != "/src:/dst:ro,z" {
		t.Errorf("flags[1] = %s, want /src:/dst:ro,z", flags[1])
	}
}

func TestMountFlags_DevNull(t *testing.T) {
	cfg := container.AgentContainerConfig{
		Mounts: []container.MountSpec{
			{Dest: "/masked", Type: container.DevNull},
		},
	}
	p := &container.Podman{}
	flags := p.MountFlags(cfg)
	if len(flags) != 2 {
		t.Fatalf("len = %d, want 2", len(flags))
	}
	if flags[1] != "/dev/null:/masked:ro" {
		t.Errorf("flags[1] = %s, want /dev/null:/masked:ro", flags[1])
	}
}

func TestMountFlags_Bind_Hardened(t *testing.T) {
	cfg := container.AgentContainerConfig{
		Mounts: []container.MountSpec{
			{Source: "/home", Dest: "/home", Type: container.Bind, Hardened: true},
		},
	}
	p := &container.Podman{}
	flags := p.MountFlags(cfg)
	if len(flags) != 2 {
		t.Fatalf("len = %d, want 2", len(flags))
	}
	want := "/home:/home:z,nosuid,nodev"
	if flags[1] != want {
		t.Errorf("flags[1] = %s, want %s", flags[1], want)
	}
}

func TestMountFlags_EmptyRO(t *testing.T) {
	cfg := container.AgentContainerConfig{
		Mounts: []container.MountSpec{
			{Dest: "/empty", Type: container.EmptyRO},
		},
	}
	p := &container.Podman{}
	flags := p.MountFlags(cfg)
	if len(flags) != 2 {
		t.Fatalf("len = %d, want 2", len(flags))
	}
	if flags[0] != "--tmpfs" {
		t.Errorf("flags[0] = %s, want --tmpfs", flags[0])
	}
	if flags[1] != "/empty:ro,size=0,mode=000" {
		t.Errorf("flags[1] = %s, want /empty:ro,size=0,mode=000", flags[1])
	}
}
