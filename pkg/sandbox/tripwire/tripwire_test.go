// SPDX-License-Identifier: GPL-3.0-only

package tripwire_test

import (
	"testing"

	"github.com/89luca89/clampdown/pkg/container"
	"github.com/89luca89/clampdown/pkg/sandbox/tripwire"
)

func TestHostPaths(t *testing.T) {
	mounts := []container.MountSpec{
		{Source: "/work", Dest: "/work", Type: container.Bind},
		{Source: "/ro-dir", Dest: "/ro-dir", RO: true, Type: container.Bind},
		{Dest: "/masked-file", Type: container.DevNull},
		{Dest: "/empty-dir", Type: container.EmptyRO},
		{Source: "/ro-dup", Dest: "/ro-dup", RO: true, Type: container.Bind},
		{Source: "/ro-dup", Dest: "/ro-dup-alias", RO: true, Type: container.Bind},
	}
	paths := tripwire.HostPaths(mounts)

	want := map[string]bool{
		"/ro-dir":      true,
		"/masked-file": true,
		"/empty-dir":   true,
		"/ro-dup":      true,
	}
	if len(paths) != len(want) {
		t.Errorf("len = %d, want %d: %v", len(paths), len(want), paths)
	}
	for _, p := range paths {
		if !want[p] {
			t.Errorf("unexpected path: %s", p)
		}
	}
}
