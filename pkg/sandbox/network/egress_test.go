// SPDX-License-Identifier: GPL-3.0-only

package network_test

import (
	"testing"

	"github.com/89luca89/clampdown/pkg/sandbox/network"
)

func TestClassifyIPs(t *testing.T) {
	ip4s, ip6s := network.ClassifyIPs([]string{
		"1.2.3.4",
		"::1",
		"10.0.0.1",
		"fe80::1",
	})
	if len(ip4s) != 2 {
		t.Errorf("IPv4 count = %d, want 2", len(ip4s))
	}
	if len(ip6s) != 2 {
		t.Errorf("IPv6 count = %d, want 2", len(ip6s))
	}
}
