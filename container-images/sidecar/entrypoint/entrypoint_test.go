// SPDX-License-Identifier: GPL-3.0-only

package main

import "testing"

func TestClassifyIPs(t *testing.T) {
	ip4s, ip6s := classifyIPs([]string{
		"1.2.3.4",
		"10.0.0.1",
		"::1",
		"fe80::1",
		"192.168.1.0/24",
		"fc00::/7",
	})
	if len(ip4s) != 3 {
		t.Errorf("IPv4 count = %d, want 3: %v", len(ip4s), ip4s)
	}
	if len(ip6s) != 3 {
		t.Errorf("IPv6 count = %d, want 3: %v", len(ip6s), ip6s)
	}
}

func TestClassifyIPs_Dedup(t *testing.T) {
	ip4s, _ := classifyIPs([]string{"1.2.3.4", "1.2.3.4"})
	if len(ip4s) != 1 {
		t.Errorf("duplicates not removed: %v", ip4s)
	}
}

func TestClassifyIPs_BadCIDR(t *testing.T) {
	ip4s, ip6s := classifyIPs([]string{"not-an-ip/32"})
	if len(ip4s)+len(ip6s) != 0 {
		t.Error("bad CIDR should be skipped")
	}
}
