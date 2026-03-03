// SPDX-License-Identifier: GPL-3.0-only

package network

import (
	"context"
	"log/slog"
	"net"
	"strings"
)

// ResolveAllowlist resolves domains to IPs using the host's DNS resolver.
// IPs and CIDRs pass through unchanged. Used at startup to pre-resolve
// the agent's static allowlist before passing to the sidecar as env var.
func ResolveAllowlist(domains []string) []string {
	var out []string
	resolver := net.DefaultResolver

	for _, entry := range domains {
		// Already an IP — pass through.
		if net.ParseIP(entry) != nil {
			out = append(out, entry)
			continue
		}
		// CIDR — validate and reject overly broad ranges.
		_, cidr, cidrErr := net.ParseCIDR(entry)
		if cidrErr == nil {
			ones, _ := cidr.Mask.Size()
			if ones < 4 {
				slog.Warn("overly broad CIDR in allowlist, skipping", "cidr", entry)
				continue
			}
			out = append(out, entry)
			continue
		}
		// Domain — resolve.
		addrs, err := resolver.LookupHost(context.Background(), entry)
		if err != nil {
			slog.Warn("cannot resolve host", "host", entry, "error", err)
			continue
		}
		for _, a := range addrs {
			if net.ParseIP(a) != nil {
				out = append(out, a)
			}
		}
	}

	return out
}

// ClassifyIPs splits resolved IPs into IPv4 and IPv6 buckets.
func ClassifyIPs(entries []string) ([]string, []string) {
	var ip4s, ip6s []string
	for _, entry := range entries {
		if strings.Contains(entry, ":") {
			ip6s = append(ip6s, entry)
		} else {
			ip4s = append(ip4s, entry)
		}
	}
	return ip4s, ip6s
}
