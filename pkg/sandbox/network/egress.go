// SPDX-License-Identifier: GPL-3.0-only

package network

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Public DNS servers to query for diverse round-robin results.
// CDNs like GitHub/Cloudflare return different IPs to different resolvers.
var dnsServers = []string{
	"",                          // system resolver (empty = default)
	"1.1.1.1:53",                // Cloudflare (IPv4)
	"[2606:4700:4700::1111]:53", // Cloudflare (IPv6)
	"8.8.8.8:53",                // Google (IPv4)
	"[2001:4860:4860::8888]:53", // Google (IPv6)
	"9.9.9.9:53",                // Quad9 (IPv4)
	"[2620:fe::fe]:53",          // Quad9 (IPv6)
	"208.67.222.222:53",         // OpenDNS (IPv4)
	"[2620:119:35::35]:53",      // OpenDNS (IPv6)
}

// AllowEntry pairs a resolved allowlist target with its TCP destination port.
// Target is an IP or CIDR.
type AllowEntry struct {
	Target string
	Port   int
}

const defaultAllowPort = 443

// ResolveAllowEntries parses each entry as "host[:port]" and resolves hostnames
// to IPs in parallel per entry. Literals pass through with their parsed port.
func ResolveAllowEntries(raw []string) []AllowEntry {
	results := make([][]AllowEntry, len(raw))
	var wg sync.WaitGroup
	for i, r := range raw {
		wg.Go(func() {
			host, port, literal := splitSpec(r)
			if host == "" {
				return
			}
			if literal {
				results[i] = []AllowEntry{{Target: host, Port: port}}
				return
			}
			ips := resolveDomain(host)
			if len(ips) == 0 {
				slog.Warn("cannot resolve host", "host", host)
				return
			}
			out := make([]AllowEntry, len(ips))
			for j, ip := range ips {
				out[j] = AllowEntry{Target: ip, Port: port}
			}
			results[i] = out
		})
	}
	wg.Wait()

	seen := make(map[AllowEntry]struct{})
	var out []AllowEntry
	for _, es := range results {
		for _, e := range es {
			if _, ok := seen[e]; ok {
				continue
			}
			seen[e] = struct{}{}
			out = append(out, e)
		}
	}
	return out
}

// resolveDomain queries all DNS servers in parallel, each 20 times sequentially
// to catch round-robin rotation. Returns deduplicated IPs.
func resolveDomain(domain string) []string {
	perServer := make([][]string, len(dnsServers))

	var wg sync.WaitGroup
	for i, server := range dnsServers {
		wg.Go(func() {
			resolver := &net.Resolver{PreferGo: true}
			if server != "" {
				resolver = &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
						d := net.Dialer{Timeout: 2 * time.Second}
						return d.DialContext(ctx, "udp", server)
					},
				}
			}

			var ips []string
			for range 20 {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				addrs, err := resolver.LookupHost(ctx, domain)
				cancel()
				if err != nil {
					continue
				}
				for _, a := range addrs {
					if net.ParseIP(a) != nil {
						ips = append(ips, a)
					}
				}
			}
			perServer[i] = ips
		})
	}
	wg.Wait()

	var all []string
	for _, ips := range perServer {
		all = append(all, ips...)
	}
	slices.Sort(all)
	return slices.Compact(all)
}

// splitSpec parses "host[:port]" into host, port, and whether host is a literal
// IP or CIDR that bypasses DNS. Port defaults to 443 when absent or invalid;
// port 0 signals "all ports" to rule emitters. IPv6 literals must be bracketed
// to carry a port ("[::1]:443").
func splitSpec(s string) (string, int, bool) {
	host := strings.TrimSpace(s)
	port := defaultAllowPort
	if h, p, err := net.SplitHostPort(host); err == nil {
		if n, perr := strconv.Atoi(p); perr == nil && n >= 0 && n <= 65535 {
			host, port = h, n
		}
	}
	literal := false
	if net.ParseIP(host) != nil {
		literal = true
	} else if _, _, err := net.ParseCIDR(host); err == nil {
		literal = true
	}
	return host, port, literal
}
