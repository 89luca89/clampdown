// SPDX-License-Identifier: GPL-3.0-only

package network

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/89luca89/clampdown/pkg/container"
)

const (
	chainAgentAllow = "AGENT_ALLOW"
	chainAgentBlock = "AGENT_BLOCK"
	chainPodAllow   = "POD_ALLOW"
	chainPodBlock   = "POD_BLOCK"

	binIPT4 = "/usr/sbin/iptables"
	binIPT6 = "/usr/sbin/ip6tables"

	// maxRulesPerChunk caps the number of -A rules per iptables-restore call.
	// Avoid kernel's netlink batch return EMSGSIZE.
	maxRulesPerChunk = 150
)

var privateV4 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"}
var privateV6 = []string{"::1/128", "fc00::/7", "fe80::/10"}

// FirewallEntry is a single dynamic rule (allow or block) for a host.
type FirewallEntry struct {
	Host   string   `json:"host"`
	IPs    []string `json:"ips"`
	Port   int      `json:"port"`
	Action string   `json:"action"`
}

// FirewallState holds all dynamic firewall rules, persisted to disk.
type FirewallState struct {
	Agent []FirewallEntry `json:"agent"`
	Pod   []FirewallEntry `json:"pod"`
}

// LoadState reads the firewall state file. Returns empty state if the
// file does not exist.
func LoadState(path string) (*FirewallState, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &FirewallState{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read firewall state: %w", err)
	}
	var state FirewallState
	err = json.Unmarshal(data, &state)
	if err != nil {
		return nil, fmt.Errorf("parse firewall state: %w", err)
	}
	return &state, nil
}

// SaveState writes the firewall state file atomically.
func SaveState(path string, state *FirewallState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal firewall state: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

// InitState creates an empty firewall state file if it does not exist.
func InitState(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	return SaveState(path, &FirewallState{})
}

// BuildAgentFirewall creates the full agent OUTPUT chain structure via
// iptables-restore.
//
// deny mode: loopback -> established -> DNS (rate-limited) -> per-entry
//
//	TCP port ACCEPT -> private CIDRs REJECT -> AGENT_ALLOW -> terminal REJECT
//
// allow mode: loopback -> established -> AGENT_ALLOW -> private CIDRs REJECT ->
//
//	AGENT_BLOCK -> terminal ACCEPT
func BuildAgentFirewall(
	ctx context.Context,
	rt container.Runtime,
	sidecar string,
	policy string,
	allow []AllowEntry,
) error {
	var v4, v6 []AllowEntry
	for _, e := range allow {
		if strings.Contains(e.Target, ":") {
			v6 = append(v6, e)
		} else {
			v4 = append(v4, e)
		}
	}

	for _, bin := range []string{binIPT4, binIPT6} {
		var dests []AllowEntry
		var privRanges []string
		rejectType := "icmp-port-unreachable"
		restoreBin := "/usr/sbin/iptables-restore"
		if bin == binIPT6 {
			dests = v6
			privRanges = privateV6
			rejectType = "icmp6-port-unreachable"
			restoreBin = "/usr/sbin/ip6tables-restore"
		} else {
			dests = v4
			privRanges = privateV4
		}

		for _, chunk := range agentRestoreChunks(policy, dests, privRanges, rejectType) {
			out, err := rt.ExecStdin(ctx, sidecar, []string{restoreBin, "--noflush"}, []byte(chunk))
			if err != nil {
				return fmt.Errorf("%s restore: %w: %s", restoreBin, err, out)
			}
		}
	}

	parts := make([]string, 0, len(allow))
	for _, e := range allow {
		parts = append(parts, fmt.Sprintf("%s:%d", e.Target, e.Port))
	}
	_ = rt.Log(ctx, sidecar, "firewall",
		fmt.Sprintf("BUILD agent: policy=%s allow=%s",
			policy, strings.Join(parts, ",")))
	slog.Info("agent firewall built", "policy", policy, "ipv4", len(v4), "ipv6", len(v6))
	return nil
}

func agentRestoreChunks(policy string, dests []AllowEntry, privRanges []string, rejectType string) []string {
	header := fmt.Sprintf("*filter\n"+
		":%s - [0:0]\n"+
		":%s - [0:0]\n"+
		":OUTPUT ACCEPT [0:0]\n",
		chainAgentAllow, chainAgentBlock)

	writeEntry := func(buf *strings.Builder, e AllowEntry) {
		if e.Port == 0 {
			fmt.Fprintf(buf, "-A OUTPUT -p tcp -d %s -j ACCEPT\n", e.Target)
		} else {
			fmt.Fprintf(buf, "-A OUTPUT -p tcp --dport %d -d %s -j ACCEPT\n", e.Port, e.Target)
		}
	}

	if policy != "deny" {
		var buf strings.Builder
		buf.WriteString(header)
		buf.WriteString("-F OUTPUT\n" +
			"-A OUTPUT -o lo -j ACCEPT\n" +
			"-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n")
		fmt.Fprintf(&buf, "-A OUTPUT -j %s\n", chainAgentAllow)
		for _, cidr := range privRanges {
			fmt.Fprintf(&buf, "-A OUTPUT ! -o lo -d %s -j REJECT --reject-with %s\n", cidr, rejectType)
		}
		fmt.Fprintf(&buf, "-A OUTPUT -j %s\n"+
			"-A OUTPUT -j ACCEPT\n",
			chainAgentBlock)
		buf.WriteString("COMMIT\n")
		return []string{buf.String()}
	}

	// DNS before private CIDRs: resolver may be on a private IP
	// (10.0.2.3 slirp4netns, 192.168.x.x bridge). Rate-limited
	// to throttle tunneling; excess dropped.
	prefix := "-F OUTPUT\n" +
		"-A OUTPUT -o lo -j ACCEPT\n" +
		"-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n" +
		"-A OUTPUT -p udp --dport 53 -m limit --limit 10/s --limit-burst 20 -j ACCEPT\n" +
		"-A OUTPUT -p udp --dport 53 -j DROP\n" +
		"-A OUTPUT -p tcp --dport 53 -m limit --limit 10/s --limit-burst 20 -j ACCEPT\n" +
		"-A OUTPUT -p tcp --dport 53 -j DROP\n"

	writeSuffix := func(buf *strings.Builder) {
		for _, cidr := range privRanges {
			fmt.Fprintf(buf, "-A OUTPUT ! -o lo -d %s -j REJECT --reject-with %s\n", cidr, rejectType)
		}
		fmt.Fprintf(buf, "-A OUTPUT -j %s\n"+
			"-A OUTPUT -j REJECT --reject-with %s\n",
			chainAgentAllow, rejectType)
	}

	chunkCount := (len(dests) + maxRulesPerChunk - 1) / maxRulesPerChunk
	if chunkCount == 0 {
		chunkCount = 1
	}
	streams := make([]string, 0, chunkCount)
	for ci := range chunkCount {
		var buf strings.Builder
		buf.WriteString(header)
		if ci == 0 {
			buf.WriteString(prefix)
		}
		start := ci * maxRulesPerChunk
		end := min(start+maxRulesPerChunk, len(dests))
		for _, e := range dests[start:end] {
			writeEntry(&buf, e)
		}
		if ci == chunkCount-1 {
			writeSuffix(&buf)
		}
		buf.WriteString("COMMIT\n")
		streams = append(streams, buf.String())
	}
	return streams
}

// BuildPodFirewall creates the full pod FORWARD chain structure via
// iptables-restore. Applied atomically in 2 calls (IPv4 + IPv6).
//
// allow mode: established -> loopback -> POD_ALLOW -> DNS ACCEPT ->
//
//	private CIDRs DROP -> POD_BLOCK -> ACCEPT
//
// deny mode: established -> loopback -> DNS ACCEPT -> POD_ALLOW -> DROP.
func BuildPodFirewall(ctx context.Context, rt container.Runtime, sidecar string, policy string) error {
	for _, bin := range []string{binIPT4, binIPT6} {
		var privRanges []string
		restoreBin := "/usr/sbin/iptables-restore"
		if bin == binIPT6 {
			privRanges = privateV6
			restoreBin = "/usr/sbin/ip6tables-restore"
		} else {
			privRanges = privateV4
		}

		var buf strings.Builder
		fmt.Fprintf(&buf, "*mangle\n"+
			":%s - [0:0]\n"+
			":%s - [0:0]\n"+
			"-F FORWARD\n"+
			"-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT\n"+
			"-A FORWARD -o lo -j ACCEPT\n",
			chainPodAllow, chainPodBlock)

		if policy == "allow" {
			fmt.Fprintf(&buf, "-A FORWARD -j %s\n", chainPodAllow)
			// Allow DNS before private CIDR block: the resolver may be on
			// a private IP (127.0.0.53 systemd-resolved, 192.168.x.x bridge,
			// 169.254.1.1 pasta, 192.168.127.1 gvproxy).
			buf.WriteString(
				"-A FORWARD -p udp --dport 53 -j ACCEPT\n" +
					"-A FORWARD -p tcp --dport 53 -j ACCEPT\n")
			for _, cidr := range privRanges {
				fmt.Fprintf(&buf, "-A FORWARD ! -o lo -d %s -j DROP\n", cidr)
			}
			fmt.Fprintf(&buf, "-A FORWARD -j %s\n"+
				"-A FORWARD -j ACCEPT\n",
				chainPodBlock)
		} else {
			fmt.Fprintf(&buf, "-A FORWARD -p udp --dport 53 -j ACCEPT\n"+
				"-A FORWARD -p tcp --dport 53 -j ACCEPT\n"+
				"-A FORWARD -j %s\n"+
				"-A FORWARD -j DROP\n",
				chainPodAllow)
		}
		buf.WriteString("COMMIT\n")

		// Ensure NAT masquerade for forwarded traffic.
		buf.WriteString("*nat\n" +
			"-A POSTROUTING ! -o lo -j MASQUERADE\n" +
			"COMMIT\n")

		out, err := rt.ExecStdin(ctx, sidecar, []string{restoreBin, "--noflush"}, []byte(buf.String()))
		if err != nil {
			return fmt.Errorf("%s restore: %w: %s", restoreBin, err, out)
		}
	}

	_ = rt.Log(ctx, sidecar, "firewall", fmt.Sprintf("BUILD pod: policy=%s", policy))
	slog.Info("pod firewall built", "policy", policy)
	return nil
}

// AgentAllow sets hosts to ACCEPT in the agent firewall. Each target is
// "host[:port]"; port defaults to 443, and port 0 means all ports.
func AgentAllow(ctx context.Context, rt container.Runtime, sidecar, statePath string, targets []string) error {
	return modifyState(ctx, rt, sidecar, statePath, "agent", "ACCEPT", targets)
}

// AgentBlock sets hosts to REJECT in the agent firewall. Target syntax matches
// AgentAllow; use "host:0" to block all ports.
func AgentBlock(ctx context.Context, rt container.Runtime, sidecar, statePath string, targets []string) error {
	return modifyState(ctx, rt, sidecar, statePath, "agent", "REJECT", targets)
}

// PodAllow sets hosts to ACCEPT in the pod firewall. Target syntax matches
// AgentAllow.
func PodAllow(ctx context.Context, rt container.Runtime, sidecar, statePath string, targets []string) error {
	return modifyState(ctx, rt, sidecar, statePath, "pod", "ACCEPT", targets)
}

// PodBlock sets hosts to DROP in the pod firewall. Target syntax matches
// AgentAllow; use "host:0" to block all ports.
func PodBlock(ctx context.Context, rt container.Runtime, sidecar, statePath string, targets []string) error {
	return modifyState(ctx, rt, sidecar, statePath, "pod", "DROP", targets)
}

// ListRules prints dynamic rules from the state file.
func ListRules(statePath string) error {
	state, err := LoadState(statePath)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, "=== Agent ===")
	printStateRules(state.Agent)

	fmt.Fprintln(os.Stdout, "\n=== Pods ===")
	printStateRules(state.Pod)

	return nil
}

func printStateRules(entries []FirewallEntry) {
	var allowed, blocked []FirewallEntry
	for _, e := range entries {
		if e.Action == "ACCEPT" {
			allowed = append(allowed, e)
		} else {
			blocked = append(blocked, e)
		}
	}

	if len(allowed) == 0 && len(blocked) == 0 {
		fmt.Fprintln(os.Stdout, "  (defaults only)")
		return
	}

	if len(allowed) > 0 {
		fmt.Fprintln(os.Stdout, "  Allowed:")
		for _, e := range allowed {
			fmt.Fprintf(os.Stdout, "    %s (%s) :%s\n", e.Host, strings.Join(e.IPs, ", "), portStr(e.Port))
		}
	}
	if len(blocked) > 0 {
		fmt.Fprintln(os.Stdout, "  Blocked:")
		for _, e := range blocked {
			fmt.Fprintf(os.Stdout, "    %s (%s) :%s\n", e.Host, strings.Join(e.IPs, ", "), portStr(e.Port))
		}
	}
}

// AgentReset clears all dynamic agent rules.
func AgentReset(ctx context.Context, rt container.Runtime, sidecar, statePath string) error {
	state, err := LoadState(statePath)
	if err != nil {
		return err
	}
	state.Agent = nil
	err = SaveState(statePath, state)
	if err != nil {
		return err
	}
	err = reconcile(ctx, rt, sidecar, state, "agent")
	if err != nil {
		return err
	}
	_ = rt.Log(ctx, sidecar, "firewall", "RESET: scope=agent")
	slog.Info("reset dynamic rules", "scope", "agent")
	return nil
}

// PodReset clears all dynamic pod rules.
func PodReset(ctx context.Context, rt container.Runtime, sidecar, statePath string) error {
	state, err := LoadState(statePath)
	if err != nil {
		return err
	}
	state.Pod = nil
	err = SaveState(statePath, state)
	if err != nil {
		return err
	}
	err = reconcile(ctx, rt, sidecar, state, "pod")
	if err != nil {
		return err
	}
	_ = rt.Log(ctx, sidecar, "firewall", "RESET: scope=pod")
	slog.Info("reset dynamic rules", "scope", "pod")
	return nil
}

// modifyState updates the state file and reconciles iptables. Each target is
// "host[:port]" (default 443, 0 means all ports).
func modifyState(
	ctx context.Context, rt container.Runtime, sidecar, statePath string,
	scope, action string, targets []string,
) error {
	state, err := LoadState(statePath)
	if err != nil {
		return err
	}

	for _, target := range targets {
		host, port, literal := splitSpec(target)
		var ips []string
		if literal {
			ips = []string{host}
		} else {
			ips = resolveDomain(host)
		}
		if len(ips) == 0 {
			return fmt.Errorf("no IPs resolved for %s", host)
		}

		entry := FirewallEntry{
			Host:   host,
			IPs:    ips,
			Port:   port,
			Action: action,
		}

		entries := scopeEntries(state, scope)
		found := false
		for i, e := range *entries {
			if e.Host == host && e.Port == port {
				(*entries)[i] = entry
				found = true
				break
			}
		}
		if !found {
			*entries = append(*entries, entry)
		}
	}

	err = SaveState(statePath, state)
	if err != nil {
		return err
	}
	err = reconcile(ctx, rt, sidecar, state, scope)
	if err != nil {
		return err
	}

	_ = rt.Log(ctx, sidecar, "firewall",
		fmt.Sprintf("%s: scope=%s targets=%s",
			action, scope, strings.Join(targets, ",")))
	slog.Info("applied firewall rules",
		"action", action, "scope", scope,
		"targets", strings.Join(targets, ", "))
	return nil
}

func scopeEntries(state *FirewallState, scope string) *[]FirewallEntry {
	if scope == "pod" {
		return &state.Pod
	}
	return &state.Agent
}

func portStr(port int) string {
	if port == 0 {
		return "*"
	}
	return strconv.Itoa(port)
}

// reconcile flushes the dynamic chains for a scope and rebuilds them from the
// state file. Rules are submitted to iptables-restore in chunks of at most
// maxRulesPerChunk to stay below the netlink batch send buffer ceiling; the
// first chunk per protocol carries the flushes. Atomicity is per-chunk.
func reconcile(ctx context.Context, rt container.Runtime, sidecar string, state *FirewallState, scope string) error {
	table, allowChain, blockChain, entries := reconcileScope(state, scope)

	for _, bin := range []string{binIPT4, binIPT6} {
		isV6 := strings.Contains(bin, "ip6")
		restoreBin := "/usr/sbin/iptables-restore"
		if isV6 {
			restoreBin = "/usr/sbin/ip6tables-restore"
		}

		lines := buildEntryLines(entries, allowChain, blockChain, isV6)
		header := fmt.Sprintf("*%s\n"+
			":%s - [0:0]\n"+
			":%s - [0:0]\n",
			table, allowChain, blockChain)
		flush := fmt.Sprintf("-F %s\n-F %s\n", allowChain, blockChain)

		if err := submitChunks(ctx, rt, sidecar, restoreBin, header, flush, lines, scope); err != nil {
			return err
		}
	}

	return nil
}

// reconcileScope resolves the table and chain names plus the entry list for
// the requested scope. Returns (table, allowChain, blockChain, entries).
func reconcileScope(
	state *FirewallState,
	scope string,
) (string, string, string, []FirewallEntry) {
	if scope == "pod" {
		return "mangle", chainPodAllow, chainPodBlock, state.Pod
	}
	return "filter", chainAgentAllow, chainAgentBlock, state.Agent
}

// buildEntryLines renders firewall entries to iptables-restore "-A ..." lines
// for the requested IP version (entries containing addresses of the other
// version are skipped).
func buildEntryLines(entries []FirewallEntry, allowChain, blockChain string, isV6 bool) []string {
	var lines []string
	for _, e := range entries {
		chain := allowChain
		if e.Action != "ACCEPT" {
			chain = blockChain
		}
		rejectSuffix := rejectSuffixFor(e.Action, isV6)
		for _, ip := range e.IPs {
			if strings.Contains(ip, ":") != isV6 {
				continue
			}
			portRule := ""
			if e.Port > 0 {
				portRule = fmt.Sprintf(" -p tcp --dport %d", e.Port)
			}
			lines = append(lines, fmt.Sprintf("-A %s -d %s%s -j %s%s\n",
				chain, ip, portRule, e.Action, rejectSuffix))
		}
	}
	return lines
}

// rejectSuffixFor returns the " --reject-with <type>" suffix for REJECT
// actions on the given IP version, or "" otherwise.
func rejectSuffixFor(action string, isV6 bool) string {
	if action != "REJECT" {
		return ""
	}
	if isV6 {
		return " --reject-with icmp6-port-unreachable"
	}
	return " --reject-with icmp-port-unreachable"
}

// submitChunks pipes the generated lines into iptables-restore in chunks of
// maxRulesPerChunk. The first chunk carries the flushes so atomicity is
// per-chunk only.
func submitChunks(
	ctx context.Context,
	rt container.Runtime,
	sidecar, restoreBin, header, flush string,
	lines []string,
	scope string,
) error {
	chunkCount := (len(lines) + maxRulesPerChunk - 1) / maxRulesPerChunk
	if chunkCount == 0 {
		chunkCount = 1
	}
	for ci := range chunkCount {
		var buf strings.Builder
		buf.WriteString(header)
		if ci == 0 {
			buf.WriteString(flush)
		}
		start := ci * maxRulesPerChunk
		end := min(start+maxRulesPerChunk, len(lines))
		for _, line := range lines[start:end] {
			buf.WriteString(line)
		}
		buf.WriteString("COMMIT\n")

		out, err := rt.ExecStdin(ctx, sidecar, []string{restoreBin, "--noflush"}, []byte(buf.String()))
		if err != nil {
			return fmt.Errorf("reconcile %s: %w: %s", scope, err, out)
		}
	}
	return nil
}
