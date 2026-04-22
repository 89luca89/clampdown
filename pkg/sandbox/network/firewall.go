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
// iptables-restore. Applied atomically in 2 calls (IPv4 + IPv6).
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

		var buf strings.Builder
		fmt.Fprintf(&buf, "*filter\n"+
			":%s - [0:0]\n"+
			":%s - [0:0]\n"+
			":OUTPUT ACCEPT [0:0]\n"+
			"-F OUTPUT\n"+
			"-A OUTPUT -o lo -j ACCEPT\n"+
			"-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n",
			chainAgentAllow, chainAgentBlock)

		if policy == "deny" {
			// DNS before private CIDRs: resolver may be on a private IP
			// (10.0.2.3 slirp4netns, 192.168.x.x bridge). Rate-limited
			// to throttle tunneling; excess dropped.
			buf.WriteString(
				"-A OUTPUT -p udp --dport 53 -m limit --limit 10/s --limit-burst 20 -j ACCEPT\n" +
					"-A OUTPUT -p udp --dport 53 -j DROP\n" +
					"-A OUTPUT -p tcp --dport 53 -m limit --limit 10/s --limit-burst 20 -j ACCEPT\n" +
					"-A OUTPUT -p tcp --dport 53 -j DROP\n")
			for _, e := range dests {
				if e.Port == 0 {
					fmt.Fprintf(&buf, "-A OUTPUT -p tcp -d %s -j ACCEPT\n", e.Target)
				} else {
					fmt.Fprintf(&buf, "-A OUTPUT -p tcp --dport %d -d %s -j ACCEPT\n", e.Port, e.Target)
				}
			}
			for _, cidr := range privRanges {
				fmt.Fprintf(&buf, "-A OUTPUT ! -o lo -d %s -j REJECT --reject-with %s\n", cidr, rejectType)
			}
			fmt.Fprintf(&buf, "-A OUTPUT -j %s\n"+
				"-A OUTPUT -j REJECT --reject-with %s\n",
				chainAgentAllow, rejectType)
		} else {
			fmt.Fprintf(&buf, "-A OUTPUT -j %s\n", chainAgentAllow)
			for _, cidr := range privRanges {
				fmt.Fprintf(&buf, "-A OUTPUT ! -o lo -d %s -j REJECT --reject-with %s\n", cidr, rejectType)
			}
			fmt.Fprintf(&buf, "-A OUTPUT -j %s\n"+
				"-A OUTPUT -j ACCEPT\n",
				chainAgentBlock)
		}
		buf.WriteString("COMMIT\n")

		out, err := rt.ExecStdin(ctx, sidecar, []string{restoreBin, "--noflush"}, []byte(buf.String()))
		if err != nil {
			return fmt.Errorf("%s restore: %w: %s", restoreBin, err, out)
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

// reconcile flushes the dynamic chains for a scope and rebuilds them
// from the state file using iptables-restore for atomicity.
func reconcile(ctx context.Context, rt container.Runtime, sidecar string, state *FirewallState, scope string) error {
	var table, allowChain, blockChain string
	var entries []FirewallEntry
	if scope == "pod" {
		table = "mangle"
		allowChain = chainPodAllow
		blockChain = chainPodBlock
		entries = state.Pod
	} else {
		table = "filter"
		allowChain = chainAgentAllow
		blockChain = chainAgentBlock
		entries = state.Agent
	}

	for _, bin := range []string{binIPT4, binIPT6} {
		isV6 := strings.Contains(bin, "ip6")
		restoreBin := "/usr/sbin/iptables-restore"
		if isV6 {
			restoreBin = "/usr/sbin/ip6tables-restore"
		}

		var buf strings.Builder
		fmt.Fprintf(&buf, "*%s\n"+
			":%s - [0:0]\n"+
			":%s - [0:0]\n"+
			"-F %s\n"+
			"-F %s\n",
			table, allowChain, blockChain, allowChain, blockChain)

		for _, e := range entries {
			chain := allowChain
			if e.Action != "ACCEPT" {
				chain = blockChain
			}

			rejectSuffix := ""
			if e.Action == "REJECT" {
				rejectType := "icmp-port-unreachable"
				if isV6 {
					rejectType = "icmp6-port-unreachable"
				}
				rejectSuffix = " --reject-with " + rejectType
			}

			for _, ip := range e.IPs {
				if strings.Contains(ip, ":") != isV6 {
					continue
				}
				portRule := ""
				if e.Port > 0 {
					portRule = fmt.Sprintf(" -p tcp --dport %d", e.Port)
				}
				fmt.Fprintf(&buf, "-A %s -d %s%s -j %s%s\n", chain, ip, portRule, e.Action, rejectSuffix)
			}
		}

		buf.WriteString("COMMIT\n")

		out, err := rt.ExecStdin(ctx, sidecar, []string{restoreBin, "--noflush"}, []byte(buf.String()))
		if err != nil {
			return fmt.Errorf("reconcile %s: %w: %s", scope, err, out)
		}
	}

	return nil
}
