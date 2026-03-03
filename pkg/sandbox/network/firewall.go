// SPDX-License-Identifier: GPL-3.0-only

package network

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/89luca89/clampdown/pkg/container"
)

// Chain names match those created by the sidecar entrypoint.
const (
	chainAgentAllow = "AGENT_ALLOW"
	chainAgentBlock = "AGENT_BLOCK"
	chainPodAllow   = "POD_ALLOW"
	chainPodBlock   = "POD_BLOCK"
)

// AgentAllow adds ACCEPT rules to AGENT_ALLOW (filter table).
func AgentAllow(ctx context.Context, rt container.Runtime, sidecar string, targets []string, ports string) error {
	return modifyChain(ctx, rt, sidecar, "filter", chainAgentAllow, "ACCEPT", targets, ports)
}

// AgentBlock adds DROP rules to AGENT_BLOCK (filter table).
func AgentBlock(ctx context.Context, rt container.Runtime, sidecar string, targets []string, ports string) error {
	return modifyChain(ctx, rt, sidecar, "filter", chainAgentBlock, "DROP", targets, ports)
}

// PodAllow adds ACCEPT rules to POD_ALLOW (mangle table).
func PodAllow(ctx context.Context, rt container.Runtime, sidecar string, targets []string, ports string) error {
	return modifyChain(ctx, rt, sidecar, "mangle", chainPodAllow, "ACCEPT", targets, ports)
}

// PodBlock adds DROP rules to POD_BLOCK (mangle table).
func PodBlock(ctx context.Context, rt container.Runtime, sidecar string, targets []string, ports string) error {
	return modifyChain(ctx, rt, sidecar, "mangle", chainPodBlock, "DROP", targets, ports)
}

// ListRules prints all four dynamic chains grouped by Agent and Pods.
func ListRules(ctx context.Context, rt container.Runtime, sidecar string) error {
	fmt.Fprintln(os.Stderr, "=== Agent ===")
	allowed := listChain(ctx, rt, sidecar, "filter", chainAgentAllow)
	blocked := listChain(ctx, rt, sidecar, "filter", chainAgentBlock)
	if len(allowed) == 0 && len(blocked) == 0 {
		fmt.Fprintln(os.Stderr, "  (defaults only)")
	} else {
		printRules("Allowed", allowed)
		printRules("Blocked", blocked)
	}

	fmt.Fprintln(os.Stderr, "\n=== Pods ===")
	allowed = listChain(ctx, rt, sidecar, "mangle", chainPodAllow)
	blocked = listChain(ctx, rt, sidecar, "mangle", chainPodBlock)
	if len(allowed) == 0 && len(blocked) == 0 {
		fmt.Fprintln(os.Stderr, "  (defaults only)")
		return nil
	}

	printRules("Allowed", allowed)
	printRules("Blocked", blocked)

	return nil
}

func printRules(label string, rules []string) {
	if len(rules) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "  %s:\n", label)
	for _, r := range rules {
		fmt.Fprintf(os.Stderr, "    %s\n", r)
	}
}

// AgentReset flushes AGENT_ALLOW and AGENT_BLOCK chains.
func AgentReset(ctx context.Context, rt container.Runtime, sidecar string) error {
	return flushChains(ctx, rt, sidecar, "filter", chainAgentAllow, chainAgentBlock)
}

// PodReset flushes POD_ALLOW and POD_BLOCK chains.
func PodReset(ctx context.Context, rt container.Runtime, sidecar string) error {
	return flushChains(ctx, rt, sidecar, "mangle", chainPodAllow, chainPodBlock)
}

func flushChains(ctx context.Context, rt container.Runtime, sidecar, table string, chains ...string) error {
	for _, bin := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} {
		for _, chain := range chains {
			_, err := rt.Exec(ctx, sidecar, []string{bin, "-t", table, "-F", chain}, nil)
			if err != nil {
				return fmt.Errorf("%s flush %s/%s: %w", bin, table, chain, err)
			}
		}
	}
	slog.Info("reset dynamic rules", "table", table)
	return nil
}

func modifyChain(
	ctx context.Context, rt container.Runtime, sidecar string,
	table, chain, verdict string,
	targets []string, ports string,
) error {
	resolved := ResolveAllowlist(targets)
	if len(resolved) == 0 {
		return fmt.Errorf("no IPs resolved for %v", targets)
	}
	ip4s, ip6s := ClassifyIPs(resolved)
	count := 0
	for _, ip := range ip4s {
		err := iptExec(ctx, rt, sidecar, "/usr/sbin/iptables", table, chain, verdict, ip, ports)
		if err != nil {
			return err
		}
		count++
	}
	for _, ip := range ip6s {
		err := iptExec(ctx, rt, sidecar, "/usr/sbin/ip6tables", table, chain, verdict, ip, ports)
		if err != nil {
			return err
		}
		count++
	}
	slog.Info("applied firewall rules",
		"verdict", verdict,
		"count", count,
		"table", table,
		"chain", chain,
		"targets", strings.Join(targets, ", "))
	return nil
}

func iptExec(
	ctx context.Context, rt container.Runtime, sidecar string,
	bin, table, chain, verdict, dest, ports string,
) error {
	args := []string{bin, "-t", table, "-A", chain, "-d", dest}
	portList := strings.Split(ports, ",")
	if len(portList) == 1 {
		args = append(args, "-p", "tcp", "--dport", portList[0])
	} else {
		args = append(args, "-p", "tcp", "-m", "multiport", "--dports", ports)
	}
	args = append(args, "-j", verdict)
	_, err := rt.Exec(ctx, sidecar, args, nil)
	return err
}

func listChain(ctx context.Context, rt container.Runtime, sidecar, table, chain string) []string {
	var rules []string
	for _, bin := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} {
		out, err := rt.Exec(ctx, sidecar, []string{
			bin, "-t", table, "-L", chain, "-n", "--line-numbers",
		}, nil)
		if err != nil {
			continue
		}
		ipVer := "IPv4"
		if strings.Contains(bin, "ip6") {
			ipVer = "IPv6"
		}
		for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
			if strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "num") || strings.TrimSpace(line) == "" {
				continue
			}
			rules = append(rules, fmt.Sprintf("[%s] %s", ipVer, line))
		}
	}
	return rules
}
