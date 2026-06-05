// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	ucli "github.com/urfave/cli/v3"

	"github.com/89luca89/clampdown/pkg/agent"
	"github.com/89luca89/clampdown/pkg/container"
	"github.com/89luca89/clampdown/pkg/sandbox"
	"github.com/89luca89/clampdown/pkg/sandbox/network"
	"github.com/89luca89/clampdown/pkg/sandbox/session"
)

// Run is the top-level entry point.
func Run(args []string) error {
	cfg := LoadConfig()

	cmd := &ucli.Command{
		Name:  "clampdown",
		Usage: "Run AI agents in sandboxed containers",
		Before: func(ctx context.Context, cmd *ucli.Command) (context.Context, error) {
			var level slog.Level
			switch cmd.String("log-level") {
			case "debug":
				level = slog.LevelDebug
			case "info":
				level = slog.LevelInfo
			case "warn", "warning":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			default:
				return ctx, fmt.Errorf("unknown log level: %s", cmd.String("log-level"))
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: level,
				ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
					if a.Key == slog.TimeKey {
						return slog.Attr{}
					}
					return a
				},
			})))
			return ctx, nil
		},
		Flags: []ucli.Flag{
			&ucli.StringFlag{
				Name:  "log-level",
				Value: "info",
				Usage: "Log level (debug, info, warn, error)",
			},
			&ucli.StringFlag{
				Name:    "runtime",
				Value:   cfg.Runtime,
				Sources: ucli.EnvVars("CONTAINER_RUNTIME"),
				Usage:   "Container runtime (podman, docker, nerdctl)",
			},
			&ucli.StringFlag{
				Name:  "sidecar-image",
				Value: cfg.SidecarImage,
				Usage: "Override sidecar container image",
			},
			&ucli.StringFlag{
				Name:  "proxy-image",
				Value: cfg.ProxyImage,
				Usage: "Override auth proxy container image",
			},
			&ucli.StringFlag{
				Name:  "agent-image",
				Usage: "Override agent container image (takes precedence over agent_images map in config.json)",
			},
			&ucli.BoolFlag{
				Name:  "allow-hooks",
				Value: cfg.AllowHooks,
				Usage: "Allow writes to .git/hooks/ (default: read-only)",
			},
			&ucli.BoolFlag{
				Name:    "registry-auth",
				Value:   cfg.RegistryAuth,
				Sources: ucli.EnvVars("SANDBOX_REGISTRY_AUTH"),
				Usage:   "Forward host registry credentials to agent (read-only)",
			},
			&ucli.BoolFlag{
				Name:  "tripwire",
				Value: cfg.EnableTripwire,
				Usage: "Kill session on protected path modification (off by default; restores on exit either way)",
			},
			&ucli.StringFlag{
				Name:    "agent-policy",
				Value:   defaultStr(cfg.AgentPolicy, "deny"),
				Sources: ucli.EnvVars("SANDBOX_AGENT_POLICY"),
				Usage:   "Agent network policy (allow, deny)",
			},
			&ucli.StringFlag{
				Name:    "agent-allow",
				Value:   cfg.AgentAllow,
				Sources: ucli.EnvVars("SANDBOX_AGENT_ALLOW"),
				Usage:   "Additional host[:port] entries for agent allowlist (comma-separated, default port 443). Startup entries sit before the private-CIDR reject so explicit private targets are reachable.",
			},
			&ucli.StringFlag{
				Name:    "pod-policy",
				Value:   defaultStr(cfg.PodPolicy, "allow"),
				Sources: ucli.EnvVars("SANDBOX_POD_POLICY"),
				Usage:   "Pod network policy (allow, deny)",
			},
			&ucli.StringFlag{
				Name:    "require-digest",
				Value:   defaultStr(cfg.RequireDigest, "warn"),
				Sources: ucli.EnvVars("SANDBOX_REQUIRE_DIGEST"),
				Usage:   "Image digest enforcement: warn (log tag-only pulls) or block (reject them)",
			},
			&ucli.StringFlag{
				Name:    "memory",
				Value:   defaultStr(cfg.Memory, "4g"),
				Sources: ucli.EnvVars("SANDBOX_MEMORY"),
				Usage:   "Memory limit for containers (e.g. 4g, 8g)",
			},
			&ucli.IntFlag{
				Name:    "cpus",
				Value:   defaultInt(cfg.CPUs, 4),
				Sources: ucli.EnvVars("SANDBOX_CPUS"),
				Usage:   "CPU limit for containers (e.g. 4, 8)",
			},
			&ucli.StringFlag{
				Name:    "workdir",
				Aliases: []string{"w"},
				Usage:   "Directory to work into",
			},
			&ucli.BoolFlag{
				Name:  "gitconfig",
				Value: cfg.GitConfig,
				Usage: "Forward ~/.gitconfig read-only into tool containers",
			},
			&ucli.BoolFlag{
				Name:  "gh",
				Value: cfg.GH,
				Usage: "Forward ~/.config/gh read-only into tool containers (GitHub CLI auth)",
			},
			&ucli.BoolFlag{
				Name:  "ssh",
				Value: cfg.SSH,
				Usage: "Forward SSH agent socket into tool containers (SSH_AUTH_SOCK)",
			},
			&ucli.StringSliceFlag{
				Name:  "protect",
				Usage: "Additional paths to protect read-only (repeatable; trailing / = directory)",
			},
			&ucli.StringSliceFlag{
				Name:  "mask",
				Usage: "Paths to mask (content hidden; repeatable; trailing / = directory)",
			},
			&ucli.StringSliceFlag{
				Name:  "unmask",
				Usage: "Remove paths from the default mask list (e.g. --unmask .env)",
			},
		},
		Commands: append(agentCommands(cfg),
			&ucli.Command{
				Name:  "list",
				Usage: "List running sandbox sessions",
				Flags: []ucli.Flag{
					&ucli.BoolFlag{
						Name:    "all",
						Aliases: []string{"a"},
						Usage:   "Include stopped sessions",
					},
				},
				Action: listSessions,
			},
			&ucli.Command{
				Name:   "attach",
				Usage:  "Attach to a running sandbox session",
				Flags:  []ucli.Flag{sessionFlag()},
				Action: attachSession,
			},
			&ucli.Command{
				Name:   "stop",
				Usage:  "Stop a running sandbox session",
				Flags:  []ucli.Flag{sessionFlag()},
				Action: stopSession,
			},
			&ucli.Command{
				Name:   "delete",
				Usage:  "Remove a stopped session's containers and cache",
				Flags:  []ucli.Flag{sessionFlag()},
				Action: deleteSession,
			},
			&ucli.Command{
				Name:  "logs",
				Usage: "Show merged logs from all containers in a session",
				Flags: []ucli.Flag{
					sessionFlag(),
					&ucli.BoolFlag{
						Name:  "dump-agent-conversation",
						Usage: "Include raw agent container output (full conversation)",
					},
				},
				Action: showLogs,
			},
			&ucli.Command{
				Name:  "network",
				Usage: "Manage network access for agent and pod containers",
				Commands: []*ucli.Command{
					{
						Name:  "agent",
						Usage: "Manage agent network rules",
						Commands: []*ucli.Command{
							{
								Name:      "allow",
								Usage:     "Allow agent traffic to host[:port] (default port 443, :0 means all ports)",
								ArgsUsage: "<host[:port]> [host[:port]...]",
								Flags:     []ucli.Flag{sessionFlag()},
								Action:    networkAgentAllow,
							},
							{
								Name:      "block",
								Usage:     "Block agent traffic to host[:port] (default port 443, :0 means all ports)",
								ArgsUsage: "<host[:port]> [host[:port]...]",
								Flags:     []ucli.Flag{sessionFlag()},
								Action:    networkAgentBlock,
							},
							{
								Name:   "reset",
								Usage:  "Remove all dynamic agent network rules",
								Flags:  []ucli.Flag{sessionFlag()},
								Action: networkAgentReset,
							},
						},
					},
					{
						Name:  "pod",
						Usage: "Manage pod network rules",
						Commands: []*ucli.Command{
							{
								Name:      "allow",
								Usage:     "Allow pod traffic to host[:port] (default port 443, :0 means all ports)",
								ArgsUsage: "<host[:port]> [host[:port]...]",
								Flags:     []ucli.Flag{sessionFlag()},
								Action:    networkPodAllow,
							},
							{
								Name:      "block",
								Usage:     "Block pod traffic to host[:port] (default port 443, :0 means all ports)",
								ArgsUsage: "<host[:port]> [host[:port]...]",
								Flags:     []ucli.Flag{sessionFlag()},
								Action:    networkPodBlock,
							},
							{
								Name:   "reset",
								Usage:  "Remove all dynamic pod network rules",
								Flags:  []ucli.Flag{sessionFlag()},
								Action: networkPodReset,
							},
						},
					},
					{
						Name:   "list",
						Usage:  "Show dynamic network rules for a session",
						Flags:  []ucli.Flag{sessionFlag()},
						Action: networkList,
					},
				},
			},
			&ucli.Command{
				Name:  "image",
				Usage: "Manage container images in sandbox sessions",
				Commands: []*ucli.Command{
					{
						Name:      "push",
						Usage:     "Push host images into a running sandbox session",
						ArgsUsage: "<image> [image...]",
						Flags:     []ucli.Flag{sessionFlag()},
						Action:    imagePush,
					},
				},
			},
			&ucli.Command{
				Name:   "prune",
				Usage:  "Remove per-project cached container storage, images, and state",
				Action: prune,
			},
		),
	}

	return cmd.Run(context.Background(), args)
}

func sessionFlag() *ucli.StringFlag {
	return &ucli.StringFlag{
		Name:     "session",
		Aliases:  []string{"s"},
		Usage:    "Session ID (use 'list' to find running sessions)",
		Required: true,
	}
}

// agentCommands generates a subcommand for each registered agent.
func agentCommands(cfg Config) []*ucli.Command {
	var cmds []*ucli.Command
	for _, name := range agent.Available() {
		cmds = append(cmds, &ucli.Command{
			Name:   name,
			Usage:  fmt.Sprintf("Run the %s agent in a sandbox [-- agent-flags...]", name),
			Action: runAgent(name, cfg),
		})
	}
	return cmds
}

func runAgent(agName string, cfg Config) ucli.ActionFunc {
	return func(ctx context.Context, cmd *ucli.Command) error {
		rt, err := resolveRuntime(cmd)
		if err != nil {
			return err
		}
		rt.SetDebug(cmd.String("log-level") == "debug")

		ag, err := agent.Get(agName)
		if err != nil {
			return err
		}

		workdir := cmd.String("workdir")
		if workdir == "" {
			workdir, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("getwd: %w", err)
			}
		}
		workdir, err = filepath.Abs(workdir)
		if err != nil {
			return fmt.Errorf("abs: %w", err)
		}

		opts := sandbox.Options{
			AgentAllow:     cmd.String("agent-allow"),
			AgentArgs:      cmd.Args().Slice(),
			AgentImage:     resolveAgentImage(cmd.String("agent-image"), cfg, agName),
			AgentPolicy:    cmd.String("agent-policy"),
			AllowHooks:     cmd.Bool("allow-hooks"),
			CPUs:           cmd.Int("cpus"),
			EnableTripwire: cmd.Bool("tripwire"),
			GH:             cmd.Bool("gh"),
			GitConfig:      cmd.Bool("gitconfig"),
			MaskPaths:      append(cfg.MaskPaths, cmd.StringSlice("mask")...),
			Memory:         cmd.String("memory"),
			PodPolicy:      cmd.String("pod-policy"),
			ProxyImage:     cmd.String("proxy-image"),
			ProtectPaths:   append(cfg.ProtectPaths, cmd.StringSlice("protect")...),
			RegistryAuth:   cmd.Bool("registry-auth"),
			RequireDigest:  cmd.String("require-digest"),
			SidecarImage:   cmd.String("sidecar-image"),
			SSH:            cmd.Bool("ssh"),
			UnmaskPaths:    append(cfg.UnmaskPaths, cmd.StringSlice("unmask")...),
			Workdir:        workdir,
		}

		sessionID, err := sandbox.Run(ctx, rt, ag, opts)
		if sessionID != "" {
			session.TeardownIfExited(ctx, rt, sessionID)
		}
		return err
	}
}

func resolveRuntime(cmd *ucli.Command) (container.Runtime, error) {
	rtName := cmd.String("runtime")
	if rtName != "" {
		return container.ForName(rtName)
	}
	return container.Detect()
}

func listSessions(ctx context.Context, cmd *ucli.Command) error {
	rt, err := resolveRuntime(cmd)
	if err != nil {
		return err
	}
	all, err := session.List(ctx, rt)
	if err != nil {
		return err
	}
	if cmd.Bool("all") {
		session.Print(all)
		return nil
	}
	var running []session.Session
	for _, s := range all {
		if s.State == "running" {
			running = append(running, s)
		}
	}
	if len(running) == 0 && len(all) > 0 {
		fmt.Fprintln(os.Stdout, "No running sessions. Use --all to see stopped sessions.")
		return nil
	}
	session.Print(running)
	return nil
}

func attachSession(ctx context.Context, cmd *ucli.Command) error {
	rt, err := resolveRuntime(cmd)
	if err != nil {
		return err
	}

	sessionID := cmd.String("session")
	opts := sandbox.Options{
		EnableTripwire: cmd.Bool("tripwire"),
		Workdir:        cmd.String("workdir"),
	}
	if opts.Workdir == "" {
		opts.Workdir, _ = os.Getwd()
	}

	err = sandbox.Attach(ctx, rt, sessionID, opts)
	session.TeardownIfExited(ctx, rt, sessionID)
	return err
}

func stopSession(ctx context.Context, cmd *ucli.Command) error {
	rt, err := resolveRuntime(cmd)
	if err != nil {
		return err
	}
	sessionID := cmd.String("session")
	sandbox.DumpSessionAudit(ctx, rt, sessionID)
	sandbox.CleanupSessionFiles(ctx, rt, sessionID)
	return session.Stop(ctx, rt, sessionID)
}

func deleteSession(ctx context.Context, cmd *ucli.Command) error {
	rt, err := resolveRuntime(cmd)
	if err != nil {
		return err
	}
	sessionID := cmd.String("session")
	sandbox.CleanupSessionFiles(ctx, rt, sessionID)
	return session.Delete(ctx, rt, sessionID)
}

func showLogs(ctx context.Context, cmd *ucli.Command) error {
	rt, err := resolveRuntime(cmd)
	if err != nil {
		return err
	}
	ctrs, err := session.FindContainers(ctx, rt, cmd.String("session"))
	if err != nil {
		return err
	}
	dumpAgent := cmd.Bool("dump-agent-conversation")
	var lines []string
	for _, ctr := range ctrs {
		isAgent := ctr.Role != "sidecar" && ctr.Role != "proxy"
		if isAgent && !dumpAgent {
			continue
		}
		logs, logErr := rt.Logs(ctx, ctr.Name)
		if logErr != nil {
			continue
		}
		// Logs() returns --timestamps output: each line is prefixed
		// with an RFC3339Nano timestamp by the container runtime.
		for line := range strings.SplitSeq(string(logs), "\n") {
			if line == "" {
				continue
			}
			if isAgent || strings.Contains(line, "clampdown:") {
				lines = append(lines, line)
			}
		}
	}
	// Runtime timestamps (RFC3339Nano prefix) make lexicographic
	// sort produce chronological order across all containers.
	slices.Sort(lines)
	for _, line := range lines {
		stripped := sandbox.StripRuntimeTimestamp(line)
		if strings.HasPrefix(stripped, "clampdown:") {
			fmt.Fprintln(os.Stdout, stripped)
		} else {
			// Agent line: keep runtime timestamp for postmortem
			// correlation. Strip ANSI escapes, replace control
			// characters with spaces.
			clean := sandbox.CleanTerminalLine(line)
			content := strings.TrimSpace(sandbox.StripRuntimeTimestamp(clean))
			if !hasAlphanum(content) {
				continue
			}
			if utf8.RuneCountInString(content) < 4 {
				continue
			}
			fmt.Fprintln(os.Stdout, clean)
		}
	}
	return nil
}

// hasAlphanum reports whether s contains at least one letter or digit.
func hasAlphanum(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func findSidecar(ctx context.Context, cmd *ucli.Command) (container.Runtime, string, error) {
	rt, err := resolveRuntime(cmd)
	if err != nil {
		return nil, "", err
	}
	sidecar, err := session.FindSidecar(ctx, rt, cmd.String("session"))
	if err != nil {
		return nil, "", err
	}
	return rt, sidecar, nil
}

func networkAgentAllow(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	targets := cmd.Args().Slice()
	if len(targets) == 0 {
		return errors.New("at least one host[:port] target required")
	}
	statePath, err := findStatePath(ctx, rt, sidecar)
	if err != nil {
		return err
	}
	return network.AgentAllow(ctx, rt, sidecar, statePath, targets)
}

func networkAgentBlock(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	targets := cmd.Args().Slice()
	if len(targets) == 0 {
		return errors.New("at least one host[:port] target required")
	}
	statePath, err := findStatePath(ctx, rt, sidecar)
	if err != nil {
		return err
	}
	return network.AgentBlock(ctx, rt, sidecar, statePath, targets)
}

func networkPodAllow(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	targets := cmd.Args().Slice()
	if len(targets) == 0 {
		return errors.New("at least one host[:port] target required")
	}
	statePath, err := findStatePath(ctx, rt, sidecar)
	if err != nil {
		return err
	}
	return network.PodAllow(ctx, rt, sidecar, statePath, targets)
}

func networkPodBlock(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	targets := cmd.Args().Slice()
	if len(targets) == 0 {
		return errors.New("at least one host[:port] target required")
	}
	statePath, err := findStatePath(ctx, rt, sidecar)
	if err != nil {
		return err
	}
	return network.PodBlock(ctx, rt, sidecar, statePath, targets)
}

func networkAgentReset(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	statePath, err := findStatePath(ctx, rt, sidecar)
	if err != nil {
		return err
	}
	return network.AgentReset(ctx, rt, sidecar, statePath)
}

func networkPodReset(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	statePath, err := findStatePath(ctx, rt, sidecar)
	if err != nil {
		return err
	}
	return network.PodReset(ctx, rt, sidecar, statePath)
}

func networkList(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	statePath, err := findStatePath(ctx, rt, sidecar)
	if err != nil {
		return err
	}
	return network.ListRules(statePath)
}

// findStatePath discovers the firewall state file for a session by reading
// the sidecar container's workdir label and computing the state directory.
func findStatePath(ctx context.Context, rt container.Runtime, sidecar string) (string, error) {
	// Extract session ID from sidecar name to find its labels.
	sessionID := ""
	parts := strings.Split(sidecar, "-")
	if len(parts) >= 2 {
		sessionID = parts[1]
	}
	if sessionID == "" {
		return "", fmt.Errorf("cannot extract session ID from sidecar name %q", sidecar)
	}

	containers, err := rt.List(ctx, map[string]string{"clampdown.session": sessionID})
	if err != nil {
		return "", fmt.Errorf("list containers: %w", err)
	}

	for _, c := range containers {
		workdir := c.Labels["clampdown.workdir"]
		if workdir == "" {
			continue
		}
		paths := sandbox.GenPaths(rt.Name(), workdir)
		return filepath.Join(paths.State, "firewall.json"), nil
	}

	return "", fmt.Errorf("no container with workdir label found for session %s", sessionID)
}

func imagePush(ctx context.Context, cmd *ucli.Command) error {
	images := cmd.Args().Slice()
	if len(images) == 0 {
		return errors.New("at least one image required")
	}

	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}

	env := map[string]string{"CONTAINER_HOST": container.SidecarAPI}
	var needed []string
	for _, img := range images {
		hostID, _ := rt.ImageID(ctx, img)
		if hostID == "" {
			needed = append(needed, img)
			continue
		}
		out, execErr := rt.Exec(ctx, sidecar, []string{
			"/usr/local/bin/podman", "image", "inspect", "--format", "{{.Id}}", img,
		}, env)
		if execErr != nil {
			needed = append(needed, img)
			continue
		}
		if hostID == strings.TrimSpace(string(out)) {
			slog.Info("skipped (already present)", "image", img)
			continue
		}
		needed = append(needed, img)
	}

	if len(needed) == 0 {
		slog.Info("all images already present")
		return nil
	}

	slog.Info("pushing images", "count", len(needed))
	err = rt.PushImage(ctx, sidecar, needed)
	if err != nil {
		return err
	}
	for _, img := range needed {
		_ = rt.Log(ctx, sidecar, "image", fmt.Sprintf("PUSH %s", img))
	}
	return nil
}

func prune(ctx context.Context, cmd *ucli.Command) error {
	rt, err := resolveRuntime(cmd)
	if err != nil {
		return err
	}
	workdir := cmd.String("workdir")
	if workdir == "" {
		workdir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("getwd: %w", err)
		}
	}
	workdir, err = filepath.Abs(workdir)
	if err != nil {
		return fmt.Errorf("abs: %w", err)
	}
	dir := sandbox.ProjectDir(workdir)
	err = rt.Prune(ctx, dir)
	if err != nil {
		return fmt.Errorf("prune: %w", err)
	}
	slog.Info("pruned project cache", "dir", dir)
	return nil
}

func defaultStr(val, fallback string) string {
	if val != "" {
		return val
	}
	return fallback
}

func defaultInt(val, fallback int) int {
	if val != 0 {
		return val
	}
	return fallback
}

// resolveAgentImage picks the image for an agent: --agent-image CLI flag
// wins, then cfg.AgentImages[agName], else empty (sandbox falls back to
// the agent's built-in default).
func resolveAgentImage(flagVal string, cfg Config, agName string) string {
	if flagVal != "" {
		return flagVal
	}
	return cfg.AgentImages[agName]
}
