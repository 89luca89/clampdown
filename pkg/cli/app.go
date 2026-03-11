// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

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
				Name:  "disable-tripwire",
				Value: cfg.DisableTripwire,
				Usage: "Don't kill session on protected path modification (still restores on exit)",
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
				Usage:   "Additional domains for agent allowlist (comma-separated)",
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
			&ucli.StringFlag{
				Name:    "cpus",
				Value:   defaultStr(cfg.CPUs, "4"),
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
		},
		Commands: append(agentCommands(cfg),
			&ucli.Command{
				Name:   "list",
				Usage:  "List running sandbox sessions",
				Action: listSessions,
			},
			&ucli.Command{
				Name:   "delete",
				Usage:  "Stop a session and remove its containers and cache",
				Flags:  []ucli.Flag{sessionFlag()},
				Action: deleteSession,
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
								Usage:     "Allow agent traffic to a host/CIDR on specific ports",
								ArgsUsage: "<target> [target...]",
								Flags:     []ucli.Flag{sessionFlag(), portFlag()},
								Action:    networkAgentAllow,
							},
							{
								Name:      "block",
								Usage:     "Block agent traffic to a host/CIDR on specific ports",
								ArgsUsage: "<target> [target...]",
								Flags:     []ucli.Flag{sessionFlag(), portFlag()},
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
								Usage:     "Allow pod traffic to a host/CIDR on specific ports",
								ArgsUsage: "<target> [target...]",
								Flags:     []ucli.Flag{sessionFlag(), portFlag()},
								Action:    networkPodAllow,
							},
							{
								Name:      "block",
								Usage:     "Block pod traffic to a host/CIDR on specific ports",
								ArgsUsage: "<target> [target...]",
								Flags:     []ucli.Flag{sessionFlag(), portFlag()},
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

func portFlag() *ucli.StringFlag {
	return &ucli.StringFlag{
		Name:     "port",
		Usage:    "Port(s) to allow/block (comma-separated, e.g. 443 or 80,443)",
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
			AgentAllow:      cmd.String("agent-allow"),
			AgentArgs:       cmd.Args().Slice(),
			AgentPolicy:     cmd.String("agent-policy"),
			AllowHooks:      cmd.Bool("allow-hooks"),
			CPUs:            cmd.String("cpus"),
			DisableTripwire: cmd.Bool("disable-tripwire"),
			GH:              cmd.Bool("gh"),
			GitConfig:       cmd.Bool("gitconfig"),
			MaskPaths:       append(cfg.MaskPaths, cmd.StringSlice("mask")...),
			Memory:          cmd.String("memory"),
			PodPolicy:       cmd.String("pod-policy"),
			ProtectPaths:    append(cfg.ProtectPaths, cmd.StringSlice("protect")...),
			RegistryAuth:    cmd.Bool("registry-auth"),
			RequireDigest:   cmd.String("require-digest"),
			SSH:             cmd.Bool("ssh"),
			Workdir:         workdir,
		}

		return sandbox.Run(ctx, rt, ag, opts)
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
	sessions, err := session.List(ctx, rt)
	if err != nil {
		return err
	}
	session.Print(sessions)
	return nil
}

func deleteSession(ctx context.Context, cmd *ucli.Command) error {
	rt, err := resolveRuntime(cmd)
	if err != nil {
		return err
	}
	return session.Delete(ctx, rt, cmd.String("session"))
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
		return errors.New("at least one host/IP/CIDR required")
	}
	return network.AgentAllow(ctx, rt, sidecar, targets, cmd.String("port"))
}

func networkAgentBlock(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	targets := cmd.Args().Slice()
	if len(targets) == 0 {
		return errors.New("at least one host/IP/CIDR required")
	}
	return network.AgentBlock(ctx, rt, sidecar, targets, cmd.String("port"))
}

func networkPodAllow(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	targets := cmd.Args().Slice()
	if len(targets) == 0 {
		return errors.New("at least one host/IP/CIDR required")
	}
	return network.PodAllow(ctx, rt, sidecar, targets, cmd.String("port"))
}

func networkPodBlock(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	targets := cmd.Args().Slice()
	if len(targets) == 0 {
		return errors.New("at least one host/IP/CIDR required")
	}
	return network.PodBlock(ctx, rt, sidecar, targets, cmd.String("port"))
}

func networkAgentReset(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	return network.AgentReset(ctx, rt, sidecar)
}

func networkPodReset(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	return network.PodReset(ctx, rt, sidecar)
}

func networkList(ctx context.Context, cmd *ucli.Command) error {
	rt, sidecar, err := findSidecar(ctx, cmd)
	if err != nil {
		return err
	}
	return network.ListRules(ctx, rt, sidecar)
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
	return rt.PushImage(ctx, sidecar, needed)
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
