// SPDX-License-Identifier: GPL-3.0-only

package session

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/89luca89/clampdown/pkg/container"
	"github.com/89luca89/clampdown/pkg/sandbox"
)

// Session holds display info for a running sandbox session.
type Session struct {
	Agent       string
	AgentPolicy string
	ID          string
	PodPolicy   string
	State       string
	Uptime      time.Duration
	Workdir     string
}

// List returns all running sandbox sessions.
func List(ctx context.Context, rt container.Runtime) ([]Session, error) {
	infos, err := rt.List(ctx, map[string]string{
		"clampdown":      sandbox.AppName,
		"clampdown.role": "sidecar",
	})
	if err != nil {
		return nil, err
	}
	sessions := make([]Session, 0, len(infos))
	for _, info := range infos {
		uptime := time.Duration(0)
		if info.StartedAt > 0 {
			uptime = time.Since(time.Unix(info.StartedAt, 0))
		}
		sessions = append(sessions, Session{
			Agent:       info.Labels["clampdown.agent"],
			AgentPolicy: info.Labels["clampdown.agent_policy"],
			ID:          info.Labels["clampdown.session"],
			PodPolicy:   info.Labels["clampdown.pod_policy"],
			State:       info.State,
			Uptime:      uptime,
			Workdir:     info.Labels["clampdown.workdir"],
		})
	}
	return sessions, nil
}

// FindSidecar resolves a session ID to a sidecar container name.
func FindSidecar(ctx context.Context, rt container.Runtime, sessionID string) (string, error) {
	labels := map[string]string{
		"clampdown":         sandbox.AppName,
		"clampdown.role":    "sidecar",
		"clampdown.session": sessionID,
	}
	infos, err := rt.List(ctx, labels)
	if err != nil {
		return "", err
	}
	if len(infos) == 0 {
		return "", fmt.Errorf("no running session %s found", sessionID)
	}
	return infos[0].Name, nil
}

// Delete stops and removes all containers for a session.
func Delete(ctx context.Context, rt container.Runtime, sessionID string) error {
	infos, err := rt.List(ctx, map[string]string{
		"clampdown":         sandbox.AppName,
		"clampdown.session": sessionID,
	})
	if err != nil {
		return err
	}
	if len(infos) == 0 {
		return fmt.Errorf("no containers found for session %s", sessionID)
	}

	// Remove agents before sidecars — the agent's network namespace
	// depends on the sidecar, so the sidecar can't be removed first.
	var agents, sidecars []string
	for _, info := range infos {
		if info.Labels["clampdown.role"] == "sidecar" {
			sidecars = append(sidecars, info.Name)
		} else {
			agents = append(agents, info.Name)
		}
	}

	err = rt.Remove(ctx, append(agents, sidecars...)...)
	if err != nil {
		return fmt.Errorf("remove containers: %w", err)
	}
	slog.Info("removed session containers", "count", len(agents)+len(sidecars), "session", sessionID)
	return nil
}

// Print writes a formatted session table to stderr.
func Print(sessions []Session) {
	if len(sessions) == 0 {
		fmt.Fprintln(os.Stderr, "No running sessions.")
		return
	}
	w := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SESSION\tAGENT\tWORKDIR\tSTATUS\tAGENTNET\tPODNET\tUPTIME")
	for _, s := range sessions {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			s.ID, s.Agent, s.Workdir, s.State, s.AgentPolicy, s.PodPolicy, FormatDuration(s.Uptime))
	}
	w.Flush()
}

func FormatDuration(d time.Duration) string {
	d = d.Truncate(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm", m)
	}
	return "<1m"
}
