// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/89luca89/clampdown/pkg/agent"
	"github.com/89luca89/clampdown/pkg/container"
	"github.com/89luca89/clampdown/pkg/sandbox/mounts"
	"github.com/89luca89/clampdown/pkg/sandbox/network"
	"github.com/89luca89/clampdown/pkg/sandbox/seccomp"
	"github.com/89luca89/clampdown/pkg/sandbox/tripwire"
)

const (
	containerPrefix  = AppName
	readinessTimeout = 5
	agentPIDLimit    = 2048
	proxyPIDLimit    = 512
	sidecarPIDLimit  = 4096
)

// Options configures a sandbox run.
type Options struct {
	AgentAllow     string
	AgentArgs      []string
	AgentImage     string
	AgentPolicy    string
	AllowHooks     bool
	CPUs           string
	EnableTripwire bool
	GH             bool
	MaskPaths      []string
	GitConfig      bool
	Memory         string
	PodPolicy      string
	ProxyImage     string
	ProtectPaths   []string
	RegistryAuth   bool
	RequireDigest  string
	SidecarImage   string
	SSH            bool
	UnmaskPaths    []string
	Workdir        string
}

// SessionState persists session metadata for stop/delete operations.
// Stored at $STATE/session-<id>.json.
type SessionState struct {
	ID      string   `json:"id"`
	Agent   string   `json:"agent"`
	Workdir string   `json:"workdir"`
	Created []string `json:"created"`
	Audit   string   `json:"audit"`
}

// generateSessionID returns a 6-character random hex string.
func generateSessionID() (string, error) {
	var b [3]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Run starts a new session and attaches to it. This is the default path
// for `clampdown <agent>` — start everything, then connect the terminal.
// Returns the session ID so the caller can perform post-attach lifecycle
// cleanup (e.g., tear down infrastructure when the agent exits).
func Run(ctx context.Context, rt container.Runtime, ag agent.Agent, opts Options) (string, error) {
	sessionID, err := Start(ctx, rt, ag, opts)
	if err != nil {
		return "", err
	}

	return sessionID, Attach(ctx, rt, sessionID, opts)
}

// Start creates all session containers (sidecar, proxy, agent) in detached
// mode. Returns the session ID. All containers use --restart=unless-stopped.
// On error mid-flow, partially created containers are cleaned up.
//
//nolint:gocognit,gocyclo,cyclop // Start orchestrates the full sandbox setup: sidecar, proxy, agent, firewall.
func Start(ctx context.Context, rt container.Runtime, ag agent.Agent, opts Options) (string, error) {
	err := runPreflightChecks(ctx, rt)
	if err != nil {
		return "", err
	}

	// Resolve workdir: if HOME, use scratch dir.
	if opts.Workdir == Home {
		opts.Workdir = filepath.Join(os.TempDir(), AppName, "scratch")
		err = os.MkdirAll(opts.Workdir, 0o750)
		if err != nil {
			return "", fmt.Errorf("create scratch dir: %w", err)
		}
	}

	p := GenPaths(rt.Name(), opts.Workdir)
	err = EnsurePaths(p)
	if err != nil {
		return "", err
	}

	rcEnv, err := LoadRC(opts.Workdir)
	if err != nil {
		return "", fmt.Errorf(".clampdownrc: %w", err)
	}

	sidecarSeccomp, agentSeccomp, err := seccomp.EnsureProfiles(DataDir)
	if err != nil {
		return "", fmt.Errorf("seccomp profiles: %w", err)
	}

	warnIfRootful(ctx, rt)

	rt.CleanStale(ctx, containerPrefix)

	sessionID, err := generateSessionID()
	if err != nil {
		return "", err
	}
	sidecarName := fmt.Sprintf("%s-%s-sidecar", containerPrefix, sessionID)
	agentName := fmt.Sprintf("%s-%s-%s", containerPrefix, sessionID, ag.Name())

	// Determine the active proxy route before writing agent config files so
	// agent-specific prep (e.g. Codex auth mode) can match the selected
	// credential source.
	proxyRoute := ActiveProxyRoute(ag, rcEnv)

	// Write sandbox prompt to persistent HOME before building mounts so
	// HOME-relative protected paths exist when ProtectMount runs.
	err = WriteSandboxPrompt(ag, p.Home)
	if err != nil {
		return "", fmt.Errorf("sandbox prompt: %w", err)
	}
	if ag.Name() == "codex" {
		err = agent.PrepareCodexHome(p.Home, proxyRoute)
		if err != nil {
			return "", fmt.Errorf("prepare codex home: %w", err)
		}
	}

	// Write cross-platform skills to both .claude/skills/ and .agents/skills/.
	err = WriteSkills(ag, p.Home)
	if err != nil {
		return "", fmt.Errorf("write skills: %w", err)
	}

	// Build protection mounts (must happen before cleanup is defined).
	protection := mounts.MergeProtection(opts.AllowHooks)
	for _, raw := range opts.ProtectPaths {
		isDir := strings.HasSuffix(raw, "/")
		protection = append(protection, agent.ProtectedPath{
			Path:  strings.TrimSuffix(raw, "/"),
			IsDir: isDir,
		})
	}

	// Build masked path list (universal + user --mask, minus --unmask).
	var masked []agent.MaskedPath
	for _, m := range mounts.UniversalMaskedPaths {
		if !slices.Contains(opts.UnmaskPaths, m.Path) {
			masked = append(masked, m)
		}
	}
	for _, raw := range opts.MaskPaths {
		masked = append(masked, agent.MaskedPath{
			Path:  strings.TrimSuffix(raw, "/"),
			IsDir: strings.HasSuffix(raw, "/"),
		})
	}

	// Sidecar masked mounts (creates host placeholders for cleanup).
	sidecarMasks, maskCreated := SidecarMaskedPaths(opts.Workdir, masked)

	mnts, mountCreated, err := mounts.Build(opts.Workdir, p.Home, Home, ag, protection, masked)
	created := maskCreated
	created = append(created, mountCreated...)
	if err != nil {
		for _, c := range created {
			_ = os.RemoveAll(c)
		}
		return "", fmt.Errorf("build mounts: %w", err)
	}

	// Update .git/info/exclude so placeholder files don't show as untracked.
	UpdateGitExclude(opts.Workdir, opts.ProtectPaths, opts.MaskPaths)

	// Ensure agent TMPDIR exists in persistent HOME (Bun extracts .so here).
	tmpdir := ag.Env()["TMPDIR"]
	if tmpdir != "" {
		rel, _ := filepath.Rel(agent.Home, tmpdir)
		_ = os.MkdirAll(filepath.Join(p.Home, rel), 0o750)
	}

	// Per-session tool cache home created by nested containers.
	created = append(created, filepath.Join(opts.Workdir, "."+ag.Name(), sessionID))

	// Audit log: persists after containers are removed.
	auditPath := filepath.Join(p.State, fmt.Sprintf("audit-%s.log", sessionID))
	auditFile, auditErr := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if auditErr != nil {
		return "", fmt.Errorf("audit log: %w", auditErr)
	}
	defer auditFile.Close()

	// Save session state for stop/delete.
	state := SessionState{
		ID:      sessionID,
		Agent:   ag.Name(),
		Workdir: opts.Workdir,
		Created: created,
		Audit:   auditPath,
	}
	err = saveSessionState(p.State, state)
	if err != nil {
		return "", fmt.Errorf("save session state: %w", err)
	}

	// Nil means no API key is set — the agent starts without a proxy (e.g.,
	// Claude OAuth login or Codex ChatGPT subscription auth).
	if proxyRoute == nil && len(ag.ProxyRoutes()) > 0 {
		slog.Warn("no API key found — starting without auth proxy",
			"agent", ag.Name())
	}

	proxyName := ""
	if proxyRoute != nil {
		proxyName = fmt.Sprintf("%s-%s-proxy", containerPrefix, sessionID)
	}

	// rollback removes partially created containers on startup failure.
	rollback := func() {
		//nolint:govet // redeclare to avoid override of the outer scope
		var err error
		names := []string{agentName}
		if proxyName != "" {
			names = append(names, proxyName)
		}
		names = append(names, sidecarName)

		err = rt.Stop(context.Background(), names...)
		if err != nil {
			slog.Debug("rollback: stop failed", "error", err)
		}
		err = rt.Remove(context.Background(), names...)
		if err != nil {
			slog.Debug("rollback: remove failed", "error", err)
		}
		for _, c := range created {
			err = os.RemoveAll(c)
			if err != nil {
				slog.Debug("rollback: cleanup failed", "path", c, "error", err)
			}
		}
		_ = os.Remove(sessionStatePath(p.State, sessionID)) // Best effort
	}

	sidecarCfg := sidecarConfig(sidecarName, sessionID, opts, p, sidecarSeccomp, ag, masked)

	// SSH agent forwarding requires a native runtime — Unix sockets
	// cannot cross the VM boundary (virtiofs/9p don't support them).
	if opts.SSH {
		native, _ := rt.IsNative(ctx)
		if !native {
			slog.Warn("--ssh: SSH agent forwarding is not supported" +
				"on VM-based runtimes (colima, podman machine). Skipping.")
			opts.SSH = false
		}
	}
	sidecarCfg.Mounts = CredentialMounts(opts)
	sidecarCfg.MaskedPaths = slices.Concat(sidecarMasks, hardenedMounts)

	slog.Info("starting container sidecar")
	err = rt.StartSidecar(ctx, sidecarCfg)
	if err != nil {
		rollback()
		return "", fmt.Errorf("start sidecar: %w", err)
	}

	slog.Info("waiting for container API")
	err = waitReady(ctx, rt, sidecarName)
	if err != nil {
		logs, _ := rt.Logs(ctx, sidecarName)
		if len(logs) > 0 {
			slog.Error("sidecar logs", "output", string(logs))
		}
		rollback()
		return "", err
	}
	slog.Info("container API ready")

	_ = rt.Log(ctx, sidecarName, "session",
		fmt.Sprintf("START agent=%s workdir=%s session=%s", ag.Name(), opts.Workdir, sessionID))

	// Build the full firewall ruleset now that the sidecar API is up.
	// The entrypoint set a deny-all baseline; we add the agent allowlist
	// and pod chains before any untrusted code starts.
	allowIPs := agentAllowIPs(ag, opts.AgentAllow)
	err = network.BuildAgentFirewall(ctx, rt, sidecarName, opts.AgentPolicy, allowIPs)
	if err != nil {
		rollback()
		return "", fmt.Errorf("agent firewall: %w", err)
	}
	err = network.BuildPodFirewall(ctx, rt, sidecarName, opts.PodPolicy)
	if err != nil {
		rollback()
		return "", fmt.Errorf("pod firewall: %w", err)
	}
	err = network.InitState(filepath.Join(p.State, "firewall.json"))
	if err != nil {
		rollback()
		return "", fmt.Errorf("init firewall state: %w", err)
	}

	// Start auth proxy if a proxy route is active.
	if proxyRoute != nil {
		proxyCfg := ProxyConfig(
			proxyName, sidecarName, sessionID, opts,
			ag, proxyRoute, agentSeccomp, rcEnv,
		)
		slog.Info("starting auth proxy", "upstream", proxyRoute.Upstream)
		err = rt.StartProxy(ctx, proxyCfg)
		if err != nil {
			rollback()
			return "", fmt.Errorf("start proxy: %w", err)
		}

		err = waitProxyReady(ctx, rt, proxyName)
		if err != nil {
			logs, _ := rt.Logs(ctx, proxyName)
			if len(logs) > 0 {
				slog.Error("proxy logs", "output", string(logs))
			}
			rollback()
			return "", err
		}
		slog.Info("auth proxy ready")
	}

	agentCfg := agentConfig(
		agentName, sidecarName, sessionID, opts,
		ag, mnts, agentSeccomp,
		p.Home, proxyRoute,
	)

	slog.Info("starting agent", "name", ag.Name())
	err = rt.StartAgent(ctx, agentCfg)
	if err != nil {
		rollback()
		return "", fmt.Errorf("start agent: %w", err)
	}

	slog.Info("session started", "session", sessionID)
	return sessionID, nil
}

// Attach connects the terminal to a running agent container. Blocks until
// the user detaches (ctrl-]) or the container exits. Does not clean up
// the session on return — the session persists for reattach or stop.
func Attach(ctx context.Context, rt container.Runtime, sessionID string, opts Options) error {
	agentName, running, err := findAgentState(ctx, rt, sessionID)
	if err != nil {
		return err
	}
	if !running {
		return fmt.Errorf("agent container %s is not running — use 'stop' or 'delete'", agentName)
	}

	// Host-side tripwire: monitors read-only mount sources via inotify.
	// Only active while attached (acceptable — tripwire is opt-in).
	var tw *tripwire.Tripwire
	if opts.EnableTripwire {
		p := GenPaths(rt.Name(), opts.Workdir)
		mnts, _, _ := mounts.Build(opts.Workdir, p.Home, Home, nil, nil, nil)
		var watchErr error
		tw, watchErr = tripwire.Start(tripwire.HostPaths(mnts), func(path string) {
			slog.Error("read-only path tampered", "path", path)
		})
		if watchErr != nil {
			slog.Warn("tripwire failed to start", "error", watchErr)
		}
	}

	slog.Info("attaching to session (detach: ctrl+])", "session", sessionID)
	err = rt.AttachAgent(ctx, agentName)

	if tw != nil {
		tw.Stop()
	}

	return err
}

// DumpSessionAudit writes container logs to the session's audit file.
func DumpSessionAudit(ctx context.Context, rt container.Runtime, sessionID string) {
	state, err := LoadSessionState(ctx, rt, sessionID)
	if err != nil {
		return
	}

	auditFile, err := os.OpenFile(state.Audit, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer auditFile.Close()

	sidecar, proxy := "", ""
	infos, _ := rt.List(ctx, map[string]string{
		"clampdown":         AppName,
		"clampdown.session": sessionID,
	})
	for _, info := range infos {
		switch info.Labels["clampdown.role"] {
		case "sidecar":
			sidecar = info.Name
		case "proxy":
			proxy = info.Name
		}
	}
	if sidecar == "" {
		return
	}

	dumpAuditLogs(ctx, rt, auditFile, sidecar, proxy)
}

// LoadSessionState reads the session state file for a given session.
// It discovers the state directory from the session's workdir label.
func LoadSessionState(ctx context.Context, rt container.Runtime, sessionID string) (*SessionState, error) {
	workdir, err := sessionWorkdir(ctx, rt, sessionID)
	if err != nil {
		return nil, err
	}

	p := GenPaths(rt.Name(), workdir)
	return loadSessionState(p.State, sessionID)
}

func sessionStatePath(stateDir, sessionID string) string {
	return filepath.Join(stateDir, fmt.Sprintf("session-%s.json", sessionID))
}

func saveSessionState(stateDir string, state SessionState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(sessionStatePath(stateDir, state.ID), data, 0o600)
}

func loadSessionState(stateDir, sessionID string) (*SessionState, error) {
	data, err := os.ReadFile(sessionStatePath(stateDir, sessionID))
	if err != nil {
		return nil, err
	}
	var state SessionState
	err = json.Unmarshal(data, &state)
	if err != nil {
		return nil, err
	}
	return &state, nil
}

// CleanupSessionFiles removes temp files and the session state file.
// Called by delete after containers have been removed.
func CleanupSessionFiles(ctx context.Context, rt container.Runtime, sessionID string) {
	state, err := LoadSessionState(ctx, rt, sessionID)
	if err != nil {
		return
	}

	for _, c := range state.Created {
		_ = os.RemoveAll(c)
	}

	workdir, wErr := sessionWorkdir(ctx, rt, sessionID)
	if wErr == nil {
		p := GenPaths(rt.Name(), workdir)
		_ = os.Remove(sessionStatePath(p.State, sessionID))
	}
}

// findAgentState returns the agent container name and whether it's running.
func findAgentState(ctx context.Context, rt container.Runtime, sessionID string) (string, bool, error) {
	infos, err := rt.List(ctx, map[string]string{
		"clampdown":         AppName,
		"clampdown.session": sessionID,
	})
	if err != nil {
		return "", false, err
	}
	for _, info := range infos {
		role := info.Labels["clampdown.role"]
		if role != "sidecar" && role != "proxy" {
			return info.Name, info.State == "running", nil
		}
	}
	return "", false, fmt.Errorf("no agent found for session %s", sessionID)
}

// sessionWorkdir extracts the workdir from a session's container labels.
func sessionWorkdir(ctx context.Context, rt container.Runtime, sessionID string) (string, error) {
	infos, err := rt.List(ctx, map[string]string{
		"clampdown":         AppName,
		"clampdown.session": sessionID,
	})
	if err != nil {
		return "", err
	}
	for _, info := range infos {
		w := info.Labels["clampdown.workdir"]
		if w != "" {
			return w, nil
		}
	}
	return "", fmt.Errorf("cannot determine workdir for session %s", sessionID)
}

func waitReady(ctx context.Context, rt container.Runtime, sidecar string) error {
	env := map[string]string{"CONTAINER_HOST": container.SidecarAPI}
	cmd := []string{"/usr/local/bin/podman", "info"}
	for range readinessTimeout {
		_, err := rt.Exec(ctx, sidecar, cmd, env)
		if err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("sidecar did not become ready within %ds", readinessTimeout)
}

var proxyReadyRe = regexp.MustCompile("proxy:.*ready")

// waitProxyReady polls the proxy container logs for the "proxy: ready" line.
func waitProxyReady(ctx context.Context, rt container.Runtime, proxyName string) error {
	for range readinessTimeout {
		logs, err := rt.Logs(ctx, proxyName)
		if err == nil && proxyReadyRe.Match(logs) {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("proxy did not become ready within %ds", readinessTimeout)
}

// warnIfRootful prints a warning when the container runtime runs as real root.
// A rootful runtime means the sidecar runs as real root on the host —
// a container escape gives full root access.
func warnIfRootful(ctx context.Context, rt container.Runtime) {
	rootless, err := rt.IsRootless(ctx)
	if err != nil || rootless {
		return
	}
	fmt.Fprintf(os.Stderr, "\n"+
		"  ⚠️  %s is running in rootful mode.\n"+
		"  The sidecar runs as real root on the host.\n"+
		"  A container escape gives full root access.\n"+
		"  Consider: podman (rootless by default) or Docker rootless mode.\n\n",
		rt.Name())
}

// runPreflightChecks runs host kernel safety checks (Landlock, Yama).
// Skipped when the container daemon runs on a different kernel (VM, remote),
// since host kernel state is irrelevant in that case.
func runPreflightChecks(ctx context.Context, rt container.Runtime) error {
	if rt.IsDockerDesktop(ctx) {
		fmt.Fprintf(os.Stderr, "\n"+
			"  Docker Desktop is not supported.\n"+
			"  Its fakeowner filesystem is incompatible with Landlock,\n"+
			"  leading to a degraded security posture for the sandbox.\n"+
			"  Use one of:\n"+
			"    colima start && docker context use colima\n"+
			"    podman machine start (and use podman runtime)\n\n")
		return errors.New("docker Desktop is not supported (see above)")
	}

	native, err := rt.IsNative(ctx)
	if err != nil {
		return err
	}

	if !native {
		return nil
	}

	err = CheckLandlock()
	if err != nil {
		return err
	}

	return checkYama()
}

// CheckLandlock verifies Landlock LSM is available on the host kernel.
//
// Hard-fails if Landlock is absent or cannot be confirmed.
// Warns if kernel < 6.12 (Landlock present but lacks IPC + TCP scoping).
func CheckLandlock() error {
	lsm, readErr := os.ReadFile("/sys/kernel/security/lsm")
	if readErr != nil {
		return fmt.Errorf("cannot read /sys/kernel/security/lsm: %w", readErr)
	}

	modules := strings.Split(strings.TrimSpace(string(lsm)), ",")
	if !slices.Contains(modules, "landlock") {
		return errors.New("landlock LSM is not enabled — boot with lsm=landlock or set CONFIG_LSM=landlock")
	}

	major, minor := kernelVersion()

	// Landlock IPC + TCP scoping requires kernel >= 6.12.
	// Warn if we can't determine the version (major == 0) or it's too old.
	if major == 0 || major < 6 || (major == 6 && minor < 12) {
		fmt.Fprintf(os.Stderr, "\n"+
			"  ⚠️  Kernel %d.%d lacks Landlock IPC and TCP scoping (needs 6.12+).\n"+
			"  Consider upgrading to kernel 6.12+ for full Landlock V6 support.\n\n",
			major, minor)
	}

	return nil
}

// kernelVersion returns the major and minor kernel version from uname.
// Returns (0, 0) on parse failure.
func kernelVersion() (int, int) {
	release := container.UnameRelease()
	if release == "" {
		return 0, 0
	}
	var major, minor int
	_, err := fmt.Sscanf(release, "%d.%d", &major, &minor)
	if err != nil {
		return 0, 0
	}
	return major, minor
}

// checkYama warns if Yama LSM ptrace_scope is 0 (permissive).
//
// ptrace is blocked by seccomp in workload profiles, but Yama is an
// independent enforcement point in a different kernel subsystem.
// If an attacker bypasses seccomp (kernel bug), Yama scope >= 1
// still restricts ptrace to descendants only.
//
// Advisory only — never blocks startup.
func checkYama() error {
	scope, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		// Yama not present or /proc not accessible.
		fmt.Fprintf(os.Stderr, "\n"+
			"  ⚠️  Yama LSM not detected (/proc/sys/kernel/yama/ptrace_scope unreadable).\n"+
			"  ptrace is blocked by seccomp, but Yama provides independent\n"+
			"  defense-in-depth against ptrace-based escapes.\n"+
			"  Enable Yama: boot with lsm=...,yama or set CONFIG_SECURITY_YAMA=y.\n\n")
		return nil //nolint:nilerr // advisory only, never blocks startup
	}

	val := strings.TrimSpace(string(scope))

	if val == "3" {
		fmt.Fprintf(os.Stderr, "\n"+
			"  yama ptrace_scope is 3 (no-attach).\n"+
			"  The seccomp-notif supervisor reads syscall arguments from\n"+
			"  /proc/<pid>/mem, which requires ptrace access. yama=3 blocks\n"+
			"  ALL cross-process memory reads — even with CAP_SYS_PTRACE.\n"+
			"  This disables the supervisor's path-based security checks\n"+
			"  (bind source allowlist, exec allowlist, protected paths, firewall lock).\n\n"+
			"  Set ptrace_scope to 1 or 2:\n"+
			"    echo 1 > /proc/sys/kernel/yama/ptrace_scope   (relational — parent can trace children)\n"+
			"    echo 2 > /proc/sys/kernel/yama/ptrace_scope   (capability — requires CAP_SYS_PTRACE)\n\n"+
			"  Both are compatible with clampdown. yama=1 is the recommended default.\n"+
			"  Note: yama=3 is write-once — if already set, a reboot with\n"+
			"  kernel.yama.ptrace_scope=1 in sysctl.conf is required.\n\n")
		return errors.New("yama ptrace_scope=3 is incompatible with the seccomp-notif supervisor (see above)")
	}

	return nil
}
