// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/89luca89/clampdown/pkg/agent"
	"github.com/89luca89/clampdown/pkg/container"
	"github.com/89luca89/clampdown/pkg/sandbox/mounts"
	"github.com/89luca89/clampdown/pkg/sandbox/seccomp"
	"github.com/89luca89/clampdown/pkg/sandbox/tripwire"
)

const (
	containerPrefix  = AppName
	readinessTimeout = 5
	sidecarPIDLimit  = 512
	agentPIDLimit    = 2048
)

// Options configures a sandbox run.
type Options struct {
	AgentAllow      string
	AgentArgs       []string
	AgentPolicy     string
	AllowHooks      bool
	CPUs            string
	DisableTripwire bool
	GH              bool
	MaskPaths       []string
	GitConfig       bool
	Memory          string
	PodPolicy       string
	ProtectPaths    []string
	RegistryAuth    bool
	RequireDigest   string
	SSH             bool
	Workdir         string
}

// errTamper is returned when the watcher detects modification of a
// read-only host path, indicating a possible container escape.
var errTamper = errors.New("session killed: read-only path tampered")

// Run starts the sidecar and agent, blocking until the agent exits.
func Run(ctx context.Context, rt container.Runtime, ag agent.Agent, opts Options) error {
	// We need landlock, fail if not present.
	err := checkLandlock()
	if err != nil {
		return err
	}

	checkYama()

	// Resolve workdir: if HOME, use scratch dir.
	if opts.Workdir == Home {
		opts.Workdir = filepath.Join(os.TempDir(), AppName, "scratch")
		err = os.MkdirAll(opts.Workdir, 0o750)
		if err != nil {
			return fmt.Errorf("create scratch dir: %w", err)
		}
	}

	p := GenPaths(rt.Name(), opts.Workdir)
	err = EnsurePaths(p)
	if err != nil {
		return err
	}

	rcEnv, err := LoadRC(opts.Workdir)
	if err != nil {
		return fmt.Errorf(".clampdownrc: %w", err)
	}

	sidecarSeccomp, agentSeccomp, err := seccomp.EnsureProfiles(DataDir)
	if err != nil {
		return fmt.Errorf("seccomp profiles: %w", err)
	}

	warnIfRootful(ctx, rt)

	rt.CleanStale(ctx, containerPrefix)

	pid := os.Getpid()
	sidecarName := fmt.Sprintf("%s-%d-sidecar", containerPrefix, pid)
	agentName := fmt.Sprintf("%s-%d-%s", containerPrefix, pid, ag.Name())

	// Write sandbox prompt to persistent HOME before building mounts so
	// HOME-relative protected paths exist when ProtectMount runs.
	err = WriteSandboxPrompt(ag, p.Home)
	if err != nil {
		return fmt.Errorf("sandbox prompt: %w", err)
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

	// Build masked path list (universal + user --mask flags).
	masked := make([]agent.MaskedPath, len(mounts.UniversalMaskedPaths))
	copy(masked, mounts.UniversalMaskedPaths)
	for _, raw := range opts.MaskPaths {
		masked = append(masked, agent.MaskedPath{
			Path:  strings.TrimSuffix(raw, "/"),
			IsDir: strings.HasSuffix(raw, "/"),
		})
	}

	// Sidecar masked mounts (creates host placeholders for cleanup).
	sidecarMasks, maskCreated := SidecarMaskedPaths(opts.Workdir, masked)

	mnts, mountCreated, err := mounts.Build(opts.Workdir, p.Home, Home, ag, protection, masked)
	created := append(maskCreated, mountCreated...)
	if err != nil {
		for _, c := range created {
			_ = os.RemoveAll(c)
		}
		return fmt.Errorf("build mounts: %w", err)
	}

	// Ensure agent TMPDIR exists in persistent HOME (Bun extracts .so here).
	tmpdir := ag.Env()["TMPDIR"]
	if tmpdir != "" {
		rel, _ := filepath.Rel(agent.Home, tmpdir)
		_ = os.MkdirAll(filepath.Join(p.Home, rel), 0o750)
	}

	// Clean up per-session tool cache home created by nested containers.
	created = append(created, filepath.Join(opts.Workdir, "."+ag.Name(), strconv.Itoa(pid)))

	// runCtx is cancelled on SIGINT/SIGTERM or tripwire tamper detection.
	// Cancelling it kills the podman process via exec.CommandContext,
	// so cmd.Run() returns immediately instead of blocking.
	runCtx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(nil)

	// Host-side tripwire: monitors all read-only mount sources on the host
	// via inotify. Snapshots files before launch, restores on exit.
	// Any modification kills the session immediately.
	// Disabled with --disable-tripwire.
	var tw *tripwire.Tripwire
	if !opts.DisableTripwire {
		var watchErr error
		tw, watchErr = tripwire.Start(tripwire.HostPaths(mnts), func(path string) {
			slog.Error("read-only path tampered", "path", path)
			cancelRun(fmt.Errorf("tampered: %s", path))
		})
		if watchErr != nil {
			return fmt.Errorf("tripwire: %w", watchErr)
		}
	}

	// Determine active proxy route (first matching key from host env + rcEnv).
	// Nil means no API key is set — the agent starts without a proxy (e.g.,
	// Claude OAuth login).
	proxyRoute := ActiveProxyRoute(ag, rcEnv)
	if proxyRoute == nil && len(ag.ProxyRoutes()) > 0 {
		slog.Warn("no API key found — starting without auth proxy",
			"agent", ag.Name())
	}

	proxyName := ""
	if proxyRoute != nil {
		proxyName = fmt.Sprintf("%s-%d-proxy", containerPrefix, pid)
	}

	var once sync.Once
	sigCh := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer func() {
		signal.Stop(sigCh)
		close(done)
		// Stop the tripwire before cleanup so that cleanup's removal of
		// DevNull placeholder files (paths that didn't exist at session start)
		// doesn't fire a spurious "read-only path tampered" error.
		if tw != nil {
			tw.Stop()
		}
		cleanup(&once, rt, agentName, proxyName, sidecarName, created)
	}()
	go func() {
		select {
		case <-sigCh:
			if tw != nil {
				tw.Stop()
			}
			cleanup(&once, rt, agentName, proxyName, sidecarName, created)
			os.Exit(1)
		case <-done:
		}
	}()

	sidecarCfg := sidecarConfig(sidecarName, pid, opts, p, sidecarSeccomp, ag, masked)
	sidecarCfg.Mounts = CredentialMounts(opts)
	sidecarCfg.MaskedPaths = sidecarMasks

	slog.Info("starting container sidecar")
	err = rt.StartSidecar(runCtx, sidecarCfg)
	if err != nil {
		return fmt.Errorf("start sidecar: %w", err)
	}

	slog.Info("waiting for container API")
	err = waitReady(runCtx, rt, sidecarName)
	if err != nil {
		logs, _ := rt.Logs(ctx, sidecarName)
		if len(logs) > 0 {
			slog.Error("sidecar logs", "output", string(logs))
		}
		return err
	}
	slog.Info("container API ready")

	// Start auth proxy if a proxy route is active.
	if proxyRoute != nil {
		proxyCfg := ProxyConfig(
			proxyName, sidecarName, pid, opts,
			ag, proxyRoute, agentSeccomp, rcEnv,
		)
		slog.Info("starting auth proxy", "upstream", proxyRoute.Upstream)
		err = rt.StartProxy(runCtx, proxyCfg)
		if err != nil {
			return fmt.Errorf("start proxy: %w", err)
		}

		err = waitProxyReady(runCtx, rt, proxyName)
		if err != nil {
			logs, _ := rt.Logs(ctx, proxyName)
			if len(logs) > 0 {
				slog.Error("proxy logs", "output", string(logs))
			}
			return err
		}
		slog.Info("auth proxy ready")
	}

	agentCfg := agentConfig(
		agentName, sidecarName, pid, opts,
		ag, mnts, agentSeccomp,
		p.Home, proxyRoute,
	)

	err = rt.StartAgent(runCtx, agentCfg)

	// If the context was cancelled by the watcher, the agent was killed
	// due to tamper detection. Return a specific error so the caller
	// knows this wasn't a normal exit. The deferred cleanup runs after
	// this return: containers removed, permissions restored.
	if context.Cause(runCtx) != nil {
		return errTamper
	}
	return err
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

func cleanup(once *sync.Once, rt container.Runtime, agentName, proxyName, sidecar string, created []string) {
	once.Do(func() {
		// Remove order: agent → proxy → sidecar.
		// Agent depends on sidecar's network namespace; proxy does too.
		names := []string{agentName}
		if proxyName != "" {
			names = append(names, proxyName)
		}
		names = append(names, sidecar)
		_ = rt.Remove(context.Background(), names...)
		for _, p := range created {
			_ = os.RemoveAll(p)
		}
	})
}

// waitProxyReady polls the proxy container logs for the "proxy: ready" line.
func waitProxyReady(ctx context.Context, rt container.Runtime, proxyName string) error {
	for range readinessTimeout {
		logs, err := rt.Logs(ctx, proxyName)
		if err == nil {
			match, err := regexp.MatchString("proxy:.*ready", string(logs))
			if err == nil && match {
				return nil
			}
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

// checkLandlock verifies Landlock LSM is available on the host kernel.
//
// Hard-fails if Landlock is confirmed absent (file readable, not in list).
// Warns if /sys/kernel/security/lsm is unreadable (can't confirm — let
// seal do the final enforcement inside the container).
// Warns if kernel < 6.12 (Landlock present but lacks IPC + TCP scoping).
func checkLandlock() error {
	lsm, readErr := os.ReadFile("/sys/kernel/security/lsm")
	if readErr != nil {
		// Can't read LSM list (unusual — maybe container-in-container).
		// Warn and continue; seal will hard-fail inside if Landlock is truly absent.
		fmt.Fprintf(os.Stderr, "\n"+
			"  ⚠️  Cannot read /sys/kernel/security/lsm.\n"+
			"  Landlock availability unknown. If Landlock is missing,\n"+
			"  the sandbox will fail when the agent starts.\n\n")
		return nil //nolint:nilerr // intentional: warn and let seal enforce inside container
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
	var buf syscall.Utsname
	err := syscall.Uname(&buf)
	if err != nil {
		return 0, 0
	}

	// buf.Release is [65]int8, e.g. "6.7.4-200.fc39.x86_64".
	var release []byte
	for _, b := range buf.Release {
		if b == 0 {
			break
		}
		release = append(release, byte(b))
	}

	var major, minor int
	_, err = fmt.Sscanf(string(release), "%d.%d", &major, &minor)
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
func checkYama() {
	scope, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		// Yama not present or /proc not accessible.
		fmt.Fprintf(os.Stderr, "\n"+
			"  ⚠️  Yama LSM not detected (/proc/sys/kernel/yama/ptrace_scope unreadable).\n"+
			"  ptrace is blocked by seccomp, but Yama provides independent\n"+
			"  defense-in-depth against ptrace-based escapes.\n"+
			"  Enable Yama: boot with lsm=...,yama or set CONFIG_SECURITY_YAMA=y.\n\n")
		return
	}

	val := strings.TrimSpace(string(scope))
	if val == "0" {
		fmt.Fprintf(os.Stderr, "\n"+
			"  ⚠️  Yama ptrace_scope is 0 (permissive).\n"+
			"  Any same-UID process can ptrace any other.\n"+
			"  ptrace is blocked by seccomp, but Yama is independent defense-in-depth.\n"+
			"  Recommend: echo 1 > /proc/sys/kernel/yama/ptrace_scope\n\n")
	}
}
