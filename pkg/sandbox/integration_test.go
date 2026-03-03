// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package sandbox_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/89luca89/clampdown/pkg/container"
	"github.com/89luca89/clampdown/pkg/sandbox"
	"github.com/89luca89/clampdown/pkg/sandbox/network"
	"github.com/89luca89/clampdown/pkg/sandbox/seccomp"
)

const (
	alpineImage       = "alpine"
	pythonAlpineImage = "python:alpine"
	isolatedImage     = "ghcr.io/edera-dev/am-i-isolated:nightly"
)

// Package-level state set by TestMain.
var (
	rt               container.Runtime
	sidecarName      string
	digestSidecar    string
	integSidecar     string
	workdir          string
	workdirDigest    string
	workdirInteg     string
	integGitconfig   string   // host-side gitconfig dir (contains gitconfig file)
	integGHDir       string   // host-side gh config dir
	integSocketPath  string   // host-side Unix socket for forwarding test
	integSocketLn    net.Listener
	innerPodman      = "/usr/local/bin/podman"
	innerEnv         = map[string]string{"CONTAINER_HOST": container.SidecarAPI}
)

// sidecarExec runs a command inside the given sidecar container.
func sidecarExec(t *testing.T, ctr string, cmd []string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return rt.Exec(ctx, ctr, cmd, innerEnv)
}

// sidecarExecTimeout is like sidecarExec but with a custom timeout.
func sidecarExecTimeout(t *testing.T, ctr string, cmd []string, timeout time.Duration) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return rt.Exec(ctx, ctr, cmd, innerEnv)
}

// innerRun builds a podman run command for execution inside the sidecar.
func innerRun(flags []string, cmd ...string) []string {
	args := []string{innerPodman, "run", "--rm"}
	args = append(args, flags...)
	args = append(args, alpineImage)
	args = append(args, cmd...)
	return args
}

// innerPull builds a podman pull command for execution inside the sidecar.
// --retry 0 avoids 3 default retries on network failure (saves ~80s when
// iptables blocks the connection).
func innerPull(image string) []string {
	return []string{innerPodman, "pull", "--retry", "0", image}
}

// requireFail asserts the command returned a non-zero exit code.
func requireFail(t *testing.T, out []byte, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected failure but command succeeded; output:\n%s", out)
	}
}

// requireSuccess asserts the command returned exit code zero.
func requireSuccess(t *testing.T, out []byte, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected success but got error: %v; output:\n%s", err, out)
	}
}

// waitReady polls the sidecar's podman API until it responds.
func waitReady(ctx context.Context, name string) error {
	cmd := []string{innerPodman, "info"}
	for range 10 {
		_, err := rt.Exec(ctx, name, cmd, innerEnv)
		if err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("sidecar %s not ready after 10s", name)
}

// sidecarCaps matches the 17 capabilities granted to the sidecar,
// identical to sandbox/config.go sidecarConfig().
var sidecarCaps = []string{
	"CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL",
	"LINUX_IMMUTABLE", "MKNOD",
	"NET_ADMIN", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP",
	"SETUID", "SYS_ADMIN", "SYS_CHROOT", "SYS_PTRACE", "SYS_RESOURCE",
}

func buildSidecarConfig(
	name, seccompPath string,
	p sandbox.ProjectPaths,
	wd string,
	env map[string]string,
) container.SidecarContainerConfig {
	return container.SidecarContainerConfig{
		Name:           name,
		Image:          "clampdown-sidecar:latest",
		Workdir:        wd,
		StorageDir:     p.Storage,
		CacheDir:       p.Cache,
		TempDir:        p.Temp,
		Capabilities:   sidecarCaps,
		Devices:        []string{"/dev/fuse"},
		SeccompProfile: seccompPath,
		Labels:         map[string]string{"clampdown": "integration-test"},
		Resources:      container.Resources{PIDLimit: 512},
		Env:            env,
	}
}

func TestMain(m *testing.M) {
	var err error
	rt, err = container.Detect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "skip: %v\n", err)
		os.Exit(0)
	}
	os.Exit(runTests(m))
}

// cleanStaleIntegContainers removes integration test containers leaked by
// previous runs. Covers both running containers (--restart=unless-stopped
// keeps them alive after test process death) and stopped/dead containers.
func cleanStaleIntegContainers(ctx context.Context) {
	// Running containers with the integration-test label.
	infos, err := rt.List(ctx, map[string]string{"clampdown": "integration-test"})
	if err == nil {
		for _, info := range infos {
			_ = rt.Remove(ctx, info.Name)
		}
	}
	// Exited/dead/created containers from previous runs.
	rt.CleanStale(ctx, "clampdown-integ")
}

// runTests sets up sidecars, runs tests, and returns the exit code.
// Cleanup is deferred so it runs on early returns, panics, and normal
// completion — the only case it misses is SIGKILL (uncatchable).
// cleanStaleIntegContainers handles leaks from that scenario on the
// next run.
func runTests(m *testing.M) (code int) {
	ctx := context.Background()
	cleanStaleIntegContainers(ctx)

	var dataDir string

	defer func() {
		var containers []string
		for _, name := range []string{sidecarName, digestSidecar, integSidecar} {
			if name != "" {
				containers = append(containers, name)
			}
		}
		if len(containers) > 0 {
			_ = rt.Remove(ctx, containers...)
		}
		// Storage dirs contain files with shifted UIDs from rootless podman.
		// Prune cleans them via podman unshare.
		for _, wd := range []string{workdir, workdirDigest, workdirInteg} {
			if wd != "" {
				_ = rt.Prune(ctx, sandbox.ProjectDir(wd))
				_ = os.RemoveAll(wd)
			}
		}
		if integGitconfig != "" {
			_ = os.RemoveAll(integGitconfig)
		}
		if integGHDir != "" {
			_ = os.RemoveAll(integGHDir)
		}
		if integSocketLn != nil {
			integSocketLn.Close()
		}
		if integSocketPath != "" {
			_ = os.RemoveAll(filepath.Dir(integSocketPath))
		}
		if dataDir != "" {
			_ = os.RemoveAll(dataDir)
		}
	}()

	var err error

	workdir, err = os.MkdirTemp("", "clampdown-integ-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdirtemp: %v\n", err)
		return 1
	}
	workdirDigest, err = os.MkdirTemp("", "clampdown-integ-digest-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdirtemp: %v\n", err)
		return 1
	}

	paths := sandbox.GenPaths(rt.Name(), workdir)
	err = sandbox.EnsurePaths(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ensure paths: %v\n", err)
		return 1
	}
	pathsDigest := sandbox.GenPaths(rt.Name(), workdirDigest)
	err = sandbox.EnsurePaths(pathsDigest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ensure paths: %v\n", err)
		return 1
	}

	dataDir, err = os.MkdirTemp("", "clampdown-integ-data-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdirtemp: %v\n", err)
		return 1
	}
	sidecarSeccomp, _, err := seccomp.EnsureProfiles(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seccomp: %v\n", err)
		return 1
	}

	resolved := network.ResolveAllowlist(container.RegistryDomains)
	allowlist := strings.Join(resolved, ",")

	uid := strconv.Itoa(os.Getuid())
	gid := strconv.Itoa(os.Getgid())

	workdirInteg, err = os.MkdirTemp("", "clampdown-integ-integ-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdirtemp: %v\n", err)
		return 1
	}
	pathsInteg := sandbox.GenPaths(rt.Name(), workdirInteg)
	err = sandbox.EnsurePaths(pathsInteg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ensure paths (integ): %v\n", err)
		return 1
	}

	// Create integration test fixtures on the host. These get bind-mounted
	// into the integration sidecar at /run/credentials/* and should be
	// forwarded by seal-inject into nested containers.
	integGitconfig, err = os.MkdirTemp("", "integ-gitconfig-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create gitconfig dir: %v\n", err)
		return 1
	}
	gitconfigFile := filepath.Join(integGitconfig, "gitconfig")
	err = os.WriteFile(gitconfigFile, []byte("[user]\n\tname = integ-test-user\n\temail = integ@test.dev\n"), 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write gitconfig: %v\n", err)
		return 1
	}

	integGHDir, err = os.MkdirTemp("", "integ-gh-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create gh dir: %v\n", err)
		return 1
	}
	err = os.WriteFile(filepath.Join(integGHDir, "hosts.yml"), []byte("github.com:\n  oauth_token: fake-test-token\n"), 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write hosts.yml: %v\n", err)
		return 1
	}

	// Create a Unix socket listener on the host. The socket is mounted into
	// the integration sidecar and forwarded into nested containers by seal-inject.
	// The listener echoes "pong" on every connection, proving end-to-end data flow.
	socketDir, err := os.MkdirTemp("", "integ-socket-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create socket dir: %v\n", err)
		return 1
	}
	integSocketPath = filepath.Join(socketDir, "ssh-agent.sock")
	integSocketLn, err = net.Listen("unix", integSocketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen unix socket: %v\n", err)
		return 1
	}
	go func() {
		for {
			conn, acceptErr := integSocketLn.Accept()
			if acceptErr != nil {
				return // listener closed
			}
			_, _ = conn.Write([]byte("pong"))
			conn.Close()
		}
	}()

	pid := os.Getpid()
	sidecarName = fmt.Sprintf("clampdown-integ-%d-sidecar", pid)
	digestSidecar = fmt.Sprintf("clampdown-integ-%d-digest", pid)
	integSidecar = fmt.Sprintf("clampdown-integ-%d-integ", pid)

	defaultEnv := map[string]string{
		"SANDBOX_AGENT_ALLOW":    allowlist,
		"SANDBOX_AGENT_POLICY":   "deny",
		"SANDBOX_POD_POLICY":     "allow",
		"SANDBOX_REQUIRE_DIGEST": "warn",
		"SANDBOX_UID":            uid,
		"SANDBOX_GID":            gid,
		"SANDBOX_WORKDIR":        workdir,
	}
	digestEnv := map[string]string{
		"SANDBOX_AGENT_ALLOW":    allowlist,
		"SANDBOX_AGENT_POLICY":   "deny",
		"SANDBOX_POD_POLICY":     "allow",
		"SANDBOX_REQUIRE_DIGEST": "block",
		"SANDBOX_UID":            uid,
		"SANDBOX_GID":            gid,
		"SANDBOX_WORKDIR":        workdirDigest,
	}

	cfg := buildSidecarConfig(sidecarName, sidecarSeccomp, paths, workdir, defaultEnv)
	cfgDigest := buildSidecarConfig(digestSidecar, sidecarSeccomp, pathsDigest, workdirDigest, digestEnv)

	integEnv := map[string]string{
		"SANDBOX_AGENT_ALLOW":    allowlist,
		"SANDBOX_AGENT_POLICY":   "deny",
		"SANDBOX_POD_POLICY":     "allow",
		"SANDBOX_REQUIRE_DIGEST": "warn",
		"SANDBOX_UID":            uid,
		"SANDBOX_GID":            gid,
		"SANDBOX_WORKDIR":        workdirInteg,
	}
	cfgInteg := buildSidecarConfig(integSidecar, sidecarSeccomp, pathsInteg, workdirInteg, integEnv)
	cfgInteg.Mounts = []container.MountSpec{
		{Source: gitconfigFile, Dest: "/run/credentials/gitconfig", RO: true, Type: container.Bind},
		{Source: integGHDir, Dest: "/run/credentials/gh", RO: true, Type: container.Bind},
		{Source: integSocketPath, Dest: "/run/credentials/ssh-agent.sock", RO: true, Type: container.Bind},
	}

	err = rt.StartSidecar(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start sidecar: %v\n", err)
		return 1
	}
	err = rt.StartSidecar(ctx, cfgDigest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start digest sidecar: %v\n", err)
		return 1
	}
	err = rt.StartSidecar(ctx, cfgInteg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start integ sidecar: %v\n", err)
		return 1
	}

	err = waitReady(ctx, sidecarName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sidecar not ready: %v\n", err)
		return 1
	}
	err = waitReady(ctx, digestSidecar)
	if err != nil {
		fmt.Fprintf(os.Stderr, "digest sidecar not ready: %v\n", err)
		return 1
	}
	err = waitReady(ctx, integSidecar)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integ sidecar not ready: %v\n", err)
		return 1
	}

	// Push alpine from the host into all sidecars so tests don't
	// need to pull over the network (except the egress tests).
	for _, sc := range []string{sidecarName, digestSidecar, integSidecar} {
		err = rt.PushImage(ctx, sc, []string{alpineImage})
		if err != nil {
			fmt.Fprintf(os.Stderr, "push alpine to %s: %v\n", sc, err)
			return 1
		}
	}
	// Push python:alpine into the integ sidecar for the socket data flow
	// test (busybox lacks a Unix socket client).
	err = rt.PushImage(ctx, integSidecar, []string{pythonAlpineImage})
	if err != nil {
		fmt.Fprintf(os.Stderr, "push python:alpine to integ: %v\n", err)
		return 1
	}

	// Push am-i-isolated for the security audit test.
	err = rt.PushImage(ctx, sidecarName, []string{isolatedImage})
	if err != nil {
		fmt.Fprintf(os.Stderr, "push am-i-isolated: %v\n", err)
		return 1
	}

	return m.Run()
}

// ---------------------------------------------------------------------------
// Positive tests: normal operations succeed.
// ---------------------------------------------------------------------------

func TestPositive(t *testing.T) {
	t.Parallel()

	t.Run("echo", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "echo", "hello"))
		requireSuccess(t, out, err)
		if !bytes.Contains(out, []byte("hello")) {
			t.Errorf("expected 'hello' in output, got: %s", out)
		}
	})

	t.Run("workdir_volume", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"-v", workdir + ":" + workdir}, "ls", workdir))
		requireSuccess(t, out, err)
	})

	t.Run("workdir_writable", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"-v", workdir + ":" + workdir},
				"sh", "-c", "touch "+workdir+"/integ_test && rm "+workdir+"/integ_test"))
		requireSuccess(t, out, err)
	})
}

// ---------------------------------------------------------------------------
// Security policy: each subtest triggers one of the 14 createRuntime checks.
//
// Skipped checks (defense-in-depth, not CLI-triggerable):
//   - #3 checkNoNewPrivileges: containers.conf sets no_new_privileges=true.
//     Podman applies it before the CLI flag can override, so the OCI config
//     always has noNewPrivileges=true and the check never fires.
//   - #6 checkMountOptions: overlaps with #5 checkMounts. Non-workdir writable
//     mounts are blocked by checkMounts before checkMountOptions runs.
//   - #8 checkRootfsPropagation: set internally by the runtime, no CLI flag.
//   - #10 checkMaskedPaths: seal-inject always re-adds masked paths at
//     precreate, so unmask=ALL doesn't remove them before createRuntime.
//   - #14 checkImageRef: hook reads SANDBOX_REQUIRE_DIGEST from env, but
//     crun doesn't reliably pass sidecar env vars to hook processes.
//     The env var must be propagated through the hook JSON spec or another
//     mechanism for this check to work.
// ---------------------------------------------------------------------------

func TestSecurityPolicy(t *testing.T) {
	t.Parallel()

	t.Run("checkCaps", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--cap-add", "CAP_SYS_ADMIN"}, "true"))
		requireFail(t, out, err)
	})

	t.Run("checkSeccomp", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--security-opt", "seccomp=unconfined"}, "true"))
		requireFail(t, out, err)
	})

	t.Run("checkNamespaces_pid", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--pid=host"}, "true"))
		requireFail(t, out, err)
	})

	t.Run("checkNamespaces_net", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--network=host"}, "true"))
		requireFail(t, out, err)
	})

	t.Run("checkNamespaces_ipc", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--ipc=host"}, "true"))
		requireFail(t, out, err)
	})

	t.Run("checkMounts", func(t *testing.T) {
		t.Parallel()
		// /etc/passwd is not under workdir or infra prefixes.
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"-v", "/etc/passwd:/mounted:ro"}, "true"))
		requireFail(t, out, err)
	})

	t.Run("checkMountPropagation", func(t *testing.T) {
		t.Parallel()
		mount := fmt.Sprintf("type=bind,src=%s,dst=/mnt,bind-propagation=shared", workdir)
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--mount", mount}, "true"))
		requireFail(t, out, err)
	})

	t.Run("checkDevices", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--device", "/dev/fuse"}, "true"))
		requireFail(t, out, err)
	})

	t.Run("checkReadonlyPaths", func(t *testing.T) {
		t.Parallel()
		// unmask=/proc/sys removes /proc/sys from readonlyPaths.
		// seal-inject does not restore readonlyPaths, so the check fires.
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--security-opt", "unmask=/proc/sys"}, "true"))
		requireFail(t, out, err)
	})

	t.Run("checkSysctl_netAllowed", func(t *testing.T) {
		t.Parallel()
		// net.* sysctls are namespace-scoped and allowed.
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--sysctl", "net.ipv4.ip_forward=1"}, "true"))
		requireSuccess(t, out, err)
	})

	t.Run("checkSysctl_kernelBlocked", func(t *testing.T) {
		t.Parallel()
		// Non-net sysctls remain blocked (CVE-2022-0811 class).
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--sysctl", "kernel.domainname=evil"}, "true"))
		requireFail(t, out, err)
	})

	t.Run("checkRlimits", func(t *testing.T) {
		t.Parallel()
		// containers.conf sets core=0:0. --ulimit overrides it.
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--ulimit", "core=1024:1024"}, "true"))
		requireFail(t, out, err)
	})
}

// ---------------------------------------------------------------------------
// Seal-inject: validate precreate hook effects on nested containers.
// ---------------------------------------------------------------------------

func TestSealInject(t *testing.T) {
	t.Parallel()

	t.Run("uid_enforcement", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "id", "-u"))
		requireSuccess(t, out, err)
		got := strings.TrimSpace(string(out))
		want := strconv.Itoa(os.Getuid())
		if got != want {
			t.Errorf("UID = %s, want %s", got, want)
		}
	})

	t.Run("landlock_write_blocked", func(t *testing.T) {
		t.Parallel()
		// /etc is read-only under Landlock policy.
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "touch", "/etc/landlock_test"))
		requireFail(t, out, err)
	})

	t.Run("caps_bounding", func(t *testing.T) {
		t.Parallel()
		// CapBnd matches containers.conf default_capabilities (10 caps).
		// Cap enforcement is containers.conf + security-policy hook;
		// seal does not prune caps.
		//   CHOWN(0) DAC_OVERRIDE(1) FOWNER(3) FSETID(4) KILL(5)
		//   SETGID(6) SETUID(7) SETPCAP(8) NET_BIND_SERVICE(10)
		//   SETFCAP(31)
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c",
				"grep CapBnd /proc/self/status | awk '{print $2}'"))
		requireSuccess(t, out, err)
		capHex := strings.TrimSpace(string(out))
		capVal, parseErr := strconv.ParseUint(capHex, 16, 64)
		if parseErr != nil {
			t.Fatalf("cannot parse CapBnd %q: %v", capHex, parseErr)
		}
		// containers.conf default_capabilities as bitmask.
		// SYS_CHROOT (bit 18) intentionally removed.
		const expected = uint64(1<<0 | 1<<1 | 1<<3 | 1<<4 | 1<<5 |
			1<<6 | 1<<7 | 1<<8 | 1<<10 | 1<<31)
		if capVal != expected {
			t.Errorf("CapBnd = 0x%x, want 0x%x", capVal, expected)
		}
	})

	t.Run("hidepid", func(t *testing.T) {
		t.Parallel()
		// hidepid=2: container can only see its own PIDs.
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c",
				"ls /proc | grep -cE '^[0-9]+$'"))
		requireSuccess(t, out, err)
		count, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		if count > 10 {
			t.Errorf("expected few visible PIDs with hidepid=2, got %d", count)
		}
	})

	t.Run("masked_paths", func(t *testing.T) {
		t.Parallel()
		// /proc/kallsyms should be empty (masked with /dev/null).
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "cat", "/proc/kallsyms"))
		if err == nil && len(bytes.TrimSpace(out)) > 0 {
			t.Errorf("expected /proc/kallsyms empty/masked, got %d bytes", len(out))
		}
	})

	t.Run("rename_shim_loaded", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "ls", "/.sandbox/rename_exdev_shim.so"))
		requireSuccess(t, out, err)
	})

	t.Run("ld_preload_set", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c", "echo $LD_PRELOAD"))
		requireSuccess(t, out, err)
		if !strings.Contains(string(out), "rename_exdev_shim.so") {
			t.Errorf("LD_PRELOAD not set, got: %s", out)
		}
	})
}

// ---------------------------------------------------------------------------
// Egress: registry pulls and nested container network access.
// Sequential — network operations are flaky under contention.
// ---------------------------------------------------------------------------

func TestEgress(t *testing.T) {
	t.Run("approved_registry_pull", func(t *testing.T) {
		// docker.io is in policy.json and agent allowlist.
		out, err := sidecarExec(t, sidecarName,
			innerPull("docker.io/alpine:3.21"))
		requireSuccess(t, out, err)
	})

	t.Run("unapproved_domain_iptables", func(t *testing.T) {
		// mcr.microsoft.com is not in the agent egress allowlist.
		// DNS resolves (port 53 is allowed), but HTTPS to the resolved
		// IP is blocked by the agent OUTPUT chain. The pull times out.
		// Use a short timeout so this doesn't stall the test suite.
		out, err := sidecarExecTimeout(t, sidecarName,
			innerPull("mcr.microsoft.com/dotnet/runtime:latest"),
			15*time.Second)
		requireFail(t, out, err)
	})

	t.Run("unapproved_registry_policy", func(t *testing.T) {
		// Add iptables egress rules for mcr.microsoft.com so the network
		// layer allows it. The pull should still fail because policy.json
		// does not include mcr.microsoft.com (default: reject).
		ctx := context.Background()
		err := network.AgentAllow(ctx, rt, sidecarName,
			[]string{"mcr.microsoft.com"}, "443")
		if err != nil {
			t.Fatalf("add agent allow: %v", err)
		}

		out, pullErr := sidecarExec(t, sidecarName,
			innerPull("mcr.microsoft.com/dotnet/runtime:latest"))
		requireFail(t, out, pullErr)
	})

	t.Run("nested_http_fetch", func(t *testing.T) {
		// Pod egress default allow, example.com is not a private CIDR.
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "wget", "-q", "-O", "/dev/null",
				"--timeout=10", "http://example.com"))
		requireSuccess(t, out, err)
	})

	t.Run("private_cidr_blocked", func(t *testing.T) {
		// 169.254.169.254 (cloud metadata) is blocked by iptables.
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "wget", "-q", "-O", "/dev/null",
				"--timeout=5", "http://169.254.169.254/latest/meta-data/"))
		requireFail(t, out, err)
	})

	t.Run("pod_block", func(t *testing.T) {
		// Nested containers can reach example.com by default (pod policy
		// = allow, not a private CIDR). Add a PodBlock rule for
		// example.com:80, then verify the fetch fails.
		ctx := context.Background()
		err := network.PodBlock(ctx, rt, sidecarName,
			[]string{"example.com"}, "80")
		if err != nil {
			t.Fatalf("add pod block: %v", err)
		}

		out, fetchErr := sidecarExec(t, sidecarName,
			innerRun(nil, "wget", "-q", "-O", "/dev/null",
				"--timeout=5", "http://example.com"))
		requireFail(t, out, fetchErr)
	})
}

// ---------------------------------------------------------------------------
// Credential forwarding: verify seal-inject forwards /run/credentials/*
// mounts and env vars into nested containers.
// ---------------------------------------------------------------------------

func TestCredentialForwarding(t *testing.T) {
	t.Parallel()

	t.Run("gitconfig_mounted", func(t *testing.T) {
		t.Parallel()
		// seal-inject should mount /run/credentials/gitconfig as
		// /etc/gitconfig inside the nested container.
		out, err := sidecarExec(t, integSidecar,
			innerRun(nil, "cat", "/etc/gitconfig"))
		requireSuccess(t, out, err)
		if !strings.Contains(string(out), "integ-test-user") {
			t.Errorf("expected gitconfig content, got: %s", out)
		}
	})

	t.Run("gitconfig_readonly", func(t *testing.T) {
		t.Parallel()
		// The gitconfig mount should be read-only.
		out, err := sidecarExec(t, integSidecar,
			innerRun(nil, "sh", "-c", "echo x >> /etc/gitconfig"))
		requireFail(t, out, err)
	})

	t.Run("gh_dir_mounted", func(t *testing.T) {
		t.Parallel()
		// seal-inject should mount /run/credentials/gh/ and set
		// GH_CONFIG_DIR=/run/credentials/gh in the nested container.
		out, err := sidecarExec(t, integSidecar,
			innerRun(nil, "cat", "/run/credentials/gh/hosts.yml"))
		requireSuccess(t, out, err)
		if !strings.Contains(string(out), "fake-test-token") {
			t.Errorf("expected gh hosts.yml content, got: %s", out)
		}
	})

	t.Run("gh_config_dir_env", func(t *testing.T) {
		t.Parallel()
		// GH_CONFIG_DIR should be set to /run/credentials/gh.
		out, err := sidecarExec(t, integSidecar,
			innerRun(nil, "sh", "-c", "echo $GH_CONFIG_DIR"))
		requireSuccess(t, out, err)
		got := strings.TrimSpace(string(out))
		if got != "/run/credentials/gh" {
			t.Errorf("GH_CONFIG_DIR = %q, want /run/credentials/gh", got)
		}
	})

	t.Run("gh_dir_readonly", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, integSidecar,
			innerRun(nil, "sh", "-c", "echo x > /run/credentials/gh/test"))
		requireFail(t, out, err)
	})

	t.Run("ssh_auth_sock_env", func(t *testing.T) {
		t.Parallel()
		// SSH_AUTH_SOCK should be set to /run/ssh-agent.sock.
		out, err := sidecarExec(t, integSidecar,
			innerRun(nil, "sh", "-c", "echo $SSH_AUTH_SOCK"))
		requireSuccess(t, out, err)
		got := strings.TrimSpace(string(out))
		if got != "/run/ssh-agent.sock" {
			t.Errorf("SSH_AUTH_SOCK = %q, want /run/ssh-agent.sock", got)
		}
	})

	t.Run("ssh_socket_is_socket", func(t *testing.T) {
		t.Parallel()
		// The forwarded path must be an actual Unix socket, not a file.
		out, err := sidecarExec(t, integSidecar,
			innerRun(nil, "test", "-S", "/run/ssh-agent.sock"))
		requireSuccess(t, out, err)
	})

	t.Run("ssh_socket_data_flows", func(t *testing.T) {
		t.Parallel()
		// Connect to the forwarded socket and read the "pong" response
		// from the host-side listener. Proves end-to-end data flow
		// through: host → sidecar → nested container.
		// Uses python:alpine because busybox lacks a Unix socket client.
		pyCmd := "import socket; s=socket.socket(socket.AF_UNIX); " +
			"s.connect('/run/ssh-agent.sock'); print(s.recv(64).decode()); s.close()"
		cmd := []string{innerPodman, "run", "--rm", pythonAlpineImage, "python3", "-c", pyCmd}
		out, err := sidecarExec(t, integSidecar, cmd)
		requireSuccess(t, out, err)
		if !strings.Contains(string(out), "pong") {
			t.Errorf("expected 'pong' from socket, got: %q", string(out))
		}
	})

	t.Run("integration_mounts_allowed_by_policy", func(t *testing.T) {
		t.Parallel()
		// Verify security-policy accepts /run/credentials/ as a valid
		// mount source (infraMountPrefixes). If this fails, the nested
		// container would not start at all.
		out, err := sidecarExec(t, integSidecar,
			innerRun(nil, "ls", "/run/credentials/gh/hosts.yml"))
		requireSuccess(t, out, err)
	})
}

// ---------------------------------------------------------------------------
// Third-party security audit: am-i-isolated + CDK.
//
// Supplementary validation via independent tools. The primary security
// gate is our own integration tests above (14 deterministic checks).
// These third-party tools provide a second set of eyes.
//
// Sequential — each tool's output is contiguous in the test log.
// Run with -v to see full output.
//
// am-i-isolated skipped checks:
//   - "container virtualization": always fails in containers — expects a VM.
//   - "Yama LSM": false negative from /proc/kallsyms masking.
// ---------------------------------------------------------------------------

func TestSecurityAudit(t *testing.T) {
	// Sequential — no t.Parallel() on parent or subtests.

	t.Run("am_i_isolated", func(t *testing.T) {
		cmd := []string{innerPodman, "run", "--rm", isolatedImage}
		out, _ := sidecarExecTimeout(t, sidecarName, cmd, 30*time.Second)
		t.Log("\n" + string(out))

		const (
			red    = "\U0001F534"
			yellow = "\U0001F7E1"
		)
		for _, line := range strings.Split(string(out), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "container virtualization") {
				continue
			}
			if strings.Contains(trimmed, "Yama LSM") {
				continue
			}
			if strings.Contains(trimmed, red) || strings.Contains(trimmed, yellow) {
				t.Errorf("am-i-isolated: %s", trimmed)
			}
		}
	})

	t.Run("cdk", func(t *testing.T) {
		cmd := []string{
			innerPodman, "run", "--rm", "--tmpfs", "/home/audit",
			alpineImage, "sh", "-c",
			"wget -q -O /home/audit/cdk https://github.com/cdk-team/CDK/releases/download/v1.5.3/cdk_linux_amd64 && " +
				"chmod +x /home/audit/cdk && /home/audit/cdk evaluate --full 2>&1",
		}
		out, err := sidecarExecTimeout(t, sidecarName, cmd, 120*time.Second)
		t.Log("\n" + string(out))
		if err != nil {
			t.Fatalf("cdk failed: %v", err)
		}
		output := string(out)

		// 1. Tool completeness: verify key sections ran.
		for _, section := range []string{
			"Information Gathering - Commands and Capabilities",
			"Information Gathering - Net Namespace",
			"Information Gathering - Sysctl Variables",
			"Information Gathering - ASLR",
		} {
			if !strings.Contains(output, section) {
				t.Errorf("cdk: missing section %q — tool may not have completed", section)
			}
		}

		// 2. Capabilities: zero effective/permitted/inheritable.
		for _, expect := range []string{
			"CapInh:\t0000000000000000",
			"CapPrm:\t0000000000000000",
			"CapEff:\t0000000000000000",
		} {
			if !strings.Contains(output, expect) {
				t.Errorf("cdk: expected %q in output", expect)
			}
		}

		// 3. No exploitable capabilities (CDK prints [!] CAP_ or
		// "Critical -" when it finds exploitable caps).
		for _, bad := range []string{
			"[!] CAP_",
			"Critical - SYS_ADMIN",
			"Critical - Possible Privileged",
			"Added capability list:",
		} {
			if strings.Contains(output, bad) {
				t.Errorf("cdk: exploitable capability: %s", bad)
			}
		}

		// 4. Network namespace must be isolated.
		if !strings.Contains(output, "net namespace isolated") {
			t.Error("cdk: expected net namespace isolated")
		}

		// 5. ASLR must be enabled.
		if !strings.Contains(output, "ASLR is enabled") {
			t.Error("cdk: expected ASLR enabled")
		}

		// 6. route_localnet must be 0 (CVE-2020-8558).
		if strings.Contains(output, "route_localnet = 1") {
			t.Error("cdk: route_localnet=1 (CVE-2020-8558)")
		}

		// 7. Cloud metadata APIs unreachable (private CIDRs blocked).
		// CDK outputs "failed to dial" for each cloud API when blocked.
		if strings.Contains(output, "Bindcloud") ||
			strings.Contains(output, "Metadata API available") {
			t.Error("cdk: cloud metadata API reachable")
		}

		// 8. K8s API server must forbid anonymous requests (or not exist).
		if strings.Contains(output, "allows anonymous request") ||
			strings.Contains(output, "have a high authority") {
			t.Error("cdk: K8s anonymous auth or high-authority SA detected")
		}

		// 9. Sensitive files: no docker.sock, .ssh, .kube, serviceaccount.
		for _, bad := range []string{
			"/docker.sock - ",
			"/.ssh/ - ",
			"/.kube/ - ",
			"/serviceaccount - ",
		} {
			if strings.Contains(output, bad) {
				t.Errorf("cdk: sensitive file found: %s", bad)
			}
		}

		// 10. No sensitive services detected in env/processes.
		if strings.Contains(output, "sensitive env found") {
			t.Error("cdk: sensitive environment variables detected")
		}
	})

}
