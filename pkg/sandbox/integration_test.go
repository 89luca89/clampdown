// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package sandbox_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
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
)

// Package-level state set by TestMain.
var (
	rt              container.Runtime
	sidecarName     string
	digestSidecar   string
	integSidecar    string
	workdir         string
	workdirDigest   string
	workdirInteg    string
	integGitconfig  string // host-side gitconfig dir (contains gitconfig file)
	integGHDir      string // host-side gh config dir
	integSocketPath string // host-side Unix socket for forwarding test
	integSocketLn   net.Listener
	isNative        bool // true if runtime runs natively (not in a VM)
	innerPodman     = "/usr/local/bin/podman"
	innerEnv        = map[string]string{"CONTAINER_HOST": container.SidecarAPI}
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

// sidecarExecStdinTimeout runs a command inside the sidecar, piping stdin and
// forwarding innerEnv. Unlike rt.ExecStdin (which does not pass env vars), this
// builds the exec command directly so -e flags are included.
func sidecarExecStdinTimeout(t *testing.T, ctr string, cmd []string, stdin []byte, timeout time.Duration) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	args := []string{"exec", "-i"}
	for k, v := range innerEnv {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, ctr)
	args = append(args, cmd...)
	c := exec.CommandContext(ctx, rt.Name(), args...)
	c.Stdin = bytes.NewReader(stdin)
	return c.CombinedOutput()
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
		StorageVolume:  p.Storage,
		CacheVolume:    p.Cache,
		TempVolume:     p.Temp,
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
	name := filepath.Base(os.Getenv("CTR"))
	if name != "" && name != "." {
		rt, err = container.ForName(name)
	} else {
		rt, err = container.Detect()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "skip: %v\n", err)
		os.Exit(0)
	}

	// Preflight: runtime must run natively (not in a VM) for kernel features.
	isNative, err = rt.IsNative(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "skip: %v\n", err)
		os.Exit(0)
	}

	// Preflight: Landlock must be available — the sidecar hard-fails without it.
	err = sandbox.CheckLandlock()
	if err != nil && isNative {
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

	// Use $HOME/.cache for temp dirs. On macOS with colima, only ~/ is
	// shared into the VM by default. /tmp and /var/folders are not.
	testBase := filepath.Join(os.Getenv("HOME"), ".cache", "clampdown-test")

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
		// Remove the test base dir if empty (all children removed above).
		_ = os.Remove(testBase)
	}()

	var err error

	err = os.MkdirAll(testBase, 0o755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create test base: %v\n", err)
		return 1
	}

	workdir, err = os.MkdirTemp(testBase, "integ-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdirtemp: %v\n", err)
		return 1
	}
	workdirDigest, err = os.MkdirTemp(testBase, "clampdown-integ-digest-*")
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

	dataDir, err = os.MkdirTemp(testBase, "clampdown-integ-data-*")
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

	uid := strconv.Itoa(os.Getuid())
	gid := strconv.Itoa(os.Getgid())

	workdirInteg, err = os.MkdirTemp(testBase, "clampdown-integ-integ-*")
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
	integGitconfig, err = os.MkdirTemp(testBase, "integ-gitconfig-*")
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

	integGHDir, err = os.MkdirTemp(testBase, "integ-gh-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create gh dir: %v\n", err)
		return 1
	}
	err = os.WriteFile(
		filepath.Join(integGHDir, "hosts.yml"),
		[]byte("github.com:\n  oauth_token: fake-test-token\n"),
		0o644,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write hosts.yml: %v\n", err)
		return 1
	}

	// Create a Unix socket listener on the host. The socket is mounted into
	// the integration sidecar and forwarded into nested containers by seal-inject.
	// The listener echoes "pong" on every connection, proving end-to-end data flow.
	socketDir, err := os.MkdirTemp(testBase, "integ-socket-*")
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
		"SANDBOX_REQUIRE_DIGEST": "warn",
		"SANDBOX_UID":            uid,
		"SANDBOX_GID":            gid,
		"SANDBOX_WORKDIR":        workdir,
	}
	digestEnv := map[string]string{
		"SANDBOX_REQUIRE_DIGEST": "block",
		"SANDBOX_UID":            uid,
		"SANDBOX_GID":            gid,
		"SANDBOX_WORKDIR":        workdirDigest,
	}

	cfg := buildSidecarConfig(sidecarName, sidecarSeccomp, paths, workdir, defaultEnv)
	cfgDigest := buildSidecarConfig(digestSidecar, sidecarSeccomp, pathsDigest, workdirDigest, digestEnv)

	integEnv := map[string]string{
		"SANDBOX_REQUIRE_DIGEST": "warn",
		"SANDBOX_UID":            uid,
		"SANDBOX_GID":            gid,
		"SANDBOX_WORKDIR":        workdirInteg,
	}
	cfgInteg := buildSidecarConfig(integSidecar, sidecarSeccomp, pathsInteg, workdirInteg, integEnv)

	cfgInteg.Mounts = []container.MountSpec{
		{Source: gitconfigFile, Dest: "/run/credentials/gitconfig", RO: true, Type: container.Bind},
		{Source: integGHDir, Dest: "/run/credentials/gh", RO: true, Type: container.Bind},
	}
	// SSH socket forwarding only works on native runtimes — Unix sockets
	// cannot cross the VM boundary (virtiofs/9p).
	if isNative {
		cfgInteg.Mounts = append(cfgInteg.Mounts, container.MountSpec{
			Source: integSocketPath, Dest: "/run/credentials/ssh-agent.sock", RO: true, Type: container.Bind,
		})
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

	// Build firewall rulesets — the entrypoint only sets deny-all baseline.
	for _, sc := range []string{sidecarName, digestSidecar, integSidecar} {
		err = network.BuildAgentFirewall(ctx, rt, sc, "deny", resolved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent firewall %s: %v\n", sc, err)
			return 1
		}
		err = network.BuildPodFirewall(ctx, rt, sc, "allow")
		if err != nil {
			fmt.Fprintf(os.Stderr, "pod firewall %s: %v\n", sc, err)
			return 1
		}
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
	// Push python:alpine into the default sidecar for syscall blocking
	// tests and into the integ sidecar for the socket data flow test.
	err = rt.PushImage(ctx, sidecarName, []string{pythonAlpineImage})
	if err != nil {
		fmt.Fprintf(os.Stderr, "push python:alpine to sidecar: %v\n", err)
		return 1
	}
	err = rt.PushImage(ctx, integSidecar, []string{pythonAlpineImage})
	if err != nil {
		fmt.Fprintf(os.Stderr, "push python:alpine to integ: %v\n", err)
		return 1
	}

	code = m.Run()
	if code != 0 {
		// Dump sidecar logs before cleanup so failures are diagnosable.
		for _, sc := range []string{sidecarName, digestSidecar, integSidecar} {
			if sc == "" {
				continue
			}
			logs, logErr := rt.Logs(ctx, sc)
			if logErr != nil {
				fmt.Fprintf(os.Stderr, "--- LOGS %s: error: %v\n", sc, logErr)
				continue
			}
			fmt.Fprintf(os.Stderr, "--- LOGS %s ---\n%s\n", sc, logs)
		}
	}
	return code
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

	t.Run("build_simple", func(t *testing.T) {
		t.Parallel()
		// Builds inside the sidecar must pipe the Containerfile via stdin
		// (-f -) because file-based builds with a context directory fail
		// with EPERM from the supervisor's bind-source allowlist.
		tag := "integ-build-simple"
		cf := "FROM " + alpineImage + "\nRUN echo hello-from-build > /data.txt\n"
		out, err := sidecarExecStdinTimeout(t, sidecarName, []string{
			innerPodman, "build", "--no-cache",
			"-t", tag,
			"-f", "-",
		}, []byte(cf), 120*time.Second)
		requireSuccess(t, out, err)

		// Run the built image and verify the RUN step executed.
		out, err = sidecarExec(t, sidecarName, []string{
			innerPodman, "run", "--rm", tag, "cat", "/data.txt",
		})
		requireSuccess(t, out, err)
		if !bytes.Contains(out, []byte("hello-from-build")) {
			t.Errorf("expected RUN output, got: %s", out)
		}

		// Clean up.
		sidecarExec(t, sidecarName, []string{innerPodman, "rmi", tag})
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

	t.Run("checkMACDisabled_label", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--security-opt", "label=disable"}, "true"))
		requireFail(t, out, err)
	})

	t.Run("checkMACDisabled_apparmor", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"--security-opt", "apparmor=unconfined"}, "true"))
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

	t.Run("checkMounts_volume_allowed", func(t *testing.T) {
		t.Parallel()
		// Named volumes are legitimate — create, mount, verify.
		out, err := sidecarExec(t, sidecarName,
			[]string{innerPodman, "volume", "create", "integ-test-vol"})
		requireSuccess(t, out, err)
		defer sidecarExec(t, sidecarName,
			[]string{innerPodman, "volume", "rm", "integ-test-vol"})

		out, err = sidecarExec(t, sidecarName,
			innerRun([]string{"-v", "integ-test-vol:/data"}, "ls", "/data"))
		requireSuccess(t, out, err)
	})

	t.Run("checkMounts_volume_traversal_blocked", func(t *testing.T) {
		t.Parallel()
		// Path traversal via _data/../../ must be rejected by the hook's
		// isValidVolumeMount (cleaned path escapes the volume data dir).
		out, err := sidecarExec(t, sidecarName,
			[]string{innerPodman, "volume", "create", "integ-test-trav"})
		requireSuccess(t, out, err)
		defer sidecarExec(t, sidecarName,
			[]string{innerPodman, "volume", "rm", "integ-test-trav"})

		volPath := "/var/lib/containers/storage/volumes/integ-test-trav/_data/../../"
		out, err = sidecarExec(t, sidecarName,
			innerRun([]string{"-v", volPath + ":/escape"}, "ls", "/escape"))
		requireFail(t, out, err)
	})
}

func TestBuildSupervisor(t *testing.T) {
	t.Parallel()

	// All build tests pipe the Containerfile via stdin (-f -) because
	// file-based builds with a context directory fail with EPERM from
	// the supervisor's bind-source allowlist. The -v mounts exercise
	// the supervisor's bind-source checks during the RUN step.
	cf := []byte("FROM " + alpineImage + "\nRUN true\n")

	t.Run("bind_etc_passwd_blocked", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExecStdinTimeout(t, sidecarName, []string{
			innerPodman, "build", "--no-cache",
			"-v", "/etc/passwd:/mounted:ro",
			"-f", "-",
		}, cf, 120*time.Second)
		requireFail(t, out, err)
	})

	t.Run("bind_etc_containers_blocked", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExecStdinTimeout(t, sidecarName, []string{
			innerPodman, "build", "--no-cache",
			"-v", "/etc/containers:/mnt:ro",
			"-f", "-",
		}, cf, 120*time.Second)
		requireFail(t, out, err)
	})

	t.Run("bind_hook_dir_blocked", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExecStdinTimeout(t, sidecarName, []string{
			innerPodman, "build", "--no-cache",
			"-v", "/usr/share/containers/oci/hooks.d:/mnt:ro",
			"-f", "-",
		}, cf, 120*time.Second)
		requireFail(t, out, err)
	})

	t.Run("bind_workdir_allowed", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExecStdinTimeout(t, sidecarName, []string{
			innerPodman, "build", "--no-cache",
			"-v", workdir + ":/work:ro",
			"-f", "-",
		}, cf, 120*time.Second)
		requireSuccess(t, out, err)
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
// Syscall blocking: verify seccomp blocks dangerous syscalls at runtime
// inside nested containers.
// ---------------------------------------------------------------------------

// pythonSyscallTemplate invokes a raw syscall via ctypes. Template args:
// amd64 syscall number, arm64 syscall number. Exits 1 if blocked, 0 if
// the syscall succeeded (a security violation).
const pythonSyscallTemplate = `import ctypes, ctypes.util, platform, sys
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
libc.syscall.restype = ctypes.c_long
nums = {'x86_64': %d, 'aarch64': %d}
arch = platform.machine()
if arch not in nums:
    print('skip: unsupported arch ' + arch)
    sys.exit(0)
ret = libc.syscall(nums[arch])
errno = ctypes.get_errno()
if errno != 0:
    print('blocked: errno=' + str(errno))
    sys.exit(1)
print('SECURITY VIOLATION: syscall succeeded')
sys.exit(0)`

type syscallCase struct {
	name  string
	amd64 int
	arm64 int
}

func TestSyscallBlocking(t *testing.T) {
	t.Parallel()

	// Shell subtests: common attack primitives via busybox.

	t.Run("unshare_newuser", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "unshare", "-U", "id"))
		requireFail(t, out, err)
	})

	t.Run("mount_tmpfs", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "mount", "-t", "tmpfs", "none", "/mnt"))
		requireFail(t, out, err)
	})

	// Python subtests: invoke raw syscalls via ctypes to verify seccomp
	// blocks them at the kernel level. Uses python:alpine (pushed in TestMain).
	cases := []syscallCase{
		{"bpf", 321, 280},
		{"io_uring_setup", 425, 425},
		{"ptrace", 101, 117},
		{"perf_event_open", 298, 241},
		{"userfaultfd", 323, 282},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pyCmd := fmt.Sprintf(pythonSyscallTemplate, tc.amd64, tc.arm64)
			cmd := []string{innerPodman, "run", "--rm", pythonAlpineImage, "python3", "-c", pyCmd}
			out, err := sidecarExec(t, sidecarName, cmd)
			requireFail(t, out, err)
			if bytes.Contains(out, []byte("SECURITY VIOLATION")) {
				t.Fatalf("syscall %s was not blocked by seccomp", tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Protected path access: verify Landlock and readonlyPaths block runtime
// access to sensitive paths inside nested containers.
// ---------------------------------------------------------------------------

func TestProtectedPathAccess(t *testing.T) {
	t.Parallel()

	t.Run("proc_sys_write", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c", "echo x > /proc/sys/kernel/hostname"))
		requireFail(t, out, err)
	})

	t.Run("usr_bin_write", func(t *testing.T) {
		t.Parallel()
		// Landlock enforces read-only on /usr.
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "touch", "/usr/bin/evil"))
		requireFail(t, out, err)
	})
}

// ---------------------------------------------------------------------------
// Egress: registry pulls and nested container network access.
// Sequential — network operations are flaky under contention.
// ---------------------------------------------------------------------------

func TestEgress(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "firewall.json")

	t.Run("approved_registry_pull", func(t *testing.T) {
		// ghcr.io is in policy.json and agent allowlist. Retry up to 5
		// times — registry pulls are flaky (DNS hiccups, CDN timeouts).
		var out []byte
		var err error
		for attempt := 1; attempt <= 5; attempt++ {
			out, err = sidecarExec(t, sidecarName,
				innerPull("ghcr.io/containerd/busybox:1.36"))
			if err == nil {
				break
			}
			t.Logf("attempt %d/5 failed: %v", attempt, err)
			time.Sleep(5 * time.Second)
		}
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
		err := network.AgentAllow(ctx, rt, sidecarName, statePath,
			[]string{"mcr.microsoft.com"}, 443)
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
		err := network.PodBlock(ctx, rt, sidecarName, statePath,
			[]string{"example.com"}, 80)
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
		if !isNative {
			t.Skip("SSH agent forwarding not supported on VM-based runtimes")
		}
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
		if !isNative {
			t.Skip("SSH agent forwarding not supported on VM-based runtimes")
		}
		t.Parallel()
		// The forwarded path must be an actual Unix socket, not a file.
		out, err := sidecarExec(t, integSidecar,
			innerRun(nil, "test", "-S", "/run/ssh-agent.sock"))
		requireSuccess(t, out, err)
	})

	t.Run("ssh_socket_data_flows", func(t *testing.T) {
		if !isNative {
			t.Skip("SSH agent forwarding not supported on VM-based runtimes")
		}
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
// Third-party security audit: CDK.
//
// Supplementary validation via an independent tool. The primary security
// gate is our own integration tests above (14 deterministic checks).
// CDK provides a second set of eyes.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Supervisor: seccomp-notif handler enforcement tests.
// Uses "podman run --rm <sidecar-image> <cmd>" so the command is a direct
// child of the entrypoint and inherits the seccomp-notif filter.
// "podman exec" enters via setns and does NOT inherit the filter.
// ---------------------------------------------------------------------------

// sidecarRun runs a one-shot sidecar container where <cmd> is a direct child
// of the entrypoint — inheriting the seccomp-notif filter. The workdir is
// bind-mounted so tests can place binaries there.
func sidecarRun(t *testing.T, wd string, env map[string]string, cmd ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	args := []string{
		"run", "--rm", "--privileged",
		"--read-only",
		"-v", wd + ":" + wd,
		"-w", wd,
	}
	for k, v := range env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, "clampdown-sidecar:latest")
	args = append(args, cmd...)

	out, err := exec.CommandContext(ctx, rt.Name(), args...).CombinedOutput()
	return out, err
}

func TestSupervisor(t *testing.T) {
	t.Parallel()

	t.Run("exec_allowlist_logged", func(t *testing.T) {
		t.Parallel()
		// The running sidecars should have the exec allowlist in their logs.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		logs, err := rt.Logs(ctx, sidecarName)
		if err != nil {
			t.Fatalf("read sidecar logs: %v", err)
		}
		output := string(logs)
		for _, bin := range []string{
			"/usr/local/bin/podman",
			"/usr/local/bin/crun",
			"/usr/sbin/xtables-nft-multi",
			"/sandbox-seal",
			"/entrypoint",
		} {
			if !strings.Contains(output, "exec allowlist: "+bin+" sha256=") {
				t.Errorf("expected %s in exec allowlist log", bin)
			}
		}
	})

	t.Run("exec_rootfs_binary_allowed", func(t *testing.T) {
		t.Parallel()
		// A rootfs binary (/log) runs as a direct child of the entrypoint.
		// The exec allowlist must allow it.
		out, err := sidecarRun(t, workdir,
			map[string]string{"SANDBOX_UID": "0", "SANDBOX_GID": "0", "SANDBOX_WORKDIR": workdir},
			"/log", "test", "exec-allowed")
		requireSuccess(t, out, err)
	})

	t.Run("exec_unknown_binary_blocked", func(t *testing.T) {
		t.Parallel()
		// Write an executable file to the workdir. It doesn't need to
		// be a valid binary — the supervisor's exec allowlist rejects
		// it (hash not in allowlist) BEFORE the kernel tries to load it.
		fakeBin := filepath.Join(workdir, "fake_exec_test")
		err := os.WriteFile(fakeBin, []byte("\x7fELF_fake_binary"), 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(fakeBin)

		out, err := sidecarRun(t, workdir,
			map[string]string{"SANDBOX_UID": "0", "SANDBOX_GID": "0", "SANDBOX_WORKDIR": workdir},
			fakeBin)
		requireFail(t, out, err)
	})

	t.Run("exec_symlink_to_unknown_blocked", func(t *testing.T) {
		t.Parallel()
		// Create a symlink in the workdir pointing to a fake binary.
		// The supervisor resolves the symlink via EvalSymlinks, finds
		// the target is not in the allowlist, and blocks the exec.
		fakeBin := filepath.Join(workdir, "fake_symlink_target")
		err := os.WriteFile(fakeBin, []byte("\x7fELF_symlink_test"), 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(fakeBin)

		link := filepath.Join(workdir, "link_to_fake")
		err = os.Symlink(fakeBin, link)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(link)

		out, err := sidecarRun(t, workdir,
			map[string]string{"SANDBOX_UID": "0", "SANDBOX_GID": "0", "SANDBOX_WORKDIR": workdir},
			link)
		requireFail(t, out, err)
	})

	t.Run("exec_symlink_to_rootfs_allowed", func(t *testing.T) {
		t.Parallel()
		// Create a symlink in the workdir pointing to /log (rootfs binary).
		// The supervisor resolves the symlink → /log → in allowlist → allowed.
		link := filepath.Join(workdir, "link_to_log")
		err := os.Symlink("/log", link)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(link)

		out, err := sidecarRun(t, workdir,
			map[string]string{"SANDBOX_UID": "0", "SANDBOX_GID": "0", "SANDBOX_WORKDIR": workdir},
			link, "test", "symlink-allowed")
		requireSuccess(t, out, err)
	})

	t.Run("exec_path_collision_blocked", func(t *testing.T) {
		t.Parallel()
		// Write a file named "entrypoint" in the workdir — same name
		// as the rootfs binary but different path. The allowlist keys
		// by absolute resolved path, so /workdir/entrypoint != /entrypoint.
		collision := filepath.Join(workdir, "entrypoint")
		err := os.WriteFile(collision, []byte("\x7fELF_collision"), 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(collision)

		out, err := sidecarRun(t, workdir,
			map[string]string{"SANDBOX_UID": "0", "SANDBOX_GID": "0", "SANDBOX_WORKDIR": workdir},
			collision)
		requireFail(t, out, err)
	})

	t.Run("iptables_direct_blocked", func(t *testing.T) {
		t.Parallel()
		// Run xtables-nft-multi directly as a child of the entrypoint.
		// The binary IS in the exec allowlist (rootfs), but its
		// socket(AF_NETLINK, NETLINK_NETFILTER) call must be blocked
		// because the parent is the entrypoint, not netavark.
		out, err := sidecarRun(t, workdir,
			map[string]string{"SANDBOX_UID": "0", "SANDBOX_GID": "0", "SANDBOX_WORKDIR": workdir},
			"/usr/sbin/xtables-nft-multi", "iptables", "-L")
		requireFail(t, out, err)
	})

	t.Run("no_false_positive_blocks", func(t *testing.T) {
		t.Parallel()
		// After all sidecar operations, verify no legitimate syscalls
		// were blocked by the new handlers.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		logs, err := rt.Logs(ctx, sidecarName)
		if err != nil {
			t.Fatalf("read sidecar logs: %v", err)
		}
		output := string(logs)
		for _, bad := range []string{
			"BLOCKED execve",
			"BLOCKED execveat",
			"BLOCKED openat",
			"BLOCKED unlinkat",
			"BLOCKED symlinkat",
			"BLOCKED linkat",
			"BLOCKED renameat2",
			"BLOCKED socket(AF_NETLINK",
			"BLOCKED setsockopt",
		} {
			if strings.Contains(output, bad) {
				t.Errorf("unexpected %q in sidecar logs — false positive", bad)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Rootfs tampering: pentest escape chain — bind mount source allowlist.
// Validates that the seccomp-notif supervisor blocks the attack at the
// mount level, preventing access to sidecar config via -v /:/hostroot.
// Build containers skip OCI hooks; the supervisor is the only defense.
// ---------------------------------------------------------------------------

func TestRootfsTampering(t *testing.T) {
	t.Parallel()

	t.Run("run_bind_root_blocked", func(t *testing.T) {
		t.Parallel()
		// podman run -v /:/hostroot — exposes entire sidecar rootfs.
		// The supervisor's bind source check must reject source "/".
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"-v", "/:/hostroot"}, "cat", "/hostroot/etc/containers/containers.conf"))
		requireFail(t, out, err)
	})

	t.Run("run_bind_etc_blocked", func(t *testing.T) {
		t.Parallel()
		// podman run -v /etc:/hostetc — exposes sidecar config dir.
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"-v", "/etc:/hostetc"}, "cat", "/hostetc/containers/containers.conf"))
		requireFail(t, out, err)
	})

	t.Run("run_bind_usr_blocked", func(t *testing.T) {
		t.Parallel()
		// podman run -v /usr:/hostusr — exposes hook binaries/configs.
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"-v", "/usr:/hostusr"}, "ls", "/hostusr/share/containers"))
		requireFail(t, out, err)
	})

	t.Run("build_escalate_full_chain", func(t *testing.T) {
		t.Parallel()
		cf := strings.Join([]string{
			"FROM " + alpineImage,
			"RUN ls -la /hostroot/usr/share/containers/oci/hooks.d/security-policy.json /hostroot/usr/share/containers/oci/hooks.d/seal-inject.json",
			"RUN cat /hostroot/usr/share/containers/oci/hooks.d/security-policy.json /hostroot/usr/share/containers/oci/hooks.d/seal-inject.json",
			"RUN rm -f /hostroot/usr/share/containers/oci/hooks.d/security-policy.json /hostroot/usr/share/containers/oci/hooks.d/seal-inject.json",
			"",
		}, "\n")
		out, err := sidecarExecStdinTimeout(t, sidecarName, []string{
			innerPodman, "build", "--no-cache",
			"--cap-add", "ALL",
			"-v", "/:/hostroot",
			"-f", "-",
		}, []byte(cf), 120*time.Second)
		requireFail(t, out, err)
	})

	t.Run("build_bind_root_delete_hooks", func(t *testing.T) {
		t.Parallel()
		cf := "FROM " + alpineImage + "\nRUN rm -f /hostroot/usr/share/containers/oci/hooks.d/security-policy.json\n"
		out, err := sidecarExecStdinTimeout(t, sidecarName, []string{
			innerPodman, "build", "--no-cache",
			"-v", "/:/hostroot",
			"-f", "-",
		}, []byte(cf), 120*time.Second)
		requireFail(t, out, err)
	})

	t.Run("build_bind_root_overwrite_seccomp", func(t *testing.T) {
		t.Parallel()
		// Overwrite seccomp_nested.json to weaken nested container restrictions.
		cf := "FROM " + alpineImage + "\nRUN echo '{}' > /hostroot/etc/containers/seccomp_nested.json\n"
		out, err := sidecarExecStdinTimeout(t, sidecarName, []string{
			innerPodman, "build", "--no-cache",
			"-v", "/:/hostroot",
			"-f", "-",
		}, []byte(cf), 120*time.Second)
		requireFail(t, out, err)
	})

	t.Run("build_bind_root_modify_containers_conf", func(t *testing.T) {
		t.Parallel()
		// Modify containers.conf to disable security defaults.
		cf := "FROM " + alpineImage + "\nRUN echo '[containers]' > /hostroot/etc/containers/containers.conf\n"
		out, err := sidecarExecStdinTimeout(t, sidecarName, []string{
			innerPodman, "build", "--no-cache",
			"-v", "/:/hostroot",
			"-f", "-",
		}, []byte(cf), 120*time.Second)
		requireFail(t, out, err)
	})

	t.Run("run_bind_etc_containers_blocked", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"-v", "/etc/containers:/mnt"}, "cat", "/mnt/containers.conf"))
		requireFail(t, out, err)
	})

	t.Run("run_bind_hook_dir_blocked", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"-v", "/usr/share/containers/oci/hooks.d:/mnt"}, "ls", "/mnt"))
		requireFail(t, out, err)
	})

	t.Run("run_bind_hook_binary_blocked", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"-v", "/usr/libexec/oci/hooks.d/security-policy:/mnt/sp"}, "ls", "/mnt/sp"))
		requireFail(t, out, err)
	})

	t.Run("run_bind_dev_fuse_blocked", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"-v", "/dev/fuse:/dev/fuse"}, "ls", "/dev/fuse"))
		requireFail(t, out, err)
	})

	t.Run("run_workdir_mount_allowed", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun([]string{"-v", workdir + ":/work"}, "ls", "/work"))
		requireSuccess(t, out, err)
	})
}

// ---------------------------------------------------------------------------
// SecurityAudit: comprehensive sandbox validation from inside nested containers.
// ---------------------------------------------------------------------------

func TestSecurityAudit(t *testing.T) {
	t.Parallel()

	// --- Capabilities

	for _, tc := range []struct {
		name, field string
	}{
		{"cap_effective_zero", "CapEff"},
		{"cap_permitted_zero", "CapPrm"},
		{"cap_inheritable_zero", "CapInh"},
		{"cap_ambient_zero", "CapAmb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := sidecarExec(t, sidecarName,
				innerRun(nil, "sh", "-c", "grep '^"+tc.field+":' /proc/self/status"))
			requireSuccess(t, out, err)
			if !strings.Contains(string(out), "0000000000000000") {
				t.Errorf("%s not zero: %s", tc.field, strings.TrimSpace(string(out)))
			}
		})
	}

	t.Run("cap_bounding_limited", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c", "grep '^CapBnd:' /proc/self/status"))
		requireSuccess(t, out, err)
		s := strings.TrimSpace(string(out))
		// Bitmask for 10 default caps (CHOWN, DAC_OVERRIDE, FOWNER, FSETID,
		// KILL, NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID).
		if !strings.Contains(s, "00000000800005fb") {
			t.Errorf("CapBnd unexpected: %s", s)
		}
	})

	// --- Seccomp & MAC

	t.Run("seccomp_filtering", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c", "grep '^Seccomp:' /proc/self/status"))
		requireSuccess(t, out, err)
		// Seccomp: 2 means SECCOMP_MODE_FILTER.
		if !strings.Contains(string(out), "\t2") {
			t.Errorf("seccomp not filtering: %s", strings.TrimSpace(string(out)))
		}
	})

	t.Run("no_new_privs", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c", "grep '^NoNewPrivs:' /proc/self/status"))
		requireSuccess(t, out, err)
		if !strings.Contains(string(out), "\t1") {
			t.Errorf("NoNewPrivs not set: %s", strings.TrimSpace(string(out)))
		}
	})

	// --- Namespaces

	t.Run("namespaces_isolated", func(t *testing.T) {
		t.Parallel()
		// Properly isolated PID namespace should show very few PIDs.
		// Host PID namespace would show hundreds.
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c", "ls /proc | grep -c '^[0-9]'"))
		requireSuccess(t, out, err)
		n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		if n > 20 {
			t.Errorf("PID namespace may not be isolated: %d PIDs visible", n)
		}
	})

	// --- Kernel params

	t.Run("aslr_enabled", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "cat", "/proc/sys/kernel/randomize_va_space"))
		requireSuccess(t, out, err)
		if strings.TrimSpace(string(out)) != "2" {
			t.Errorf("ASLR not fully enabled: %s", strings.TrimSpace(string(out)))
		}
	})

	t.Run("route_localnet_zero", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "cat", "/proc/sys/net/ipv4/conf/all/route_localnet"))
		requireSuccess(t, out, err)
		if strings.TrimSpace(string(out)) != "0" {
			t.Errorf("route_localnet not 0 (CVE-2020-8558): %s", strings.TrimSpace(string(out)))
		}
	})

	// --- Filesystem

	t.Run("read_only_rootfs", func(t *testing.T) {
		t.Parallel()
		_, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c", "touch /rootfs-write-test"))
		if err == nil {
			t.Error("rootfs is writable — touch /rootfs-write-test succeeded")
		}
	})

	t.Run("no_raw_device_access", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c",
				"for d in /dev/sda /dev/vda /dev/nvme0 /dev/dm-0; do "+
					"test -e $d && echo FOUND:$d; done; echo DONE"))
		requireSuccess(t, out, err)
		if strings.Contains(string(out), "FOUND:") {
			t.Errorf("raw device accessible: %s", strings.TrimSpace(string(out)))
		}
	})

	t.Run("no_docker_socket", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c",
				"test -e /var/run/docker.sock && echo FOUND || echo ABSENT"))
		requireSuccess(t, out, err)
		if strings.Contains(string(out), "FOUND") {
			t.Error("docker socket exposed in container")
		}
	})

	t.Run("proc_sys_read_only", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c",
				"echo x > /proc/sys/kernel/hostname 2>&1 || echo BLOCKED"))
		requireSuccess(t, out, err)
		if !strings.Contains(string(out), "BLOCKED") &&
			!strings.Contains(string(out), "Read-only") &&
			!strings.Contains(string(out), "Permission denied") {
			t.Error("/proc/sys is writable")
		}
	})

	t.Run("cgroup_not_writable", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c",
				"echo $$ > /sys/fs/cgroup/cgroup.procs 2>&1 || echo BLOCKED"))
		requireSuccess(t, out, err)
		if !strings.Contains(string(out), "BLOCKED") &&
			!strings.Contains(string(out), "Permission denied") &&
			!strings.Contains(string(out), "Read-only") {
			t.Error("cgroup.procs is writable")
		}
	})

	t.Run("core_dumps_disabled", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c", "ulimit -c"))
		requireSuccess(t, out, err)
		if strings.TrimSpace(string(out)) != "0" {
			t.Errorf("core dumps not disabled: ulimit -c = %s", strings.TrimSpace(string(out)))
		}
	})

	// --- Dangerous operations blocked
	// Verify the operations FAIL at runtime, not just that tools are absent.

	t.Run("dangerous_mount_blocked", func(t *testing.T) {
		t.Parallel()
		_, err := sidecarExec(t, sidecarName,
			innerRun(nil, "mount", "-t", "tmpfs", "none", "/mnt"))
		if err == nil {
			t.Error("mount succeeded — should be blocked by seccomp")
		}
	})

	t.Run("dangerous_mknod_blocked", func(t *testing.T) {
		t.Parallel()
		_, err := sidecarExec(t, sidecarName,
			innerRun(nil, "mknod", "/tmp/testnode", "b", "8", "0"))
		if err == nil {
			t.Error("mknod succeeded — should be blocked by seccomp/device cgroup")
		}
	})

	t.Run("dangerous_unshare_blocked", func(t *testing.T) {
		t.Parallel()
		_, err := sidecarExec(t, sidecarName,
			innerRun(nil, "unshare", "-m", "echo", "ok"))
		if err == nil {
			t.Error("unshare succeeded — should be blocked by seccomp")
		}
	})

	t.Run("dangerous_chroot_blocked", func(t *testing.T) {
		t.Parallel()
		_, err := sidecarExec(t, sidecarName,
			innerRun(nil, "chroot", "/", "echo", "ok"))
		if err == nil {
			t.Error("chroot succeeded — should be blocked by seccomp")
		}
	})

	// --- Syscall probing

	auditSyscalls := []syscallCase{
		{"keyctl", 250, 219},
		{"kexec_load", 246, 104},
		{"init_module", 175, 105},
		{"open_by_handle_at", 304, 265}, // Shocker exploit (CVE-2014-3519)
		{"name_to_handle_at", 303, 264}, // Shocker exploit prerequisite
		{"pivot_root", 155, 41},
	}
	for _, tc := range auditSyscalls {
		t.Run("syscall_"+tc.name+"_blocked", func(t *testing.T) {
			t.Parallel()
			pyCmd := fmt.Sprintf(pythonSyscallTemplate, tc.amd64, tc.arm64)
			cmd := []string{innerPodman, "run", "--rm", pythonAlpineImage, "python3", "-c", pyCmd}
			out, err := sidecarExec(t, sidecarName, cmd)
			requireFail(t, out, err)
			if bytes.Contains(out, []byte("SECURITY VIOLATION")) {
				t.Fatalf("syscall %s was not blocked by seccomp", tc.name)
			}
		})
	}

	// --- Info leak

	t.Run("sensitive_files_absent", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c",
				"for f in /var/run/docker.sock $HOME/.ssh $HOME/.kube "+
					"/run/secrets/kubernetes.io/serviceaccount; do "+
					"test -e $f && echo FOUND:$f; done; echo DONE"))
		requireSuccess(t, out, err)
		if strings.Contains(string(out), "FOUND:") {
			t.Errorf("sensitive files found: %s", strings.TrimSpace(string(out)))
		}
	})

	t.Run("sensitive_env_clean", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c",
				"env | grep -iE '^(KUBERNETES_|DOCKER_HOST=|SSH_AUTH_SOCK=)' || echo CLEAN"))
		requireSuccess(t, out, err)
		if !strings.Contains(string(out), "CLEAN") {
			t.Errorf("sensitive env vars found: %s", strings.TrimSpace(string(out)))
		}
	})

	t.Run("cloud_metadata_blocked", func(t *testing.T) {
		t.Parallel()
		// 169.254.169.254 is blocked by pod FORWARD chain (private CIDRs).
		_, err := sidecarExec(t, sidecarName,
			innerRun(nil, "sh", "-c",
				"wget -q -O- -T 2 http://169.254.169.254/latest/meta-data/ 2>&1"))
		if err == nil {
			t.Error("cloud metadata API (169.254.169.254) reachable")
		}
	})
}
