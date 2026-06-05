// SPDX-License-Identifier: GPL-3.0-only

package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// dockerDaemonInfo caches parsed fields from `docker info -f json`.
type dockerDaemonInfo struct {
	OperatingSystem string   `json:"OperatingSystem"`
	SecurityOptions []string `json:"SecurityOptions"`
	KernelVersion   string   `json:"KernelVersion"`
}

// Docker implements Runtime for docker.
type Docker struct {
	probeOnce  sync.Once
	debug      bool
	native     bool // daemon runs on the same kernel (not a VM)
	selinux    bool // daemon has SELinux enabled
	daemonInfo dockerDaemonInfo
}

func (d *Docker) Name() string    { return nameDocker }
func (d *Docker) SetDebug(v bool) { d.debug = v }

// command builds an exec.Cmd with the runtime binary and global flags
// (e.g. --log-level=debug) prepended before the subcommand args.
func (d *Docker) command(ctx context.Context, args ...string) *exec.Cmd {
	if d.debug {
		args = append([]string{"--log-level=debug"}, args...)
	}
	return exec.CommandContext(ctx, nameDocker, args...)
}

func (d *Docker) uid() string { return strconv.Itoa(os.Getuid()) }
func (d *Docker) gid() string { return strconv.Itoa(os.Getgid()) }

// HostCPUs returns the CPU count the runtime daemon will accept for --cpus.
func (d *Docker) HostCPUs(ctx context.Context) (int, error) {
	cmd := d.command(ctx, "info", "--format", "{{.NCPU}}")
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("docker info: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, fmt.Errorf("parse cpus %q: %w", string(out), err)
	}
	return n, nil
}

// probe queries the Docker daemon once and caches the result.
// All capability checks (SELinux, native, Docker Desktop) read from the cache.
func (d *Docker) probe() {
	d.probeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := d.command(ctx, "info", "-f", "json").Output()
		if err == nil {
			err = json.Unmarshal(out, &d.daemonInfo)
			if err != nil {
				slog.Warn("parse docker daemon info", "error", err)
			}
		}
		d.native = UnameRelease() != "" && d.daemonInfo.KernelVersion == UnameRelease()
		d.selinux = slices.Contains(d.daemonInfo.SecurityOptions, "name=selinux")
	})
}

// mountOpt builds a volume option suffix like ":ro,nosuid,z" from the
// given flags. Filters options based on daemon capabilities:
//   - "z" is appended when SELinux is enabled (rejected by Docker Desktop)
//   - "nosuid"/"nodev" are dropped when non-native (VM filesystems reject them)
//
// Returns "" when no options remain.
func (d *Docker) mountOpt(opts ...string) string {
	d.probe()
	if !d.native {
		opts = slices.DeleteFunc(opts, func(s string) bool {
			return s == "nosuid" || s == "nodev"
		})
	}
	if d.selinux {
		opts = append(opts, "z")
	}
	if len(opts) == 0 {
		return ""
	}
	return ":" + strings.Join(opts, ",")
}

func (d *Docker) StartSidecar(ctx context.Context, cfg SidecarContainerConfig) error {
	args := []string{"run", "-d", "--name", cfg.Name,
		"--restart=unless-stopped",
		"--read-only",
		"--cgroupns=private",
		"--tmpfs", "/run:rw,nosuid,size=256m",
		"--tmpfs", "/var/run:rw,nosuid,size=256m",
		"--cap-drop", "ALL",
	}

	for _, cap := range cfg.Capabilities {
		args = append(args, "--cap-add", cap)
	}
	for _, dev := range cfg.Devices {
		args = append(args, "--device", dev)
	}

	args = append(args,
		"--security-opt", "apparmor=unconfined",
		"--security-opt", "label=type:spc_t", // docker does not support container_engine_t
		"--security-opt", "no-new-privileges",
		"--security-opt", "seccomp="+cfg.SeccompProfile,
	)

	if cfg.Resources.Memory != "" {
		args = append(args, "--memory="+cfg.Resources.Memory)
	}
	if cfg.Resources.CPUs > 0 {
		args = append(args, fmt.Sprintf("--cpus=%d", cfg.Resources.CPUs))
	}
	if cfg.Resources.PIDLimit > 0 {
		args = append(args, fmt.Sprintf("--pids-limit=%d", cfg.Resources.PIDLimit))
	}

	for k, v := range cfg.Env {
		args = append(args, "-e", k+"="+v)
	}
	for k, v := range cfg.Labels {
		args = append(args, "--label", k+"="+v)
	}

	args = append(args, "-v", cfg.Workdir+":"+cfg.Workdir+d.mountOpt())
	// Protected paths — read-only overlays on sensitive workdir paths.
	for _, m := range cfg.ProtectedPaths {
		switch m.Type {
		case Bind:
			args = append(args, "-v", m.Source+":"+m.Dest+d.mountOpt("ro"))
		case DevNull:
			args = append(args, "-v", "/dev/null:"+m.Dest+":ro")
		case EmptyRO:
			args = append(args, "--tmpfs", m.Dest+":ro,size=0,mode=000")
		}
	}
	// Masked paths — DevNull/EmptyRO overlays hiding secret content.
	for _, m := range cfg.MaskedPaths {
		switch m.Type {
		case Bind:
			// Bind-type masked paths are not used; masks are always DevNull or EmptyRO.
		case DevNull:
			args = append(args, "-v", "/dev/null:"+m.Dest+":ro")
		case EmptyRO:
			args = append(args, "--tmpfs", m.Dest+":ro,size=0,mode=000")
		}
	}
	args = append(args,
		"-v", cfg.StorageVolume+":/var/lib/containers/storage",
		"-v", cfg.CacheVolume+":/var/lib/containers/cache",
		"-v", cfg.CacheVolume+":/var/cache/containers",
		"-v", cfg.TempVolume+":/tmp",
		"-v", cfg.TempVolume+":/var/tmp",
	)
	if cfg.AuthFile != "" {
		args = append(args, "-v", cfg.AuthFile+":/root/.config/containers/auth.json"+d.mountOpt("ro"))
	}
	for _, m := range cfg.Mounts {
		args = append(args, "-v", m.Source+":"+m.Dest+d.mountOpt("ro"))
	}
	args = append(args, cfg.Image)

	cmd := d.command(ctx, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	slog.Debug("exec", "cmd", cmd.Args)
	return cmd.Run()
}

func (d *Docker) StartProxy(ctx context.Context, cfg ProxyContainerConfig) error {
	args := []string{"run", "-d", "--name", cfg.Name,
		"--restart=unless-stopped",
		"--user", d.uid() + ":" + d.gid(),
		"--network", "container:" + cfg.SidecarName,
		"--cap-drop=ALL",
		"--read-only",
		"--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=" + cfg.SeccompProfile,
		"--ulimit", "core=0:0",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=1m",
	}

	if cfg.Resources.Memory != "" {
		args = append(args, "--memory="+cfg.Resources.Memory)
	}
	if cfg.Resources.CPUs > 0 {
		args = append(args, fmt.Sprintf("--cpus=%d", cfg.Resources.CPUs))
	}
	if cfg.Resources.PIDLimit > 0 {
		args = append(args, fmt.Sprintf("--pids-limit=%d", cfg.Resources.PIDLimit))
	}

	for k, v := range cfg.Env {
		args = append(args, "-e", k+"="+v)
	}
	for k, v := range cfg.Labels {
		args = append(args, "--label", k+"="+v)
	}

	// Masked paths — DevNull/EmptyRO overlays hiding secret content.
	for _, m := range cfg.MaskedPaths {
		switch m.Type {
		case Bind:
			// Bind-type masked paths are not used; masks are always DevNull or EmptyRO.
		case DevNull:
			args = append(args, "-v", "/dev/null:"+m.Dest+":ro")
		case EmptyRO:
			args = append(args, "--tmpfs", m.Dest+":ro,size=0,mode=000")
		}
	}

	args = append(args, cfg.Image)

	cmd := d.command(ctx, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	slog.Debug("exec", "cmd", cmd.Args)
	return cmd.Run()
}

func (d *Docker) AttachAgent(ctx context.Context, name string) error {
	cmd := d.command(ctx, "attach", "--detach-keys=ctrl-]", name)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	slog.Debug("exec", "cmd", cmd.Args)
	err := cmd.Start()
	if err != nil {
		return err
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		NudgeTerminal()
	}()
	return cmd.Wait()
}

func (d *Docker) StartAgent(ctx context.Context, cfg AgentContainerConfig) error {
	uid, gid := d.uid(), d.gid()
	uidGID := uid + ":" + gid

	ttyFlag := "-ti"
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		ttyFlag = "-i"
	}
	args := []string{"run", "-d", ttyFlag, "--name", cfg.Name,
		"--restart=on-failure",
		"--user", uidGID,
		"--network", "container:" + cfg.SidecarName,
		"--cap-drop=ALL",
		"--read-only",
		"--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=" + cfg.SeccompProfile,
	}

	if cfg.Resources.Memory != "" {
		args = append(args, "--memory="+cfg.Resources.Memory)
	}
	if cfg.Resources.CPUs > 0 {
		args = append(args, fmt.Sprintf("--cpus=%d", cfg.Resources.CPUs))
	}
	if cfg.Resources.PIDLimit > 0 {
		args = append(args, fmt.Sprintf("--pids-limit=%d", cfg.Resources.PIDLimit))
	}
	if cfg.Resources.UlimitCore != "" {
		args = append(args, "--ulimit", "core="+cfg.Resources.UlimitCore)
	}

	// Masked paths — DevNull/EmptyRO overlays hiding secret content.
	for _, m := range cfg.MaskedPaths {
		switch m.Type {
		case Bind:
			// Bind-type masked paths are not used; masks are always DevNull or EmptyRO.
		case DevNull:
			args = append(args, "-v", "/dev/null:"+m.Dest+":ro")
		case EmptyRO:
			args = append(args, "--tmpfs", m.Dest+":ro,size=0,mode=000")
		}
	}

	// Docker tmpfs needs uid/gid for user-owned dirs.
	for _, t := range cfg.Tmpfs {
		opts := "rw"
		if t.NoSuid {
			opts += ",nosuid"
		}
		if t.NoExec {
			opts += ",noexec"
		}
		if t.Size != "" {
			opts += ",size=" + t.Size
		}
		opts += ",uid=" + uid + ",gid=" + gid
		args = append(args, "--tmpfs", t.Path+":"+opts)
	}

	for k, v := range cfg.Env {
		args = append(args, "-e", k+"="+v)
	}
	for k, v := range cfg.Labels {
		args = append(args, "--label", k+"="+v)
	}

	args = append(args, d.MountFlags(cfg)...)

	args = append(args, "--workdir", cfg.Workdir, cfg.Image)
	args = append(args, cfg.EntrypointArgs...)

	cmd := d.command(ctx, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	slog.Debug("exec", "cmd", cmd.Args)
	return cmd.Run()
}

func (d *Docker) MountFlags(cfg AgentContainerConfig) []string {
	var flags []string
	for _, m := range cfg.Mounts {
		switch m.Type {
		case Bind:
			var opts []string
			if m.RO {
				opts = append(opts, "ro")
			}
			flags = append(flags, "-v", m.Source+":"+m.Dest+d.mountOpt(opts...))
		case DevNull:
			flags = append(flags, "-v", "/dev/null:"+m.Dest+":ro")
		case EmptyRO:
			flags = append(flags, "--tmpfs", m.Dest+":ro,size=0,mode=000")
		}
	}
	return flags
}

func (d *Docker) Exec(
	ctx context.Context, ctr string, cmd []string, env map[string]string,
) ([]byte, error) {
	args := []string{"exec"}
	for k, v := range env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, ctr)
	args = append(args, cmd...)

	c := d.command(ctx, args...)
	slog.Debug("exec", "cmd", c.Args)
	return c.CombinedOutput()
}

func (d *Docker) ExecStdin(
	ctx context.Context, ctr string, cmd []string, stdin []byte,
) ([]byte, error) {
	args := append([]string{"exec", "-i", ctr}, cmd...)
	c := d.command(ctx, args...)
	c.Stdin = bytes.NewReader(stdin)
	slog.Debug("exec-stdin", "cmd", c.Args)
	return c.CombinedOutput()
}

func (d *Docker) List(ctx context.Context, labels map[string]string) ([]Info, error) {
	args := []string{"ps", "--all", "--format", "json"}
	for k, v := range labels {
		args = append(args, "--filter", "label="+k+"="+v)
	}
	cmd := d.command(ctx, args...)
	slog.Debug("exec", "cmd", cmd.Args)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	// Docker outputs NDJSON (one JSON object per line).
	var infos []Info
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var raw struct {
			Names     string `json:"Names"`
			Labels    string `json:"Labels"`
			State     string `json:"State"`
			CreatedAt string `json:"CreatedAt"`
		}
		err = json.Unmarshal([]byte(line), &raw)
		if err != nil {
			slog.Debug("skip malformed container entry", "line", line, "error", err)
			continue
		}
		// Docker Labels field is "k1=v1,k2=v2" in --format json.
		parsed := make(map[string]string)
		for pair := range strings.SplitSeq(raw.Labels, ",") {
			k, v, ok := strings.Cut(pair, "=")
			if ok {
				parsed[k] = v
			}
		}

		var startedAt int64
		t, parseErr := time.Parse("2006-01-02 15:04:05 -0700 MST", raw.CreatedAt)
		if parseErr == nil {
			startedAt = t.Unix()
		}

		infos = append(infos, Info{
			Name:      raw.Names,
			Labels:    parsed,
			State:     raw.State,
			StartedAt: startedAt,
		})
	}
	return infos, nil
}

func (d *Docker) Prune(ctx context.Context, projectDir string) error {
	hash := filepath.Base(projectDir)
	vols := []string{
		"clampdown-" + d.Name() + "-" + hash + "-storage",
		"clampdown-" + d.Name() + "-" + hash + "-cache",
		"clampdown-" + d.Name() + "-" + hash + "-tmp",
	}
	err := d.command(ctx, append([]string{"volume", "rm", "--force"}, vols...)...).Run()
	if err != nil {
		slog.Debug("volume prune failed", "volumes", vols, "error", err)
	}

	// Remaining host dirs: <rt>-home, <rt>-state.
	dirs, err := filepath.Glob(filepath.Join(projectDir, d.Name()+"-*"))
	if err != nil {
		return fmt.Errorf("glob: %w", err)
	}
	for _, dir := range dirs {
		err = os.RemoveAll(dir)
		if err != nil {
			return fmt.Errorf("remove %s: %w", dir, err)
		}
	}
	return nil
}

func (d *Docker) CleanStale(ctx context.Context, prefix string) {
	cmd := d.command(ctx,
		"ps", "-a",
		"--filter", "status=exited",
		"--filter", "status=dead",
		"--filter", "status=created",
		"--format", "{{.Names}}",
	)
	slog.Debug("exec", "cmd", cmd.Args)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return
	}
	match := prefix + "-"
	for name := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if name != "" && strings.HasPrefix(name, match) {
			rm := d.command(ctx, "rm", "-f", name)
			slog.Debug("exec", "cmd", rm.Args)
			_ = rm.Run()
		}
	}
}

func (d *Docker) Stop(ctx context.Context, names ...string) error {
	var hasErrored error
	for _, name := range names {
		cmd := d.command(ctx, "stop", "-t", "5", name)
		slog.Debug("exec", "cmd", cmd.Args)
		err := cmd.Run()
		if err != nil && hasErrored == nil {
			hasErrored = err
		}
	}
	return hasErrored
}

func (d *Docker) Remove(ctx context.Context, names ...string) error {
	var hasErrored error
	for _, name := range names {
		cmd := d.command(ctx, "rm", "-f", name)
		slog.Debug("exec", "cmd", cmd.Args)
		err := cmd.Run()
		if err != nil && hasErrored == nil {
			hasErrored = err
		}
	}
	return hasErrored
}

func (d *Docker) IsNative(_ context.Context) (bool, error) {
	d.probe()
	return d.native, nil
}

func (d *Docker) IsRootless(_ context.Context) (bool, error) {
	d.probe()
	return slices.Contains(d.daemonInfo.SecurityOptions, "name=rootless"), nil
}

func (d *Docker) IsDockerDesktop(_ context.Context) bool {
	d.probe()
	return d.daemonInfo.OperatingSystem == "Docker Desktop"
}

func (d *Docker) ImageID(ctx context.Context, image string) (string, error) {
	cmd := d.command(ctx, "image", "inspect", "--format", "{{.Id}}", image)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (d *Docker) PushImage(ctx context.Context, sidecar string, images []string) error {
	saveCmd := d.command(ctx, append([]string{"save"}, images...)...)
	loadCmd := d.command(ctx,
		"exec", "-i",
		"-e", "CONTAINER_HOST="+SidecarAPI,
		sidecar,
		"/usr/local/bin/podman", "load",
	)

	pipe, err := saveCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	loadCmd.Stdin = pipe
	loadCmd.Stdout = os.Stderr
	loadCmd.Stderr = os.Stderr
	saveCmd.Stderr = os.Stderr

	slog.Debug("push", "save", saveCmd.Args, "load", loadCmd.Args)

	err = loadCmd.Start()
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	saveErr := saveCmd.Run()
	loadErr := loadCmd.Wait()

	if saveErr != nil {
		return fmt.Errorf("save: %w", saveErr)
	}
	return loadErr
}

// Log writes a timestamped message to the container's PID 1 stderr
// via the /log binary so it appears in `docker logs`.
func (d *Docker) Log(ctx context.Context, ctr string, source, msg string) error {
	_, err := d.Exec(ctx, ctr, []string{"/log", source, msg}, nil)
	return err
}

func (d *Docker) Logs(ctx context.Context, ctr string) ([]byte, error) {
	var buf bytes.Buffer
	cmd := d.command(ctx, "logs", "--timestamps", ctr)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	slog.Debug("exec", "cmd", cmd.Args)
	err := cmd.Run()
	return buf.Bytes(), err
}
