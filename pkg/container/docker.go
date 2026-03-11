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
	"time"
)

// Docker implements Runtime for docker.
type Docker struct{}

func (d *Docker) Name() string { return nameDocker }
func (d *Docker) bin() string  { return nameDocker }

func (d *Docker) uid() string { return strconv.Itoa(os.Getuid()) }
func (d *Docker) gid() string { return strconv.Itoa(os.Getgid()) }

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
		"--security-opt", "label=type:container_engine_t",
		"--security-opt", "no-new-privileges",
		"--security-opt", "seccomp="+cfg.SeccompProfile,
	)

	if cfg.Resources.Memory != "" {
		args = append(args, "--memory="+cfg.Resources.Memory)
	}
	if cfg.Resources.CPUs != "" {
		args = append(args, "--cpus="+cfg.Resources.CPUs)
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

	args = append(args, "-v", cfg.Workdir+":"+cfg.Workdir+":z")
	// Protected paths — read-only overlays on sensitive workdir paths.
	for _, m := range cfg.ProtectedPaths {
		switch m.Type {
		case Bind:
			args = append(args, "-v", m.Source+":"+m.Dest+":ro,z")
		case DevNull:
			args = append(args, "-v", "/dev/null:"+m.Dest+":ro")
		case EmptyRO:
			args = append(args, "--tmpfs", m.Dest+":ro,size=0,mode=000")
		}
	}
	// Masked paths — DevNull/EmptyRO overlays hiding secret content.
	for _, m := range cfg.MaskedPaths {
		switch m.Type {
		case DevNull:
			args = append(args, "-v", "/dev/null:"+m.Dest+":ro")
		case EmptyRO:
			args = append(args, "--tmpfs", m.Dest+":ro,size=0,mode=000")
		}
	}
	args = append(args,
		"-v", cfg.StorageDir+":/var/lib/containers/storage:z",
		"-v", cfg.CacheDir+":/var/lib/containers/cache:z",
		"-v", cfg.CacheDir+":/var/cache/containers:z",
		"-v", cfg.TempDir+":/tmp:z",
		"-v", cfg.TempDir+":/var/tmp:z",
	)
	if cfg.AuthFile != "" {
		args = append(args, "-v", cfg.AuthFile+":/root/.config/containers/auth.json:ro,z")
	}
	for _, m := range cfg.Mounts {
		args = append(args, "-v", m.Source+":"+m.Dest+":ro,z")
	}
	args = append(args, cfg.Image)

	cmd := exec.CommandContext(ctx, d.bin(), args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	slog.Debug("exec", "cmd", cmd.Args)
	return cmd.Run()
}

func (d *Docker) StartProxy(ctx context.Context, cfg ProxyContainerConfig) error {
	args := []string{"run", "-d", "--name", cfg.Name,
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
	if cfg.Resources.CPUs != "" {
		args = append(args, "--cpus="+cfg.Resources.CPUs)
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

	args = append(args, cfg.Image)

	cmd := exec.CommandContext(ctx, d.bin(), args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	slog.Debug("exec", "cmd", cmd.Args)
	return cmd.Run()
}

func (d *Docker) StartAgent(ctx context.Context, cfg AgentContainerConfig) error {
	uid, gid := d.uid(), d.gid()
	uidGID := uid + ":" + gid

	args := []string{"run", "--rm", "-ti", "--name", cfg.Name,
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
	if cfg.Resources.CPUs != "" {
		args = append(args, "--cpus="+cfg.Resources.CPUs)
	}
	if cfg.Resources.PIDLimit > 0 {
		args = append(args, fmt.Sprintf("--pids-limit=%d", cfg.Resources.PIDLimit))
	}
	if cfg.Resources.UlimitCore != "" {
		args = append(args, "--ulimit", "core="+cfg.Resources.UlimitCore)
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

	cmd := exec.CommandContext(ctx, d.bin(), args...)
	cmd.Stdin = os.Stdin
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
			opt := ":z"
			if m.RO {
				opt = ":ro,z"
			}
			if m.Hardened {
				opt += ",nosuid,nodev"
			}
			flags = append(flags, "-v", m.Source+":"+m.Dest+opt)
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

	c := exec.CommandContext(ctx, d.bin(), args...)
	slog.Debug("exec", "cmd", c.Args)
	return c.CombinedOutput()
}

func (d *Docker) List(ctx context.Context, labels map[string]string) ([]Info, error) {
	args := []string{"ps", "--format", "json"}
	for k, v := range labels {
		args = append(args, "--filter", "label="+k+"="+v)
	}
	cmd := exec.CommandContext(ctx, d.bin(), args...)
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
	dirs, err := filepath.Glob(filepath.Join(projectDir, d.Name()+"-*"))
	if err != nil {
		return fmt.Errorf("glob: %w", err)
	}
	if len(dirs) == 0 {
		return nil
	}
	// Docker creates files as root. Use a container to remove them.
	args := []string{
		"run", "--rm",
		"-v", projectDir + ":" + projectDir,
		"alpine:latest", "rm", "-rf",
	}
	args = append(args, dirs...)
	cmd := exec.CommandContext(ctx, d.bin(), args...)
	cmd.Stderr = os.Stderr
	slog.Debug("exec", "cmd", cmd.Args)
	return cmd.Run()
}

func (d *Docker) CleanStale(ctx context.Context, prefix string) {
	cmd := exec.CommandContext(ctx, d.bin(),
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
			rm := exec.CommandContext(ctx, d.bin(), "rm", "-f", name)
			slog.Debug("exec", "cmd", rm.Args)
			_ = rm.Run()
		}
	}
}

func (d *Docker) Remove(ctx context.Context, names ...string) error {
	var hasErrored error
	for _, name := range names {
		cmd := exec.CommandContext(ctx, d.bin(), "rm", "-f", name)
		slog.Debug("exec", "cmd", cmd.Args)
		err := cmd.Run()
		if err != nil && hasErrored == nil {
			hasErrored = err
		}
	}
	return hasErrored
}

func (d *Docker) IsRootless(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, d.bin(), "info", "-f", "json")
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}
	var info struct {
		SecurityOptions []string `json:"SecurityOptions"`
	}
	if err = json.Unmarshal(out, &info); err != nil {
		return false, err
	}
	return slices.Contains(info.SecurityOptions, "name=rootless"), nil
}

func (d *Docker) ImageID(ctx context.Context, image string) (string, error) {
	cmd := exec.CommandContext(ctx, d.bin(), "image", "inspect", "--format", "{{.Id}}", image)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (d *Docker) PushImage(ctx context.Context, sidecar string, images []string) error {
	saveCmd := exec.CommandContext(ctx, d.bin(), append([]string{"save"}, images...)...)
	loadCmd := exec.CommandContext(ctx, d.bin(),
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

func (d *Docker) Logs(ctx context.Context, ctr string) ([]byte, error) {
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, d.bin(), "logs", ctr)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	slog.Debug("exec", "cmd", cmd.Args)
	err := cmd.Run()
	return buf.Bytes(), err
}
