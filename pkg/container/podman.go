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
	"strings"
)

// Podman implements Runtime for podman.
type Podman struct{}

func (p *Podman) Name() string { return namePodman }
func (p *Podman) bin() string  { return namePodman }

func (p *Podman) StartSidecar(ctx context.Context, cfg SidecarContainerConfig) error {
	args := []string{"run", "-d", "--name", cfg.Name,
		"--restart=unless-stopped",
		"--read-only",
		"--userns=keep-id",
		"--user", "0:0",
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
	// Applied AFTER the workdir bind mount so they take precedence.
	// Prevents a compromised sidecar from modifying .git/hooks, .envrc, etc.
	for _, m := range cfg.ProtectedPaths {
		switch m.Type {
		case Bind:
			opt := ":ro,z"
			args = append(args, "-v", m.Source+":"+m.Dest+opt)
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

	cmd := exec.CommandContext(ctx, p.bin(), args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	slog.Debug("exec", "cmd", cmd.Args)
	return cmd.Run()
}

func (p *Podman) StartAgent(ctx context.Context, cfg AgentContainerConfig) error {
	args := []string{"run", "--rm", "-ti", "--name", cfg.Name,
		"--userns=keep-id",
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
		args = append(args, "--tmpfs", t.Path+":"+opts)
	}

	for k, v := range cfg.Env {
		args = append(args, "-e", k+"="+v)
	}
	for k, v := range cfg.Labels {
		args = append(args, "--label", k+"="+v)
	}

	args = append(args, p.MountFlags(cfg)...)

	args = append(args, "--workdir", cfg.Workdir, cfg.Image)
	args = append(args, cfg.EntrypointArgs...)

	cmd := exec.CommandContext(ctx, p.bin(), args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	slog.Debug("exec", "cmd", cmd.Args)
	return cmd.Run()
}

func (p *Podman) MountFlags(cfg AgentContainerConfig) []string {
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

func (p *Podman) Exec(
	ctx context.Context, ctr string, cmd []string, env map[string]string,
) ([]byte, error) {
	args := []string{"exec"}
	for k, v := range env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, ctr)
	args = append(args, cmd...)

	c := exec.CommandContext(ctx, p.bin(), args...)
	slog.Debug("exec", "cmd", c.Args)
	return c.CombinedOutput()
}

func (p *Podman) List(ctx context.Context, labels map[string]string) ([]Info, error) {
	args := []string{"ps", "--format", "json"}
	for k, v := range labels {
		args = append(args, "--filter", "label="+k+"="+v)
	}
	cmd := exec.CommandContext(ctx, p.bin(), args...)
	slog.Debug("exec", "cmd", cmd.Args)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("podman ps: %w", err)
	}
	var raw []struct {
		Names     []string          `json:"Names"`
		Labels    map[string]string `json:"Labels"`
		State     string            `json:"State"`
		StartedAt int64             `json:"StartedAt"`
	}
	err = json.Unmarshal(out, &raw)
	if err != nil {
		return nil, fmt.Errorf("parse podman ps: %w", err)
	}
	infos := make([]Info, len(raw))
	for i, r := range raw {
		name := ""
		if len(r.Names) > 0 {
			name = r.Names[0]
		}
		infos[i] = Info{
			Name:      name,
			Labels:    r.Labels,
			State:     r.State,
			StartedAt: r.StartedAt,
		}
	}
	return infos, nil
}

func (p *Podman) Prune(ctx context.Context, projectDir string) error {
	dirs, err := filepath.Glob(filepath.Join(projectDir, p.Name()+"-*"))
	if err != nil {
		return fmt.Errorf("glob: %w", err)
	}
	if len(dirs) == 0 {
		return nil
	}
	// podman unshare enters the user namespace so rm can access
	// files created by rootless podman with shifted UIDs.
	args := append([]string{"unshare", "rm", "-rf"}, dirs...)
	cmd := exec.CommandContext(ctx, p.bin(), args...)
	cmd.Stderr = os.Stderr
	slog.Debug("exec", "cmd", cmd.Args)
	return cmd.Run()
}

func (p *Podman) CleanStale(ctx context.Context, prefix string) {
	cmd := exec.CommandContext(ctx, p.bin(),
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
			rm := exec.CommandContext(ctx, p.bin(), "rm", "-f", name)
			slog.Debug("exec", "cmd", rm.Args)
			_ = rm.Run()
		}
	}
}

func (p *Podman) Remove(ctx context.Context, names ...string) error {
	var hasErrored error
	for _, name := range names {
		cmd := exec.CommandContext(ctx, p.bin(), "rm", "-f", name)
		slog.Debug("exec", "cmd", cmd.Args)
		err := cmd.Run()
		if err != nil && hasErrored == nil {
			hasErrored = err
		}
	}
	return hasErrored
}

func (p *Podman) IsRootless(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, p.bin(), "info", "-f", "json")
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}
	var info struct {
		Host struct {
			Security struct {
				Rootless bool `json:"rootless"`
			} `json:"security"`
		} `json:"host"`
	}
	if err = json.Unmarshal(out, &info); err != nil {
		return false, err
	}
	return info.Host.Security.Rootless, nil
}

func (p *Podman) ImageID(ctx context.Context, image string) (string, error) {
	cmd := exec.CommandContext(ctx, p.bin(), "image", "inspect", "--format", "{{.Id}}", image)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (p *Podman) PushImage(ctx context.Context, sidecar string, images []string) error {
	saveCmd := exec.CommandContext(ctx, p.bin(), append([]string{"save"}, images...)...)
	loadCmd := exec.CommandContext(ctx, p.bin(),
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

func (p *Podman) Logs(ctx context.Context, ctr string) ([]byte, error) {
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, p.bin(), "logs", ctr)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	slog.Debug("exec", "cmd", cmd.Args)
	err := cmd.Run()
	return buf.Bytes(), err
}
