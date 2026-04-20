// SPDX-License-Identifier: GPL-3.0-only

package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
)

// Podman implements Runtime for podman.
type Podman struct {
	debug bool
}

func (p *Podman) Name() string                           { return namePodman }
func (p *Podman) SetDebug(v bool)                        { p.debug = v }
func (p *Podman) IsDockerDesktop(_ context.Context) bool { return false }

// command builds an exec.Cmd with the runtime binary and global flags
// (e.g. --log-level=debug) prepended before the subcommand args.
func (p *Podman) command(ctx context.Context, args ...string) *exec.Cmd {
	if p.debug {
		args = append([]string{"--log-level=debug"}, args...)
	}
	return exec.CommandContext(ctx, namePodman, args...)
}

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
		args = append(args, "-v", cfg.AuthFile+":/root/.config/containers/auth.json:ro,z")
	}
	for _, m := range cfg.Mounts {
		args = append(args, "-v", m.Source+":"+m.Dest+":ro,z")
	}
	args = append(args, cfg.Image)

	cmd := p.command(ctx, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	slog.Debug("exec", "cmd", cmd.Args)
	return cmd.Run()
}

func (p *Podman) StartProxy(ctx context.Context, cfg ProxyContainerConfig) error {
	args := []string{"run", "-d", "--name", cfg.Name,
		"--restart=unless-stopped",
		"--userns=keep-id",
		"--network", "container:" + cfg.SidecarName,
		"--cap-drop=ALL",
		"--read-only",
		"--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=" + cfg.SeccompProfile,
		// Proxy holds API keys in memory — prevent core dump exfiltration.
		"--ulimit", "core=0:0",
		// No filesystem writes needed. Minimal tmpfs for Go runtime.
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

	cmd := p.command(ctx, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	slog.Debug("exec", "cmd", cmd.Args)
	return cmd.Run()
}

func (p *Podman) AttachAgent(ctx context.Context, name string) error {
	cmd := p.command(ctx, "attach", "--detach-keys=ctrl-]", name)
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

func (p *Podman) StartAgent(ctx context.Context, cfg AgentContainerConfig) error {
	ttyFlag := "-ti"
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		ttyFlag = "-i"
	}
	args := []string{"run", "-d", ttyFlag, "--name", cfg.Name,
		"--restart=on-failure",
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

	cmd := p.command(ctx, args...)
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

	c := p.command(ctx, args...)
	slog.Debug("exec", "cmd", c.Args)
	return c.CombinedOutput()
}

func (p *Podman) ExecStdin(
	ctx context.Context, ctr string, cmd []string, stdin []byte,
) ([]byte, error) {
	args := append([]string{"exec", "-i", ctr}, cmd...)
	c := p.command(ctx, args...)
	c.Stdin = bytes.NewReader(stdin)
	slog.Debug("exec-stdin", "cmd", c.Args)
	return c.CombinedOutput()
}

func (p *Podman) List(ctx context.Context, labels map[string]string) ([]Info, error) {
	args := []string{"ps", "--all", "--format", "json"}
	for k, v := range labels {
		args = append(args, "--filter", "label="+k+"="+v)
	}
	cmd := p.command(ctx, args...)
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
	hash := filepath.Base(projectDir)
	vols := []string{
		"clampdown-" + p.Name() + "-" + hash + "-storage",
		"clampdown-" + p.Name() + "-" + hash + "-cache",
		"clampdown-" + p.Name() + "-" + hash + "-tmp",
	}
	err := p.command(ctx, append([]string{"volume", "rm", "--force"}, vols...)...).Run()
	if err != nil {
		slog.Debug("volume prune failed", "volumes", vols, "error", err)
	}

	// Remaining host dirs: <rt>-home, <rt>-state.
	dirs, err := filepath.Glob(filepath.Join(projectDir, p.Name()+"-*"))
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

func (p *Podman) CleanStale(ctx context.Context, prefix string) {
	cmd := p.command(ctx,
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
			rm := p.command(ctx, "rm", "-f", name)
			slog.Debug("exec", "cmd", rm.Args)
			_ = rm.Run()
		}
	}
}

func (p *Podman) Stop(ctx context.Context, names ...string) error {
	var hasErrored error
	for _, name := range names {
		cmd := p.command(ctx, "stop", "-t", "5", name)
		slog.Debug("exec", "cmd", cmd.Args)
		err := cmd.Run()
		if err != nil && hasErrored == nil {
			hasErrored = err
		}
	}
	return hasErrored
}

func (p *Podman) Remove(ctx context.Context, names ...string) error {
	var hasErrored error
	for _, name := range names {
		cmd := p.command(ctx, "rm", "-f", name)
		slog.Debug("exec", "cmd", cmd.Args)
		err := cmd.Run()
		if err != nil && hasErrored == nil {
			hasErrored = err
		}
	}
	return hasErrored
}

func (p *Podman) IsNative(ctx context.Context) (bool, error) {
	host := UnameRelease()
	if host == "" {
		return false, errors.New("cannot detect kernel")
	}

	cmd := p.command(ctx, "info", "-f", "json")
	out, err := cmd.Output()
	if err != nil {
		return false, errors.New("cannot detect kernel")
	}

	var info struct {
		Host struct {
			Kernel string `json:"kernel"`
		} `json:"host"`
	}
	err = json.Unmarshal(out, &info)
	if err != nil {
		slog.Warn("parse podman info", "error", err)
		return false, errors.New("cannot parse kernel info")
	}

	return info.Host.Kernel == host, nil
}

func (p *Podman) IsRootless(ctx context.Context) (bool, error) {
	cmd := p.command(ctx, "info", "-f", "json")
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
	cmd := p.command(ctx, "image", "inspect", "--format", "{{.Id}}", image)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (p *Podman) PushImage(ctx context.Context, sidecar string, images []string) error {
	saveCmd := p.command(ctx, append([]string{"save"}, images...)...)
	loadCmd := p.command(ctx,
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
// via the /log binary so it appears in `podman logs`.
func (p *Podman) Log(ctx context.Context, ctr string, source, msg string) error {
	_, err := p.Exec(ctx, ctr, []string{"/log", source, msg}, nil)
	return err
}

func (p *Podman) Logs(ctx context.Context, ctr string) ([]byte, error) {
	var buf bytes.Buffer
	cmd := p.command(ctx, "logs", "--timestamps", ctr)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	slog.Debug("exec", "cmd", cmd.Args)
	err := cmd.Run()
	return buf.Bytes(), err
}
