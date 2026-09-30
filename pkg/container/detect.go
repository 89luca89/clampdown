// SPDX-License-Identifier: GPL-3.0-only

package container

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const (
	nameDocker = "docker"
	namePodman = "podman"
)

// Detect probes PATH for container runtimes in preference order.
func Detect() (Runtime, error) {
	for _, name := range []string{namePodman, nameDocker} {
		_, err := exec.LookPath(name)
		if err == nil {
			return forName(name)
		}
	}
	return nil, errors.New("no container runtime found (install podman or docker)")
}

// ForName returns the runtime for the given binary name.
func ForName(name string) (Runtime, error) {
	_, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("container runtime %q not found in PATH", name)
	}
	return forName(name)
}

// UnameRelease returns the host kernel release string (same as `uname -r`).
// Returns "" on error.
func UnameRelease() string {
	//nolint: noctx // single shot command, no need for ctx
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func forName(name string) (Runtime, error) {
	switch name {
	case namePodman:
		return &Podman{}, nil
	case nameDocker:
		return &Docker{}, nil
	default:
		return nil, fmt.Errorf("unsupported container runtime: %s", name)
	}
}
