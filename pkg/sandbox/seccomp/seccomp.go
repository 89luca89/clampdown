// SPDX-License-Identifier: GPL-3.0-only

package seccomp

import (
	"crypto/sha256"
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed seccomp_sidecar.json
var sidecarProfile []byte

//go:embed seccomp_agent.json
var agentProfile []byte

// EnsureProfiles writes embedded seccomp profiles to dataDir/seccomp/
// if missing or stale. Returns the host paths to each profile.
func EnsureProfiles(dataDir string) (string, string, error) {
	dir := filepath.Join(dataDir, "seccomp")
	err := os.MkdirAll(dir, 0o750)
	if err != nil {
		return "", "", err
	}

	sidecarPath := filepath.Join(dir, "sidecar.json")
	agentPath := filepath.Join(dir, "agent.json")

	err = writeIfStale(sidecarPath, sidecarProfile)
	if err != nil {
		return "", "", err
	}
	err = writeIfStale(agentPath, agentProfile)
	if err != nil {
		return "", "", err
	}
	return sidecarPath, agentPath, nil
}

func writeIfStale(path string, content []byte) error {
	want := sha256.Sum256(content)
	existing, err := os.ReadFile(path)
	if err == nil {
		got := sha256.Sum256(existing)
		if got == want {
			return nil
		}
	}
	return os.WriteFile(path, content, 0o600)
}
