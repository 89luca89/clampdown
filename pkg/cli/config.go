// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/89luca89/clampdown/pkg/sandbox"
)

// Config holds user preferences loaded from config.json.
type Config struct {
	AgentAllow      string   `json:"agent_allow"`
	AgentPolicy     string   `json:"agent_policy"`
	AllowHooks      bool     `json:"allow_hooks"`
	CPUs            string   `json:"cpus"`
	DisableTripwire bool     `json:"disable_tripwire"`
	GH              bool     `json:"gh"`
	GitConfig       bool     `json:"gitconfig"`
	Memory          string   `json:"memory"`
	PodPolicy       string   `json:"pod_policy"`
	ProtectPaths    []string `json:"protect_paths"`
	RegistryAuth    bool     `json:"registry_auth"`
	RequireDigest   string   `json:"require_digest"`
	Runtime         string   `json:"runtime"`
	SSH             bool     `json:"ssh"`
}

// LoadConfig reads $XDG_CONFIG_HOME/clampdown/config.json.
// Missing file returns zero-value Config (all defaults).
func LoadConfig() Config {
	path := filepath.Join(sandbox.ConfigDir, "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}
	}
	var cfg Config
	_ = json.Unmarshal(data, &cfg)
	return cfg
}
