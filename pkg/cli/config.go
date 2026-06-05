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
	AgentAllow     string            `json:"agent_allow"`
	AgentImages    map[string]string `json:"agent_images"`
	AgentPolicy    string            `json:"agent_policy"`
	AllowHooks     bool              `json:"allow_hooks"`
	CPUs           int               `json:"cpus"`
	EnableTripwire bool              `json:"tripwire"`
	GH             bool              `json:"gh"`
	GitConfig      bool              `json:"gitconfig"`
	Memory         string            `json:"memory"`
	PodPolicy      string            `json:"pod_policy"`
	MaskPaths      []string          `json:"mask_paths"`
	ProtectPaths   []string          `json:"protect_paths"`
	ProxyImage     string            `json:"proxy_image"`
	RegistryAuth   bool              `json:"registry_auth"`
	RequireDigest  string            `json:"require_digest"`
	Runtime        string            `json:"runtime"`
	SidecarImage   string            `json:"sidecar_image"`
	SSH            bool              `json:"ssh"`
	UnmaskPaths    []string          `json:"unmask_paths"`
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
