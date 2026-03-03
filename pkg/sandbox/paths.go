// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// AppName is the application identifier used for container labels, cache paths, etc.
const AppName = "clampdown"

// Resolved once at package init. All code uses these instead of os.Getenv.
var (
	Home      = os.Getenv("HOME")
	CacheHome = envOrDefault("XDG_CACHE_HOME", filepath.Join(Home, ".cache"))
	ConfigDir = filepath.Join(
		envOrDefault("XDG_CONFIG_HOME",
			filepath.Join(Home,
				".config")),
		AppName)
	DataDir = filepath.Join(
		envOrDefault("XDG_DATA_HOME",
			filepath.Join(Home,
				".local",
				"share")),
		AppName)
)

func envOrDefault(key, fallback string) string {
	v := os.Getenv(key)
	if v != "" {
		return v
	}
	return fallback
}

// ProjectPaths holds all computed directories for a sandbox run.
type ProjectPaths struct {
	Cache   string
	Home    string
	State   string
	Storage string
	Temp    string
}

// CacheBase is the root of all per-project cache directories.
var CacheBase = filepath.Join(CacheHome, AppName)

func GenPaths(rtName, workdir string) ProjectPaths {
	hash := projectHash(workdir)
	project := filepath.Join(CacheBase, hash)
	return ProjectPaths{
		Cache:   filepath.Join(project, rtName+"-cache"),
		Home:    filepath.Join(project, rtName+"-home"),
		State:   filepath.Join(project, rtName+"-state"),
		Storage: filepath.Join(project, rtName+"-storage"),
		Temp:    filepath.Join(project, rtName+"-tmp"),
	}
}

// ProjectDir returns the per-project cache directory for the given workdir.
func ProjectDir(workdir string) string {
	return filepath.Join(CacheBase, projectHash(workdir))
}

func EnsurePaths(p ProjectPaths) error {
	for _, d := range []string{p.Storage, p.Cache, p.Home, p.Temp, p.State} {
		err := os.MkdirAll(d, 0o750)
		if err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}
	return nil
}

func projectHash(workdir string) string {
	h := sha256.Sum256([]byte(workdir))
	return hex.EncodeToString(h[:6])
}
