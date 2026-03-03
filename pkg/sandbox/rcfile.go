// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
)

// ParseRC reads KEY=VALUE pairs from path.
// Lines starting with # are comments. Blank lines are ignored.
// Returns an empty map, nil if the file does not exist.
func ParseRC(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}

	out := make(map[string]string)
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: missing '='", path, i+1)
		}
		k = strings.TrimSpace(k)
		if k == "" {
			return nil, fmt.Errorf("%s:%d: empty key", path, i+1)
		}
		v = strings.TrimSpace(v)

		// strip away quotes
		if len(v) >= 2 {
			q := v[0]
			if (q == '"' || q == '\'') && v[len(v)-1] == q {
				v = v[1 : len(v)-1]
			}
		}
		out[k] = v
	}
	return out, nil
}

// LoadRC reads $XDG_CONFIG_HOME/clampdown/clampdownrc (global) then
// $workdir/.clampdownrc (project). Project values override global on conflict.
func LoadRC(workdir string) (map[string]string, error) {
	global, err := ParseRC(filepath.Join(ConfigDir, "clampdownrc"))
	if err != nil {
		return nil, err
	}
	project, err := ParseRC(filepath.Join(workdir, ".clampdownrc"))
	if err != nil {
		return nil, err
	}
	maps.Copy(global, project)
	return global, nil
}
