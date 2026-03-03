// SPDX-License-Identifier: GPL-3.0-only

package session_test

import (
	"testing"
	"time"

	"github.com/89luca89/clampdown/pkg/sandbox/session"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "<1m"},
		{5 * time.Minute, "5m"},
		{90 * time.Minute, "1h30m"},
		{2*time.Hour + 5*time.Minute, "2h5m"},
		{0, "<1m"},
	}
	for _, tt := range tests {
		got := session.FormatDuration(tt.d)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
