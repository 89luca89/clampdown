// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import "testing"

// evalSysctl drives the hard-fail preflight. Each row of kernelSysctls has one
// safe window and the test exercises both sides of it, plus the whitespace and
// unparseable cases that come straight from /proc.
func TestEvalSysctl(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		raw    string
		wantOK bool
	}{
		// vm.unprivileged_userfaultfd: safe iff ==0.
		{"userfaultfd disabled", "/proc/sys/vm/unprivileged_userfaultfd", "0\n", true},
		{"userfaultfd enabled", "/proc/sys/vm/unprivileged_userfaultfd", "1\n", false},

		// kernel.unprivileged_bpf_disabled: safe iff ==1 or ==2.
		{"bpf disabled", "/proc/sys/kernel/unprivileged_bpf_disabled", "1\n", true},
		{"bpf locked", "/proc/sys/kernel/unprivileged_bpf_disabled", "2\n", true},
		{"bpf allowed", "/proc/sys/kernel/unprivileged_bpf_disabled", "0\n", false},

		// kernel.kptr_restrict: safe iff >=1.
		{"kptr hidden", "/proc/sys/kernel/kptr_restrict", "1\n", true},
		{"kptr strict", "/proc/sys/kernel/kptr_restrict", "2\n", true},
		{"kptr leaked", "/proc/sys/kernel/kptr_restrict", "0\n", false},

		// kernel.dmesg_restrict: safe iff ==1.
		{"dmesg restricted", "/proc/sys/kernel/dmesg_restrict", "1\n", true},
		{"dmesg world-readable", "/proc/sys/kernel/dmesg_restrict", "0\n", false},

		// kernel.perf_event_paranoid: safe iff >=2.
		{"perf paranoid=2", "/proc/sys/kernel/perf_event_paranoid", "2\n", true},
		{"perf paranoid=3", "/proc/sys/kernel/perf_event_paranoid", "3\n", true},
		{"perf permissive=1", "/proc/sys/kernel/perf_event_paranoid", "1\n", false},
		{"perf permissive=-1", "/proc/sys/kernel/perf_event_paranoid", "-1\n", false},

		// kernel.yama.ptrace_scope: safe iff 1 or 2. =0 is permissive;
		// =3 is a supervisor-incompatibility (no-attach breaks the
		// seccomp-notif /proc/<pid>/mem reads) and must also fail.
		{"yama relational", "/proc/sys/kernel/yama/ptrace_scope", "1\n", true},
		{"yama capability", "/proc/sys/kernel/yama/ptrace_scope", "2\n", true},
		{"yama permissive", "/proc/sys/kernel/yama/ptrace_scope", "0\n", false},
		{"yama no-attach breaks supervisor", "/proc/sys/kernel/yama/ptrace_scope", "3\n", false},

		// Whitespace tolerance: /proc entries always end in a newline, but a
		// trailing-space variant must not slip past as unparseable.
		{"trailing whitespace", "/proc/sys/kernel/dmesg_restrict", "  1  \n", true},

		// Unparseable contents fail closed. If the kernel ever hands back a
		// non-integer value for a path we check, we treat the host as unsafe
		// rather than silently assuming the safe value.
		{"garbage value", "/proc/sys/kernel/dmesg_restrict", "yes\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, msg := evalSysctl(tt.path, tt.raw)
			if ok != tt.wantOK {
				t.Fatalf("evalSysctl(%s, %q) ok=%v, want %v (msg=%q)",
					tt.path, tt.raw, ok, tt.wantOK, msg)
			}
			if !ok && msg == "" {
				t.Errorf("evalSysctl(%s, %q): unsafe result returned empty message",
					tt.path, tt.raw)
			}
			if ok && msg != "" {
				t.Errorf("evalSysctl(%s, %q): safe result returned non-empty message %q",
					tt.path, tt.raw, msg)
			}
		})
	}
}
