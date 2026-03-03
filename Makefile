# SPDX-License-Identifier: GPL-3.0-only
CTR ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null || command -v nerdctl 2>/dev/null)

SIDECAR_IMAGE  := clampdown-sidecar:latest
CLAUDE_IMAGE   := clampdown-claude:latest
OPENCODE_IMAGE := clampdown-opencode:latest

# Go binary sources
SEAL_SRCS       := container-images/sidecar/seal/seal.go container-images/sidecar/seal/go.mod container-images/sidecar/seal/go.sum
ENTRYPOINT_SRCS := container-images/sidecar/entrypoint/entrypoint.go container-images/sidecar/entrypoint/go.mod
SECPOL_SRCS     := container-images/sidecar/hooks/createRuntime/security-policy.go container-images/sidecar/hooks/createRuntime/go.mod
SEALINJ_SRCS    := container-images/sidecar/hooks/precreate/seal-inject.go container-images/sidecar/hooks/precreate/go.mod

# All sidecar container inputs (non-Go sources)
SIDECAR_SRCS := container-images/sidecar/Containerfile \
		container-images/sidecar/shims/rename_exdev_shim.c \
		container-images/sidecar/containers.conf \
		container-images/sidecar/policy.json \
		container-images/sidecar/registries.conf \
		container-images/sidecar/seccomp_nested.json \
		container-images/sidecar/hooks/createRuntime/security-policy.json \
		container-images/sidecar/hooks/precreate/seal-inject.json

# Pre-built Go binaries that feed into the sidecar image
SIDECAR_BINS := container-images/sidecar/seal/sandbox-seal \
		container-images/sidecar/entrypoint/entrypoint \
		container-images/sidecar/hooks/createRuntime/security-policy \
		container-images/sidecar/hooks/precreate/seal-inject

CLAUDE_SRCS   := container-images/claude/Containerfile
OPENCODE_SRCS := container-images/opencode/Containerfile

.PHONY: all test test-integration seal sidecar claude opencode launcher install clean

all: .sidecar.stamp .claude.stamp .opencode.stamp launcher

test:
	go test -v ./pkg/...
	cd container-images/sidecar/seal && go test -v .
	cd container-images/sidecar/hooks/createRuntime && go test -v .
	cd container-images/sidecar/hooks/precreate && go test -v .
	cd container-images/sidecar/entrypoint && go test -v .

# Integration tests need these images on the host (pushed into sidecar at test start).
INTEG_IMAGES := alpine python:alpine ghcr.io/edera-dev/am-i-isolated:nightly

test-integration: .sidecar.stamp
	@for img in $(INTEG_IMAGES); do \
		$(CTR) image exists $$img 2>/dev/null || $(CTR) pull $$img; \
		done
	go test -tags integration -count=1 -timeout 600s -v ./pkg/sandbox/

# --- Go binaries (host builds, CGO_ENABLED=0) ---

container-images/sidecar/seal/sandbox-seal: $(SEAL_SRCS)
	cd container-images/sidecar/seal && CGO_ENABLED=0 go build -ldflags='-s -w' -o sandbox-seal .

container-images/sidecar/entrypoint/entrypoint: $(ENTRYPOINT_SRCS)
	cd container-images/sidecar/entrypoint && CGO_ENABLED=0 go build -ldflags='-s -w' -o entrypoint .

container-images/sidecar/hooks/createRuntime/security-policy: $(SECPOL_SRCS)
	cd container-images/sidecar/hooks/createRuntime && CGO_ENABLED=0 go build -ldflags='-s -w' -o security-policy .

container-images/sidecar/hooks/precreate/seal-inject: $(SEALINJ_SRCS)
	cd container-images/sidecar/hooks/precreate && CGO_ENABLED=0 go build -ldflags='-s -w' -o seal-inject .

# --- Container images (stamp-based, skip when sources unchanged) ---

.sidecar.stamp: $(SIDECAR_BINS) $(SIDECAR_SRCS)
	$(CTR) build -f container-images/sidecar/Containerfile -t $(SIDECAR_IMAGE) container-images/sidecar/
	@touch $@

.claude.stamp: container-images/sidecar/seal/sandbox-seal $(CLAUDE_SRCS)
	cp container-images/sidecar/seal/sandbox-seal container-images/claude/sandbox-seal
	$(CTR) build -f container-images/claude/Containerfile -t $(CLAUDE_IMAGE) container-images/claude/
	@touch $@

.opencode.stamp: container-images/sidecar/seal/sandbox-seal $(OPENCODE_SRCS)
	cp container-images/sidecar/seal/sandbox-seal container-images/opencode/sandbox-seal
	$(CTR) build -f container-images/opencode/Containerfile -t $(OPENCODE_IMAGE) container-images/opencode/
	@touch $@

# --- Aliases ---

seal: container-images/sidecar/seal/sandbox-seal
sidecar: .sidecar.stamp
claude: .claude.stamp
opencode: .opencode.stamp

launcher:
	CGO_ENABLED=0 go build -ldflags='-s -w' -o clampdown .

install: launcher
	install -Dm755 clampdown ~/.local/bin/clampdown

clean:
	rm -f clampdown \
		.sidecar.stamp .claude.stamp .opencode.stamp \
		container-images/sidecar/seal/sandbox-seal \
		container-images/claude/sandbox-seal \
		container-images/opencode/sandbox-seal \
		container-images/sidecar/entrypoint/entrypoint \
		container-images/sidecar/hooks/createRuntime/security-policy \
		container-images/sidecar/hooks/precreate/seal-inject
	$(CTR) rmi $(SIDECAR_IMAGE) 2>/dev/null || true
	$(CTR) rmi $(CLAUDE_IMAGE) 2>/dev/null || true
	$(CTR) rmi $(OPENCODE_IMAGE) 2>/dev/null || true
