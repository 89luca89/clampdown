# SPDX-License-Identifier: GPL-3.0-only
CTR      ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null || command -v nerdctl 2>/dev/null)
GOARCH   ?= $(shell go env GOARCH)
REGISTRY ?=
TAG      ?= latest
PLATFORM ?= linux/$(GOARCH)

SIDECAR_IMAGE  := clampdown-sidecar:latest
CLAUDE_IMAGE   := clampdown-claude:latest
CODEX_IMAGE    := clampdown-codex:latest
OPENCODE_IMAGE := clampdown-opencode:latest
PROXY_IMAGE    := clampdown-proxy:latest

# Go binary sources
SEAL_SRCS       := container-images/sidecar/seal/seal.go container-images/sidecar/seal/go.mod container-images/sidecar/seal/go.sum
ENTRYPOINT_SRCS := container-images/sidecar/entrypoint/entrypoint.go container-images/sidecar/entrypoint/bootstrap.go container-images/sidecar/entrypoint/protect.go container-images/sidecar/entrypoint/filter.go container-images/sidecar/entrypoint/supervisor.go container-images/sidecar/entrypoint/handlers.go container-images/sidecar/entrypoint/execallow.go container-images/sidecar/entrypoint/go.mod container-images/sidecar/entrypoint/go.sum
LOG_SRCS        := container-images/sidecar/log/log.go container-images/sidecar/log/go.mod
SECPOL_SRCS     := container-images/sidecar/hooks/createRuntime/security-policy.go container-images/sidecar/hooks/createRuntime/go.mod
SEALINJ_SRCS    := container-images/sidecar/hooks/precreate/seal-inject.go container-images/sidecar/hooks/precreate/go.mod
PROXY_SRCS      := container-images/proxy/proxy.go container-images/proxy/go.mod

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
		container-images/sidecar/log/log \
		container-images/sidecar/hooks/createRuntime/security-policy \
		container-images/sidecar/hooks/precreate/seal-inject

HELPERS_SRC       := container-images/helpers/sandbox_command_helper.sh
NETWORK_HELPER    := container-images/helpers/sandbox_network_helper.c
CLAUDE_SRCS       := container-images/claude/Containerfile $(HELPERS_SRC) $(NETWORK_HELPER)
CODEX_SRCS        := container-images/codex/Containerfile $(HELPERS_SRC) $(NETWORK_HELPER)
OPENCODE_SRCS     := container-images/opencode/Containerfile $(HELPERS_SRC) $(NETWORK_HELPER)

.PHONY: all binaries test test-integration lint \
	seal sidecar claude codex opencode proxy launcher install clean \
	push-sidecar push-claude push-codex push-opencode push-proxy push-images \
	manifest save-images dev undev audit-escape audit-project

all: .sidecar.stamp .claude.stamp .codex.stamp .opencode.stamp .proxy.stamp launcher

lint:
	# Avoid if x := foo; condition() type of expressions
	@if grep -rnE --include='*.go' --exclude='*_test.go' 'if[[:space:]]+.*:=.*;' pkg/ container-images/ main.go 2>/dev/null; then \
		echo "" >&2; \
		echo "lint: if-init-statement forbidden (see AGENTS.md Go Style)" >&2; \
		exit 1; \
	fi
	@gopls check -severity=hint $$(find * -iname "*.go")
	@golangci-lint run ./...

test:
	go test -v -race ./pkg/...
	cd container-images/sidecar/entrypoint && go test -v -race .
	cd container-images/sidecar/seal && go test -v -race .
	cd container-images/sidecar/hooks/createRuntime && go test -v -race .
	cd container-images/sidecar/hooks/precreate && go test -v -race .

# Integration tests need these images on the host (pushed into sidecar at test start).
INTEG_IMAGES := alpine python:alpine

test-integration: .sidecar.stamp
	@for img in $(INTEG_IMAGES); do \
		$(CTR) image inspect $$img >/dev/null 2>&1 || $(CTR) pull $$img; \
		done
	CTR=$(CTR) go test -tags integration -count=1 -timeout 600s -v ./pkg/sandbox/

# --- Go binaries (host builds, CGO_ENABLED=0) ---

container-images/sidecar/seal/sandbox-seal: $(SEAL_SRCS)
	cd container-images/sidecar/seal && CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -ldflags='-s -w' -o sandbox-seal .

container-images/sidecar/entrypoint/entrypoint: $(ENTRYPOINT_SRCS)
	cd container-images/sidecar/entrypoint && CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -ldflags='-s -w' -o entrypoint .

container-images/sidecar/log/log: $(LOG_SRCS)
	cd container-images/sidecar/log && CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -ldflags='-s -w' -o log .

container-images/sidecar/hooks/createRuntime/security-policy: $(SECPOL_SRCS)
	cd container-images/sidecar/hooks/createRuntime && CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -ldflags='-s -w' -o security-policy .

container-images/sidecar/hooks/precreate/seal-inject: $(SEALINJ_SRCS)
	cd container-images/sidecar/hooks/precreate && CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -ldflags='-s -w' -o seal-inject .

container-images/proxy/auth-proxy: $(PROXY_SRCS)
	cd container-images/proxy && CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -ldflags='-s -w' -o auth-proxy .

# Build all Go binaries for the current GOARCH (used by CI release).
binaries: $(SIDECAR_BINS) container-images/proxy/auth-proxy launcher

# --- Container images (stamp-based, skip when sources unchanged) ---

.sidecar.stamp: $(SIDECAR_BINS) $(SIDECAR_SRCS)
	$(CTR) build --build-arg TARGETARCH=$(GOARCH) -f container-images/sidecar/Containerfile -t $(SIDECAR_IMAGE) container-images/sidecar/
	@touch $@

.claude.stamp: container-images/sidecar/seal/sandbox-seal $(CLAUDE_SRCS)
	$(CTR) build --build-arg TARGETARCH=$(GOARCH) -f container-images/claude/Containerfile -t $(CLAUDE_IMAGE) container-images/
	@touch $@

.codex.stamp: container-images/sidecar/seal/sandbox-seal $(CODEX_SRCS)
	$(CTR) build --build-arg TARGETARCH=$(GOARCH) -f container-images/codex/Containerfile -t $(CODEX_IMAGE) container-images/
	@touch $@

.opencode.stamp: container-images/sidecar/seal/sandbox-seal $(OPENCODE_SRCS)
	$(CTR) build --build-arg TARGETARCH=$(GOARCH) -f container-images/opencode/Containerfile -t $(OPENCODE_IMAGE) container-images/
	@touch $@

.proxy.stamp: container-images/proxy/auth-proxy container-images/sidecar/seal/sandbox-seal container-images/proxy/Containerfile
	$(CTR) build --build-arg TARGETARCH=$(GOARCH) -f container-images/proxy/Containerfile -t $(PROXY_IMAGE) container-images/
	@touch $@

# --- Registry image builds (require REGISTRY and TAG) ---
# Build and push a single-platform image tagged as $(REGISTRY)/...:$(TAG)-$(GOARCH).

push-sidecar: $(SIDECAR_BINS) $(SIDECAR_SRCS)
	$(CTR) build \
		--platform $(PLATFORM) \
		-t $(REGISTRY)/clampdown-sidecar:$(TAG)-$(GOARCH) \
		-f container-images/sidecar/Containerfile \
		container-images/sidecar/
	$(CTR) push $(REGISTRY)/clampdown-sidecar:$(TAG)-$(GOARCH)

push-claude: container-images/sidecar/seal/sandbox-seal $(CLAUDE_SRCS)
	$(CTR) build \
		--platform $(PLATFORM) \
		-t $(REGISTRY)/clampdown-claude:$(TAG)-$(GOARCH) \
		-f container-images/claude/Containerfile \
		container-images/
	$(CTR) push $(REGISTRY)/clampdown-claude:$(TAG)-$(GOARCH)

push-codex: container-images/sidecar/seal/sandbox-seal $(CODEX_SRCS)
	$(CTR) build \
		--platform $(PLATFORM) \
		-t $(REGISTRY)/clampdown-codex:$(TAG)-$(GOARCH) \
		-f container-images/codex/Containerfile \
		container-images/
	$(CTR) push $(REGISTRY)/clampdown-codex:$(TAG)-$(GOARCH)

push-opencode: container-images/sidecar/seal/sandbox-seal $(OPENCODE_SRCS)
	$(CTR) build \
		--platform $(PLATFORM) \
		-t $(REGISTRY)/clampdown-opencode:$(TAG)-$(GOARCH) \
		-f container-images/opencode/Containerfile \
		container-images/
	$(CTR) push $(REGISTRY)/clampdown-opencode:$(TAG)-$(GOARCH)

push-proxy: container-images/proxy/auth-proxy container-images/sidecar/seal/sandbox-seal container-images/proxy/Containerfile
	$(CTR) build \
		--platform $(PLATFORM) \
		-t $(REGISTRY)/clampdown-proxy:$(TAG)-$(GOARCH) \
		-f container-images/proxy/Containerfile \
		container-images/
	$(CTR) push $(REGISTRY)/clampdown-proxy:$(TAG)-$(GOARCH)

push-images: push-sidecar push-claude push-codex push-opencode push-proxy

# Merge per-arch images into a multi-arch manifest at :$(TAG) and :latest.
# Requires docker 20.10+ or podman 4+.
manifest:
	@for img in sidecar claude codex opencode proxy; do \
		$(CTR) manifest create \
			$(REGISTRY)/clampdown-$$img:$(TAG) \
			$(REGISTRY)/clampdown-$$img:$(TAG)-amd64 \
			$(REGISTRY)/clampdown-$$img:$(TAG)-arm64; \
		$(CTR) manifest push $(REGISTRY)/clampdown-$$img:$(TAG); \
		$(CTR) manifest create \
			$(REGISTRY)/clampdown-$$img:latest \
			$(REGISTRY)/clampdown-$$img:$(TAG)-amd64 \
			$(REGISTRY)/clampdown-$$img:$(TAG)-arm64; \
		$(CTR) manifest push $(REGISTRY)/clampdown-$$img:latest; \
	done

# Pull the per-arch images and export each as a compressed tar archive.
save-images:
	@for img in sidecar claude codex opencode proxy; do \
		$(CTR) pull --platform $(PLATFORM) $(REGISTRY)/clampdown-$$img:$(TAG)-$(GOARCH); \
		$(CTR) save $(REGISTRY)/clampdown-$$img:$(TAG)-$(GOARCH) | gzip > clampdown-$$img-$(GOARCH).tar.gz; \
	done

# --- Aliases ---

seal: container-images/sidecar/seal/sandbox-seal
sidecar: .sidecar.stamp
claude: .claude.stamp
codex: .codex.stamp
opencode: .opencode.stamp
proxy: .proxy.stamp

launcher:
	CGO_ENABLED=0 GOARCH=$(GOARCH) go build -ldflags='-s -w' -o clampdown .

install: launcher
	install -Dm755 clampdown ~/.local/bin/clampdown

CONFIG_DIR  := $(shell echo "$${XDG_CONFIG_HOME:-$$HOME/.config}/clampdown")
CONFIG_FILE := $(CONFIG_DIR)/config.json

dev: all install
	@mkdir -p "$(CONFIG_DIR)"
	@if [ -f "$(CONFIG_FILE)" ]; then \
		tmp=$$(mktemp); \
		jq '. + {"sidecar_image":"$(SIDECAR_IMAGE)","proxy_image":"$(PROXY_IMAGE)","agent_images":{"claude":"$(CLAUDE_IMAGE)","codex":"$(CODEX_IMAGE)","opencode":"$(OPENCODE_IMAGE)"}}' \
			"$(CONFIG_FILE)" > "$$tmp" && mv "$$tmp" "$(CONFIG_FILE)"; \
	else \
		printf '{"sidecar_image":"%s","proxy_image":"%s","agent_images":{"claude":"%s","codex":"%s","opencode":"%s"}}\n' \
			"$(SIDECAR_IMAGE)" "$(PROXY_IMAGE)" "$(CLAUDE_IMAGE)" "$(CODEX_IMAGE)" "$(OPENCODE_IMAGE)" > "$(CONFIG_FILE)"; \
	fi
	@echo "config: $(CONFIG_FILE)"
	@echo "  sidecar_image:          $(SIDECAR_IMAGE)"
	@echo "  proxy_image:            $(PROXY_IMAGE)"
	@echo "  agent_images.claude:    $(CLAUDE_IMAGE)"
	@echo "  agent_images.codex:     $(CODEX_IMAGE)"
	@echo "  agent_images.opencode:  $(OPENCODE_IMAGE)"

# Remove local image overrides from config.json.
undev:
	@if [ -f "$(CONFIG_FILE)" ]; then \
		tmp=$$(mktemp); \
		jq 'del(.sidecar_image, .proxy_image, .agent_images)' \
			"$(CONFIG_FILE)" > "$$tmp" && mv "$$tmp" "$(CONFIG_FILE)"; \
		echo "removed image overrides from $(CONFIG_FILE)"; \
	else \
		echo "no config file at $(CONFIG_FILE)"; \
	fi

clean:
	rm -f clampdown \
		.sidecar.stamp .claude.stamp .codex.stamp .opencode.stamp .proxy.stamp \
		container-images/sidecar/seal/sandbox-seal \
		container-images/sidecar/entrypoint/entrypoint \
		container-images/sidecar/log/log \
		container-images/sidecar/hooks/createRuntime/security-policy \
		container-images/sidecar/hooks/precreate/seal-inject \
		container-images/proxy/auth-proxy
	$(CTR) rmi $(SIDECAR_IMAGE) 2>/dev/null || true
	$(CTR) rmi $(CLAUDE_IMAGE) 2>/dev/null || true
	$(CTR) rmi $(CODEX_IMAGE) 2>/dev/null || true
	$(CTR) rmi $(OPENCODE_IMAGE) 2>/dev/null || true
	$(CTR) rmi $(PROXY_IMAGE) 2>/dev/null || true

# --- Security Audit ---
AUDIT_AGENT ?= claude

# Sandbox escape audit - agent attempts to break out of confinement
audit-escape: all
	./tools/security-audit/security-audit-sandbox.sh $(AUDIT_AGENT)

# Full project audit: holistic analysis, then file-by-file sweep
audit-project:
	@echo "=== Holistic project audit ==="
	@AGENT=$(AUDIT_AGENT) ./tools/security-audit/security-audit.sh --project .

audit-project-files:
	@echo "=== File-by-file sweep ==="
	@find pkg/ container-images/ -type f -print0 | xargs -0 file --mime-type | grep text | cut -d: -f1 | xargs -I{} env AGENT=$(AUDIT_AGENT) ./tools/security-audit/security-audit.sh --file {}
