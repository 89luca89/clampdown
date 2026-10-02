// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package sandbox_test

import (
	"context"
	"testing"
	"time"
)

const (
	rustImage     = "rust:alpine"
	goAlpineImage = "golang:alpine"
	nodeImage     = "node:alpine"
	wlRustImage   = "localhost/clampdown-wl-rust:latest"
	wlGoImage     = "localhost/clampdown-wl-go:latest"
	wlCImage      = "localhost/clampdown-wl-c:latest"
)

// CARGO_HOME and GOPATH point under HOME because the image defaults
// (/usr/local/cargo, /go) are root-owned and seal-inject runs as non-root.
func workloadRun(image, subdir, shellCmd string) []string {
	return []string{
		innerPodman, "run", "--rm",
		"-v", workdir + ":" + workdir, "-w", workdir,
		"-e", "HOME=" + subdir,
		"-e", "PATH=/go/bin:/usr/local/go/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"-e", "CARGO_HOME=" + subdir + "/.cargo",
		"-e", "GOPATH=" + subdir + "/go",
		image, "sh", "-c",
		"mkdir -p " + subdir + " && cd " + subdir + " && " + shellCmd,
	}
}

// buildah skips precreate, so RUN executes as root; the image still runs
// as non-root when invoked via workloadRun.
func buildWorkloadImage(t *testing.T, tag, containerfile string) {
	t.Helper()
	cmd := []string{innerPodman, "build", "-t", tag, "-f", "-", "/tmp"}
	out, err := sidecarExecStdinTimeout(t, sidecarName, cmd,
		[]byte(containerfile), 300*time.Second)
	if err != nil {
		t.Fatalf("build %s: %v\n%s", tag, err, out)
	}
}

func TestWorkloads(t *testing.T) {
	ctx := context.Background()
	err := rt.PushImage(ctx, sidecarName, []string{
		rustImage, goAlpineImage, nodeImage,
	})
	if err != nil {
		t.Fatalf("push workload images: %v", err)
	}

	buildWorkloadImage(t, wlRustImage,
		"FROM rust:alpine\nRUN apk add --no-cache build-base git\n")
	buildWorkloadImage(t, wlGoImage,
		"FROM golang:alpine\nRUN apk add --no-cache git\n")
	buildWorkloadImage(t, wlCImage,
		"FROM alpine\nRUN apk add --no-cache build-base git "+
			"autoconf automake libtool linux-headers\n")

	t.Run("install_rust_ripgrep", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExecTimeout(t, sidecarName, workloadRun(
			wlRustImage, workdir+"/install_rust",
			"cargo install ripgrep --version 14.1.1 --root .",
		), 900*time.Second)
		requireSuccess(t, out, err)
	})

	t.Run("install_go_cobra_cli", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExecTimeout(t, sidecarName, workloadRun(
			goAlpineImage, workdir+"/install_go",
			"go install github.com/spf13/cobra-cli@v1.3.0",
		), 300*time.Second)
		requireSuccess(t, out, err)
	})

	t.Run("install_node_express", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExecTimeout(t, sidecarName, workloadRun(
			nodeImage, workdir+"/install_node",
			"npm install express@4.21.1 && node -e 'require(\"express\")()'",
		), 300*time.Second)
		requireSuccess(t, out, err)
	})

	t.Run("install_python_flask", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExecTimeout(t, sidecarName, workloadRun(
			pythonAlpineImage, workdir+"/install_python",
			"pip install --user flask==3.1.0 && python -c 'import flask; print(flask.__version__)'",
		), 300*time.Second)
		requireSuccess(t, out, err)
	})

	t.Run("build_go_clampdown", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExecTimeout(t, sidecarName, workloadRun(
			wlGoImage, workdir+"/build_go",
			"git clone --depth=1 https://github.com/89luca89/clampdown.git repo && "+
				"cd repo && go build -o clampdown .",
		), 300*time.Second)
		requireSuccess(t, out, err)
	})

	t.Run("build_rust_hyperfine", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExecTimeout(t, sidecarName, workloadRun(
			wlRustImage, workdir+"/build_rust",
			"git clone --depth=1 --branch v1.19.0 https://github.com/sharkdp/hyperfine.git repo && "+
				"cd repo && cargo build --release",
		), 600*time.Second)
		requireSuccess(t, out, err)
	})

	t.Run("build_c_redis", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExecTimeout(t, sidecarName, workloadRun(
			wlCImage, workdir+"/build_redis",
			"git clone --depth=1 --branch 7.4.1 https://github.com/redis/redis.git repo && "+
				"cd repo && make -j$(nproc) BUILD_TLS=no",
		), 300*time.Second)
		requireSuccess(t, out, err)
	})

	t.Run("build_c_jq", func(t *testing.T) {
		t.Parallel()
		out, err := sidecarExecTimeout(t, sidecarName, workloadRun(
			wlCImage, workdir+"/build_jq",
			"git clone --depth=1 --shallow-submodules --recurse-submodules "+
				"--branch jq-1.8.1 https://github.com/jqlang/jq.git repo && "+
				"cd repo && autoreconf -fi && ./configure --with-oniguruma=builtin && make -j$(nproc)",
		), 300*time.Second)
		requireSuccess(t, out, err)
	})
}
