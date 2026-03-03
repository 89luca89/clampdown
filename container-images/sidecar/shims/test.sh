#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
#
# Build the EXDEV rename shim and run cross-libc tests.
#
# Uses podman to test on Alpine (musl), Debian (glibc), Ubuntu (glibc),
# and Fedora (glibc).  Each distro runs the test suite twice: once
# without the shim (expecting EXDEV) and once with LD_PRELOAD.
#
# Usage: sh sidecar/shims/test.sh

set -eu

SHIM_DIR="$(cd "$(dirname "$0")" && pwd)"
SHIM_SRC="$SHIM_DIR/rename_exdev_shim.c"
SHIM_SO="$SHIM_DIR/rename_exdev_shim.so"
TEST_SRC="$SHIM_DIR/test_shim.c"

# Build the .so with musl + -nostdlib (no DT_NEEDED for any libc).
echo "--- building shim ---"
podman run --rm -v "$SHIM_DIR:/shims:Z" alpine:latest sh -c '
    apk add --no-cache gcc musl-dev >/dev/null 2>&1
    gcc -shared -fPIC -Os -s -nostdlib \
        -Wall -Wextra -Werror \
        -o /shims/rename_exdev_shim.so \
        /shims/rename_exdev_shim.c
'
echo "built: $SHIM_SO"
echo ""

total_pass=0
total_fail=0

run_distro() {
    image="$1"
    label="$2"
    install_cmd="$3"

    echo "========================================"
    echo "  $label"
    echo "========================================"

    result=$(podman run --rm \
        -v "$SHIM_DIR:/shims:Z" \
        --tmpfs /tmp \
        "$image" sh -c "
            $install_cmd
            gcc -Wall -Werror -o /bin/test_shim /shims/test_shim.c

            echo '--- without shim ---'
            cd /shims && test_shim 2>&1 || true

            echo ''
            echo '--- with shim ---'
            cd /shims && LD_PRELOAD=/shims/rename_exdev_shim.so test_shim 2>&1
        " 2>&1)

    echo "$result"
    echo ""

    # Count results from the "with shim" run (last results line).
    shim_line=$(echo "$result" | grep 'passed,' | tail -1)
    p=$(echo "$shim_line" | sed 's/ passed.*//')
    f=$(echo "$shim_line" | sed 's/.*, //' | sed 's/ failed//')
    total_pass=$((total_pass + p))
    total_fail=$((total_fail + f))
}

run_distro \
    "alpine:latest" \
    "Alpine (musl)" \
    "apk add --no-cache gcc musl-dev >/dev/null 2>&1"

run_distro \
    "debian:bookworm-slim" \
    "Debian bookworm (glibc)" \
    "apt-get update -qq && apt-get install -y -qq gcc libc6-dev >/dev/null 2>&1"

run_distro \
    "ubuntu:24.04" \
    "Ubuntu 24.04 (glibc)" \
    "apt-get update -qq && apt-get install -y -qq gcc libc6-dev >/dev/null 2>&1"

run_distro \
    "fedora:41" \
    "Fedora 41 (glibc)" \
    "dnf install -y -q gcc >/dev/null 2>&1"

# Clean up built .so.
rm -f "$SHIM_SO"

echo "========================================"
echo "  TOTAL: $total_pass passed, $total_fail failed"
echo "========================================"

[ "$total_fail" -eq 0 ]
