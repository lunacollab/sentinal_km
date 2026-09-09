#!/usr/bin/env bash
# build-arm64.sh -- aarch64 compile-only lane for the kernel module (P1.3).
#
# Verifies the module builds for aarch64: the SENTINEL_SC_* re-key, the
# per-arch __arm64_sys_* wrapper symbols, and the SENTINEL_REGS_ARG shim are
# compiled against a real arm64 Kbuild tree. It deliberately does NOT link
# against a built kernel (no Module.symvers), so unresolved-symbol warnings
# from modpost are expected and non-fatal -- the gate is: sources compile and
# the produced module is aarch64 ELF. The runtime path remains QEMU.
#
# Usage:
#   scripts/build-arm64.sh                  # fetches linux-6.6 LTS into ~/.cache
#   KDIR=<arm64 build tree> scripts/build-arm64.sh
#
# Exit 0 == PASS. The module is written to a scratch dir (repo untouched);
# its path is printed on success.
set -euo pipefail

CACHE="${CACHE:-${HOME}/.cache/sentinel-km}"
TOOLCHAIN="${TOOLCHAIN:-aarch64-linux-gnu-}"
KDIR="${KDIR:-}"

echo "== toolchain"
: "${TOOLCHAIN}gcc: cross compiler not found (apt install gcc-aarch64-linux-gnu)" \
	command -v "${TOOLCHAIN}gcc" >/dev/null 2>&1
"${TOOLCHAIN}gcc" --version | head -1

if [ -z "$KDIR" ]; then
	KDIR="$CACHE/arm64-kbuild-6.6"
	if [ ! -f "$KDIR/include/generated/autoconf.h" ]; then
		echo "== fetching linux-6.6 (arm64 Kbuild tree) into $KDIR"
		mkdir -p "$CACHE"
		ARCHIVE="$CACHE/linux-6.6.tar.xz"
		[ -f "$ARCHIVE" ] || \
			wget -q https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz -O "$ARCHIVE"
		mkdir -p "$KDIR"
		tar -xJf "$ARCHIVE" -C "$KDIR" --strip-components=1
	fi
	echo "== preparing arm64 Kbuild tree"
	make -s ARCH=arm64 CROSS_COMPILE="$TOOLCHAIN" -C "$KDIR" defconfig
	make -s ARCH=arm64 CROSS_COMPILE="$TOOLCHAIN" -C "$KDIR" modules_prepare
else
	echo "== using KDIR=$KDIR"
fi

grep -q '^CONFIG_ARM64=y' "$KDIR/.config" || { echo "FAIL: KDIR is not an arm64 build"; exit 1; }

echo "== building module in scratch dir"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp -r kernel "$WORK/module"
# Compile-only gate: keep linking (KBUILD_MODPOST_WARN), but unresolved
# symbols are expected and reported without failing the lane.
make -C "$WORK/module" KDIR="$(readlink -f "$KDIR")" \
	ARCH=arm64 CROSS_COMPILE="$TOOLCHAIN" KBUILD_MODPOST_WARN=1 -j"$(nproc)" \
	> "$WORK/build.log" 2>&1 || {
		grep -iE "error:" "$WORK/build.log" | head -20
		echo "FAIL: aarch64 build failed"
		exit 1
	}

file "$WORK/module/sentinel_km.ko" | grep -q "ARM aarch64" \
	|| { echo "FAIL: module is not aarch64 ELF"; exit 1; }

echo "== PASS: aarch64 module built ($(du -h "$WORK/module/sentinel_km.ko" | cut -f1))"
echo "   $WORK/module/sentinel_km.ko"
