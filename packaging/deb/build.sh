#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# build.sh -- build a binary sentinel-km .deb (daemon + kernel module +
# sample config + systemd unit + DKMS source). Run from the repo root.
#
# Requires: gcc, make, linux-headers for the target kernel, dpkg-deb.
# Usage:    packaging/deb/build.sh [KDIR]   (KDIR defaults to the running
#           kernel's build tree, like kernel/Makefile's KDIR)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
KDIR=${1:-/lib/modules/$(uname -r)/build}

# Single source of truth for the version string lives in dkms.conf.
VERSION=$(sed -n 's/^PACKAGE_VERSION="\([^"]*\)"/\1/p' \
	"$ROOT/packaging/dkms/dkms.conf")
[ -n "$VERSION" ] || { echo "cannot read PACKAGE_VERSION" >&2; exit 1; }

ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64)
KV=$(basename "$KDIR")

# Stage on ext4: /mnt/d is DrvFs, where chmod is a no-op and dpkg-deb
# validates real modes.
TMPSTAGE=$(mktemp -d -t sentinel-km-deb.XXXXXX)
trap 'rm -rf "$TMPSTAGE"' EXIT
STAGE="$TMPSTAGE/sentinel-km_${VERSION}_${ARCH}"
MISC="$STAGE/lib/modules/$KV/kernel/misc"

echo "== building daemon (arch $ARCH)"
make -C "$ROOT/daemon" clean >/dev/null
make -C "$ROOT/daemon"

echo "== building module against $KDIR"
make -C "$ROOT/kernel" KDIR="$KDIR" clean >/dev/null
make -C "$ROOT/kernel" KDIR="$KDIR"
ls "$ROOT/kernel/sentinel_km.ko" >/dev/null

echo "== staging"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/sbin" "$STAGE/usr/share/doc/sentinel-km" \
	"$STAGE/usr/src/sentinel-km-${VERSION}" "$STAGE/etc/sentinel" \
	"$STAGE/etc/modprobe.d" "$STAGE/lib/systemd/system" "$MISC"
chmod 0755 "$STAGE/DEBIAN"

install -m0755 "$ROOT/daemon/sentinel-daemon" "$STAGE/usr/sbin/sentinel-daemon"
install -m0644 "$ROOT/packaging/sentinel.conf" "$STAGE/etc/sentinel/sentinel.conf"
install -m0644 "$ROOT/packaging/modprobe.conf" "$STAGE/etc/modprobe.d/sentinel.conf"
install -m0644 "$ROOT/packaging/systemd/sentinel-daemon.service" \
	"$STAGE/lib/systemd/system/sentinel-daemon.service"
install -m0644 "$ROOT/kernel/sentinel_km.ko" "$MISC/sentinel_km.ko"
install -m0644 "$ROOT/packaging/dkms/dkms.conf" \
	"$STAGE/usr/src/sentinel-km-${VERSION}/dkms.conf"
cp -r "$ROOT/kernel/Kbuild" "$ROOT/kernel/Makefile" "$ROOT/kernel/core" \
	"$ROOT/kernel/hooks" "$ROOT/kernel/ipc" "$ROOT/kernel/arch" \
	"$STAGE/usr/src/sentinel-km-${VERSION}/"
# Strip the module build artifacts from the DKMS source copy: DKMS compiles
# its own tree, so only pristine sources may ship.
find "$STAGE/usr/src/sentinel-km-${VERSION}" -type f \
	\( -name '*.o' -o -name '*.cmd' -o -name '*.ko' -o -name '*.ko.*' \
	-o -name '*.mod' -o -name '*.mod.*' -o -name 'modules.order' \
	-o -name 'Module.symvers' -o -name '*.stamp' \) -delete
install -m0644 "$ROOT/LICENSE" "$ROOT/LICENSE-APACHE" \
	"$STAGE/usr/share/doc/sentinel-km/"
install -m0644 "$ROOT/README.md" "$STAGE/usr/share/doc/sentinel-km/README.md"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: sentinel-km
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Maintainer: sentinel-km maintainers <maintainers@example.invalid>
Depends: kmod
Description: kernel syscall activity monitor (kprobe ring + daemon)
 kprobe/kretprobe hook set with a zero-copy mmap ring and a small
 validating daemon. Kernel module (DKMS-ready) + userspace consumer.
EOF

cat > "$STAGE/DEBIAN/postinst" <<EOF
#!/bin/sh
set -e
if command -v depmod >/dev/null 2>&1; then
	depmod -a $KV >/dev/null 2>&1 || true
fi
if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
EOF

cat > "$STAGE/DEBIAN/prerm" <<EOF
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
	systemctl stop sentinel-daemon.service >/dev/null 2>&1 || true
	systemctl disable sentinel-daemon.service >/dev/null 2>&1 || true
fi
EOF

cat > "$STAGE/DEBIAN/postrm" <<EOF
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
EOF

chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"
chmod -R u=rwX,go=rX "$STAGE"
chmod 0755 "$STAGE/DEBIAN" "$MISC" 2>/dev/null || true

echo "== building .deb"
OUT="$ROOT/build/pkg"
mkdir -p "$OUT"
dpkg-deb --root-owner-group --build "$STAGE" \
	"$OUT/sentinel-km_${VERSION}_${ARCH}.deb"
ls -l "$OUT/sentinel-km_${VERSION}_${ARCH}.deb"
