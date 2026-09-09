#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# build.sh -- build the sentinel-km RPM via rpmbuild. Run from the repo root.
#
# Requires: rpmbuild (rpm package), kernel-devel matching `uname -r`.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=$(sed -n 's/^PACKAGE_VERSION="\([^"]*\)"/\1/p' \
	"$ROOT/packaging/dkms/dkms.conf")
[ -n "$VERSION" ] || { echo "cannot read PACKAGE_VERSION" >&2; exit 1; }

command -v rpmbuild >/dev/null 2>&1 || {
	echo "rpmbuild not found (install the rpm package)" >&2
	exit 1
}
command -v gcc >/dev/null 2>&1 || { echo "gcc required" >&2; exit 1; }
command -v make >/dev/null 2>&1 || { echo "make required" >&2; exit 1; }

# Kernel headers tree to build against. Prefer the running kernel's copy;
# on Debian-ish guests (or with a KDIR override) fall back to apt headers.
DEFAULTPATH="/lib/modules/$(uname -r)/build"
if [ ! -d "$DEFAULTPATH" ]; then
	DEFAULTPATH=$(find /usr/src -maxdepth 1 -type d \
		-name 'linux-headers-*-generic' 2>/dev/null | head -1)
fi
KPATH=${KDIR:-$DEFAULTPATH}
[ -n "$KPATH" ] && [ -d "$KPATH" ] || {
	echo "kernel devel tree missing (set KDIR or install headers)" >&2
	exit 1
}
KPATH=$(readlink -f "$KPATH")
KV=$(basename "$KPATH" | sed 's/^linux-headers-//')

TOPDIR="$HOME/.cache/sentinel-km/rpm-topdir"
rm -rf "$TOPDIR"
mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,rpmdb}
rpm --initdb --dbpath "$TOPDIR/rpmdb" >/dev/null 2>&1 || true
# The tarball needs a single top-level directory for %setup -n to land in.
tar czf "$TOPDIR/SOURCES/sentinel-km-$VERSION.tar.gz" \
	--exclude '*/build' --exclude '.git' --exclude '*.o' --exclude '*.ko' \
	--transform "s,^,sentinel-km-$VERSION/," \
	-C "$ROOT" daemon kernel packaging LICENSE LICENSE-APACHE README.md

rpmbuild --define "_topdir $TOPDIR" \
	--define "_dbpath $TOPDIR/rpmdb" \
	--define "_sentinel_version $VERSION" \
	--define "_kpath $KPATH" --define "_kver $KV" \
	--nodeps \
	-bb "$ROOT/packaging/rpm/sentinel-km.spec"

mkdir -p "$ROOT/build/pkg/rpm"
cp "$TOPDIR"/RPMS/*/*.rpm "$ROOT/build/pkg/rpm/"
ls -l "$ROOT/build/pkg/rpm/"
