#!/usr/bin/env bash
# boot.sh -- boot a throwaway VM for module testing.
#
# Prefers virtme-ng (https://github.com/arighi/virtme-ng), which boots the
# current kernel in ~seconds. Falls back to printing a manual QEMU recipe.
#
# Usage:
#   tests/qemu/boot.sh [-- <extra virtme-ng args>]
set -euo pipefail

cd "$(dirname "$0")/../.."

if command -v vng >/dev/null 2>&1; then
    exec vng --rw -- ./.ci-run.sh "$@"
fi

if command -v virtme-run >/dev/null 2>&1; then
    exec virtme-run --rw --dir . --script-sh "bash .ci-run.sh $*"
fi

cat >&2 <<'EOF'
virtme-ng not found. Install it, or run manually:

  qemu-system-x86_64 \
    -kernel <your bzImage (CONFIG_KPROBES=y)> \
    -initrd <your initramfs with sentinel_km.ko + sentinel-daemon> \
    -append "console=ttyS0" -nographic

Then run tests/qemu/smoke_test.sh inside the guest.
EOF
exit 1
