#!/usr/bin/env bash
# mprotect_hammer.sh -- thrash PROT_EXEC transitions against the mprotect
# hook while rmmod races it. Complements tests/stress/rmmod_under_load.sh
# with a report that exercises the newest hook's capture path under churn.
#
# Run inside the test VM, as root.
set -euo pipefail

cd "$(dirname "$0")/../.."

MOD=kernel/sentinel_km.ko
ITERS=${ITERS:-25}
TRIG=/tmp/mprotect_trigger

echo "== building mprotect trigger"
cc -O2 -o "$TRIG" tests/qemu/mprotect_trigger.c

dump_dmesg_after() {
    echo "=== dmesg tail ==="
    dmesg | tail -40
}

echo "== mprotect churn for $ITERS load/unload cycles"
for i in $(seq 1 "$ITERS"); do
    # a burst of PROT_RX flips in a subshell...
    (
      for j in $(seq 1 200); do
        "$TRIG"
      done
    ) &
    TRIG_PID=$!

    # ...while the module loads, drains, and is yanked mid-storm
    insmod "$MOD"
    sleep 0.01
    rmmod sentinel_km

    wait "$TRIG_PID" 2>/dev/null || true

    if dmesg | grep -Ei 'BUG:|WARNING:|Kernel panic|Oops|general protection' | grep -vq sentinel_km; then
        echo "FAIL: crash signature on iteration $i"
        dump_dmesg_after
        exit 1
    fi
done

echo "== survived $ITERS mprotect load/unload cycles"
rm -f "$TRIG"
halt 2>/dev/null || sync
exit 0
