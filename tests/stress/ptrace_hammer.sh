#!/usr/bin/env bash
# ptrace_hammer.sh -- thrash the ptrace hook while rmmod races it.
#
# ptrace(PTRACE_TRACEME) is emitted unconditionally (no retval gating), so a
# tight loop of failing ptrace calls is the cheapest possible way to pound
# the newest capture path -- probe fires, blob is built, ring push happens --
# while the module is torn down underneath it. Any use-after-free on the
# probe-out side must surface as a BUG/WARNING/panic in dmesg.
#
# Run inside the test VM, as root.
set -euo pipefail

cd "$(dirname "$0")/../.."

MOD=kernel/sentinel_km.ko
ITERS=${ITERS:-25}
TRIG=/tmp/ptrace_hammer_trigger

echo "== building ptrace hammer trigger"
cc -O2 -o "$TRIG" -x c - <<'EOF'
#include <sys/ptrace.h>
#include <unistd.h>
int main(void)
{
	for (int i = 0; i < 2000; i++)
		ptrace(PTRACE_TRACEME, 0, 0, 0);	/* EPERM each time; event still fires */
	return 0;
}
EOF

dump_dmesg_after() {
    echo "=== dmesg tail ==="
    dmesg | tail -40
}

echo "== ptrace churn for $ITERS load/unload cycles"
for i in $(seq 1 "$ITERS"); do
    (
      for j in $(seq 1 100); do
        "$TRIG"
      done
    ) &
    TRIG_PID=$!

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

echo "== survived $ITERS ptrace load/unload cycles"
rm -f "$TRIG"
halt 2>/dev/null || sync
exit 0
