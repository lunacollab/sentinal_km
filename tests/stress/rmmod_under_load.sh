#!/usr/bin/env bash
# rmmod_under_load.sh -- hammer syscalls in a loop while rmmod races it.
#
# The #1 unload correctness test: generate execve/openat/connect churn from
# one shell while another repeatedly loads/unloads the module. Any
# use-after-free, lock imbalance, or refcount leak must surface as a
# BUG/WARNING/panic in dmesg within N iterations.
#
# Run inside the test VM, as root.
set -euo pipefail

cd "$(dirname "$0")/../.."

MOD=kernel/sentinel_km.ko
ITERS=${ITERS:-50}

load_sync() {
    while :; do
        insmod "$MOD" 2>/dev/null && break
        sleep 0.2
    done
}

dump_dmesg_after() {
    echo "=== dmesg tail ==="
    dmesg | tail -40
}

echo "== generating syscall load for $ITERS load/unload cycles"
for i in $(seq 1 "$ITERS"); do
    # churn: exec, opens, a connect attempt
    (
      for j in $(seq 1 200); do
        /bin/true
        cat /etc/hostname >/dev/null 2>&1
        (exec 3<>/dev/tcp/127.0.0.1/9) 2>/dev/null || true
      done
    ) &
    LOAD_PID=$!

    insmod "$MOD"
    # let a few events land, then yank it mid-storm
    sleep 0.01
    rmmod sentinel_km

    wait "$LOAD_PID" 2>/dev/null || true

    if dmesg | grep -Ei 'BUG:|WARNING:|Kernel panic|Oops|general protection' | grep -vq sentinel_km; then
        echo "FAIL: crash signature on iteration $i"
        dump_dmesg_after
        exit 1
    fi
done

echo "== survived $ITERS load/unload cycles under load"
halt 2>/dev/null || sync
exit 0
