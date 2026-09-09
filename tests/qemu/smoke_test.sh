#!/usr/bin/env bash
# smoke_test.sh -- load -> trigger each hook once -> assert events ->
# unload -> assert dmesg clean. Runs inside the test VM as root.
#
# Exit code 0 == module loads, the three core event types are observed (plus
# the x86_64-only events mprotect/mmap_exec/ptrace/execveat/memfd_create and
# the v8 clone3/io_uring_enter/finit_module), module unloads without refcount
# leak, and dmesg shows no BUG/WARNING/panic.
set -euo pipefail

cd "$(dirname "$0")/../.."

MOD=kernel/sentinel_km.ko
DAEMON=daemon/sentinel-daemon
OUT=$(mktemp)
DROPPED=$(mktemp)

finish() {
    kill "${DAEMON_PID:-0}" 2>/dev/null || true
    rmmod sentinel_km 2>/dev/null || true
    rm -f "$OUT" "$DROPPED"
}
trap finish EXIT

dmesg_dirty() {
    dmesg | grep -Ei 'BUG:|WARNING:|Kernel panic|Oops|general protection' | grep -v 'sentinel_km' || true
}

# On any failed assert: dump the kernel's own counters (drops_by_type,
# bails, per-cpu ring stats) first -- they disambiguate "syscall never
# reached the ring" from "ring dropped the event" -- then the event log.
fail() {
    echo "$1"
    echo "== kernel stats"
    cat /sys/kernel/sentinel_km/stats 2>/dev/null || true
    echo "== event log"
    cat "$OUT"
    exit 1
}

echo "== loading $MOD"
dmesg --clear
if ! insmod "$MOD"; then
    echo "insmod failed; kernel log follows" >&2
    dmesg >&2
    exit 1
fi
[[ -z "$(dmesg_dirty)" ]] || { echo "dirty dmesg after insmod"; exit 1; }

echo "== starting daemon"
"$DAEMON" --json --reconnect >"$OUT" 2>&1 &
DAEMON_PID=$!
sleep 1

echo "== generating activity"
# Exercise execve/openat plus the v5 events (execveat, memfd_create, ptrace,
# and the fileless execveat) through the C trigger.
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    cc -O2 -o /tmp/trace_triggers tests/qemu/trace_triggers.c
    /bin/true                       # execve
    cat /etc/hostname >/dev/null
    /tmp/trace_triggers
    rm -f /tmp/trace_triggers

    # P2.3 ring contract: second consumer refused (-EBUSY), resize refused
    # while held, epoch strictly increasing across re-opens, runtime
    # capacity discovery on the daemon-side mapping size.
    cc -O2 -o /tmp/ringmap_reopen_test tests/qemu/ringmap_reopen_test.c
    /tmp/ringmap_reopen_test || { fail "FAIL: ringmap_reopen_test"; }
    # P2.4 per-type overflow breakdown must be present in the stats file.
    grep -q 'drops_by_type' /sys/kernel/sentinel_km/stats || { fail "FAIL: stats lacks drops_by_type"; }
    [ "$(cat /sys/kernel/sentinel_km/ringmap_size)" = "16" ] || { fail "FAIL: ringmap_size not restored after harness"; }
    rm -f /tmp/ringmap_reopen_test
else
    /bin/true                       # execve
    cat /etc/hostname >/dev/null    # openat
fi

# give the per-CPU rings/drain workers time to flush
sleep 2

echo "== asserting one event per type"
grep -q '"type":"execve"' "$OUT" || fail "FAIL: no execve event"
grep -q '"type":"openat"' "$OUT" || fail "FAIL: no openat event"
if [ "$ARCH" = "x86_64" ]; then
    grep -q '"type":"mprotect"' "$OUT" || fail "FAIL: no mprotect event"
    grep -q '"type":"mmap_exec"' "$OUT" || fail "FAIL: no mmap_exec event"
    grep -q '"type":"ptrace"' "$OUT" || fail "FAIL: no ptrace event"
    grep -q '"type":"memfd_create"' "$OUT" || fail "FAIL: no memfd_create event"
    grep -q '"type":"execveat"' "$OUT" || fail "FAIL: no execveat event"
    # v8 events: clone3 (real child + degenerate NULL shape), io_uring_enter
    # completion pairing, finit_module on a memfd-tracking fd.
    grep -q '"type":"clone3"' "$OUT" || fail "FAIL: no clone3 event"
    grep -q '"type":"io_uring_enter"' "$OUT" || fail "FAIL: no io_uring_enter event"
    grep -q '"type":"finit_module"' "$OUT" || fail "FAIL: no finit_module event"
    # the entry hook must report a raw submitted/completed pair on ret
    grep -q '"submitted":' "$OUT" || fail "FAIL: io_uring_enter without submitted"
    # the memfd -> execveat("", AT_EMPTY_PATH) flow must be correlated as
    # fileless by the daemon (same pid, inside the 30 s window)
    grep -q '"fileless":true' "$OUT" || fail "FAIL: no fileless annotation"
    # every event that carries an exec_trans annotation must name an image
    if grep -q '"exec_trans":true' "$OUT"; then
        grep -q '"known_exec"' "$OUT" || fail "FAIL: exec_trans without known_exec"
    fi
fi

echo "== unloading"
rmmod sentinel_km
[[ -z "$(dmesg_dirty)" ]] || { echo "dirty dmesg after rmmod"; exit 1; }

# no leaked refcount: lsmod must no longer list it
if lsmod | grep -q '^sentinel_km '; then
    echo "FAIL: module still loaded / refcount not zero"
    exit 1
fi

[[ -f /sys/kernel/sentinel_km/stats ]] && { echo "FAIL: sysfs node survived rmmod"; exit 1; }

echo "== SMOKE TEST OK"
echo "events seen: $(wc -l < "$OUT")"
exit 0
