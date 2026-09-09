#!/usr/bin/env bash
# .ci-run.sh -- entry point executed inside the test VM by boot.sh.
set -euo pipefail
cd "$(dirname "$0")"

echo "== building module against the VM kernel"
make -C kernel
echo "== smoke test"
tests/qemu/smoke_test.sh
echo "== stress test (module unload under load)"
tests/stress/rmmod_under_load.sh ITERS="${ITERS:-25}"
echo "== stress test (mprotect churn + unload race)"
tests/stress/mprotect_hammer.sh ITERS="${ITERS:-25}"
echo "== stress test (ptrace churn + unload race)"
tests/stress/ptrace_hammer.sh ITERS="${ITERS:-25}"
echo "== ALL VM TESTS PASSED"
