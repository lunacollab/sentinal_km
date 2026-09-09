# Contributing

Small project, high bar. Kernel code is unforgiving, so the bar is formal
and enforced by CI.

## Ground rules

- Anything touching the kernel must pass `checkpatch.pl` with **0 errors**
  (warnings: only the two known `kzalloc_obj` compat suggestions are
  tolerated, and they are tolerated only because the module still builds
  against kernels older than that API):

  ```sh
  make -C kernel checkpatch KDIR=/usr/src/linux-headers-$(uname -r)
  ```

- The userspace daemon must build clean under `-Wall -Wextra`, and its unit
  tests must pass:

  ```sh
  make -C daemon
  make -C daemon test
  ```

- Wire protocol changes bump `SENTINEL_PROTO_VERSION` and update
  `docs/WIRE_PROTOCOL.md`. Never mutate a struct in place without a version
  bump and a protocol doc update.

- New events ripple wider than the parser: every event type needs a
  daemon-side parse case, a text/JSON printer in `main.c`, parser unit
  tests, and — when it feeds a heuristic — a `correlate_observe()` branch
  plus correlator tests. A new hook this shallow is still a protocol
  change; treat it as one.

- A new syscall probe must be exercised at runtime, not just compiled and
  unit-tested: extend `tests/qemu/trace_triggers.c` and the
  `smoke_test.sh` grep list (the deterministic fileless case is the
  canonical example), or add it to the stress hammers if its capture can
  race unload.

- The unload ordering in `sentinel_main.c` (unregister probes ->
  `synchronize_rcu()` -> flush ring -> free -> unregister genl family) is a
  correctness invariant. Don't reorder it "to be tidier".

- New hooks: follow [docs/HOOKS.md](docs/HOOKS.md) ("Adding a new hook").
  Every new syscall probe gets a kernel-side capture size assert, a
  daemon-side parser case, a printer, unit tests, and a runtime trigger.

## Development workflow

1. Fork, branch from `main`, keep commits small and focused.
2. Kernel modules are best iterated in QEMU/virtme (`tests/qemu/boot.sh`),
   where a crash costs seconds, not a host reboot.
3. Open a PR. The `.github/workflows/` gates run on PRs and pushes to
   `main`:
   - `build.yml` — kernel build matrix across the header versions plus the
     arm64 cross lane, daemon build + unit tests.
   - `checkpatch.yml` — `checkpatch.pl` 0 errors / 0 warnings / 0
     new checks (see above).
   - `pipeline.yml` — actionlint on the workflows + pre-commit battery.
   - `quality.yml` — line-coverage gate (≥55%), markdown-link check, README
     freshness guard (the last two are informational; a nightly schedule
     re-runs them so drift still shows up).
   - `sanitize.yml` — the daemon unit battery under ASan+UBSan plus a
     libFuzzer harness compile.
   - `security-scan.yml` — gitleaks secret scan, semgrep, sparse + `W=1`
     kernel build (informational), cppcheck + shellcheck + codespell +
     whitespace sanity.
   - `runtime.yml` — virtme-ng kernel boots + `smoke_test.sh`; fatal on the
     6.8 lane, informational on 5.15.
   - `release.yml` — on `v*` tags, builds module + daemon and stages them
     with `SHA256SUMS` into a GitHub release.

## Style

The full contract lives in `sentinel-km-deep-plan.md` §10 (Engineering
standard); the binding rules that decide reviews:

- Kernel: kernel coding style, SPDX `GPL-2.0-only` headers, descriptive
  block comments over inline commentary. No emojis, no embellishment.
- Daemon: plain C99, `_GNU_SOURCE`, same concision, SPDX `Apache-2.0`.
- SPDX header **only**: no license block, no authorship banner, no comments
  that restate the code. A comment earns its place when it names an
  invariant, explains something non-obvious, or pins a kernel-version quirk.
- Names are dense and specific (`path_off`, `drain_work`, `ring_requeue`) —
  not `helper`, `utils`, `processData`. CamelCase has no home here.
- The atomic probe path is the benchmark: no allocation, no lock, no sleep,
  no page fault. Any budget smell in a probe handler is a review blocker.
- Defense lives in consumers: the daemon treats the wire as semi-trusted,
  bounds-checks every field before dereference, and drops — never repairs —
  malformed input.
- Every asm primitive ships with a C reference and an init-time differential
  selftest. Asm never outruns correctness.
- Docs track code: a wire or hook change updates `docs/` and this plan in
  the same commit. `WIRE_PROTOCOL.md`, `ARCHITECTURE.md`, `HOOKS.md` are
  review artifacts.
- Commit messages: imperative mood, subject under 72 chars, body explains
  *why*.

## Reporting bugs

Include: `uname -r`, kernel config or distro, `dmesg` tail on crash/load
failure, and the module+`sysfs` stats. For a panic, the whole `dmesg`
buffer is worth more than your recollection of it.

## Licensing

The tree is dual-licensed by component: the kernel module (`kernel/`) is
GPL-2.0-only (mandatory: kprobes are `EXPORT_SYMBOL_GPL`); the daemon,
tests, and docs are Apache-2.0; the shared wire header
(`kernel/ipc/sentinel_proto.h`) is `GPL-2.0-only OR Apache-2.0`. BY
CONTRIBUTING you agree to license your contribution under the terms of the
**component you touch** — GPL-2.0 for kernel files, Apache-2.0 for
daemon/tests/docs. Every new or edited file carries a matching SPDX header;
do not mix the two licenses inside one file. See `LICENSE` and
`LICENSE-APACHE`.
