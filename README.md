# sentinel-km

A Linux kernel module that observes `execve`, `openat`, `connect`,
`execveat`, `memfd_create`, `ptrace`, and (on x86_64) `mmap`/`mprotect`
syscalls with kprobes and streams the activity to userspace over Generic
Netlink multicast (batched) or a zero-copy mmap ring. Ships with a small C
daemon that validates, filters, correlates, and prints the events as text or
JSON-lines.

**Status: hot path and runtime exercised.** Kernel and daemon build against
Ubuntu LTS / current headers; checkpatch is 0 errors; the daemon parser,
correlator, `memchr_zero`, and `capture_store` are unit-tested; static
analysis (semgrep/sparse/cppcheck/shellcheck/gitleaks) runs in CI. Runtime
CI boots a real VM with virtme-ng on every push (fatal on Ubuntu 24.04's
6.8 LTS, informational on 22.04's 5.15 LTS): load, trigger every hook,
assert every event type lands (including the `fileless` execveat
correlation), then race the module's unload against syscall storms — see
[Testing](#testing).

---

## Table of Contents

- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Build and Install](#build-and-install)
- [Platforms](#platforms)
- [Usage](#usage)
- [Compatibility](#compatibility)
- [Architecture and docs](#architecture-and-docs)
- [Development](#development)
- [Testing](#testing)
- [License](#license)

## Features

- kprobe/kretprobe capture with per-CPU lock-free event rings — producers
  never block, events are dropped (and counted) under overload.
- Deferred, bounded processing in process context; nothing sleeps in the
  probe path.
- RCU-protected hook registry and deterministic, order-checked module
  unload.
- Versioned wire protocol (v6) validated defensively by the consumers.
- **Batched netlink delivery**: the drain worker packs up to
  `SENTINEL_GENL_BATCH_MAX` events per multicast datagram (`sent` counter
  reports datagram volume), so a bursty producer no longer costs a skb per
  event.
- **`execveat`/`memfd_create`/`ptrace` observation on x86_64**: fd-relative
  exec (with a dedicated `fileless` handler when it execs an anonymous
  fd), anonymous executable-memory minting, and the full
  `ptrace(request, pid, addr, data)` register set.
- **Daemon-side correlation agent** (`correlate.c`): tracks each pid's
  known image from the exec stream and annotates `mmap`/`mprotect`
  `PROT_WRITE|PROT_EXEC` flips inside it as `exec_trans` (known-image W^X
  violation) and `memfd_create`+`execveat("", AT_EMPTY_PATH)` pairs as
  `fileless` (diskless execution) — disabled with `-C/--no-correlate`.
- **Full `argv` capture for `execve`** — up to 16 arguments, each truncated
  at 128 bytes, bounded-fault-safe copies into a kmem_cache pool.
- **In-kernel filtering** on event type + pid bitmap, controllable at load
  time (module params) and at runtime (sysfs): the kernel drops most noise
  before it ever reaches userspace. The master `enable` gate is a **static
  key** — an idle module costs a single patched NOP per syscall.
- **`mmap` observation on x86_64** (all `mmap` calls, with `PROT_EXEC`
  events that also report requested length, prot, flags, fd, and file offset).
- **`mprotect` observation on x86_64** (`mprotect(addr, len, prot)` events
  that fire on success *and* failure whenever `PROT_EXEC` is among the
  requested protections — JITs making memory executable, and the classic
  W^X violation of adding `PROT_WRITE` to an executable region).
- **Two transports**: multicast Generic Netlink (any number of subscribers)
  and a single-consumer **zero-copy mmap ring** (`/dev/sentinel_ring`) that
  the daemon reads directly with `--mmap`.
- **x86_64 asm hot path**: the capture is moved into the ring by a
  hand-written SSE2 + fast-string primitive (`sentinel_capture_store`) that
  copies the populated header/payload prefix and zero-fills the rest in one
  pass, plus an alignment-unrolled `memchr_zero` NUL scan. Both keep a C
  reference that a differential selftest proves byte-identical, so "full asm"
  never sacrifices correctness (`kernel/ipc/sentinel_capture.c`,
  `kernel/arch/x86_64/`).
- GPL kernel core (required for the kprobe API) with an Apache-2.0 daemon;
  see [License](#license).

## How it works

```
syscall entry/exit  -> kretprobe handler (atomic)
                 -> kernel-side filter gate (type bitmap + pid set)
                 -> per-CPU ring (lock-free push)
                 -> bound drain worker (process context)
                 -> genl multicast "sentinel_km"/"events"  AND/OR
                 -> mmap ring (/dev/sentinel_ring)
                 -> sentinel-daemon (validate -> filter -> print/JSON)
```

Events carry pid, realtime timestamp, cpu, and a bounded per-syscall
payload: execve/execveat report the full argv vector (paths truncated at 128
bytes per argument / 16 arguments) plus `dirfd`/`flags` for the latter,
openat a path, connect a sockaddr, memfd_create its name and flags, ptrace
the request/target/addr/data registers, and mmap the requested
prot/flags/length/fd. The daemon folds the exec stream into a bounded
per-pid image table and annotates W^X flips and anonymous execs. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/WIRE_PROTOCOL.md](docs/WIRE_PROTOCOL.md).

## Requirements

| Component | Requirement |
|---|---|
| Kernel module | A Linux kernel with kprobes enabled + matching headers (`/lib/modules/$(uname -r)/build`), or any headers tree passed to `make KDIR=...` |
| Daemon | Linux userspace with a C99 compiler and kernel UAPI headers; no external libraries |
| Runtime | `CAP_SYS_MODULE` to load the module |

Supports x86_64 (primary, runtime-tested) and aarch64 (compile-only lane).
Probes are keyed to the per-arch wrapper symbols (`__x64_sys_*` /
`__arm64_sys_*`) selected by `SENTINEL_SC_WRAPPER()`; syscall arguments are
read via `hook_reg_arg()` (`di`/`si`/`dx`/`r10`/`r8`/`r9` on x86_64,
`pt_regs->regs[0..5]` on aarch64) and the `Sentinel_SC_*` gate numbers are
re-keyed per arch in `hook_common.h`. The x86_64 asm hot-path objects stay
x86-only; aarch64 uses the C fallbacks. See
[docs/KERNEL_COMPAT.md](docs/KERNEL_COMPAT.md).

## Build and Install

### On Linux (native, or headless CI)

```sh
# daemon
make -C daemon
make -C daemon test        # parser unit tests

# kernel module, against the running kernel
make -C kernel
# ...or against an explicit header set:
make -C kernel KDIR=/usr/src/linux-headers-$(uname -r)
```

Install:

```sh
sudo make -C kernel modules_install
sudo make -C daemon install
```

### On Windows — WSL2 (Ubuntu)

WSL2 gives you a real Ubuntu userland but a **signed Microsoft kernel**. Two
things follow:

1. **Building** works exactly as on native Linux. From inside Ubuntu:

   ```sh
   cd /mnt/d/path/to/sentinel-km
   sudo apt-get update
   sudo apt-get install -y build-essential linux-headers-generic
   make -C daemon && make -C daemon test
  make -C kernel KDIR=/usr/src/linux-headers-<matching-kernel>
   ```

   Headers for the *WSL2* kernel itself (`6.6.x-microsoft-standard`) are not
   packaged, so build/test the module against a `linux-headers-*` package,
   which is a valid compile check (this is what CI does). The daemon builds
   and its tests run natively in WSL.

2. **Loading** the module inside stock WSL2 is **not supported**: the
   Microsoft kernel is signed and does not accept out-of-tree modules.
   To actually `insmod`, either:

   - use a real Linux machine / VM, or
   - build a **custom WSL2 kernel** (Microsoft's documented procedure:
     compile the kernel from microsoft/WSL with module support and point
     `.wslconfig` at the resulting `bzImage`), then load the module in WSL.

   For CI-style validation without hardware, use QEMU/virtme as described
   under [Testing](#testing).

### Loading and unloading

```sh
sudo insmod kernel/sentinel_km.ko
sudo rmmod sentinel_km
dmesg | tail          # expect clean "loaded"/"unloaded" lines, no BUG/WARNING
```

The module registers a sysfs node at `/sys/kernel/sentinel_km`:

| File | Meaning |
|---|---|
| `stats` | `pushed` / `dropped` / `requeued` / `drain_ns` / `sent` totals (ring enqueues, overflow drops, deferred-flush re-queues, accumulated drain time in ns, netlink datagrams multicast); `drops_by_type` breaks overflow drops down per numeric event type |
| `version` | module + wire protocol version |
| `enable` | master gate (static key); `1`/`0` enables/disables all probes at runtime |
| `filter` | hex syscall mask; bit N = syscall N (see `sentinel_proto.h`); `all`/`none`/`set N`/`clr N` to change bits live |
| `filter_pids` | whitespace-separated pid list; empty = all pids |
| `filter_uids` | whitespace-separated uid list; empty = all uids |
| `ring_size` | per-CPU ring capacity in slots (power of two); resize is refused while a drain holds the arena |
| `ringmap_size` | mmap-ring data capacity in KiB (power of two); a resize is refused while a consumer holds the mapping; the next open applies it and records a fresh `epoch` (re-open handshake) |

The same knobs are available at load time via the `trace_enable`,
`trace_mask`, `trace_pids`, and `trace_uids` module parameters, and are
mirrored at runtime under `/proc/sys/kernel/sentinel/` (`enable`, `filter`,
`filter_pids`, `filter_uids`) with identical write syntax to the sysfs
files above. The pid and uid lists are AND-ed: an event passes only when
every non-empty list contains its value.

## Platforms

| Platform | Build | Load/Run | Notes |
|---|---|---|---|
| Linux (native x86_64) | Yes | Yes | Primary target. Requires kernel headers + `CAP_SYS_MODULE`. |
| Linux (aarch64) | Yes (compile-only) | Planned | `scripts/build-arm64.sh` compiles the module for aarch64 (`__arm64_sys_*` wrappers, `regs[i]` args); runtime still requires an arm64 QEMU/kernel lane. |
| Windows / WSL2 | Daemon yes; module with explicit KDIR | No | Daemon builds and tests under WSL2 Ubuntu. The stock Microsoft kernel has no packaged matching headers and cannot load out-of-tree modules; use `KDIR=/usr/src/linux-headers-<matching-kernel>` for a module compile check. See [Build and Install](#build-and-install). |
| Docker / Podman | Yes | With `--privileged` | Container must run with `--privileged` or `--cap-add=SYS_MODULE` to `insmod`. Build works in any privileged or unprivileged container with headers installed. |

## Usage

```sh
# start the daemon in one shell (netlink transport)
sudo ./daemon/sentinel-daemon --json

# ...or the zero-copy mmap ring instead
sudo ./daemon/sentinel-daemon --mmap --json

# in another shell, generate activity
ls /tmp; bash -c 'exec /bin/echo "$0" "$1"' _ hello world; <fetch some url>

# daemon prints lines like:
# {"type":"execve","pid":1234,...,"path":"/bin/bash","argv":["/bin/bash","-c",...]}
# {"type":"execve","pid":1235,...,"path":"/usr/bin/echo","argv":["/usr/bin/echo","hello","world"]}
# {"type":"openat","pid":1235,...,"filename":"/tmp/...","dfd":-100,"flags":...}
# {"type":"connect","pid":5678,...,"family":2,"port":443,"addr":".."}
# {"type":"mmap","pid":1235,...,"addr":..,"length":..,"prot":..,"flags":..,"fd":-1,"offset":0}
# {"type":"mprotect","pid":1235,...,"addr":..,"len":..,"prot":..,
#  "exec_trans":true,"known_exec":"/usr/bin/…"}        when W|X inside a known image
# {"type":"memfd_create","pid":1235,...,"name":"c","flags":..}
# {"type":"execveat","pid":1235,...,"dirfd":3,"flags":0x1000,"path":"",
#  "fileless":true}                                     memfd + AT_EMPTY_PATH exec
# {"type":"ptrace","pid":900,...,"request":16,"target":999,"addr":0,"data":0}
```

### Daemon options

| Flag | Meaning |
|---|---|
| `-p, --pid PID` | emit only events for this pid (repeatable) |
| `-u, --uid UID` | emit only events for this uid (repeatable) |
| `-t, --type TYPE` | emit only `execve`/`openat`/`connect`/`mmap`/`mprotect`/`execveat`/`memfd_create`/`ptrace`/`clone3`/`io_uring_enter`/`finit_module` (repeatable) |
| `-j, --json` | newline-delimited JSON instead of text |
| `-m, --mmap [PATH]` | consume the mmap ring at PATH (default `/dev/sentinel_ring`) instead of netlink |
| `-R, --ring-read[=PATH]` | consume the mmap ring via `read(2)` instead of mmap; PATH defaults to `/dev/sentinel_ring` |
| `-C, --no-correlate` | disable the correlation agent (no fileless / exec-trans annotations) |
| `-L, --container-labels` | resolve and annotate each event with its container label (read from the task's cgroup) |
| `-s, --stats` | query filter+ring counters from the kernel via genl `CMD_STATS` and print them, then exit |
| `-a, --apply EXPR` | apply mask/pids/uids/enable to the kernel via genl (e.g. `-a mask=3ffffffff,enable=1,uids=1000,2000`) and exit |
| `-r, --reconnect` | survive module unload/reload: re-resolves the family, treats netlink EOF as a disconnect, and at startup waits (1–30s backoff) for the module if it isn't loaded yet |
| `-f, --config FILE` | read key=value defaults from FILE (see below); every CLI option overrides them |
| `-h, --help` | usage |

Config files are key=value lines with `#` comments; booleans accept
`1/yes/true/on` and `0/no/false/off`. Keys mirror the CLI flags:
`pid`, `uid`, `type`, `json`, `reconnect`, `stats`, `apply`,
`no-correlate`, `container-labels`, and one of `mmap=PATH` /
`ring-read=PATH` (a file may choose a single transport; an empty path
means the default `/dev/sentinel_ring`). Unknown keys, malformed
values, and conflicting transports abort startup with a `file:line`
diagnostic — the file is a defaults source, never a silent guess.

The daemon treats kernel data as semi-trusted: version and payload size are
revalidated before any field is parsed, and a mismatch drops the message
instead of crashing.

## Compatibility

Targets Ubuntu LTS kernels. Build is verified against 5.15-era and current
header sets; see [docs/KERNEL_COMPAT.md](docs/KERNEL_COMPAT.md) for the
matrix and the workarounds that keep the module compiling as kernel APIs
drift (`kallsyms_lookup_name` unexported since 5.7, `_nofault` string-copy
export churn, genl struct evolution).

## Architecture and docs

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — data path, unload ordering, concurrency model
- [docs/HOOKS.md](docs/HOOKS.md) — per-syscall register mapping and capture rules
- [docs/WIRE_PROTOCOL.md](docs/WIRE_PROTOCOL.md) — wire structs, byte offsets, validation
- [docs/KERNEL_COMPAT.md](docs/KERNEL_COMPAT.md) — kernel version matrix and build workarounds
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — what this does and does not defend against

`sentinel-km-deep-plan.md` at the repository root is the design document
(current edition: v7). The code follows it with a few documented
deviations.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

```sh
make -C kernel checkpatch          # must be 0 errors
make -C kernel checkpatch-strict   # checkpatch --strict (informational)
make -C daemon test                # parser unit tests
```

`checkpatch` is a hard **0 errors**; the few remaining warnings are accepted
style friction (`LINUX_VERSION_CODE` version-gating, memory-barrier read/
write pairs, and newer-API suggestions like `kzalloc_obj` that postdate the
oldest kernel we build against). Builds are verified via `make KDIR=...` against the
encoded matrix in [docs/KERNEL_COMPAT.md](docs/KERNEL_COMPAT.md).

Static analysis runs in CI (`.github/workflows/security-scan.yml`):
gitleaks (secret scan), semgrep (`.semgrep/` C rules), sparse + `W=1`
(codegen warnings), cppcheck (daemon), shellcheck (CI/VM scripts), and
codespell. `make -C kernel KDIR=... W=1` and `sparse` (`C=2 CHECK=sparse`)
are available locally too — the workflow runs them non-fatally because
generated headers across kernel versions can emit noise that is not ours.

The kernel module builds as a plain out-of-tree module (`kernel/Makefile`).
No out-of-tree dependencies; the daemon has none either.

## Testing

- Daemon unit tests: `make -C daemon test` — the parser (both transports,
  v8 ABI asserts, batched datagram dispatch), the correlator (exec-track /
  exec-trans / fileless / memfd-window expiry / table eviction / disabled),
  the config-file parser, the JSON escaper (control-byte hardening), and
  differential asm tests (`memchr_zero`, `capture_store`). No kernel
  needed. The same battery runs under ASan+UBSan via `make -C daemon
  sanitize`, and `make -C daemon coverage` drives the line-coverage gate.
- Kernel compile against N header sets: CI matrix, see
  `.github/workflows/build.yml` (Ubuntu 22.04/5.15, 24.04/6.8, current
  mainline headers, plus the aarch64 cross-lane via
  `scripts/build-arm64.sh`). Locally: `make -C kernel KDIR=...`.
- Static analysis / security audit: `.github/workflows/security-scan.yml`
  (gitleaks, semgrep, sparse, cppcheck, shellcheck, codespell).
- Pipeline hygiene: `.github/workflows/pipeline.yml` runs actionlint on the
  workflows and the repo `pre-commit` hooks; `.github/workflows/quality.yml`
  gates on daemon line coverage (`make -C daemon coverage`), checks
  `docs/` links nightly, and flags README drift.
- Runtime (load → trigger every hook → assert one event per type → unload →
  `dmesg` clean): `.github/workflows/runtime.yml` boots a VM with virtme-ng
  on each push — fatal on Ubuntu 24.04 (6.8 LTS), informational on 22.04
  (5.15 LTS). Locally the same suite runs via
  `tests/qemu/boot.sh` (→ `.ci-run.sh`). The smoke test compiles
  `tests/qemu/trace_triggers.c` (a deterministic x86_64 trigger for all
  eight hooks, including a memfd→`execveat(AT_EMPTY_PATH)` fileless exec
  and a hand-rolled 131-byte static ELF) plus `tests/qemu/connect_storm.c`
  (a saturated `connect(2)` trigger so a single ring-drop can never spur
  the "one event per type" assert) and asserts every event type plus
  the `fileless` annotation. `tests/stress/` races rmmod against syscall
  storms: `rmmod_under_load.sh`, `mprotect_hammer.sh`, and
  `ptrace_hammer.sh`.

## Packaging

`packaging/` ships non-interactive package builders driven by
`scripts/build-arm64.sh`-adjacent one-shot scripts:
`packaging/deb/build.sh` and `packaging/rpm/build.sh` (both validate the
toolchain and kernel headers up front). They produce a binary package
(daemon + `sentinel_km.ko` for the build kernel + `/etc/sentinel/sentinel.conf`
sample + systemd unit + DKMS source), installing the module into
`/lib/modules/<kernel>/kernel/misc/` with `depmod` in `%post`/`postinst`.
The version string's single source of truth is `packaging/dkms/dkms.conf`;
`packaging/rpm/sentinel-km.spec` does a source build so it also works
against kernels with matching installation paths (`_kpath`/`_kver`).

## License

Dual-licensed by component:

- **Kernel** (`kernel/`): [GPL-2.0](LICENSE). A module using
  `EXPORT_SYMBOL_GPL` symbols (kprobes) must be GPL-compatible; this choice
  is not optional at the technical level.
- **Shared wire header** `kernel/ipc/sentinel_proto.h`: `GPL-2.0-only OR
  Apache-2.0`.
- **Daemon, tests, docs** (`daemon/`, `tests/`, `docs/`, root docs):
  [Apache-2.0](LICENSE-APACHE). The daemon only *reads* the header and is
  meant to be reusable as the basis for other consumers.

Each file carries a matching SPDX header; see [CONTRIBUTING.md](CONTRIBUTING.md).
