# Wire Protocol

Versioned at `SENTINEL_PROTO_VERSION` (currently `8`) in
`kernel/ipc/sentinel_proto.h`, included unmodified by both kernel and
daemon. Bump the version on ANY layout change; the daemon refuses to parse
a message whose version does not match.

v7 changes since v6: the event header grows 48→52 bytes with a trailing
per-record CRC-32C; `SENTINEL_EV_MEMFD_CREATE` gains the returned `fd`
(identity key for the fileless correlation); `SENTINEL_EV_CLONE3` and
`SENTINEL_EV_IO_URING_ENTER` are added.

v8 changes since v7: `SENTINEL_EV_IO_URING_ENTER` grows 24→32 bytes with a
ret-side completion pairing (`submitted`, `completed`); `SENTINEL_EV_FINIT_MODULE`
(8 bytes) is added; `SENTINEL_ATTR_MASK` becomes a hex-text syscall bitmap
over the full 1024-bit space (v7's `u64` could only express syscalls 0–63,
but v8 hooks live at 313/426/435); the mmap ring meta gains `capacity` and
`epoch` and the data-ring size becomes runtime-configurable (`ringmap_size`
knob), with the `epoch` re-open handshake and a dual-consumer refusal harness
(P2.3).

## Transports

Two, both reading the same record stream:

### 1. Generic Netlink multicast

- family name: `sentinel_km`
- family version: `SENTINEL_PROTO_VERSION`
- multicast group: `events` (index `SENTINEL_GENL_MCGRP_EVENT == 0`)
- message: one `nlmsghdr` + `genlmsghdr` followed by one or more
  `EVENT`+`PAYLOAD` attribute pairs. Events are batched: the kernel fills a
  skb up to `SENTINEL_GENL_BATCH_MAX` events (a soft bound — on a full skb
  the batch flushes first, so no event is dropped by batching), then
  multicasts. A single datagram may therefore carry many events; consumers
  must dispatch every pair, not just the first.

Attributes:

| id | name | content |
|---|---|---|
| 1 | `SENTINEL_ATTR_EVENT` | `struct sentinel_event_hdr` |
| 2 | `SENTINEL_ATTR_PAYLOAD` | event-specific payload struct |

Each `EVENT` attribute is immediately followed by its `PAYLOAD`; pairs
repeat back-to-back in one `nlmsghdr`.

The kernel never sends anything but multicast events on its own; the
userspace daemon must skip `GENL_HDRLEN` before iterating attributes — a
common off-by-one in hand-rolled clients.

#### Generic Netlink commands (request/response)

The kernel also exposes a request/response control plane via unicast
messages. The family advertises these commands:

| command | enum | direction | request attrs | response attrs |
|---|---|---|---|---|
| `CMD_STATS` | 1 | → kernel → userspace | none | `ATTR_STATS_PUSHED`, `ATTR_STATS_DROPPED`, `ATTR_STATS_RINGMAP_DROPPED`, `ATTR_STATS_BAILED`, `ATTR_STATS_REQUEUED`, `ATTR_STATS_DRAIN_NS`, `ATTR_STATS_SENT`, `ATTR_MASK`, `ATTR_PIDS`, `ATTR_UIDS`, `ATTR_ENABLE` |
| `CMD_SETMASK` | 2 | → kernel | `ATTR_MASK` (v8 hex text) | none (ACK) |
| `CMD_SETPIDS` | 3 | → kernel | `ATTR_PIDS` (nul-string) | none (ACK) |
| `CMD_ENABLE` | 4 | → kernel | `ATTR_ENABLE` (u8) | none (ACK) |
| `CMD_SETUIDS` | 5 | → kernel | `ATTR_UIDS` (nul-string) | none (ACK) |

#### Generic Netlink attributes

| id | name | type | notes |
|---|---|---|---|
| 1 | `ATTR_EVENT` | binary | `struct sentinel_event_hdr` (multicast only) |
| 2 | `ATTR_PAYLOAD` | binary | event-specific payload (multicast only) |
| 3 | `ATTR_MASK` | v8: hex text | syscall bitmap for syscalls `0..SENTINEL_MASK_BITS-1`, as ASCII hex (up to 256 digits, NUL-terminated). The kernel parses the *same* grammar its sysfs `filter` knob uses (`all`/`none`/`set NR`/`clr NR`/hex), so the daemon's `--apply "mask=..."` and the sysfs write can never drift. Numbers above 63 (`finit_module`=313, `io_uring_enter`=426, `clone3`=435) are addressable from v8 |
| 4 | `ATTR_PIDS` | nul-string | whitespace-separated pids, same semantics as sysfs `filter_pids` |
| 5 | `ATTR_ENABLE` | u8 | `1`/`0` master enable gate |
| 6 | `ATTR_STATS_PUSHED` | u64 | cumulative events pushed to per-CPU rings |
| 7 | `ATTR_STATS_DROPPED` | u64 | cumulative per-CPU ring overflows |
| 8 | `ATTR_STATS_RINGMAP_DROPPED` | u64 | cumulative mmap ring overflows |
| 9 | `ATTR_STATS_BAILED` | u64 | cumulative reentrancy bail-outs |
| 10 | `ATTR_STATS_REQUEUED` | u64 | deferred-flush re-queues (see ring design) |
| 11 | `ATTR_STATS_DRAIN_NS` | u64 | accumulated drain-worker time, ns |
| 12 | `ATTR_STATS_SENT` | u64 | netlink datagrams multicast (v6) |
| 13 | `ATTR_UIDS` | nul-string | comma-separated uids, same semantics as sysfs `filter_uids` |

### 2. mmap ring (`/dev/sentinel_ring`)

The same events, but the drain worker writes records directly into a
5-page ring the consumer maps with `mmap()`; see "mmap ring export" below.

## Event types

| value | name |
|---|---|---|
| 1 | `SENTINEL_EV_EXECVE` |
| 2 | `SENTINEL_EV_OPENAT` |
| 3 | `SENTINEL_EV_CONNECT` |
| 4 | `SENTINEL_EV_MMAP_EXEC` (x86_64) |
| 5 | `SENTINEL_EV_MPROTECT` (x86_64) |
| 6 | `SENTINEL_EV_EXECVEAT` (x86_64) |
| 7 | `SENTINEL_EV_MEMFD_CREATE` (x86_64) |
| 8 | `SENTINEL_EV_PTRACE` (x86_64) |
| 9 | `SENTINEL_EV_CLONE3` (x86_64) |
| 10 | `SENTINEL_EV_IO_URING_ENTER` (x86_64) |
| 11 | `SENTINEL_EV_FINIT_MODULE` (x86_64) |

## Header — `struct sentinel_event_hdr` (52 bytes)

The first four bytes are ABI-pinned at offsets `0..3`; consumers may not
assume the rest is stable across major versions, but the daemon only ever
parses one pinned version at a time.

| offset | size | field | notes |
|---|---|---|---|
| 0 | 1 | `proto_version` | must equal `SENTINEL_PROTO_VERSION` |
| 1 | 1 | `event_type` | one of the enum above |
| 2 | 2 | `payload_len` | size of the payload struct that follows |
| 4 | 4 | `pid` | tgid capture for the task |
| 8 | 4 | `ppid` | parent tgid at capture time (v6) |
| 12 | 4 | `uid` | real uid, init-ns munged (v6) |
| 16 | 4 | `gid` | real gid, init-ns munged (v6) |
| 20 | 8 | `timestamp_ns` | `ktime_get_real_fast_ns()` at syscall entry |
| 28 | 2 | `cpu` | `raw_smp_processor_id()` |
| 30 | 16 | `comm` | exec base name, fixed 16 bytes (v6) |
| 46 | 2 | `reserved` | zeroed |
| 48 | 4 | `crc32` | CRC-32C over the 48 bytes at `0..47` (v7) |

The context quartet and `comm` are sampled in the kretprobe handler, so for
`execve`/`execveat` the `comm` reflects the image that actually ran. `comm`
is *not* guaranteed NUL-terminated on the wire; treat it as a fixed-length
field. If none of the three (ppid/uid/gid) is interesting as a scan target,
mask them out client-side — they cost nothing to carry.

`crc32` is computed over the packed header+payload of the record the
producer emits; the CRC is part of the *frame* the daemon verifies. Both
transports carry the same field — netlink pairs and ring records alike.

## Payloads

### `struct sentinel_ev_execve` — variable-length, v2

Fixed part is 6 bytes; three `u16` offsets address a string blob. The
layout is *not* a fixed-size struct:

| offset | size | field | notes |
|---|---|---|---|
| 0 | 2 | `path_off` | must equal `SENTINEL_EXECVE_PATH_OFF` (`sizeof(...) == 6`) |
| 2 | 2 | `args_off` | byte offset of the argv blob; `path_off <= args_off <= payload_len` |
| 4 | 2 | `argc` | number of NUL-terminated strings in the argv blob |
| `path_off` | ... | `path` | NUL-terminated filename |
| `args_off` | ... | `argv blob` | exactly `argc` NUL-terminated strings, concatenated |

Worst case: `6 + 256 + 16*128 = 2310` bytes. `SENTINEL_MAX_PAYLOAD` (4096)
bounds the on-wire payload; the daemon enforces it before parsing.

### `struct sentinel_ev_openat` (264 bytes)

| offset | size | field |
|---|---|---|
| 0 | 256 | `filename` (NUL-terminated) |
| 256 | 4 | `dfd` (`int`) |
| 260 | 4 | `flags` (`int`, raw `openat` arg2) |

### `struct sentinel_ev_connect` (135 bytes)

| offset | size | field |
|---|---|---|
| 0 | 4 | `sockfd` |
| 4 | 1 | `addr_family` (`sa_family_t`, host byte order) |
| 5 | 2 | `port_be` (big-endian; swap for host order) |
| 7 | 128 | `addr` (AF_INET: 4 bytes; AF_INET6: 16 bytes; else zeroed) |

### `struct sentinel_ev_mmap_exec` (44 bytes)

| offset | size | field | notes |
|---|---|---|---|
| 0 | 8 | `mapped_addr` | return value on success |
| 8 | 8 | `req_addr` | requested address (arg0) |
| 16 | 8 | `length` | mapping size (arg1) |
| 24 | 4 | `prot` | raw arg2 (`PROT_EXEC`, `PROT_WRITE` bits) |
| 28 | 4 | `flags` | raw arg3 (contains `MAP_ANONYMOUS`) |
| 32 | 4 | `fd` | raw arg4; `-1` for anonymous |
| 36 | 8 | `offset` | raw arg5; mmap file offset in bytes |

### `struct sentinel_ev_mprotect` (24 bytes), v4

The signal is a region being flipped to `PROT_EXEC` (a JIT making its code
pages runnable) or to `PROT_WRITE|PROT_EXEC` (the textbook W^X violation).
No user memory is copied; the three register arguments are the whole event.
The event fires on success *and* on failure — a failed `mprotect(PROT_EXEC)`
is at least as interesting as a successful one.

| offset | size | field | notes |
|---|---|---|---|
| 0 | 8 | `addr` | start of the affected range (arg0) |
| 8 | 8 | `len` | range length in bytes (arg1) |
| 16 | 4 | `prot` | raw arg2 (`PROT_EXEC`, `PROT_WRITE` bits) |
| 20 | 4 | `reserved` | zeroed |

### `struct sentinel_ev_execveat` — variable-length, v5

Same blob discipline as `sentinel_ev_execve` — a fixed 14-byte head plus
offset-addressed strings — but carries the fd-relative form's extra
arguments. For an `AT_EMPTY_PATH` exec the `path` string is empty; the pair
`memfd_create` (which since v7 carries the returned `fd`) +
`execveat("", dirfd=fd, AT_EMPTY_PATH)` in the same pid is the daemon's
`fileless` correlation — an identity match on pid + fd + empty path, not a
pid+time guess.

| offset | size | field | notes |
|---|---|---|---|
| 0 | 2 | `path_off` | must equal `SENTINEL_EXECVEAT_PATH_OFF` (`sizeof(...) == 14`) |
| 2 | 2 | `args_off` | byte offset of the argv blob; `path_off <= args_off <= payload_len` |
| 4 | 2 | `argc` | number of NUL-terminated strings in the argv blob |
| 6 | 4 | `dirfd` | raw arg0 (fd, or `AT_FDCWD`) |
| 10 | 4 | `flags` | raw arg4 (`AT_EMPTY_PATH` = 0x1000) |
| `path_off` | ... | `path` | NUL-terminated filename (`""` when `AT_EMPTY_PATH`) |
| `args_off` | ... | `argv blob` | exactly `argc` NUL-terminated strings, concatenated |

The event fires only on success (retval 0), mirroring `execve`.

### `struct sentinel_ev_memfd_create` (28 bytes), v7

| offset | size | field | notes |
|---|---|---|---|
| 0 | 16 | `name` | the `memfd_create` name (NUL-terminated, 15 chars + NUL) |
| 16 | 4 | `flags` | raw arg1 (`MFD_CLOEXEC`, `MFD_ALLOW_SEALING`, ...) |
| 20 | 4 | `fd` | kretprobe return value: the memfd descriptor on success, the negative errno on failure (`s32`) |
| 24 | 4 | `reserved` | zeroed |

The descriptor first captured in v7. Emitted unconditionally — a failed
`memfd_create` is still a memfd attempt — and when it fails `fd < 0`, so the
attempt signal and the identity key ride on the same record. As a transient
descriptor `fd` is process-relative and only meaningful while open; the
daemon never resolves it, it only matches it against `execveat.dirfd`.

### `struct sentinel_ev_ptrace` (24 bytes), v5

ptrace reaches into arbitrary processes by design; capturing the request,
target, and pointer arguments (without dereferencing) makes the event both
cheap and analyst-usable. Emitted unconditionally — `PTRACE_ATTACH` that
fails with `EPERM` is as interesting as one that succeeds.

| offset | size | field | notes |
|---|---|---|---|
| 0 | 4 | `request` | raw arg0 (`PTRACE_*` enum) |
| 4 | 4 | `target_pid` | raw arg1 (pid, `s32`; `0` = self) |
| 8 | 8 | `addr` | raw arg2 (address or `NULL`) |
| 16 | 8 | `data` | raw arg3 (register value, address, or `NULL`) |

### `struct sentinel_ev_clone3` (24 bytes), v7

The userns/namespace-mint observability clock. Entry-emitted unconditionally
with a bounded no-fault copy of two `struct clone_args` fields; nothing user-
accessible is dereferenced beyond that. The daemon decodes the `CLONE_NEW*`
bits in `flags` — `CLONE_NEWUSER` is the headline signal.

| offset | size | field | notes |
|---|---|---|---|
| 0 | 8 | `flags` | `clone_args.flags` (raw arg; `CLONE_NEWUSER` etc.) |
| 8 | 4 | `args_size` | raw arg1 (the caller's `sizeof(struct clone_args)`; 0 if `uargs` was `NULL`) |
| 12 | 4 | `exit_signal` | `clone_args.exit_signal` (u32 at offset 40; 0 if `args_size` did not cover it) |
| 16 | 8 | `pidfd_ptr` | raw arg2 (`struct file __user *` to receive the pidfd; never dereferenced) |

### `struct sentinel_ev_io_uring_enter` (32 bytes), v8

Async-submission visibility, now with a ret-side completion pairing. The
entry handler stashes the raw register set on the way in; the ret handler
folds in the two numbers that bracket the call:

- `submitted` — how many SQEs the kernel admitted. On success the kernel's
  contract is that the return value counts submitted workers; on failure it
  returns `-submitted`. Both decode to a plain count here, clamped to the
  offered `to_submit` so a broken kernel cannot overflow the field.
- `completed` — how many CQEs the caller was going to wait for. The kernel
  exposes no per-call drain counter, so the honest proxy is `min_complete`
  when `IORING_ENTER_GETEVENTS` (bit 0 of `flags`) requested it, else 0.

Nothing is dereferenced: `sig` is a pointer captured raw.

| offset | size | field | notes |
|---|---|---|---|
| 0 | 4 | `fd` | raw arg0 (`s32`; the io_uring instance) |
| 4 | 4 | `to_submit` | raw arg1 (SQEs offered) |
| 8 | 4 | `min_complete` | raw arg2 (CQEs awaited) |
| 12 | 4 | `flags` | raw arg3 (`IORING_ENTER_*`) |
| 16 | 8 | `sig_ptr` | raw arg4 (`sigset_t __user *`; never dereferenced) |
| 24 | 4 | `submitted` | v8: decode of the penultimate retval, clamped |
| 28 | 4 | `completed` | v8: `GETEVENTS ? min_complete : 0` |

### `struct sentinel_ev_finit_module` (8 bytes), v8

A module image loaded from a detached descriptor — the fileless driver-load
path. `fd` is the identity key for the daemon's image correlation: a memfd
fd minted by `memfd_create` in the same pid and then handed to
`finit_module` is exactly how a loader stages a sealable image. Emitted for
every call, success or failure — an `EPERM`'d attempt is signal, not noise.
The payload is the two register arguments verbatim; nothing is dereferenced.

| offset | size | field | notes |
|---|---|---|---|
| 0 | 4 | `fd` | raw arg0 (`s32`; descriptor of the module image; may be negative on a probe of the fast-fail path) |
| 4 | 4 | `flags` | raw arg1 (`MODULE_INIT_*` bits) |

## mmap ring export

`/dev/sentinel_ring` is a single-consumer misc device (a second open returns
`-EBUSY`). The mapping is **meta page + a power-of-two data ring**; the data
capacity is runtime-configurable via the `ringmap_size` knob (module param
and `/sys/kernel/sentinel_km/ringmap_size`, KiB, power of two between
`SENTINEL_RINGMAP_MIN_KIB` (4) and `SENTINEL_RINGMAP_MAX_KIB` (1024), default
`SENTINEL_RINGMAP_DEFAULT_KIB` (16)). A resize is refused while a consumer
holds the mapping. The consumers discover the size from the meta page, so the
mapping is `SENTINEL_RINGMAP_META_SIZE + capacity` bytes — 5 pages at the
default 16 KiB.

- **page 0** — `struct sentinel_ringmap_meta`: `magic`
  (`SENTINEL_RINGMAP_MAGIC == 0x53454e52`), `mask` (`capacity - 1`),
  `capacity` (data ring bytes), `epoch`, `head`/`tail` byte indices
  (absolute, grow until the capacity-1 wrap), `drop_count`.
- **the rest** — `capacity` bytes of data ring; the ring slot at absolute
  index `i` is `i & mask`. Capacity is a power of two, so the consumer wraps
  with a mask, never a modulo.

`epoch` is the re-open handshake: a strictly increasing incarnation counter
assigned on every `open()` (first is 1, never 0). Consumers record it at
open, so a mapping that outlives a close/reopen (e.g. across module reload)
is provably a stale ring, and the daemon can detect "this mapping predates
the current device incarnation" by comparing against a fresh open. The
dual-consumer refusal harness (`tests/qemu/ringmap_reopen_test.c`) asserts
the `-EBUSY`, resize-while-held, and epoch-ordering sides of the contract.

Each record is `struct sentinel_ring_rec`: `rec_len` (== `sizeof(rec)` +
payload_len, 56 + payload_len in v8) followed by the 52-byte
`sentinel_event_hdr` and the payload:

| offset | size | field |
|---|---|---|
| 0 | 4 | `rec_len` |
| 4 | 52 | `struct sentinel_event_hdr` |
| 56 | ... | payload (`rec_len - 56` bytes) |

Index protocol: the producer stores `head` with **release** semantics after
writing a record; the consumer stores `tail` with **release** after
consuming one, and both read the peer's index with **acquire**. A record is
not ready until `head` moves; the consumer must never read a slot `>= head`.
`poll()`/`EPOLLIN` returns when `head != tail`. Overfull records are
dropped and `drop_count` incremented.

Consumers: the daemon (`-m/--mmap`) implements the same single-consumer
algorithm; the userspace side re-checks `magic`, `epoch`, `capacity` (range
and power of two), `mask == capacity - 1`, and `rec_len <= capacity` before
dereferencing anything.

## Validation rules (daemon)

Before any payload cast the daemon checks, in order:

1. `nlmsg_len` covers `nlmsghdr` + `genlmsghdr`.
2. `SENTINEL_ATTR_EVENT` payload is exactly `sizeof(struct sentinel_event_hdr)`.
3. `proto_version == SENTINEL_PROTO_VERSION`.
4. `event_type` is a known value.
5. `payload_len == sizeof(<that event's payload struct>)` (for the two
   variable-length carry types `execve` and `execveat`: `payload_len >=
   SENTINEL_*_PATH_OFF`, `path_off == sizeof(fixed head)`, `args_off` in
   bounds, `argc` <= `SENTINEL_ARGV_MAX_ARGS`, and the argc NUL-terminated
   strings must fit exactly in the blob).
6. `SENTINEL_ATTR_PAYLOAD` exists, matches `payload_len`, and follows the
   header attribute.
7. `crc32` matches a CRC-32C over the packed header+payload (v7). A record
   whose CRC fails is dropped as malformed, never "repaired".

A violation drops the message (in batch mode, only the offending pair; the
rest of the datagram still dispatches) and (in non-JSON mode) logs
"malformed event"; the stream is treated as semi-trusted input in case of a
kernel bug.

## Loss accounting

A probe that finds its per-CPU ring full drops the event and increments a
per-CPU counter, surfaced at `/sys/kernel/sentinel_km/stats` (`dropped`, an
aggregate over CPUs); the mmap ring additionally counts overfull records in
`drop_count`. Consumers should treat gaps between timestamps as possibly
lost events once `dropped`/`drop_count` grows.

The same stats file carries `drops_by_type`, the overflow drops (online
rings + mmap ring summed) split by numeric event type as `<type>=<n>` pairs
— hanging a `grep 'drops_by_type'` on the live node shows *which* syscalls
are being shed under overload (P2.4).

Two v5 counters describe the drain machinery itself: `requeued` counts
deferred-flush re-queues (the worker reclaiming the ownership token after a
push landed during a drain — see the ring handshake in `ARCHITECTURE.md`),
`drain_ns` accumulates worker emit time, and `sent` counts netlink datagrams
multicast (batches, not events). A steadily climbing `requeued` next to a
full `dropped` counter is the classic shape of a producer that outruns the
drain; `drain_ns`/events is the per-event cost per CPU; `events` vs `sent`
is the batching ratio.
