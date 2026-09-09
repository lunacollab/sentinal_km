# Hooks

All eight probes are `kretprobe`s on x86_64 syscall wrapper symbols. The
`__x64_sys_*` prefix is architecture- and version-specific; see
[KERNEL_COMPAT.md](KERNEL_COMPAT.md).

## Register argument mapping (x86_64 System V)

| Syscall | wrapper symbol | arg0 (`di`) | arg1 (`si`) | arg2 (`dx`) | note |
|---|---|---|---|---|---|
| execve | `__x64_sys_execve` | filename | argv | envp | unistd 59 |
| openat | `__x64_sys_openat` | dfd | filename | flags | unistd 257 |
| connect | `__x64_sys_connect` | sockfd | uservaddr | addrlen | unistd 42 |
| mmap | `__x64_sys_mmap` | addr | length | prot | unistd 9 |
| mprotect | `__x64_sys_mprotect` | addr | len | prot | unistd 10 |
| execveat | `__x64_sys_execveat` | dirfd | filename | argv | unistd 322 |
| memfd_create | `__x64_sys_memfd_create` | name | flags | — | unistd 319 |
| ptrace | `__x64_sys_ptrace` | request | pid | addr | unistd 101 |

The *fourth and fifth* syscall arguments are delivered in `r10` and `r8`,
not `rcx` — `rcx` is clobbered as the return address by the syscall entry
path. Read `regs->r10` for arg3, `regs->r8` for arg4, and `regs->r9` for
arg5. Specifically: mmap `flags` is arg3 (`r10`), execveat `envp` is arg3
(`r10`) and `flags` is arg4 (`r8`), ptrace `addr` is arg2 (`dx`) and `data`
is arg4 (`r10`).

## Filter gate

Every entry handler first consults `hook_filter_gate(SENTINEL_SC_*)`
(`core/sentinel_filter.c`, gate numbers in `hooks/hook_common.h`): a
RCU-protected syscall-bitmap + pid set that can be changed at runtime via
sysfs. If the event is filtered out, the handler returns without capturing,
and the ret handler short-circuits via a per-CTX `armed` flag. The gate
reads are lock-free and safe in the atomic probe path.

The `enable` kill switch is deliberately the outermost, cheapest test: it is
a **static key** (`static_branch_unlikely(sentinel_master_gate)`). When
recording is disabled, the whole filter is a single patched NOP — no data
read at all — so an idle module is a few instructions per syscall, not a
cacheline-bound test_bit scan.

## Per-hook capture rules

### execve — `hook_execve.c`

- Entry: capture `pid`, `timestamp_ns`, `cpu`, and `SENTINEL_EXECVE_PATH_MAX`
  bytes of `filename` from `regs->di`.
- Ret: emit **only when `regs_return_value() == 0`**. A failed execve never
  becomes a process image. Slots that were `armed` at entry are walked on the
  way back: `argv` (`regs->si`) is read as an array of pointers and up to
  `SENTINEL_ARGV_MAX_ARGS` entries are copied, each bounded to
  `SENTINEL_ARGV_STR_MAX` bytes, reusing the pre-allocated kmem_cache
  capture. The payload is offset-addressed (`path_off`, `args_off`, `argc`)
  so the bounded body is one blob; see [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md).
- No `copy_from_user` on argv: lengths are measured with the page-chunked
  nofault `sentinel_strnlen_user_max()`, then copied with the same
  `strncpy_from_user_nofault` used for paths.
- `maxactive = 16`.

### openat — `hook_openat.c`

- Entry: capture `dfd`, `flags`, bounded copy of `filename` from `regs->si`.
- Ret: emit **always, success or failure** — but only if the entry handler
  armed the slot. Failed opens are events of interest to an activity monitor.

### connect — `hook_connect.c`

- Entry: capture `sockfd` and a bounded copy of the userspace `sockaddr`
  (clamped to `sizeof(struct sockaddr_storage)`). `copy_from_user()` is
  safe: the buffer is a live user mapping the syscall is about to
  dereference and we run as `current`.
- Ret: parse family; for `AF_INET` emit port + 4-byte address, for
  `AF_INET6` emit port + 16-byte address. Other families keep the family
  byte and empty payload fields.

### mmap — `hook_mmap_exec.c`

- Entry (`CONFIG_X86_64` only): capture `addr`, `length`, `prot`, `flags`
  (from `regs->r10`), `fd` (from `regs->r8`), and `offset` (from
  `regs->r9`, raw mmap file offset / arg5).
- Ret: variable-length record whose `path` field is only set when the mapping
  is not `MAP_ANONYMOUS`; used on the daemon side to distinguish an executable
  file mapping from anon executable memory (a JIT). `req_addr` is the
  requested address, `mapped_addr` the kernel's return value. `offset` is the
  file offset passed to `mmap`; it is always `0` for `MAP_ANONYMOUS` but
  nonzero for file-backed mappings (useful for correlating with debuginfo or
  ETLS relocation logic).

### mprotect — `hook_mprotect.c`

- Entry (`CONFIG_X86_64` only): capture `addr`, `len`, and `prot` straight
  from `regs->di`/`regs->si`/`regs->dx`. **No userspace memory is copied**:
  the three register arguments are the whole event, so the entry context is
  tiny and there is no string path to go wrong.
- Ret: emit **always, success or failure** (a *failed*
  `mprotect(PROT_EXEC)` is at least as interesting to an activity monitor
  as a successful one — the openat/connect convention), but only when the
  entry handler armed the slot: `armed = prot & PROT_EXEC`. That keeps the
  ret path a no-op for the (overwhelmingly more common) non-EXEC calls while
  still firing on W^X violations (`PROT_WRITE|PROT_EXEC`) and JIT
  executable flips.

### execveat — `hook_execveat.c`

- Entry: capture `dirfd` (`regs->di`), bounded copy of `filename`
  (`regs->si`), `flags` (`regs->r8`). The argv/envp pointers (`regs->dx` /
  `regs->r10`) are stashed for the ret handler like execve's.
- Ret: emit **only when `regs_return_value() == 0`**, reusing the exact
  argv-copy machinery of `hook_execve.c`. The payload is the execve blob
  plus the extra 8 bytes of `dirfd`/`flags` (`SENTINEL_EXECVEAT_PATH_OFF ==
  14`). With `AT_EMPTY_PATH` (0x1000) `filename` is `""` and the fd in
  `dirfd` is the whole story — the daemon's `fileless` correlation keys on
  that combination against a `memfd_create` that returned the **same fd**
  (v7: identity correlation, see `correlate.c`).
- `maxactive = 16`.

### memfd_create — `hook_memfd_create.c`

- Entry: capture up to 15 bytes of `name` from `regs->di` and `flags` from
  `regs->si`.
- Ret: emit **always** — an attempt is an attempt, whether or not the kernel
  handed back a fd. Since v7 the returned `fd` *is* carried on the wire
  (`regs_return_value()`; negative errno on failure) so the daemon can pair
  it exactly with `execveat.dirfd` instead of a pid+time window.

### ptrace — `hook_ptrace.c`

- Entry: capture `request` (`regs->di`), `target_pid` (`regs->si`), `addr`
  (`regs->dx`), and `data` (`regs->r10`) — registers only, never
  dereferenced.
- Ret: emit **always, success or failure**. There is no `armed` gating or
  retval check: ptrace's victims (secrets, memory, control flow) make the
  *attempt* the signal. Each static helper is named `ptrace_hook_*` — never
  `ptrace_*` — to avoid colliding with the kernel's own `<linux/ptrace.h>`
  inlines.

## Copy discipline (all hooks)

Every user-controlled string is copied with `hook_copy_us_str()`, bounded by
a compile-time constant (`SENTINEL_PATH_MAX`/`SENTINEL_ARGV_STR_MAX`), and
NUL-terminates defensively. The underlying call is
`strncpy_from_user_nofault()` when resolvable (resolved once at init via a
throwaway kprobe for kernels where it is not exported); otherwise it falls
back to the always-exported `strncpy_from_user()`. Both agree on return
value and termination; the fault behavior differs in ways irrelevant to us.

`sentinel_strnlen_user_max()` measures argv strings **without the hard page-
fault path**: it walks the source page-by-page, never crossing a page
boundary within one nofault copy, so every fault is either fully contained
on that page or surfaces as a clean truncation — there is no `FIXUP`/`__ex_table`
edge case. (An earlier design used hand-written fixup asm, which cannot ship
as an out-of-tree module on `CONFIG_STACK_VALIDATION` builds; see
[KERNEL_COMPAT.md](KERNEL_COMPAT.md).)

## Captures and lifetime

Ret handlers build `struct sentinel_capture` from a kmem_cache pool
(`sentinel_capture_alloc_gfp_atomic()`, `..._free()`), sized to the worst
record (~2.4 KB execve). This keeps kretprobe frames tiny and avoids
`GFP_KERNEL` in the atomic path; the pool itself is created at module init
and destroyed at exit, after all probes are unregistered.

## Per-instance data sizing

`struct kretprobe.data_size` must be set explicitly. It is fixed per probe
and allocated out of the kretprobe pool, so oversized values waste
preallocated memory and undersized values corrupt adjacent instances.
`maxactive` bounds concurrent outstanding calls per probe.

## Hook lifecycle

`enable`/`disable` in each `const struct sentinel_hook_ops` call
`register_kretprobe()`/`unregister_kretprobe()`. The registry calls these
once at module init/exit; probes are never toggled at runtime — the sysfs
`enable` gate works by making entry handlers no-op, not by (re)registering
probes.

## Adding a new hook

1. Define the event type in `sentinel_proto.h` (bump the version).
2. Add the payload struct there; make sure `SENTINEL_MAX_PAYLOAD` still
   covers the worst case.
3. Add the gate bit `SENTINEL_SC_<SYS>` (the x86_64 unistd number used by
   the sysfs mask) to the enum in `kernel/hooks/hook_common.h`.
4. Write `hook_<name>.c`: per-instance ctx, armed entry + ret handlers,
   `enable`/`disable`, and a `const sentinel_hook_ops` table.
5. Add `.name` symbol to `kernel/hooks/sentinel_hooks.h`, add the object to
   `kernel/Kbuild`, and register the hook in `sentinel_main.c`.
6. Update `docs/WIRE_PROTOCOL.md` byte table and the daemon parser
   (`daemon/src/parse.c`) dispatch, the text/JSON printers in
   `daemon/src/main.c`, the DAEMON test binaries, and extend `correlate.c`
   when the event should feed a heuristic (fileless exec, known-image
   tracking).
