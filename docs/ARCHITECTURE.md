# Architecture

sentinel_km is a Linux kernel module that watches syscall activity and a
small userspace daemon that consumes it. The kernel side never blocks and
never sleeps in the probe path; all expensive work is pushed onto a
per-CPU worker and delivered over Generic Netlink multicast and/or a
zero-copy mmap ring.

## Data path

```
syscall entry/exit
   │  kretprobe pre/post handlers  (atomic, preemption disabled)
   ▼
kernel-side filter gate (type bitmap + pid set, RCU-safe)
   │
   ▼
kprobe handler copies bounded context into a per-instance ctx (armed iff not filtered)
   │
   ▼
ret handler builds a struct sentinel_capture from the kmem_cache pool
   │  preemption still disabled; never allocates GFP_KERNEL
   ▼
sentinel_ring_push() stores the capture into the calling CPU's ring
   │  lock-free: single writer per CPU
   │   on x86_64 the store is sentinel_capture_store():
   │   1-pass copy of the populated prefix + zero-fill (see sentinel_capture.c)
   ▼
ring_drain_worker (bound kworker on the same CPU, process context)
   │
   ├──▼ sentinel_genl_emit() -> genlmsg_multicast()
   │       │
   │       ▼  userspace: sentinel-daemon on multicast group "events"
   │
   └──▼ sentinel_ringmap_emit() -> spinlock-protected mmap ring write
           │
           ▼  userspace: sentinel-daemon --mmap on /dev/sentinel_ring
```

### Why the ring exists

The probe handlers cannot sleep, cannot fault-recover, and cannot
`GFP_KERNEL`-allocate. `genlmsg_new()` + `nla_put()` + multicast are all
requireable process-context operations. The ring decouples the two:
producers always succeed or drop, consumers do the real work.

### Why the mmap ring exists

Generic netlink copies every payload into each subscriber's skb. For a
single high-throughput consumer the `mmap` ring skips allocation, the skb
path, and userspace receipt entirely: the drain `memcpy`s record bytes
into shared memory and the consumer reads them back with only a release
store on one index word. This is the zero-garbage-collection observation
path for load-driven workloads.

## The unload ordering (the part most modules get wrong)

`sentinel_exit()` runs, in order:

1. `sentinel_filter_exit()` — `synchronize_rcu()` after all writers are
   gone, so no probe reads a freed filter. All subsequent probes are
   scheduled off anyway.
2. `sentinel_hook_unregister()` for every hook — which itself unregisters
   the kretprobe, then `synchronize_rcu()` so no handler is in flight.
3. `sentinel_ringmap_unregister()` — the mmap device is torn down.
4. `sentinel_ring_flush()` — `flush_workqueue()` waits for every queued
   drain worker. After step 2 no new captures can be produced, so the flush
   is terminal.
5. `sentinel_ring_exit()` — frees the percpu ring storage and the capture
   kmem_cache.
6. `sentinel_genl_unregister()` — only after no code can emit.

Reversing any of these steps is a use-after-free: a worker touching
`ring_cpus` after `free_percpu()`, a probe firing after
`unregister_kretprobe()`, or a drain worker emitting into a freed mmap
ring.

## Concurrency model

| Component | Mechanism | Why |
|---|---|---|
| Hook registry | RCU list + writers under one spinlock | read once per syscall, write at load/unload |
| Filter gate | RCU-protected bitmap + pid set | read in every probe entry, write from sysfs |
| Per-CPU ring | single-writer/single-reader, no lock | preemption disabled in handlers; bound worker on same CPU |
| Ring drain | bound (per-CPU) workqueue | a worker must never migrate off its ring's CPU |
| Capture pool | `kmem_cache`, `GFP_ATOMIC` fallback | reuses worst-case records without stack allocations |
| mmap ring | one producer (drain workers, under a spinlock), one consumer | single-consumer device; Aeq/Rel index publishing |
| Drop counter | `atomic64_t` | any CPU may observe it via sysfs |

## Per-CPU ring, worker affinity

`alloc_workqueue("sentinel_ring", 0, 0)` creates a *bound* workqueue.
`queue_work_on(smp_processor_id(), ...)` therefore runs the drain worker on
the exact CPU that produced the events. This is what makes the
`head`/`tail`/`pending` accesses race-free without locks. An `WQ_UNBOUND`
pool would allow worker migration and reintroduce a data race.

## Syscall hook mechanics

Each hook is a `struct kretprobe` with an entry handler and a ret handler.
See [HOOKS.md](HOOKS.md) for the per-syscall register layout and the
bounded-copy rules. All captures are time-stamped with
`ktime_get_real_fast_ns()` (CLOCK_REALTIME, no lock).

## Module anatomy

```
kernel/
  core/sentinel_main.c       init/exit, sysfs knobs, hook wiring
  core/sentinel_registry.c   RCU hook registry
  core/sentinel_filter.c     syscall-bitmap + pid-set gate (params + sysfs)
  core/sentinel_symresolve.c kallsyms workaround
  hooks/hook_execve.c        __x64_sys_execve (full argv walk)
  hooks/hook_openat.c        __x64_sys_openat
  hooks/hook_connect.c       __x64_sys_connect
  hooks/hook_mmap_exec.c     __x64_sys_mmap (CONFIG_X86_64)
  hooks/hook_copy.c          version-independent user copy + page-chunked strnlen
  ipc/sentinel_genl.c        genl family, multicast emit
  ipc/sentinel_ring.c        per-CPU ring + bound drain workers + capture pool
  ipc/sentinel_ringmap.c     /dev/sentinel_ring mmap export
  ipc/sentinel_proto.h       wire protocol (shared with userspace)
```

## Loose ends kept deliberately out of v2

- No control/GENL commands: the family only reserves the name + multicast
  group. Adding a stats command is a later phase.
- The mmap ring is single-consumer by design (`-EBUSY` on a second open);
  multi-consumer would need per-consumer tails.
- `trace_mask` semantics: the gate follows the *syscall number in the
  architecture's unistd table*, so `SENTINEL_SC_*` bit values are
  x86_64-specific (unistd 9 mmap, 42 connect, 59 execve, 257 openat).
