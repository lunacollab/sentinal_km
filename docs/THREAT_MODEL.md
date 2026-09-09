# Threat Model

sentinel_km is a *legitimate observability tool* — a kernel module that
reports which processes execute, open files, and connect. State clearly
what it protects against, what it does not, and the trust boundary.

## What it defends against

- Post-compromise *observation* by an operator: an admin with
  `CAP_SYS_MODULE` can load the module and see process-exec, file-open and
  outbound-connect activity with kernel timestamps, in near real time,
  without polling `/proc`.
- Blind spot elimination: on-disk auditing (auditd) is bypassable;
  kprobe-based capture sits at the syscall boundary and cannot be eluded by
  a userspace process (a process cannot skip its own `execve`, `openat`, or
  `connect` syscalls).

## What it does NOT defend against

- **Kernel-level attackers.** If the kernel is already compromised at a
  level that can blind or patch kprobes — or disable the module — this tool
  is useless. It is not a rootkit detector, and claims otherwise would be
  dishonest.
- **eBPF/other syscall-boundary races.** A determined attacker with
  `CAP_SYS_ADMIN` or kernel write primitives outranks any userspace
  monitor.
- **Data completeness.** Events are emitted asynchronously through per-CPU
  rings. Under sustained syscall storms rings fill and events are dropped
  (counted via `/sys/kernel/sentinel_km/stats`). This is a sampling
  monitor with loss accounting, not a gapless recorder.
- **Encrypted or mmap'd I/O contents.** It records metadata (paths, ports,
  pids), never file contents or packet payloads.

## Trust assumptions

1. **`CAP_SYS_MODULE`** is equivalent to kernel code execution. Granting it
   is granting full control; the module adds nothing to that boundary.
2. **Root/user separation** matters only if the kernel itself is trusted.
3. **The daemon is unprivileged-peer only.** It subscribes to a multicast
   group any process on the system can join by design (open monitoring
   channel). Do not put secrets in events meant for it.

## Explicit non-goals

- **Module hiding.** No DKOM, no `/proc/modules` manipulation. Hiding would
  change the threat model into malware-adjacent territory and is rejected.
- **Stealth IPC.** The genl family name and multicast group are public.
- **Forensic-grade guarantees.** For a compromised host, assume the
  attacker controls what you observe.

## Operational guidance

- Load the module before the workload you care about starts; there is no
  retroactive capture.
- Watch `dropped` in sysfs; if it grows, you are over-sampling and should
  filter (`-t`, `-p`) rather than expect more from the ring.
- Audit who can `insmod` and who can read the daemon output; both are the
  real decision points.
