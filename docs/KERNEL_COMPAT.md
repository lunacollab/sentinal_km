# Kernel Compatibility

The module targets mainline-compatible Ubuntu LTS kernels. It builds
out-of-tree; the build is only as good as the headers you compile against,
so CI builds against a matrix, never just the host kernel.

## What must hold for a build to succeed

| Kernel range | Notes |
|---|---|
| 5.4 – 5.10 (Ubuntu 20.04 HWE) | `kallsyms_lookup_name` still exported on some ≤5.6 builds; we never rely on it. `strncpy_from_user_nofault()` exists and is exported on these. |
| 5.15 (Ubuntu 22.04) | Baseline dev target. `strncpy_from_user_nofault()` exported. |
| 6.8 (Ubuntu 24.04 LTS) | CI build target. genl family uses `genl_split_ops` (>= 6.4 path). |
| 6.12+ / 7.x (Ubuntu 26.04) | `strncpy_from_user_nofault()` becomes *unexported* on newer 6.x/7.x builds → the `hook_copy.c` kallsyms fallback engages; resolved from the running kernel headers tree. |

## Version-sensitive pieces and their safeguards

1. **`kallsyms_lookup_name`** — unexported since 5.7. `sentinel_symresolve.c`
   registers a throwaway kprobe on the symbol name and reads `kp.addr`,
   then unregisters. Used only for `strncpy_from_user_nofault` today.

2. **Syscall wrapper symbols** — `__x64_sys_*` (x86_64) and `__arm64_sys_*`
   (aarch64). The `SENTINEL_SC_WRAPPER()` macro in `hook_common.h` selects the
   per-arch prefix (`#ifdef CONFIG_ARM64`) so every kprobe table names the
   right symbol; on aarch64 the tree probes `__arm64_sys_map` etc. Correct
   names must still be verified per target; `register_kretprobe()` fails
   cleanly (returns `-EINVAL`/`-ENOENT`) if the name does not exist, and
   module init aborts rather than half-loading. Syscall arguments are read
   through `hook_reg_arg()`: x86_64 uses the `di`/`si`/`dx`/`r10`/`r8`/`r9`
   slots (System V: `rcx` is clobbered by entry, so the mmap 4th arg lives in
   `r10`), aarch64 maps straight to `pt_regs->regs[0..5]`. The `SENTINEL_SC_*`
   gate bits name the *arch unistd numbers* (`SENTINEL_SC_MMAP` is 9 on
   x86_64, 222 on aarch64); the enum is re-keyed in `hook_common.h`.

3. **genl API** — the family block uses the long-lived
   `struct genl_family` with `.ops/.n_ops/.mcgrps`. Since 6.4 the kernel
   prefers `family_ops` + `policy_{do,dump}`; the classic form still builds
   but emits a deprecation warning on the newest trees. v3 now ships
   `genl_split_ops` support: on kernels >= 6.4 the family registers via
   `family_ops` with split do/dump policies; on < 6.4 the legacy
   `genl_ops` form is used. The build selects the path at compile time
   via `LINUX_VERSION_CODE`.

4. **`__packed`** — the wire structs use `__packed`, so no
   layout differences across ABI revisions or compilers.

5. **`__ex_table` / fixup asm cannot ship out-of-tree** — a hand-written
   `strnlen` with `.fixup` entries fails to build as a module on
   `CONFIG_STACK_VALIDATION` toolchains: gas-15 resolves cross-section
   symbol differences (`__ex_table` referencing `.fixup`) at compile time
   and errors ("can't resolve .fixup - .Linsn"), and forcing the fixup into
   `.text` makes objtool reject the folded relocation. `sentinel_strnlen_user_max`
   is therefore implemented in C: it copies page-by-page with
   `copy_from_user_nofault`, never spanning a page boundary, so fault
   handling is uniform and needs no custom `extable` entries at all.

6. **kernel 6.x `vm_flags`** — read-only since 6.3; `remap_pfn_range` +
   `vm_flags_set()` are used on the mmap ring's `mmap()` handler, guarded by
   `LINUX_VERSION_CODE` (the 5.x branch keeps the direct `vm_flags |=`).

8. **sysctl `proc_handler` constification (6.11)** — 6.11 changed every
   `proc_handler` (and `proc_dointvec`/`proc_dostring`) to take
   `const struct ctl_table *`; older kernels keep the mutable `struct
   ctl_table *`. The `kernel/sentinel` handlers use a `typedef
   sentinel_ctl_table` selected by `LINUX_VERSION_CODE >= 6.11` so the
   function signature always matches the headers being built against
   (`-Werror=incompatible-pointer-types` on 6.8 otherwise).

9. **`list_del_rcu` include** — `sentinel_registry.c` needs
   `linux/rculist.h` explicitly; newer kernels pull it in via `list.h`,
   5.15 does not.

7. **asm hot-path objects carry no `__ex_table`** — both
   `sentinel_memchr_zero.S` and `sentinel_capture_store.S` touch only kernel
   memory and never fault, so they need no exception table, which is exactly
   the class of cross-section fixup that cannot build out-of-tree (see item
   5). `sentinel_capture_store` uses the fast-string `rep movsb`/`rep stosb`
   pair, which the CPU drives and which needs no alignment bookkeeping, so
   there is no `.balign`, no `movdqa`-style alignment requirement, and no
   toolchain version coupling. The `n_filled` bound is validated by the C
   caller (`SENTINEL_CAPTURE_HDR_SIZE + payload_len <=
   SENTINEL_CAPTURE_BYTES`), and the store constant is pinned on both sides
   by `static_assert` + the differential selftest so a drift aborts the
   load instead of silently corrupting a ring slot. On non-x86_64 the C
   reference (`sentinel_capture_store_c`) is selected by Kbuild and the same
   guarantee is upheld.

## Testing philosophy

- `make KDIR=...` against *each* headers set, not just the running kernel.
  CI runs at least 3 (`5.15`, a `6.x`, and a current mainline-ish) per
  `tests/qemu/kernel-matrix.txt`.
- `checkpatch.pl --no-tree -f` must be 0 errors (two `kzalloc_obj`
  suggestions are tolerated for old-kernel compat).
- Runtime hooks emit from the same instruction stream regardless of kernel,
  but a header-level API rename (e.g. a `_nofault` shuffle) only shows up
  as a link error — hence the resolver fallback rather than a hard
  dependency.

## Known windows to re-verify per kernel

- Any kernel where `strncpy_from_user_nofault` moves between
  `EXPORT_SYMBOL` and `EXPORT_SYMBOL_GPL` (or drops export) — the fallback
  silently changes which function is used. `dmesg` logs which path engaged
  at init.
- New syscall wrapper renames beyond the `__x64_`/`__arm64_` patterns (riscv,
  etc.) — currently the hooks build only on x86_64 and aarch64. The
  `SENTINEL_SC_*` gate bits name the *arch unistd numbers*, so moving to
  another arch re-keys the sysfs mask.
- Architecture gating (P1.3): the full hook set builds on x86_64 and arm64;
  the three asm accelerators (`memchr_zero`, `capture_store`, `crc32c`) stay
  x86_64-only and the C fallbacks (in `hook_copy.c`, `sentinel_capture.c`,
  `sentinel_crc.c`) are the production path on aarch64. A compile-only
  aarch64 lane is `scripts/build-arm64.sh`; symbol resolution against a
  *built* arm64 kernel (full in-tree `modules`) is left to CI.
- Any kernel where a `_nofault` string API returns differently on a
  partially-faulted tail page — the page-chunked `sentinel_strnlen_user_max`
  contracts around "never cross a page boundary in one call", which keeps
  the answer consistent across such churn.

**Current status:** CI builds + `checkpatch` (0 errors; remaining warnings
  are accepted version-gating/barrier style friction) against a three-way
  matrix — Ubuntu 22.04 (5.15), Ubuntu 24.04 (6.8), and current mainline
  headers (7.0.0-31) — plus a dedicated `security-scan` workflow (gitleaks,
  semgrep, sparse, cppcheck, shellcheck, codespell). Local development is on
  the WSL 7.0.0-31 headers; daemon build + parser unit tests pass on the same
  WSL instance.
