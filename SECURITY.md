# Security Policy

## Supported Versions

sentinel-km is a privileged kernel module: it hooks syscalls across the
whole system and, when the mmap ring is attached, exposes raw event
records via a device node. Treat every release as security-sensitive.

| Version | Supported |
|---|---|
| current `main` | yes |
| tagged releases (v*) | yes, for the lifecycle stated at release time |
| older than the latest two releases | best effort |

## Reporting a Vulnerability

Do **not** open a public issue for suspected security problems. Report
privately to the maintainers:

- Open a [private security advisory](https://github.com/anomalyco/sentinel-km/security/advisories/new)
- Or email the maintainers at the address listed in the latest release notes

Please include:

- the version and commit under test;
- kernel version and distribution (or reproducer config);
- a minimal reproducer when possible (module flags, daemon options,
  trigger workload);
- an assessment of impact and exploitability if you have one.

We aim to acknowledge within 48 hours and to triage within a week. Once a
fix is ready, we publish an advisory and a release, and credit reporters
who want it.

## Scope

Matters here because the module runs with kernel privileges:

- memory safety in the kprobe handlers (the module runs in atomic context
  and must never fault);
- the wire protocol: header/payload bounds, integer truncation across the
  v6 layout, malformed-input handling in the daemon parsers;
- the `filter`/`filter_pids`/`filter_uids` control plane (misconfiguration
  must not bypass the allowlists);
- the mmap ring export (`/dev/sentinel_ring`): record bounds, consumer
  races;
- the genl socket family: attribute parsing, privilege checks on the
  control commands.

Out of scope: the container-label resolver (best-effort, consumer-side
labeling that never affects captured data).
