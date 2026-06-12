# Changelog

## v0.4.0 — 2026-06-12

`activation` subcommand for `agentns-doctor`: evaluates the full continuity-activation chain
layer by layer (kernel-installed pkgrel skew, kernel-prctl probe in forked child,
launcher-installed + cap_sys_admin, launcher-wired without --no-unshare, live agent_session,
downstream provfs stamp) and reports the first blocking layer with an exact remedy.

Human table output by default; `--json` emits a stable JSON object validated against
`schemas/activation.schema.json`. Env overrides (`ACTIVATION_UNAME`, `ACTIVATION_PACMAN_BIN`,
`ACTIVATION_RC_FILE`, `ACTIVATION_HOME`) support unit testing without boot-gated kernel surfaces.

SessionStart hook at `~/.claude/scripts/agentns-activation-check.sh` prints a one-line remedy
banner on BLOCKED and is silent on LIVE; exits 0 always. Wired into `~/.claude/settings.json`
under `hooks.SessionStart`.

## v0.3.0 — 2026-05-29

`receipt` subcommand for `agentns-doctor`: snapshots the seven per-namespace kernel counters
(`total_syscalls`, `openat_count`, `write_bytes`, `connect_count`, `unlink_count`, `fork_count`,
`elapsed_ns`) into a JSON ledger at `~/.cache/agentns/receipts/<sid>.json`, keyed by
`agent_session_id` + `intent_tag`. Supports `--emit`, `--list`, `--show`, `--join-ctrace`,
and `--require-wrapped` (refuses to emit in the init namespace). Joinable with ctrace eBPF
session histograms and recall session stamps for per-session resource attribution.

## v0.2.0 — 2026-05-29

Add `receipt` subcommand that snapshots per-namespace counters (total_syscalls, openat_count, write_bytes, connect_count, unlink_count, fork_count, elapsed_ns) into a JSON ledger at ~/.cache/agentns/receipts/<sid>.json, keyed by agent_session_id. Supports --emit, --list, --show, --join-ctrace, and --require-wrapped for safe init-ns guard. Mirrors ctrace session layout for cross-substrate joins.
