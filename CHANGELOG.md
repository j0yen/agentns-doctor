# Changelog

## v0.3.0 — 2026-05-29

`receipt` subcommand for `agentns-doctor`: snapshots the seven per-namespace kernel counters
(`total_syscalls`, `openat_count`, `write_bytes`, `connect_count`, `unlink_count`, `fork_count`,
`elapsed_ns`) into a JSON ledger at `~/.cache/agentns/receipts/<sid>.json`, keyed by
`agent_session_id` + `intent_tag`. Supports `--emit`, `--list`, `--show`, `--join-ctrace`,
and `--require-wrapped` (refuses to emit in the init namespace). Joinable with ctrace eBPF
session histograms and recall session stamps for per-session resource attribution.

## v0.2.0 — 2026-05-29

Add `receipt` subcommand that snapshots per-namespace counters (total_syscalls, openat_count, write_bytes, connect_count, unlink_count, fork_count, elapsed_ns) into a JSON ledger at ~/.cache/agentns/receipts/<sid>.json, keyed by agent_session_id. Supports --emit, --list, --show, --join-ctrace, and --require-wrapped for safe init-ns guard. Mirrors ctrace session layout for cross-substrate joins.
