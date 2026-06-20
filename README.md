# agentns-doctor

A read-only CLI that reads a process's `/proc` surfaces and tells you which of four agent-namespace states it's in — and, with `activation`, exactly which layer of the setup chain is broken.

## Why it exists

The wintermute kernel exposes `/proc/$PID/agent_session`, `/proc/$PID/agent_counters`, and `/proc/$PID/ns/agent`. The trouble is that two healthy states and one broken one can read almost identically — an unwrapped process in the init namespace shows all-zeros, and so does a stock kernel that never had the feature. Read the surfaces by hand and it's easy to call a healthy init-ns "broken kernel." That misdiagnosis is the thing this tool removes.

It classifies into four states:

| state | meaning |
|-------|---------|
| `absent` | stock kernel — no `CLONE_NEWAGENT` |
| `init` | kernel present, process unwrapped — expected and healthy |
| `live` | process in a fresh agent namespace (wrapped via `agentns-claude`) |
| `malformed` | a genuine anomaly worth surfacing |

## Install

```sh
cargo install --git https://github.com/j0yen/agentns-doctor
```

Or clone and build:

```sh
git clone https://github.com/j0yen/agentns-doctor
cd agentns-doctor
cargo build --release
# binary at target/release/agentns-doctor
```

## Quickstart

```sh
# Classify the current process
agentns-doctor status

# Machine-readable
agentns-doctor status --format json

# A human-readable explanation of the current state
agentns-doctor explain
```

Other subcommands:

```sh
# Inspect another PID
agentns-doctor status --pid 1234

# Read the per-namespace syscall counters
agentns-doctor counters

# Sample counters twice 100ms apart and show deltas
agentns-doctor counters --delta 100

# Classify against a fixture /proc tree (used by the tests)
agentns-doctor status --proc-root /tmp/my-fixture-proc
```

## The activation chain

`agentns-doctor activation` answers a different question from `status`. `status` reads one process; `activation` walks the whole setup chain — kernel, launcher, session, downstream stamp — and stops at the first layer that's broken, with the remedy for that layer.

```sh
agentns-doctor activation        # human table
agentns-doctor activation --json # for scripts and the SessionStart hook
```

Six layers, evaluated in order, short-circuiting to the first blocker:

| Layer | What it checks |
|-------|----------------|
| `kernel-installed` | Installed pkgrel (pacman) vs running pkgrel (uname -r). Skew → `RebootPending`. |
| `kernel-prctl` | `prctl(PR_SET_AGENT_NS)` probed in a **forked child**, so the parent namespace is untouched. EINVAL/ENOSYS → `KernelLacksPrctl`. |
| `launcher-installed` | `~/.local/bin/agentns-claude` exists, is executable, has `cap_sys_admin=ep`. |
| `launcher-wired` | the `claude()` shell function carries no `--no-unshare` flag. |
| `live-session` | `/proc/self/agent_session` is a non-zero 32-hex id. |
| `downstream-stamp` | `getfattr -n user.prov.session` on a probe file returns a real agentns id, not the fallback. |

Human output names the blocker and the fix:

```
LAYER                 STATE       DETAIL
----------------------------------------------------------------------
kernel-installed      BLOCKED     running pkgrel 5 < installed 12
ACTIVATION: BLOCKED at kernel-installed — reboot into linux-wintermute (the fix kernel is on /boot already)
```

The `--json` schema is at `schemas/activation.schema.json`.

### SessionStart hook

`~/.claude/scripts/agentns-activation-check.sh` runs `activation --json` at session start: a one-line amber banner when BLOCKED, silent when LIVE, exit 0 always. Wire it in `~/.claude/settings.json`:

```json
{ "type": "command", "command": "/home/you/.claude/scripts/agentns-activation-check.sh" }
```

### Test overrides

The activation layers read real system surfaces, so the tests override them through env vars rather than booting a kernel:

| Env var | Override |
|---------|---------|
| `ACTIVATION_UNAME` | output of `uname -r` |
| `ACTIVATION_PACMAN_BIN` | path to a fake pacman script |
| `ACTIVATION_RC_FILE` | path to a fixture `.zshrc` |
| `ACTIVATION_HOME` | alternate HOME for the launcher path |

## Receipts

`agentns-doctor receipt` snapshots the seven per-namespace counters — `total_syscalls`, `openat_count`, `write_bytes`, `connect_count`, `unlink_count`, `fork_count`, `elapsed_ns` — into a JSON ledger at `~/.cache/agentns/receipts/<sid>.json`, keyed by the `agent_session_id`. The layout mirrors ctrace's session histograms, so receipts join across substrates for per-session resource attribution.

```sh
agentns-doctor receipt --emit                   # snapshot counters for this session
agentns-doctor receipt --emit --require-wrapped # refuse to emit in the init namespace
agentns-doctor receipt --list                   # newest first
agentns-doctor receipt --show <sid>             # one receipt by session-id prefix
agentns-doctor receipt --join-ctrace <sid>      # join with the ctrace histogram
```

## Exit codes

| code | meaning |
|------|---------|
| 0 | healthy (`absent`, `init`, or `live`) |
| 2 | kernel surface absent and `--expect-kernel` was passed |
| 3 | malformed surface |

## Where it fits

Part of the wintermute substrate: the kernel provides the agent namespace, `agentns-claude` wraps a session into one, ctrace records the eBPF session histograms, and `agentns-doctor` is the diagnostic that reads it all back. It's deliberately read-only — it classifies and reports, it never changes a process's state.

## License

MIT OR Apache-2.0
