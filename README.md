# agentns-doctor

Read-only CLI that classifies a process's agent-namespace state from `/proc` surfaces.

The wintermute kernel exposes `/proc/$PID/agent_session`, `/proc/$PID/agent_counters`,
and `/proc/$PID/ns/agent`. Three distinct system states produce three distinct readings,
and nothing on this laptop used to tell them apart:

| state | meaning |
|-------|---------|
| `absent` | stock kernel — no `CLONE_NEWAGENT` |
| `init` | kernel present, process unwrapped — **expected and healthy** |
| `live` | process in a fresh agent namespace (wrapped via `agentns-claude`) |
| `malformed` | genuine anomaly worth surfacing |

`agentns-doctor` ends the mis-diagnosis of healthy init-ns all-zeros as "broken kernel."

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

## Usage

```sh
# Classify current process's agent-namespace state
agentns-doctor status

# Machine-readable JSON output
agentns-doctor status --format json

# Inspect another PID
agentns-doctor status --pid 1234

# Print a human explanation of the current state
agentns-doctor explain

# Read syscall counters
agentns-doctor counters

# Sample counters twice 100ms apart and show deltas
agentns-doctor counters --delta 100

# Use fixture directory for testing (--proc-root)
agentns-doctor status --proc-root /tmp/my-fixture-proc
```

## Exit codes

| code | meaning |
|------|---------|
| 0 | healthy (`absent`, `init`, or `live`) |
| 2 | kernel surface absent and `--expect-kernel` was passed |
| 3 | malformed surface |

## Recent

- **v0.2.0** — `receipt` subcommand: snapshot per-namespace counters to `~/.cache/agentns/receipts/<sid>.json`; supports `--emit`, `--list`, `--show`, `--join-ctrace`, `--require-wrapped`.

## License

MIT OR Apache-2.0
