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

# Evaluate the full activation chain (kernel → launcher → session → stamp)
agentns-doctor activation

# JSON output for scripts and the SessionStart hook
agentns-doctor activation --json
```

## Activation chain

`agentns-doctor activation` evaluates six layers in order, short-circuiting to the first blocker:

| Layer | What it checks |
|-------|----------------|
| `kernel-installed` | Installed pkgrel (pacman) vs running pkgrel (uname -r). Skew → `RebootPending`. |
| `kernel-prctl` | `prctl(PR_SET_AGENT_NS)` probe in a **forked child** (parent namespace unchanged). EINVAL/ENOSYS → `KernelLacksPrctl`. |
| `launcher-installed` | `~/.local/bin/agentns-claude` exists, is executable, has `cap_sys_admin=ep`. |
| `launcher-wired` | `claude()` shell function contains no `--no-unshare` flag. |
| `live-session` | `/proc/self/agent_session` is a non-zero 32-hex id. |
| `downstream-stamp` | `getfattr -n user.prov.session` on a probe file returns a real agentns id vs fallback. |

Output (human):
```
LAYER                 STATE       DETAIL
----------------------------------------------------------------------
kernel-installed      BLOCKED     running pkgrel 5 < installed 12
ACTIVATION: BLOCKED at kernel-installed — reboot into linux-wintermute (the fix kernel is on /boot already)
```

`--json` schema is at `schemas/activation.schema.json`.

### SessionStart hook

`~/.claude/scripts/agentns-activation-check.sh` runs `activation --json` at session start and
prints a one-line amber banner when BLOCKED, silent when LIVE. Wire it in `~/.claude/settings.json`:

```json
{ "type": "command", "command": "/home/you/.claude/scripts/agentns-activation-check.sh" }
```

### Test overrides

| Env var | Override |
|---------|---------|
| `ACTIVATION_UNAME` | Output of `uname -r` |
| `ACTIVATION_PACMAN_BIN` | Path to a fake pacman script |
| `ACTIVATION_RC_FILE` | Path to a fixture `.zshrc` |
| `ACTIVATION_HOME` | Alternate HOME for launcher path |

## Exit codes

| code | meaning |
|------|---------|
| 0 | healthy (`absent`, `init`, or `live`) |
| 2 | kernel surface absent and `--expect-kernel` was passed |
| 3 | malformed surface |

## Recent

- **v0.4.0** — `activation` subcommand: full continuity-chain evaluator with per-layer remediation, JSON schema, and SessionStart hook.
- **v0.3.0** — `receipt` subcommand: snapshot per-namespace counters to `~/.cache/agentns/receipts/<sid>.json`; supports `--emit`, `--list`, `--show`, `--join-ctrace`, `--require-wrapped`.

## License

MIT OR Apache-2.0
