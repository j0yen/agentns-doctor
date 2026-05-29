//! Agent-namespace syscall counter reader.
//!
//! Reads `/proc/<pid>/agent_counters` and optionally samples twice to
//! produce per-counter deltas.

use crate::ProcReader;
use serde::{Deserialize, Serialize};
use std::thread;
use std::time::Duration;

/// The seven counter fields the kernel maintains per agent namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentCounters {
    /// Total syscall count.
    pub total_syscalls: u64,
    /// `openat(2)` call count.
    pub openat_count: u64,
    /// Bytes written via `write(2)`.
    pub write_bytes: u64,
    /// `connect(2)` call count.
    pub connect_count: u64,
    /// `unlink(2)` call count.
    pub unlink_count: u64,
    /// `fork(2)`/`clone(2)` call count.
    pub fork_count: u64,
    /// Elapsed namespace time in nanoseconds.
    pub elapsed_ns: u64,
}

impl AgentCounters {
    /// Compute per-field delta between two samples (`other - self`).
    #[must_use]
    pub fn delta(&self, other: &Self) -> Self {
        Self {
            total_syscalls: other.total_syscalls.saturating_sub(self.total_syscalls),
            openat_count: other.openat_count.saturating_sub(self.openat_count),
            write_bytes: other.write_bytes.saturating_sub(self.write_bytes),
            connect_count: other.connect_count.saturating_sub(self.connect_count),
            unlink_count: other.unlink_count.saturating_sub(self.unlink_count),
            fork_count: other.fork_count.saturating_sub(self.fork_count),
            elapsed_ns: other.elapsed_ns.saturating_sub(self.elapsed_ns),
        }
    }
}

/// Result returned by `read_counters`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountersResult {
    /// PID that was inspected.
    pub pid: u32,
    /// First (or only) sample.
    pub sample: AgentCounters,
    /// Delta between two samples, present only when `--delta` was given.
    pub delta: Option<AgentCounters>,
    /// Duration between samples in milliseconds (when `--delta` was given).
    pub delta_ms: Option<u64>,
    /// Human note about the current state.
    pub note: Option<String>,
}

/// Parse the kernel JSON format into `AgentCounters`.
///
/// The kernel emits:
/// ```json
/// { "total_syscalls": 0, "openat_count": 0, "write_bytes": 0,
///   "connect_count": 0, "unlink_count": 0, "fork_count": 0, "elapsed_ns": 0 }
/// ```
///
/// # Errors
/// Returns an error if the string is not valid JSON or is missing fields.
fn parse_counters(s: &str) -> Result<AgentCounters, String> {
    let v: serde_json::Value =
        serde_json::from_str(s).map_err(|e| format!("invalid agent_counters JSON: {e}"))?;

    fn field(v: &serde_json::Value, key: &str) -> Result<u64, String> {
        v.get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("agent_counters: missing or non-integer field '{key}'"))
    }

    Ok(AgentCounters {
        total_syscalls: field(&v, "total_syscalls")?,
        openat_count: field(&v, "openat_count")?,
        write_bytes: field(&v, "write_bytes")?,
        connect_count: field(&v, "connect_count")?,
        unlink_count: field(&v, "unlink_count")?,
        fork_count: field(&v, "fork_count")?,
        elapsed_ns: field(&v, "elapsed_ns")?,
    })
}

/// Read counters for `pid`.  When `delta_ms` is `Some`, sample twice.
///
/// # Errors
/// Returns an error if the counters file exists but cannot be read or parsed.
pub fn read_counters(
    reader: &ProcReader,
    pid: u32,
    delta_ms: Option<u64>,
) -> Result<CountersResult, String> {
    let raw = reader
        .agent_counters(pid)
        .map_err(|e| format!("cannot read agent_counters for pid {pid}: {e}"))?;

    let note_init = "counters are per-namespace; init ns counters are always zero".to_owned();

    match raw {
        None => {
            // No counters surface — return zeroed struct with a note.
            Ok(CountersResult {
                pid,
                sample: AgentCounters::default(),
                delta: None,
                delta_ms: None,
                note: Some("agent_counters not present (kernel absent or pre-kernel)".to_owned()),
            })
        }
        Some(first_raw) => {
            let first = parse_counters(&first_raw)?;
            let all_zero = first == AgentCounters::default();
            let note = if all_zero {
                Some(note_init.clone())
            } else {
                None
            };

            match delta_ms {
                None => Ok(CountersResult {
                    pid,
                    sample: first,
                    delta: None,
                    delta_ms: None,
                    note,
                }),
                Some(ms) => {
                    thread::sleep(Duration::from_millis(ms));

                    let second_raw = reader
                        .agent_counters(pid)
                        .map_err(|e| format!("cannot read agent_counters for pid {pid} (second sample): {e}"))?
                        .ok_or_else(|| {
                            format!("agent_counters disappeared between samples for pid {pid}")
                        })?;

                    let second = parse_counters(&second_raw)?;
                    let delta = first.delta(&second);
                    let delta_all_zero = delta == AgentCounters::default();

                    Ok(CountersResult {
                        pid,
                        sample: first,
                        delta: Some(delta),
                        delta_ms: Some(ms),
                        note: if delta_all_zero && all_zero {
                            Some(note_init)
                        } else {
                            None
                        },
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_counters_all_zero() {
        let json = r#"{ "total_syscalls": 0, "openat_count": 0, "write_bytes": 0,
          "connect_count": 0, "unlink_count": 0, "fork_count": 0, "elapsed_ns": 0 }"#;
        let c = parse_counters(json).expect("parse failed");
        assert_eq!(c.total_syscalls, 0);
        assert_eq!(c.elapsed_ns, 0);
    }

    #[test]
    fn parse_counters_nonzero() {
        let json = r#"{ "total_syscalls": 42, "openat_count": 7, "write_bytes": 1024,
          "connect_count": 3, "unlink_count": 1, "fork_count": 2, "elapsed_ns": 5000000 }"#;
        let c = parse_counters(json).expect("parse failed");
        assert_eq!(c.total_syscalls, 42);
        assert_eq!(c.write_bytes, 1024);
    }

    #[test]
    fn parse_counters_missing_field_errors() {
        let json = r#"{ "total_syscalls": 0 }"#;
        assert!(parse_counters(json).is_err());
    }

    #[test]
    fn delta_is_saturating() {
        let a = AgentCounters {
            total_syscalls: 10,
            ..AgentCounters::default()
        };
        let b = AgentCounters {
            total_syscalls: 8,
            ..AgentCounters::default()
        };
        // b < a in total_syscalls — saturating_sub gives 0
        let d = a.delta(&b);
        assert_eq!(d.total_syscalls, 0);
    }
}
