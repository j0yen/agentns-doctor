//! Agent-namespace state classifier.
//!
//! Three observable states (plus one error state):
//!
//! | state      | condition                                      |
//! |------------|------------------------------------------------|
//! | `absent`   | `agent_session` file does not exist            |
//! | `init`     | file present, value is 32 ASCII `'0'` chars    |
//! | `live`     | file present, value is non-zero 32-hex chars   |
//! | `malformed`| file present but value doesn't match either    |

use crate::ProcReader;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The four mutually exclusive states a process's agent-namespace surface can be in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    /// Kernel has no `CLONE_NEWAGENT` support (stock kernel).
    Absent,
    /// Kernel present; process is in the init namespace (unwrapped — expected).
    Init,
    /// Kernel present; process is in a fresh agent namespace (wrapped).
    Live,
    /// File present but value is neither all-zero 32-hex nor valid non-zero 32-hex.
    Malformed,
}

impl fmt::Display for AgentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => write!(f, "absent"),
            Self::Init => write!(f, "init"),
            Self::Live => write!(f, "live"),
            Self::Malformed => write!(f, "malformed"),
        }
    }
}

/// A short stable enum string for machine consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Stock kernel — no CLONE_NEWAGENT.
    KernelAbsent,
    /// Kernel present, process not wrapped — expected and healthy.
    UnwrappedExpected,
    /// Process is in a live agent namespace.
    Wrapped,
    /// Surface exists but content is unexpected.
    MalformedSurface,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KernelAbsent => write!(f, "kernel-absent"),
            Self::UnwrappedExpected => write!(f, "unwrapped-expected"),
            Self::Wrapped => write!(f, "wrapped"),
            Self::MalformedSurface => write!(f, "malformed-surface"),
        }
    }
}

/// Full result of a status classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResult {
    /// Classified state.
    pub state: AgentState,
    /// Raw session id string (32 hex chars), or `"0"*32` for init, or the raw bad value for malformed.
    pub session_id: String,
    /// True when session_id is not all-zeros.
    pub session_nonzero: bool,
    /// Inode of `/proc/<pid>/ns/agent`, if available.
    pub ns_inode: Option<u64>,
    /// intent_tag field — currently always null (read side not yet in kernel surface).
    pub intent_tag: Option<String>,
    /// PID that was inspected.
    pub pid: u32,
    /// Short stable verdict string.
    pub verdict: Verdict,
}

const SESSION_HEX_LEN: usize = 32;
const ZERO_SESSION: &str = "00000000000000000000000000000000";

/// Check if a string is exactly 32 lowercase hex characters.
fn is_valid_hex32(s: &str) -> bool {
    s.len() == SESSION_HEX_LEN && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Classify the agent-namespace state for `pid`.
///
/// # Errors
/// Returns an error if proc files exist but cannot be read.
pub fn classify(reader: &ProcReader, pid: u32) -> Result<StatusResult, String> {
    let session_raw = reader
        .agent_session(pid)
        .map_err(|e| format!("cannot read agent_session for pid {pid}: {e}"))?;

    let ns_inode = reader
        .ns_agent_inode(pid)
        .map_err(|e| format!("cannot stat ns/agent for pid {pid}: {e}"))?;

    match session_raw {
        None => Ok(StatusResult {
            state: AgentState::Absent,
            session_id: String::new(),
            session_nonzero: false,
            ns_inode,
            intent_tag: None,
            pid,
            verdict: Verdict::KernelAbsent,
        }),
        Some(raw) => {
            if !is_valid_hex32(&raw) {
                return Ok(StatusResult {
                    state: AgentState::Malformed,
                    session_id: raw,
                    session_nonzero: false,
                    ns_inode,
                    intent_tag: None,
                    pid,
                    verdict: Verdict::MalformedSurface,
                });
            }

            let is_zero = raw == ZERO_SESSION;
            if is_zero {
                Ok(StatusResult {
                    state: AgentState::Init,
                    session_id: raw,
                    session_nonzero: false,
                    ns_inode,
                    intent_tag: None,
                    pid,
                    verdict: Verdict::UnwrappedExpected,
                })
            } else {
                Ok(StatusResult {
                    state: AgentState::Live,
                    session_id: raw,
                    session_nonzero: true,
                    ns_inode,
                    intent_tag: None,
                    pid,
                    verdict: Verdict::Wrapped,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_hex32_accepts_all_zeros() {
        assert!(is_valid_hex32("00000000000000000000000000000000"));
    }

    #[test]
    fn is_valid_hex32_accepts_valid_nonzero() {
        assert!(is_valid_hex32("deadbeefcafe0123456789abcdef0000"));
    }

    #[test]
    fn is_valid_hex32_rejects_short() {
        assert!(!is_valid_hex32("0000000000000000"));
    }

    #[test]
    fn is_valid_hex32_rejects_non_hex() {
        assert!(!is_valid_hex32("gggggggggggggggggggggggggggggggg"));
    }

    #[test]
    fn is_valid_hex32_rejects_wrong_length() {
        assert!(!is_valid_hex32("000000000000000000000000000000001"));
    }
}
