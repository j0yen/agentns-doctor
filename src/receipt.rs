//! Session receipt: snapshot agent-namespace counters to a JSON ledger.
//!
//! Writes `~/.cache/agentns/receipts/<sid>.json` atomically, keyed by
//! `agent_session_id` + `intent_tag`.  Mirrors ctrace's
//! `~/.cache/ctrace/sessions/` layout so the join is a sibling-dir glob.
//!
//! Schema: `agentns-receipt/1`.

use crate::classify::{AgentState, classify};
use crate::counters::AgentCounters;
use crate::proc_reader::ProcReader;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// One persisted session receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReceipt {
    /// The 32-hex session id from `agent_session`.
    pub session_id: String,
    /// Intent tag for the session (e.g. `/build`), if present.
    pub intent_tag: Option<String>,
    /// PID that was inspected.
    pub pid: u32,
    /// Classified state at emit time.
    pub state: AgentState,
    /// The seven counter fields.
    pub counters: AgentCounters,
    /// RFC 3339 emission timestamp.
    pub emitted_at: String,
    /// Schema version string — must be `agentns-receipt/1`.
    pub schema: String,
}

/// Error type for receipt operations.
#[derive(Debug)]
pub enum ReceiptError {
    /// IO error reading or writing.
    Io(io::Error),
    /// JSON parse / serialization error.
    Json(serde_json::Error),
    /// Proc-read or classification error.
    Classify(String),
    /// Session is in init/absent namespace; `--require-wrapped` set.
    NotWrapped(String),
    /// Receipt not found for that session id.
    NotFound(String),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::Classify(s) => write!(f, "classification error: {s}"),
            Self::NotWrapped(s) => write!(f, "{s}"),
            Self::NotFound(s) => write!(f, "{s}"),
        }
    }
}

impl From<io::Error> for ReceiptError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for ReceiptError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Return the receipts directory: `~/.cache/agentns/receipts/`.
///
/// # Errors
/// Returns an error if `HOME` is not set or the dir cannot be created.
pub fn receipts_dir() -> Result<PathBuf, ReceiptError> {
    let home = std::env::var("HOME")
        .map_err(|_| ReceiptError::Io(io::Error::new(io::ErrorKind::NotFound, "HOME not set")))?;
    let dir = PathBuf::from(home)
        .join(".cache")
        .join("agentns")
        .join("receipts");
    // Mode 0700 — must_use result here.
    ensure_dir_0700(&dir)?;
    Ok(dir)
}

/// Create `dir` with mode `0700` if it doesn't exist.
///
/// # Errors
/// Returns an error if directory creation fails.
fn ensure_dir_0700(dir: &Path) -> Result<(), ReceiptError> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.exists() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    Ok(())
}

/// RFC 3339 timestamp from `SystemTime`.
fn rfc3339_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Manual ISO 8601 UTC: YYYY-MM-DDTHH:MM:SSZ
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400; // days since 1970-01-01
    // Gregorian date from days since epoch.
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
#[allow(clippy::as_conversions)]
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Shift to 1 Mar 0000 era to simplify leap-year math (Euclidean algorithm).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Parse `agent_counters` JSON string into `AgentCounters`.
///
/// # Errors
/// Returns a `ReceiptError::Classify` if the JSON is invalid or missing fields.
fn parse_counters(raw: &str) -> Result<AgentCounters, ReceiptError> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| ReceiptError::Classify(format!("invalid agent_counters JSON: {e}")))?;

    fn field(v: &serde_json::Value, key: &str) -> Result<u64, ReceiptError> {
        v.get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| ReceiptError::Classify(format!("agent_counters: missing field '{key}'")))
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

/// Emit a receipt for `pid`.
///
/// Returns `ReceiptError::NotWrapped` (exit 2) when `require_wrapped` is true
/// and the state is `init` or `absent`.
///
/// # Errors
/// Returns an error on IO, JSON, or classification failure.
pub fn emit_receipt(
    reader: &ProcReader,
    pid: u32,
    require_wrapped: bool,
    receipts_dir_override: Option<&Path>,
) -> Result<PathBuf, ReceiptError> {
    // Classify state.
    let status = classify(reader, pid).map_err(ReceiptError::Classify)?;

    // Guard: refuse init/absent when --require-wrapped.
    if require_wrapped {
        match status.state {
            AgentState::Init | AgentState::Absent => {
                return Err(ReceiptError::NotWrapped(
                    "not wrapped; init ns".to_owned(),
                ));
            }
            AgentState::Live | AgentState::Malformed => {}
        }
    }

    // Read counters.
    let counters = match reader
        .agent_counters(pid)
        .map_err(|e| ReceiptError::Classify(format!("cannot read agent_counters: {e}")))?
    {
        Some(raw) => parse_counters(&raw)?,
        None => AgentCounters::default(),
    };

    let session_id = if status.session_id.is_empty() {
        "00000000000000000000000000000000".to_owned()
    } else {
        status.session_id.clone()
    };

    let receipt = SessionReceipt {
        session_id: session_id.clone(),
        intent_tag: status.intent_tag,
        pid,
        state: status.state,
        counters,
        emitted_at: rfc3339_now(),
        schema: "agentns-receipt/1".to_owned(),
    };

    // Determine output directory.
    let dir = match receipts_dir_override {
        Some(p) => {
            ensure_dir_0700(p)?;
            p.to_path_buf()
        }
        None => receipts_dir()?,
    };

    let target = dir.join(format!("{session_id}.json"));
    write_receipt_atomic(&target, &receipt)?;

    Ok(target)
}

/// Write `receipt` to `path` atomically (temp + rename).
///
/// # Errors
/// Returns an error if the file cannot be written or renamed.
pub fn write_receipt_atomic(path: &Path, receipt: &SessionReceipt) -> Result<(), ReceiptError> {
    let json = serde_json::to_string_pretty(receipt)?;
    let parent = path
        .parent()
        .ok_or_else(|| ReceiptError::Io(io::Error::new(io::ErrorKind::InvalidInput, "no parent dir")))?;

    // Write to a temp file in the same directory, then rename (atomic on same-FS).
    let tmp_path = parent.join(format!(
        ".receipt-{}.tmp",
        std::process::id()
    ));
    fs::write(&tmp_path, json.as_bytes())?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// One row in the `--list` output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptRow {
    /// Full session id.
    pub session_id: String,
    /// Intent tag, if any.
    pub intent_tag: Option<String>,
    /// Total syscall count.
    pub total_syscalls: u64,
    /// Bytes written.
    pub write_bytes: u64,
    /// Emission timestamp.
    pub emitted_at: String,
}

/// List all receipts in `dir` (or `~/.cache/agentns/receipts/`), newest first.
///
/// # Errors
/// Returns an error on IO failure reading the directory.
pub fn list_receipts(receipts_dir_override: Option<&Path>) -> Result<Vec<ReceiptRow>, ReceiptError> {
    let dir = match receipts_dir_override {
        Some(p) => p.to_path_buf(),
        None => receipts_dir()?,
    };

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let mtime = entry.metadata()?.modified()?;
            entries.push((mtime, path));
        }
    }

    // Sort newest first.
    entries.sort_by(|a, b| b.0.cmp(&a.0));

    let mut rows = Vec::new();
    for (_, path) in entries {
        match load_receipt(&path) {
            Ok(r) => rows.push(ReceiptRow {
                session_id: r.session_id,
                intent_tag: r.intent_tag,
                total_syscalls: r.counters.total_syscalls,
                write_bytes: r.counters.write_bytes,
                emitted_at: r.emitted_at,
            }),
            Err(_) => {
                // Skip malformed receipt files.
            }
        }
    }
    Ok(rows)
}

/// Load a receipt from a file path.
///
/// # Errors
/// Returns an error on IO or JSON parse failure.
pub fn load_receipt(path: &Path) -> Result<SessionReceipt, ReceiptError> {
    let raw = fs::read_to_string(path)?;
    let r: SessionReceipt = serde_json::from_str(&raw)?;
    Ok(r)
}

/// Find a receipt by session id prefix in `~/.cache/agentns/receipts/`.
///
/// # Errors
/// Returns an error on IO failure or if no matching receipt is found.
pub fn find_receipt(sid_prefix: &str, receipts_dir_override: Option<&Path>) -> Result<SessionReceipt, ReceiptError> {
    let dir = match receipts_dir_override {
        Some(p) => p.to_path_buf(),
        None => receipts_dir()?,
    };

    if !dir.exists() {
        return Err(ReceiptError::NotFound(format!(
            "no receipt found for sid prefix '{sid_prefix}' (receipts dir absent)"
        )));
    }

    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            if stem.starts_with(sid_prefix) {
                return load_receipt(&path);
            }
        }
    }

    Err(ReceiptError::NotFound(format!(
        "no receipt found for sid prefix '{sid_prefix}'"
    )))
}

/// Result of `--join-ctrace`.
#[derive(Debug, Clone)]
pub struct JoinResult {
    /// The agentns receipt.
    pub receipt: SessionReceipt,
    /// Total syscalls from ctrace ndjson, if found.
    pub ctrace_total_syscalls: Option<u64>,
    /// Total write bytes from ctrace ndjson, if found.
    pub ctrace_write_bytes: Option<u64>,
    /// Whether a ctrace record was found.
    pub ctrace_found: bool,
    /// Divergence note if >10% difference.
    pub divergence_note: Option<String>,
}

/// Join a receipt with a ctrace sessions file.
///
/// Searches `~/.cache/ctrace/sessions/` for a file matching `<sid_prefix>`.
/// Counts `syscalls` and `write_bytes` from ndjson events.
///
/// # Errors
/// Returns an error if the receipt is not found.
pub fn join_ctrace(
    sid_prefix: &str,
    receipts_dir_override: Option<&Path>,
    ctrace_dir_override: Option<&Path>,
) -> Result<JoinResult, ReceiptError> {
    let receipt = find_receipt(sid_prefix, receipts_dir_override)?;

    let ctrace_dir = match ctrace_dir_override {
        Some(p) => p.to_path_buf(),
        None => {
            let home = std::env::var("HOME").map_err(|_| {
                ReceiptError::Io(io::Error::new(io::ErrorKind::NotFound, "HOME not set"))
            })?;
            PathBuf::from(home).join(".cache").join("ctrace").join("sessions")
        }
    };

    // Look for a ctrace file that contains the sid_prefix.
    let ctrace_path = if ctrace_dir.exists() {
        let mut found = None;
        for entry in fs::read_dir(&ctrace_dir)? {
            let entry = entry?;
            let fname = entry.file_name();
            let name = fname.to_string_lossy();
            if name.contains(sid_prefix) {
                found = Some(entry.path());
                break;
            }
        }
        found
    } else {
        None
    };

    match ctrace_path {
        None => Ok(JoinResult {
            receipt,
            ctrace_total_syscalls: None,
            ctrace_write_bytes: None,
            ctrace_found: false,
            divergence_note: None,
        }),
        Some(path) => {
            let (ct_syscalls, ct_writes) = parse_ctrace_ndjson(&path)?;
            let divergence_note = compute_divergence(
                receipt.counters.total_syscalls,
                ct_syscalls,
                receipt.counters.write_bytes,
                ct_writes,
            );
            Ok(JoinResult {
                receipt,
                ctrace_total_syscalls: Some(ct_syscalls),
                ctrace_write_bytes: Some(ct_writes),
                ctrace_found: true,
                divergence_note,
            })
        }
    }
}

/// Parse ctrace ndjson: sum `syscalls` and `write_bytes` fields across all events.
///
/// # Errors
/// Returns an error on IO failure.
fn parse_ctrace_ndjson(path: &Path) -> Result<(u64, u64), ReceiptError> {
    let raw = fs::read_to_string(path)?;
    let mut total_syscalls: u64 = 0;
    let mut total_write_bytes: u64 = 0;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(n) = v.get("syscalls").and_then(serde_json::Value::as_u64) {
                total_syscalls = total_syscalls.saturating_add(n);
            }
            if let Some(n) = v.get("write_bytes").and_then(serde_json::Value::as_u64) {
                total_write_bytes = total_write_bytes.saturating_add(n);
            }
        }
    }
    Ok((total_syscalls, total_write_bytes))
}

/// Compute divergence note for syscalls and writes; returns `None` if both within 10%.
#[allow(clippy::float_arithmetic)]
fn compute_divergence(
    agentns_syscalls: u64,
    ctrace_syscalls: u64,
    agentns_writes: u64,
    ctrace_writes: u64,
) -> Option<String> {
    let syscall_diverged = is_diverged(agentns_syscalls, ctrace_syscalls);
    let writes_diverged = is_diverged(agentns_writes, ctrace_writes);

    if !syscall_diverged && !writes_diverged {
        return None;
    }

    let mut parts = Vec::new();
    if syscall_diverged {
        parts.push(format!(
            "syscalls: agentns={agentns_syscalls} ctrace={ctrace_syscalls}"
        ));
    }
    if writes_diverged {
        parts.push(format!(
            "write_bytes: agentns={agentns_writes} ctrace={ctrace_writes}"
        ));
    }
    Some(format!("divergence >10%: {}", parts.join(", ")))
}

/// Return true if two u64 counts differ by >10%.
#[allow(clippy::float_arithmetic)]
fn is_diverged(a: u64, b: u64) -> bool {
    if a == 0 && b == 0 {
        return false;
    }
    let max = a.max(b) as f64;
    let diff = a.abs_diff(b) as f64;
    diff / max > 0.10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_now_looks_like_iso8601() {
        let s = rfc3339_now();
        // Basic structural check: "YYYY-MM-DDTHH:MM:SSZ"
        assert_eq!(s.len(), 20, "expected 20-char timestamp, got '{s}'");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[19..20], "Z");
    }

    #[test]
    fn days_to_ymd_unix_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2026-05-29: days since epoch = 20_602
        let (y, m, d) = days_to_ymd(20_602);
        assert_eq!((y, m, d), (2026, 5, 29));
    }

    #[test]
    fn is_diverged_within_10_percent() {
        assert!(!is_diverged(100, 109), "9% diff should not diverge");
        assert!(!is_diverged(100, 91), "9% diff should not diverge");
    }

    #[test]
    fn is_diverged_beyond_10_percent() {
        assert!(is_diverged(100, 115), "15% diff should diverge");
        assert!(is_diverged(200, 100), "50% diff should diverge");
    }

    #[test]
    fn is_diverged_both_zero() {
        assert!(!is_diverged(0, 0));
    }

    #[test]
    fn compute_divergence_agreement() {
        assert!(compute_divergence(100, 105, 200, 210).is_none());
    }

    #[test]
    fn compute_divergence_syscall_drift() {
        let note = compute_divergence(100, 200, 100, 105);
        let note = note.expect("should have divergence note");
        assert!(note.contains("syscalls"), "note: {note}");
        assert!(!note.contains("write_bytes"), "note: {note}");
    }

    #[test]
    fn atomic_write_no_tmp_survives_on_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.json");
        let receipt = SessionReceipt {
            session_id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_owned(),
            intent_tag: Some("/build".to_owned()),
            pid: 1234,
            state: AgentState::Live,
            counters: AgentCounters::default(),
            emitted_at: "2026-05-29T00:00:00Z".to_owned(),
            schema: "agentns-receipt/1".to_owned(),
        };
        write_receipt_atomic(&path, &receipt).expect("write");

        // No .tmp file should survive.
        let tmp_files: Vec<_> = std::fs::read_dir(dir.path())
            .expect("readdir")
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .collect();
        assert!(tmp_files.is_empty(), "unexpected .tmp files: {tmp_files:?}");

        // The target must be valid JSON.
        let raw = std::fs::read_to_string(&path).expect("read");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("json parse");
        assert_eq!(v["schema"].as_str(), Some("agentns-receipt/1"));
    }

    #[test]
    fn round_trip_through_serde() {
        let receipt = SessionReceipt {
            session_id: "deadbeefcafe0123456789abcdef0000".to_owned(),
            intent_tag: None,
            pid: 99,
            state: AgentState::Init,
            counters: AgentCounters {
                total_syscalls: 42,
                openat_count: 7,
                write_bytes: 1024,
                connect_count: 3,
                unlink_count: 1,
                fork_count: 2,
                elapsed_ns: 5_000_000,
            },
            emitted_at: "2026-05-29T12:34:56Z".to_owned(),
            schema: "agentns-receipt/1".to_owned(),
        };
        let json = serde_json::to_string_pretty(&receipt).expect("serialize");
        let decoded: SessionReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.session_id, receipt.session_id);
        assert_eq!(decoded.counters.total_syscalls, 42);
        assert_eq!(decoded.schema, "agentns-receipt/1");
    }

    #[test]
    fn list_receipts_newest_first() {
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("tempdir");

        // Write three receipts with distinct emitted_at.  Use mtime manipulation
        // via file names to simulate ordering (list_receipts sorts by mtime).
        let sids = [
            ("aaaa0000000000000000000000000000", "2026-05-29T10:00:00Z"),
            ("bbbb0000000000000000000000000000", "2026-05-29T11:00:00Z"),
            ("cccc0000000000000000000000000000", "2026-05-29T12:00:00Z"),
        ];

        for (i, (sid, ts)) in sids.iter().enumerate() {
            let receipt = SessionReceipt {
                session_id: sid.to_string(),
                intent_tag: None,
                pid: 1,
                state: AgentState::Init,
                counters: AgentCounters::default(),
                emitted_at: ts.to_string(),
                schema: "agentns-receipt/1".to_owned(),
            };
            let path = dir.path().join(format!("{sid}.json"));
            write_receipt_atomic(&path, &receipt).expect("write");
            // Set mtime explicitly via std::fs::File so ordering is deterministic.
            let mtime = std::time::SystemTime::UNIX_EPOCH
                + Duration::from_secs(1_748_000_000 + (i as u64) * 3600);
            filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(mtime)).ok();
        }

        let rows = list_receipts(Some(dir.path())).expect("list");
        assert_eq!(rows.len(), 3);
        // Newest first: cccc > bbbb > aaaa.
        assert!(
            rows[0].session_id.starts_with("cccc"),
            "expected cccc first, got {}",
            rows[0].session_id
        );
        assert!(
            rows[2].session_id.starts_with("aaaa"),
            "expected aaaa last, got {}",
            rows[2].session_id
        );
    }
}
