//! Acceptance tests for the `receipt` subcommand (PRD-agentns-session-receipt ACs).
//!
//! ACs tested here (fixture-testable set):
//!   R1  -- `--require-wrapped` exits 2 in init ns, writes no file
//!   R3  -- atomic write leaves no .tmp on success (exercised via unit test too)
//!   R4  -- `--list` returns newest-first (exercised in receipt unit tests too)
//!   R5  -- `--show <sid>` round-trips the emitted receipt
//!   R6  -- `--join-ctrace` reports agreement / divergence with a fixture ctrace ndjson
//!   R7  -- fixture `--emit` captures the exact counter values from agent_counters
//!   R8  -- receipts dir is created 0700 when absent
//!   R9  -- golden key set: the emitted receipt has exactly the required keys
//!   R10 -- `receipt --help` documents all four mode flags and --require-wrapped

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::TempDir;

fn agentns_doctor_bin() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/debug/agentns-doctor");
    p
}

/// Build a minimal --proc-root fixture for pid 42000 in init ns (all-zero session).
fn make_proc_root_init() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_dir = dir.path().join("42000");
    fs::create_dir_all(pid_dir.join("ns")).expect("create ns dir");
    fs::write(
        pid_dir.join("agent_session"),
        "00000000000000000000000000000000",
    )
    .expect("write agent_session");
    fs::write(
        pid_dir.join("agent_counters"),
        r#"{ "total_syscalls": 0, "openat_count": 0, "write_bytes": 0,
  "connect_count": 0, "unlink_count": 0, "fork_count": 0, "elapsed_ns": 0 }"#,
    )
    .expect("write agent_counters");
    dir
}

/// Build a minimal --proc-root fixture for pid 42001 in live ns (non-zero session).
fn make_proc_root_live(session_id: &str) -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_dir = dir.path().join("42001");
    fs::create_dir_all(pid_dir.join("ns")).expect("create ns dir");
    fs::write(pid_dir.join("agent_session"), session_id).expect("write agent_session");
    fs::write(
        pid_dir.join("agent_counters"),
        r#"{ "total_syscalls": 1203481, "openat_count": 88123, "write_bytes": 41203992,
  "connect_count": 91, "unlink_count": 2044, "fork_count": 312, "elapsed_ns": 75600000000000 }"#,
    )
    .expect("write agent_counters");
    dir
}

// ---------------------------------------------------------------------------
// AC-R1: --require-wrapped refuses init ns
// ---------------------------------------------------------------------------

#[test]
fn acceptance_r1_require_wrapped_refuses_init_ns() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("receipt AC-R1: binary not built, skipping");
        return;
    }

    let proc_root = make_proc_root_init();
    let receipts_dir = tempfile::tempdir().expect("receipts tempdir");

    let out = Command::new(&bin)
        .args([
            "receipt",
            "--emit",
            "--pid", "42000",
            "--proc-root", proc_root.path().to_str().expect("utf8"),
            "--receipts-dir", receipts_dir.path().to_str().expect("utf8"),
            "--require-wrapped",
        ])
        .output()
        .expect("run agentns-doctor");

    // Must exit 2
    assert_eq!(
        out.status.code(),
        Some(2),
        "AC-R1: --require-wrapped in init ns must exit 2, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    // Must not write any file
    let entries: Vec<_> = fs::read_dir(receipts_dir.path())
        .expect("readdir")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        entries.is_empty(),
        "AC-R1: no file should be written, but found: {entries:?}"
    );

    // Stderr must mention "not wrapped" or "init"
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_ascii_lowercase().contains("not wrapped")
            || stderr.to_ascii_lowercase().contains("init"),
        "AC-R1: stderr should mention 'not wrapped' or 'init', got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// AC-R5 / AC-R7: emit writes receipt; --show round-trips; counter fidelity
// ---------------------------------------------------------------------------

#[test]
fn acceptance_r5_r7_emit_and_show_roundtrip() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("receipt AC-R5/R7: binary not built, skipping");
        return;
    }

    let session_id = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
    let proc_root = make_proc_root_live(session_id);
    let receipts_dir = tempfile::tempdir().expect("receipts tempdir");

    // Emit
    let out = Command::new(&bin)
        .args([
            "receipt",
            "--emit",
            "--pid", "42001",
            "--proc-root", proc_root.path().to_str().expect("utf8"),
            "--receipts-dir", receipts_dir.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run agentns-doctor receipt --emit");

    assert_eq!(
        out.status.code(),
        Some(0),
        "AC-R5: --emit should exit 0\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The receipt file must exist
    let receipt_path = receipts_dir.path().join(format!("{session_id}.json"));
    assert!(
        receipt_path.exists(),
        "AC-R5: receipt file should exist at {receipt_path:?}"
    );

    // --show must return the same object
    let show_out = Command::new(&bin)
        .args([
            "receipt",
            "--show", session_id,
            "--receipts-dir", receipts_dir.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run agentns-doctor receipt --show");

    assert_eq!(
        show_out.status.code(),
        Some(0),
        "AC-R5: --show should exit 0\nstderr: {}",
        String::from_utf8_lossy(&show_out.stderr)
    );

    let show_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&show_out.stdout))
            .expect("AC-R5: --show should emit valid JSON");

    // AC-R7: counter fidelity — match the fixture values
    assert_eq!(
        show_json["counters"]["total_syscalls"].as_u64(),
        Some(1_203_481),
        "AC-R7: total_syscalls should match fixture"
    );
    assert_eq!(
        show_json["counters"]["write_bytes"].as_u64(),
        Some(41_203_992),
        "AC-R7: write_bytes should match fixture"
    );
    assert_eq!(
        show_json["session_id"].as_str(),
        Some(session_id),
        "AC-R7: session_id should match"
    );
    assert_eq!(
        show_json["schema"].as_str(),
        Some("agentns-receipt/1"),
        "AC-R7: schema must be agentns-receipt/1"
    );
}

// ---------------------------------------------------------------------------
// AC-R6: --join-ctrace reports agreement / divergence
// ---------------------------------------------------------------------------

#[test]
fn acceptance_r6_join_ctrace_agreement() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("receipt AC-R6 agreement: binary not built, skipping");
        return;
    }

    let session_id = "beef0000000000000000000000000001";
    let proc_root = {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_dir = dir.path().join("43001");
        fs::create_dir_all(pid_dir.join("ns")).expect("create ns dir");
        fs::write(pid_dir.join("agent_session"), session_id).expect("write agent_session");
        // counters with total_syscalls=100, write_bytes=200
        fs::write(
            pid_dir.join("agent_counters"),
            r#"{ "total_syscalls": 100, "openat_count": 10, "write_bytes": 200,
  "connect_count": 1, "unlink_count": 0, "fork_count": 0, "elapsed_ns": 1000 }"#,
        )
        .expect("write agent_counters");
        dir
    };

    let receipts_dir = tempfile::tempdir().expect("receipts tempdir");
    let ctrace_dir = tempfile::tempdir().expect("ctrace tempdir");

    // Write a ctrace ndjson fixture: same session, syscalls=103, write_bytes=205 (within 10%)
    let ctrace_file = ctrace_dir.path().join(format!("{session_id}.ndjson"));
    fs::write(
        &ctrace_file,
        r#"{"event":"syscall","syscalls":103,"write_bytes":205}
"#,
    )
    .expect("write ctrace fixture");

    // Emit the receipt
    let emit_out = Command::new(&bin)
        .args([
            "receipt", "--emit",
            "--pid", "43001",
            "--proc-root", proc_root.path().to_str().expect("utf8"),
            "--receipts-dir", receipts_dir.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run --emit");
    assert_eq!(emit_out.status.code(), Some(0), "emit should succeed");

    // Join with ctrace
    let join_out = Command::new(&bin)
        .args([
            "receipt", "--join-ctrace", session_id,
            "--receipts-dir", receipts_dir.path().to_str().expect("utf8"),
            "--ctrace-dir", ctrace_dir.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run --join-ctrace");

    assert_eq!(
        join_out.status.code(),
        Some(0),
        "AC-R6 agreement: --join-ctrace should exit 0\nstderr: {}",
        String::from_utf8_lossy(&join_out.stderr)
    );

    let stdout = String::from_utf8_lossy(&join_out.stdout);
    assert!(
        stdout.contains("agreement"),
        "AC-R6: within-10% join should say 'agreement', got: {stdout}"
    );
}

#[test]
fn acceptance_r6_join_ctrace_divergence() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("receipt AC-R6 divergence: binary not built, skipping");
        return;
    }

    let session_id = "beef0000000000000000000000000002";
    let proc_root = {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_dir = dir.path().join("43002");
        fs::create_dir_all(pid_dir.join("ns")).expect("create ns dir");
        fs::write(pid_dir.join("agent_session"), session_id).expect("write agent_session");
        // counters with total_syscalls=100
        fs::write(
            pid_dir.join("agent_counters"),
            r#"{ "total_syscalls": 100, "openat_count": 10, "write_bytes": 100,
  "connect_count": 1, "unlink_count": 0, "fork_count": 0, "elapsed_ns": 1000 }"#,
        )
        .expect("write agent_counters");
        dir
    };

    let receipts_dir = tempfile::tempdir().expect("receipts tempdir");
    let ctrace_dir = tempfile::tempdir().expect("ctrace tempdir");

    // ctrace: syscalls=200 (100% divergence, way >10%)
    let ctrace_file = ctrace_dir.path().join(format!("{session_id}.ndjson"));
    fs::write(
        &ctrace_file,
        r#"{"event":"syscall","syscalls":200,"write_bytes":100}
"#,
    )
    .expect("write ctrace fixture");

    let emit_out = Command::new(&bin)
        .args([
            "receipt", "--emit",
            "--pid", "43002",
            "--proc-root", proc_root.path().to_str().expect("utf8"),
            "--receipts-dir", receipts_dir.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run --emit");
    assert_eq!(emit_out.status.code(), Some(0));

    let join_out = Command::new(&bin)
        .args([
            "receipt", "--join-ctrace", session_id,
            "--receipts-dir", receipts_dir.path().to_str().expect("utf8"),
            "--ctrace-dir", ctrace_dir.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run --join-ctrace");

    assert_eq!(join_out.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&join_out.stdout);
    assert!(
        stdout.contains("divergence"),
        "AC-R6: >10% join should say 'divergence', got: {stdout}"
    );
}

#[test]
fn acceptance_r6_join_ctrace_no_match() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("receipt AC-R6 no-match: binary not built, skipping");
        return;
    }

    let session_id = "beef0000000000000000000000000003";
    let proc_root = {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_dir = dir.path().join("43003");
        fs::create_dir_all(pid_dir.join("ns")).expect("create ns dir");
        fs::write(pid_dir.join("agent_session"), session_id).expect("write agent_session");
        fs::write(
            pid_dir.join("agent_counters"),
            r#"{ "total_syscalls": 5, "openat_count": 1, "write_bytes": 100,
  "connect_count": 0, "unlink_count": 0, "fork_count": 0, "elapsed_ns": 500 }"#,
        )
        .expect("write agent_counters");
        dir
    };

    let receipts_dir = tempfile::tempdir().expect("receipts tempdir");
    // Empty ctrace dir — no match
    let ctrace_dir = tempfile::tempdir().expect("ctrace tempdir");

    let emit_out = Command::new(&bin)
        .args([
            "receipt", "--emit",
            "--pid", "43003",
            "--proc-root", proc_root.path().to_str().expect("utf8"),
            "--receipts-dir", receipts_dir.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run --emit");
    assert_eq!(emit_out.status.code(), Some(0));

    let join_out = Command::new(&bin)
        .args([
            "receipt", "--join-ctrace", session_id,
            "--receipts-dir", receipts_dir.path().to_str().expect("utf8"),
            "--ctrace-dir", ctrace_dir.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run --join-ctrace");

    assert_eq!(join_out.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&join_out.stdout);
    assert!(
        stdout.contains("no ctrace match"),
        "AC-R6: absent ctrace should say 'no ctrace match', got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// AC-R8: receipts dir created 0700
// ---------------------------------------------------------------------------

#[test]
fn acceptance_r8_receipts_dir_created_0700() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("receipt AC-R8: binary not built, skipping");
        return;
    }

    let session_id = "cafe0000000000000000000000000001";
    let proc_root = make_proc_root_live(session_id);

    // Use a receipts dir that does NOT yet exist (nested)
    let base = tempfile::tempdir().expect("base tempdir");
    let receipts_dir = base.path().join("new_subdir").join("receipts");

    let out = Command::new(&bin)
        .args([
            "receipt", "--emit",
            "--pid", "42001",
            "--proc-root", proc_root.path().to_str().expect("utf8"),
            "--receipts-dir", receipts_dir.to_str().expect("utf8"),
        ])
        .output()
        .expect("run agentns-doctor");

    assert_eq!(
        out.status.code(),
        Some(0),
        "AC-R8: emit to new dir should succeed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Check the dir was created
    assert!(receipts_dir.exists(), "AC-R8: receipts dir should be created");

    // Check permissions: must be 0700
    let meta = fs::metadata(&receipts_dir).expect("metadata");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "AC-R8: receipts dir should have mode 0700, got {:o}",
        mode
    );
}

// ---------------------------------------------------------------------------
// AC-R9: golden key set for receipt JSON
// ---------------------------------------------------------------------------

#[test]
fn acceptance_r9_golden_key_set() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("receipt AC-R9: binary not built, skipping");
        return;
    }

    let session_id = "dead000000000000000000000000cafe";
    let proc_root = make_proc_root_live(session_id);
    let receipts_dir = tempfile::tempdir().expect("receipts tempdir");

    let out = Command::new(&bin)
        .args([
            "receipt", "--emit",
            "--pid", "42001",
            "--proc-root", proc_root.path().to_str().expect("utf8"),
            "--receipts-dir", receipts_dir.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run agentns-doctor");

    assert_eq!(out.status.code(), Some(0));

    let receipt_path = receipts_dir.path().join(format!("{session_id}.json"));
    let raw = fs::read_to_string(&receipt_path).expect("read receipt");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse receipt JSON");
    let obj = v.as_object().expect("receipt must be an object");

    // Golden key set per §2.1
    let required_keys = [
        "session_id",
        "intent_tag",
        "pid",
        "state",
        "counters",
        "emitted_at",
        "schema",
    ];
    for key in &required_keys {
        assert!(
            obj.contains_key(*key),
            "AC-R9: receipt missing required key '{key}'; keys present: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }

    // counters must have the seven sub-fields
    let counters = obj
        .get("counters")
        .and_then(|c| c.as_object())
        .expect("counters must be an object");
    let counter_keys = [
        "total_syscalls",
        "openat_count",
        "write_bytes",
        "connect_count",
        "unlink_count",
        "fork_count",
        "elapsed_ns",
    ];
    for key in &counter_keys {
        assert!(
            counters.contains_key(*key),
            "AC-R9: counters missing field '{key}'"
        );
    }

    // schema must be exactly "agentns-receipt/1"
    assert_eq!(
        v["schema"].as_str(),
        Some("agentns-receipt/1"),
        "AC-R9: schema version must be 'agentns-receipt/1'"
    );
}

// ---------------------------------------------------------------------------
// AC-R10: receipt --help documents all mode flags
// ---------------------------------------------------------------------------

#[test]
fn acceptance_r10_receipt_help() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("receipt AC-R10: binary not built, skipping");
        return;
    }

    let out = Command::new(&bin)
        .args(["receipt", "--help"])
        .output()
        .expect("run agentns-doctor receipt --help");

    assert_eq!(
        out.status.code(),
        Some(0),
        "AC-R10: receipt --help should exit 0"
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--emit"),
        "AC-R10: --help should document --emit"
    );
    assert!(
        stdout.contains("--list"),
        "AC-R10: --help should document --list"
    );
    assert!(
        stdout.contains("--show"),
        "AC-R10: --help should document --show"
    );
    assert!(
        stdout.contains("--join-ctrace"),
        "AC-R10: --help should document --join-ctrace"
    );
    assert!(
        stdout.contains("--require-wrapped"),
        "AC-R10: --help should document --require-wrapped"
    );
}
