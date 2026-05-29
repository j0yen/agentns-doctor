//! AC5 (MUST): agentns-doctor counters --format json reproduces the seven kernel
//! counter fields; on init ns all are 0 and a note field flags init-ns zeros.
//!
//! AC6 (MUST): Sampling twice with --delta produces a delta object with the same
//! seven keys; on an idle init ns every delta is 0.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn agentns_doctor_bin() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/debug/agentns-doctor");
    p
}

fn make_proc_root_with_counters(session_id: &str, counters_json: &str) -> TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    let pid_dir = dir.path().join("77777");
    fs::create_dir_all(pid_dir.join("ns")).expect("create ns dir");
    fs::write(pid_dir.join("agent_session"), session_id).expect("write agent_session");
    fs::write(pid_dir.join("agent_counters"), counters_json).expect("write agent_counters");
    dir
}

const ZERO_COUNTERS: &str = r#"{ "total_syscalls": 0, "openat_count": 0, "write_bytes": 0,
  "connect_count": 0, "unlink_count": 0, "fork_count": 0, "elapsed_ns": 0 }"#;

const NONZERO_COUNTERS: &str = r#"{ "total_syscalls": 42, "openat_count": 7, "write_bytes": 1024,
  "connect_count": 3, "unlink_count": 1, "fork_count": 2, "elapsed_ns": 5000000 }"#;

#[test]
fn acceptance_ac5_counters_init_ns_json() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("AC5: binary not built, skipping");
        return;
    }

    // Use all-zero session to simulate init ns
    let proc_root =
        make_proc_root_with_counters("00000000000000000000000000000000", ZERO_COUNTERS);

    let out = Command::new(&bin)
        .args([
            "counters",
            "--format",
            "json",
            "--pid",
            "77777",
            "--proc-root",
            proc_root.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run agentns-doctor");

    assert_eq!(
        out.status.code(),
        Some(0),
        "counters should exit 0\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    // Verify the seven counter fields exist with zero values
    let sample = &v["sample"];
    assert_eq!(sample["total_syscalls"].as_u64(), Some(0));
    assert_eq!(sample["openat_count"].as_u64(), Some(0));
    assert_eq!(sample["write_bytes"].as_u64(), Some(0));
    assert_eq!(sample["connect_count"].as_u64(), Some(0));
    assert_eq!(sample["unlink_count"].as_u64(), Some(0));
    assert_eq!(sample["fork_count"].as_u64(), Some(0));
    assert_eq!(sample["elapsed_ns"].as_u64(), Some(0));

    // note field should be present and mention init ns
    let note = v["note"].as_str().unwrap_or("");
    assert!(
        note.contains("init"),
        "note should mention init ns, got: {note:?}"
    );
}

#[test]
fn acceptance_ac5_counters_live_ns_nonzero() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("AC5 live: binary not built, skipping");
        return;
    }

    let proc_root =
        make_proc_root_with_counters("deadbeefcafe0123456789abcdef0001", NONZERO_COUNTERS);

    let out = Command::new(&bin)
        .args([
            "counters",
            "--format",
            "json",
            "--pid",
            "77777",
            "--proc-root",
            proc_root.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run agentns-doctor");

    assert_eq!(out.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let sample = &v["sample"];
    assert_eq!(sample["total_syscalls"].as_u64(), Some(42));
    assert_eq!(sample["write_bytes"].as_u64(), Some(1024));
    // note should be null/absent for live ns
    assert!(v["note"].is_null(), "live ns note should be null");
}

#[test]
fn acceptance_ac6_counters_delta_init_ns_all_zeros() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("AC6: binary not built, skipping");
        return;
    }

    // Static fixture — both samples will read the same zeros, so delta is all zeros
    let proc_root =
        make_proc_root_with_counters("00000000000000000000000000000000", ZERO_COUNTERS);

    let out = Command::new(&bin)
        .args([
            "counters",
            "--format",
            "json",
            "--pid",
            "77777",
            "--proc-root",
            proc_root.path().to_str().expect("utf8"),
            "--delta",
            "10",
        ])
        .output()
        .expect("run agentns-doctor");

    assert_eq!(
        out.status.code(),
        Some(0),
        "counters --delta should exit 0\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    let delta = &v["delta"];
    assert!(!delta.is_null(), "delta should be present");
    assert_eq!(delta["total_syscalls"].as_u64(), Some(0));
    assert_eq!(delta["openat_count"].as_u64(), Some(0));
    assert_eq!(delta["write_bytes"].as_u64(), Some(0));
    assert_eq!(delta["connect_count"].as_u64(), Some(0));
    assert_eq!(delta["unlink_count"].as_u64(), Some(0));
    assert_eq!(delta["fork_count"].as_u64(), Some(0));
    assert_eq!(delta["elapsed_ns"].as_u64(), Some(0));

    // delta_ms should equal 10
    assert_eq!(v["delta_ms"].as_u64(), Some(10));
}
