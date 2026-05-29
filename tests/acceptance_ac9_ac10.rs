//! AC9 (MUST): agentns-doctor --help lists status/counters/explain/receipt; --version is non-empty.
//! AC10 (MUST): status --format json key set is exactly
//!   {state, session_id, session_nonzero, ns_inode, intent_tag, pid, verdict}.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn agentns_doctor_bin() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/debug/agentns-doctor");
    p
}

fn make_proc_root_init() -> TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    let pid_dir = dir.path().join("11111");
    fs::create_dir_all(pid_dir.join("ns")).expect("create ns dir");
    fs::write(
        pid_dir.join("agent_session"),
        "00000000000000000000000000000000",
    )
    .expect("write agent_session");
    dir
}

#[test]
fn acceptance_ac9_help_lists_subcommands() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("AC9: binary not built, skipping");
        return;
    }

    let out = Command::new(&bin)
        .arg("--help")
        .output()
        .expect("run agentns-doctor --help");

    // --help exits 0
    assert_eq!(
        out.status.code(),
        Some(0),
        "--help should exit 0, got {:?}",
        out.status.code()
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("status"), "--help should list 'status'");
    assert!(stdout.contains("counters"), "--help should list 'counters'");
    assert!(stdout.contains("explain"), "--help should list 'explain'");
    assert!(stdout.contains("receipt"), "--help should list 'receipt'");
}

#[test]
fn acceptance_ac9_version_prints_version() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("AC9: binary not built, skipping");
        return;
    }

    let out = Command::new(&bin)
        .arg("--version")
        .output()
        .expect("run agentns-doctor --version");

    assert_eq!(
        out.status.code(),
        Some(0),
        "--version should exit 0"
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    // Version must be non-empty and contain a semver-like string
    assert!(
        stdout.contains("agentns-doctor"),
        "--version should contain crate name, got: {stdout}"
    );
    assert!(
        stdout.chars().any(|c| c.is_ascii_digit()),
        "--version should contain a digit, got: {stdout}"
    );
}

#[test]
fn acceptance_ac10_stable_json_schema() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("AC10: binary not built, skipping");
        return;
    }

    let proc_root = make_proc_root_init();

    let out = Command::new(&bin)
        .args([
            "status",
            "--format",
            "json",
            "--pid",
            "11111",
            "--proc-root",
            proc_root.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run agentns-doctor");

    assert_eq!(out.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    // Golden-key set: exactly these seven keys must be present
    let expected_keys = [
        "state",
        "session_id",
        "session_nonzero",
        "ns_inode",
        "intent_tag",
        "pid",
        "verdict",
    ];

    let obj = v.as_object().expect("status JSON must be an object");

    for key in &expected_keys {
        assert!(
            obj.contains_key(*key),
            "status JSON missing required key '{key}'; keys present: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }

    // No extra keys beyond the golden set
    for key in obj.keys() {
        assert!(
            expected_keys.contains(&key.as_str()),
            "status JSON has unexpected extra key '{key}'"
        );
    }
}
