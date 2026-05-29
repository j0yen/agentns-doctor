//! AC4 (MUST): A fixture agent_session with a 16-char or non-hex value yields
//! state:malformed, exit 3.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn agentns_doctor_bin() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/debug/agentns-doctor");
    p
}

fn make_proc_root_malformed(session_content: &str) -> TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    let pid_dir = dir.path().join("55555");
    fs::create_dir_all(pid_dir.join("ns")).expect("create ns dir");
    fs::write(pid_dir.join("agent_session"), session_content)
        .expect("write agent_session");
    dir
}

#[test]
fn acceptance_ac4_malformed_short_value() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("AC4: binary not built at {bin:?}, skipping");
        return;
    }

    // 16-char value (too short to be a valid 32-hex id)
    let proc_root = make_proc_root_malformed("0000000000000000");

    let out = Command::new(&bin)
        .args([
            "status",
            "--format",
            "json",
            "--pid",
            "55555",
            "--proc-root",
            proc_root.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run agentns-doctor");

    assert_eq!(
        out.status.code(),
        Some(3),
        "malformed should exit 3, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["state"].as_str(), Some("malformed"));
    assert_eq!(v["verdict"].as_str(), Some("malformed-surface"));
}

#[test]
fn acceptance_ac4_malformed_non_hex_value() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("AC4: binary not built at {bin:?}, skipping");
        return;
    }

    // 32-char but not hex
    let proc_root = make_proc_root_malformed("gggggggggggggggggggggggggggggggg");

    let out = Command::new(&bin)
        .args([
            "status",
            "--format",
            "json",
            "--pid",
            "55555",
            "--proc-root",
            proc_root.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run agentns-doctor");

    assert_eq!(
        out.status.code(),
        Some(3),
        "non-hex malformed should exit 3, got {:?}",
        out.status.code()
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["state"].as_str(), Some("malformed"));
}
