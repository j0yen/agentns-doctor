//! AC2 (MUST): With --proc-root fixture dir where agent_session is absent,
//! status returns state:absent, verdict:kernel-absent, exit 0.
//! With --expect-kernel flag, exit 2.

use std::process::Command;
use tempfile::TempDir;

fn agentns_doctor_bin() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/debug/agentns-doctor");
    p
}

fn make_proc_root_absent() -> TempDir {
    // Create a temp dir with a /proc-like structure but NO agent_session
    let dir = tempfile::tempdir().expect("create tempdir");
    let pid_dir = dir.path().join("12345");
    std::fs::create_dir_all(pid_dir.join("ns")).expect("create ns dir");
    // Do NOT create agent_session
    dir
}

#[test]
fn acceptance_ac2_absent_state_exit_0() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("AC2: binary not built at {bin:?}, skipping");
        return;
    }

    let proc_root = make_proc_root_absent();

    let out = Command::new(&bin)
        .args([
            "status",
            "--format",
            "json",
            "--pid",
            "12345",
            "--proc-root",
            proc_root.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run agentns-doctor");

    assert_eq!(
        out.status.code(),
        Some(0),
        "absent without --expect-kernel should exit 0, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("should emit valid JSON");

    assert_eq!(v["state"].as_str(), Some("absent"));
    assert_eq!(v["verdict"].as_str(), Some("kernel-absent"));
}

#[test]
fn acceptance_ac2_absent_with_expect_kernel_exit_2() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("AC2: binary not built at {bin:?}, skipping");
        return;
    }

    let proc_root = make_proc_root_absent();

    let out = Command::new(&bin)
        .args([
            "status",
            "--format",
            "json",
            "--pid",
            "12345",
            "--proc-root",
            proc_root.path().to_str().expect("utf8"),
            "--expect-kernel",
        ])
        .output()
        .expect("run agentns-doctor");

    assert_eq!(
        out.status.code(),
        Some(2),
        "absent with --expect-kernel should exit 2, got {:?}",
        out.status.code()
    );
}
