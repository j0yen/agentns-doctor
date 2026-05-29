//! AC1 (MUST): agentns-doctor status --format json on the real init-ns session
//! emits state==init, session_nonzero==false, verdict==unwrapped-expected,
//! ns_inode is a non-null integer, exit code 0.
//!
//! This test reads /proc/self directly, so it only passes on a wintermute kernel
//! that has /proc/self/agent_session. On a stock kernel (absent surface) the
//! test is skipped.

use std::process::Command;

fn agentns_doctor_bin() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/debug/agentns-doctor");
    p
}

#[test]
fn acceptance_ac1_init_ns_json() {
    // Skip if we're on a stock kernel (no agent_session surface)
    if !std::path::Path::new("/proc/self/agent_session").exists() {
        eprintln!("AC1: /proc/self/agent_session absent — stock kernel, skipping live test");
        return;
    }

    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("AC1: binary not built at {bin:?}, skipping");
        return;
    }

    let out = Command::new(&bin)
        .args(["status", "--format", "json"])
        .output()
        .expect("failed to run agentns-doctor");

    assert_eq!(
        out.status.code(),
        Some(0),
        "exit code should be 0, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("status --format json should emit valid JSON");

    // Must be init state
    assert_eq!(
        v["state"].as_str(),
        Some("init"),
        "expected state==init, got: {v}"
    );
    assert_eq!(
        v["session_nonzero"].as_bool(),
        Some(false),
        "expected session_nonzero==false"
    );
    assert_eq!(
        v["verdict"].as_str(),
        Some("unwrapped-expected"),
        "expected verdict==unwrapped-expected"
    );
    assert!(
        v["ns_inode"].is_number(),
        "expected ns_inode to be a non-null integer"
    );
}
