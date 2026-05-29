//! AC3 (MUST): With --proc-root fixture dir where agent_session contains a
//! non-zero 32-hex string, status returns state:live, session_nonzero:true,
//! verdict:wrapped, and echoes the 32-hex id.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn agentns_doctor_bin() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/debug/agentns-doctor");
    p
}

fn make_proc_root_live(session_id: &str) -> TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    let pid_dir = dir.path().join("99001");
    fs::create_dir_all(pid_dir.join("ns")).expect("create ns dir");
    fs::write(pid_dir.join("agent_session"), session_id).expect("write agent_session");
    // Write a dummy agent_counters too
    fs::write(
        pid_dir.join("agent_counters"),
        r#"{ "total_syscalls": 123, "openat_count": 45, "write_bytes": 4096,
  "connect_count": 2, "unlink_count": 0, "fork_count": 1, "elapsed_ns": 9000000 }"#,
    )
    .expect("write agent_counters");
    dir
}

#[test]
fn acceptance_ac3_live_state() {
    let bin = agentns_doctor_bin();
    if !bin.exists() {
        eprintln!("AC3: binary not built at {bin:?}, skipping");
        return;
    }

    let session_id = "deadbeefcafe0123456789abcdef0001";
    let proc_root = make_proc_root_live(session_id);

    let out = Command::new(&bin)
        .args([
            "status",
            "--format",
            "json",
            "--pid",
            "99001",
            "--proc-root",
            proc_root.path().to_str().expect("utf8"),
        ])
        .output()
        .expect("run agentns-doctor");

    assert_eq!(
        out.status.code(),
        Some(0),
        "live state should exit 0\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert_eq!(v["state"].as_str(), Some("live"));
    assert_eq!(v["session_nonzero"].as_bool(), Some(true));
    assert_eq!(v["verdict"].as_str(), Some("wrapped"));
    assert_eq!(v["session_id"].as_str(), Some(session_id));
}
