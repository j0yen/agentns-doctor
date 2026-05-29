//! Abstraction over `/proc` reads, with optional redirection to a fixture dir.
//!
//! The `--proc-root <dir>` test hook replaces `/proc` with a user-supplied
//! directory so acceptance tests can exercise `absent`, `live`, and `malformed`
//! without a real wrapped session.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Reads files from `/proc` (or a test fixture directory).
#[derive(Debug)]
pub struct ProcReader {
    proc_root: PathBuf,
}

impl ProcReader {
    /// Create a new reader.  `None` → `/proc`.
    #[must_use]
    pub fn new(proc_root: Option<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.unwrap_or_else(|| PathBuf::from("/proc")),
        }
    }

    /// Read `agent_session` for `pid`.  Returns `None` if the file is absent.
    ///
    /// # Errors
    /// Returns an error when the file exists but cannot be read.
    pub fn agent_session(&self, pid: u32) -> io::Result<Option<String>> {
        let path = self.proc_root.join(pid.to_string()).join("agent_session");
        match fs::read_to_string(&path) {
            Ok(s) => Ok(Some(s.trim().to_owned())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Read `agent_counters` for `pid`.  Returns `None` if the file is absent.
    ///
    /// # Errors
    /// Returns an error when the file exists but cannot be read.
    pub fn agent_counters(&self, pid: u32) -> io::Result<Option<String>> {
        let path = self.proc_root.join(pid.to_string()).join("agent_counters");
        match fs::read_to_string(&path) {
            Ok(s) => Ok(Some(s.trim().to_owned())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Return the inode of `ns/agent` for `pid` via `stat`.
    /// Returns `None` if the file is absent (pre-kernel or fixture).
    ///
    /// # Errors
    /// Returns an error when the path exists but cannot be stat'd.
    pub fn ns_agent_inode(&self, pid: u32) -> io::Result<Option<u64>> {
        let path = self.proc_root.join(pid.to_string()).join("ns").join("agent");
        match fs::metadata(&path) {
            Ok(m) => Ok(Some(m.ino())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Return the configured proc root path (for display in diagnostics).
    #[must_use]
    pub fn proc_root(&self) -> &Path {
        &self.proc_root
    }
}
