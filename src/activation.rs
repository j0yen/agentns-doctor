//! Activation chain evaluator for `agentns-doctor activation`.
//!
//! Evaluates the whole continuity chain, layer by layer, short-circuiting to
//! the first blocking layer:
//!
//! 1. **kernel-installed** — installed pkgrel vs running pkgrel
//! 2. **kernel-prctl** — prctl(PR_GET_AGENT_SESSION_ID) probe in a forked child
//! 3. **launcher-installed** — ~/.local/bin/agentns-claude exists + cap_sys_admin=ep
//! 4. **launcher-wired** — claude() shell function not using --no-unshare
//! 5. **live-session** — /proc/self/agent_session non-zero 32-hex
//! 6. **downstream-stamp** — getfattr probe reports real agentns id vs fallback
//!
//! All probes are read-only; the only write is a throwaway temp file for the
//! stamp probe which is deleted before return.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Agent-namespace prctl constants ────────────────────────────────────────────────

/// Base PR_* constant for agent-namespace prctl ops (0x41544E53 = "ATNS").
/// Declared as i32 directly to avoid the `as` cast lint.
const PR_AGENT_BASE: libc::c_int = 0x4154_4E53_i32;
/// PR_GET_AGENT_SESSION_ID: read the calling task's agent session id.
/// Used as the kernel-support probe: it succeeds unprivileged with a valid
/// output buffer, while a kernel without agentns returns EINVAL.
const PR_GET_AGENT_SESSION_ID: libc::c_int = PR_AGENT_BASE + 1;
/// Size of the session-id buffer PR_GET_AGENT_SESSION_ID writes into.
const AGENT_NS_ID_BYTES: usize = 16;

// ── Layer state ──────────────────────────────────────────────────────────────

/// The state of a single activation layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LayerState {
    /// Layer check passed.
    Ok,
    /// Reboot pending: installed pkgrel > running pkgrel.
    RebootPending {
        /// Pkgrel of the running kernel.
        running: String,
        /// Pkgrel of the installed kernel package.
        installed: String,
        /// Suggested remedy command.
        remedy: String,
    },
    /// Running kernel lacks the agent-namespace prctl opcodes.
    KernelLacksPrctl {
        /// errno from the prctl call.
        errno: i32,
        /// Suggested remedy.
        remedy: String,
    },
    /// Launcher binary is absent or not executable.
    LauncherMissing {
        /// Path that was checked.
        path: String,
        /// Suggested remedy.
        remedy: String,
    },
    /// Launcher is present but missing cap_sys_admin effective capability.
    LauncherUncapped {
        /// Path of the launcher.
        path: String,
        /// Suggested remedy.
        remedy: String,
    },
    /// Shell wrapper calls the launcher with --no-unshare (forces synthetic session).
    WrapperForcesSynth {
        /// Suggested remedy.
        remedy: String,
    },
    /// /proc/self/agent_session is all-zeros (not in a live agent namespace).
    SessionZero {
        /// Suggested remedy.
        remedy: String,
    },
    /// Downstream stamp layer: real agentns id stamped on files.
    StampReal {
        /// The session id found in the xattr.
        session_id: String,
    },
    /// Downstream stamp layer: fallback comm:...:pid:... form (provfs not active).
    StampFallback {
        /// The fallback string found.
        fallback: String,
        /// Suggested remedy.
        remedy: String,
    },
    /// getfattr not available or xattr read failed.
    StampUnavailable {
        /// Reason.
        reason: String,
    },
}

impl LayerState {
    /// Return true if this state blocks activation.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        !matches!(self, Self::Ok | Self::StampReal { .. })
    }

    /// Short label for display.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::RebootPending { .. } => "BLOCKED",
            Self::KernelLacksPrctl { .. } => "BLOCKED",
            Self::LauncherMissing { .. } => "BLOCKED",
            Self::LauncherUncapped { .. } => "BLOCKED",
            Self::WrapperForcesSynth { .. } => "BLOCKED",
            Self::SessionZero { .. } => "BLOCKED",
            Self::StampReal { .. } => "ok",
            Self::StampFallback { .. } => "fallback",
            Self::StampUnavailable { .. } => "unavailable",
        }
    }

    /// One-line detail for human table.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Ok => "pass".to_owned(),
            Self::RebootPending { running, installed, .. } => {
                format!("running pkgrel {running} < installed {installed}")
            }
            Self::KernelLacksPrctl { errno, .. } => {
                format!("prctl(PR_GET_AGENT_SESSION_ID) errno={errno}")
            }
            Self::LauncherMissing { path, .. } => {
                format!("not found: {path}")
            }
            Self::LauncherUncapped { path, .. } => {
                format!("missing cap_sys_admin: {path}")
            }
            Self::WrapperForcesSynth { .. } => {
                "--no-unshare in claude() wrapper".to_owned()
            }
            Self::SessionZero { .. } => {
                "/proc/self/agent_session all-zeros".to_owned()
            }
            Self::StampReal { session_id } => {
                format!("user.prov.session={}", &session_id[..8.min(session_id.len())])
            }
            Self::StampFallback { fallback, .. } => {
                format!("fallback: {fallback}")
            }
            Self::StampUnavailable { reason } => {
                format!("unavailable: {reason}")
            }
        }
    }

    /// Extract remedy string, if any.
    #[must_use]
    pub fn remedy(&self) -> Option<&str> {
        match self {
            Self::RebootPending { remedy, .. }
            | Self::KernelLacksPrctl { remedy, .. }
            | Self::LauncherMissing { remedy, .. }
            | Self::LauncherUncapped { remedy, .. }
            | Self::WrapperForcesSynth { remedy }
            | Self::SessionZero { remedy }
            | Self::StampFallback { remedy, .. } => Some(remedy.as_str()),
            Self::Ok | Self::StampReal { .. } | Self::StampUnavailable { .. } => None,
        }
    }
}

/// A named activation layer with its result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerResult {
    /// Layer name (kebab-case).
    pub layer: String,
    /// The layer's state.
    pub state: LayerState,
}

/// Full activation chain result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationResult {
    /// All evaluated layers (only layers that were reached are included).
    pub layers: Vec<LayerResult>,
    /// Name of the first blocking layer, or null if fully live.
    pub blocked_layer: Option<String>,
    /// Remedy for the first blocking layer, or null.
    pub remedy: Option<String>,
    /// Running kernel pkgrel (from uname -r).
    pub running_pkgrel: Option<String>,
    /// Installed kernel pkgrel (from pacman -Q linux-wintermute).
    pub installed_pkgrel: Option<String>,
    /// Content of /proc/self/agent_session, if readable.
    pub agent_session: Option<String>,
    /// "real", "fallback", or "unavailable" — stamp form from downstream layer.
    pub stamp_form: Option<String>,
}

/// Options for running the activation check, allowing env-based overrides for testing.
#[derive(Debug)]
pub struct ActivationOptions {
    /// Override for `uname -r` output (ACTIVATION_UNAME env var).
    pub uname_override: Option<String>,
    /// Override for pacman binary path (ACTIVATION_PACMAN_BIN env var).
    pub pacman_bin_override: Option<String>,
    /// Override for HOME dir (for launcher check).
    pub home_override: Option<PathBuf>,
    /// Override for rc file path (ACTIVATION_RC_FILE env var).
    pub rc_file_override: Option<PathBuf>,
    /// Override proc root for agent_session reads.
    pub proc_root: Option<PathBuf>,
}

impl ActivationOptions {
    /// Read options from environment variables.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            uname_override: std::env::var("ACTIVATION_UNAME").ok(),
            pacman_bin_override: std::env::var("ACTIVATION_PACMAN_BIN").ok(),
            home_override: std::env::var("ACTIVATION_HOME")
                .ok()
                .map(PathBuf::from),
            rc_file_override: std::env::var("ACTIVATION_RC_FILE").ok().map(PathBuf::from),
            proc_root: None,
        }
    }
}

// ── pkgrel parsing ───────────────────────────────────────────────────────────

/// Parse pkgrel from `uname -r` output like `7.0.10-arch1-5-wintermute`.
/// The pkgrel is the last numeric segment before `-wintermute`.
fn parse_uname_pkgrel(uname_r: &str) -> Option<u32> {
    // Format: <version>-<extra>-<pkgrel>-wintermute
    let without_wm = uname_r.trim().strip_suffix("-wintermute")?;
    let pkgrel_str = without_wm.rsplit('-').next()?;
    pkgrel_str.parse().ok()
}

/// Parse pkgrel from `pacman -Q linux-wintermute` output like `linux-wintermute 7.0.10.arch1-12`.
/// The pkgrel is the number after the final `-`.
fn parse_pacman_pkgrel(pacman_q: &str) -> Option<u32> {
    // Format: linux-wintermute <epoch:version-pkgrel>
    let ver_part = pacman_q.trim().split_whitespace().nth(1)?;
    let pkgrel_str = ver_part.rsplit('-').next()?;
    pkgrel_str.parse().ok()
}

// ── Layer implementations ────────────────────────────────────────────────────

fn check_kernel_installed(opts: &ActivationOptions) -> LayerResult {
    let uname_out = match &opts.uname_override {
        Some(s) => s.clone(),
        None => {
            match Command::new("uname").arg("-r").output() {
                Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
                Err(_) => {
                    return LayerResult {
                        layer: "kernel-installed".to_owned(),
                        state: LayerState::Ok,
                    };
                }
            }
        }
    };

    let pacman_out = match &opts.pacman_bin_override {
        Some(bin) => {
            match Command::new(bin).args(["linux-wintermute"]).output() {
                Ok(o) if o.status.success() => {
                    String::from_utf8_lossy(&o.stdout).to_string()
                }
                _ => {
                    // pacman not available or package not found; skip layer
                    return LayerResult {
                        layer: "kernel-installed".to_owned(),
                        state: LayerState::Ok,
                    };
                }
            }
        }
        None => {
            match Command::new("pacman").args(["-Q", "linux-wintermute"]).output() {
                Ok(o) if o.status.success() => {
                    String::from_utf8_lossy(&o.stdout).to_string()
                }
                _ => {
                    return LayerResult {
                        layer: "kernel-installed".to_owned(),
                        state: LayerState::Ok,
                    };
                }
            }
        }
    };

    let running_pkgrel = parse_uname_pkgrel(uname_out.trim()).unwrap_or(0);
    let installed_pkgrel = parse_pacman_pkgrel(pacman_out.trim()).unwrap_or(0);

    let running_str = running_pkgrel.to_string();
    let installed_str = installed_pkgrel.to_string();

    if installed_pkgrel > running_pkgrel {
        LayerResult {
            layer: "kernel-installed".to_owned(),
            state: LayerState::RebootPending {
                running: running_str,
                installed: installed_str,
                remedy: "reboot into linux-wintermute (the fix kernel is on /boot already)"
                    .to_owned(),
            },
        }
    } else {
        LayerResult {
            layer: "kernel-installed".to_owned(),
            state: LayerState::Ok,
        }
    }
}

/// Run the prctl probe in a forked child, return the errno (0 = success).
///
/// Uses `unsafe` for `libc::fork`, `libc::prctl`, and `libc::_exit`:
/// - `fork()` is async-signal-safe.
/// - Between fork and _exit, only async-signal-safe calls are made (no
///   allocator, no stdio, no panic machinery).
/// - `prctl(PR_GET_AGENT_SESSION_ID, ...)` is the intentional probe operation.
/// - `_exit()` terminates the child without flushing stdio.
///
/// This is the single documented unsafe block in this module. The parent
/// process's agent_session is unchanged because the call runs exclusively
/// in the child.
#[allow(unsafe_code)]
fn probe_prctl_in_child() -> i32 {
    // SAFETY: fork() is async-signal-safe. We call only prctl + _exit in the
    // child — no allocator, no stdio, no panic machinery.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // fork failed; treat as if prctl unsupported
        return libc::EINVAL;
    }
    if pid == 0 {
        // Child: call prctl and exit with the errno.
        // Probe with PR_GET_AGENT_SESSION_ID and a valid stack buffer: it
        // succeeds unprivileged when the kernel has agentns, and returns
        // EINVAL when it does not. (PR_SET_AGENT_NS is unsuitable as a
        // probe — it needs privilege, so EPERM would be ambiguous.)
        // SAFETY: stack buffer outlives the call; remaining args are 0.
        // _exit is async-signal-safe.
        let mut id_buf = [0u8; AGENT_NS_ID_BYTES];
        let ret = unsafe {
            libc::prctl(
                PR_GET_AGENT_SESSION_ID,
                id_buf.as_mut_ptr() as usize,
                0usize,
                0usize,
                0usize,
            )
        };
        let child_errno = if ret == 0 {
            0
        } else {
            // SAFETY: errno() is safe to call in child after a single syscall.
            unsafe { *libc::__errno_location() }
        };
        // SAFETY: _exit is async-signal-safe and does not flush stdio.
        unsafe { libc::_exit(child_errno & 0xFF) };
    }
    // Parent: wait for child exit status
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid on a known child pid is safe.
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited < 0 {
        return libc::EINVAL;
    }
    // WEXITSTATUS gives the low 8 bits we encoded
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        libc::EINVAL
    }
}

fn check_kernel_prctl() -> LayerResult {
    let errno = probe_prctl_in_child();
    if errno == 0 {
        return LayerResult {
            layer: "kernel-prctl".to_owned(),
            state: LayerState::Ok,
        };
    }
    LayerResult {
        layer: "kernel-prctl".to_owned(),
        state: LayerState::KernelLacksPrctl {
            errno,
            remedy: "install linux-wintermute pkgrel >= 12 and reboot".to_owned(),
        },
    }
}

fn check_launcher_installed(opts: &ActivationOptions) -> LayerResult {
    let home = match &opts.home_override {
        Some(h) => h.clone(),
        None => match std::env::var("HOME") {
            Ok(h) => PathBuf::from(h),
            Err(_) => {
                return LayerResult {
                    layer: "launcher-installed".to_owned(),
                    state: LayerState::LauncherMissing {
                        path: "~/.local/bin/agentns-claude".to_owned(),
                        remedy: "run agentns-claude install.sh".to_owned(),
                    },
                };
            }
        },
    };

    let launcher = home.join(".local/bin/agentns-claude");
    let launcher_str = launcher.display().to_string();

    if !launcher.exists() {
        return LayerResult {
            layer: "launcher-installed".to_owned(),
            state: LayerState::LauncherMissing {
                path: launcher_str,
                remedy: "run agentns-claude install.sh".to_owned(),
            },
        };
    }

    // Check executable bit
    let is_exec = fs::metadata(&launcher)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false);
    if !is_exec {
        return LayerResult {
            layer: "launcher-installed".to_owned(),
            state: LayerState::LauncherMissing {
                path: launcher_str,
                remedy: "chmod +x ~/.local/bin/agentns-claude".to_owned(),
            },
        };
    }

    // Check cap_sys_admin via getcap
    let has_cap = check_cap_sys_admin(&launcher);
    if has_cap {
        LayerResult {
            layer: "launcher-installed".to_owned(),
            state: LayerState::Ok,
        }
    } else {
        LayerResult {
            layer: "launcher-installed".to_owned(),
            state: LayerState::LauncherUncapped {
                path: launcher_str,
                remedy: "sudo setcap cap_sys_admin=ep ~/.local/bin/agentns-claude".to_owned(),
            },
        }
    }
}

/// Check if a binary has cap_sys_admin=ep via `getcap`.
fn check_cap_sys_admin(path: &Path) -> bool {
    match Command::new("getcap").arg(path).output() {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout);
            out.contains("cap_sys_admin") && out.contains("=ep")
        }
        Err(_) => false,
    }
}

fn check_launcher_wired(opts: &ActivationOptions) -> LayerResult {
    let rc_path = match &opts.rc_file_override {
        Some(p) => p.clone(),
        None => {
            let home = match std::env::var("HOME") {
                Ok(h) => PathBuf::from(h),
                Err(_) => {
                    return LayerResult {
                        layer: "launcher-wired".to_owned(),
                        state: LayerState::Ok,
                    };
                }
            };
            home.join(".zshrc")
        }
    };

    match parse_rc_for_no_unshare(&rc_path) {
        Ok(true) => LayerResult {
            layer: "launcher-wired".to_owned(),
            state: LayerState::WrapperForcesSynth {
                remedy:
                    "remove --no-unshare from the claude() shell function (see PRD-agentns-launch-flip)"
                        .to_owned(),
            },
        },
        Ok(false) => LayerResult {
            layer: "launcher-wired".to_owned(),
            state: LayerState::Ok,
        },
        Err(_) => {
            // rc file unreadable — assume not wired with --no-unshare
            LayerResult {
                layer: "launcher-wired".to_owned(),
                state: LayerState::Ok,
            }
        }
    }
}

/// Returns true if the claude() function in the rc file contains `--no-unshare`.
fn parse_rc_for_no_unshare(rc_path: &Path) -> io::Result<bool> {
    let content = fs::read_to_string(rc_path)?;
    // Find the claude() function block and scan for --no-unshare
    let mut in_claude_fn = false;
    let mut brace_depth: i32 = 0;
    for line in content.lines() {
        let trimmed = line.trim();
        if !in_claude_fn {
            // Look for claude() function definition
            if trimmed.starts_with("claude()")
                || trimmed.starts_with("function claude")
                || trimmed.starts_with("claude ()")
            {
                in_claude_fn = true;
            }
        }
        if in_claude_fn {
            for ch in line.chars() {
                if ch == '{' {
                    brace_depth += 1;
                } else if ch == '}' {
                    brace_depth -= 1;
                }
            }
            if line.contains("--no-unshare") {
                return Ok(true);
            }
            if in_claude_fn && brace_depth <= 0 && brace_depth != i32::MAX {
                // Exited the function block
                in_claude_fn = false;
                brace_depth = 0;
            }
        }
    }
    // Also check outside any function — if --no-unshare appears in a non-function
    // context (e.g. alias or sourced wrapper), flag it
    if content.contains("--no-unshare") {
        return Ok(true);
    }
    Ok(false)
}

fn check_live_session(opts: &ActivationOptions) -> (LayerResult, Option<String>) {
    let proc_root = opts
        .proc_root
        .as_deref()
        .unwrap_or_else(|| Path::new("/proc"));
    let session_path = proc_root.join("self/agent_session");

    let session_val = match fs::read_to_string(&session_path) {
        Ok(s) => s.trim().to_owned(),
        Err(_) => {
            // Surface absent — kernel lacks support; treat as zero
            let state = LayerState::SessionZero {
                remedy: "boot into linux-wintermute pkgrel >= 12".to_owned(),
            };
            return (
                LayerResult {
                    layer: "live-session".to_owned(),
                    state,
                },
                None,
            );
        }
    };

    let is_nonzero = session_val.len() == 32
        && session_val.chars().all(|c| c.is_ascii_hexdigit())
        && session_val != "00000000000000000000000000000000";

    if is_nonzero {
        (
            LayerResult {
                layer: "live-session".to_owned(),
                state: LayerState::Ok,
            },
            Some(session_val),
        )
    } else {
        (
            LayerResult {
                layer: "live-session".to_owned(),
                state: LayerState::SessionZero {
                    remedy: "ensure agentns-claude launcher wraps the process".to_owned(),
                },
            },
            Some(session_val),
        )
    }
}

/// Write a temp file, read `getfattr -n user.prov.session`, return stamp state.
fn check_downstream_stamp() -> (LayerResult, Option<String>) {
    // Create a temp file to probe
    let tmp_path = {
        let mut p = std::env::temp_dir();
        p.push(format!("agentns-stamp-probe-{}", std::process::id()));
        p
    };

    // Create the file
    if fs::write(&tmp_path, b"").is_err() {
        let result = LayerResult {
            layer: "downstream-stamp".to_owned(),
            state: LayerState::StampUnavailable {
                reason: "cannot create probe file".to_owned(),
            },
        };
        return (result, Some("unavailable".to_owned()));
    }

    // Run getfattr
    let getfattr_out = Command::new("getfattr")
        .args(["-n", "user.prov.session", "--only-values"])
        .arg(&tmp_path)
        .output();

    // Clean up temp file
    let _ = fs::remove_file(&tmp_path);

    match getfattr_out {
        Err(_) => {
            let result = LayerResult {
                layer: "downstream-stamp".to_owned(),
                state: LayerState::StampUnavailable {
                    reason: "getfattr not available".to_owned(),
                },
            };
            (result, Some("unavailable".to_owned()))
        }
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout).trim().to_owned();
            if out.is_empty() || !o.status.success() {
                // No xattr stamped at all
                let result = LayerResult {
                    layer: "downstream-stamp".to_owned(),
                    state: LayerState::StampUnavailable {
                        reason: "no user.prov.session xattr on probe file".to_owned(),
                    },
                };
                (result, Some("unavailable".to_owned()))
            } else if out.starts_with("comm:") || out.starts_with("pid:") {
                let fallback = out.clone();
                let result = LayerResult {
                    layer: "downstream-stamp".to_owned(),
                    state: LayerState::StampFallback {
                        fallback,
                        remedy: "boot into linux-wintermute with active agentns session"
                            .to_owned(),
                    },
                };
                (result, Some("fallback".to_owned()))
            } else {
                // Real agentns session id
                let session_id = out.clone();
                let result = LayerResult {
                    layer: "downstream-stamp".to_owned(),
                    state: LayerState::StampReal { session_id },
                };
                (result, Some("real".to_owned()))
            }
        }
    }
}

// ── Top-level evaluator ──────────────────────────────────────────────────────

/// Accumulated evaluation context; passed through each layer check.
struct EvalCtx {
    layers: Vec<LayerResult>,
    running_pkgrel: Option<String>,
    installed_pkgrel: Option<String>,
}

impl EvalCtx {
    fn new() -> Self {
        Self {
            layers: Vec::new(),
            running_pkgrel: None,
            installed_pkgrel: None,
        }
    }

    /// Push a layer; return `Some(ActivationResult)` if it blocks (caller should return it).
    fn push_or_block(
        &mut self,
        layer: LayerResult,
        agent_session: Option<String>,
        stamp_form: Option<String>,
    ) -> Option<ActivationResult> {
        if layer.state.is_blocked() {
            let blocked_layer = Some(layer.layer.clone());
            let remedy = layer.state.remedy().map(str::to_owned);
            self.layers.push(layer);
            Some(ActivationResult {
                layers: std::mem::take(&mut self.layers),
                blocked_layer,
                remedy,
                running_pkgrel: self.running_pkgrel.take(),
                installed_pkgrel: self.installed_pkgrel.take(),
                agent_session,
                stamp_form,
            })
        } else {
            self.layers.push(layer);
            None
        }
    }
}

/// Collect the pkgrel top-level fields by re-running the same queries as `check_kernel_installed`.
fn collect_pkgrels(opts: &ActivationOptions) -> (Option<String>, Option<String>) {
    let uname_out = match &opts.uname_override {
        Some(s) => Some(s.clone()),
        None => Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned()),
    };
    let pacman_out = match &opts.pacman_bin_override {
        Some(bin) => Command::new(bin)
            .args(["linux-wintermute"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned()),
        None => Command::new("pacman")
            .args(["-Q", "linux-wintermute"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned()),
    };
    let running = uname_out
        .as_deref()
        .and_then(parse_uname_pkgrel)
        .map(|n| n.to_string());
    let installed = pacman_out
        .as_deref()
        .and_then(parse_pacman_pkgrel)
        .map(|n| n.to_string());
    (running, installed)
}

/// Run the full activation chain and return the result.
///
/// Short-circuits at the first blocking layer (layers 1–5).
/// Layer 6 (downstream-stamp) runs only when layer 5 passes.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn evaluate(opts: &ActivationOptions) -> ActivationResult {
    let mut ctx = EvalCtx::new();
    (ctx.running_pkgrel, ctx.installed_pkgrel) = collect_pkgrels(opts);

    // Layer 1: kernel-installed
    if let Some(r) = ctx.push_or_block(check_kernel_installed(opts), None, None) {
        return r;
    }
    // Layer 2: kernel-prctl
    if let Some(r) = ctx.push_or_block(check_kernel_prctl(), None, None) {
        return r;
    }
    // Layer 3: launcher-installed
    if let Some(r) = ctx.push_or_block(check_launcher_installed(opts), None, None) {
        return r;
    }
    // Layer 4: launcher-wired
    if let Some(r) = ctx.push_or_block(check_launcher_wired(opts), None, None) {
        return r;
    }
    // Layer 5: live-session
    let (live_layer, session_val) = check_live_session(opts);
    if let Some(r) = ctx.push_or_block(live_layer, session_val.clone(), None) {
        return r;
    }
    // Layer 6: downstream-stamp (only when live)
    let (stamp_layer, stamp_form) = check_downstream_stamp();
    ctx.layers.push(stamp_layer);

    ActivationResult {
        layers: ctx.layers,
        blocked_layer: None,
        remedy: None,
        running_pkgrel: ctx.running_pkgrel,
        installed_pkgrel: ctx.installed_pkgrel,
        agent_session: session_val,
        stamp_form,
    }
}

// ── Output ───────────────────────────────────────────────────────────────────

/// Print a human-readable activation table + verdict line.
///
/// # Panics
/// Never panics.
#[allow(clippy::print_stdout)]
pub fn print_activation(result: &ActivationResult) {
    println!("{:<20}  {:<10}  {}", "LAYER", "STATE", "DETAIL");
    println!("{}", "-".repeat(70));
    for lr in &result.layers {
        println!(
            "{:<20}  {:<10}  {}",
            lr.layer,
            lr.state.label(),
            lr.state.detail()
        );
    }
    println!();
    match &result.blocked_layer {
        Some(layer) => {
            let remedy = result.remedy.as_deref().unwrap_or("(no remedy)");
            println!("ACTIVATION: BLOCKED at {layer} — {remedy}");
        }
        None => {
            println!("ACTIVATION: LIVE");
        }
    }
}

/// Print JSON activation result.
///
/// # Panics
/// Never panics.
#[allow(clippy::print_stdout)]
pub fn print_activation_json(result: &ActivationResult) {
    let json = serde_json::to_string_pretty(result)
        .unwrap_or_else(|_| r#"{"error":"serialization_failed"}"#.to_owned());
    println!("{json}");
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uname_pkgrel_standard() {
        assert_eq!(
            parse_uname_pkgrel("7.0.10-arch1-5-wintermute"),
            Some(5)
        );
    }

    #[test]
    fn parse_uname_pkgrel_higher() {
        assert_eq!(
            parse_uname_pkgrel("7.0.10-arch1-12-wintermute"),
            Some(12)
        );
    }

    #[test]
    fn parse_uname_pkgrel_stock_kernel() {
        // Stock kernel — no -wintermute suffix
        assert_eq!(parse_uname_pkgrel("6.11.0-25-generic"), None);
    }

    #[test]
    fn parse_pacman_pkgrel_standard() {
        assert_eq!(
            parse_pacman_pkgrel("linux-wintermute 7.0.10.arch1-12"),
            Some(12)
        );
    }

    #[test]
    fn parse_pacman_pkgrel_low() {
        assert_eq!(
            parse_pacman_pkgrel("linux-wintermute 7.0.10.arch1-5"),
            Some(5)
        );
    }

    #[test]
    fn parse_rc_no_unshare_found() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            "claude() {{\n  exec agentns-claude --no-unshare -- claude \"$@\"\n}}"
        )
        .unwrap();
        assert!(parse_rc_for_no_unshare(f.path()).unwrap());
    }

    #[test]
    fn parse_rc_no_unshare_absent() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            "claude() {{\n  exec agentns-claude -- claude \"$@\"\n}}"
        )
        .unwrap();
        assert!(!parse_rc_for_no_unshare(f.path()).unwrap());
    }
}
