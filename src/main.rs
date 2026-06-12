//! agentns-doctor — read-only CLI to classify a process's agent-namespace state.
//!
//! Reads `/proc/<pid>/agent_session`, `/proc/<pid>/ns/agent`, and
//! `/proc/<pid>/agent_counters` then classifies the process into one of:
//! `absent`, `init`, `live`, or `malformed`.
//!
//! Also provides a `receipt` subcommand to snapshot counters to a JSON ledger.
//!
//! Exit codes:
//! - 0: healthy (absent, init, or live)
//! - 2: kernel surface absent when `--expect-kernel` was passed,
//!      or init-ns session with `receipt --emit --require-wrapped`
//! - 3: malformed surface

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod activation;
mod classify;
mod counters;
mod explain;
mod output;
mod proc_reader;
mod receipt;

pub use classify::{AgentState, StatusResult};
pub use counters::CountersResult;
pub use proc_reader::ProcReader;

/// Classify a process's agent-namespace state from /proc surfaces.
#[derive(Parser, Debug)]
#[command(name = "agentns-doctor", version, author)]
#[command(about = "Read-only diagnostic for agent-namespace state")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Classify the process's agent-namespace state (absent/init/live/malformed).
    Status {
        /// PID to inspect (default: self).
        #[arg(long)]
        pid: Option<u32>,

        /// Output format.
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,

        /// Redirect /proc reads to this directory (for testing with fixtures).
        #[arg(long)]
        proc_root: Option<PathBuf>,

        /// Return exit code 2 when the kernel surface (agent_session) is absent.
        #[arg(long)]
        expect_kernel: bool,
    },

    /// Read and display agent-namespace syscall counters.
    Counters {
        /// PID to inspect (default: self).
        #[arg(long)]
        pid: Option<u32>,

        /// Output format.
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,

        /// Sample twice with this delay (ms) and show per-counter deltas.
        #[arg(long)]
        delta: Option<u64>,

        /// Redirect /proc reads to this directory (for testing with fixtures).
        #[arg(long)]
        proc_root: Option<PathBuf>,
    },

    /// Print a human-readable explanation of the current agent-namespace state.
    Explain {
        /// PID to inspect (default: self).
        #[arg(long)]
        pid: Option<u32>,

        /// Redirect /proc reads to this directory (for testing with fixtures).
        #[arg(long)]
        proc_root: Option<PathBuf>,
    },

    /// Evaluate the full continuity-activation chain and report the first blocking layer.
    Activation {
        /// Emit JSON instead of the human table.
        #[arg(long)]
        json: bool,
    },

    /// Snapshot agent-namespace counters to a JSON ledger (session receipt).
    ///
    /// Subcommands:
    ///   --emit             Snapshot counters for pid to ~/.cache/agentns/receipts/<sid>.json
    ///   --list             List receipts, newest first
    ///   --show <sid>       Print one receipt by session id prefix
    ///   --join-ctrace <sid> Join receipt with ctrace histogram
    ///
    /// --require-wrapped exits 2 without writing anything when state is init/absent.
    Receipt {
        /// Emit a receipt for the process (write to ~/.cache/agentns/receipts/<sid>.json).
        #[arg(long, conflicts_with_all = ["list", "show", "join_ctrace"])]
        emit: bool,

        /// List receipts, newest first.
        #[arg(long, conflicts_with_all = ["emit", "show", "join_ctrace"])]
        list: bool,

        /// Show one receipt by session id prefix.
        #[arg(long, conflicts_with_all = ["emit", "list", "join_ctrace"])]
        show: Option<String>,

        /// Join a receipt with ctrace histogram data.
        #[arg(long, conflicts_with_all = ["emit", "list", "show"])]
        join_ctrace: Option<String>,

        /// PID to inspect (default: self). Only used with --emit.
        #[arg(long)]
        pid: Option<u32>,

        /// Exit 2 and write nothing when the session is in init/absent namespace.
        #[arg(long)]
        require_wrapped: bool,

        /// Output format for --list and --show.
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,

        /// Redirect /proc reads to this directory (for testing with fixtures).
        #[arg(long)]
        proc_root: Option<PathBuf>,

        /// Override receipts directory (for testing).
        #[arg(long)]
        receipts_dir: Option<PathBuf>,

        /// Override ctrace sessions directory (for testing).
        #[arg(long)]
        ctrace_dir: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    let exit_code = run(cli);
    std::process::exit(exit_code);
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
fn run(cli: Cli) -> i32 {
    match cli.command {
        Commands::Activation { json } => {
            let opts = activation::ActivationOptions::from_env();
            let result = activation::evaluate(&opts);
            if json {
                activation::print_activation_json(&result);
            } else {
                activation::print_activation(&result);
            }
            0
        }
        Commands::Status {
            pid,
            format,
            proc_root,
            expect_kernel,
        } => {
            let reader = ProcReader::new(proc_root);
            let target_pid = pid.unwrap_or_else(std::process::id);
            match classify::classify(&reader, target_pid) {
                Ok(result) => {
                    output::print_status(&result, &format);
                    match result.state {
                        AgentState::Absent if expect_kernel => 2,
                        AgentState::Malformed => 3,
                        _ => 0,
                    }
                }
                Err(e) => {
                    eprintln!("agentns-doctor: error: {e}");
                    1
                }
            }
        }
        Commands::Counters {
            pid,
            format,
            delta,
            proc_root,
        } => {
            let reader = ProcReader::new(proc_root);
            let target_pid = pid.unwrap_or_else(std::process::id);
            match counters::read_counters(&reader, target_pid, delta) {
                Ok(result) => {
                    output::print_counters(&result, &format);
                    0
                }
                Err(e) => {
                    eprintln!("agentns-doctor: error: {e}");
                    1
                }
            }
        }
        Commands::Explain { pid, proc_root } => {
            let reader = ProcReader::new(proc_root);
            let target_pid = pid.unwrap_or_else(std::process::id);
            match classify::classify(&reader, target_pid) {
                Ok(result) => {
                    explain::print_explain(&result, target_pid);
                    0
                }
                Err(e) => {
                    eprintln!("agentns-doctor: error: {e}");
                    1
                }
            }
        }
        Commands::Receipt {
            emit,
            list,
            show,
            join_ctrace,
            pid,
            require_wrapped,
            format,
            proc_root,
            receipts_dir,
            ctrace_dir,
        } => {
            run_receipt(
                emit,
                list,
                show,
                join_ctrace,
                pid,
                require_wrapped,
                &format,
                proc_root,
                receipts_dir,
                ctrace_dir,
            )
        }
    }
}

#[allow(clippy::print_stdout, clippy::print_stderr, clippy::too_many_arguments)]
fn run_receipt(
    emit: bool,
    list: bool,
    show: Option<String>,
    join_ctrace: Option<String>,
    pid: Option<u32>,
    require_wrapped: bool,
    format: &str,
    proc_root: Option<PathBuf>,
    receipts_dir: Option<PathBuf>,
    ctrace_dir: Option<PathBuf>,
) -> i32 {
    if emit {
        let reader = ProcReader::new(proc_root);
        let target_pid = pid.unwrap_or_else(std::process::id);
        match receipt::emit_receipt(
            &reader,
            target_pid,
            require_wrapped,
            receipts_dir.as_deref(),
        ) {
            Ok(path) => {
                println!("receipt written: {}", path.display());
                0
            }
            Err(receipt::ReceiptError::NotWrapped(msg)) => {
                eprintln!("agentns-doctor receipt: {msg}");
                2
            }
            Err(e) => {
                eprintln!("agentns-doctor receipt: {e}");
                1
            }
        }
    } else if list {
        match receipt::list_receipts(receipts_dir.as_deref()) {
            Ok(rows) => {
                if format == "json" {
                    let json = serde_json::to_string_pretty(&rows)
                        .unwrap_or_else(|_| r#"{"error":"serialization_failed"}"#.to_owned());
                    println!("{json}");
                } else {
                    for row in &rows {
                        let tag = row.intent_tag.as_deref().unwrap_or("-");
                        println!(
                            "{}  {}  syscalls={}  write={}  {}",
                            &row.session_id[..8],
                            tag,
                            row.total_syscalls,
                            row.write_bytes,
                            row.emitted_at
                        );
                    }
                }
                0
            }
            Err(e) => {
                eprintln!("agentns-doctor receipt --list: {e}");
                1
            }
        }
    } else if let Some(sid) = show {
        match receipt::find_receipt(&sid, receipts_dir.as_deref()) {
            Ok(r) => {
                let json = serde_json::to_string_pretty(&r)
                    .unwrap_or_else(|_| r#"{"error":"serialization_failed"}"#.to_owned());
                println!("{json}");
                0
            }
            Err(receipt::ReceiptError::NotFound(msg)) => {
                eprintln!("agentns-doctor receipt --show: {msg}");
                1
            }
            Err(e) => {
                eprintln!("agentns-doctor receipt --show: {e}");
                1
            }
        }
    } else if let Some(sid) = join_ctrace {
        match receipt::join_ctrace(&sid, receipts_dir.as_deref(), ctrace_dir.as_deref()) {
            Ok(result) => {
                let r = &result.receipt;
                let json = serde_json::to_string_pretty(r)
                    .unwrap_or_else(|_| r#"{"error":"serialization_failed"}"#.to_owned());
                println!("{json}");
                if result.ctrace_found {
                    println!(
                        "ctrace: syscalls={}  write_bytes={}",
                        result.ctrace_total_syscalls.unwrap_or(0),
                        result.ctrace_write_bytes.unwrap_or(0)
                    );
                    match &result.divergence_note {
                        None => println!("agreement"),
                        Some(note) => println!("{note}"),
                    }
                } else {
                    println!("no ctrace match for sid '{sid}'");
                }
                0
            }
            Err(receipt::ReceiptError::NotFound(msg)) => {
                eprintln!("agentns-doctor receipt --join-ctrace: {msg}");
                1
            }
            Err(e) => {
                eprintln!("agentns-doctor receipt --join-ctrace: {e}");
                1
            }
        }
    } else {
        eprintln!("agentns-doctor receipt: specify --emit, --list, --show <sid>, or --join-ctrace <sid>");
        1
    }
}
