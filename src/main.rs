//! agentns-doctor — read-only CLI to classify a process's agent-namespace state.
//!
//! Reads `/proc/<pid>/agent_session`, `/proc/<pid>/ns/agent`, and
//! `/proc/<pid>/agent_counters` then classifies the process into one of:
//! `absent`, `init`, `live`, or `malformed`.
//!
//! Exit codes:
//! - 0: healthy (absent, init, or live)
//! - 2: kernel surface absent when `--expect-kernel` was passed
//! - 3: malformed surface

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod classify;
mod counters;
mod explain;
mod output;
mod proc_reader;

pub use classify::{AgentState, StatusResult};
pub use counters::CountersResult;
pub use proc_reader::ProcReader;

/// Classify a process's agent-namespace state from /proc surfaces.
#[derive(Parser, Debug)]
#[command(name = "agentns-doctor", version = "0.1.0", author)]
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
}

fn main() {
    let cli = Cli::parse();
    let exit_code = run(cli);
    std::process::exit(exit_code);
}

fn run(cli: Cli) -> i32 {
    match cli.command {
        Commands::Status {
            pid,
            format,
            proc_root,
            expect_kernel,
        } => {
            let reader = ProcReader::new(proc_root);
            let target_pid = pid.unwrap_or_else(|| {
                std::process::id()
            });
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
            let target_pid = pid.unwrap_or_else(|| {
                std::process::id()
            });
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
        Commands::Explain {
            pid,
            proc_root,
        } => {
            let reader = ProcReader::new(proc_root);
            let target_pid = pid.unwrap_or_else(|| {
                std::process::id()
            });
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
    }
}
