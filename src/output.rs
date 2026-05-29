//! Output formatters for `status` and `counters` subcommands.

use crate::classify::StatusResult;
use crate::counters::CountersResult;

/// Print the status result in either text or JSON format.
///
/// # Panics
/// Never panics — JSON serialisation of `StatusResult` is infallible for this type.
#[allow(clippy::print_stdout)]
pub fn print_status(result: &StatusResult, format: &str) {
    if format == "json" {
        let json = serde_json::to_string_pretty(result)
            .unwrap_or_else(|_| r#"{"error":"serialization_failed"}"#.to_owned());
        println!("{json}");
    } else {
        println!("state:        {}", result.state);
        println!(
            "session_id:   {}",
            if result.session_id.is_empty() {
                "(none)"
            } else {
                &result.session_id
            }
        );
        println!(
            "ns_inode:     {}",
            result
                .ns_inode
                .map_or_else(|| "(unavailable)".to_owned(), |i| i.to_string())
        );
        println!("pid:          {}", result.pid);
        println!("verdict:      {}", result.verdict);
        let verdict_text = match result.verdict {
            crate::classify::Verdict::KernelAbsent => {
                "Stock kernel — no CLONE_NEWAGENT support."
            }
            crate::classify::Verdict::UnwrappedExpected => {
                "Unwrapped — expected until launches route through agentns-claude."
            }
            crate::classify::Verdict::Wrapped => "Wrapped — live agent namespace session.",
            crate::classify::Verdict::MalformedSurface => {
                "Malformed — unexpected agent_session value."
            }
        };
        println!("detail:       {verdict_text}");
    }
}

/// Print the counters result in either text or JSON format.
///
/// # Panics
/// Never panics.
#[allow(clippy::print_stdout)]
pub fn print_counters(result: &CountersResult, format: &str) {
    if format == "json" {
        let json = serde_json::to_string_pretty(result)
            .unwrap_or_else(|_| r#"{"error":"serialization_failed"}"#.to_owned());
        println!("{json}");
    } else {
        println!("pid:             {}", result.pid);
        println!("total_syscalls:  {}", result.sample.total_syscalls);
        println!("openat_count:    {}", result.sample.openat_count);
        println!("write_bytes:     {}", result.sample.write_bytes);
        println!("connect_count:   {}", result.sample.connect_count);
        println!("unlink_count:    {}", result.sample.unlink_count);
        println!("fork_count:      {}", result.sample.fork_count);
        println!("elapsed_ns:      {}", result.sample.elapsed_ns);
        if let Some(delta) = &result.delta {
            println!("--- delta ({}ms) ---", result.delta_ms.unwrap_or(0));
            println!("Δtotal_syscalls: {}", delta.total_syscalls);
            println!("Δopenat_count:   {}", delta.openat_count);
            println!("Δwrite_bytes:    {}", delta.write_bytes);
            println!("Δconnect_count:  {}", delta.connect_count);
            println!("Δunlink_count:   {}", delta.unlink_count);
            println!("Δfork_count:     {}", delta.fork_count);
            println!("Δelapsed_ns:     {}", delta.elapsed_ns);
        }
        if let Some(note) = &result.note {
            println!("note:            {note}");
        }
    }
}
