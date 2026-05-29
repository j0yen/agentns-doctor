//! Human-readable explanation generator for `agentns-doctor explain`.

use crate::classify::{AgentState, StatusResult};

/// Print an explanation paragraph to stdout based on the classified state.
#[allow(clippy::print_stdout)]
pub fn print_explain(result: &StatusResult, pid: u32) {
    let text = build_explain(result, pid);
    println!("{text}");
}

/// Build the explanation string (exposed for testing).
#[must_use]
pub fn build_explain(result: &StatusResult, pid: u32) -> String {
    match result.state {
        AgentState::Absent => format!(
            "PID {pid}: The agent_session file is absent under this proc root.\n\
             This means the running kernel has no CLONE_NEWAGENT support — \
             this is a stock (non-wintermute) kernel.\n\
             The agent-namespace subsystem (CONFIG_AGENT_NS) is not compiled in.\n\
             To get agent-namespace support, boot the linux-wintermute kernel."
        ),

        AgentState::Init => format!(
            "PID {pid}: This process is in the initial agent namespace.\n\
             The wintermute kernel (CONFIG_AGENT_NS=y) is present and working; \
             the session id reads all-zeros because nothing called \
             unshare(CLONE_NEWAGENT) on this process's launch path.\n\
             This is expected and not a fault.\n\
             To get a non-zero session id, route the launch through agentns-claude \
             (see PRD-claude-agentns-wrap). A hook cannot fix this post-hoc — \
             unshare is per-process and self-only."
        ),

        AgentState::Live => format!(
            "PID {pid}: This process is in a live agent namespace.\n\
             Session id: {}\n\
             The process was launched via agentns-claude (or equivalent) and \
             received a fresh agent namespace via unshare(CLONE_NEWAGENT).\n\
             The session id is meaningful; agent_counters track syscall activity \
             within this namespace.",
            result.session_id
        ),

        AgentState::Malformed => format!(
            "PID {pid}: The agent_session file exists but contains an unexpected value: {:?}\n\
             Expected either 32 ASCII hex characters (all-zero for init ns, \
             or non-zero for a live ns).\n\
             This is a genuine anomaly. The kernel surface may be corrupt or \
             written by an unexpected actor. Inspect the raw file and report \
             the issue to the wintermute kernel maintainer.",
            result.session_id
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{AgentState, StatusResult, Verdict};

    fn make_result(state: AgentState, session_id: &str, verdict: Verdict) -> StatusResult {
        StatusResult {
            state,
            session_id: session_id.to_owned(),
            session_nonzero: !session_id.chars().all(|c| c == '0'),
            ns_inode: Some(4_026_531_996),
            intent_tag: None,
            pid: 1234,
            verdict,
        }
    }

    #[test]
    fn explain_init_contains_expected_substrings() {
        let r = make_result(
            AgentState::Init,
            "00000000000000000000000000000000",
            Verdict::UnwrappedExpected,
        );
        let text = build_explain(&r, 1234);
        assert!(
            text.contains("initial agent namespace"),
            "expected 'initial agent namespace' in: {text}"
        );
        assert!(
            text.contains("not a fault"),
            "expected 'not a fault' in: {text}"
        );
        assert!(
            text.contains("agentns-claude"),
            "expected 'agentns-claude' in: {text}"
        );
    }

    #[test]
    fn explain_live_contains_session_id() {
        let session = "deadbeefcafe0123456789abcdef0001";
        let r = make_result(AgentState::Live, session, Verdict::Wrapped);
        let text = build_explain(&r, 1234);
        assert!(
            text.contains(session),
            "expected session id in live explain: {text}"
        );
        assert!(
            !text.contains("not a fault"),
            "live explain should not contain 'not a fault'"
        );
    }

    #[test]
    fn explain_absent_mentions_kernel() {
        let r = make_result(AgentState::Absent, "", Verdict::KernelAbsent);
        let text = build_explain(&r, 1234);
        assert!(
            text.contains("CLONE_NEWAGENT"),
            "expected CLONE_NEWAGENT in absent explain"
        );
    }
}
