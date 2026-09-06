// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! A subagent may never hold a tool its parent does not hold. This is the agent
//! equivalent of privilege escalation, and it is fully deterministic.

use std::collections::{BTreeSet, HashMap};

use crate::event::{AgentId, SessionId};

/// A subagent asked for tools its parent does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escalation {
    pub agent: AgentId,
    pub parent: AgentId,
    /// The tools beyond the parent's grant, sorted.
    pub extra: Vec<String>,
}

/// Per-session record of which agent holds which tools.
#[derive(Debug, Default)]
pub struct Authority {
    grants: HashMap<SessionId, HashMap<AgentId, BTreeSet<String>>>,
}

impl Authority {
    /// Register the top-level agent's tool grant. Everything else descends from this.
    pub fn set_root(&mut self, session: &str, agent: &str, tools: &[String]) {
        self.grants
            .entry(session.to_string())
            .or_default()
            .insert(agent.to_string(), tools.iter().cloned().collect());
    }

    /// Register a spawn. Returns `Some(Escalation)` when the child asked for more than
    /// the parent holds; in that case the child is NOT registered.
    pub fn spawn(
        &mut self,
        session: &str,
        parent: &str,
        child: &str,
        requested: &[String],
    ) -> Option<Escalation> {
        let session_grants = self.grants.entry(session.to_string()).or_default();
        let parent_tools = session_grants.get(parent).cloned().unwrap_or_default();
        let requested: BTreeSet<String> = requested.iter().cloned().collect();

        let extra: Vec<String> = requested.difference(&parent_tools).cloned().collect();
        if !extra.is_empty() {
            return Some(Escalation {
                agent: child.to_string(),
                parent: parent.to_string(),
                extra,
            });
        }
        session_grants.insert(child.to_string(), requested);
        None
    }

    /// Does this agent hold this tool?
    pub fn holds(&self, session: &str, agent: &str, tool: &str) -> bool {
        self.grants
            .get(session)
            .and_then(|s| s.get(agent))
            .is_some_and(|t| t.contains(tool))
    }

    pub fn end_session(&mut self, session: &str) {
        self.grants.remove(session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_subset_grant_is_contained() {
        let mut a = Authority::default();
        a.set_root("s1", "main", &tools(&["Read", "Bash", "WebFetch"]));
        assert_eq!(
            a.spawn("s1", "main", "osint-agent", &tools(&["Read", "WebFetch"])),
            None
        );
    }

    #[test]
    fn an_equal_grant_is_contained() {
        let mut a = Authority::default();
        a.set_root("s1", "main", &tools(&["Read"]));
        assert_eq!(a.spawn("s1", "main", "child", &tools(&["Read"])), None);
    }

    #[test]
    fn requesting_a_tool_the_parent_lacks_is_escalation() {
        let mut a = Authority::default();
        a.set_root("s1", "main", &tools(&["Read"]));
        let esc = a
            .spawn("s1", "main", "child", &tools(&["Read", "Bash"]))
            .expect("escalation");
        assert_eq!(esc.agent, "child");
        assert_eq!(esc.extra, tools(&["Bash"]));
    }

    #[test]
    fn escalation_is_detected_transitively_through_a_chain() {
        let mut a = Authority::default();
        a.set_root("s1", "main", &tools(&["Read", "Bash"]));
        assert_eq!(a.spawn("s1", "main", "child", &tools(&["Read"])), None);
        // Grandchild asks for Bash, which the *parent* (child) does not hold,
        // even though the root does.
        let esc = a
            .spawn("s1", "child", "grandchild", &tools(&["Bash"]))
            .expect("escalation");
        assert_eq!(esc.extra, tools(&["Bash"]));
    }

    #[test]
    fn an_unknown_parent_grants_nothing() {
        let mut a = Authority::default();
        let esc = a
            .spawn("s1", "ghost", "child", &tools(&["Read"]))
            .expect("escalation");
        assert_eq!(esc.extra, tools(&["Read"]));
    }

    #[test]
    fn a_contained_spawn_registers_the_child_grant() {
        let mut a = Authority::default();
        a.set_root("s1", "main", &tools(&["Read", "Bash"]));
        a.spawn("s1", "main", "child", &tools(&["Read"]));
        assert!(a.holds("s1", "child", "Read"));
        assert!(!a.holds("s1", "child", "Bash"));
    }

    #[test]
    fn sessions_are_isolated() {
        let mut a = Authority::default();
        a.set_root("s1", "main", &tools(&["Read"]));
        assert!(!a.holds("s2", "main", "Read"));
        a.end_session("s1");
        assert!(!a.holds("s1", "main", "Read"));
    }

    // --- Hazard 2: a rejected spawn must not register the child at all. ---
    #[test]
    fn a_rejected_spawn_does_not_register_the_child() {
        let mut a = Authority::default();
        a.set_root("s1", "main", &tools(&["Read"]));
        let esc = a
            .spawn("s1", "main", "child", &tools(&["Read", "Bash"]))
            .expect("escalation");
        assert_eq!(esc.extra, tools(&["Bash"]));
        assert!(!a.holds("s1", "child", "Read"));
        assert!(!a.holds("s1", "child", "Bash"));
    }

    // --- Hazard 1: an unregistered parent (set_root never called for this session
    // at all) must still be treated as holding nothing, not as a free pass.
    #[test]
    fn a_completely_unregistered_session_grants_nothing() {
        let mut a = Authority::default();
        // No set_root call for "s1" at all.
        let esc = a
            .spawn("s1", "main", "child", &tools(&["Read"]))
            .expect("escalation");
        assert_eq!(esc.extra, tools(&["Read"]));
        assert!(!a.holds("s1", "child", "Read"));
    }

    // --- Hazard 5: an empty grant set is contained under any parent, including
    // an unknown one — the empty set is a subset of everything.
    #[test]
    fn an_empty_grant_is_contained_even_from_an_unknown_parent() {
        let mut a = Authority::default();
        assert_eq!(a.spawn("s1", "ghost", "child", &tools(&[])), None);
        // The child is registered with an empty grant, so it still holds nothing.
        assert!(!a.holds("s1", "child", "Read"));
    }

    // --- Hazard 4: duplicate spawns / re-registration overwrite, they don't merge. ---
    #[test]
    fn a_second_spawn_with_the_same_child_name_overwrites_the_first_grant() {
        let mut a = Authority::default();
        a.set_root("s1", "main", &tools(&["Read", "Bash"]));
        assert_eq!(a.spawn("s1", "main", "child", &tools(&["Read"])), None);
        assert!(a.holds("s1", "child", "Read"));
        assert!(!a.holds("s1", "child", "Bash"));
        // Respawn the same name with a different (still-contained) grant.
        assert_eq!(a.spawn("s1", "main", "child", &tools(&["Bash"])), None);
        assert!(a.holds("s1", "child", "Bash"));
        assert!(
            !a.holds("s1", "child", "Read"),
            "the second spawn should overwrite, not merge with, the first"
        );
    }
}
