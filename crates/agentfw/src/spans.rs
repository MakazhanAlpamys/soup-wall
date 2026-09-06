// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! A bounded per-session cache of untrusted content, keyed by the sequence number of
//! the event that introduced it.
//!
//! The judge (see `judge.rs`) judges content rather than actions, but `TaintMark`
//! records only a source and a sequence number — the taint tracker keeps 8-byte
//! fingerprints so it stays bounded. This fills that gap on the daemon side, so
//! `crates/agent` does not have to carry content it has no use for.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Truncate on a UTF-8 boundary at or below `max` bytes.
fn clamp(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[derive(Default)]
struct SessionSpans {
    by_seq: HashMap<u64, String>,
    order: VecDeque<u64>,
}

/// Bounded per-session store of untrusted content.
///
/// `cap` entries per session, each truncated to `max_bytes`. Both bounds matter: this
/// holds attacker-influenced content in memory on a long-running daemon.
pub struct SpanCache {
    cap: usize,
    max_bytes: usize,
    sessions: Mutex<HashMap<String, SessionSpans>>,
}

impl SpanCache {
    pub fn new(cap: usize, max_bytes: usize) -> Self {
        Self {
            cap,
            max_bytes,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn put(&self, session: &str, seq: u64, content: &str) {
        let Ok(mut m) = self.sessions.lock() else {
            return;
        };
        let e = m.entry(session.to_string()).or_default();
        let is_new = e
            .by_seq
            .insert(seq, clamp(content, self.max_bytes).to_string())
            .is_none();
        // Only push to the eviction queue for a genuinely new seq. Pushing
        // unconditionally — as a naive version of this cache would — lets a seq
        // that gets `put` repeatedly (e.g. the same tainted event re-inspected
        // within a session) accumulate duplicate entries in `order` forever:
        // `order.len()` would grow without bound even though `by_seq` stays
        // capped at one entry per distinct seq. Each stale duplicate popped off
        // the front would then remove-by-seq from `by_seq` again (a no-op once
        // the seq is already gone) while still counting as an eviction, so a
        // hot seq being re-put would silently push OTHER, genuinely distinct
        // seqs in the same session out of the cache far sooner than `cap`
        // implies. Re-`put`ting an existing seq instead just refreshes its
        // value in place, with no eviction-order effect — reasonable, since it
        // hasn't gone stale by being seen again.
        if is_new {
            e.order.push_back(seq);
            while e.order.len() > self.cap {
                if let Some(old) = e.order.pop_front() {
                    e.by_seq.remove(&old);
                }
            }
        }
    }

    pub fn get(&self, session: &str, seq: u64) -> Option<String> {
        let m = self.sessions.lock().ok()?;
        m.get(session)?.by_seq.get(&seq).cloned()
    }

    pub fn end_session(&self, session: &str) {
        if let Ok(mut m) = self.sessions.lock() {
            m.remove(session);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_retrieves_by_sequence_number() {
        let c = SpanCache::new(4, 100);
        c.put("s1", 7, "poisoned text");
        assert_eq!(c.get("s1", 7).as_deref(), Some("poisoned text"));
    }

    #[test]
    fn an_absent_entry_is_none() {
        let c = SpanCache::new(4, 100);
        assert!(c.get("s1", 1).is_none());
    }

    #[test]
    fn sessions_are_isolated() {
        let c = SpanCache::new(4, 100);
        c.put("s1", 1, "a");
        assert!(c.get("s2", 1).is_none());
    }

    #[test]
    fn content_is_truncated_on_a_utf8_boundary() {
        let c = SpanCache::new(4, 5);
        c.put("s1", 1, &"α".repeat(10));
        let got = c.get("s1", 1).unwrap();
        assert!(got.len() <= 5);
        assert!(std::str::from_utf8(got.as_bytes()).is_ok());
    }

    #[test]
    fn the_oldest_entry_is_evicted_at_capacity() {
        let c = SpanCache::new(2, 100);
        c.put("s1", 1, "one");
        c.put("s1", 2, "two");
        c.put("s1", 3, "three");
        assert!(c.get("s1", 1).is_none(), "seq 1 should have been evicted");
        assert!(c.get("s1", 3).is_some());
    }

    #[test]
    fn ending_a_session_drops_its_spans() {
        let c = SpanCache::new(4, 100);
        c.put("s1", 1, "a");
        c.end_session("s1");
        assert!(c.get("s1", 1).is_none());
    }

    #[test]
    fn putting_the_same_seq_twice_does_not_grow_the_eviction_queue_unboundedly() {
        // The plan's reference code pushes to `order` unconditionally on every
        // `put`, even when the seq already has an entry. Re-fetching the same
        // tainted event N times (e.g. the same tool result inspected repeatedly
        // within a session) would then let `order` grow past `cap` while
        // `by_seq` still holds only one entry per distinct seq — an unbounded
        // memory leak in the queue even though the map itself stays bounded.
        // Cap is 2: putting seq 1 three times must not evict it via its own
        // stale duplicate order entries, and a distinct seq 2 must still fit.
        let c = SpanCache::new(2, 100);
        c.put("s1", 1, "one-a");
        c.put("s1", 1, "one-b");
        c.put("s1", 1, "one-c");
        c.put("s1", 2, "two");
        assert_eq!(
            c.get("s1", 1).as_deref(),
            Some("one-c"),
            "seq 1 must still be present and hold the latest value"
        );
        assert_eq!(c.get("s1", 2).as_deref(), Some("two"));
    }
}
