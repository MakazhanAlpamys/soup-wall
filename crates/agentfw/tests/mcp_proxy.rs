// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! The stdio relay's enforcement decision, exercised through the public API.
//!
//! The full spawn/pump path (`proxy::run`) writes to the process's real stdout, so
//! asserting relayed bytes in-process is brittle; it is verified by hand per the
//! README's `agentfw mcp -- <mock-server>` walkthrough. What matters for correctness
//! — *when* the proxy withholds a manifest — is pure and tested here and in the unit
//! test inside `proxy.rs`.

use agentfw::mcp::proxy::{should_withhold, Verdict};

#[test]
fn enforcing_a_rejected_manifest_withholds_it_but_shadow_and_unavailable_do_not() {
    // Enforcing + ask/deny withholds.
    assert!(should_withhold(&Verdict::Ask, true));
    assert!(should_withhold(&Verdict::Deny, true));
    // Allow never withholds.
    assert!(!should_withhold(&Verdict::Allow, true));
    // A down/unparsable daemon fails open — a broken firewall must not break MCP.
    assert!(!should_withhold(&Verdict::Unavailable, true));
    // Shadow mode never withholds, whatever the verdict.
    assert!(!should_withhold(&Verdict::Ask, false));
    assert!(!should_withhold(&Verdict::Deny, false));
}
