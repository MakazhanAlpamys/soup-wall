// SPDX-License-Identifier: Apache-2.0

//! Pin the behaviour of the *shipped* `policies/default.yaml`.
//!
//! These assert against the real file operators deploy, not an inline fixture,
//! so a change to the shipped defaults cannot pass silently.

use llm_firewall_core::{Action, Direction, Finding, PolicySet, Severity};

fn shipped() -> PolicySet {
    // Embedded at compile time, the way `agent` embeds `agent-default.yaml`.
    // The path is still the real file operators deploy -- two levels above this
    // crate, at the workspace root -- so a change to the shipped defaults cannot
    // pass silently. What changes is *when* a missing file is noticed: a
    // checkout that lacks `policies/default.yaml` (an extracted Core without
    // the root layout, for example) now fails to compile with the path in the
    // error, instead of failing four tests at runtime with a bare "not found".
    let yaml = include_str!("../../../policies/default.yaml");
    PolicySet::from_yaml(yaml).expect("shipped policy parses")
}

fn ml_injection() -> Vec<Finding> {
    vec![Finding::new(
        "injection.ml",
        Severity::High,
        0.99,
        "ML-detected prompt injection",
    )]
}

#[test]
fn ml_injection_blocks_on_the_input_path() {
    let d = shipped().evaluate(&ml_injection(), 0, Direction::Input);
    assert_eq!(
        d.action,
        Action::Block,
        "a prompt-injection classifier hit on user input must block"
    );
}

/// The prompt-injection classifier is trained on *user prompts that try to hijack
/// a model*. A model's own reply is not such a prompt, and applying the classifier
/// there is a category error: measured on the phase-13 corpus it caught 0% of
/// harmful replies while over-blocking 16% of legitimate security answers
/// (defensive phishing guidance, password-policy advice, authorized-pentest
/// methodology). Indirect injection is unaffected — retrieved content and tool
/// results are projected as `Direction::Input` and are still covered.
#[test]
fn ml_injection_does_not_block_the_model_reply() {
    let d = shipped().evaluate(&ml_injection(), 0, Direction::Output);
    assert_eq!(
        d.action,
        Action::Allow,
        "injection.ml must not block model output — it over-blocks legitimate security content"
    );
}

/// `detector: injection` matches `injection.ml` by segment prefix, so the
/// signature/heuristic rule must be scoped too or it silently re-blocks the
/// model reply that `block-ml-injection` deliberately lets through.
#[test]
fn signature_injection_is_also_input_scoped() {
    let f = vec![Finding::new(
        "injection",
        Severity::High,
        0.9,
        "ignore all previous instructions",
    )];
    let p = shipped();
    assert_eq!(p.evaluate(&f, 0, Direction::Input).action, Action::Block);
    assert_eq!(
        p.evaluate(&f, 0, Direction::Output).action,
        Action::Allow,
        "a reply that quotes an injection (security article, CTF writeup) is not an attack on us"
    );
}

#[test]
fn output_side_protections_still_block() {
    let p = shipped();
    // Secrets leaking in a reply.
    let secret = vec![Finding::new("secret.aws", Severity::High, 0.99, "aws key")];
    assert_eq!(
        p.evaluate(&secret, 0, Direction::Output).action,
        Action::Block
    );
    // Improper output handling (LLM05).
    let dangerous = vec![Finding::new("output", Severity::High, 0.99, "curl | sh")];
    assert_eq!(
        p.evaluate(&dangerous, 0, Direction::Output).action,
        Action::Block
    );
}
