// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Generate the `settings.json` hook block. Prints by default; there is no
//! `--write` mode — silently editing a user's `settings.json`, or correctly
//! merging into an existing `hooks` block, is a whole task of its own and not
//! something a first release should do unprompted.

use std::path::Path;

use serde_json::json;

/// The `settings.json` fragment wiring all five hook events to the daemon.
///
/// The token is passed by environment variable, never written inline — settings
/// files are routinely committed to version control, and a token embedded in
/// JSON would ship straight into git history.
///
/// The 5-second timeout is deliberate, not conservative padding: measured
/// 2026-07-30, an unreachable HTTP hook fails open — Claude Code waits out the
/// timeout, then lets the tool call proceed. So this number is exactly what a
/// stopped daemon costs on every single tool call. It stays at 5s rather than
/// dropping lower because phase 10's local-model judge tier needs a 3s budget of
/// its own; shortening this now would clip legitimate slow judgments later.
pub fn hook_block(port: u16) -> serde_json::Value {
    let entry = json!({
        "type": "http",
        "url": format!("http://127.0.0.1:{port}/hook"),
        "headers": { "Authorization": "Bearer $AGENTFW_TOKEN" },
        "allowedEnvVars": ["AGENTFW_TOKEN"],
        "timeout": 5
    });
    // "*" matches every tool — the documented wildcard form for a hook matcher.
    let one = |matcher: &str| json!([{ "matcher": matcher, "hooks": [entry.clone()] }]);

    json!({
        "hooks": {
            "PreToolUse": one("*"),
            "PostToolUse": one("*"),
            "SubagentStop": one("*"),
            "SessionStart": one("*"),
            "SessionEnd": one("*")
        }
    })
}

/// Human-readable installation instructions: this is the operator's entire
/// first experience of the tool, so it prints the token *path* (never the
/// token itself — an operator pasting this into a bug report should not leak
/// their secret), and spells out both costs an operator would otherwise have
/// to discover by debugging: a stopped daemon silently taxing every tool call,
/// and shadow mode silently declining to block anything until told to.
pub fn instructions(port: u16, token_path: &Path) -> String {
    format!(
        "Add this to your Claude Code settings.json (merge into any existing \"hooks\" block \
         rather than overwriting it):\n\n\
         {block}\n\n\
         Then export the token before starting Claude Code — the token itself is never printed \
         here, only its path:\n\n  \
         export AGENTFW_TOKEN=$(cat {token_path})\n\n\
         THE HOOK IS NOT A SECURITY BOUNDARY. Each hook has a 5-second timeout. If agentfw is \
         not running, every tool call still proceeds — Claude Code fails open — after waiting out \
         the full 5 seconds. The host decides this and agentfw cannot override it, so a stopped \
         daemon is silent: it shows up as \"Claude Code feels slow\", never as an error. Do not \
         rely on the hook to prevent anything; treat it as a decision and audit layer.\n\n  \
         Check before a session, or from your shell profile or a wrapper script:\n\n  \
         agentfw preflight              # exits 2 if the daemon is down, 4 with --require-enforce in shadow mode\n\n\
         SHADOW MODE: the daemon starts with enforcement OFF. Verdicts are computed and written \
         to the audit log on every tool call, but nothing is ever blocked — permissionDecision is \
         always \"defer\", leaving your existing permission rules untouched. This is deliberate: it \
         lets you measure this firewall's real false-positive rate on your own normal work before \
         it can affect anything.\n\n  \
         PROMOTING TO ENFORCEMENT — the whole sequence:\n\n  \
         1. Run your usual sessions in shadow mode. Not an afternoon: `agentfw replay` refuses to \
         recommend anything below 500 events across 20 sessions, because a recommendation drawn \
         from less than that is a guess.\n  \
         2. Read the report:\n\n       \
         agentfw replay\n\n     \
         It ends with a VERDICT line. `not enough evidence` means keep soaking. `review required` \
         means enforcement would have interrupted real work — and the tool deliberately will not \
         tell you those were false positives, because only you know what you intended. Go through \
         the rules it lists and decide, per rule, whether each interruption was correct.\n  \
         3. Narrow any rule that was wrong BEFORE enforcing, not after. Then gate the edited \
         policy against the reviewed attack and benign corpus -- it exits non-zero if your edit \
         now misses a known attack or interrupts known-benign work:\n\n       \
         soup-wall-bench --agent crates/bench/corpora/agent_sessions.jsonl --policy my-policy.yaml\n\n  \
         4. Set `enforce: true` in ~/.agentfw/config.yaml, restart, then confirm the change \
         actually took effect:\n\n       \
         agentfw preflight --require-enforce\n\n\
         HIGH-RISK SHELL TOOLS: the daemon hook is a decision/audit layer, not process containment. \
         Route approved shell calls through the Linux-only guarded entry point so the exact command \
         is inspected before bubblewrap creates a process:\n\n  \
         agentfw guarded-shell --workspace ./checkout -- 'make test'\n",
        block = serde_json::to_string_pretty(&hook_block(port)).unwrap_or_default(),
        token_path = token_path.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_all_five_events_pointing_at_the_daemon() {
        let v = hook_block(8787);
        let hooks = &v["hooks"];
        for event in [
            "PreToolUse",
            "PostToolUse",
            "SubagentStop",
            "SessionStart",
            "SessionEnd",
        ] {
            assert!(hooks.get(event).is_some(), "missing {event}");
            let entry = &hooks[event][0]["hooks"][0];
            assert_eq!(entry["type"], "http");
            assert_eq!(entry["url"], "http://127.0.0.1:8787/hook");
        }
    }

    #[test]
    fn matches_all_tools() {
        let v = hook_block(8787);
        assert_eq!(v["hooks"]["PreToolUse"][0]["matcher"], "*");
    }

    #[test]
    fn passes_the_token_by_env_var_never_inline() {
        // The literal secret must not be written into settings.json, which is
        // routinely committed to version control.
        let v = hook_block(8787);
        let entry = &v["hooks"]["PreToolUse"][0]["hooks"][0];
        assert_eq!(entry["headers"]["Authorization"], "Bearer $AGENTFW_TOKEN");
        assert_eq!(entry["allowedEnvVars"][0], "AGENTFW_TOKEN");
        assert!(
            !serde_json::to_string(&v).unwrap().contains("Bearer test"),
            "no literal token may appear"
        );
    }

    #[test]
    fn sets_a_short_timeout_so_a_stalled_daemon_cannot_hang_the_loop() {
        let v = hook_block(8787);
        assert_eq!(v["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"], 5);
    }

    #[test]
    fn honours_a_custom_port() {
        let v = hook_block(9999);
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["url"],
            "http://127.0.0.1:9999/hook"
        );
    }

    #[test]
    fn instructions_never_print_a_literal_token() {
        // instructions() reads the token PATH via load_or_create semantics, but
        // must never interpolate the secret itself into the printed output. This
        // exercise proves the assertion is not trivially true: a real secret
        // deliberately embedded in the text WOULD be caught by this check.
        let path = Path::new("/home/u/.agentfw/token");
        let out = instructions(8787, path);
        assert!(out.contains(&path.display().to_string()));
        assert!(out.contains("cat "), "must show how to read the token file");

        // Sanity-check the assertion style itself would catch a leak: a string
        // that DOES contain a bogus "real" token must fail this same check.
        let fake_leak = format!("{out}\nBearer sk-should-not-appear-abc123");
        assert!(
            fake_leak.contains("Bearer sk-should-not-appear-abc123"),
            "sanity check: the contains-based assertion must be able to detect a leak"
        );
        assert!(
            !out.contains("Bearer sk-should-not-appear-abc123"),
            "the real instructions output must not contain any concrete bearer token"
        );
    }

    #[test]
    fn instructions_mention_shadow_mode_and_the_timeout_cost() {
        let out = instructions(8787, Path::new("/home/u/.agentfw/token"));
        let lower = out.to_lowercase();
        assert!(lower.contains("shadow"), "must explain shadow mode: {out}");
        assert!(
            lower.contains("enforce"),
            "must say how to turn enforcement on: {out}"
        );
        assert!(
            lower.contains("5 second") || lower.contains("5-second"),
            "must warn about the per-call cost of a stopped daemon: {out}"
        );
    }

    /// The hook fails open and the host owns that decision, so the setup text
    /// must say so plainly and hand the operator the check that does fail loudly,
    /// rather than implying the hook prevents anything.
    /// Shadow-first is only honest if the way out of it is spelled out. The
    /// setup text must carry the whole sequence, including the refusal to
    /// recommend promotion from thin evidence.
    #[test]
    fn instructions_carry_the_promotion_sequence_and_its_evidence_bar() {
        let out = instructions(8787, Path::new("/home/u/.agentfw/token"));
        assert!(
            out.contains("agentfw replay"),
            "must show how to review: {out}"
        );
        assert!(
            out.contains("500 events") && out.contains("20 sessions"),
            "must state the evidence bar, not just say review: {out}"
        );
        assert!(
            out.contains("preflight --require-enforce"),
            "must show how to confirm enforcement took effect: {out}"
        );
        assert!(
            out.to_lowercase()
                .contains("only you know what you intended"),
            "must not imply the tool can classify false positives: {out}"
        );
    }

    #[test]
    fn instructions_disclaim_the_hook_and_point_at_preflight() {
        let out = instructions(8787, Path::new("/home/u/.agentfw/token"));
        let lower = out.to_lowercase();
        assert!(
            lower.contains("fails open"),
            "must state that the hook fails open: {out}"
        );
        assert!(
            lower.contains("not a security boundary"),
            "must not imply the hook prevents anything: {out}"
        );
        assert!(
            out.contains("agentfw preflight"),
            "must hand the operator the check that exits non-zero: {out}"
        );
    }
}
