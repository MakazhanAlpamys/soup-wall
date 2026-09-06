// SPDX-License-Identifier: Apache-2.0

//! Turn a silently absent daemon into an explicit, scriptable failure.
//!
//! Claude Code's HTTP hook **fails open**: if the daemon is not listening, the
//! host waits out the hook timeout and then runs the tool anyway. That is the
//! host's decision and this crate cannot override it, so the honest response is
//! not to pretend the hook is a security boundary but to give the operator a
//! check they can run *before* a session, and wire into a wrapper script or CI.
//!
//! `evaluate` is deliberately pure — it takes the outcome of a probe rather than
//! performing one — so every posture below is covered by a test without binding
//! a socket.

/// What a probe of the daemon's `/health` endpoint established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// The endpoint answered with this status and body.
    Answered { status: u16, body: String },
    /// No answer: connection refused, timed out, DNS, TLS, anything.
    Unreachable { detail: String },
}

/// The posture the operator needs to act on. Ordered from worst to best only for
/// readability; callers must match explicitly rather than compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// Nothing is listening. Every tool call will pass after the hook timeout.
    Unreachable,
    /// Something answered but is not a healthy agentfw daemon.
    Unhealthy,
    /// The daemon is up but enforcement is off: verdicts are recorded, never applied.
    Shadow,
    /// The daemon is up and enforcing.
    Enforcing,
}

impl Posture {
    /// Exit status for scripts. Non-zero for anything an operator would want a
    /// wrapper or CI step to stop on.
    ///
    /// `Shadow` is only a failure when the caller asked for enforcement. That
    /// keeps the default check usable during the shadow-mode soak the product
    /// deliberately recommends, while still letting a hardened deployment
    /// demand enforcement with one flag.
    pub fn exit_code(self, require_enforce: bool) -> i32 {
        match self {
            Self::Unreachable => 2,
            Self::Unhealthy => 3,
            Self::Shadow if require_enforce => 4,
            Self::Shadow | Self::Enforcing => 0,
        }
    }
}

/// A human-readable result of one preflight check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub posture: Posture,
    /// `None` when the daemon did not report a usable enforcement flag.
    pub enforce: Option<bool>,
    pub detail: String,
}

impl Report {
    pub fn exit_code(&self, require_enforce: bool) -> i32 {
        self.posture.exit_code(require_enforce)
    }

    /// One line for a terminal or a CI log. Never prints the token or any body
    /// content beyond the fields this crate itself defines.
    pub fn render(&self, require_enforce: bool) -> String {
        let verdict = match self.posture {
            Posture::Unreachable => "FAIL",
            Posture::Unhealthy => "FAIL",
            Posture::Shadow if require_enforce => "FAIL",
            Posture::Shadow => "WARN",
            Posture::Enforcing => "OK",
        };
        format!("{verdict}: {}", self.detail)
    }
}

/// Classify a probe result. Pure: no I/O, no clock, no environment.
pub fn evaluate(probe: &Probe) -> Report {
    match probe {
        Probe::Unreachable { detail } => Report {
            posture: Posture::Unreachable,
            enforce: None,
            detail: format!(
                "agentfw is not reachable ({detail}). The Claude Code hook fails open, so \
                 every tool call will proceed unchecked after the hook timeout. Start it with \
                 `agentfw serve`."
            ),
        },
        Probe::Answered { status, .. } if *status != 200 => Report {
            posture: Posture::Unhealthy,
            enforce: None,
            detail: format!(
                "agentfw answered HTTP {status} on /health, which is not a healthy daemon."
            ),
        },
        Probe::Answered { body, .. } => classify_body(body),
    }
}

fn classify_body(body: &str) -> Report {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return Report {
            posture: Posture::Unhealthy,
            enforce: None,
            detail: "agentfw /health did not return JSON; something else is on this port.".into(),
        };
    };
    if value.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
        return Report {
            posture: Posture::Unhealthy,
            enforce: None,
            detail: "agentfw /health did not report status=ok.".into(),
        };
    }
    // A daemon that answers `ok` without an `enforce` flag is not a build this
    // check understands. Treat the unknown posture as unhealthy rather than
    // guessing that it enforces.
    let Some(enforce) = value.get("enforce").and_then(serde_json::Value::as_bool) else {
        return Report {
            posture: Posture::Unhealthy,
            enforce: None,
            detail: "agentfw /health reported no enforcement flag; enforcement posture is unknown."
                .into(),
        };
    };
    if enforce {
        Report {
            posture: Posture::Enforcing,
            enforce: Some(true),
            detail: "agentfw is running and enforcing.".into(),
        }
    } else {
        Report {
            posture: Posture::Shadow,
            enforce: Some(false),
            detail:
                "agentfw is running in shadow mode: verdicts are recorded but nothing is \
                     blocked. Set `enforce: true` in ~/.agentfw/config.yaml and restart to enforce."
                    .into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answered(status: u16, body: &str) -> Probe {
        Probe::Answered {
            status,
            body: body.into(),
        }
    }

    /// The case W3 exists for: nothing listening must be a loud, non-zero result,
    /// not the silent pass the host hook produces on its own.
    #[test]
    fn an_unreachable_daemon_fails_and_says_the_hook_fails_open() {
        let report = evaluate(&Probe::Unreachable {
            detail: "connection refused".into(),
        });
        assert_eq!(report.posture, Posture::Unreachable);
        assert_eq!(report.exit_code(false), 2);
        assert_eq!(
            report.exit_code(true),
            2,
            "unreachable must fail regardless of the enforcement requirement"
        );
        assert!(
            report.detail.contains("fails open"),
            "the operator must be told why this matters: {}",
            report.detail
        );
    }

    #[test]
    fn an_enforcing_daemon_passes_either_way() {
        let report = evaluate(&answered(200, r#"{"status":"ok","enforce":true}"#));
        assert_eq!(report.posture, Posture::Enforcing);
        assert_eq!(report.enforce, Some(true));
        assert_eq!(report.exit_code(false), 0);
        assert_eq!(report.exit_code(true), 0);
    }

    /// Shadow mode is the shipped default and the product deliberately asks
    /// operators to soak in it, so the plain check must not fail on it — but a
    /// deployment that has finished the soak can demand enforcement.
    #[test]
    fn shadow_mode_warns_by_default_and_fails_only_when_enforcement_is_required() {
        let report = evaluate(&answered(200, r#"{"status":"ok","enforce":false}"#));
        assert_eq!(report.posture, Posture::Shadow);
        assert_eq!(report.exit_code(false), 0);
        assert_eq!(report.exit_code(true), 4);
        assert!(report.render(false).starts_with("WARN"));
        assert!(report.render(true).starts_with("FAIL"));
    }

    #[test]
    fn a_non_200_answer_is_unhealthy() {
        let report = evaluate(&answered(503, r#"{"status":"ok","enforce":true}"#));
        assert_eq!(report.posture, Posture::Unhealthy);
        assert_eq!(report.exit_code(false), 3);
    }

    #[test]
    fn something_else_on_the_port_is_unhealthy_not_healthy() {
        for body in ["<html>hello</html>", r#"{"status":"degraded"}"#] {
            let report = evaluate(&answered(200, body));
            assert_eq!(
                report.posture,
                Posture::Unhealthy,
                "body {body:?} must not pass as a healthy daemon"
            );
        }
    }

    /// An unknown build that omits the flag must not be optimistically read as
    /// enforcing.
    #[test]
    fn a_missing_enforcement_flag_is_unhealthy_rather_than_assumed_enforcing() {
        let report = evaluate(&answered(200, r#"{"status":"ok"}"#));
        assert_eq!(report.posture, Posture::Unhealthy);
        assert_eq!(report.enforce, None);
        assert_ne!(report.exit_code(false), 0);
    }
}
