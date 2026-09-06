# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a vulnerability** form
(Security → Advisories) on this repository rather than opening a public issue. Include steps to
reproduce and, where possible, a proof of concept. We aim to acknowledge reports within a few
days.

## Scope

This is a defensive tool. Relevant reports include:

- Detection **bypasses**: a prompt-injection, secret, PII, or harmful-content payload that
  evades a detector it should catch, with a concrete example.
- **Policy bypasses** in the agent layer: an action the shipped policy should interrupt that
  it does not, or a human approval grant that authorizes something other than the exact call
  it was issued for.
- **Over-defense** regressions that materially raise the false-positive rate on benign work.
- Memory-safety, denial-of-service, or resource-exhaustion issues in the daemon or the MCP proxy.

## Out of scope, by design

- The Claude Code hook fails open when the daemon is not running. The host decides that; this
  project cannot override it and says so. Use `agentfw preflight` and the guarded execution path.
- The default build is signatures and heuristics only; higher recall needs the optional `ml`
  feature and model assets. A miss the ML stage would catch is a documented trade-off.
- Detection is probabilistic and every published classifier has been bypassed by adaptive
  attacks. The deterministic policy on actions is the control; detectors reduce risk.
- Approval grants defend against the agent approving itself. A local attacker already running as
  the operator can read the daemon key; that is not in the threat model.
- The content-moderation layer is not a full safety system and makes no claim to detect illegal
  material.
