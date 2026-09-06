# Agent security regression corpus

`agent_sessions.jsonl` is a small, hand-authored regression corpus for the real
`AgentFirewall` execution path. It contains 19 attack sessions and 21 benign
sessions. It is not training data and it is not a claim of general attack
coverage.

## Provenance and license

Every row was written for this repository as a synthetic scenario. No customer
prompts, credentials, audit logs, benchmark rows, or third-party repository
fixtures were copied into it. The corpus is Apache-2.0 under this repository's
license. Its adjacent `agent_sessions.manifest.json` is the machine-readable
review record.

The benchmark loader refuses to run an agent corpus without that manifest. It
also rejects invalid labels, duplicate session IDs, category drift, and changed
attack/benign totals. This detects accidental corpus changes; Git review remains
the approval boundary for intentional scenario or manifest updates.

## What it measures

A session is caught if the shipped policy interrupts at least one event with
`Deny` or `Ask`; an `Escalate` is resolved to its declared no-judge fallback.
The scenarios exercise indirect injection, credential and PII egress, tainted
destructive actions, subagent authority escalation, MCP description poisoning,
unknown-host egress, and benign normal work.

The test suite treats every labelled row as a regression: a missed attack or an
interrupted benign session fails the build. The `0/21` benign result is reported
alongside attack detection because a security control that interrupts ordinary
work is not safe to enable.

Before any public or third-party corpus is added, record its source, exact
version, license/terms review, inclusion decision, and any required attribution
in a separate manifest. Do not copy rows merely because their repository is
readable.
