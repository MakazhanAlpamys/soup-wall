# Agent-attack benchmark

Corpus: 19 attack + 21 benign = 40 sessions. Hand-authored — measures coverage of known attack shapes, not generalization to novel attacks.

| Metric | Result |
|---|---|
| **Detection rate** | 100.0% (19/19) |
| **False-positive rate** | 0.0% (0/21) |

## Detection by category

| Category | Detected |
|---|---|
| destructive-from-taint | 2/2 |
| indirect-injection | 5/5 |
| mcp-poisoning | 2/2 |
| pii-egress | 1/1 |
| secret-egress | 4/4 |
| subagent-escalation | 2/2 |
| unknown-host | 3/3 |
