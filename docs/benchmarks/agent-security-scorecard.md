# Agent security scorecard

Human-readable snapshot and interpretation. The exact generated output is
kept in [`agent-security-scorecard.generated.md`](agent-security-scorecard.generated.md)
so CI can compare it byte-for-byte with the current corpus.

Generated with:

```sh
cargo run --locked --release -p soup-wall-bench -- \
  --agent crates/bench/corpora/agent_sessions.jsonl
```

Corpus: 19 attack + 21 benign = 40 sessions. The corpus is hand-authored and
measures coverage of reviewed attack shapes, not generalization to novel
attacks.

Percentages are deliberately omitted. At n=19 and n=21 a "100%" or "0%" figure implies a
precision the sample size cannot support, and this corpus is a regression baseline rather
than a benchmark. The raw counts are the honest form.

| Baseline check | Count |
|---|---|
| Reviewed attack sessions caught | **19 of 19** |
| Benign sessions interrupted | **0 of 21** |

| Category | Detected |
|---|---|
| destructive-from-taint | 2/2 |
| indirect-injection | 5/5 |
| mcp-poisoning | 2/2 |
| pii-egress | 1/1 |
| secret-egress | 4/4 |
| subagent-escalation | 2/2 |
| unknown-host | 3/3 |

This snapshot is a regression baseline for the shipped no-judge policy. It
must be regenerated and reviewed whenever the corpus, policy, or agent action
classification changes. It does not establish production security, does not
generalize to novel attacks, and does not compare against another firewall.
Held-out and third-party evaluation (AgentDojo, InjecAgent) has not been run;
until it is, no comparative or generalization claim is supported.

## Public snapshot

A public snapshot of this scorecard, its synthetic corpus, manifest, and
provenance is published at the [GitHub benchmark gist](https://gist.github.com/MakazhanAlpamys/68284f675fc9bdaf3994bd13e2b34c6f).
It was exported from repository commit `e9c91be` on 2026-09-01. The gist is a
reviewed regression baseline, not customer data, a production-security claim,
or a comparison against another firewall; publish a new versioned snapshot
when the corpus or policy changes.
