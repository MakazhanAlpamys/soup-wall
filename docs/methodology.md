# Benchmark methodology

## Reproducible agent regression scorecard

The benchmark that runs in this repository and in CI is an offline replay of the
versioned, synthetic agent sessions in
[`crates/bench/corpora/agent_sessions.jsonl`](../crates/bench/corpora/agent_sessions.jsonl).
Its adjacent manifest records the reviewed labels and counts. Run it with:

```sh
cargo run --locked --release -p soup-wall-bench -- \
  --agent crates/bench/corpora/agent_sessions.jsonl
```

The current corpus has 19 attack and 21 benign sessions. The committed
[generated scorecard](benchmarks/agent-security-scorecard.generated.md) is
compared byte-for-byte with a fresh run by the benchmark CI workflow. The
[human-readable scorecard](benchmarks/agent-security-scorecard.md) reports the
raw counts and explains the categories. A session is detected when the agent
policy interrupts at least one event; the benign count records interruptions
of ordinary work. You can check a candidate policy with `--policy path/to/policy.yaml`;
the command exits nonzero if it misses a reviewed attack or interrupts a
reviewed benign session.

This small, hand-authored corpus checks regressions in known scenarios. It is
not a held-out sample, a measure of novel-attack detection, or evidence of a
production protection rate. No current rival comparison is published from it.

Add `--agent-out target/agent-evaluation.json` to retain machine-readable evidence.
The report records SHA-256 hashes of the corpus, review manifest, policy and
running binary; author-supplied provenance; each session's interruption outcome;
missed attacks and interrupted benign sessions; and p50/p99 policy replay time.
It contains no event payloads. A candidate policy that fails `--policy` still
writes this report before returning a nonzero exit. The existing Markdown
regression scorecard stays unchanged and is still compared byte-for-byte in CI;
CI also retains the JSON report.

Replay time includes construction of a fresh firewall per session and stops at
the first interruption. It does not measure warmed daemon throughput, provider
latency or tool execution. No model or tool runs during this evaluation, so
task utility is explicitly unmeasured. A policy interruption is not evidence
that a host prevented an action. Report task success and attack success from a
separate end-to-end experiment before claiming field effectiveness.

For an independently collected corpus, provide the same reviewed session JSONL
format and an adjacent `.manifest.json` with its actual license, provenance,
source URL/revision, counts and categories. Keep the source snapshot and its
conversion procedure available for review. Freeze the corpus and policy before
evaluating; label review and independence are human acceptance gates, not facts
the executable can establish from an author-supplied manifest. Do not re-label
missed attacks or tune against held-out results and continue calling them held
out. Record the exact source commit, build profile, compiler and hardware with
the generated hashes. This import path supports offline policy review; running
AgentDojo or another live-agent benchmark still requires its separately
reviewed runtime, permissions, models and dataset terms.

## Text benchmark: available tool, historical results

The text benchmark accepts labeled JSONL (`{"text":"...","label":true}`,
where `true` means malicious) and reports malicious recall, benign false-positive
rate, F1, and per-example p50/p99 latency. For a local run:

```sh
./scripts/fetch-datasets.sh
cargo run --locked --release -p soup-wall-bench -- \
  --dataset datasets/safe_guard.jsonl --out results.json
```

The download script currently requests deepset/prompt-injections,
jackhhao/jailbreak-classification, xTRam1/safe-guard-prompt-injection, and
JailbreakBench/JBB-Behaviors from the Hugging Face datasets-server API. The
JailbreakBench harmful-goal set tests a different content-moderation question;
it should not be presented as prompt-injection recall. The dataset rows are
not bundled or revision-pinned, and upstream content or availability may
change. Check each dataset's terms before downloading, redistributing, or
publishing results.

Earlier versions of this methodology listed text-corpus percentages and ML
latencies from separate experiments. The repository does not contain the exact
dataset snapshots, model weights, machine configuration, or complete run
artifacts needed to reproduce those figures. Treat them as historical results,
not current Soup Wall measurements. Before publishing new text scores, record
the source revision and license of every dataset, exact model asset revision,
Soup Wall commit, build flags, policy and threshold, hardware, and raw per-run
output. Report attack recall and benign false-positive rate together.

The default Rust build uses rules and heuristics. `--features ml` enables the
optional model code, but model assets are fetched separately by
`scripts/fetch-model.sh` and are not included in the open-source repository.
The text benchmark warns and falls back to rules when the injection model is
unavailable; optional moderation is likewise disabled if its model is missing.
Verify that the intended model actually loaded before describing a run as an
ML result. Review upstream model and training-data terms separately; the
repository's Apache-2.0 license does not cover those assets.

## External guards and fair comparisons

`--rival "name=program arg arg"` is a simple adapter: the process receives one
example on stdin and must return exactly `0` (benign) or `1` (malicious) on
stdout. A missing program, write error, nonzero exit, or invalid response now
fails the run. It is never converted into a benign prediction or a score. No
rival implementation, isolated environment, or current rival score is bundled.

The adapter starts a new process for every example while Soup Wall runs in the
benchmark process. Its latency therefore includes subprocess startup and is
not directly comparable to the in-process Soup Wall latency. A fair published
comparison needs pinned rival versions, the same labeled corpus and hardware,
documented warmup and invocation method, and separate attack-recall and benign
false-positive results. The text benchmark exercises the core detector path;
it does not measure gateway networking or the end-to-end agent runtime.
