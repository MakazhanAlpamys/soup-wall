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
