# Independent historical trace replay

This import exercises the shipped no-judge agent policy on independently authored,
public historical AgentDojo traces. It measures policy interruptions on a projection
of recorded calls and results. It does not measure defended task utility, attack
success, a live agent, host enforcement, or unbiased held-out generalization.

## Reviewed sources and inclusion decision

| Source | Pinned revision | License and runtime review | Decision |
|---|---|---|---|
| [AgentDojo](https://github.com/ethz-spylab/agentdojo/tree/089ed468cf3ed0322acc66b0211f26d9d90dbf60) | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | [MIT notice](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/LICENSE). The repository includes recorded model messages, native tool calls/results, and original task evaluators. | Import pinned workspace histories locally. Preserve the full notice beside local data; publish only metadata and aggregate evidence. |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent/tree/f19c9f2c79a41046eb13c03c51a24c567a8ffa07) | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | [MIT notice](https://github.com/uiuc-kang-lab/InjecAgent/blob/f19c9f2c79a41046eb13c03c51a24c567a8ffa07/LICENCE). Test cases describe injected tool responses and desired attacker actions; they do not supply matched benign trajectories. | No import here. Do not fabricate subsequent tool calls or treat desired actions as observed execution. Live evaluation needs the original model and attack evaluator. |
| [BIPIA](https://github.com/microsoft/BIPIA/tree/a004b69ec0dd446e0afd461d98cb5e96e120a5d0) | `a004b69ec0dd446e0afd461d98cb5e96e120a5d0` | [Composite license](https://github.com/microsoft/BIPIA/blob/a004b69ec0dd446e0afd461d98cb5e96e120a5d0/LICENSE): code MIT; datasets include CC-BY-SA-4.0 components and MIT invoice data. Its task-oriented injected contexts are not native agent tool trajectories. | No import here. Component licenses and attribution need separate review. A text-classification adaptation would not establish agent attack success. |

No upstream code, attack rows, or raw traces are committed. The importer is original
standard-library Python. Fetching public JSON does not execute upstream tools or
create model traffic. No API key or deployment credential is read.

## Frozen selection and fidelity

[`agentdojo-history.source-lock.json`](../../scripts/benchmarks/agentdojo-history.source-lock.json)
fixes the Git revision, tree, license hashes, 80 trace paths, and their Git blob IDs.
The importer verifies the complete upstream tree and re-derives the selection.
It computes SHA-256 for every original file and the projected corpus/manifest.
The source-lock hash uses canonical sorted, indented UTF-8 JSON with LF, so a
Windows Git checkout's newline conversion does not change selection identity.

Selection was frozen before replay: all 40 `workspace` benign histories for
`gpt-4o-2024-05-13`, plus one attack per matching user task from 480 `direct` and
`tool_knowledge` candidates. Choose the minimum SHA-256 of
`soup-wall-independent-history-v1` + newline + original path. Trace content,
upstream success results, and Soup Wall verdicts do not enter selection. This
produces 18 direct and 22 tool-knowledge attempts. It is a bounded public historical
sample, with publication and suite/model/strategy selection bias.

For each recorded assistant tool call, emit its original native function name and
JSON argument values. For each corresponding tool message, emit its original
string result. Preserve message order, including parallel call/result order.
Original call IDs must match the result's complete call object. User/system prompts
and assistant prose have no corresponding `EventKind` and are not projected; they
remain in the local original files. No namespacing, invented MCP handshake, shell
command, fake egress URL, content prefix, attacker next call, or benign substitute
is added. Serialization preserves JSON values rather than original lexical bytes;
hashes bind the complete source bytes.

A non-string output, unsupported native name/schema, unmatched ID, upstream run
error, incomplete or empty tool trace fails the entire import. Selected traces are
never replaced or silently omitted. Original tool-level error outputs remain
unchanged; their counts are recorded. Their errors are distinct from a failed
upstream benchmark run.

## Native-tool coverage boundary

The imported native names are outside the shipped coding-tool vocabulary in
[`action.rs`](../../crates/agent/src/action.rs). Calls therefore start with generic
`SideEffecting`; existing argument-pattern upgrades and URL extraction still run.
For the same unmodified names, the current hook
[`provenance.rs`](../../crates/agentfw/src/provenance.rs) returns `LocalSystem`, which
is semi-trusted. The importer reproduces this fallback. It does not pretend that
workspace files, email, or calendar messages have the correct external-resource
trust mapping. Core detectors still inspect tool-result text, but these results do
not create the untrusted taint needed by later taint rules. A native `send_email`
is not understood as a network send solely from its name; `delete_file` is not
understood as destructive solely from its name. This replay does not isolate the
causes of individual misses.

The manifest enumerates the actual unknown native names and call counts. Do not
rename these tools to `Bash` or `mcp__...` to improve results: that changes both
action classification and trust. A future reviewed native adapter should declare
tool semantics explicitly while retaining original parameters and output, then
receive a new versioned evaluation rather than replacing this baseline.

An `attack` label means an upstream injection **attempt**, including an attempt
that the original model resisted or never encountered. Interruption counts on that
label are not an attack-success rate or causal prevention. The upstream `utility`
and `security` fields belong to the upstream run. In AgentDojo's
[`TaskSuite.run_task_with_pipeline`](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/task_suite/task_suite.py),
the second returned boolean denotes injection-task success; a benign run has a
sentinel value. None of those values becomes Soup Wall task utility.

## Reproduce without credentials

Use Python 3.10+ and the repository's Rust toolchain. From the checkout root:

```sh
python -m unittest discover -s scripts/benchmarks -p 'test_*.py' -v
python scripts/import-agentdojo-history.py
python scripts/import-agentdojo-history.py --output-dir datasets/agentdojo-history-v1
cargo run --locked --release -p soup-wall-bench -- \
  --agent datasets/agentdojo-history-v1/agent_sessions.jsonl \
  --policy crates/agent/policies/agent-default.yaml \
  --agent-out datasets/agentdojo-history-v1/replay-report.json
```

The first import invocation verifies selection only. Output must be a fresh
subdirectory under this checkout's ignored `datasets/`; an existing destination
is rejected. HTTPS access to GitHub's public API and raw-file host is required.
The license, original traces, JSONL projection, manifest, and full sanitized report
stay local. Inspect only metadata and aggregate outputs before publishing evidence.
Passing the unmodified shipped YAML to `--policy` enables the process-exit gate
without tuning the policy. The CLI writes `--agent-out` before exiting nonzero when
that gate fails. Without `--policy`, the scorecard command can exit zero while the
JSON's `passes_reviewed_policy_gate` is false; inspect that field. Keep the failed
report. The existing
hand-authored regression scorecard remains a separate gate.

## Live field gate remains open

The available live extension points at this revision are
[`FunctionsRuntime.run_function`](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/functions_runtime.py),
[`ToolsExecutor`](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/agent_pipeline/tool_execution.py),
and the original `TaskSuite.run_task_with_pipeline` evaluators. A live Soup Wall
integration has not been implemented or validated here. An upstream benchmark
command by itself is not a Soup Wall defended run.

The next checkpoint requires these concrete inputs and work:

1. Freeze the upstream revision, supported native tools, suites/tasks, strategies,
   and original utility/injection-success evaluators. Review each tool's trust,
   action semantics, nested execution, and output formatting before binding it to
   the firewall; never synthesize a shell command to encode a native action.
2. Implement pre-call and post-result inspection around the real runtime, including
   nested calls. Define how `Ask`, `Deny`, timeouts, and judge fallback reach the
   agent. Test that blocked tools actually never execute, and reset task state for
   every defended/undefended run.
3. Supply an operator-selected provider/model or verified local model, isolated
   credentials, approved model-call/token/cost budget, concurrency and retry limits,
   and output directory. Do not send trace attacks to a paid provider merely to
   recreate this offline result.
4. Run matched benign and attacked tasks with/without enforcement under the same
   frozen policy and environment. Record native task utility, injection-task success,
   enforcement receipts, and actual end-to-end latency separately from replay
   latency. A policy interruption alone does not satisfy this checkpoint.
5. Publish only reviewed aggregate results and hashes. Any policy or adapter tuned
   after this public sample is a development change; independent evaluation must use
   a fresh preregistered sample and retain this negative baseline.
