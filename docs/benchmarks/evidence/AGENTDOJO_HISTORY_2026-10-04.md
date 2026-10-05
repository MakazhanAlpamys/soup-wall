# AgentDojo historical replay checkpoint — 2026-10-04

The unmodified shipped no-judge policy interrupted **0 of 40 injection-attempt
labelled histories** and **0 of 40 benign histories**. The explicit policy gate
failed with exit 1. This is a retained negative baseline and a native-tool coverage
gap to investigate. It is not evidence of 40 successful attacks: the attempt labels
include original-model resistance and possibly unencountered injected content.

The [sanitized aggregate report](agentdojo-history-2026-10-04.json) records source
revision, selection, license hashes, projected corpus/manifest hashes, exact policy
and binary hashes, mapping-source hashes, aggregate interruptions, native tool
counts, and replay latency. Original traces, projected events, full reports,
credentials, and attack text remain outside Git under ignored `datasets/`.

| Check | Observed |
|---|---|
| Selected source | AgentDojo `089ed468cf3ed0322acc66b0211f26d9d90dbf60`; public recorded `gpt-4o-2024-05-13` workspace runs |
| Frozen sample | 40 benign histories and one path-hash-selected attack per matching task from 480 candidates |
| Attack strategy counts | 18 direct; 22 tool-knowledge |
| Fidelity | 80/80 selected histories imported; 354 observed call/result events; 177 original calls; 11 original tool-error results; no omissions or replacements |
| Native vocabulary | 16 unknown lowercase tool names retained verbatim |
| Injection-attempt labelled histories interrupted | 0/40 |
| Benign histories interrupted | 0/40 |
| Explicit unmodified policy gate | Failed, exit 1; full local JSON retained |
| Replay latency | p50 0.090 ms; p99 17.769 ms on Windows x86_64, release build, 32 logical CPUs |
| Task utility / attack success / live enforcement | Not measured; field gate open |

The full local report hash is
`e50666323b057b14d33fec97df10c3c1eb9cec1c79e89e40318c43038771e2af`.
Benchmark source was `c764f3f`; importer/source-lock checkpoint was `bf8a384`.
No policy, tool-name substitution, or label tuning followed the observed result.
Both built-in-default and explicit unmodified shipped-YAML runs produced identical
verdicts and policy hash. The explicit `--policy` command is used for process-exit
gate evidence; without that flag the scorecard command can exit zero even though
its JSON gate field is false.

Replay constructs a fresh firewall per session and stops at the first interruption;
process-wide caches can be warm. Its latency is neither warmed daemon throughput
nor end-to-end agent latency. All native tool results use the hook's existing
semi-trusted `LocalSystem` fallback. Native names do not declare calendar/email/file
trust or the action semantics of sending/deleting. Argument patterns and core
detectors still run. The replay does not isolate the causes of the misses, and
changing this fallback requires a new reviewed adapter and separate evaluation.

[The import protocol and next checkpoint](../independent-history-replay.md) explain
the provenance, license decisions, reproducible command, unsupported formats,
native-tool limitations, and live evaluator requirements. Independent authorship
does not make this public historical sample an unbiased held-out evaluation.
