# Native admission checkpoint — 2026-10-05

The reviewed Windows native fixture passed **26 checks** at
`2026-10-05T10:25:32.289010+00:00`. The existing fallback passed **29 checks** at
`2026-10-05T10:25:56.000138+00:00`. Both measured clean source
`e259b76b74f8678d0095aaf4fb66019f01228642` and the same actual Agent executable.

The [native aggregate JSON](agentdojo-native-fixture-2026-10-05.json) binds the
exact compiled CLI/helper/test snapshots, unchanged executable, pinned upstream
source inventory and Python dependency versions. The
[fallback compatibility JSON](agentdojo-fallback-after-native-2026-10-05.json)
retains the original 29 check names, policy hash and runtime versions. Neither
record contains provider credentials, prompts, function arguments or customer
data.

## What actually ran

- Original AgentDojo revision `089ed468cf3ed0322acc66b0211f26d9d90dbf60`, with
  all 112 source files verified before import, and the original MIT license.
- Python 3.12.10 with the pinned dependency versions recorded in JSON, including
  Pydantic 2.13.5 and OpenAI SDK 3.24.0.
- An actual native-enabled Windows `agentfw` process in each fresh private
  profile, with separate hook/native keys and immutable installed registries.
- Original functions, parameter schemas, environment dependencies, defaults,
  nested invocation ordering, values, exceptions and tool-result formatting.
- Pre-call denial preventing the harmless fixture write; result denial stopping
  a nested value before its parent runs; final formatter changes inspected
  before messages return; exact opaque call/content bindings and sticky faults.
- Seventy nested parent results across two outer invocations, with 72 admitted
  calls and no pending invocation records left afterward.
- The actual production `run_live` native path, original `AgentPipeline` factory,
  shared LLM leaf, original `TaskSuite` and evaluators. Seven authenticated
  requests reached a scripted numeric-loopback provider. Frozen plan, policy
  and registry inputs survived changes to the original files during execution.
  Policy withholding stopped the defended case without reporting its evaluators.
- Childless configuration/registry preparation failures cleaned their newly
  owned profile. Lifecycle-notification failure still stopped an owned child;
  failed process teardown propagated an error and retained its profile.

No actual model or paid provider ran. Scripted loopback provider traffic is
counted separately. New profiles from the final runs were removed, and no Agent
process remained afterward. Historical profiles described below remain.

The executable SHA-256 is
`a851c7642dcea9da555c127854a5d7ef4ddf5358d688dbddebee06e1380673b3`.
It was produced by the tested workspace build. Required Windows checks also
passed: formatting, workspace Clippy with warnings denied, 759 default workspace
tests, and the release-mode shipped-policy corpus. Five default tests retain
their explicit live-model, external-identity or dependency-service gates.
The hand-authored corpus still interrupts its 19 reviewed attacks and preserves
its 21 benign sessions; this is a regression result.

## Preserved incomplete attempts

| UTC | Checks / errors | Observation and repair |
| --- | --- | --- |
| 09:50:18 | 21 / 12 | CLI compilation inherited future-annotation flags into upstream fixture helpers; compile exact snapshots with `dont_inherit=True` |
| 09:51:06 | 21 / 1 | Server rejected the original `FunctionCall.placeholder_args` field; admit the exact original four-field function-call envelope |
| 10:13:16 | 24 / 2 | A second CLI helper snapshot changed module identity; dynamic client import made later lifecycle cleanup miss its exception type |

The third attempt's production native pipeline check itself passed, but the
overall attempt remains incomplete. The corrected registry-owned client factory
retains its originating snapshot, and shutdown now runs through owned teardown
even after lifecycle failure. Both exact owned child processes from the failed
attempt were verified and stopped. Automatic review rejected removal of its two
private temporary profiles with the sole supplied reason **"blocked by policy"**.
They remain ignored and private; removal was not retried through another method.
The previously rejected Keycloak profile was not touched. These historical
cleanup limits are separate from successful cleanup of the final new profiles.

The JSON retains all three original incomplete aggregate reports, including
their actual source and executable hashes. The later passing run does not
rewrite those earlier outcomes.

## Reproduction and remaining gates

Prepare the explicitly pinned runtime using the
[fallback instructions](../agentdojo-live-fallback.md), then run from the source
checkout with fresh evidence destinations:

```text
cargo fmt --all -- --check
cargo test --locked --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run --locked --release -p soup-wall-bench -- --agent crates/bench/corpora/agent_sessions.jsonl --policy crates/agent/policies/agent-default.yaml
target/agentdojo-venv/Scripts/python.exe -I scripts/agentdojo-live.py --mode native-fixture --upstream-checkout target/agentdojo-upstream --agent-binary target/debug/agentfw.exe --evidence target/native-fixture-new.json
target/agentdojo-venv/Scripts/python.exe -I scripts/agentdojo-live.py --mode fixture --upstream-checkout target/agentdojo-upstream --agent-binary target/debug/agentfw.exe --evidence target/fallback-fixture-new.json
```

This establishes the [native collector contract](../native-admission.md) for
harmless fixtures and reviewed custom policies. Registry accuracy for selected
real tools, independent held-out attacks, missed attacks, legitimate task
utility, real model/provider behavior, latency under field load and shadow
soaking still require their own evidence. Native escalation uses its explicit
policy fallback, and native configuration requires the optional judge disabled.
There is no human native approval channel or runtime-execution attestation.

The default `/hook` fallback keeps its existing action/provenance classification
and observation-only PostToolUse behavior. The native endpoint is opt-in and
does not silently change that host contract. No external field gate is closed.
