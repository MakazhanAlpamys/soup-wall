# AgentDojo live fallback adapter

This original Python adapter connects AgentDojo's pinned runtime to the existing
AgentFW `/hook` contract. It preserves native tool names, schemas, dependencies,
parameters, implementation, results, errors, and the upstream YAML formatter.
It uses the unmodified shipped policy with the optional judge disabled. It does
not make unknown native tools into coding tools or MCP servers, add semantic
hints, or replace the [negative historical baseline](independent-history-replay.md).

The implemented and measured checkpoint is a free runtime integration fixture.
An operator-selected independent live model evaluation remains outstanding.

The existing benchmark CI runs the dependency-free checks with:

```powershell
python -m unittest discover -s scripts/benchmarks -p 'test_*.py' -v
```

It exercises eight historical-import and ten adapter safety methods. Without an
explicit upstream checkout, the bytecode-contamination method and two runtime
test classes are explicitly skipped. The separate fixture command below runs
all 29 adapter checks with the pinned runtime and a disposable Agent.

## Prepare an isolated runtime

The default command prints a manifest and makes no model calls:

```powershell
python .\scripts\agentdojo-live.py
```

Python 3.12 was verified on Windows. Keep upstream source and dependencies under
the ignored `target` directory; they are not vendored into this repository. Git
checks out the exact revision, with source/data and the full MIT license retained:

```powershell
git clone --filter=blob:none --no-checkout --depth 1 https://github.com/ethz-spylab/agentdojo.git target/agentdojo-upstream
git -C target/agentdojo-upstream fetch --depth 1 origin 089ed468cf3ed0322acc66b0211f26d9d90dbf60
git -C target/agentdojo-upstream sparse-checkout init --cone
git -C target/agentdojo-upstream sparse-checkout set src
git -C target/agentdojo-upstream checkout --detach 089ed468cf3ed0322acc66b0211f26d9d90dbf60
python -m venv target/agentdojo-venv
target/agentdojo-venv/Scripts/python.exe -m pip install -r scripts/benchmarks/agentdojo-live.requirements.txt
python scripts/agentdojo-live.py --mode validate --upstream-checkout target/agentdojo-upstream
cargo build --locked -p agentfw --bin agentfw
```

Check each command's exit status before continuing. On Unix, use the venv's
`bin/python` and the binary `target/debug/agentfw`. The dependency lock records
the verified Windows environment; another OS/environment needs its own fixture
check. It contains dependency versions, not upstream code or model weights.
The checkout validator rejects other revisions, changed tracked source/data,
unexpected Python/data files, and imports outside the selected source tree.
It also rejects bytecode caches, symlinks, and junctions under `src`: Python can
read a stale or modified `.pyc` even when source hashes match. Use a fresh,
cache-free checkout; the adapter never removes operator caches automatically.

## Free fixture check

```powershell
target/agentdojo-venv/Scripts/python.exe -I scripts/agentdojo-live.py --mode fixture --upstream-checkout target/agentdojo-upstream --agent-binary target/debug/agentfw.exe --evidence target/agentdojo-live-fixture.json
```

This uses actual upstream `Function`, `FunctionsRuntime`, `ToolsExecutor`
formatter, `OpenAILLM`, `AgentPipeline`, and `TaskSuite` classes. Neutral in-memory
functions and a deterministic loopback Chat Completions fixture require no model
or provider key. Disposable custom `deny`, `ask`, and `allow` policies verify
execution control; the production orchestration fixture uses the shipped policy.
No custom fixture policy is used to claim attack protection.

The checks establish that:

- Deny and unattended Ask never call the blocked function, including nested calls.
- The outer function is checked after upstream nested resolution, validation,
  and defaulting, using its actual parameters without environment dependencies.
- Function metadata and original objects stay unchanged; registry replacement
  and registration cannot remove the wrapper.
- Result objects, upstream error behavior, and the exact model-facing formatter
  remain intact. Compound internal helper effects belong to the original tool.
- Transport failure, malformed/permissive responses, oversized results, and
  a shadow daemon cannot become an unchecked execution.
- The production matched-run path uses original fresh-state task evaluators,
  the original pipeline, and a bounded local provider fixture.
- Own daemon processes and profiles are removed, including failed preflight.

The sanitized [recorded fixture evidence](evidence/agentdojo-live-fixture-2026-10-05.json)
contains only hashes, versions, check counts, and limitations. Fixture utility is
not independent AgentDojo task utility or attack success.
The observed source revision and modification flag accompany exact file-byte
hashes; newline conversion can change those hashes across checkouts.

## Operator-selected live run

Live execution is opt-in with `--mode live`. Every provider, model, endpoint,
credential variable, experiment plan, budget, and output destination must be
explicit. No existing provider key is selected automatically and `.env` is never
loaded. Only the named credential variable is read. Ambient credentials/proxy
settings are cleared before upstream imports, and daemon children receive their
own profiles and only OS/runtime paths. HTTP transport does not inherit proxies
or follow redirects. Provider HTTP is allowed only for numeric loopback; external
providers require HTTPS.

Create a frozen plan in an ignored local location, with this shape. Supply
reviewed native task IDs, an original injection-task ID or `null`, and the original
injection strings. The empty example performs a benign task only; it is not an
attack evaluator. A matched evaluation also needs the corresponding attacked
case(s), frozen before results are examined:

```json
{
  "schema_version": 1,
  "upstream_revision": "089ed468cf3ed0322acc66b0211f26d9d90dbf60",
  "benchmark_version": "v1",
  "suite": "workspace",
  "cases": [
    {"user_task_id": "user_task_0", "injection_task_id": null, "injections": {}}
  ]
}
```

An explicit invocation has the following form. The model, URL, prices, and limits
are operator inputs, not defaults or recommendations; the selected credential
variable must already be present in that isolated shell:

```powershell
target/agentdojo-venv/Scripts/python.exe -I scripts/agentdojo-live.py --mode live --upstream-checkout target/agentdojo-upstream --agent-binary target/debug/agentfw.exe --plan datasets/my-frozen-plan.json --provider openai-compatible --model '<selected-model-id>' --base-url '<selected-https-or-loopback-v1-url>' --credential-env SOUP_WALL_EVAL_KEY --max-calls 20 --max-total-request-bytes 1000000 --max-output-tokens 512 --max-reserved-usd '<selected-limit>' --input-usd-per-million '<selected-rate>' --output-usd-per-million '<selected-rate>' --acknowledge-cost-estimate --evidence target/my-live-result.json
```

The model must support the original native function-call protocol and the
`max_tokens` output parameter. No runtime discovery, server startup, model pull,
or coding-host substitution occurs. Each selected case runs undefended and
enforced with fresh upstream state and a fresh disposable Agent profile. Root
enforcement cannot undo nested calls that already ran before a blocked outer
function; their ordering and effects remain upstream's original behavior.

Calls and total request bytes are bounded before every provider attempt, including
the pinned LLM's retries. `max_tokens` bounds the requested output; a provider
response reporting a larger completion is rejected. Cost reservations use one
input unit per serialized UTF-8 request byte plus the output cap, multiplied by
the explicit rates. Failed attempts consume reservations. This is an estimate,
not a verified tokenizer, hard invoice ceiling, or provider-side spending limit.
Local fixture rates are zero; paid provider rates must be chosen by the operator.

Only original `TaskSuite.run_task_with_pipeline` evaluator booleans become task
utility and injection success. The benign security sentinel becomes `null` in
the report. Missing inspection or runtime/provider failure marks the run
incomplete, preserves aggregate partial evidence, and exits nonzero; it is not
reported as prevention. Reports exclude attack strings, prompts, raw results,
credentials, endpoint URLs, and paths. Source hashes bind the actual imported
bytes, so newline conversion can change the inventory hash across platforms.

The live command reserves a fresh writable evidence destination before any
provider request and publishes JSON atomically. The plan is parsed and hashed
from one byte snapshot. Every daemon reads the same private copy of the shipped
policy, whose original bytes are hashed before execution. Reports also bind the
Agent executable, executed adapter/CLI bytes, native schema registry, Python
dependency versions, model selection, formatter, Ask behavior, and all budget
limits. Changes to the original plan or policy during a run cannot rewrite its
recorded experiment inputs.

## Existing boundary remains

The optional [native admission contract](native-admission.md) provides a separate
operator-installed registry and result/context gate. Select it explicitly with
`--native-registry`; the fallback described and measured here keeps `/hook`.

`/hook` classifies native names with the existing unknown-tool fallback and
derives their result provenance as `LocalSystem`. It accepts no trusted native
semantic declarations. PostToolUse inspects/records results but always returns
`{}`; the adapter does not interpret this as a prevention decision. The shipped
policy's no-judge escalation fallback remains unchanged. Unattended Ask refuses
execution because this adapter has no human approval channel; this host behavior
is stated separately from the YAML policy.

The separately versioned native path supplies installed trust/action
declarations and result/context admission. It requires its own registry review
and evaluation; the fallback does not acquire those semantics. Shell encoding,
fake egress URLs, fabricated MCP handshakes, or tuning against the 40 public
attack attempts do not establish coverage. A live fallback run does not close
the native-semantic or field-effectiveness gate.

Primary runtime contracts: [FunctionsRuntime](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/functions_runtime.py),
[ToolsExecutor and formatter](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/agent_pipeline/tool_execution.py),
[TaskSuite](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/task_suite/task_suite.py),
[pipeline/provider](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/src/agentdojo/agent_pipeline/agent_pipeline.py).
