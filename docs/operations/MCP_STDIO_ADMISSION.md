# Opt-in stdio MCP admission

`agentfw mcp --native-admission --id <server-id> -- <server> <args>` adds an
execution boundary for a deliberately small stdio MCP contract. The legacy
`agentfw mcp -- ...` command remains the manifest collector described in the
existing architecture; its manifest decision does not gate individual calls.

## Operator configuration

Start the Agent with enforcement enabled, the optional judge disabled, and an
explicitly reviewed [native registry](../benchmarks/native-admission.md):

```yaml
enforce: true
native:
  registry_path: 'C:/absolute/private/mcp-registry.json'
  registry_sha256: '<SHA-256 of the exact registry bytes>'
```

The registry names the original MCP tools and pins each original input schema.
For example, a real `send_http({url, body})` tool has declared action `network`
and required `url_host` extraction at `/url`. Its returned provenance is an
operator decision. A tool name, server description or annotation cannot grant
authority or supply its own action class. Generic Claude hooks classify an
unknown MCP tool as side-effecting; that is insufficient to describe every
network send. The proxy uses the reviewed declarations without translating
the tool into a fabricated Bash command.

The guarded collector uses `/native/v1` and the separate private `native-token`.
It requires the same registry digest as the running daemon. Missing native
configuration, unavailable inspection, malformed replies and shadow posture
never authorize a guarded action. The collector is trusted and the server
executable still runs as the operator; this command is not an OS sandbox.
Admission covers the JSON-RPC stdin/stdout transport. Server stderr remains
the runtime's diagnostic stream; arbitrary server logging and other process
I/O are outside that admission guarantee.

## Boundaries

The collector admits each supported `tools/call` before writing its original
line to the server's stdin. Accepted names, arguments and bytes stay intact.
The server's matching original response must be admitted before its original
line is written to client stdout. Call IDs, session ownership, schema identity,
argument binding and content hashes correlate the two boundaries.

Native `result` delivery `mcp_host` hashes the entire original JSON-RPC envelope
and inspects its decoded original text blocks separately. It also inspects the
original JSON-RPC error message or original error-result blocks. Unsupported
payloads are rejected rather than partially forwarded. Successful host release
records the declared provenance for later calls in that collector session.

This is admission to the MCP **host**. The proxy cannot attest how Claude Code
later serializes or consumes the result, or whether the model follows its
instructions. There is no fabricated AgentDojo `context` message and no claim
of general Claude Code context admission. Withholding an already executed
tool's result cannot undo its effects; preventing a send requires call admission.

## Supported initial contract

The initial contract is synchronous stdio with one outstanding request and
text-only tool results. The SOU-11 input profile accepts closed top-level objects,
bounded nested objects/arrays and explicitly typed scalar fields. The collector
checks actual arguments before admission; the supported keywords and limits are
listed below. Defaults are inert metadata, never inserted into arguments;
implicit destinations remain outside this contract. Results contain only original text blocks and an
optional Boolean `isError`; JSON-RPC errors contain an integer code and message.

`tools/list` accepts empty parameters or the observed Codex discovery metadata
`_meta: {progressToken: <integer>}`. Call metadata, when present, contains exactly
one host identifier (`claudecode/toolUseId` for Claude Code or `threadId` for
Codex) and `progressToken`. Identifiers must be nonempty strings of at most 128
ASCII letters, digits, `_` or `-`; progress tokens must be nonnegative integers
no greater than 2^53 - 1. Mixed host identifiers and other metadata fields are
rejected. These shapes include those emitted by Codex CLI 0.148.0.

Host identifiers and progress tokens grant no authority, supply no native
session identity and do not change argument inspection. Accepted original
request bytes, including metadata, reach the server unchanged. Other metadata
and server progress notifications remain outside the supported contract.

Codex also probes `resources/list` and `resources/templates/list` during full
inventory discovery, even for servers advertising only tools. After the pinned
manifest is admitted, the collector answers these probes locally with JSON-RPC
`-32601` (method not supported) and the original request ID. It accepts the same
bounded discovery parameters, forwards no resource request or content, and
keeps the tool connection available. Resource reads remain unsupported.

Batched calls, tool-call notifications, duplicate/replayed identifiers,
unrecognized content paths, server-initiated requests, multimedia, embedded
resources, structured content and result/server metadata are unsupported. This is a bounded
integration, not a general MCP transport, concurrent executor, child-authority
system or human approval channel. Ask and Deny must prevent the affected call
or result; a correlated refusal lets a supported client continue ordinary work.
Transport uncertainty ends the collector rather than silently switching to
the legacy relay. Explicitly inspect the retained evidence and refusal behavior
before attaching another server or runtime.

## Selected harness and event contract

The initial harness is Claude Code acting as a stdio MCP client, where the
existing execution proof is strongest. The collector maps its native frames onto
the [`sw-native/1` events](../benchmarks/native-admission.md#admission-stages)
without translating tools into another format:

| Harness frame | Collector | Native event | Classification and policy | Outcome |
| --- | --- | --- | --- | --- |
| `initialize`, `tools/list` | Checks the initialization result and pins each tool schema against the registry | Manifest inspection | Tool-description rules | Release the manifest, or close before tools reach the host |
| `tools/call` | Validates arguments against the pinned schema; `_meta` stays transport correlation; an installed classifier then sees the admitted discovery snapshot, actual arguments and trusted baseline | `call` with `tool`, `args`, `schema_sha256` | Registry `action_class` and egress hosts form a `ToolCall` event for the agent policy | `allow` writes the original frame to the server; `deny` and `ask` return a correlated `isError` refusal and the server never receives the frame |
| Server response | Binds the response to the pending call | `result` with `call_id`, `result_kind`, `delivery: mcp_host`, `content` | Decoded text blocks form `ToolResult` events with the declared provenance | `allow` writes the original bytes to the host; otherwise a correlated `isError` refusal |

The JSON-RPC id, tool name, arguments and `_meta` stay in the original bytes,
and a refusal reuses the original id. There is no approval channel in this
contract, so `ask` is enforced exactly like a denial until a reviewed
single-use approval path exists.

### Classifier seam

The collector accepts one replaceable `InvocationClassifier` between argument
validation and the daemon `call` event. Its candidate output
(`sw-classification/candidate-1`) is `actions[]` from `read`, `write`,
`delete`, `send_data` and `change_permissions`, a separate `unknown` Boolean,
and confidence, uncertainty and a reason. This remains the bounded compatibility
profile; the reviewed SOU-10 contract defines the generic target. It changes
neither the MCP frames nor `sw-native/1`.

- A single action maps to `ReadOnly`, `SideEffecting`, `Destructive`, `Network`
  or `PrivilegeChanging`. The result is evidence only: the daemon still
  authorizes against the trusted registry class, so a lower or higher label
  cannot change restrictions. A difference is recorded as `baseline_mismatch`.
- Mixed actions, an empty action list and `unknown: true` return
  `unsupported_classification_mapping` until their policy semantics are agreed.
- Timeout (2 s), crash, error and invalid scores or actions are technical
  failures. Like an unsupported mapping, they answer the host with a JSON-RPC
  error that keeps the original id and says "policy not reached". The call never
  reaches the daemon or the server, the session continues, and a later call is
  admitted afresh. Missing discovery state still terminates the collector.

Each classified call writes one `mcp_classification` JSON line to the
collector's stderr with the source, host call id, snapshot, schema, argument and
registry digests, the classification (reason hashed), mapped and trusted
classes, `policy: reached | not_reached`, any failure label and classifier
latency. Debug builds provide two identified test doubles:
`AGENTFW_TEST_CLASSIFIER_READ=1` ([classified read](CLASSIFIED_READ_EVIDENCE.md))
and `AGENTFW_TEST_CLASSIFIER=fixture-v1`, which infers `send_data` from
URL-valued arguments rather than tool names and injects faults named in argument
values. Release builds refuse both. The real Team 1 adapter is described below.

### Real Task 1 rule baseline (SOU-22)

The explicit runtime adapter invokes the repository's `rule_baseline.py` through
isolated Python (`-I -u`), using newline-delimited JSON on stdin/stdout. Set:

```sh
export AGENTFW_CLASSIFIER=rule-baseline
export AGENTFW_RULE_BASELINE="$PWD/rule_baseline/rule_baseline.py"
# Optional: an explicitly selected Python executable.
export AGENTFW_CLASSIFIER_PYTHON="$(command -v python3)"
```

It maps the admitted tool name, original arguments, description, schema and server
identity into the baseline input. The trusted registry remains authoritative;
no server schema is invented as a trusted `pinned_schema`. The original MCP frame,
host ID and arguments are never rewritten. Python receives no inherited daemon
credentials. The selected script digest is pinned at startup and recorded as
`classifier_sha256`; no prediction cache is used. For each invocation the isolated
child reads a bounded source snapshot, checks its digest, and compiles those same
bytes. It does not reopen a parent-checked pathname for execution, so replacement
between the parent check and interpreter launch cannot execute unpinned code.
The runtime fixture image includes the exact classifier source at the path
embedded in the integration tests; missing source fails the fixture build.

`status=error`, invalid JSON, nonzero process exit and process timeout are technical
failures (`classifier_error`, policy not reached) with zero forwarding. Input is
bounded to 1 MiB and output to 16 KiB. The subprocess is killed and reaped after
1.5 seconds, within the collector's existing two-second classification deadline.
Invalid scores are refused by the existing mapping validator. Valid unknown and
mixed classifications retain the candidate harness's explicit unsupported-mapping
refusal; this increment does not claim acceptance of a final shared contract.
Test and real classifier settings cannot be combined. Test doubles remain debug-only;
the real adapter is also available in release builds.

Reproduce the real baseline matrix with the same independent executor/receiver
witnesses (the injected test-double fault cases are excluded rather than relabelled):

```sh
cargo build --locked -p agentfw
python3 scripts/mcp-admission-demo.py --classifier rule-baseline --keep \
  --out target/sou-22-real-baseline.json
cargo test --locked -p agentfw --test mcp_admission
python3 -m unittest discover -s rule_baseline -p 'test_*.py' -v
```

The integration suite separately injects Python crash, malformed output, error
status, timeout, oversized output and invalid score responses and checks original
host IDs, zero server execution and policy-not-reached evidence. These injected
processes are identified test fixtures, not real baseline predictions. The real
baseline test separately proves Allow execution, Deny/Ask non-execution and
original request-byte preservation. The actual Claude host check is reported as
skipped when its executable is unavailable; scripted frames do not establish
live-model security effectiveness.

## SOU-11: collection, input validation and definition identity

This increment extends the existing guarded collector in `crates/agentfw/src/mcp/`.
It uses the [reviewed SOU-10 semantic contract](../../contract/updated_contract2.md)
and the same selected stdio server and daemon. Resource extraction (SOU-12),
generic classification (SOU-14) and policy/result integration (SOU-15) consume
these inputs; this increment does not complete those tasks.

### Passive host configuration inspection

```sh
agentfw mcp-inspect-config --path /absolute/path/to/selected-host-config.json
```

The selected JSON file must contain a Claude-style `mcpServers` object. Inspection
only returns server names, transport support and `requires_explicit_selection`.
Command strings, arguments, environment values, URLs and headers are not printed.
It neither launches discovered commands nor contacts discovered URLs. The
supported configuration transport is explicit/default `stdio` with a nonempty
command and optional string arguments. Remote transports are reported unsupported.
The file limit is 1 MiB and 256 server entries; malformed or duplicate-key JSON
is refused without echoing its contents. Other host formats are unsupported.

Inventory support does not authorize execution or certify a server. Active
collection still requires the operator to explicitly select the local server
with `mcp --native-admission --id ... -- ...` and install its reviewed registry.
The command does not import a host file into an executable launch configuration.

### Supported validation profile

Original `tools/list` definitions, descriptions, schemas and supported annotations
remain in the admitted snapshot and `Invocation.definition`. `Invocation.args`
holds the parsed original arguments; accepted JSON-RPC bytes, including native
IDs, are forwarded unchanged. `Invocation.semantic_input()` excludes host call
IDs and trusted registry classes. Schema defaults never add an absent field.
No schema is promoted to `pinned_schema` by its own metadata.

| Shape | Supported constraints |
| --- | --- |
| Object | Explicit `type: object`, `properties`, `additionalProperties: false`; optional `required` contains unique declared keys |
| Array | Explicit `type: array` and one supported `items` schema |
| Scalars | `string`, `integer` (JSON integer representation), finite `number`, `boolean`, `null`; no coercion |
| Schema annotations | String `title`/`description` and inert `default`; original JSON retained |
| Tool annotations | String `title`; Boolean `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` |
| Limits | Depth 8 from root, 256 object properties/array elements, 1,024 schema nodes, 4,096 argument nodes, 16 KiB per argument string; existing 256 KiB frame limit |

References, unions/combinators, open objects, pagination, unknown keywords and
unlisted constraints are refused explicitly. Both schemas and actual arguments
must fit the profile. Annotation text is inspected at the existing manifest
boundary; hints cannot change registry permissions. Missing required fields,
wrong types and oversized inputs stop the collector before forwarding the call.
For a reusable synthetic schema see
[`nested_schema.json`](../../crates/agentfw/tests/fixtures/mcp_inputs/nested_schema.json).

### Definition refresh and prediction reuse identity

`Invocation` includes the operator-selected server ID, untrusted advertised
`server_info`, discovery snapshot/schema/definition SHA-256 values, original
arguments, classifier revision and `input_sha256`. The last digest binds the
`sou11-input-v1` profile, server identity, entire discovery snapshot, selected
definition/schema, arguments and classifier source/revision. Metadata, tool-list,
schema, server or classifier revision changes cannot retain the same key.
The hashes use the existing canonical JSON encoding; original objects stay intact.
Registry/policy identity remains separate in correlation context. Neither a
prediction key nor an optional trusted profile is an execution grant.

There is no cross-call prediction cache: every call is classified afresh. The
per-session definition cache is discarded before every discovery refresh and
on an advertised `notifications/tools/list_changed`. After that notification,
calls require a newly validated and admitted `tools/list`; stale definitions are
never a fallback. A schema or tool-set change outside the installed registry
is refused and requires operator review and a new session/configuration. The
collector never silently updates trusted pins. Notifications during an outstanding
request, unadvertised changes and malformed notifications end the collector;
withholding a result cannot undo an already executed call.

`input_sha256` and `definition_sha256` are included in the existing classification
audit line without logging original arguments or metadata. Classifiers without
a fixed revision have no reusable prediction-cache identity guarantee; debug
test doubles exercise transport, not classification quality. A downstream cache
must require a pinned revision and still run policy admission for every call.

### Reproduce the bounded checks

Requirements: Rust stable, platform C/C++ build tools and Python 3 on `PATH`.
Run from the repository root:

```sh
cargo test --locked -p agentfw --test mcp_inputs
cargo test --locked -p agentfw --lib input_identity_tests
cargo test --locked -p agentfw --test mcp_admission
```

The added `sou11_` integration cases use the existing disposable daemon/local
MCP fixture and execution ledger. They cover an unfamiliar tool with nested
arguments, missing/wrong/oversized inputs, original bytes and IDs, metadata refresh,
stale definition refusal, schema-pin changes and injection in annotation text.
The input tests also verify that inspecting a synthetic host configuration creates
no command marker and opens no loopback connection. Identity unit checks cover
server and classifier revision changes and preservation of original definitions.
These are synthetic local checks, not live-provider or arbitrary-server acceptance.

### Local SOU-11 evidence (2026-10-10)

Source: the accompanying SOU-11 changes based on main
`5ab2fb55b7c68ac95c06162e6edb656c26982f81`, using the contract and synthetic
registry/server configuration linked above. Environment: Windows, Rust/Cargo
1.99.0, Visual Studio 2022 C++ Build Tools, Python 3.13.12.

| Command | Actual result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets --locked -j 1 -- -D warnings` | Passed, no warnings |
| `cargo test --workspace --locked -j 1 -- --test-threads=2` | 890 passed, 0 failed, 5 ignored |
| `python -B -m unittest discover -s scripts/tests -p 'test_*.py' -v` | 174 passed, 9 skipped |
| `python -B -m unittest discover -s scripts/benchmarks -p 'test_*.py' -v` | 26 passed, 18 skipped |
| `python -B scripts/check_docs.py` | 63 Markdown files, 282 local links, 0 errors |

The Rust run includes 194 `agentfw` library tests, 43 MCP admission tests and
7 input-profile tests. Of those, 17 tests are added by SOU-11; existing tests
and their authorship are retained. The unrestricted parallel workspace build
initially exceeded available Windows commit memory; the recorded successful
run limits compilation to one job and test execution to two threads.

The five ignored Rust checks require a live local judge, disposable Redis and
PostgreSQL, or selected real OIDC/SAML endpoints. Python skips cover unavailable
symlink privileges, Unix/Linux-only behavior and explicitly selected AgentDojo/
native-daemon environments. No external provider, live Claude/Codex host,
Linux/macOS run or GitHub CI outcome is claimed by this Windows evidence.

## Local demonstration

The demonstration runs on Linux, macOS and Windows without a model, provider or
account. Linux CI runs it on every pull request:

```sh
cargo build --locked -p agentfw
python3 scripts/mcp-admission-demo.py
```

It creates a disposable Agent home under `target/`, starts `agentfw serve` in
enforcing mode with a demonstration registry and fixture policy, and wraps the
harmless [demonstration server](../../scripts/fixtures/mcp_admission_demo_server.py)
with `agentfw mcp --native-admission` and the `fixture-v1` classifier double.
It sends Claude Code's stdio frames, including the `_meta` correlation pair,
and checks each scenario against witnesses the firewall does not control: the
server's execution ledger, a loopback receiver and the note files.

| Scenario | Expected outcome | Independent witness |
| --- | --- | --- |
| `read_document` | Allow | Ledger holds the exact original frame; the harness receives the server's response byte-for-byte |
| `send_http` and unfamiliar `publish_report` with benign data | Allow | The receiver records exactly one delivery each |
| `send_http` with a synthetic secret, also with an understated `read` classification | Deny before execution | Ledger and receiver unchanged |
| `delete_note` | Deny before execution | Ledger unchanged; the note still exists |
| `send_http` containing an email address | Ask, held without an approval path | Ledger and receiver unchanged |
| Classifier timeout, crash, invalid scores, `unknown`, mixed actions | Policy not reached | Ledger and receiver unchanged |
| `read_document` returning an injection | Executed, result withheld | Ledger grows; the harness never receives the marker |
| Follow-up `read_document`, then daemon outage | Allow, then fail closed | Work continues; after the outage the collector exits and the ledger is unchanged |

The report `target/mcp-admission-demo.json` lists, per scenario, the original
host call id, expected and actual outcome, expected (`truth_actions`) and actual
classification with its source, policy reached or not, technical failure,
executor and receiver deltas, result release and latency. Each run summary
separates classification errors, false blocks, enforcement failures and
technical failures with their sample counts. The latency scope is one sample
per scenario from harness request to harness response with a debug build. The
report also records the commit, platform, binary, registry, policy and fixture
digests, and the daemon's own audit decisions. `--keep` retains the workspace.
The registry path must not contain linked components, so the script uses the
resolved `target/` directory rather than macOS `/tmp` or `/var`.

### Actual Claude Code host check

On macOS and Linux the same scenarios also run through an actual Claude Code
process when one is found (`--claude PATH`, `target/claude-code` or `PATH`).
Otherwise the report marks the host check `skipped` with the reason; a skipped
check is never shown as passed. A local Messages API stand-in proposes the fixed
tool calls and records every request Claude Code sends to the model; no real
model, provider account or credential is used. Claude Code runs with an isolated
profile, a fixture API key, restricted built-in tools and a strict MCP
configuration that launches the collector; outbound proxies point at a closed
loopback port.

```sh
npm install --prefix target/claude-code @anthropic-ai/claude-code
python3 scripts/mcp-admission-demo.py
```

This mode also checks that executed frames carry Claude's own `tool_use` ids and
original arguments and that the injected marker never appeared in any model
request. It records the Claude Code version and observed call metadata keys. The
daemon-outage case and per-call latency are scripted-only. MCP host release does
not attest what a model later observes. The Windows actual-host check below
remains the separate Windows evidence.

## Reproducible Claude Code check

The isolated Windows check uses the installed Claude Code, two original local
MCP tools and a deterministic loopback Messages provider. It copies only OS
runtime variables, uses disposable Claude/Agent profiles and fixture-only keys,
and refuses outbound proxy requests. It does not use a real model or provider.

The private document, raw Messages requests and Claude stdout/stderr are encrypted
before storage with current-user Windows DPAPI. The original `read_document`
tool decrypts the same document for both cases; the reviewed MCP schemas and
plaintext result remain identical. Evidence distinguishes the plaintext document
hash from the encrypted file hash. Decryption checks the bounded payload version,
length and digest and has no plaintext fallback. The owner-only runtime ACL still
applies. Other processes running as the same Windows user can decrypt these files;
this fixture storage is not a production secrets vault. Incomplete attempts retain
encrypted diagnostics; earlier retained attempts predate this storage correction.

Run on native Windows with Python 3.10 or later, an installed Claude Code
executable supporting `--restricted`, `--strict-mcp-config` and
`--no-session-persistence`, and Git for Windows with Git Bash. The harness uses
these existing installations. For custom locations, pass `--claude-binary` and
`--git-bash` with absolute paths.

```powershell
cargo build --locked -p agentfw --bin agentfw
python scripts/windows-claude-mcp-acceptance.py --run --evidence target/claude-mcp-new.json
```

The control must execute the send and deliver the synthetic secret. The defended
case must propose the matched send, refuse it before server execution, retain
no secret at the independent local receiver and finish the legitimate task.
The useful result is evaluated independently from the document's facts; stopping
the entire task is not a pass. A separate result-withholding check covers the
return boundary. Binary/source, policy, registry, fixture and evaluator versions
belong in the sanitized aggregate, together with failed attempts and cleanup.

The check deliberately uses a custom fixture policy so the infected document
can reach the scripted provider and the send boundary can be exercised. It
establishes these concrete execution and continuation behaviors, not shipped
policy effectiveness, held-out attack success or live defended task utility.
Those require an operator-selected model, access and spend budget.

The [2026-10-05 committed-source proof](../benchmarks/evidence/CLAUDE_MCP_STDIO_2026-10-05.md)
records the actual matched control/protected pair, successful useful completion,
preserved incomplete attempts and cleanup limits.
