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
text-only tool results. Input schemas are closed top-level objects with required
string fields; the collector checks the actual arguments against that supported
schema before admission. Complex schemas, defaults and implicit destinations
are outside this contract. Results contain only original text blocks and an
optional Boolean `isError`; JSON-RPC errors contain an integer code and message.

When present, supported Claude call metadata contains exactly a nonempty
`claudecode/toolUseId` string of at most 128 ASCII letters, digits, `_` or `-`, and a nonnegative integer
`progressToken` no greater than 2^53 - 1. These host correlation fields
grant no authority and do not change argument inspection. The accepted original
request bytes, including those fields, reach the server unchanged. Other call
metadata and server progress notifications are outside the supported contract.

Batched calls, tool-call notifications, duplicate/replayed identifiers,
unrecognized content paths, server-initiated requests, multimedia, embedded
resources, structured content and result/server metadata are unsupported. This is a bounded
integration, not a general MCP transport, concurrent executor, child-authority
system or human approval channel. Ask and Deny must prevent the affected call
or result; a correlated refusal lets a supported client continue ordinary work.
Transport uncertainty ends the collector rather than silently switching to
the legacy relay. Explicitly inspect the retained evidence and refusal behavior
before attaching another server or runtime.

## Portable local execution check

The deterministic MCP client in
[mcp-local-acceptance.py](../../scripts/mcp-local-acceptance.py) exercises the
actual Agent executable, stdio admission proxy and
[synthetic local server](../../scripts/fixtures/local_mcp_server.py).
It needs the built Agent and Python 3.10+ with its standard library.
It needs no Claude installation, provider account, model or paid API.
From the repository root on macOS or Linux:

```sh
cargo build --locked -p agentfw --bin agentfw
python3 scripts/mcp-local-acceptance.py --run --evidence target/mcp-local-acceptance.json
```

On Windows, use the same build command and replace `python3` with `python`.
For a release binary, add `--agent-binary /absolute/path/to/agentfw`
(or an absolute Windows executable path). Omit `--run` to print prerequisites
without starting processes. Every run requires a fresh evidence destination;
the driver refuses to overwrite previous results.

The driver reserves a disposable profile and resolves its temporary root before
writing the registry. This handles macOS's ordinary `/var` to `/private/var`
alias while keeping production registry symlink checks intact.
The real `agentfw install` bootstraps only that profile; no user hooks or existing
configuration are changed. Child environments exclude provider keys, proxy
settings and inherited Agent credentials. The server can send only to the
driver's exact numeric-loopback receiver, without redirects.

The custom demo policy denies synthetic credential egress, requires confirmation
for email egress, and requires confirmation for injected result text. It is
identified by a digest and does not replace the shipped policy. Its email rule
uses `pii.email` so the receiver's loopback IP alone does not request confirmation.

| Check | Required observation |
| --- | --- |
| Control send | The original valid request executes and reaches the local receiver |
| Allowed read and send | Original request hashes, IDs and result bytes match; the send is received |
| Denied send | Same request as the control, zero executor entries and receiver deliveries |
| Confirmation-required call and retry | Both are audited as Ask, with zero executor entries or deliveries |
| Rejected result | The read executes; decoded injection text is refused before client release |
| Ordinary error and follow-up | Original JSON-RPC error bytes survive; a benign task still completes |

The executor records entry before validation and effects. The receiver independently
records actual deliveries, and the Agent audit confirms policy decisions.
Missing transport, unrelated tool errors and incomplete runs cannot count as
successful prevention. Reports include observed counts, binary/source, policy
and registry hashes; they exclude tokens, raw arguments, response content and
receiver addresses. The driver stops its processes and removes its owned runtime;
cleanup failure prevents a passing report. The output reserved before startup
remains marked incomplete if the run cannot finish.

There is no native human approval/resume path. Ask remains blocked; the
existing hook-specific `agentfw approve` command cannot authorize these MCP
calls. A subprocess regression explicitly checks that a matching signed hook
grant is not redeemed and that subsequent benign calls still work.

This client proves the selected protocol and execution boundaries. It does
not prove compatibility with every Claude Code, Codex or other MCP host.
Some requests exercise the already supported Claude correlation metadata;
that is a protocol test, not an actual Claude-host run. The full CI matrix
includes Linux, both macOS release architectures and Windows; passing evidence
from one machine does not establish another platform's result.
Use the real-host procedure below when actual Claude integration is required.

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
