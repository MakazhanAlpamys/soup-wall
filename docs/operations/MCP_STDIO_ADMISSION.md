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
