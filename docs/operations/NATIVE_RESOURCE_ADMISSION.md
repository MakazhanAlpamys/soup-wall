# Native resource admission

The opt-in `sw-native/resources/1` contract at `/native/v1` checks permissions and one-shot correlation for an authenticated trusted collector. It does not attest an executor sandbox. The shipped generic stdio relay refuses resource-profiled calls until a reviewed executor can enforce grants at the actual file/network boundary. See [MCP admission](MCP_STDIO_ADMISSION.md).

## Operator configuration

The registry remains `sw-native/1`. Each tool can optionally carry a closed `resource_policy` object with:

- `profile`: the existing typed ResourceProfile (server ID, tool, schema digest and 1–32 selectors).
- `workspace` and `cwd`: existing absolute directories, with canonical cwd inside workspace.
- `executor_sha256` and `classifier_sha256`: operator-reviewed revision digests.
- `allowed_resources`: 1–256 complete normalized Resource values.

Digests must be 64 lowercase hexadecimal characters. The profile must match the installed tool and schema. This policy is loaded from trusted operator configuration, never from a call or MCP annotations. Existing native policy and declared egress checks still apply after resource checks.

Allowed resources use the [existing extractor's typed shapes](../../crates/agentfw/src/mcp/resources.rs): a URL's canonical text, host and port; a canonical absolute path; a domain; or a mailbox address and domain. Membership is exact. A permitted host does not authorize another URL port/path, and a permitted mail domain does not authorize another mailbox. A domain-only selector expresses domain scope; use URL selectors for URL-level restrictions.

## Request and receipt

Start/end sessions with the existing `sw-native/1` events. A resource call uses `contract_version: "sw-native/resources/1"`, the usual registry hash, session, `event: "call"`, tool, args and schema digest. It also requires a closed `resource_admission` object:

| Field | Meaning |
| --- | --- |
| `server_id` | Operator-reviewed profile's server identity |
| `host_call_id` | Original bounded integer/string JSON-RPC ID |
| `profile_sha256` | Normalized operator profile digest |
| `executor_sha256`, `classifier_sha256` | Operator-reviewed revision digests |
| `snapshot_sha256`, `definition_sha256`, `input_sha256` | Admitted discovery/classification correlation digests |
| `resources` | Nonempty typed evidence array (pointer, source and resource), maximum 256 |

The daemon checks the pinned server/profile/executor/classifier identities, repeats extraction from the **actual args** using operator selectors, and requires complete derived evidence to equal supplied evidence. Every resource must be explicitly allowed. Missing policy, ambiguous extraction, forged evidence, untyped arrays and stale pinned revisions fail closed. A Deny gets no call ID or invocation grant. Metadata obeys both protocol and configured record byte limits.

The trusted collector remains responsible for validating discovery and classification before submission. Snapshot/definition/input hashes are bound correlation fields, not independent discovery or model attestations from this daemon. Changing any of them, the original host ID, resources, args or revisions changes the opaque invocation binding.

For hashing, deserialize profiles/evidence into typed Rust shapes, serialize them including selector defaults, recursively sort JSON object keys, serialize compact JSON and SHA-256 the UTF-8 bytes. Arrays retain order. `resources_sha256` covers the normalized evidence array. The collector must require exact equality, not just valid digest syntax. Missing/mismatched hashes and unsolicited hashes on legacy receipts fail closed.

Result/context events retain the call's contract version and ordinary grant fields. A `delivery: "mcp_host"` result must retain the bound original JSON-RPC ID. A wrong stage/version/ID spends the grant and refuses release. Legacy binding bytes remain unchanged without resource admission. An installed resource policy cannot be bypassed with a legacy call.

## Verification and remaining work

```sh
cargo test --locked -p agentfw --test native_endpoint
cargo test --locked -p agentfw --test mcp_admission
cargo test --locked -p agentfw resource_receipt_tests
python3 scripts/verify-sou17.py --allow-dirty --offline
```

These exercise the real native router and stdio boundary, positive legacy execution and negative unsupported resource execution. They do not establish arbitrary-server containment, actual Claude Code availability, generic classification coverage or complete SOU-15 acceptance. Resource-aware execution requires a separately reviewed operation-level constrained executor.
