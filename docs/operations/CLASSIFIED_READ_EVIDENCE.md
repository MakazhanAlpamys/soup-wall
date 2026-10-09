# Classified read seam evidence

This procedure checks the Task 2 classifier seam on the existing protected stdio MCP path. It uses a fixed **test double**, `test-double/read-v1`; the real Team 1 classifier and shared Teams 1/2/3 contract approval are still required for integrated acceptance.

Run from the repository root:

```sh
cargo test -p agentfw --test mcp_admission classified_read_keeps_original_call_and_result_bytes
```

The test starts a local daemon and MCP server. It sends one `read_document({"path":"memo-1"})` call with numeric host ID `39` through the protected collector. The test checks the structured classification record, the daemon's Allow and result-release audit entries, the exact original request bytes in the server execution ledger, and the exact matching result bytes returned to the client. The classifier result is `actions=["read"]`, `unknown=false`; the candidate singleton mapping is `ReadOnly`, matching the trusted registry baseline. The collector records argument and schema digests without logging argument or reason text.

The classifier seam is a local Rust `InvocationClassifier` trait. The test switch `AGENTFW_TEST_CLASSIFIER_READ=1` is accepted only in debug builds and is removed from the MCP server's environment. Ordinary protected admission retains its existing registry behavior when no classifier is installed. This test proves only the read seam and its existing policy path. It does not establish the final contract version, mixed-action or unknown handling, real classifier quality, or actual Claude Code host observation.

Singleton mappings for every candidate action, `baseline_mismatch` evidence, unsupported mixed or unknown results and classifier timeout, crash and invalid-output failures are covered separately by the `fixture-v1` test double; see the [classifier seam](MCP_STDIO_ADMISSION.md#classifier-seam) and the [local demonstration](MCP_STDIO_ADMISSION.md#local-demonstration).
