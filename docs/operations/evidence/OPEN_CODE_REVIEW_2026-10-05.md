# OpenCodeReview delegation checkpoint

The official [Alibaba OpenCodeReview v1.12.12](https://github.com/alibaba/open-code-review/tree/v1.12.12)
Windows binary, source `182898cf522da3d04157b422752d028417974e19`, was verified
against the release API digest and published checksum. The actual CLI ran
delegation preview/rules on frozen `50b6b4e..e275019` and full-tree `scan --preview`.
Its home/config was isolated, provider credentials cleared and telemetry off.
No extra external provider calls, global installation or GitHub comments occurred.

The CLI selected 22 of 31 changed files. The host agent also reviewed all nine
excluded files, including native Python tests and documentation. Full-tree
preview selected 187 of 240 files; that command selects inputs and is **not** an
autonomous completed defect scan. Large unchanged PostgreSQL/tenant-store files
were excluded by the tool. No complete-project clean audit is claimed.

The rule-guided host review confirmed a policy-ordering defect with the actual
AgentFirewall hook and native entrypoints: an unknown-host call returned Ask
without taint but Allow after admitted ordinary foreign URL content. The earlier
tainted escalation used fallback Allow and preempted the explicit unknown-host
Ask. `0c333cd` moves every explicit Ask ahead of the weaker escalation, preserving
allowlisted ordinary side-effect fallback and stronger destructive/secret Deny.
Two real-engine regressions cover both entrypoints and overlapping conditions.

All 157 Agent tests, focused Clippy and formatting pass. The release corpus still
interrupts 19/19 reviewed attacks and preserves 21/21 benign sessions. The rebuilt
Agent passes [26 native checks](../../benchmarks/evidence/agentdojo-native-after-review-2026-10-05.json)
and [29 fallback checks](../../benchmarks/evidence/agentdojo-fallback-after-review-2026-10-05.json)
on clean `0c333cd`. Native production orchestration makes seven scripted loopback
HTTP requests; no real model or paid provider is called. Newly owned profiles
cleaned successfully. Previously denied profile removal remains a separate
historical limitation.

Hosted CodeQL additionally flagged two fixed nonce strings in new test fixtures.
`8f607f5` replaces them with fresh values from the existing token generator;
13 hook and 28 native endpoint regressions pass. No CodeQL query was disabled
and these new alerts were not dismissed.

The [aggregate report](OPEN_CODE_REVIEW_2026-10-05.json) records executable/source
hashes, the complete changed-file ledger, original/corrected policy hashes,
before/after probe hashes and coverage limits. This is delegation plus host-agent
review, without OpenCodeReview-managed model inference.
