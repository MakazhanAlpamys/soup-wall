# Code scanning triage — 2026-10-11

Initial triage is prepared for the October 11 deadline. Authorized GitHub UI access
showed **six open Critical alerts and 74 closed alerts** for `is:open branch:main`.
All six open findings have rule `rust/hard-coded-cryptographic-value`, list only
`main` as an affected branch, and show no GitHub assignee. The evidence supports
false-positive recommendations for production-secret defects; **all six alerts
remain open pending technical review**. No dismissal, confirmed defect, remediation
issue or fix was established in this review.

[Structured inventory](CODE_SCANNING_TRIAGE_2026-10-11.json) records alert URLs,
rule, severity, locations, revisions, hashes, analysis status and follow-up owners.
Raw authenticated UI snapshots stay local; the committed summary excludes account
navigation and literal cryptographic fixture values.

## Exact source and analysis

- Reviewed main source: `9b055a6d97166a9b3f9347c45c305038c331cfcf`.
- Initial Rust scan and alert source: `900cc3a03bb9fef32b62e0fc4eed6c92eb299ef8`.
- Follow-up Rust scan and all six alert source links: `9b055a6d97166a9b3f9347c45c305038c331cfcf`.
- [Rust default-setup configuration](https://github.com/SoupTeam/soup-wall/security/code-scanning/tools/CodeQL/status/configurations/automatic/2b7122206b8ac86cd7b88fd927bd502861908b2a6bfb3dfdcf2968009cb71086) reported working as expected,
  last scan October 11: CodeQL 2.27.2, `/language:rust`, rust-queries 0.1.44,
  rust-all 0.2.23 and threat-models 1.0.59.
- Initially the sidebar showed Python and Actions on `9b055a6` and Rust on
  `900cc3a`. A later authenticated refresh showed all three configurations on
  `9b055a6`. Rust reported working as expected; each of the six alerts was
  reread and linked to this exact revision. This closes the observed scan lag,
  without clearing the six open findings or constituting a remediation scan.

`git show` of both affected files at the analyzed and reviewed commits produced
identical bytes and the hashes recorded in previous triage:

| File | SHA-256 |
| --- | --- |
| `provider_baseline.rs` | `70755b1ffd48ba145a7689b0a0572fc8be4d833c35dd419528a14fc9ad212fce` |
| `provider_parity.rs` | `29afd20f093375a539bb2efd8b0818bd6017671c966001be396bdafc0ad3889f` |

## Per-alert assessment

| Alert | Reviewed source | Evidence-backed rationale | Disposition |
| --- | --- | --- | --- |
| [#85](https://github.com/SoupTeam/soup-wall/security/code-scanning/85) | [provider_baseline.rs:165](https://github.com/SoupTeam/soup-wall/blob/9b055a6d97166a9b3f9347c45c305038c331cfcf/vendor/kryptering/tests/provider_baseline.rs#L165) | PBKDF2 known-answer input with fixed expected bytes; FIPS mode rejects undersized parameters. | Open; FP recommendation awaits review |
| [#86](https://github.com/SoupTeam/soup-wall/security/code-scanning/86) | [provider_baseline.rs:193](https://github.com/SoupTeam/soup-wall/blob/9b055a6d97166a9b3f9347c45c305038c331cfcf/vendor/kryptering/tests/provider_baseline.rs#L193) | Compliant PBKDF2 known-answer input; fixed expected output, independently documented Python hashlib comparison. | Open; FP recommendation awaits review |
| [#87](https://github.com/SoupTeam/soup-wall/security/code-scanning/87) | [provider_baseline.rs:524](https://github.com/SoupTeam/soup-wall/blob/9b055a6d97166a9b3f9347c45c305038c331cfcf/vendor/kryptering/tests/provider_baseline.rs#L524) | Negative RustCrypto test asserts UnsupportedAlgorithm before input parsing; no credential is installed. | Open; FP recommendation awaits review |
| [#88](https://github.com/SoupTeam/soup-wall/security/code-scanning/88) | [provider_baseline.rs:549](https://github.com/SoupTeam/soup-wall/blob/9b055a6d97166a9b3f9347c45c305038c331cfcf/vendor/kryptering/tests/provider_baseline.rs#L549) | Negative FIPS test asserts refusal of SHA-1 PBKDF2 before parameter validation. | Open; FP recommendation awaits review |
| [#89](https://github.com/SoupTeam/soup-wall/security/code-scanning/89) | [provider_parity.rs:502](https://github.com/SoupTeam/soup-wall/blob/9b055a6d97166a9b3f9347c45c305038c331cfcf/vendor/kryptering/tests/provider_parity.rs#L502) | Fixed PBKDF2 expected outputs check provider parity; FIPS mode rejects undersized parameters. | Open; FP recommendation awaits review |
| [#90](https://github.com/SoupTeam/soup-wall/security/code-scanning/90) | [provider_parity.rs:532](https://github.com/SoupTeam/soup-wall/blob/9b055a6d97166a9b3f9347c45c305038c331cfcf/vendor/kryptering/tests/provider_parity.rs#L532) | Compliant PBKDF2 parameter variants check fixed expected outputs across providers. | Open; FP recommendation awaits review |

These inputs belong to explicit integration-test targets in
[the vendored manifest](../../../vendor/kryptering/Cargo.toml), separate from its
`src/lib.rs` production library. The application workspace excludes the vendored
crate as a member while using its library as a dependency. Source searches found
no production import or inclusion of these test files. Release packaging includes
application binaries and the vendored licence, not test targets. Fixed expected
outputs and intentional rejection cases need deterministic inputs; no deployed
credential was evidenced at these locations. Randomizing the fixtures to silence
the query would weaken those checks.

## Review and delivery

Konung3 owns triage and verification. **Nari_Ab coordinates affected-code technical
review within the implementation team**; no CODEOWNERS or module-owner assignment
was verified. Obtain and record a reviewer-supported disposition for each alert.
Any actual dismissal needs its explicit rationale. Until then, the six open
recommendations must remain visible as pending work.

Link this inventory and its pending review status in SOU-17 by October 11, 23:59.
For any newly confirmed defect, create a focused linked remediation issue with
impact, priority, implementation owner/reviewer and capacity/dependency risks.
The affected implementation owner provides the fix and boundary regression;
konung3 verifies a new scan of the exact fix commit by October 12, 23:59. There
is no such fix or remediation rescan to claim for the current six recommendations.

Refresh inventory and exact-source scan evidence on the final integrated candidate;
changes after verification require affected checks again. Report access, scan or
review blockers explicitly. Userarlan/SOU-18 owns scanning configuration and actual
merge-gate acceptance; no settings were changed or duplicated here. A working scan
or clean PR delta does not clear existing main alerts, prove merge protection or
establish tool-call enforcement effectiveness.
