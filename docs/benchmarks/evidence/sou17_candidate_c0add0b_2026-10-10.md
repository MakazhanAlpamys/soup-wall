# SOU-17 independent recheck of candidate c0add0b

Owner: konung3. Review coordinator: Nari_Ab. Roadmap: R06, bounded P01–P02.

The previous refusal-capacity regression is **fixed** on clean SOU-15 PR #62 head
`c0add0b139e82daedc01bc0c5f26b2711a651cca`. The unchanged PR #67 probe observed
64 correlated Ask refusals with zero execution, followed by a useful Allow that
executed exactly once and released 123 original result bytes. This supersedes the
capacity outcome in the [historical b76910a report](sou17_candidate_b76910a_2026-10-10.md).
**Final SOU-17 acceptance remains pending the completed, reviewed integration.**

[Structured outcomes](sou17_candidate_c0add0b_2026-10-10.json) retain the complete
launcher manifest, individual production-probe outcomes, source/configuration,
artifact hashes and timings. [Raw witness excerpts](sou17_candidate_c0add0b_2026-10-10.txt)
retain independent executor frames, native decisions and actual client responses.
Historical failures are preserved unchanged.

## Exact source and execution

Native macOS arm64 / Darwin 25.3.0, Rust/Cargo 1.99.0, Python 3.14.3; locked offline
dependencies, default Cargo features, debug information and incremental compilation
disabled. Candidate source was clean and unchanged before/after all probes.
Launcher manifest SHA-256:
`55362006739ac874c3f1604d60aea44b067c7ac785b270d7c088e5b8fe6d591f`.
Built agentfw SHA-256:
`a1eedb55117380613f94af79cb81f6b5f3bbb5994032d784d3456d98b70127fd`.
The probes used a saved copy of that exact binary and unchanged verification
scripts from `c41d1ac85346031394c74f2876584c05e156b897`.

No competing pipeline was defined: the probes reuse the repository's actual
native daemon, MCP collector, production classifier bridge, policy and local
fixture executor. Synthetic classifier replies test enforcement, not model quality.
Execution and original result release have separate raw-byte witnesses; refusal
text is not protected result content. No external model, paid service or user data
was used. These loopback fixtures are not OS sandboxing evidence.

| Check | Observed outcome |
| --- | --- |
| Exact-commit launcher | 105 pass: 19 adapter resilience, 49 MCP admission, 37 native endpoint; 35 witness records; zero failures/skips |
| Additional resource receipt tests | 2 pass, zero failures/skips; missing/changed digest and old contract refused over HTTP |
| Unchanged classifier-boundary probe | 12/12 bounded expectations observed; five explicitly unsupported mappings |
| Unchanged refusal-capacity probe | Pass: 64 Ask refusals, zero refused executor entries; 65th useful call executes once and returns its exact result |

Among call/result events, native audit in the capacity probe now contains only
the useful call's Allow and result Allow. Refused calls reserve no native grants. The collector exits 0, the
original useful call bytes are preserved, and the independent receiver records
zero deliveries. The fresh matrix benign control separately executes once and
returns 118 exact original bytes. High-uncertainty Read has zero effects and zero
original result bytes. Malformed classifier JSON, NaN, invalid confidence/uncertainty
and missing confidence all fail closed before execution.

## Resource fixes and remaining acceptance

Source review and the new endpoint regressions confirm typed resource authorization
before grant reservation: repeat extraction from actual arguments, match pinned
operator revisions and exact permitted resources, reject legacy downgrade and
bind the original host ID. Receipt validation now requires canonical digest equality.
Completion consumes the one-shot grant and rejects changed identity/contract.

The false confinement assertion has been removed. Generic stdio calls with a
resource profile or native resource policy return `resource_executor_unsupported`,
including when the old environment flag is asserted. This is a safe explicit
refusal, **not positive resource-aware execution support**. The native resource
tests establish router permissions/receipts; they do not establish arbitrary-server
containment or successful resource call → constrained executor → released result.
See the candidate's [resource contract documentation](https://github.com/SoupTeam/soup-wall/blob/c0add0b139e82daedc01bc0c5f26b2711a651cca/docs/operations/NATIVE_RESOURCE_ADMISSION.md).

Unknown, Read+Unknown and Read+Delete/SendData/ChangePermissions remain technical
`unsupported_classification_mapping` refusals with `policy: not_reached`. All five
have zero effects and original result bytes; they cannot count as integrated
ordinary Ask/Deny semantics or generic-classifier acceptance.

Source still puts uncertainty Ask before write-on-ReadOnly Deny. Both remain
blocked, but hard-deny overlap precedence needs an agreed production rule and
regression. Cancellation while awaiting classification/native admission also
remains unverified; existing tests cover before a call and after an effect. Several
lifecycle fixtures omit the production classifier. These are remaining acceptance
items, not newly reproduced execution bypasses in this run. Re-run the affected
suite on the reviewed integrated configuration and after any subsequent code change.

One request observation per fresh matrix case measured 27.80–64.23 ms, including
Python startup/admission. This is not latency overhead or population percentiles.
Fresh benign interruption: 0/1; useful followup after 64 Ask: 0/1, previously 1/1.
Do not pool these designed controls into a population false-positive rate. Accepted
latency/interruption limits, actual intended host coverage and final review remain
outstanding. No actual Claude Code or new baseline demonstration was run here.

GitHub at inspection showed 15 successful, eight in-progress and one neutral
checks on c0add0b, with requested changes still present. The
[maintainer's repair note](https://github.com/SoupTeam/soup-wall/pull/62#pullrequestreview-5480330701)
also explicitly leaves SOU-15 open. This report claims no final CI outcome and no
new code-scanning inventory/rescan. The previous dated CodeQL triage remains separate.

## Reproduce

Use the [development prerequisites](../../DEVELOPMENT.md) and the unchanged probes
from PR #67. Keep the exact clean candidate and binary separate from the verification
checkout; choose new output directories to preserve evidence.

```sh
CANDIDATE_REPO="$PWD/../soup-wall-sou17-candidate"
git worktree add --detach "$CANDIDATE_REPO" c0add0b139e82daedc01bc0c5f26b2711a651cca
(
  cd "$CANDIDATE_REPO"
  CARGO_TARGET_DIR="$CANDIDATE_REPO/target" python3 scripts/verify-sou17.py \
    --expected-commit c0add0b139e82daedc01bc0c5f26b2711a651cca --offline
  cargo test --locked --offline -p agentfw --lib resource_receipt_tests -- --test-threads=1
)
python3 scripts/verify-sou17-refusal-capacity.py \
  --repo "$CANDIDATE_REPO" --agentfw "$CANDIDATE_REPO/target/debug/agentfw" \
  --expected-commit c0add0b139e82daedc01bc0c5f26b2711a651cca \
  --output target/sou17-c0add0b-capacity
python3 scripts/verify-sou17-classifier-boundary.py \
  --repo "$CANDIDATE_REPO" --agentfw "$CANDIDATE_REPO/target/debug/agentfw" \
  --expected-commit c0add0b139e82daedc01bc0c5f26b2711a651cca \
  --output target/sou17-c0add0b-classifier
```

Both probes exit 0 for the bounded observations above, while retaining
`acceptance_passed: false`. Passing them does not authorize execution or close SOU-17.
