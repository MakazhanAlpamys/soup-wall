# SOU-19 classifier edge-case review (2026-10-10)

Roadmap: A01, A03, A06. This bounded contribution reuses the shared classifier,
runner and SOU-21 fixtures. The classifier implementation and its original
54 tests belong to the baseline owner. This change adds five classifier review
tests and four evaluator test methods, and validates optional scalar scores in
the existing evaluator. It does not implement a second evaluation pipeline.

## Reviewed source and contract

- Repository base: `6da8aadb3f6e2f160fe3a259816540559e1e3798` (main, includes
  merged classifier PR #53, contract PR #57, and initial bridge PR #58).
- Reviewed classifier Git blob: `ab01f17b96b57d9decae24deec43a2dbc7a45b9d`.
- Reviewed contract: [SOU-10 v0.4](../../../contract/updated_contract2.md),
  commit `4820bbae4f1f9eb543fee450fb12548b6de800ac`, Git blob
  `b5d5349917d5abc32703c17e4f1f2612980c12ce`.
- The classifier text matches the previously supplied corrected file after
  normalizing line endings. Git checkout CRLF conversion changes raw-file hashes;
  use the Git blob above to identify repository source.
- Environment: Windows, Python 3.13.12. No external model, provider or real tool
  call was used by classification evaluation.

## Changes and attribution

The owner already fixed the previously reported quoted-separator, comment,
redirection, workflow-data and unknown propagation examples. Existing tests
cover these fixes, including unknown after sudo; they are not duplicated here.

`rule_baseline/test_contract_edges.py` retains explicit command-tail and
depth-limit regressions, adds propagation from truncated workflow children,
checks argument immutability, and checks missing/malformed tool names under the
existing local diagnostic error convention. These are five passing test methods.

Before this change, `eval_runner.check_output` accepted invalid optional
confidence/uncertainty. For example, an otherwise matching output with
`confidence=-0.01`, `uncertainty="0.8"` or `confidence=NaN` could pass. SOU-10
requires finite numbers in [0,1]. The existing evaluator now reports a technical
error for invalid supplied values, including booleans and null. Omitted optional
fields and explicit no-op remain valid. Tests also verify expected-unknown and
pending cases cannot conceal these errors and a later valid case still runs.

This changes diagnostic output validation only. It does not establish runtime
authorization, change classifier predictions, edit historical gold labels or
define every legacy per-action `scores` extension. The bridge already contains
finite/range checks for its selected profile; that Rust path was read, not run.

## Results

| Check | Outcome |
|---|---|
| Baseline unit suite | 59/59 passed (54 existing + 5 added) |
| Evaluation runner unit suite | 32/32 passed (28 existing + 4 added) |
| Frozen core v0.4 | 21/21 passed; 2 pending |
| Challenge v0.1 | 28/34 passed; 6 mismatches; 1 pending |
| SOU-21 mixed-action v0.1 | 4/4 passed |
| SOU-21 benign comparison v0.1 | 1/1 passed |
| Four fixture suites combined | 54/60 passed; 6 mismatches; 0 technical errors; 3 pending; 0 constraint violations |
| scripts/tests | 183 total: 174 passed, 9 skipped |
| scripts/benchmarks | 44 total: 26 passed, 18 skipped |

The unchanged challenge mismatches are CU01, CU02, CU03, CM01, CX06 and CS06.
CU02 still misses delete while returning unknown; it is not a true positive.
The original report identifies several disputed expectations. See the captured
[summary](summary.md), [per-case CSV](results.csv) and [JSON](results.json).
Fixture expectations remain provisional; this is synthetic diagnostic evidence,
not held-out accuracy or proof of execution protection. Evaluation exit 1 is
expected for the six recorded classification mismatches.

The general Python skips concern unavailable pinned AgentDojo runtime/daemon,
platform-specific POSIX paths/permissions/process groups, and an unavailable
Windows symlink operation. They are not passes. Native Rust prerequisites and
binaries are not installed in this environment: cargo fmt, clippy, workspace
tests, and real MCP admission acceptance are unverified here and remain required
in the repository's CI/review workflow. No merge or complete-task claim is made.

## Reproduce from the repository root

On Windows use `python`, a writable TEMP/TMP and PYTHONPATH for this checkout:

```powershell
$reviewTemp = Join-Path $PWD 'local-notes\sou19-temp'
New-Item -ItemType Directory -Force -Path $reviewTemp | Out-Null
$env:TEMP = $reviewTemp
$env:TMP = $reviewTemp
$env:PYTHONPATH = Join-Path $PWD 'rule_baseline'
python -B -m unittest discover -s rule_baseline -p 'test_*.py' -v
python -B -m unittest discover -s eval -p 'test_*.py' -v
python -B eval/eval_runner.py eval/fixtures/soup_task1_evaluation_cases_v0.4.json eval/fixtures/soup_task1_challenge_cases_v0.1.json eval/fixtures/soup_task1_mixed_actions_urtisto_v0.1.json eval/fixtures/soup_task1_benign_comparison_urtisto_v0.1.json --classifier-path rule_baseline --out-dir local-notes/sou19-evaluation
python -B -m unittest discover -s scripts/tests -p 'test_*.py'
python -B -m unittest discover -s scripts/benchmarks -p 'test_*.py'
python -B scripts/check_docs.py
```

Linux/macOS can use python3, their normal temporary directory and the same test
and evaluator arguments. CI already discovers both new test files through the
existing suite commands. No workflow change is needed. The local Windows
interpreter emitted a location warning but completed all recorded Python runs.

## Acceptance boundaries and handoff

The historical draft is already superseded by the versioned SOU-10 contract;
this PR references it and does not republish an internal draft. Call correlation
belongs to the orchestrator; these tests do not add call IDs to semantic input.

The diagnostic classifier still has a legacy error envelope and can infer read
from a name with missing/null arguments. The object-argument admission profile
owns rejection before dispatch. This work does not certify that boundary: native
admission tests require the missing Rust build. No new desired labels for those
invalid inputs are silently substituted into the frozen fixtures.

For follow-up, the baseline owner retains core changes and the interface/bridge
owners retain pinned-schema validation, typed failures and all policy/resource
restrictions. The current approved contract permits a bounded bridge that refuses
unsupported mappings; generic unknown forwarding and multi-action policy support
still need their own acceptance. SOU-19 should not be marked Done solely from this
evidence directory; link the reviewed contribution and required check outcomes.
