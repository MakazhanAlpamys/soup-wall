# Task 1: Tool-call classification, final evaluation report (SOU-20)

Date: 10 October 2026. Owner: @iazizza. PR review coordinator and parent
delivery owner: @sake_ai. Parent task: SOU-5 (Task 1); evaluation handoff: SOU-7 (Task 3).
Roadmap: A06, F07; E02/E04 measurement preparation.
Contract: [SOU-10 v0.4](../../contract/updated_contract2.md), decisions D01 to D10 accepted.

This report consolidates the Task 1 research, evaluation runs, add-on fixtures
and defect notes into one place. Section 4 is the **final current-baseline run**,
made for this report on `main` at commit `8e1d4d7d81da525f7592e2111d36eedba2da9706`. Section 5 holds the
**historical runs**, kept for traceability only. All results are synthetic
developer regression evidence, not held-out accuracy and not proof of execution
safety. Gold labels stay provisional until the contract fixture updates and a
second label review are complete.

## 1. Summary

- **Prototype:** a deterministic rule-based classifier
  ([`rule_baseline/`](../../rule_baseline/README.md), PR #53, owner @sake_ai).
  It reads the tool name, schema and actual arguments and returns `actions`
  (read, write, delete, send_data, change_permissions) plus a separate Boolean
  `unknown`. It never executes tools and never returns Allow/Ask/Deny.
- **Final run:** 54/60 scored cases pass on four fixture suites, 0 technical
  errors, 3 pending. Core suites alone: 49/55.
- **Critical labels:** no confident miss. The one missed critical label
  (`delete` on CU02) comes back with `unknown=true`. D08 requires policy Ask
  or trusted Deny for unresolved effects. This run measured neither policy nor
  execution; the current MCP bridge refuses unknown/mixed mappings before
  native policy rather than implementing Ask continuation. CU02 remains a miss.
- **Untrusted descriptions:** misleading-metadata cases pass 12/13.
- **Model-based candidates:** the v5 research plan, a Jev shadow adapter (SOU-6)
  and a local learned pilot (SOU-16) exist, but **no model has a measured
  quality run**. No model accuracy is claimed.
- **Recommendation:** retain the rule baseline as the runnable reference while
  its D06/D07 gaps and generic/runtime integration are completed. Keep model
  candidates in shadow mode until reviewed data and approved access exist.

## 2. Sources and provenance

| Source | Author / owner | Date | Where it lives | Used for |
|---|---|---|---|---|
| Task 1.2 research, revision 5 (`task-1.2-report-v5`, 10 examples) | @KAZDANTOK (SOU-9) | 8 Oct | [Accepted research and asset digests](https://linear.app/soup-wall/issue/SOU-9/task-12-research-custom-tool-call-classifier) | Output/label format and proposed model/evaluation plan |
| Evaluation v0.4 report and runner | @aisarasd (SOU-5 D3) | 8 Oct | [`eval/evidence/sou5_original/`](../../eval/evidence/sou5_original/EVALUATION_REPORT.md) | Historical run 1, defects D1 to D9 |
| Evaluation v0.4.1 / v0.4.2 (documentation updates, DX defect, 43/59) | @aisarasd | 8 Oct | Shared archive `Soup_Task1_3_Evaluation_v0.4.2_contract_aligned.zip` | Historical run 2, DX |
| Mixed-action add-on UX01 to UX04 | @urtisto (SOU-21) | 8 to 9 Oct | [`eval/fixtures/`](../../eval/README.md), PR #49 | Fixtures, before/after evidence |
| Classifier fixes and edge review | @sake_ai, @Nask0fe (SOU-19) | 9 to 10 Oct | [`eval/evidence/sou19_review/`](../../eval/evidence/sou19_review/README.md) | Historical run 3 |
| Contract SOU-10 v0.4 | @Nari_Ab | 10 Oct | [`contract/updated_contract2.md`](../../contract/updated_contract2.md) | Rules D01 to D10 |
| Jev adapter, local pilot | SOU-6, SOU-16 owners | 9 to 10 Oct | [`experiments/`](../../experiments/classification/README.md) | Model comparison (section 6) |

Nothing in the historical sources was relabeled. Fixture files are used exactly
as merged.

## 3. Exact revisions of the final run

| Item | Revision |
|---|---|
| Repository | `main` at `8e1d4d7d81da525f7592e2111d36eedba2da9706` |
| Classifier | `rule_baseline/rule_baseline.py`, Git blob `ab01f17b96b57d9decae24deec43a2dbc7a45b9d`, sha256 `811af2e841c57914256a6bdb680d8e1c7443bf292505e08c8ae197a3c1b6da1d` |
| Runner | `eval/eval_runner.py`, sha256 `fd2d620c7cb7be4ce9bd4bcb6d138d108b211594a0e190ad877fc62a430c004f` |
| Core fixtures v0.4 | sha256 `047d522c8fcaaa61aa479f12a9e34eb7c6bd47dcd4c7005909e6837afea91044` |
| Challenge fixtures v0.1 | sha256 `48a445b5d53dd2cc77a999616f7042eff1962eaf8291ee099e6e88b5fe621a69` (matches the original gold freeze) |
| Mixed add-on v0.1 | sha256 `9cab289f9fda0c6ac3b6cca0ad74e1e19adff0f7898d67807f4219b6bdf0701a` |
| Benign control v0.1 | sha256 `636d31cd5248502ab8a07716671c5885827e47941748e121be9efa04e483f195` |
| Environment | Linux, Python 3.13.16, standard library only, no network, no tool executed |
| Pass rule | action set **and** `unknown` both match; a technical error never passes |

## 4. Final current-baseline run

### 4.1 Overall

| Suite | Pass | Fail | Technical | Pending (not scored) |
|---|---|---|---|---|
| Core v0.4 | 21/21 | 0 | 0 | 2 (U07, E01) |
| Challenge v0.1 | 28/34 | 6 | 0 | 1 (CS03) |
| Mixed add-on v0.1 (UX01 to UX04) | 4/4 | 0 | 0 | 0 |
| Benign control v0.1 | 1/1 | 0 | 0 | 0 |
| **All** | **54/60** | **6** | **0** | **3** |

Unit checks on the same commit: baseline 59/59, runner 32/32.

### 4.2 Required slices

| Slice (all suites) | Pass |
|---|---|
| Previously unseen tools | 9/12 |
| Misleading metadata | 12/13 |
| Mixed actions | 16/17 |
| Shell-dependent (D05 scope) | 19/20 |

### 4.3 Per-label errors (known-label denominators)

Each label has 60 provisional scored, non-technical observations. Positive
and negative denominators are separate; pending rows enter neither.

| Label | Expected present | Expected absent | Missed | Spurious |
|---|---|---|---|---|
| read | 31 | 29 | 3 | 0 |
| write | 11 | 49 | 1 | 0 |
| delete (critical) | 13 | 47 | 1 (CU02, with unknown=true) | 0 |
| send_data (critical) | 11 | 49 | 0 | 0 |
| change_permissions (critical) | 9 | 51 | 0 | 0 |

### 4.4 Unknown and abstention

- Scored cases with gold `unknown=true`: 7. All 7 predicted `unknown=true`.
- Predicted `unknown=true` on 11 of 60 scored cases; 6 of them are full
  abstentions (`actions=[]`).
- Extra `unknown` on resolvable cases: CU02, CU03, CM01, CS06 (4/53).
- No case expected `unknown=true` and got `false`.
- Pending cases U07, E01, CS03 all return `actions=[]`, `unknown=true`.

### 4.5 Remaining mismatches

| Case | Expected | Predicted | Cause |
|---|---|---|---|
| CU01 | read, write; unknown=T | none; unknown=T | verb `sync` not in vocabulary (D5) |
| CU02 | delete; unknown=F | none; unknown=T | verb `expunge` not in vocabulary (D5) |
| CU03 | send_data; unknown=F | send_data; unknown=T | unrecognised verb keeps unknown (D4) |
| CM01 | write; unknown=F | write; unknown=T | unrecognised verb `overwrite` keeps unknown (D4) |
| CX06 | read, delete; unknown=F | delete; unknown=F | read inferred from name dropped (D7) |
| CS06 | read, send_data; unknown=F | send_data; unknown=T | `tar` not recognised (D5) |

The original evaluation marked CU01, CU03, CM01 and CX06 as disputed gold labels.

### 4.6 Latency

Rule baseline only, in-process, 63 inputs x 20 rounds after warmup: p50 0.058 ms,
p95 0.147 ms, max 3.2 ms. This is classifier time, not pipeline or policy time,
and one local run is not a latency gate. No model latency was measured. These
are the report owner's exploratory Linux observations; raw samples and the
percentile procedure were not supplied. Review independently reproduced the
classification outcomes, not these quantiles. Retain raw timing samples and a
pinned procedure before using latency for performance acceptance.

## 5. Historical runs (provisional, kept for traceability)

| Run | Date | Classifier | Core suites | With UX add-on | Source |
|---|---|---|---|---|---|
| 1 | 8 Oct | original baseline, sha256 `c0a307ad...de39` | 43/55 | not run | [sou5_original](../../eval/evidence/sou5_original/summary.md) |
| 2 | 8 Oct | same | 43/55 | **43/59** (UX 0/4) | evaluation v0.4.2 archive |
| 3 | 9 to 10 Oct | after owner fixes, blob `ab01f17b` | 49/55 | 54/60 | [SOU-19 review](../../eval/evidence/sou19_review/README.md), [SOU-21 post-fix](../../eval/evidence/sou21_postfix/summary.md) |
| Final | 10 Oct | same as run 3 | 49/55 | 54/60 | section 4 of this report |

The 43/59 result was reported against provisional gold labels and an earlier
classifier revision. It stays provisional evidence, not a target score.

### 5.1 Defect notes D1 to D9 and DX, rechecked on the final classifier

The minimal inputs from the evaluation report were rerun on blob `ab01f17b`.

| ID | Finding (8 Oct) | Status now | Owner |
|---|---|---|---|
| D1 | `;` inside quotes split the command (`echo 'a; rm -rf x'` gave delete) | **Fixed**: no delete | @sake_ai |
| D2 | `#` comment not recognised (`ls # ; rm -rf x` gave delete) | **Fixed**: read only | @sake_ai |
| D3 | `cat a > b` lost read | **Fixed**: read + write | @sake_ai |
| D4 | Unrecognised verb keeps unknown even when effect is proven (CU03, CM01) | **Open**, design decision | @sake_ai |
| D5 | Vocabulary gaps (`expunge`, `sync`, `tar`) (CU01, CU02, CS06) | **Open**; fix with reviewed data, not word-by-word tuning | @sake_ai, SOU-13 |
| D6 | `attachment_path` not read evidence | **Fixed**: read + send_data | @sake_ai |
| D7 | Read inferred from name dropped on name conflict (CX06) | **Open**, gold label disputed | @sake_ai, @aisarasd |
| D8 | `echo`/`printf` counted as read | **Changed**: now unknown; D07 no-op not yet emitted | @sake_ai |
| D9 | Null arguments return unknown, not a technical error | **Open** vs D06; runtime adapter rejects null before classification | @sake_ai, interface owners |
| DX | Evidence merged across steps and nested data (UX01 to UX04 spurious labels) | **Fixed**: UX 4/4 | @sake_ai |

## 6. Model-based candidates

| | Rule baseline | v5 research plan (SOU-9) | Jev adapter (SOU-6) | Local linear pilot (SOU-16) |
|---|---|---|---|---|
| What it is | Merged classifier | Proposal: ModernBERT-base with five sigmoid heads, vs DistilBERT and TF-IDF baselines, masked loss for unknown labels | Shadow adapter for the Jev typed-question API | CPU logistic regression, five heads + unknown head |
| Status | Evaluated (section 4) | Not trained | Mock only (4/55 is plumbing, not Jev) | Smoke test only |
| Measured quality | 54/60 | none | none | none |
| Uses description | No | Untrusted input | Data only | Excluded from features |
| Remaining prerequisites | D06/D07 fixes; generic classifier and integrated acceptance | needs reviewed dataset and resources | no approved API access or budget | no approved dataset (SOU-13) |

The v5 report also proposed pilot gates (for example at most 1% critical misses
per action with an exact binomial bound). These are proposals, not measured
results. SOU-13 pilot data will extend this report; it does not block it.

## 7. Classification vs policy vs execution

This report measures **classification only**: which actions a call performs.

- **Policy** (Allow/Ask/Deny) belongs to Team 2. D08 requires unresolved effects
  to receive Ask or a trusted Deny. The selected current MCP bridge instead
  refuses unsupported unknown/mixed mappings before policy. No policy was run
  here, so contract requirements are not observations of runtime protection.
- **Execution protection** (blocked calls never reach the executor, results
  withheld) belongs to Task 2/3 and SOU-15/SOU-17. Integrated runtime acceptance
  is still pending ([SOU-17 verification](sou17_verification.md)).
- A correct label does not prove a call was blocked, and a wrong label does not
  prove it executed. Read these results only as classifier quality.

## 8. Contract alignment (SOU-10 v0.4)

| Rule | Baseline today |
|---|---|
| D01 `actions` + Boolean `unknown`, partial actions kept | Yes |
| D02 call ID outside the semantic input | Yes |
| D03 GET is read; no implied write/read | Yes |
| D04 description is untrusted | Yes |
| D05 bounded shell parsing, else unknown | Yes |
| D06 technical failures on a separate channel | **Raw API gap** (D9, local `status="error"`); the reviewed bridge already has typed failures and the collector rejects null before classification. |
| D07 proven no-op is `[]` + `unknown=false` | **Not yet** (U07, CS03 return unknown); reviewed fixture and baseline follow-up required. |
| D08 unresolved effects | Ask/trusted Deny is required by contract; policy was not measured here. |
| D09 all relevant actions/resource constraints | Not evaluated; authoritative production composition remains SOU-15 work. |
| D10 distinct error layers and reviewed gold | Technical/classification outcomes stay separate; pending/disputed labels remain provisional and no execution verdict is inferred. |

## 9. Open items and owners

| Item | Owner |
|---|---|
| Review fixture updates for U07/CS03 under accepted D07 and E01 under accepted D06; preserve this historical run | @aisarasd (SOU-13), @Nari_Ab (SOU-10 contract review) |
| Second review of disputed labels CU01, CU03, CM01, CX06 | @aisarasd, @sake_ai |
| D06 failure channel, D4, D5, D9 in the baseline | @sake_ai |
| Approved pilot dataset and family-held-out split | SOU-13 |
| Future live Jev run | @KAZDANTOK, after access and budget approval; accepted SOU-6 was explicitly mock-only |
| Integrated runtime acceptance | @Nari_Ab (SOU-15), @konung3 (SOU-17) |

D1-D9/DX are historical baseline defect IDs, distinct from accepted contract
decisions D01-D10. Gold acceptance is still a separate review; approving the
contract does not retroactively confirm every fixture. The SOU-21 add-on is
already merged; follow-up annotations do not reopen that completed contribution.
This report is delivered to @sake_ai (SOU-5) and @sayowannafly (SOU-7); model
pilot data will extend the evidence after SOU-13 review.

## 10. Reproduce

From the repository root (use `python` on Windows):

```sh
PYTHONPATH=rule_baseline python3 -m unittest discover -s rule_baseline -p 'test_*.py'
python3 -m unittest discover -s eval -p 'test_*.py'
python3 eval/eval_runner.py \
  eval/fixtures/soup_task1_evaluation_cases_v0.4.json \
  eval/fixtures/soup_task1_challenge_cases_v0.1.json \
  eval/fixtures/soup_task1_mixed_actions_urtisto_v0.1.json \
  eval/fixtures/soup_task1_benign_comparison_urtisto_v0.1.json \
  --classifier-path rule_baseline --out-dir /tmp/task1-eval
```

Expected: 59 and 32 tests OK; evaluation prints 54/60 and exits 1 (recorded
mismatches, not a crash). The runner writes `summary.md`, `results.csv` and
`results.json` with expected/actual labels, unknown, errors and per-label counts.
