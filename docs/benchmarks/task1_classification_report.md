# Task 1: Tool-call classification, final evaluation report (SOU-20)

Date: 10 October 2026. Parent task: SOU-5 (Task 1, automatic tool classification).
Contract: [SOU-10 v0.4](../../contract/updated_contract2.md), decisions D01 to D10 accepted.

This report brings together the Task 1 prototype, its evaluation and the
comparison with model-based candidates. All numbers in section 3 were rerun on
`main` at commit `8e1d4d7` for this report. They are synthetic developer
regression results, not held-out accuracy and not proof of execution safety.

## 1. Summary

- **Prototype:** a deterministic rule-based classifier
  ([`rule_baseline/`](../../rule_baseline/README.md), PR #53). It reads the tool
  name, schema and actual arguments and returns `actions` (read, write, delete,
  send_data, change_permissions) plus a separate Boolean `unknown`. It never
  executes tools and never returns Allow/Ask/Deny.
- **Result:** 54/60 scored cases pass on all four fixture suites, with 0
  technical errors and 3 pending cases. Core suites alone: 49/55.
- **Critical labels:** no confident miss. The only missed critical label
  (`delete` on CU02) comes back with `unknown=true`, so under D08 it reaches
  policy as Ask, not as a silent Allow.
- **Untrusted descriptions:** misleading metadata cases pass 12/13. The
  description cannot add, remove or hide an action.
- **Model-based candidates:** a Jev shadow adapter (SOU-6) and a local learned
  pilot (SOU-16) are built and tested, but neither has real quality numbers yet.
  Jev has no approved API access or budget; the local pilot has no approved
  dataset (SOU-13).
- **Recommendation:** use the rule-based baseline as the milestone classifier.
  Keep model candidates in shadow mode until real data and access exist.

## 2. What was evaluated

| Item | Value |
|---|---|
| Classifier | `rule_baseline/rule_baseline.py`, Git blob `ab01f17b`, sha256 `811af2e8...b6da1d` |
| Runner | `eval/eval_runner.py`, sha256 `fd2d620c...a004f` |
| Environment | Linux, Python 3.13.16, standard library only, no network |
| Pass rule | action set **and** `unknown` both match; technical errors never pass |

| Fixture suite | Purpose | Cases (scored / pending) |
|---|---|---|
| `soup_task1_evaluation_cases_v0.4.json` | Core regression (from v0.3) | 21 / 2 |
| `soup_task1_challenge_cases_v0.1.json` | Edge cases, gold frozen by hash before first run | 34 / 1 |
| `soup_task1_mixed_actions_urtisto_v0.1.json` | Mixed actions and nested data (SOU-21) | 4 / 0 |
| `soup_task1_benign_comparison_urtisto_v0.1.json` | Benign control (SOU-21) | 1 / 0 |

Only the `input` object reaches the classifier. Tool calls are inert data and
were never executed.

## 3. Results

### 3.1 Overall

| Suite | Pass | Fail | Technical | Pending |
|---|---|---|---|---|
| Core v0.4 | 21/21 | 0 | 0 | 2 (U07, E01) |
| Challenge v0.1 | 28/34 | 6 | 0 | 1 (CS03) |
| Mixed actions v0.1 | 4/4 | 0 | 0 | 0 |
| Benign control v0.1 | 1/1 | 0 | 0 | 0 |
| **All** | **54/60** | **6** | **0** | **3** |

### 3.2 Required slices

| Slice (both core and challenge) | Pass |
|---|---|
| Previously unseen tools | 9/12 |
| Misleading metadata | 12/13 |
| Mixed actions (incl. SOU-21 add-on) | 16/17 |
| Shell-dependent cases (D05 scope) | 19/20 |

### 3.3 Per-label errors (scored cases)

| Label | Expected present | Missed | Spurious |
|---|---|---|---|
| read | 31 | 3 | 0 |
| write | 11 | 1 | 0 |
| delete (critical) | 13 | 1 (CU02, with unknown=true) | 0 |
| send_data (critical) | 11 | 0 | 0 |
| change_permissions (critical) | 9 | 0 | 0 |

No spurious labels remain. No case expected `unknown=true` and got `false`.

### 3.4 Remaining mismatches

| Case | Expected | Predicted | Cause |
|---|---|---|---|
| CU01 | read, write; unknown=T | none; unknown=T | `sync` verb not in vocabulary |
| CU02 | delete; unknown=F | none; unknown=T | `expunge` verb not in vocabulary |
| CU03 | send_data; unknown=F | send_data; unknown=T | unrecognised verb `dispatch` keeps unknown |
| CM01 | write; unknown=F | write; unknown=T | unrecognised verb `overwrite` keeps unknown |
| CX06 | read, delete; unknown=F | delete; unknown=F | read inferred from name is dropped on name conflict |
| CS06 | read, send_data; unknown=F | send_data; unknown=T | `tar` not recognised as a read |

Five of six fail in the safe direction (extra `unknown`, which policy turns into
Ask). CX06 is the one confident partial answer: `delete` is kept, `read` is lost.
The original report marked CU01, CU03, CM01 and CX06 as disputed gold labels.
Labels were **not** changed to make the classifier pass.

### 3.5 Progress over time

| Date | Classifier state | Core suites | All suites |
|---|---|---|---|
| 8 Oct | Original baseline (SOU-5 evidence) | 43/55 | 43/59 |
| 9 Oct | After owner fixes (quotes, `#` comments, redirects, nested data) | 49/55 | 54/60 |
| 10 Oct | Rerun for this report | 49/55 | 54/60 |

The fixes removed every spurious `delete` (for example `echo 'a; rm -rf x'`
and `ls # ; rm -rf x`) and all four SOU-21 mixed-action false labels.

### 3.6 Latency

Rule baseline, in-process, 63 inputs x 20 rounds after warmup: p50 0.058 ms,
p95 0.147 ms, max 3.2 ms. This is classification only, not the full pipeline,
and one local run is not a latency gate.

## 4. Rule-based vs model-based comparison

| | Rule baseline | Jev adapter (SOU-6) | Local linear pilot (SOU-16) |
|---|---|---|---|
| Status | Merged, evaluated | Shadow adapter, mock only | Pipeline ready, smoke test only |
| Real quality numbers | 54/60 | None (4/55 is mock plumbing, not Jev) | None |
| Uses description | No, untrusted | Data only, under fixed instructions | Excluded from features |
| Cost / external calls | 0 | 0 so far; needs API key and budget | 0, CPU only |
| Blocker | None for the milestone | No approved access or budget | No approved dataset (SOU-13) |

Details: [Jev experiment](../../experiments/classification/README.md),
[local pilot](../../experiments/local_classifier/README.md).

**Conclusion:** only the rule baseline has measured results. Its weak point is
vocabulary on unfamiliar verbs (CU01, CU02, CU03, CM01), which is exactly where a
learned model could help. That needs a reviewed, family-split dataset first.
Adding words one by one to pass this suite would overfit it.

## 5. Contract alignment (SOU-10 v0.4)

| Rule | Baseline today |
|---|---|
| D01 `actions` + Boolean `unknown`, partial actions kept | Yes |
| D02 call ID outside the semantic input | Yes, classifier never sees it |
| D03 GET is read; no implied write/read | Yes (U06 passes) |
| D04 description is untrusted | Yes (misleading slice 12/13) |
| D05 bounded shell parsing, else unknown | Yes (shell slice 19/20) |
| D06 technical failures on a separate channel | **Not yet.** Baseline still uses local `status="error"`, and null arguments (E01) return `unknown` instead of a failure. The runtime adapter rejects null before classification, so this is not an execution risk. |
| D07 proven no-op is `[]` + `unknown=false` | **Not yet.** U07 and CS03 return `unknown=true`. This is conservative (Ask), but will fail once fixtures are updated. |

## 6. Limitations

- 60 synthetic scored cases, written by the team. Not a held-out benchmark.
- Gold labels are provisional; the D07/D04 fixture updates are deferred to SOU-13/SOU-21.
- This runner checks classification only. Policy, execution blocking and result
  delivery are Task 2/3 scope. Integrated runtime acceptance is still pending
  SOU-15 ([SOU-17 verification](sou17_verification.md)).
- A rule list cannot reveal hidden or dishonest tool behaviour. Execution
  enforcement and reviewed tool metadata remain necessary.

## 7. Follow-ups

1. Update U07/CS03 to the D07 no-op and decide E01 (SOU-13/SOU-21 fixture owners).
2. Second review of disputed gold labels CU01, CU03, CM01, CX06.
3. Baseline: move invalid input to the D06 failure channel; decide whether
   unrecognised verbs should keep `unknown` when other arguments already prove
   the effect (CU03, CM01).
4. Run a real model comparison after SOU-13 data approval, and Jev only after
   access and budget are approved.

## 8. Reproduce

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

Expected: 59 baseline tests OK, 32 runner tests OK, evaluation prints 54/60 and
exits 1 (classification mismatches, not a crash). Recorded evidence:
[SOU-19 run](../../eval/evidence/sou19_review/README.md),
[SOU-21 before/after](../../eval/evidence/sou21_postfix/summary.md),
[original SOU-5 report](../../eval/evidence/sou5_original/EVALUATION_REPORT.md).
