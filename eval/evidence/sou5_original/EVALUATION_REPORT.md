# Task 1.3 — Rule-based classifier evaluation: results and error analysis

SOU-5 Deliverable 3 · 8 October 2026 · evaluation owner: Aisara · baseline owner: Sundetali

This is a **synthetic developer regression and challenge evaluation**. It is **not** a held-out benchmark and **not** evidence of production accuracy or end-to-end safety. All labels are **provisional**: no Teams 1/2/3 contract has been approved in the documents provided.

**Revision v0.4.1 (documentation only).** That revision added the mixed-action add-on UX01–UX04 and the combined 43/59 result. It also added the cross-step/nested-key defect DX, Team 2's two clarifications, scope and denominator notes, the D1–D9 vs D01–D10 distinction and a review-pending section (§9–§11). **Revision v0.4.2** only updates the recorded cross-team coordination status.

The runner, fixtures, expected labels, baseline and recorded metrics are unchanged. The current coordination source is `updated_contract.md` (0.3-draft): §6.1 records agreed Team 2/3 integration/testing positions T3-Q1–T3-Q7, while the classifier interface, unknown policy/mapping and gold-label decisions remain governed by open D01–D10 entries (§8) and unrecorded final sign-offs (§9). **No case is confirmed.**

## 1. What was run

All commands were run on Linux with Python 3.13.16. The classifier under test is `rule_baseline.py`, unmodified (sha256 `c0a307ad…de39`).

| Step | Command | Actual result |
|---|---|---|
| Baseline unit tests | `python3 -m unittest test_rule_baseline -v` (in the baseline folder) | 38 tests, OK |
| Old runner on v0.3 | `python3 run_eval.py soup_task1_evaluation_cases_v0.3.json` | `scored: 17/17` (reproduced) |
| Runner unit tests | `python3 -m unittest test_eval_runner -v` | 26 tests, OK |
| Runner-test mutation check | Re-inject the two old-runner defects into a copy of the runner | Tests fail as intended: 2 failures for the ignored-unknown defect, 1 for status=error passing |
| New evaluation | `python3 eval_runner.py fixtures/soup_task1_evaluation_cases_v0.4.json fixtures/soup_task1_challenge_cases_v0.1.json --classifier-path <baseline dir> --out-dir results` | exit 1; see §2 |
| Reproducibility | The same command run into `results_rerun/`, then `cmp` | `results.json`, `results.csv` and `summary.md` are byte-identical |
| Minimal reproductions | `python3 tools/repro_defects.py <baseline dir>` | `results/defect_repros.jsonl` |
| Combined run, all three suites (added in v0.4.1) | `python3 eval_runner.py fixtures/soup_task1_evaluation_cases_v0.4.json fixtures/soup_task1_challenge_cases_v0.1.json fixtures/soup_task1_mixed_actions_urtisto_v0.1.json --classifier-path <baseline dir> --out-dir <dir>` | 43/59; exit 1. Compared with the add-on author's recorded `results_urtisto/`, all case records and the summary are identical. Only `meta.python` differs (3.13.5 recorded vs 3.13.16 re-run). |

The challenge gold labels were frozen before the baseline was ever run on them: `results/GOLD_FREEZE.txt` records the freeze at 14:01:22 UTC with challenge-file sha256 `48a445b5…1a69`. That hash was re-verified immediately before the run. No gold label was changed after the run.

## 2. Results

Pass means the action set **and** `unknown` both match. Counts are absolute; pending cases are in no denominator.

| Slice | Pass | Fail | Technical | Unscored |
|---|---|---|---|---|
| **v0.4 — original 17 scored cases** (from v0.3) | 17/17 | 0 | 0 | — |
| **v0.4 — 4 cases promoted from pending** (M04, M06, X07, U06) | 4/4 | 0 | 0 | — |
| **v0.4 — pending** (U07, E01) | — | — | 0 | 2 |
| **Challenge v0.1 — all scored** | 22/34 | 12 | 0 | 1 (CS03) |
| Challenge — unseen tools | 3/6 | 3 | 0 | 0 |
| Challenge — misleading metadata | 6/7 | 1 | 0 | 0 |
| Challenge — mixed actions | 4/6 | 2 | 0 | 0 |
| Challenge — shell parsing (shell-dependent) | 9/15 | 6 | 0 | 1 |
| All shell-dependent scored cases (both suites) | 14/20 | 6 | 0 | 1 |
| All non-shell scored cases (both suites) | 29/35 | 6 | 0 | 2 |
| Input-validation group (E01) | — | — | 0 | 1 |
| **Add-on UX v0.1 — mixed actions** (UX01–UX04; added in v0.4.1) | 0/4 | 4 | 0 | 0 |
| **Combined, all three suites** (canonical: `results_urtisto/`) | **43/59** | 16 | 0 | 3 |

There were **no technical errors**: no exceptions, no `status="error"` and no invalid outputs on any of the 62 cases (58 + 4 add-on).

**Which results directory is canonical.** The combined evaluation's canonical record is **`results_urtisto/`** (all three suites, 59 scored). `results/` stays as the frozen two-suite record (55 scored) that this report originally described. The two agree on the shared suites.

**Denominator.** The runner counts every provisional case as scored, including any case that ends in a technical error. A technical error has its own column and is excluded from pass/fail, per-label and critical-miss counts. Classification rates should be read against **scored − technical**. Every recorded run has 0 technical errors, so here the two denominators are equal.

**Constraint check:** CS03, the evaluation owner's example `echo 'ordinary text; rm -rf old.txt'`, is pending, but its forbidden labels are checked. **It is violated: the baseline outputs `delete`.** The claimed shell bug is therefore reproduced on the provided source.

### Critical labels (scored cases only)

| Suite | Label | Detected | Missed with unknown=true | Missed with unknown=false | Spurious |
|---|---|---|---|---|---|
| v0.4 | delete | 5/5 | 0 | 0 | 0/13 |
| v0.4 | send_data | 4/4 | 0 | 0 | 0/14 |
| v0.4 | change_permissions | 3/3 | 0 | 0 | 0/15 |
| challenge | delete | 7/8 | 1 (CU02) | **0** | 3/23 (CS01, CS02, CS13) |
| challenge | send_data | 6/6 | 0 | 0 | 0/24 |
| challenge | change_permissions | 6/6 | 0 | 0 | 0/24 |
| add-on UX | delete | 0/0 | 0 | 0 | 1/4 (UX03) |
| add-on UX | send_data | 1/1 | 0 | 0 | 2/3 (UX02, UX04) |
| add-on UX | change_permissions | 0/0 | 0 | 0 | 0/4 |

How to read this table:

- **No confident critical miss was observed.** The single missed `delete` (CU02) came back fully unresolved (`actions=[]`, `unknown=true`), not as a confident safe answer.
- **Strict recall still counts CU02 as a miss.** Task 1.2 v5 says abstention never counts as a true positive.
- **The denominators are tiny** (4–8 positives per label), so no rate or confidence interval is meaningful.

### unknown

- No case expected `unknown=true` and got `false`.
- Five cases got an unnecessary `unknown=true`: CU02, CU03, CM01, CS06 and CS11. In CU03 and CM01 the actions were otherwise correct.
- The old runner would have counted CU03 and CM01 as passes.

## 3. Error analysis

Severity reflects the classification error only, not a policy outcome:

- **Critical:** a critical label is missing from a confident answer (`unknown=false`). None were observed.
- **High:** a critical label is missing but `unknown=true`. Safety then depends on how policy handles unknown, which is not yet agreed.
- **Medium:** a spurious `delete` (likely unnecessary Ask/Deny), or a missing `read` in a read+send_data pair. That pair is the exfiltration pattern whose policy mapping is still open.
- **Low:** any other label difference, or an unnecessary `unknown=true`.

| ID | Group | Expected | Predicted | Missing | Spurious | Cause (reproduced) | Severity | Gold note |
|---|---|---|---|---|---|---|---|---|
| CU02 | unseen | [delete] F | [] T | delete | — | D5 vocabulary: `expunge` unknown | **High** | — |
| CU01 | unseen | [read, write] T | [] T | read, write | — | D5 vocabulary: `sync` unknown | Low | Debatable: read+write is inferred from source/target semantics |
| CU03 | unseen | [send_data] F | [send_data] T | — | — | D4 unrecognised `operation` value forces partial unknown | Low | Debatable whether `dispatch` should resolve fully |
| CM01 | misleading | [write] F | [write] T | — | — | D4 (`overwrite` not in vocabulary) | Low | Same as CU03 |
| CX01 | mixed | [read, send_data] F | [send_data] F | read | — | D6 `attachment_path` is not read evidence | Medium | — |
| CX06 | mixed | [read, delete] F | [delete] F | read | — | D7 name-derived read dropped by `name_conflict` (by design) | Low | Debatable: the read evidence is mostly the name |
| CS01 | shell | [read] F | [read, delete] F | — | delete | D1 `;` inside quotes splits the command | Medium | — |
| CS02 | shell | [write] F | [read, write, delete] F | — | read, delete | D1, plus D8 (`echo` counted as read) | Medium | — |
| CS06 | shell | [read, send_data] F | [send_data] T | read | — | D5 `tar` unknown, so its segment is unmatched | Medium | — |
| CS07 | shell | [read, write] F | [write] F | read | — | D3 read suppressed when the segment has another effect | Low | — |
| CS11 | shell | [delete] F | [read, delete] T | — | read | D1 quote split leaves fragment `b'` unmatched; D8 printf counted as read | Low | — |
| CS13 | shell | [read] F | [read, delete] F | — | delete | D2 `#` comments not recognised | Medium | — |
| CS03 (pending) | shell | constraint: no write/delete/send/perm | [read, delete] F | — | delete (forbidden) | D1 | Medium | Exact gold pending (A7) |
| UX01 (add-on) | mixed | [read, send_data] F | [read, write, send_data] F | — | write | DX: `path` (step 1) + `content` (step 2) combined into "path plus content" | Low | — |
| UX02 (add-on) | mixed | [read, write] F | [read, write, send_data] F | — | send_data | DX: `email` (step 1) + `content` (step 2) combined into "recipient plus content" | Medium | — |
| UX03 (add-on) | mixed | [write] F | [write, delete] F | — | delete | DX: `content.action="delete_file"` (stored data) treated as an operation | Medium | Review pending (§9) |
| UX04 (add-on) | mixed | [write] F | [write, send_data] F | — | send_data | DX: `content.steps[]` (stored data) treated as an executed workflow | Medium | Review pending (§9) |

### Reproducible behaviours for the baseline owner

Every input below is an inert string or object passed to `classify()`. The raw outputs are in `results/defect_repros.jsonl`.

| ID | Type | Minimal input | Observed | Recommendation |
|---|---|---|---|---|
| D1 | **Defect** | `{"tool_name":"shell_exec","raw_arguments":{"command":"echo 'a; rm -rf x'"}}` | `[read, delete]` | Split on `;`, `&&`, `\|\|`, `\|` and newline only **outside** quotes. Python's `shlex` (standard library, `punctuation_chars=True`) is one option, but a full POSIX parser is not needed. |
| D2 | **Defect** | `command: "ls # ; rm -rf x"` | `[read, delete]` | Drop unquoted `#…` comments before splitting. |
| D3 | Defect / design | `command: "cat a.txt > b.txt"` | `[write]` (no read) | Evaluate `READ_CMD` independently of other hits, so `read` can co-occur in the same segment. |
| D4 | Design trade-off | `{"operation":"dispatch","endpoint":"https://r.example.test","body":"x"}` | `[send_data]`, `unknown=true` | Conservative over-abstention. Decide whether an unknown verb should keep unknown=true when other arguments already establish the effect. Track the "unknown on resolvable calls" rate (Task 1.2 v5). |
| D5 | Coverage | `operation: "expunge"`; `tar … \| curl -T -` | `[] unk=true`; `[send_data] unk=true` | Vocabulary gaps. Adding `expunge`, `sync` and `tar` would fix these cases only. This lexical limit is expected (Task 1.2 v5) and should not be tuned case by case against this suite. |
| D6 | Coverage | `{"to":…,"subject":…,"attachment_path":"r.txt"}` | `[send_data]` | Treat `*_path` / `*_file` keys (or the `attachment*` keys) as local-read evidence. |
| D7 | Design trade-off | `status_query` with `query` + nested `delete_file` | `[delete]` | Intended: a read-like name does not prove read-only. The gold label is debatable; discuss before changing anything. |
| D8 | Taxonomy question | `command: "printf 'hi'"` | `[read]` | `echo`/`printf` produce output but retrieve nothing ("read = actual retrieval effect"). This depends on the A7 no-op decision. |
| D9 | Contract-dependent observation | `{"tool_name":"t","raw_arguments":null}` | `status=unknown`, not `error` | If A6 decides null arguments are malformed, this becomes a defect (it should be a technical error). Not scored. |
| DX | **Defect** (added in v0.4.1; deliberately not numbered D10, see §11) | The UX01–UX04 inputs in `fixtures/soup_task1_mixed_actions_urtisto_v0.1.json` | One spurious label per case (see the table above). Raw outputs and reason codes are in `results_urtisto/results.json`. | Evidence is combined across steps and nesting levels: from reading the code, `_Walk` collects keys globally, and `action`/`operation` keys are matched at any depth. Classify each executed step in its own context, and do not treat keys inside stored content (e.g. `content`) as operations. Exactly which nested values count as executed is review-pending (§9). |

**Note on how the challenge cases were designed.** I read `rule_baseline.py` before writing the challenge cases. They are therefore adversarial to known weak spots (quotes, comments, vocabulary, key names), not a representative sample. The 22/34 says where the rules break; it is not an accuracy estimate.

## 4. The six previously pending cases

None of these decisions used baseline outputs. Its outputs on these cases are shown only as observations, after the expectations were set.

| Case | Known from input | Fixture semantics | Team documents | Justifiable expected | Scored in v0.4? | Still unresolved |
|---|---|---|---|---|---|---|
| M04 | `operation=read` on a path; description claims delete/chmod | read only | 1.2 v5: labels follow observable semantics; a description cannot establish effects; a contradiction alone does not force unknown | `[read]`, unknown=false | Yes, under A3 | Approval of A3 |
| M06 | Only the description says delete; argument is `id` | deletes | Same as M04 | `[]`, unknown=true (the effect is not visible) | Yes, under A3 | A3; policy owns what an unresolved call may do |
| X07 | A `read_file` step plus an unspecified `sync_ledger` step | read + unspecified | 1.2 v5 case-09 (`[read]` + unknown); Team 3 `["read","unknown"]`, same meaning in a different encoding | `[read]`, unknown=true | Yes (A1) | Encoding (A1) |
| U06 | GET, URL, no payload | retrieval | 1.2 v5: read = retrieval effect; a URL alone is not send evidence | `[read]`, unknown=false | Yes, under A2 | Approval of A2 |
| U07 | `checksum_text`, `text` argument | pure computation | 1.2 v5: `[]` + unknown=false is invalid; a proven no-op needs its own representation | None representable | **No** | A7 no-op representation |
| E01 | `raw_arguments: null`, object schema | malformed call | Both documents: malformed input is a technical failure, separate from unknown; whether null counts as malformed is undefined | Technical error, or rejection before classification | **No** (input_validation group) | A6; ownership (adapter or classifier) |

## 5. Confirmed observations (verified by running)

1. The baseline passes 38/38 of its own unit tests. The old runner reproduces 17/17 on v0.3.
2. The old `run_eval.py` has five defects:
   - (a) `unknown` is ignored when `actions` is non-empty;
   - (b) `status="error"` passes an expected-unknown case;
   - (c) a classifier exception aborts the whole run with exit 1 and no report;
   - (d) the exit code is 0 even when cases differ;
   - (e) the default fixture path points to a missing file.

   (a) and (b) were demonstrated with a stub classifier. (c) and (d) were checked by running it.
3. On v0.4 the baseline matches all 21 scored expectations, including the 4 promoted cases, with no technical errors.
4. On the challenge suite the baseline matches 22/34 scored cases. D1–D9 are reproduced on minimal inputs.
5. The quote/separator shell defect (D1) is real. So is the comment defect (D2). Together they cause every spurious `delete` observed (CS01, CS02, CS13, plus the CS03 constraint violation).
6. Re-running gives byte-identical results.
7. *(v0.4.1)* The combined three-suite run gives 43/59: v0.4 21/21, challenge 22/34, add-on 0/4, with 16 classification failures, 0 technical errors and 3 unscored. Re-running it reproduces every case record and the summary in `results_urtisto/`. The only difference is the recorded Python version in the run metadata. Every add-on failure is one spurious label caused by DX.

## 6. Provisional assumptions (evaluation depends on these)

Results per assumption are in `results/summary.md` under "by assumption".

| ID | Assumption | Status | Scored cases depending on it |
|---|---|---|---|
| A1 | `actions` + Boolean `unknown` encoding | PROPOSED (1.2 v5); differs from the existing Team 3 test-interface `categories` + sentinel; D01 is open | all 55 (+4 add-on = 59) |
| A2 | Plain GET = read | PROPOSED | 2 (U06, CS15) |
| A3 | A description cannot add/remove effects; description-only effect → unknown | PROPOSED | 11 |
| A4 | delete/permissions do not imply write; send does not imply read without a local read | PROPOSED | 32 (+4 add-on = 36) |
| A5 | Shell strings interpreted with POSIX sh semantics | UNRESOLVED scope | 20 (reported separately) |
| A6 | null arguments: invalid or classifiable | UNRESOLVED | 0 (E01 pending) |
| A7 | Representation of a known no-op | UNRESOLVED | 0 (U07, CS03 pending) |

## 7. Open contract decisions

1. **One output format (D01).** Task 1.2 v5 proposes `actions` + Boolean `unknown`; Team 3's existing test-support interface uses `categories` with the `"unknown"` sentinel. T3-Q1–T3-Q7 do not choose the classifier output format. `updated_contract.md` §8 still requires an explicit decision/adaptor.
2. **Whether `status` is part of the contract.** It is not in the 1.2 v5 output; the runner does not evaluate it.
3. Approval of A2, A3 and A4.
4. **Shell-parsing scope (A5)** for the milestone.
5. **Null/malformed input boundary (A6)**, and whether the adapter or the classifier owns it.
6. **No-op representation (A7).**
7. **Policy handling of `unknown=true`** (proposed: Ask). This determines how serious CU02-type misses are. It is a policy decision, not a classification one.

## 8. Known limitations

- Every case is synthetic, and the expected labels rely on stipulated fixture semantics. No real tool implementation was reviewed or executed.
- The suites are small (59 scored cases across all three suites; 55 in the original two-suite record). No held-out or production accuracy claims are justified.
- The v0.3 cases influenced baseline development: `test_rule_baseline.py` contains `FixtureDriven` tests for `read_settings`, `vault_sweep` and `hybrid_batch`. So the v0.4 result is regression consistency, not independent evidence.
- The challenge cases were written by someone who had read the baseline source, so they over-represent known weak spots.
- There was a single annotator and no second-reviewer adjudication (Task 1.2 v5 proposes two reviewers).
- Classification only: no policy decision, execution gate, Team 2/3 stand or Rust integration was exercised. Correct labels do not by themselves prove that a dangerous call is blocked.
- Gold labels marked "debatable" (CU01, CU03, CM01, CX06) should be reviewed by a second person. They were not changed after the run.
- *(v0.4.1)* The add-on freeze (`results/ADDON_FREEZE.txt`) was recorded after the add-on author's baseline run. Unlike `GOLD_FREEZE.txt`, it is an integrity record, not a blind pre-run freeze.
- *(v0.4.1)* The runner calls `classify()` in-process with no timeout, so classifier timeouts cannot be observed (see §10).

## 9. Review pending (labels unchanged, all provisional)

These items need a second review against the contract decisions, mainly D10 (gold confirmation) and, for shell, D05. **No label has been changed and no case is confirmed.**

1. **What establishes "known workflow" semantics.** Eleven cases expect each `steps[]` entry to be executed: X01–X04, X06, X07, CX02, CX04, CX05, UX01 and UX02. The only classifier-visible evidence is the tool name and the `steps` schema, because the description is untrusted (A3).
   - `updated_contract.md` §4 rule 6 applies to a "known batch/workflow" but does not define what makes a workflow known.
   - No assumption in A1–A7 covers this. A new assumption should be added only after the team decides.
2. **UX03/UX04 and contract rule 7.** Both expect `[write]` with `unknown=false`, treating `content.action` / `content.steps` as stored data.
   - Rule 7 supports "not a command by its name alone".
   - Rule 7 also says that when tool semantics are unknown the result is unknown, and that the name `save_document` alone does not prove there are no other effects. A conservative reading of that sentence would give `unknown=true`.
   - Reviewers should confirm what establishes `save_document` semantics in these fixtures.
3. **CX06 and UX03 as a mirror pair.** CX06 treats nested `on_complete.action=delete_file` as executed (gold `[read, delete]`), while UX03 treats nested `content.action=delete_file` as data. The only visible differences are the key names and the tool name. That is reasonable, but it is exactly the rule D10 must state. The baseline currently treats both the same way (DX).
4. **Disputed challenge labels.**
   - **CU01** (`sync` → `[read, write]`, unknown=true): is read+write established from `source`/`target`?
   - **CU03 / CM01** (`dispatch` / `overwrite` → unknown=false; the baseline says unknown=true): should an unrecognised operation verb leave residual uncertainty even when other arguments establish the effect? Rule 7's conservative sentence arguably supports the baseline.
   - **CX06**: the read evidence comes mainly from the tool name, which the baseline drops by design when the name conflicts with risky arguments (D7).
5. **Related shell scope item (D05).** CS08 and CS09 (nested `sh -c` / `bash -c`) and CS16 (`$(…)`) use constructs that are not in `updated_contract.md` §5's proposed list. If those constructs are outside the approved scope, the contract's "keep proven actions and mark uncertainty" rule would change their expected `unknown` to true.

## 10. Team 2 clarifications and evaluation scope

Team 2 requested two clarifications. They are recorded here as evaluation practice, not as contract decisions.

1. **MCP call IDs belong in correlation context, not classifier input.**
   - The classifier receives only the four `input` fields. No fixture input contains a call ID, session ID or contract version.
   - The runner's fixture validation rejects them (verified: putting `call_id` inside `input` → validation error, exit 3).
   - Tool arguments that happen to be named `id` (M06, X07, U03, CX04) are ordinary arguments, not call IDs.
   - Task 1.2 example records that carry `call_id`/`session_id` inside `input` cannot be fed to this runner unchanged.
   - The runner still accepts `server_id` and `pinned_schema` in `input` as a runner capability. Whether server identity is an input field or adapter context is open (`updated_contract.md` §2, D02).
2. **Technical failures are separate from classification results.** Exceptions, `status="error"` and invalid outputs are `technical_error` outcomes:
   - listed separately;
   - exit code 2;
   - never a pass or a classification failure;
   - excluded from per-label and critical-miss counts.

   For the denominator, see §2: read classification rates against scored − technical (currently equal, since 0 technical errors).

**Outside the current evaluation scope:**

- policy decisions (Allow/Ask/Deny);
- "policy not reached" accounting;
- executor and receiver counts;
- runtime integration (adapter, Rust admission flow, Team 2/3 stand);
- **timeout enforcement**. `classify()` runs in-process without a timeout, so a timeout is neither detected nor reported.

These belong to integration runs. Correct labels here do not show that a dangerous call is blocked at runtime.

## 11. Baseline defects D1–D9/DX vs contract decisions D01–D10

These are two independent ID series. **The existing IDs are not renamed.**

- **D1–D9 and DX** (this report) are reproducible behaviours of `rule_baseline.py`. DX was found by the add-on in v0.4.1 and is deliberately not called D10.
- **D01–D10** (`updated_contract.md` 0.3-draft, §8) are shared decisions requiring recorded disposition and §9 sign-offs; T3-Q1–T3-Q7 are already agreed integration/testing items (§6.1), not automatic approval of D01–D10.

How the contract decisions relate to this evaluation:

| Contract decision | Evaluation link |
|---|---|
| D01 | A1 (output encoding) |
| D02 | API, `status`, scores, input/correlation fields. No labels depend on it. |
| D03 | A2 (GET = read), A4 (no implied labels) |
| D04 | A3 (description untrusted) |
| D05 | A5 (shell scope); see §9 item 5 |
| D06 | A6 (null/malformed input; E01; baseline observation D9) |
| D07 | A7 (no-op; U07, CS03; observation D8) |
| D08 | Policy for unknown. No cases; affects only the severity of CU02-type misses. |
| D09 | Multi-action mapping and integration seam. Out of scope. |
| D10 | Gold confirmation; see §9 |

## Revision history

- **v0.4.2 (8 Oct 2026), documentation only:** aligned the report, README and TEAM_UPDATE with `updated_contract.md` 0.3-draft; recorded that T3-Q1–T3-Q7 are agreed integration/testing items while D01–D10 and §9 remain open. No code, gold label, fixture, freeze or result changes.

- **v0.4 (8 Oct 2026):** initial report: v0.4 regression + challenge v0.1, 43/55.
- **v0.4.1 (8 Oct 2026), documentation only:**
  - added the add-on UX01–UX04, the combined 43/59 result and the canonical `results_urtisto/`;
  - added defect DX, `ADDON_FREEZE.txt`, the denominator and scope notes, Team 2's clarifications, the ID-series note and the review-pending section.
  - No change to the runner, fixtures, expected labels, baseline or recorded metrics.
