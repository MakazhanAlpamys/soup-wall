# Task 1 classification evaluation (SOU-5)

This directory publishes the shared **classification-only** Python evaluation runner and the frozen regression/challenge fixtures prepared by @aisarasd. This PR does **not** add or modify the classifier, policy engine, runtime admission, or mixed-action fixtures owned by SOU-21.

## Scope and provenance

- `eval_runner.py`: stdlib-only runner; compares the complete set of five action labels and separate Boolean `unknown`, without executing fixture tool calls.
- `test_eval_runner.py`: 26 local runner unit tests (stub classifiers, no project baseline required).
- `fixtures/soup_task1_evaluation_cases_v0.4.json`: Task 1 regression suite (23 entries, some unscored/pending).
- `fixtures/soup_task1_challenge_cases_v0.1.json`: independent *developer challenge* suite (35 entries, some unscored/pending). **It is not a held-out training benchmark.**
- `tools/make_challenge_v01.py`: reproduction script for frozen challenge fixture.
- `tools/make_v04.py`: historical transformation from v0.3 to v0.4 (requires the separately archived v0.3 input; included to preserve the original gold freeze).
- `evidence/sou5_original/`: **historical pre-fix baseline evidence only** (runner report, freeze record, machine-readable results). Not a report on the latest baseline.

The frozen files above have not been relabeled to match current classifier output. Expected labels depend on the pending shared contract and remain provisional unless separately confirmed. Shell-dependent cases and technical errors are reported separately. Policy `Allow/Ask/Deny`, end-to-end effects, and timeout are outside this runner's scope.

**Do not edit test expectations to make a classifier pass.** Review label disagreements separately, according to the shared contract.

## Run locally

From `eval/` with Python 3.10+:

```sh
python -m unittest test_eval_runner -v
python eval_runner.py fixtures/soup_task1_evaluation_cases_v0.4.json \
  fixtures/soup_task1_challenge_cases_v0.1.json \
  --classifier-path <directory-containing-rule_baseline.py> --out-dir /tmp/sou5-eval-results
```

`<directory-containing-rule_baseline.py>` must contain the **owner-maintained classifier**. The classifier's source and the callable `classify(input)` are prerequisites; it is not duplicated in this PR. On Windows, replace `/tmp/sou5-eval-results` with a normal local path. The evaluation's exit codes: 0 = all scored checks pass, 1 = classification mismatches, 2 = technical errors, 3 = invalid fixtures/classifier.

To regenerate the challenge cases and compare the frozen bytes:

```sh
python tools/make_challenge_v01.py /tmp/challenge-regenerated.json
cmp /tmp/challenge-regenerated.json fixtures/soup_task1_challenge_cases_v0.1.json
grep -E '^[[:xdigit:]]{64}[[:space:]]+' evidence/sou5_original/GOLD_FREEZE.txt | sha256sum -c -
```

## Historical results are not current results

For the unmodified **original** `rule_baseline.py` (as captured 8 Oct 2026): regression 21/21, challenge 22/34 = **43/55** scored passes, 12 mismatches, zero technical errors. These are synthetic, assumption-dependent results. The original combined mixed-action add-on run was 43/59, but SOU-21 owns the UX01–UX05 fixtures, so those are **not** republished here.

On 9 Oct the classifier owner separately reported **49/55** on the two core suites and **4/4** on the SOU-21 mixed-action set after fixes. This PR does not claim to have independently reproduced those later results. Obtain a pinned classifier commit and rerun before publishing up-to-date metrics.

## Related work

- SOU-5: https://linear.app/soup-wall/issue/SOU-5/task-1-automatic-tool-classification
- SOU-21 add-on / UX01–UX05: https://github.com/SoupTeam/soup-wall/pull/49
- Contract delivery: SOU-10 (owner @Nari_Ab). This PR does **not** approve the contract.

## Important limitation

These are synthetic developer regression/challenge cases, not proof of production model accuracy or security. Gold labels are provisional until the agreed contract and review process confirm them. The historical results provide traceability for discovered defects; they are not target scores.

## Reviewed runner compatibility

The runner accepts an explicit no-op result (`actions=[]`, `unknown=false`) and
compares it independently from unresolved effects (`unknown=true`). This does
not establish that any particular tool is a no-op or approve a fixture label.
The frozen historical fixtures and their pending cases are preserved unchanged;
label promotion requires separate review. Invalid outputs remain technical
errors, including a non-string local `status` field. The local `status` convention
is retained for historical diagnostics; this runner is not the runtime failure
channel or an approval of the complete SOU-10 interface.

CI runs the runner unit suite explicitly. Evaluation with the separately owned
classifier remains a reproducible diagnostic run; existing classification
mismatches are not hidden or relabeled to obtain a green score.
