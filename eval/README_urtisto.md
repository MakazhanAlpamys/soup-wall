# SOU-21 — mixed-action fixtures and automation

**Owner:** @urtisto. **Reviewer:** @sake_ai. **Report handoff:** @iazizza.

This is a focused **add-on PR**, not a new classifier or evaluation runner. Its prerequisites are the team's existing `rule_baseline.py` and @aisarasd's `eval_runner.py`. Neither is copied into this change; until their shared paths land, the PR is **not standalone-runnable**. The shared classifier interface/contract is pending sign-off.

## Coverage

- `fixtures/soup_task1_mixed_actions_urtisto_v0.1.json`: UX01–UX04, original frozen, Aisara-reviewed scenarios **unchanged**. UX01 read+send (no write); UX02 read+write (no send); UX03/UX04 `save_document` with operation-like strings stored as inert JSON content.
- `fixtures/soup_task1_benign_comparison_urtisto_v0.1.json`: **UX05**, a new read-only workflow comparator to UX01. Its gold label (`read`, `unknown=false`) requires review; it does **not** alter original challenge or UX freeze hashes.
- `evidence/sou21_baseline/results.json`: machine-readable expected/actual labels, unknown flag, per-case outcomes and mismatch details. The result is **4 classification failures + 1 benign pass**, **0 technical errors** on the recorded baseline. Do not treat the nonzero exit as a CI infrastructure error.

## Single reproducible evaluation command

From the eventual shared `eval/` directory, **after the upstream classifier and runner are published**:

```sh
python3 eval_runner.py \
  fixtures/soup_task1_mixed_actions_urtisto_v0.1.json \
  fixtures/soup_task1_benign_comparison_urtisto_v0.1.json \
  --classifier-path <directory-containing-rule_baseline.py> \
  --out-dir /tmp/sou21-reproduction
```

Exit status **1** is expected on the recorded baseline because all four UX regressions fail; status **0** requires all the scored cases to pass. The fixture inputs are synthetic and **never executed** by this runner.

## Provenance, trust and scope

- Recorded Python baseline SHA256: `c0a307adbde2d512275d88f36c6289b498f81fc0d40db8b70e797cbf8955de39` (original `rule_baseline.py`, no changes).
- Runner source: @aisarasd's `Soup_Task1_3_Evaluation_v0.4.2_contract_aligned.zip`; frozen scripts/labels from the team's evaluation. Do not merge a second implementation of this runner.
- Original `UX01–UX04` expected labels reviewed by @aisarasd on October 8; provisional because full Teams 1/2/3 contract is not finalized. UX05 is a **new proposed control**, not yet team-confirmed.
- Existing shared v0.4.2 historical score remains **43/59** with 3 unscored; this separate 5-case control check **must not be added to that historical denominator**. Re-evaluate when the runner/baseline is integrated.
- Cases guard against false extra labels, but do not constitute runtime enforcement tests; `read` must not suppress real `write`, `delete`, `send_data`, `change_permissions` or unknown effects. The wider @aisarasd regression suite covers `read+delete` and `read+change_permissions`; they are not copied into this PR.

## Handoff / blockers

- @sake_ai: reproduce four spurious-label bugs using this evidence. Core logic fixes belong to SOU-5; re-run this command against the fixed classifier revision, and preserve previous failure evidence.
- @iazizza: incorporate the original UX01–UX04 results into the SOU-20 report, cite this fixture and exact baseline hash. Keep historical and post-fix runs separate.
- **Blocker:** common `eval_runner.py` and `rule_baseline.py` are not in GitHub `main`/`task1` as of this PR preparation. This PR is additive and must identify the parent classifier/evaluation PR as prerequisite once posted. Repository path `eval/` should be aligned with the upstream PR before merge.
