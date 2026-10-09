# SOU-21 mixed-action fixtures and automation

Owner: @urtisto. Classifier owner: @sake_ai. Report handoff: @iazizza.

This add-on uses the shared [evaluation runner](README.md) from merged
[#52](https://github.com/SoupTeam/soup-wall/pull/52) and the owner-maintained
[baseline](../rule_baseline/README.md) from merged
[#53](https://github.com/SoupTeam/soup-wall/pull/53). It introduces no competing
classifier, policy engine or execution path.

## Coverage and label review

The original UX01-UX04 fixture bytes and discussed expected labels are preserved:
read+send without write; read+write without send; JSON action and workflow-like
content stored as inert data. UX05 is a synthetic read-only workflow comparator.
Its expected read-only result is consistent with the explicit single read step,
and was inspected during maintainer review. All five labels remain provisional
synthetic assumptions, not claims about an arbitrary MCP tool's real behavior
or full cross-team contract acceptance. Fixture commands and network placeholders
are data and are never executed by this runner.

## Reproduce from the repository root

```sh
python3 eval/eval_runner.py \
  eval/fixtures/soup_task1_mixed_actions_urtisto_v0.1.json \
  eval/fixtures/soup_task1_benign_comparison_urtisto_v0.1.json \
  --classifier-path rule_baseline --out-dir /tmp/sou21-reproduction
```

Use `python` and a local output directory on Windows. The merged runner and
baseline produce 5/5 matches, zero classification or technical errors and exit 0
on these provisional cases. CI runs the same command and retains per-case
JSON/CSV/Markdown evidence. A new mismatch exits 1; a scored technical failure
exits 2. This is classification evaluation, not native/MCP enforcement acceptance.
Read must not erase other established effects or unknown; the wider frozen core
suite supplies additional multi-action/uncertainty cases and remains a separate
CI regression gate.

## Historical and post-fix evidence

- `evidence/sou21_baseline/` is the author's original reproduction: UX01-UX04 each
  had one extra action label; UX05 passed. Baseline SHA256:
  `c0a307adbde2d512275d88f36c6289b498f81fc0d40db8b70e797cbf8955de39`;
  runner SHA256: `0813b65acbb2322255a8851f49b462515244286a16d8e5c9a8306eade659ce43`.
  It is preserved unchanged; its nonzero exit represents classification failures.
- `evidence/sou21_postfix/` is the independent maintainer rerun with runner source
  from #52 (reviewed head `11b557b5aeb241c7fe77b322fe1297ba9c31cbc6`) and classifier
  source from #53 (reviewed head `000136c51884e0c204ac51b77c29c5c302f7256a`). Their
  merged commits are `ab62dc8d299d2df1753631cfb743baf4247022c2` and
  `76ab471550e161095bf2d6317617ac98c90a2a6a`; source hashes are in the report.
  Five cases pass without changing any expected action/unknown labels.

Do not rewrite historical 43/59 results or add UX05 to that old denominator.
The current broader core/challenge result remains 49/55 with six mismatches and
three pending cases; these five controls do not resolve those remaining gaps.
The fixtures are synthetic developer regressions, not held-out model accuracy.

## Handoff

@iazizza can consume the linked historical and post-fix evidence for SOU-20.
Core classifier fixes remain owned by @sake_ai. Final contract compatibility,
uncertain gold labels and production integration remain separate parent work;
merging this add-on does not close SOU-5 or establish an execution barrier.
