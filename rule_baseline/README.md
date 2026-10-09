# Rule-based classifier baseline

This module supplies the owner-maintained Task 1 diagnostic classifier. It
accepts tool metadata and actual arguments and returns multi-action labels plus
an independent `unknown` flag. It never executes tools or issues Allow/Ask/Deny.
Names, argument keys and limited shell patterns are heuristics, not proof of
an unfamiliar tool's complete behavior. Scores are not calibrated probabilities.

From the repository root, with Python 3.10+:

```sh
python3 -m unittest discover -s rule_baseline -p 'test_*.py' -v
python3 eval/eval_runner.py eval/fixtures/soup_task1_evaluation_cases_v0.4.json \
  eval/fixtures/soup_task1_challenge_cases_v0.1.json \
  --classifier-path rule_baseline --out-dir /tmp/soup-wall-classifier-evaluation
```

On Windows use `python` and a local output directory. Input commands are treated
as data. The second command currently exits 1: the frozen core/challenge sets
produce 49/55 scored matches, six classification mismatches and zero scored
technical errors; three pending cases remain unscored. These synthetic fixtures
are diagnostic regressions, not held-out accuracy or production security evidence.
The historical labels are not changed to make the classifier pass. CI runs all
54 unit regressions and the frozen core regression suite explicitly. Challenge
mismatches remain recorded for review instead of being presented as passed cases.

## Interface and remaining integration work

`classify(input)` is the local Python interface consumed by the
[shared evaluation runner](../eval/README.md). The result currently includes the
local `status` convention and diagnostic fields. Invalid input is represented by
`status="error"`; evaluation records it as a technical error, never a successful
unknown classification. The runtime adapter must use the agreed failure channel,
validate pinned schemas and preserve every policy restriction before this source
is connected to admission. The module alone does not implement that integration.

An explicit no-op is valid for the shared runner, but the baseline still uses
unknown when no rule matches. Shell support is a bounded heuristic scanner;
unsupported syntax and uncertain tool semantics need further review. This source
is an independent preparation increment for SOU-5/SOU-14, not acceptance of the
complete contract or a production enforcement path.
