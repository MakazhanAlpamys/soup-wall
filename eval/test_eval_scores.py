# SPDX-License-Identifier: Apache-2.0
"""SOU-19: optional SOU-10 score fields must not turn invalid output into a pass."""
import unittest

import eval_runner as R
from test_eval_runner import case, const


class OptionalScoreValidation(unittest.TestCase):
    def test_invalid_score_is_technical_even_for_expected_unknown(self):
        invalid = [float("nan"), float("inf"), -float("inf"), -0.01, 1.01,
                   True, False, None, "0.8", [], {}, 10**400]
        for field in ("confidence", "uncertainty"):
            for value in invalid:
                with self.subTest(field=field, value=value):
                    out = {"actions": [], "unknown": True, field: value}
                    row = R.evaluate_case(case(actions=[], unknown=True), const(out), "review")
                    self.assertEqual(row["outcome"], "technical_error")
                    self.assertIn(field, row["technical_error"])
                    self.assertEqual(R.exit_code(R.summarize([row])), 2)

    def test_valid_optional_scores_and_core_only_no_op(self):
        for actions, unknown in [(["read"], False), ([], True), ([], False)]:
            for fields in [{}, {"confidence": 0}, {"uncertainty": 1},
                           {"confidence": 0.75, "uncertainty": 0.25}]:
                with self.subTest(actions=actions, unknown=unknown, fields=fields):
                    out = {"actions": actions, "unknown": unknown, **fields}
                    row = R.evaluate_case(case(actions=actions, unknown=unknown), const(out), "review")
                    self.assertEqual(row["outcome"], "pass")

    def test_pending_invalid_score_remains_unscored_but_is_reported(self):
        pending = case(actions=None, unknown=None, status="pending")
        out = {"actions": ["read"], "unknown": False, "confidence": float("nan")}
        row = R.evaluate_case(pending, const(out), "review")
        summary = R.summarize([row])
        self.assertEqual(row["outcome"], "unscored")
        self.assertEqual(summary["overall"]["scored"], 0)
        self.assertEqual(len(summary["technical_errors"]), 1)
        self.assertEqual(R.exit_code(summary), 2)

    def test_invalid_then_valid_output_does_not_abort_evaluation(self):
        outputs = [{"actions": ["read"], "unknown": False, "uncertainty": "bad"},
                   {"actions": ["read"], "unknown": False, "uncertainty": 0}]
        rows = [R.evaluate_case(case(cid=f"T{i}"), const(out), "review")
                for i, out in enumerate(outputs)]
        self.assertEqual([row["outcome"] for row in rows], ["technical_error", "pass"])


if __name__ == "__main__":
    unittest.main()
