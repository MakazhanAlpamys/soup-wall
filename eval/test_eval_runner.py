# SPDX-License-Identifier: Apache-2.0
"""Unit tests for eval_runner.py. Stub classifiers only; the real baseline is not used here."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

import eval_runner as R


def case(cid="T01", actions=("read",), unknown=False, status="provisional", forbidden=None, requires=(),
         assumptions=("A1",), tool="t", group="unseen_tools"):
    exp = {"actions": None if actions is None else list(actions), "unknown": unknown, "status": None}
    if forbidden:
        exp["forbidden_actions"] = list(forbidden)
    return {"id": cid, "group": group, "origin": "test", "expectation_status": status, "requires": list(requires),
            "contract_assumptions": list(assumptions),
            "input": {"tool_name": tool, "tool_description": None, "tool_schema": None, "raw_arguments": {"x": "y"}},
            "expected": exp, "evaluator_only": {"ground_truth_basis": "SECRET-GOLD"}}


def const(out):
    return lambda inp: copy.deepcopy(out)


def ok(actions, unknown=False):
    return {"status": "ok" if actions else "unknown", "actions": list(actions), "unknown": unknown}


class Comparison(unittest.TestCase):
    def ev(self, c, out):
        return R.evaluate_case(c, const(out), "suite")

    def test_exact_match_passes(self):
        self.assertEqual(self.ev(case(actions=["read", "send_data"]), ok(["read", "send_data"]))["outcome"], "pass")

    def test_order_is_ignored(self):
        self.assertEqual(self.ev(case(actions=["read", "send_data"]), ok(["send_data", "read"]))["outcome"], "pass")

    def test_unknown_mismatch_fails_even_when_actions_match(self):
        # the defect in the old run_eval.py: actions=[read], unknown=true passed for an expected [read]
        r = self.ev(case(actions=["read"], unknown=False), ok(["read"], unknown=True))
        self.assertEqual(r["outcome"], "fail")
        self.assertTrue(r["actions_match"])
        self.assertFalse(r["unknown_match"])

    def test_missing_unknown_on_partial_case_fails(self):
        r = self.ev(case(actions=["read"], unknown=True), ok(["read"], unknown=False))
        self.assertEqual((r["outcome"], r["unknown_match"]), ("fail", False))

    def test_missing_and_spurious(self):
        r = self.ev(case(actions=["read", "delete"]), ok(["read", "write"]))
        self.assertEqual((r["missing"], r["spurious"]), (["delete"], ["write"]))

    def test_critical_miss_is_flagged(self):
        r = self.ev(case(actions=["read", "send_data", "change_permissions"]), ok(["read"]))
        self.assertEqual(r["critical_missing"], ["send_data", "change_permissions"])

    def test_non_critical_miss_not_flagged_critical(self):
        self.assertEqual(self.ev(case(actions=["read", "write"]), ok(["read"]))["critical_missing"], [])

    def test_fully_unknown_expected_and_predicted_passes(self):
        self.assertEqual(self.ev(case(actions=[], unknown=True), ok([], unknown=True))["outcome"], "pass")

    def test_status_not_evaluated_when_expected_null(self):
        r = self.ev(case(), {"status": "unknown", "actions": ["read"], "unknown": False})
        self.assertEqual((r["outcome"], r["status_check"]), ("pass", "not_evaluated"))

    def test_status_checked_when_expected_set(self):
        c = case()
        c["expected"]["status"] = "ok"
        self.assertEqual(self.ev(c, {"status": "unknown", "actions": ["read"], "unknown": False})["outcome"], "fail")


class TechnicalErrors(unittest.TestCase):
    def ev(self, c, fn):
        return R.evaluate_case(c, fn, "suite")

    def test_error_status_is_technical_not_pass_for_unknown_case(self):
        # the second defect in the old runner: status=error passed an expected-unknown case
        r = self.ev(case(actions=[], unknown=True), const({"status": "error", "actions": [], "unknown": True}))
        self.assertEqual(r["outcome"], "technical_error")

    def test_exception_is_technical_and_does_not_stop_run(self):
        def boom(_):
            raise RuntimeError("crash")
        recs = [self.ev(case("A"), boom), self.ev(case("B"), const(ok(["read"])))]
        self.assertEqual([r["outcome"] for r in recs], ["technical_error", "pass"])
        self.assertIn("RuntimeError", recs[0]["technical_error"])

    def test_invalid_outputs(self):
        for bad in [None, "read", {"actions": "read", "unknown": False}, {"actions": ["read", "unknown"], "unknown": True},
                    {"actions": ["read"], "unknown": "no"}, {"actions": ["read", "read"], "unknown": False},
                    {"actions": [], "unknown": False}, {"status": "weird", "actions": ["read"], "unknown": False},
                    {"actions": ["read"]}]:
            with self.subTest(bad=bad):
                self.assertEqual(self.ev(case(), const(bad))["outcome"], "technical_error")


class PendingAndConstraints(unittest.TestCase):
    def test_pending_is_unscored(self):
        r = R.evaluate_case(case(actions=None, unknown=None, status="pending"), const(ok(["delete"])), "s")
        self.assertEqual(r["outcome"], "unscored")

    def test_pending_excluded_from_denominators(self):
        recs = [R.evaluate_case(case("P", actions=None, unknown=None, status="pending"), const(ok(["read"])), "s"),
                R.evaluate_case(case("S"), const(ok(["read"])), "s")]
        o = R.summarize(recs)["overall"]
        self.assertEqual((o["scored"], o["pass"], o["unscored"]), (1, 1, 1))

    def test_constraint_violation_reported_and_sets_exit_1(self):
        c = case(actions=None, unknown=None, status="pending", forbidden=["delete", "write"])
        recs = [R.evaluate_case(c, const(ok(["read", "delete"])), "s")]
        s = R.summarize(recs)
        self.assertEqual(s["constraint_violations"][0]["violated"], ["delete"])
        self.assertEqual(R.exit_code(s), 1)

    def test_constraint_satisfied(self):
        c = case(actions=None, unknown=None, status="pending", forbidden=["delete"])
        s = R.summarize([R.evaluate_case(c, const(ok(["read"])), "s")])
        self.assertEqual((s["constraint_violations"], R.exit_code(s)), ([], 0))


class Leakage(unittest.TestCase):
    def test_classifier_receives_only_input(self):
        seen = []

        def spy(inp):
            seen.append(copy.deepcopy(inp))
            return ok(["read"])
        c = case()
        R.evaluate_case(c, spy, "s")
        self.assertEqual(seen, [c["input"]])
        self.assertNotIn("SECRET-GOLD", json.dumps(seen))
        self.assertNotIn("expected", json.dumps(seen))

    def test_classifier_mutation_cannot_change_fixture(self):
        def mutate(inp):
            inp["raw_arguments"]["x"] = "changed"
            return ok(["read"])
        c = case()
        R.evaluate_case(c, mutate, "s")
        self.assertEqual(c["input"]["raw_arguments"]["x"], "y")


class Buckets(unittest.TestCase):
    def test_shell_bucket_and_assumption_bucket(self):
        recs = [R.evaluate_case(case("A", requires=["shell_parsing"], assumptions=["A1", "A5"]), const(ok(["write"])), "s"),
                R.evaluate_case(case("B"), const(ok(["read"])), "s")]
        b = R.summarize(recs)["buckets"]
        self.assertEqual(b["shell_dependent"]["s / requires shell_parsing"]["fail"], 1)
        self.assertEqual(b["shell_dependent"]["s / no shell parsing"]["pass"], 1)
        self.assertEqual(b["assumption"]["A5"]["scored"], 1)
        self.assertEqual(b["assumption"]["A1"]["scored"], 2)

    def test_unknown_mismatch_lists(self):
        recs = [R.evaluate_case(case("A", actions=["read"], unknown=True), const(ok(["read"])), "s")]
        u = R.summarize(recs)["unknown_mismatches"]
        self.assertEqual((u["expected_true_predicted_false"], u["actions_right_but_unknown_wrong"]), (["A"], ["A"]))


class ExitCodes(unittest.TestCase):
    def test_codes(self):
        passing = R.summarize([R.evaluate_case(case(), const(ok(["read"])), "s")])
        failing = R.summarize([R.evaluate_case(case(), const(ok(["write"])), "s")])
        tech = R.summarize([R.evaluate_case(case(), const(None), "s"),
                            R.evaluate_case(case("B"), const(ok(["write"])), "s")])
        self.assertEqual([R.exit_code(passing), R.exit_code(failing), R.exit_code(tech)], [0, 1, 2])


class FixtureValidation(unittest.TestCase):
    def fx(self, *cases):
        return {"fixture_version": "t", "cases": list(cases)}

    def test_valid(self):
        self.assertEqual(R.validate_fixture(self.fx(case(), case("B", actions=None, unknown=None, status="pending"))), [])

    def test_catches_problems(self):
        bad_label = case(actions=["read", "unknown"])
        bad_unknown = case("B", unknown=None)
        empty_known = case("C", actions=[], unknown=False)
        pending_with_gold = case("D", status="pending")
        dup = case("E")
        leak = case("F")
        leak["input"]["raw_arguments"] = {"note": "case F"}
        extra_input_key = case("G")
        extra_input_key["input"]["expected"] = ["read"]
        errs = R.validate_fixture(self.fx(bad_label, bad_unknown, empty_known, pending_with_gold, dup, dict(dup), leak,
                                          extra_input_key))
        text = "\n".join(errs)
        for needle in ("T01: expected.actions", "B: expected.unknown", "C: actions=[] with unknown=false",
                       "D: pending cases", "E: duplicate id", "F: case id appears", "G: input must be"):
            self.assertIn(needle, text)


class EndToEnd(unittest.TestCase):
    def test_main_writes_outputs_and_returns_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "stub_clf.py").write_text("def classify(inp):\n    return {'status':'ok','actions':['read'],'unknown':False}\n")
            fx = {"fixture_version": "t", "cases": [case("A"), case("B", actions=["delete"])]}
            (d / "fx.json").write_text(json.dumps(fx))
            code = R.main([str(d / "fx.json"), "--classifier", "stub_clf:classify", "--classifier-path", str(d),
                           "--out-dir", str(d / "out")])
            self.assertEqual(code, 1)
            res = json.loads((d / "out" / "results.json").read_text())
            self.assertEqual(res["summary"]["overall"]["pass"], 1)
            self.assertEqual(res["summary"]["critical_misses"][0]["id"], "B")
            self.assertTrue((d / "out" / "results.csv").read_text().startswith("suite,id,"))
            self.assertIn("Critical misses", (d / "out" / "summary.md").read_text())

    def test_invalid_fixture_returns_3(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "stub_clf2.py").write_text("def classify(inp):\n    return {'actions':['read'],'unknown':False}\n")
            (d / "fx.json").write_text(json.dumps({"fixture_version": "t", "cases": [case(actions=["bogus"])]}))
            self.assertEqual(R.main([str(d / "fx.json"), "--classifier", "stub_clf2:classify",
                                     "--classifier-path", str(d), "--out-dir", str(d / "out")]), 3)
            self.assertFalse((d / "out").exists())


if __name__ == "__main__":
    unittest.main()
