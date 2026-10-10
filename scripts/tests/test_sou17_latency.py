# SPDX-License-Identifier: Apache-2.0
"""Adversarial grading checks; no Cargo, processes, models or network are started."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("sou17_latency", Path(__file__).resolve().parents[1] / "measure-sou17-latency.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
DIGEST = "a" * 64


def observation(index=0, path="protected", warmup=False):
    call_id = "warmup" if warmup else f"latency-{index}"
    request = {"jsonrpc": "2.0", "id": call_id, "method": "tools/call",
               "params": {"name": "read_document", "arguments": {"name": "inventory"}}}
    response = {"jsonrpc": "2.0", "id": call_id,
                "result": {"content": [{"type": "text", "text": "Inventory: 7 red widgets."}]}}
    frame, result = json.dumps(request), json.dumps(response) + "\n"
    native = [{"event": event, "verdict": "allow", "released": True, "shadow": False,
               "tool": "read_document", "call_id": "native-" + call_id, "session": "s",
               "binding_sha256": "b" * 64} for event in ("native_call", "native_result")]
    return {"pair": index, "warmup": warmup, "path": path, "host_call_id": call_id,
            "submitted_frame": frame, "request_latency_ms": 8 if path == "protected" else 2,
            "executor_delta_raw": frame + "\n", "server_delta_raw": result, "released_raw": result,
            "native_decisions": native, "classifications": [{"host_call_id": call_id,
                "source": "rule-baseline/python", "tool": "read_document", "classifier_sha256": DIGEST,
                "contract_version": "sw-classification/candidate-1",
                "args_sha256": PROBE.sha(b'{"name":"inventory"}'),
                "classification": {"actions": ["read"], "unknown": False, "confidence": .9, "uncertainty": .1},
                "authoritative_verdict": "allow", "policy": "reached", "failure": None}]}


class LatencyEvidenceTests(unittest.TestCase):
    def grade(self, row):
        return PROBE.grade(row, row["path"] == "protected", DIGEST)

    def test_allow_requires_original_effect_result_and_actual_production_gate(self):
        for path in ("direct", "protected"):
            result = self.grade(observation(path=path))
            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["executor_count"], 1)
            self.assertGreater(result["released_bytes"], 0)

    def test_missing_duplicate_effect_and_mismatched_result_fail(self):
        for mutation in (
            lambda row: row.update(executor_delta_raw=""),
            lambda row: row.update(executor_delta_raw=row["executor_delta_raw"] * 2),
            lambda row: row.update(released_raw=row["released_raw"].replace("latency-0", "other")),
            lambda row: row.update(server_delta_raw=""),
            lambda row: row.update(released_raw=row["released_raw"].replace("7 red", "8 red")),
            lambda row: row["native_decisions"][1].update(call_id="different"),
            lambda row: row["native_decisions"][0].update(released=False),
        ):
            row = observation(); mutation(row)
            self.assertEqual(self.grade(row)["status"], "fail")
            self.assertIs(type(row["false_interruption"]), bool)

    def test_security_anomaly_does_not_invent_a_false_interruption(self):
        row = observation()
        row["native_decisions"][1]["call_id"] = "unrelated"
        self.assertEqual(self.grade(row)["status"], "fail")
        self.assertFalse(row["false_interruption"])
        row = observation()
        row["executor_delta_raw"] *= 2
        self.assertEqual(self.grade(row)["status"], "fail")
        self.assertTrue(row["execution_anomaly"])
        self.assertFalse(row["false_interruption"])
        row = observation(); row["executor_delta_raw"] = ""
        self.assertEqual(self.grade(row)["status"], "fail")
        self.assertTrue(row["false_interruption"])

    def test_null_boolean_missing_or_noncanonical_host_ids_are_incomplete(self):
        for value in (None, True, False, "", "other", 0):
            row = observation()
            request, response = json.loads(row["submitted_frame"]), json.loads(row["released_raw"])
            request["id"] = response["id"] = value
            row.update(host_call_id=value, submitted_frame=json.dumps(request),
                       released_raw=json.dumps(response) + "\n")
            row["executor_delta_raw"] = row["submitted_frame"] + "\n"
            row["server_delta_raw"] = row["released_raw"]
            row["classifications"][0]["host_call_id"] = value
            self.assertEqual(self.grade(row)["status"], "incomplete")
        row = observation()
        del row["host_call_id"]
        self.assertEqual(self.grade(row)["status"], "incomplete")
        row = observation(); row["pair"] = True
        self.assertEqual(self.grade(row)["status"], "incomplete")

    def test_invalid_expected_classifier_revision_cannot_match_missing_digest(self):
        for digest in (None, "", "x" * 64, "A" * 64, True):
            row = observation()
            row["classifications"][0].pop("classifier_sha256")
            self.assertEqual(PROBE.grade(row, True, digest)["status"], "incomplete")

    def test_nested_arrays_and_scalars_are_explicitly_incomplete(self):
        for mutation in (
            lambda row: row.update(submitted_frame='"call"'),
            lambda row: row.update(submitted_frame=json.dumps({"id": "latency-0", "params": []})),
            lambda row: row.update(classifications=[[]]),
            lambda row: row["classifications"][0].update(classification=[]),
            lambda row: row.update(native_decisions=[[], {}]),
        ):
            row = observation(); mutation(row)
            self.assertEqual(self.grade(row)["status"], "incomplete")

    def test_missing_session_or_binding_cannot_be_native_allow_evidence(self):
        for field, value in (("session", None), ("session", ""), ("binding_sha256", None),
                             ("binding_sha256", "x" * 64), ("binding_sha256", "a" * 63)):
            row = observation()
            for event in row["native_decisions"]:
                event[field] = value
            self.assertEqual(self.grade(row)["status"], "fail")

    def test_missing_or_corrupt_evidence_is_incomplete(self):
        for mutation in (
            lambda row: row.update(submitted_frame="[]"),
            lambda row: row.update(classifications=[None]),
            lambda row: row.update(native_decisions=[None, None]),
            lambda row: row["classifications"][0].update(classification=None),
            lambda row: row.update(executor_delta_raw='{broken\n'),
            lambda row: row.update(executor_delta_raw='[]\n'),
            lambda row: row.update(executor_delta_raw=row["executor_delta_raw"].rstrip()),
            lambda row: row.update(released_raw=""),
            lambda row: row.update(classifications=[]),
            lambda row: row.update(native_decisions=[]),
            lambda row: row["classifications"][0].update(classifier_sha256="wrong"),
            lambda row: row["classifications"][0].update(host_call_id="wrong"),
        ):
            row = observation(); mutation(row)
            self.assertEqual(self.grade(row)["status"], "incomplete")

    def test_bool_nonfinite_overflow_negative_and_missing_timing_cannot_pass(self):
        for value in (True, float("nan"), float("inf"), -1, 15001, 10**1000, None):
            row = observation(); row["request_latency_ms"] = value
            self.assertEqual(self.grade(row)["status"], "incomplete")
        for value in (True, float("nan"), 2, 10**1000):
            row = observation(); row["classifications"][0]["classification"]["confidence"] = value
            self.assertEqual(self.grade(row)["status"], "incomplete")

    def test_strict_json_rejects_duplicate_fields_and_overflow(self):
        for raw in ('{"a":1,"a":2}', '{"a":1e999}', '{"a":NaN}'):
            with self.assertRaises(ValueError):
                PROBE.strict_json(raw)

    def test_nearest_rank_preserves_negative_paired_overhead(self):
        self.assertEqual(PROBE.percentile(list(range(1, 101)), .95), 95)
        self.assertEqual(PROBE.percentile([-2, -1, 0, 1], .5), -1)
        for values in ([], [float("nan")], [True], [10**1000]):
            with self.assertRaises(ValueError):
                PROBE.percentile(values, .5)

    def samples(self):
        return [self.grade(observation(index, path, index == -1))
                for index in range(-1, 30) for path in ("direct", "protected")]

    def test_summary_requires_all_pairs_and_excludes_warmup(self):
        rows = self.samples()
        summary = PROBE.summarize(rows, 30, True)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["paired_overhead_ms"]["raw"], [6] * 30)
        self.assertEqual(summary["fixture_false_interruptions"], 0)
        for partial in (rows[:-1], [dict(row, status="incomplete") if row["warmup"] else row for row in rows]):
            self.assertEqual(PROBE.summarize(partial, 30, True)["status"], "incomplete")
        self.assertEqual(PROBE.summarize(rows, 30, False)["status"], "incomplete")
        self.assertEqual(PROBE.summarize(rows, 30, True, False)["status"], "incomplete")

    def test_duplicate_sample_or_warmup_cannot_substitute_for_missing_identity(self):
        rows = self.samples()
        rows[-1] = dict(rows[-2])
        self.assertEqual(PROBE.summarize(rows, 30, True)["status"], "incomplete")
        rows = self.samples()
        rows[1] = dict(rows[0])
        self.assertEqual(PROBE.summarize(rows, 30, True)["status"], "incomplete")

    def test_pair_frame_or_result_difference_prevents_overhead_claim(self):
        for field in ("submitted_frame", "released_raw"):
            rows = self.samples(); rows[-1][field] += " "
            summary = PROBE.summarize(rows, 30, True)
            self.assertEqual(summary["status"], "incomplete")
            self.assertNotIn("paired_overhead_ms", summary)

    def test_post_stop_tail_cannot_be_hidden_by_successful_per_call_snapshots(self):
        rows = self.samples()
        selected = [row for row in rows if row["path"] == "protected"]
        ledger = "".join(row["executor_delta_raw"] for row in selected).encode()
        results = b'{"id":"init"}\n{"id":"list"}\n' + "".join(row["released_raw"] for row in selected).encode()
        self.assertTrue(PROBE.reconcile(rows, ledger, results, results, "protected"))
        for tail in (b'{broken\n', selected[-1]["executor_delta_raw"].encode(), b'{}\n'):
            self.assertFalse(PROBE.reconcile(rows, ledger + tail, results, results, "protected"))
        self.assertFalse(PROBE.reconcile(rows, ledger, results + b'{}\n', results, "protected"))

    def test_credential_rejection_happens_before_any_artifact_write(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                PROBE.retain(Path(directory), {"safe.log": b"safe", "bad.log": b"token=secret"}, [b"secret"])
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
