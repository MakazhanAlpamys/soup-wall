# SPDX-License-Identifier: Apache-2.0
"""Adversarial evidence grading; these tests never start Cargo, a model or a service."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("sou17_pending", Path(__file__).resolve().parents[1] / "verify-sou17-pending-admission.py")
PROBE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROBE
SPEC.loader.exec_module(PROBE)
DIGEST = "c" * 64


def overlap(name):
    case = next(case for case in PROBE.CASES if case[0] == name)
    call_id = "overlap-" + name
    response = {"jsonrpc": "2.0", "id": call_id}
    if case[4] == "allow":
        response["result"] = {"content": [{"type": "text", "text": "Inventory: 7 red widgets."}]}
    else:
        reason = "policy_denied" if case[4] == "deny" else "policy_unconfirmed_ask"
        response["result"] = {"isError": True, "content": [{"type": "text", "text": reason}]}
    raw = json.dumps(response) + "\n"
    return {"case": name, "host_call_id": call_id, "submitted_frame": PROBE.call_frame(call_id),
        "classifications": [{"host_call_id": call_id, "tool": "read_document", "source": "rule-baseline/python",
            "trusted_baseline": "read_only", "classifier_sha256": DIGEST, "policy": "reached", "failure": None,
            "classification": {"actions": case[1], "unknown": case[2], "confidence": .95, "uncertainty": case[3]},
            "authoritative_verdict": case[4]}], "response": response, "client_response_raw": raw,
        "original_server_results": [raw] if case[4] == "allow" else [],
        "executor_ledger_raw": PROBE.call_frame(call_id) + "\n" if case[4] == "allow" else ""}


def cancellation():
    return {"case": "pending-classifier-cancellation", "host_call_id": PROBE.CANCEL_ID,
        "submitted_frame": PROBE.call_frame(PROBE.CANCEL_ID),
        "classifier_ready": {"classifier_sha256": DIGEST,
            "request": {"tool_name": "read_document", "raw_arguments": {"name": "inventory"}},
            "reply": {"actions": ["read"], "unknown": False, "confidence": .95, "uncertainty": .05}},
        "cancellation_frame": json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {
            "requestId": PROBE.CANCEL_ID, "reason": "synthetic pending admission cancellation"}}),
        "call_written_at": 0., "ready_observed_at": .1, "cancel_written_at": .11, "release_written_at": .12,
        "cancel_write_completed": True, "ledger_before_release_raw": "", "executor_ledger_raw": "",
        "transport_outcome": "eof", "gateway_exit_code": 1, "client_response_raw": "",
        "original_server_results": [], "collector_stderr": "Error: unsupported MCP notification\n"}


class PolicyOverlapGrading(unittest.TestCase):
    def grade(self, row, stable=True, digest=DIGEST):
        return PROBE.grade_overlap(row, stable, digest)["status"]

    def test_all_expected_verdicts_need_matching_witnesses(self):
        for case in PROBE.CASES:
            with self.subTest(case=case[0]):
                self.assertEqual(self.grade(overlap(case[0])), "pass")

    def test_high_uncertainty_cannot_weaken_readonly_write_deny(self):
        row = overlap("write-readonly-high")
        row["classifications"][0]["authoritative_verdict"] = "ask"
        row["response"]["result"]["content"][0]["text"] = "policy_unconfirmed_ask"
        row["client_response_raw"] = json.dumps(row["response"]) + "\n"
        self.assertEqual(self.grade(row), "fail")
        self.assertEqual(row["executor_ledger_raw"], "")

    def test_known_forbidden_entry_fails_despite_partial_response_or_corrupt_tail(self):
        for malformed in (False, True):
            row = overlap("delete-high")
            row["executor_ledger_raw"] = row["submitted_frame"] + "\n" + ("{broken\n" if malformed else "")
            row.pop("response")
            self.assertEqual(self.grade(row), "fail")

    def test_nonempty_malformed_ledger_cannot_be_zero_effect_pass(self):
        for raw in ("{broken\n", "null\n", "[]\n", '{"method":"tools/call"}\n', '{"method":"tools/call","x":1e999}\n'):
            row = overlap("delete-high")
            row["executor_ledger_raw"] = raw
            self.assertEqual(self.grade(row), "inconclusive")

    def test_missing_authority_correlations_or_changed_source_are_inconclusive(self):
        for mutation in (
            lambda row: row.pop("classifications"),
            lambda row: row["classifications"][0].update(host_call_id="other"),
            lambda row: row["classifications"][0].update(classifier_sha256="d" * 64),
            lambda row: row["classifications"][0].update(source="mock"),
            lambda row: row["classifications"][0].update(trusted_baseline="network"),
        ):
            row = overlap("delete-high")
            mutation(row)
            self.assertEqual(self.grade(row), "inconclusive")
        self.assertEqual(self.grade(overlap("delete-high"), stable=False), "inconclusive")
        self.assertEqual(self.grade(overlap("delete-high"), digest="bad"), "inconclusive")

    def test_scores_are_not_coerced_or_nonfinite(self):
        for value in (True, float("nan"), float("inf"), 10 ** 500, "0.95"):
            row = overlap("delete-high")
            row["classifications"][0]["classification"]["confidence"] = value
            self.assertEqual(self.grade(row), "inconclusive")

    def test_technical_unsupported_never_counts_as_policy_pass(self):
        row = overlap("read-unknown")
        row["classifications"][0].update(policy="not_reached", failure="unsupported_classification_mapping")
        row["response"] = {"jsonrpc": "2.0", "id": row["host_call_id"], "error": {
            "code": -32603, "message": "unsupported_classification_mapping; policy not reached"}}
        row["client_response_raw"] = json.dumps(row["response"]) + "\n"
        self.assertEqual(self.grade(row), "technical_unsupported")
        row["executor_ledger_raw"] = row["submitted_frame"] + "\n"
        self.assertEqual(self.grade(row), "fail")

    def test_allow_requires_exact_one_original_entry_and_useful_original_result(self):
        mutations = [
            lambda row: row.update(executor_ledger_raw=""),
            lambda row: row.update(executor_ledger_raw=row["executor_ledger_raw"] * 2),
            lambda row: row.update(original_server_results=[]),
            lambda row: row.update(original_server_results=["rewritten result\n"]),
        ]
        for mutation in mutations:
            row = overlap("benign-before")
            mutation(row)
            self.assertEqual(self.grade(row), "fail")

    def test_raw_client_response_and_decoded_response_must_match(self):
        row = overlap("delete-high")
        row["client_response_raw"] = ""
        self.assertEqual(self.grade(row), "inconclusive")

    def test_malformed_nested_response_is_not_a_crash_or_pass(self):
        row = overlap("read-unknown")
        row["classifications"][0].update(policy="not_reached", failure="unsupported_classification_mapping")
        for error in (None, 7, [], "text"):
            row["response"] = {"id": row["host_call_id"], "error": error}
            row["client_response_raw"] = json.dumps(row["response"])
            self.assertEqual(self.grade(row), "inconclusive")


class CancellationGrading(unittest.TestCase):
    def grade(self, row, stable=True):
        return PROBE.grade_cancellation(row, stable, DIGEST)["status"]

    def test_known_unsupported_transport_refusal_without_effect_can_pass(self):
        self.assertEqual(self.grade(cancellation()), "pass")

    def test_effect_after_valid_handshake_fails_with_missing_later_logs(self):
        row = cancellation()
        row["executor_ledger_raw"] = row["submitted_frame"] + "\n{partial\n"
        row.pop("gateway_exit_code")
        row.pop("collector_stderr")
        self.assertEqual(self.grade(row), "fail")

    def test_empty_evidence_or_missing_handshake_never_passes(self):
        self.assertEqual(self.grade({}), "inconclusive")
        for key in ("classifier_ready", "cancel_write_completed", "cancel_written_at", "ledger_before_release_raw"):
            row = cancellation()
            row.pop(key)
            self.assertEqual(self.grade(row), "inconclusive")

    def test_wrong_id_input_revision_or_order_invalidates_handshake(self):
        for mutation in (
            lambda row: row["classifier_ready"].update(classifier_sha256="d" * 64),
            lambda row: row["classifier_ready"]["request"].update(raw_arguments={"name": "other"}),
            lambda row: row.update(cancel_written_at=.2, release_written_at=.12),
            lambda row: row.update(release_written_at=1.6),
            lambda row: row.update(cancel_written_at=float("nan")),
            lambda row: row.update(release_written_at=10 ** 500),
            lambda row: row.update(cancellation_frame=json.dumps({"method": "notifications/cancelled"})),
        ):
            row = cancellation()
            mutation(row)
            self.assertEqual(self.grade(row), "inconclusive")

    def test_timeout_successful_exit_or_missing_diagnostic_is_not_refusal_pass(self):
        for changes in ({"transport_outcome": "timeout"}, {"gateway_exit_code": 0},
                        {"collector_stderr": "generic unrelated error"}, {"collector_stderr": None},
                        {"client_response_raw": "released bytes"}, {"original_server_results": ["bytes"]}):
            row = cancellation()
            row.update(changes)
            self.assertEqual(self.grade(row), "inconclusive")

    def test_malformed_or_premature_ledger_does_not_prove_after_cancel_violation(self):
        for before, after in (("{broken\n", ""), ("", "{broken\n"),
                              (PROBE.call_frame(PROBE.CANCEL_ID) + "\n", PROBE.call_frame(PROBE.CANCEL_ID) + "\n")):
            row = cancellation()
            row.update(ledger_before_release_raw=before, executor_ledger_raw=after)
            self.assertEqual(self.grade(row), "inconclusive")

    def test_source_instability_disables_candidate_claim(self):
        row = cancellation()
        row["executor_ledger_raw"] = row["submitted_frame"] + "\n"
        self.assertEqual(self.grade(row, stable=False), "inconclusive")


class FinalLedgerReconciliation(unittest.TestCase):
    def run_overlap_with_late_bytes(self, late_bytes):
        source = "print('synthetic classifier source for local test')\n"
        digest = PROBE.sha(source.encode())
        predictions = []
        for case in PROBE.CASES:
            evidence = overlap(case[0])["classifications"][0]
            evidence["classifier_sha256"] = digest
            predictions.append(evidence)
        harness = SimpleNamespace(received=[], process=SimpleNamespace(poll=lambda: 0))
        fixture = {}

        @contextmanager
        def agent_stack(_binary, workspace):
            workspace.mkdir()
            fixture["stack"] = SimpleNamespace(
                workspace=workspace, classifications=workspace / "collector.log", collector=[], env={},
                ledger=workspace / "executor.jsonl", responses=workspace / "responses.jsonl")
            yield fixture["stack"]

        def send(frame, reply=True):
            if not reply:
                return None
            request = PROBE.strict_json(frame)
            if request["method"] == "initialize":
                response = {"jsonrpc": "2.0", "id": request["id"], "result": {}}
            elif request["method"] == "tools/list":
                response = {"jsonrpc": "2.0", "id": request["id"], "result": {"tools": [{"name": "read_document"}]}}
            else:
                row = overlap(request["id"].removeprefix("overlap-"))
                response = row["response"]
                if row["executor_ledger_raw"]:
                    with fixture["stack"].ledger.open("a") as stream:
                        stream.write(frame + "\n")
                    with fixture["stack"].responses.open("a") as stream:
                        stream.write(row["client_response_raw"])
            raw = (json.dumps(response) + "\n").encode()
            harness.received.append(raw)
            return raw
        harness.send = send
        demo = SimpleNamespace(agent_stack=agent_stack, Harness=lambda *_args: harness)

        def cleanup(_harness):
            # The refusal was already read and its immediate ledger snapshot was
            # empty. The executor records this late entry only during shutdown.
            with fixture["stack"].ledger.open("a") as stream:
                stream.write(late_bytes)
            return 0

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "overlap"
            with patch.object(PROBE, "classifier_source", return_value=source), \
                    patch.object(PROBE, "telemetry", return_value=predictions), \
                    patch.object(PROBE, "stop", side_effect=cleanup):
                result = PROBE.run_probe(demo, Path("mock-local-agentfw"), "overlap", out)
            retained = (out / "executor-ledger.jsonl").read_text()
        return result, retained

    def test_refused_entry_arriving_during_cleanup_is_a_confirmed_failure(self):
        late = PROBE.call_frame("overlap-delete-high") + "\n"
        probe, retained = self.run_overlap_with_late_bytes(late)
        row = next(row for row in probe["rows"] if row["case"] == "delete-high")
        self.assertEqual(row["executor_ledger_at_response_raw"], "")
        self.assertEqual(row["executor_ledger_raw"], late)
        self.assertTrue(row["executor_ledger_final_reconciled"])
        self.assertTrue(retained.endswith(late))
        self.assertEqual(PROBE.grade_overlap(row, True, probe["classifier_sha256"])["status"], "fail")

    def test_malformed_final_tail_invalidates_otherwise_zero_effect_rows(self):
        probe, retained = self.run_overlap_with_late_bytes("{broken final tail\n")
        self.assertTrue(retained.endswith("{broken final tail\n"))
        for row in probe["rows"]:
            self.assertTrue(row["executor_ledger_final_reconciled"])
            self.assertEqual(PROBE.grade_overlap(row, True, probe["classifier_sha256"])["status"], "inconclusive")

    def test_confirmed_late_forbidden_effect_survives_corrupt_tail(self):
        late = PROBE.call_frame("overlap-delete-high") + "\n{broken final tail\n"
        probe, _retained = self.run_overlap_with_late_bytes(late)
        row = next(row for row in probe["rows"] if row["case"] == "delete-high")
        self.assertEqual(PROBE.grade_overlap(row, True, probe["classifier_sha256"])["status"], "fail")

    def test_unterminated_final_frame_preserves_confirmed_failure_but_invalidates_other_rows(self):
        late = PROBE.call_frame("overlap-delete-high")
        probe, retained = self.run_overlap_with_late_bytes(late)
        self.assertTrue(retained.endswith(late))
        for row in probe["rows"]:
            expected = "fail" if row["case"] == "delete-high" else "inconclusive"
            self.assertEqual(PROBE.grade_overlap(row, True, probe["classifier_sha256"])["status"], expected)

    def test_unrelated_final_entry_is_not_discarded(self):
        rows = [overlap("delete-high")]
        PROBE.reconcile_final_ledger(rows, PROBE.call_frame("unrelated") + "\n")
        self.assertNotEqual(rows[0]["executor_ledger_raw"], "")
        self.assertEqual(PROBE.grade_overlap(rows[0], True, DIGEST)["status"], "inconclusive")


class ProbeCompletionGrading(unittest.TestCase):
    def fixture(self, **changes):
        return dict({"mode": "overlap", "classifier_sha256": DIGEST, "gateway_exit_code": 0,
                     "rows": [overlap(case[0]) for case in PROBE.CASES], "error": None}, **changes)

    def test_complete_rows_cannot_pass_after_transport_or_cleanup_failure(self):
        for changes in ({"error": {"type": "OSError", "message": "cleanup failed"}},
                        {"gateway_exit_code": None}, {"gateway_exit_code": 1}):
            with self.subTest(changes=changes):
                probe = self.fixture(**changes)
                graded = PROBE.grade_probe(probe, True)
                self.assertTrue(all(row["status"] == "inconclusive" for row in graded))
                self.assertTrue(all(row["observed_grade"]["status"] == "pass" for row in probe["rows"]))

    def test_confirmed_violation_keeps_failure_priority_after_cleanup_error(self):
        probe = self.fixture(error={"type": "OSError", "message": "cleanup failed"})
        row = next(row for row in probe["rows"] if row["case"] == "delete-high")
        row["executor_ledger_raw"] = row["submitted_frame"] + "\n"
        self.assertEqual(PROBE.overall(PROBE.grade_probe(probe, True)), ("fail", 1))

    def test_expected_cancellation_nonzero_exit_remains_a_narrow_pass(self):
        probe = {"mode": "cancel", "classifier_sha256": DIGEST, "gateway_exit_code": 1,
                 "rows": [cancellation()], "error": None}
        self.assertEqual(PROBE.grade_probe(probe, True)[0]["status"], "pass")
        probe["error"] = {"type": "OSError", "message": "cleanup failed"}
        self.assertEqual(PROBE.grade_probe(probe, True)[0]["status"], "inconclusive")


class AggregationAndParsing(unittest.TestCase):
    def test_empty_or_incomplete_or_unsupported_cannot_be_pass(self):
        for rows in ([], [{"status": "pass"}], [{"status": "pass"}] * len(PROBE.CASES),
                     [{"status": "pass"}] * len(PROBE.CASES) + [{"status": "technical_unsupported"}]):
            self.assertEqual(PROBE.overall(rows), ("inconclusive", 2))
        rows = [{"case": case[0], "status": "pass"} for case in PROBE.CASES]
        rows.append({"case": "pending-classifier-cancellation", "status": "pass"})
        self.assertEqual(PROBE.overall(rows), ("pass", 0))
        self.assertEqual(PROBE.overall(rows[:-1] + [rows[0]]), ("inconclusive", 2))
        self.assertEqual(PROBE.overall(list(reversed(rows))), ("inconclusive", 2))
        self.assertEqual(PROBE.overall([{"status": "fail"}]), ("fail", 1))

    def test_duplicate_members_and_nonfinite_json_fail_strict_parsing(self):
        for raw in ('{"id":1,"id":2}', '{"score":1e999}', '[NaN]', '{"x":[Infinity]}'):
            with self.assertRaises(ValueError):
                PROBE.strict_json(raw)
        self.assertEqual(PROBE.strict_json('{"score":0.95}'), {"score": .95})

    def test_clean_exact_source_gate_precedes_any_fixture_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            args = SimpleNamespace(repo=base, agentfw=base / "agentfw", output=base / "out",
                                   expected_commit="a" * 40)
            for source in ({"commit": "b" * 40, "dirty": False}, {"commit": "a" * 40, "dirty": True}):
                with patch.object(PROBE, "snapshot", return_value=source), patch.object(PROBE, "load_demo") as load:
                    with self.assertRaisesRegex(ValueError, "exact expected HEAD and clean"):
                        PROBE.run(args)
                    load.assert_not_called()
                    self.assertFalse(args.output.exists())

    def test_exact_sha_syntax_is_required_before_source_or_fixture_access(self):
        args = SimpleNamespace(repo=Path("/unused"), agentfw=Path("/unused"), output=Path("/unused"), expected_commit="main")
        with patch.object(PROBE, "snapshot") as snapshot, patch.object(PROBE, "load_demo") as load:
            with self.assertRaisesRegex(ValueError, "exact 40-character"):
                PROBE.run(args)
            snapshot.assert_not_called()
            load.assert_not_called()

    def test_snapshot_hashes_actual_source_and_checks_untracked_dirty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.rs"
            source.write_text("before")
            def git(_repo, *args):
                if args[0] == "ls-files":
                    return "source.rs\0"
                if args[0] == "status":
                    self.assertIn("--untracked-files=all", args)
                    return "?? new.rs"
                return "a" * 40
            with patch.object(PROBE, "git", side_effect=git):
                before = PROBE.snapshot(root)
                source.write_text("after")
                after = PROBE.snapshot(root)
            self.assertTrue(before["dirty"])
            self.assertNotEqual(before["inputs_digest"], after["inputs_digest"])

    def test_classifier_source_is_syntax_valid_and_has_bounded_explicit_gate(self):
        for mode in ("cancel", "overlap"):
            source = PROBE.classifier_source(mode, Path("/synthetic/private"))
            compile(source, "synthetic-classifier", "exec")
            self.assertIn("ready.json", source)
            self.assertIn("time.monotonic()+1.8", source)
            self.assertIn("'release'", source)


if __name__ == "__main__":
    unittest.main()
