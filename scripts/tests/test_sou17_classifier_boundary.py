#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for independent byte/evidence grading; no daemon or build."""
import copy
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "sou17_classifier_probe", Path(__file__).resolve().parents[1] / "verify-sou17-classifier-boundary.py")
probe = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = probe
spec.loader.exec_module(probe)


class GradeCaseTests(unittest.TestCase):
    def inputs(self, name="high_uncertainty_read"):
        case = next(item for item in probe.cases() if item["name"] == name)
        call_id = "matrix-" + name
        frame = json.dumps({"jsonrpc": "2.0", "id": call_id, "method": "tools/call", "params": {
            "name": "read_document", "arguments": {"name": "inventory"}}}, separators=(",", ":"))
        expected = case["reply"]
        classifier_sha = probe.sha(probe.script_for(case).encode())
        verdict = "allow" if case["executes"] else "deny" if "delete" in expected["actions"] else "ask"
        classification = {key: expected[key] for key in ("actions", "unknown", "confidence", "uncertainty")}
        classification["reason_sha256"] = probe.sha(expected["reason"].encode())
        evidence = {"event": "mcp_classification", "host_call_id": call_id,
                    "classifier_sha256": classifier_sha, "source": "rule-baseline/python",
                    "contract_version": probe.CONTRACT, "classification": classification,
                    "authoritative_verdict": verdict, "policy": "reached", "failure": None}
        row = {"classifier_sha256": classifier_sha, "classification_evidence": [evidence],
               "native_decisions": [{"event": "native_call", "verdict": "allow"}],
               "gateway_exit_code": 0, "receiver_count": 0}
        if case["executes"]:
            reply = {"jsonrpc": "2.0", "id": call_id,
                     "result": {"content": [{"type": "text", "text": "Inventory: 7 red widgets."}]}}
            row["native_decisions"].append({"event": "native_result", "verdict": "allow"})
            ledger = (frame + "\n").encode()
        else:
            reply = {"jsonrpc": "2.0", "id": call_id, "result": {"isError": True, "content": [{
                "type": "text", "text": "Soup Wall withheld MCP invocation (policy_unconfirmed_ask)"}]}}
            ledger = b""
        delivered = (json.dumps(reply, separators=(",", ":")) + "\n").encode()
        original = [delivered] if case["executes"] else []
        return [copy.deepcopy(case), copy.deepcopy(row), ledger, delivered, original, frame]

    def assert_rejected(self, inputs, status="unexpected_observation"):
        result = probe.grade_case(*inputs)
        self.assertEqual(result["status"], status)
        self.assertTrue(result["grading_errors"])
        return result

    def test_useful_allow_requires_and_preserves_original_call_and_result(self):
        result = probe.grade_case(*self.inputs("benign_read"))
        self.assertEqual(result["status"], "boundary_expectation_observed")
        self.assertEqual(result["execution_count"], 1)
        self.assertTrue(result["original_call_bytes_preserved"])
        self.assertTrue(result["original_result_bytes_preserved"])
        self.assertGreater(result["released_original_result_bytes"], 0)

    def test_high_uncertainty_requires_semantic_ask_and_explicit_refusal(self):
        result = probe.grade_case(*self.inputs())
        self.assertEqual(result["status"], "boundary_expectation_observed")
        self.assertEqual(result["gate"], "authoritative_refusal")
        self.assertEqual(result["execution_count"], 0)
        self.assertEqual(result["released_original_result_bytes"], 0)

    def test_missing_classifier_evidence_cannot_pass_from_empty_ledger(self):
        inputs = self.inputs()
        inputs[1]["classification_evidence"] = []
        self.assert_rejected(inputs)

    def test_wrong_classifier_hash_cannot_claim_intended_probe(self):
        inputs = self.inputs()
        inputs[1]["classification_evidence"][0]["classifier_sha256"] = "0" * 64
        self.assert_rejected(inputs)

    def test_missing_or_wrong_client_id_is_rejected(self):
        for wrong_id in (None, "unrelated"):
            with self.subTest(wrong_id=wrong_id):
                inputs = self.inputs()
                reply = json.loads(inputs[3])
                if wrong_id is None:
                    reply.pop("id")
                else:
                    reply["id"] = wrong_id
                inputs[3] = json.dumps(reply).encode()
                self.assert_rejected(inputs)

    def test_malformed_or_non_call_ledger_is_inconclusive_never_empty(self):
        for raw in (b"not JSON\n", b"{}\n", b"0\n", b"\n", b'{"id":1}'):
            with self.subTest(raw=raw):
                inputs = self.inputs()
                inputs[2] = raw
                result = self.assert_rejected(inputs, "inconclusive")
                self.assertIsNone(result["execution_count"])

    def test_unexpected_execution_is_rejected_even_when_client_refuses(self):
        inputs = self.inputs()
        inputs[2] = (inputs[5] + "\n").encode()
        result = self.assert_rejected(inputs)
        self.assertEqual(result["execution_count"], 1)

    def test_empty_ledger_without_explicit_refusal_is_rejected(self):
        inputs = self.inputs()
        inputs[3] = json.dumps({"jsonrpc": "2.0", "id": "matrix-high_uncertainty_read",
                               "result": {"content": []}}).encode()
        self.assert_rejected(inputs)

    def test_unexpected_bridge_error_is_not_semantic_coverage(self):
        inputs = self.inputs("unknown")
        cls = inputs[1]["classification_evidence"][0]
        cls.update(failure="classifier_error", policy="not_reached", classification=None)
        inputs[3] = json.dumps({"jsonrpc": "2.0", "id": "matrix-unknown", "error": {
            "code": -32603, "message": "classifier_error; policy not reached"}}).encode()
        self.assert_rejected(inputs)

    def test_unknown_explicit_unsupported_mapping_is_distinguished(self):
        inputs = self.inputs("unknown")
        inputs[1]["classification_evidence"][0].update(
            failure="unsupported_classification_mapping", policy="not_reached")
        inputs[1]["native_decisions"] = []
        inputs[3] = json.dumps({"jsonrpc": "2.0", "id": "matrix-unknown", "error": {
            "code": -32603, "message": "unsupported_classification_mapping; policy not reached"}}).encode()
        result = probe.grade_case(*inputs)
        self.assertEqual(result["status"], "boundary_expectation_observed")
        self.assertEqual(result["gate"], "technical_unsupported_mapping")

    def test_mixed_danger_may_reach_explicit_composed_deny(self):
        inputs = self.inputs("read_plus_delete")
        inputs[3] = json.dumps({"jsonrpc": "2.0", "id": "matrix-read_plus_delete", "result": {
            "isError": True, "content": [{"type": "text", "text": "policy_denied"}]}}).encode()
        result = probe.grade_case(*inputs)
        self.assertEqual(result["status"], "boundary_expectation_observed")
        self.assertEqual(result["authoritative_verdict"], "deny")

    def test_semantic_score_mismatch_is_not_coverage(self):
        inputs = self.inputs()
        inputs[1]["classification_evidence"][0]["classification"]["uncertainty"] = 0.05
        self.assert_rejected(inputs)

    def test_artifact_write_failure_cannot_leave_a_successful_case(self):
        case = next(item for item in probe.cases() if item["name"] == "high_uncertainty_read")
        replies = iter((b'{"jsonrpc":"2.0","id":"matrix-init","result":{}}\n',
                        b'{"jsonrpc":"2.0","id":"matrix-list","result":{"tools":[]}}\n',
                        b'{"jsonrpc":"2.0","id":"matrix-high_uncertainty_read","result":{"isError":true}}\n'))
        harness = mock.Mock()
        harness.process.poll.return_value = 0
        harness.received = []
        harness.close.return_value = 0

        def send(_frame, reply=True):
            if not reply:
                return None
            response = next(replies)
            harness.received.append(response)
            return response
        harness.send.side_effect = send

        @contextmanager
        def agent_stack(_binary, workspace):
            workspace.mkdir()
            (workspace / ".agentfw").mkdir()
            (workspace / ".agentfw/config.yaml").write_text('{"enforce":true,"native":{}}')
            yield SimpleNamespace(
                workspace=workspace, classifications=workspace / "collector.log",
                collector=["mock-local-collector"], env={}, ledger=workspace / "executed.jsonl",
                responses=workspace / "executed.responses", receiver=SimpleNamespace(bodies=[]))

        demo = SimpleNamespace(agent_stack=agent_stack, Harness=mock.Mock(return_value=harness),
                               stop=mock.Mock())
        original_write = Path.write_bytes

        def write_bytes(path, data):
            if path.name == "executor-ledger.jsonl":
                raise OSError("simulated evidence storage failure")
            return original_write(path, data)

        def successful_grade(_case, row, *_witnesses):
            return dict(row, status="boundary_expectation_observed", grading_errors=[])

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(probe, "grade_case", side_effect=successful_grade) as grade, \
                    mock.patch.object(Path, "write_bytes", new=write_bytes):
                result = probe.run_case(demo, Path("mock-local-agentfw"), Path(directory), case)
            grade.assert_called_once()
            self.assertEqual(result["status"], "inconclusive")
            self.assertEqual(result["observed_status"], "boundary_expectation_observed")
            self.assertEqual(result["error_type"], "OSError")
            self.assertIn("evidence storage failure", result["error"])
            retained = json.loads((Path(directory) / case["name"] / "result.json").read_text())
            self.assertEqual(retained["status"], "inconclusive")
            self.assertFalse((Path(directory) / case["name"] / "executor-ledger.jsonl").exists())

    def test_useful_call_rejects_changed_bytes_or_multiple_dispatches(self):
        for mutation in ("call_bytes", "result_bytes", "duplicate_call"):
            with self.subTest(mutation=mutation):
                inputs = self.inputs("benign_read")
                if mutation == "call_bytes":
                    inputs[2] = b" " + inputs[2]
                elif mutation == "result_bytes":
                    inputs[3] = b" " + inputs[3]
                else:
                    inputs[2] *= 2
                self.assert_rejected(inputs)


if __name__ == "__main__":
    unittest.main()
