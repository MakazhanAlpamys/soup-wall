# SPDX-License-Identifier: Apache-2.0
"""Independent capacity-probe grading checks; no runtime, Cargo or network."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "sou17_capacity_probe", Path(__file__).resolve().parents[1] / "verify-sou17-refusal-capacity.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def successful_observation():
    asks, classifications = [], []
    for index in range(PROBE.ASK_COUNT):
        call_id = f"sou17-ask-{index+1:02d}"
        asks.append({"host_call_id":call_id, "executor_count":0, "correlated_ask_refusal":True,
                     "response":{"jsonrpc":"2.0", "id":call_id,
                                 "result":{"isError":True,"content":[{"type":"text",
                                     "text":"Soup Wall withheld MCP invocation (policy_unconfirmed_ask)"}]}}})
        classifications.append({"host_call_id":call_id, "tool":"read_document",
                                "source":"rule-baseline/python", "authoritative_verdict":"ask",
                                "classifier_sha256":"a"*64,
                                "classification":{"actions":["read"],"unknown":False,
                                                  "confidence":0.95,"uncertainty":0.9}})
    classifications.append({"host_call_id":PROBE.BENIGN_ID,"tool":"read_document",
                            "source":"rule-baseline/python","authoritative_verdict":"allow",
                            "classifier_sha256":"a"*64,
                            "classification":{"actions":["read"],"unknown":False,
                                              "confidence":0.95,"uncertainty":0.05}})
    return {"ask_calls":asks,"classifications":classifications,"classifier_invocations":65,
            "expected_classifier_sha256":"a"*64,"ledger_valid":True,
            "native_decisions":[{"event":"native_call","verdict":"allow","released":True}
                                for _ in range(PROBE.ASK_COUNT)],
            "ask_executor_count":0,"total_executor_count":1,"benign_executor_delta":1,
            "benign_client_bytes":122,"receiver_count":0,"gateway_exit_code":0,
            "benign_transport_outcome":"response","benign_original_server_result_count":1,
            "benign_original_call_bytes_preserved":True,"benign_original_result_released":True,
            "benign_response":{"jsonrpc":"2.0","id":PROBE.BENIGN_ID,
                               "result":{"content":[{"type":"text","text":"Inventory: 7 red widgets."}]}}}


class CapacityGrade(unittest.TestCase):
    def test_exact_known_safe_asks_and_useful_original_benign_result_pass(self):
        self.assertEqual(PROBE.grade(successful_observation(), True), "pass")

    def test_missing_or_partial_fixture_cannot_pass(self):
        for missing in ({}, {"ask_calls":[],"classifications":[]}):
            with self.subTest(missing=missing):
                self.assertEqual(PROBE.grade(missing, True), "inconclusive")
        for key in ("ask_calls","classifications"):
            data = successful_observation()
            data[key].pop()
            self.assertEqual(PROBE.grade(data, True), "inconclusive")

    def test_empty_ask_rows_cannot_vacuously_pass_with_complete_classifications(self):
        data = successful_observation()
        data["ask_calls"] = []
        self.assertEqual(PROBE.grade(data, True), "inconclusive")

    def test_missing_authoritative_verdict_is_inconclusive(self):
        for index in (0,64):
            data = successful_observation()
            del data["classifications"][index]["authoritative_verdict"]
            self.assertEqual(PROBE.grade(data, True), "inconclusive")

    def test_reordered_classifier_ids_cannot_certify_call_order(self):
        data = successful_observation()
        data["classifications"][0],data["classifications"][1] = data["classifications"][1],data["classifications"][0]
        self.assertEqual(PROBE.grade(data, True), "inconclusive")

    def test_duplicate_or_reordered_ask_ids_cannot_pass(self):
        data = successful_observation()
        data["ask_calls"][1]["host_call_id"] = data["ask_calls"][0]["host_call_id"]
        self.assertEqual(PROBE.grade(data, True), "inconclusive")
        data = successful_observation()
        data["ask_calls"].reverse()
        self.assertEqual(PROBE.grade(data, True), "inconclusive")

    def test_false_correlated_flag_and_wrong_original_response_id_do_not_pass(self):
        data = successful_observation()
        data["ask_calls"][0]["correlated_ask_refusal"] = False
        self.assertEqual(PROBE.grade(data, True), "inconclusive")
        data = successful_observation()
        data["ask_calls"][0]["response"]["id"] = "different-call"
        self.assertEqual(PROBE.grade(data, True), "inconclusive")

    def test_invalid_classifier_scores_or_wrong_final_prediction_are_inconclusive(self):
        for score in (2.0,float("nan"),float("inf"),10**1000):
            data = successful_observation()
            data["classifications"][0]["classification"]["confidence"] = score
            self.assertEqual(PROBE.grade(data, True), "inconclusive")
        data = successful_observation()
        data["classifications"][-1]["classification"]["uncertainty"] = 0.9
        self.assertEqual(PROBE.grade(data, True), "inconclusive")

    def test_source_or_binary_instability_prevents_candidate_claim(self):
        self.assertEqual(PROBE.grade(successful_observation(), False), "inconclusive")

    def test_classifier_hash_or_source_mismatch_is_inconclusive(self):
        data = successful_observation()
        data["classifications"][0]["classifier_sha256"] = "b"*64
        self.assertEqual(PROBE.grade(data, True), "inconclusive")
        self.assertEqual(PROBE.grade(successful_observation(), True, "b"*64), "inconclusive")
        data = successful_observation()
        data["classifications"][-1]["source"] = "test-double/read-v1"
        self.assertEqual(PROBE.grade(data, True), "inconclusive")

    def test_known_safe_64_asks_then_eof_on_benign_allow_fails(self):
        data = successful_observation()
        data.update(total_executor_count=0,benign_executor_delta=0,benign_client_bytes=0,
                    benign_original_call_bytes_preserved=False,benign_original_result_released=False,
                    benign_response=None,gateway_exit_code=1,benign_transport_outcome="eof",
                    benign_original_server_result_count=0)
        self.assertEqual(PROBE.grade(data, True), "fail")

    def test_short_native_prefix_or_arbitrary_timeout_is_inconclusive(self):
        data = successful_observation()
        data.update(total_executor_count=0,benign_executor_delta=0,benign_client_bytes=0,
                    benign_original_call_bytes_preserved=False,benign_original_result_released=False,
                    benign_response=None,gateway_exit_code=1,benign_transport_outcome="eof",
                    benign_original_server_result_count=0)
        for mutation in ({"native_decisions":data["native_decisions"][:-1]},
                         {"benign_transport_outcome":"timeout"},
                         {"benign_original_server_result_count":1}):
            changed = dict(data,**mutation)
            self.assertEqual(PROBE.grade(changed, True), "inconclusive")

    def test_forbidden_ask_effect_is_failure_not_inconclusive(self):
        data = successful_observation()
        data["ask_calls"][20]["executor_count"] = 1
        data["ask_executor_count"] = 1
        self.assertEqual(PROBE.grade(data, True), "fail")

    def test_confirmed_ask_effect_remains_failure_with_partial_later_logs(self):
        data = successful_observation()
        data["ask_calls"] = data["ask_calls"][:1]
        data["classifications"] = data["classifications"][:1]
        data["ask_calls"][0]["executor_count"] = 1
        self.assertEqual(PROBE.grade(data, True), "fail")
        data["classifications"][0]["authoritative_verdict"] = "allow"
        self.assertEqual(PROBE.grade(data, True), "inconclusive")

    def test_complete_aggregate_ask_effect_witness_fails(self):
        data = successful_observation()
        data["ask_executor_count"] = 1
        self.assertEqual(PROBE.grade(data, True), "fail")

    def test_duplicated_benign_effect_or_lost_original_result_fails(self):
        data = successful_observation()
        data.update(total_executor_count=2,benign_executor_delta=2)
        self.assertEqual(PROBE.grade(data, True), "fail")
        data = successful_observation()
        data["benign_original_result_released"] = False
        self.assertEqual(PROBE.grade(data, True), "fail")
        data = successful_observation()
        data["benign_response"]["id"] = "different-result"
        self.assertEqual(PROBE.grade(data, True), "fail")

    def test_missing_result_measurement_or_exit_status_is_inconclusive(self):
        for key in ("benign_client_bytes","benign_original_call_bytes_preserved",
                    "benign_original_result_released","gateway_exit_code"):
            data = successful_observation()
            del data[key]
            self.assertEqual(PROBE.grade(data, True), "inconclusive")

    def test_nonempty_malformed_executor_ledger_is_not_a_zero_effect_witness(self):
        for raw in (b"not JSON\n",b"{}\n",b"null\n"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    PROBE.ledger_records(raw)
        self.assertEqual(PROBE.ledger_records(b""), [])
        self.assertEqual(len(PROBE.ledger_records(b'{"method":"tools/call","id":1}\n')),1)
        data = successful_observation()
        data["ledger_valid"] = False
        self.assertEqual(PROBE.grade(data, True), "inconclusive")


if __name__ == "__main__":
    unittest.main()
