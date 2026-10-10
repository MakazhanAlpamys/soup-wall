# SPDX-License-Identifier: Apache-2.0
"""SOU-19 review regressions against the shared owner-maintained classifier.

All commands are inert input strings. These checks do not execute a tool or
assert policy authorization. Owner tests already cover the original sudo case.
"""
import copy
import unittest

from rule_baseline import classify


class IncompleteInputRegressions(unittest.TestCase):
    def test_missing_or_malformed_name_is_legacy_technical_failure(self):
        # This asserts the diagnostic profile, not the runtime error channel.
        for event in [{}, {"raw_arguments": {}}, {"tool_name": None},
                      {"tool_name": 7}, {"tool_name": "   "}]:
            with self.subTest(event=event):
                out = classify(event)
                self.assertEqual(out["status"], "error")
                self.assertEqual(out["actions"], [])

    def test_command_tail_beyond_limit_preserves_unknown(self):
        out = classify({"tool_name": "shell_exec", "raw_arguments": {
            "command": "ls " + " " * 4100 + "; rm fixtures/sample.txt"}})
        self.assertTrue(out["truncated"])
        self.assertIn("read", out["actions"])
        self.assertIs(out["unknown"], True)

    def test_nested_step_beyond_depth_limit_preserves_unknown(self):
        nested = {"action": "delete_file", "path": "fixtures/sample.txt"}
        for _ in range(8):
            nested = {"step": nested}
        out = classify({"tool_name": "read_file", "raw_arguments": {
            "path": "fixtures/sample.txt", "steps": nested}})
        self.assertTrue(out["truncated"])
        self.assertIn("read", out["actions"])
        self.assertIs(out["unknown"], True)

    def test_child_truncation_propagates_to_workflow_result(self):
        out = classify({"tool_name": "workflow_batch", "raw_arguments": {"steps": [
            {"action": "read_file", "path": "fixtures/sample.txt"},
            {"action": "shell_exec", "command": "ls " + " " * 4100 + "; rm fixtures/sample.txt"},
        ]}})
        self.assertTrue(out["truncated"])
        self.assertIn("read", out["actions"])
        self.assertIs(out["unknown"], True)

    def test_input_is_not_mutated_by_classification(self):
        event = {"tool_name": "workflow_batch", "raw_arguments": {"steps": [
            {"action": "read_file", "path": "fixtures/sample.txt"},
            {"action": "sync_ledger", "id": "synthetic"}]}}
        original = copy.deepcopy(event)
        out = classify(event)
        self.assertEqual(event, original)
        self.assertIn("read", out["actions"])
        self.assertIs(out["unknown"], True)


if __name__ == "__main__":
    unittest.main()
