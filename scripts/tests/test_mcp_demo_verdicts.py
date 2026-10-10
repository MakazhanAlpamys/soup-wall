# SPDX-License-Identifier: Apache-2.0
"""Recognize composed refusals without weakening unknown-error grading."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "mcp_demo_verdicts", Path(__file__).resolve().parents[1] / "mcp-admission-demo.py")
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)


class DemoVerdicts(unittest.TestCase):
    def test_composed_policy_refusals_are_distinct(self):
        for reason, verdict in [("policy_denied", "deny"), ("policy_unconfirmed_ask", "ask")]:
            with self.subTest(reason=reason):
                self.assertEqual(DEMO.outcome_of(
                    f"Soup Wall withheld MCP invocation ({reason})", True), verdict)

    def test_unsupported_executor_does_not_count_as_policy_deny(self):
        self.assertEqual(DEMO.outcome_of(
            "Soup Wall withheld MCP invocation (resource_executor_unsupported)", True),
            "refused:resource_executor_unsupported")
