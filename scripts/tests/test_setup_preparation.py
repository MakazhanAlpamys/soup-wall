# SPDX-License-Identifier: Apache-2.0
"""Regressions for truthful setup evidence and read-only scanning preparation."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SETUP = load("clean-setup-acceptance")
AUDIT = load("github-code-scanning-audit")


class SetupEvidenceTests(unittest.TestCase):
    def test_default_does_not_start_a_daemon(self):
        result = subprocess.run([sys.executable, str(SCRIPTS / "clean-setup-acceptance.py")],
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)["processes_started"], 0)

    def test_private_profile_drops_tokens_proxies_and_runtime_redirects(self):
        with patch.dict(os.environ, {"AGENTFW_TOKEN": "private", "HTTP_PROXY": "private",
                                     "ANTHROPIC_API_KEY": "private", "RUST_LOG": "trace", "PYTHONPATH": "private"}):
            env = SETUP.private_environment(Path("owned-profile"))
        self.assertEqual(env["HOME"], "owned-profile")
        self.assertEqual(env["USERPROFILE"], "owned-profile")
        for name in ("AGENTFW_TOKEN", "HTTP_PROXY", "ANTHROPIC_API_KEY", "RUST_LOG", "PYTHONPATH"):
            self.assertNotIn(name, env)

    def test_wrong_status_fails_even_if_cli_succeeds(self):
        result = subprocess.CompletedProcess([], 0, b"OK: enforcing", b"")
        with patch.object(SETUP, "run_cli", return_value=result):
            with self.assertRaisesRegex(SETUP.CheckFailed, "unexpected_preflight_exit"):
                SETUP.check_probe(Path("agentfw"), Path("profile"), {}, 2)

    def test_exit_code_without_status_text_is_not_accepted(self):
        result = subprocess.CompletedProcess([], 4, b"", b"")
        with patch.object(SETUP, "run_cli", return_value=result):
            with self.assertRaisesRegex(SETUP.CheckFailed, "status_text_missing"):
                SETUP.check_probe(Path("agentfw"), Path("profile"), {}, 4)

    def test_missing_binary_records_failure_and_removes_only_owned_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            sentinel = parent / "unrelated-settings"
            sentinel.write_text("preserve")
            with patch.object(SETUP.tempfile, "gettempdir", return_value=temporary):
                report = SETUP.acceptance(parent / "missing-private-path", 5)
            self.assertEqual(report["status"], "fail")
            self.assertFalse(report["protection_verified"])
            self.assertEqual(report["integrated_candidate_acceptance"], "not_run")
            self.assertEqual(list(parent.iterdir()), [sentinel])
            self.assertNotIn("missing-private-path", json.dumps(report))

    def test_existing_evidence_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence.json"
            output.write_text("preserve")
            result = subprocess.run([sys.executable, str(SCRIPTS / "clean-setup-acceptance.py"),
                                     "--run", "--agentfw", "missing", "--output", str(output)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), "preserve")

    def test_nearest_rank_percentiles_keep_tail_sample(self):
        self.assertEqual(SETUP.percentile(list(range(1, 21)), 50), 10)
        self.assertEqual(SETUP.percentile(list(range(1, 21)), 95), 19)
        with self.assertRaises(SETUP.CheckFailed):
            SETUP.percentile([], 95)


class ScanningEvidenceTests(unittest.TestCase):
    def test_http_errors_do_not_look_like_empty_success_or_leak_output(self):
        value = subprocess.CompletedProcess([], 1, "private payload", "private token (HTTP 403)")
        with patch.object(AUDIT.subprocess, "run", return_value=value) as run:
            with self.assertRaises(AUDIT.GitHubReadError) as error:
                AUDIT.get("repos/example/repo/rulesets")
        self.assertEqual(str(error.exception), "http_403")
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--method") + 1], "GET")

    def test_analysis_job_success_is_separate_from_results_check(self):
        rows = AUDIT.summarize_checks([
            {"name": "Analyze (rust)", "head_sha": "old", "status": "completed", "conclusion": "success"},
            {"name": "CodeQL", "head_sha": "current", "status": "in_progress", "conclusion": None}], "current")
        self.assertEqual(rows[0]["kind"], "analysis_job")
        self.assertFalse(rows[0]["matches_target"])
        self.assertEqual(rows[1]["kind"], "results_check_candidate")
        self.assertIsNone(rows[1]["conclusion"])

    def test_old_analysis_cannot_count_as_current_and_errors_are_retained(self):
        rows = AUDIT.summarize_analyses([{"commit_sha": "old", "error": "private diagnostic"}], "new")
        self.assertFalse(rows[0]["matches_target"])
        self.assertTrue(rows[0]["has_error"])
        self.assertNotIn("private diagnostic", json.dumps(rows))

    def test_threshold_requires_both_high_security_and_error_alerts(self):
        rule = {"type": "code_scanning", "parameters": {"code_scanning_tools": [
            {"tool": "CodeQL", "alerts_threshold": "errors", "security_alerts_threshold": "high_or_higher"}]}}
        self.assertTrue(AUDIT.meets_threshold(rule))
        rule["parameters"]["code_scanning_tools"][0]["security_alerts_threshold"] = "critical"
        self.assertFalse(AUDIT.meets_threshold(rule))

    def test_pagination_does_not_hide_later_alerts(self):
        with patch.object(AUDIT, "get", side_effect=[[{}] * 100, [{"id": 101}]]):
            self.assertEqual(len(AUDIT.pages("repos/example/repo/code-scanning/alerts")), 101)

    def test_missing_permissions_leave_verification_incomplete(self):
        with patch.object(AUDIT, "get", side_effect=AUDIT.GitHubReadError("http_403")):
            report = AUDIT.audit("example/repo")
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["merge_protection_verified"])
        self.assertIsNone(report["qualifying_rule_observed"])

    def test_moving_head_is_reported_and_never_verified(self):
        reads = iter([{"commit": {"sha": "before"}}, {}, {}, {}, {"commit": {"sha": "after"}}])
        with patch.object(AUDIT, "get", side_effect=lambda _: next(reads)), patch.object(AUDIT, "pages", return_value=[]):
            report = AUDIT.audit("example/repo")
        self.assertTrue(report["target_changed_during_read"])
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["merge_protection_verified"])

    def test_ruleset_example_is_disabled_and_does_not_replace_review_rules(self):
        example = json.loads((SCRIPTS.parent / "deploy/github-code-scanning-ruleset.example.json").read_text())
        self.assertEqual(example["enforcement"], "disabled")
        self.assertEqual(example["conditions"]["ref_name"]["include"], ["refs/heads/main"])
        self.assertEqual([row["type"] for row in example["rules"]], ["code_scanning"])
        self.assertTrue(AUDIT.meets_threshold(example["rules"][0]))


if __name__ == "__main__":
    unittest.main()
