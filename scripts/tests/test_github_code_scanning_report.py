# SPDX-License-Identifier: Apache-2.0
"""Offline report regressions: preserve evidence, unknowns and existing files."""
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


REPORT = load("github-code-scanning-report")
AUDIT = load("github-code-scanning-audit")


def saved_audit():
    """Synthetic schema-v1 evidence, not an observation of the real repository."""
    data = {
        "main": {"sha": "current", "protected": True},
        "default_setup": {"state": "configured", "languages": ["rust"], "query_suite": "default"},
        "repository_languages": ["Rust", "Python"],
        "workflows": [{"name": "CI", "path": ".github/workflows/ci.yml", "state": "active"}],
        "rulesets": [{"id": 12, "name": "scanning", "enforcement": "active", "source_type": "Repository"}],
        "effective_main_rules": [{"type": "code_scanning", "parameters": {"code_scanning_tools": [
            {"tool": "CodeQL", "alerts_threshold": "errors", "security_alerts_threshold": "high_or_higher"}]},
            "ruleset_id": 12}],
        "branch_protection": {"required_pull_request_reviews": {"required_approving_review_count": 1}},
        "checks": AUDIT.summarize_checks([
            {"name": "Analyze (rust)", "head_sha": "current", "status": "completed", "conclusion": "success",
             "app": {"slug": "github-actions"}},
            {"name": "CodeQL", "head_sha": "current", "status": "completed", "conclusion": "success",
             "app": {"slug": "github-advanced-security"}}], "current"),
        "analyses": AUDIT.summarize_analyses([
            {"id": 42, "tool": {"name": "CodeQL"}, "commit_sha": "current", "ref": "refs/heads/main",
             "category": "/language:rust", "created_at": "2026-10-09T12:00:00Z"}], "current"),
        "open_alert_inventory": {"open_count": 0, "by_severity": {}},
        "target_recheck": {"sha": "current"},
    }
    return {"schema_version": 1, "repository": "example/repo", "status": "collected",
            "observed_at": "2026-10-09T12:00:00Z", "read_only": True,
            "target_sha": "current", "target_ref": "refs/heads/main", "target_changed_during_read": False,
            "qualifying_rule_observed": True, "merge_protection_verified": False,
            "live_gate_cases": {"clean": "not_run", "missing_or_pending": "not_run", "qualifying_finding": "not_run"},
            "observations": {name: {"status": "read", "data": value} for name, value in data.items()},
            "limitations": ["Synthetic evidence only."]}


class ReportTests(unittest.TestCase):
    def test_complete_collection_preserves_identity_and_does_not_verify_protection(self):
        report = saved_audit()
        original = json.dumps(report, sort_keys=True)
        markdown = REPORT.render_report(report)
        for expected in ("example/repo", "2026-10-09T12:00:00Z", "| status | collected |",
                         "| target\\_sha | current |", "| merge\\_protection\\_verified | false |",
                         "Creating this report does not verify merge protection.", "high\\_or\\_higher",
                         "required\\_approving\\_review\\_count", "Synthetic evidence only."):
            self.assertIn(expected, markdown)
        self.assertEqual(json.dumps(report, sort_keys=True), original)

    def test_analysis_upload_and_results_check_keep_separate_kinds_and_apps(self):
        markdown = REPORT.render_report(saved_audit())
        self.assertIn("| Analyze (rust) | analysis\\_job | github-actions |", markdown)
        self.assertIn("| CodeQL | results\\_check\\_candidate | github-advanced-security |", markdown)

    def test_pending_neutral_failure_and_null_are_not_success(self):
        for status, conclusion in (("in_progress", None), ("completed", "neutral"), ("completed", "failure")):
            with self.subTest(conclusion=conclusion):
                report = saved_audit()
                row = report["observations"]["checks"]["data"][1]
                row.update(status=status, conclusion=conclusion)
                markdown = REPORT.render_report(report)
                line = next(line for line in markdown.splitlines() if line.startswith("| CodeQL |"))
                self.assertIn(REPORT.cell(status), line)
                self.assertIn(REPORT.cell(conclusion), line)
                self.assertNotIn("success", line)

    def test_outdated_and_merge_ref_analyses_are_not_promoted(self):
        report = saved_audit()
        report["observations"]["analyses"]["data"] = AUDIT.summarize_analyses([
            {"id": 99, "commit_sha": "old-sha", "ref": "refs/heads/main", "error": "private diagnostic"},
            {"id": 100, "commit_sha": "merge-sha", "ref": "refs/pull/3/merge"}], "current")
        report["observations"]["checks"]["data"][0].update(head_sha="old-sha", matches_target=False)
        markdown = REPORT.render_report(report)
        self.assertIn("| old-sha | refs/heads/main | false |", markdown)
        self.assertIn("| merge-sha | refs/pull/3/merge | false |", markdown)
        self.assertIn("| old-sha | false | completed | success |", markdown)
        self.assertNotIn("private diagnostic", markdown)

    def test_moving_head_remains_incomplete_and_warns_against_revision_claims(self):
        report = saved_audit()
        report.update(status="incomplete", target_changed_during_read=True)
        report["observations"]["target_recheck"]["data"]["sha"] = "new-sha"
        markdown = REPORT.render_report(report)
        self.assertIn("| status | incomplete |", markdown)
        self.assertIn("could not establish a stable head", markdown)
        self.assertIn("| sha | new-sha |", markdown)

    def test_actual_collector_permission_failures_render_without_credentials(self):
        with patch.object(AUDIT, "get", side_effect=AUDIT.GitHubReadError("http_403")):
            report = AUDIT.audit("example/repo", 3)
        markdown = REPORT.render_report(report)
        self.assertIn("| status | incomplete |", markdown)
        self.assertIn("Unavailable: http\\_403.", markdown)
        self.assertIn("| target\\_sha | not recorded |", markdown)
        self.assertIn("## Pull request", markdown)
        self.assertIn("It does not establish that protection or alerts are absent.", markdown)

    def test_404_and_missing_observations_remain_visible(self):
        report = saved_audit()
        report["observations"]["branch_protection"] = {"status": "unavailable", "reason": "http_404"}
        del report["observations"]["checks"]
        del report["qualifying_rule_observed"]
        markdown = REPORT.render_report(report)
        self.assertIn("| checks | not recorded | not recorded |", markdown)
        self.assertIn("Unavailable: http\\_404.", markdown)
        self.assertIn("| qualifying\\_rule\\_observed | not recorded |", markdown)

    def test_empty_rules_do_not_become_protection_proof(self):
        report = saved_audit()
        report["observations"]["effective_main_rules"]["data"] = []
        report["qualifying_rule_observed"] = False
        markdown = REPORT.render_report(report)
        self.assertIn("The saved read returned no records. This is not proof of protection.", markdown)

    def test_all_gate_statuses_are_preserved_including_missing_values(self):
        report = saved_audit()
        for statuses in ({"clean": "not_run", "missing_or_pending": "blocked", "qualifying_finding": "fail"},
                         {"clean": "pass", "missing_or_pending": None}):
            report["live_gate_cases"] = statuses
            markdown = REPORT.render_report(report)
            for name in REPORT.GATE_CASES:
                self.assertIn("| " + REPORT.cell(name) + " | " + REPORT.cell(statuses.get(name)) + " |", markdown)
            self.assertIn("| merge\\_protection\\_verified | false |", markdown)

    def test_markdown_html_pipes_and_newlines_remain_literal_cell_content(self):
        report = saved_audit()
        report["repository"] = "example/|`**[link](https://example.invalid)<img src=x>\r\nnext & line"
        report["limitations"] = ["[fake](https://example.invalid)\n# Heading"]
        markdown = REPORT.render_report(report)
        self.assertIn("example/\\|\\`\\*\\*\\[link\\](https://example.invalid)&lt;img src=x&gt;<br>next &amp; line", markdown)
        self.assertNotIn("<img", markdown)
        self.assertNotIn("\n# Heading", markdown)

    def test_unsupported_schema_and_malformed_shapes_have_clear_errors(self):
        for value in (None, [], True, {"schema_version": 2}, {"schema_version": True}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                REPORT.render_report(value)
        for field, value in (("observations", []), ("repository", None), ("live_gate_cases", []),
                             ("target_changed_during_read", "false"), ("limitations", None)):
            report = saved_audit()
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                REPORT.render_report(report)
        for observation in ({"status": []}, {"status": "read", "data": [None]},
                            {"status": "unavailable", "reason": None}):
            report = saved_audit()
            report["observations"]["checks"] = observation
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                REPORT.render_report(report)


class ReportCliTests(unittest.TestCase):
    def run_cli(self, source, output):
        # An absolute Python path and empty PATH exercise conversion without gh.
        return subprocess.run([sys.executable, str(SCRIPTS / "github-code-scanning-report.py"),
                               "--input", str(source), "--output", str(output)],
                              capture_output=True, text=True, env={**os.environ, "PATH": ""}, timeout=10)

    def test_offline_cli_renders_incomplete_evidence_and_leaves_source_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "audit.json"
            output = Path(temporary) / "reports" / "audit.md"
            report = saved_audit()
            report["status"] = "incomplete"
            source.write_text(json.dumps(report), encoding="utf-8")
            original = source.read_bytes()
            result = self.run_cli(source, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("does not verify merge protection", result.stdout)
            self.assertIn("| status | incomplete |", output.read_text(encoding="utf-8"))
            self.assertEqual(source.read_bytes(), original)

    def test_existing_output_and_input_as_output_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "audit.json"
            output = Path(temporary) / "audit.md"
            source.write_text(json.dumps(saved_audit()), encoding="utf-8")
            output.write_text("preserve existing evidence", encoding="utf-8")
            for destination in (output, source):
                before = destination.read_bytes()
                result = self.run_cli(source, destination)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Output already exists", result.stderr)
                self.assertEqual(destination.read_bytes(), before)

    def test_invalid_json_or_schema_does_not_create_output_or_print_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "audit.json"
            output = Path(temporary) / "new" / "audit.md"
            for payload in ('{"private":', '{"schema_version": 9}', '[]', '{"schema_version": NaN}'):
                source.write_text(payload, encoding="utf-8")
                result = self.run_cli(source, output)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(output.parent.exists())
                self.assertNotIn("Traceback", result.stderr)
                self.assertNotIn("private", result.stderr)

    def test_unreadable_or_non_utf8_input_has_a_concise_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "audit.json"
            output = Path(temporary) / "audit.md"
            for invalid_encoding in (False, True):
                if invalid_encoding:
                    source.write_bytes(b"\xff")
                result = self.run_cli(source, output)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Cannot read the input", result.stderr)
                self.assertFalse(output.exists())

    def test_unwritable_output_reports_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "audit.json"
            source.write_text(json.dumps(saved_audit()), encoding="utf-8")
            result = self.run_cli(source, source / "audit.md")
            self.assertEqual(result.returncode, 2)
            self.assertIn("Cannot write", result.stderr)


if __name__ == "__main__":
    unittest.main()
