# SPDX-License-Identifier: Apache-2.0
"""Truthful SOU-17 evidence and source gates; no Cargo or service is launched."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "verify_sou17", Path(__file__).resolve().parents[1] / "verify-sou17.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
COMMIT = "a" * 40


class EvidenceParsing(unittest.TestCase):
    def test_finite_nested_evidence_survives_libtest_prefix(self):
        records, diagnostics = VERIFY.evidence_lines(
            'test original_name ... SOU17_EVIDENCE {"observed":{"times":[0,1.5,1e3]},"executed":false}\n')
        self.assertEqual(records, [{"observed": {"times": [0, 1.5, 1000.0]}, "executed": False}])
        self.assertEqual(diagnostics, [])
        json.dumps(records, allow_nan=False)

    def test_overflowing_numbers_are_rejected_at_every_depth(self):
        for payload in ['{"latency":1e999}', '{"observed":{"times":[-1e999]}}',
                        '{"observed":[{"latency":1e999}]}']:
            with self.subTest(payload=payload):
                records, diagnostics = VERIFY.evidence_lines("SOU17_EVIDENCE " + payload)
                self.assertEqual(records, [])
                self.assertEqual(diagnostics, [{"line": 1, "error": "non-finite JSON number"}])

    def test_literal_nonfinite_numbers_are_rejected(self):
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token):
                records, diagnostics = VERIFY.evidence_lines('SOU17_EVIDENCE {"nested":[' + token + "]}")
                self.assertEqual(records, [])
                self.assertEqual(diagnostics, [{"line": 1, "error": "non-finite JSON"}])

    def test_bad_evidence_keeps_line_diagnostics_without_erasing_valid_records(self):
        records, diagnostics = VERIFY.evidence_lines(
            'ordinary output\nSOU17_EVIDENCE {bad}\nSOU17_EVIDENCE []\n'
            'SOU17_EVIDENCE {"executed":false}\n')
        self.assertEqual(records, [{"executed": False}])
        self.assertEqual([entry["line"] for entry in diagnostics], [2, 3])
        self.assertTrue(all(entry["error"] for entry in diagnostics))


class VerificationGates(unittest.TestCase):
    def fixture_run(self, *, expected=COMMIT, tracked="", untracked="", allow_dirty=False,
                    evidence='{"executed":false}'):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root, out = base / "source", base / "evidence"
            root.mkdir()
            (root / "Cargo.toml").write_text("# synthetic source\n")
            if untracked:
                (root / untracked).write_text("# untracked source\n")
            binary, agentfw = base / "fixture-test", base / "agentfw"
            binary.write_bytes(b"synthetic test artifact")
            agentfw.write_bytes(b"synthetic agent artifact")
            calls = []
            reject = expected != COMMIT or (bool(tracked or untracked) and not allow_dirty)

            def fake_command(arguments, log, timeout, **kwargs):
                calls.append((arguments, kwargs.get("env")))
                output = ""
                if arguments[:2] == ["git", "rev-parse"]:
                    output = COMMIT + "\n"
                elif arguments[:2] == ["git", "status"]:
                    output = tracked
                elif arguments[:2] == ["git", "diff"]:
                    output = "synthetic tracked patch\n" if tracked else ""
                elif arguments[:2] == ["git", "ls-files"]:
                    output = (untracked + "\0" if untracked else "") if "--others" in arguments else "Cargo.toml\0"
                elif reject:
                    self.fail("source refusal must occur before toolchain, Cargo, discovery or test execution")
                elif arguments in (["rustc", "--version"], ["cargo", "--version"]):
                    output = arguments[0] + " fixture-version\n"
                elif arguments[0] == "/fixture/python3":
                    output = json.dumps({"executable": "/fixture/python-real", "version": "3.12.1",
                                         "implementation": "CPython"})
                elif arguments[:2] == ["cargo", "test"]:
                    output = "\n".join(json.dumps(item) for item in [
                        {"reason": "compiler-artifact", "executable": str(binary),
                         "target": {"name": "resilience_tests", "kind": ["test"]}, "profile": {"test": True}},
                        {"reason": "compiler-artifact", "executable": str(agentfw),
                         "target": {"name": "agentfw", "kind": ["bin"]}, "profile": {"test": False}}])
                elif arguments[0] == str(binary) and "--list" in arguments:
                    output = "original_case: test\n"
                elif arguments[0] == str(binary) and "--exact" in arguments:
                    self.assertEqual(timeout, 60)
                    output = ('test original_case ... SOU17_EVIDENCE ' + evidence + '\nok\n'
                              'test result: ok. 1 passed; 0 failed; 0 ignored;\n')
                else:
                    self.fail(f"unexpected command: {arguments}")
                log.write_text(output)
                return {"command": arguments, "log": log.name, "exit_code": 0,
                        "timed_out": False, "elapsed_ms": 1}

            environment = {"PATH": "/fixture/bin", "LANG": "C", "OPENAI_API_KEY": "must-not-record",
                           "CARGO_ENCODED_RUSTFLAGS": "--cfg\x1ffixture", "RUSTFLAGS": "--cfg fixture"}
            with patch.object(VERIFY, "ROOT", root), patch.object(VERIFY.sys, "platform", "linux"), \
                    patch.object(VERIFY, "SUITES", (("soup-wall-adapter", "resilience_tests"),)), \
                    patch.object(VERIFY.HELPERS, "command", side_effect=fake_command), \
                    patch.object(VERIFY.shutil, "which", return_value="/fixture/python3"), \
                    patch.dict(os.environ, environment, clear=True), redirect_stdout(io.StringIO()):
                code = VERIFY.run(SimpleNamespace(out=str(out), expected_commit=expected,
                                                  allow_dirty=allow_dirty, offline=True))
            result_path = next(out.glob("*/results.json"))
            result = json.loads(result_path.read_text())
            self.assertTrue(result_path.with_name("report.md").is_file())
            self.assertEqual(result["acceptance"], "pending-sou15-integration")
            json.dumps(result, allow_nan=False)
            return code, result, calls

    def test_commit_mismatch_refuses_before_cargo_even_with_dirty_override(self):
        code, result, calls = self.fixture_run(expected="b" * 40, allow_dirty=True)
        self.assertEqual(code, 1)
        self.assertIn("differs from --expected-commit", result["error"])
        self.assertEqual(result["cases"], [])
        self.assertTrue(all(command[0] == "git" for command, _ in calls))

    def test_tracked_and_untracked_dirty_source_refuse_before_cargo(self):
        for changes in ({"tracked": " M Cargo.toml\n"}, {"untracked": "new.rs"}):
            with self.subTest(changes=changes):
                code, result, calls = self.fixture_run(**changes)
                self.assertEqual(code, 1)
                self.assertIn("Worktree is dirty", result["error"])
                self.assertTrue(result["source"]["dirty"])
                self.assertTrue(all(command[0] == "git" for command, _ in calls))

    def test_overflowing_evidence_makes_successful_rust_case_an_evidence_error(self):
        code, result, _ = self.fixture_run(evidence='{"nested":[{"latency":1e999}]}')
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "error")
        case = result["cases"][0]
        self.assertEqual(case["test_status"], "pass")
        self.assertEqual(case["status"], "error")
        self.assertEqual(case["evidence"], [])
        self.assertEqual(case["evidence_diagnostics"][0]["error"], "non-finite JSON number")

    def test_runtime_and_build_configuration_are_recorded_without_provider_credentials(self):
        code, result, calls = self.fixture_run()
        self.assertEqual(code, 0)
        environment = result["environment"]
        runtime = environment["runtime_environment"]
        self.assertEqual(runtime, {"PATH": "/fixture/bin", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(environment["fixture_python"]["version"], "3.12.1")
        self.assertEqual(environment["fixture_python"]["resolved_command"], "/fixture/python3")
        self.assertEqual(environment["build_settings"]["CARGO_ENCODED_RUSTFLAGS"], "--cfg\x1ffixture")
        self.assertEqual(result["configuration"]["cargo_features"],
                         {"default_features": True, "all_features": False, "features": []})
        self.assertNotIn("must-not-record", json.dumps(result))
        for command, child_env in calls:
            if "--exact" in command or command[0] == "/fixture/python3":
                self.assertEqual(child_env, runtime)


if __name__ == "__main__":
    unittest.main()
