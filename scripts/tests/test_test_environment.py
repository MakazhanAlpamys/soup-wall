# SPDX-License-Identifier: Apache-2.0
"""Regression checks for truthful fixture reporting and bounded process cleanup."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "test_environment", Path(__file__).resolve().parents[1] / "test-environment.py")
ENVIRONMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENVIRONMENT)


class FixtureReporting(unittest.TestCase):
    @unittest.skipUnless(sys.platform in {"linux", "darwin"}, "Linux-image path layout")
    def test_bundle_retains_exact_classifier_source_and_missing_source_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve() / "source"
            bundle = Path(temporary).resolve() / "bundle"
            for relative in ENVIRONMENT.RUNTIME_FILES:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(("synthetic:" + relative).encode())
            with patch.object(ENVIRONMENT, "ROOT", source):
                ENVIRONMENT.copy_runtime_files(bundle)
                relative = "rule_baseline/rule_baseline.py"
                copied = bundle / source.relative_to("/") / relative
                self.assertEqual(copied.read_bytes(), (source / relative).read_bytes())
                (source / relative).unlink()
                with self.assertRaises(FileNotFoundError):
                    ENVIRONMENT.copy_runtime_files(bundle)

    def test_fixture_build_context_includes_classifier_runtime_source(self):
        rules = (ENVIRONMENT.ROOT / "deploy/Dockerfile.test.dockerignore").read_text().splitlines()
        self.assertIn("!rule_baseline/", rules)
        self.assertIn("!rule_baseline/rule_baseline.py", rules)
        self.assertNotIn("!rule_baseline/**", rules)

    def test_windows_python_exits_with_wsl_instructions_before_starting_commands(self):
        with patch.object(ENVIRONMENT.sys, "platform", "win32"), \
                patch.object(ENVIRONMENT.sys, "argv", ["test-environment.py"]), \
                patch.object(ENVIRONMENT, "command") as command, \
                redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(SystemExit) as raised:
                ENVIRONMENT.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("WSL2", errors.getvalue())
        self.assertIn("Linux Python", errors.getvalue())
        self.assertIn("WSL integration", errors.getvalue())
        command.assert_not_called()

    def test_wsl_metadata_records_kernel_and_distribution_without_host_secrets(self):
        for kernel, variables in [
                ("6.6.87.2-microsoft-standard-WSL2", {}),
                ("custom-kernel", {"WSL_DISTRO_NAME": "Ubuntu-24.04"}),
                ("custom-kernel", {"WSL_INTEROP": "/run/WSL/123_interop"})]:
            with self.subTest(kernel=kernel, variables=variables), \
                    patch.object(ENVIRONMENT.sys, "platform", "linux"), \
                    patch.object(ENVIRONMENT.platform, "release", return_value=kernel), \
                    patch.dict(ENVIRONMENT.os.environ, {**variables, "PROVIDER_TOKEN": "private"}, clear=True):
                metadata = ENVIRONMENT.host_environment()
            self.assertTrue(metadata["wsl_detected"])
            self.assertEqual(metadata["host_kernel"], kernel)
            self.assertEqual(metadata["wsl_distribution"], variables.get("WSL_DISTRO_NAME", "unknown"))
            self.assertNotIn("private", json.dumps(metadata))
            self.assertNotIn("/run/WSL", json.dumps(metadata))

    def test_native_hosts_are_not_reported_as_wsl(self):
        for host in ("linux", "darwin"):
            with self.subTest(host=host), patch.object(ENVIRONMENT.sys, "platform", host), \
                    patch.object(ENVIRONMENT.platform, "release", return_value="native-kernel"), \
                    patch.dict(ENVIRONMENT.os.environ, {}, clear=True):
                metadata = ENVIRONMENT.host_environment()
            self.assertFalse(metadata["wsl_detected"])
            self.assertNotIn("wsl_distribution", metadata)

    def classify(self, text, code=0, **extra):
        return ENVIRONMENT.classify_test({"exit_code": code, **extra}, text)

    def test_only_one_executed_success_is_a_pass(self):
        self.assertEqual(self.classify("test result: ok. 1 passed; 0 failed; 0 ignored;"), "pass")
        for output in ["", "test result: ok. 0 passed; 0 failed; 0 ignored;",
                       "test result: ok. 2 passed; 0 failed; 0 ignored;"]:
            with self.subTest(output=output):
                self.assertEqual(self.classify(output), "error")

    def test_assertion_failure_is_distinct_from_infrastructure_error(self):
        failed = "test result: FAILED. 0 passed; 1 failed; 0 ignored;"
        self.assertEqual(self.classify(failed, 101), "fail")
        self.assertEqual(self.classify(failed, 137), "error")
        self.assertEqual(self.classify(failed, 0), "error")
        self.assertEqual(self.classify("", -9, timed_out=True), "error")

    def test_ignored_and_runtime_skips_cannot_turn_green(self):
        self.assertEqual(self.classify("test result: ok. 0 passed; 0 failed; 1 ignored;"), "skip")
        self.assertEqual(self.classify("skipping sandbox positive-path test: unavailable\n"
                                       "test result: ok. 1 passed; 0 failed; 0 ignored;"), "skip")
        self.assertEqual(self.classify("test sandbox ... skipping sandbox test: unavailable\n"
                                       "test result: ok. 1 passed; 0 failed; 0 ignored;"), "skip")
        self.assertEqual(ENVIRONMENT.overall([{"status": "pass"}, {"status": "skip"}]), "incomplete")

    def test_ambiguous_output_is_not_a_pass(self):
        summary = "test result: ok. 1 passed; 0 failed; 0 ignored;\n"
        self.assertEqual(self.classify(summary * 2), "error")
        self.assertEqual(self.classify(summary, 1), "error")

    def test_empty_or_duplicated_discovery_is_an_error(self):
        self.assertEqual(ENVIRONMENT.discovery("original_name: test\n"), ["original_name"])
        for value in ["0 tests, 0 benchmarks", "x: test\nx: test\n"]:
            with self.assertRaises(ValueError):
                ENVIRONMENT.discovery(value)

    def test_empty_and_failed_runs_cannot_turn_green(self):
        self.assertEqual(ENVIRONMENT.overall([]), "error")
        self.assertEqual(ENVIRONMENT.overall([{"status": "fail"}]), "fail")
        self.assertEqual(ENVIRONMENT.overall([{"status": "error"}, {"status": "pass"}]), "error")
        self.assertEqual(ENVIRONMENT.overall([{"status": "not-run"}]), "error")

    @unittest.skipUnless(sys.platform in {"linux", "darwin"}, "POSIX process-group cleanup")
    def test_timeout_kills_descendants_and_keeps_partial_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "must-not-execute"
            ready = root / "ready"
            # The descendant would outlive its parent without process-group cleanup.
            child = "import pathlib,time; time.sleep(1); pathlib.Path(%r).touch()" % str(marker)
            parent = ("import subprocess,sys,time,pathlib; "
                      "subprocess.Popen([sys.executable,'-c',%r]); "
                      "pathlib.Path(%r).touch(); print('started',flush=True); time.sleep(30)") % (child, str(ready))
            result = ENVIRONMENT.command([sys.executable, "-c", parent], root / "case.log", 0.5)
            self.assertTrue(ready.exists(), "fixture must have started before its timeout")
            self.assertTrue(result["timed_out"])
            time.sleep(0.7)
            self.assertFalse(marker.exists())
            self.assertIn("started", (root / "case.log").read_text())

    def test_missing_executable_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = ENVIRONMENT.command([str(Path(temporary) / "absent")],
                                         Path(temporary) / "missing.log", 1)
            self.assertIsNone(result["exit_code"])
            self.assertIn("error", result)

    def test_build_failure_retains_machine_and_human_reports(self):
        from types import SimpleNamespace

        def fake_command(arguments, log, timeout, **kwargs):
            output = ""
            code = 0
            if arguments[:2] == ["git", "rev-parse"]:
                output = "a" * 40
            elif arguments[:2] == ["docker", "info"]:
                output = json.dumps({"version": "fixture", "os": "linux", "architecture": "x86_64"})
            elif arguments[:3] == ["docker", "buildx", "build"]:
                output, code = "fixture build failure", 1
            log.write_text(output)
            return {"command": arguments, "exit_code": code, "log": log.name,
                    "timed_out": False, "elapsed_ms": 1}

        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(ENVIRONMENT, "command", side_effect=fake_command), \
                patch.object(ENVIRONMENT.sys, "platform", "linux"), \
                patch.object(ENVIRONMENT.os, "getuid", return_value=1000, create=True), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = ENVIRONMENT.host_run(SimpleNamespace(output=temporary, platform=None))
            result_path = next(Path(temporary).glob("*/results.json"))
            result = json.loads(result_path.read_text())
            self.assertEqual(code, 1)
            self.assertEqual(result["status"], "error")
            self.assertIn("build failed", result["error"])
            self.assertTrue(result_path.with_name("report.md").is_file())
            self.assertFalse(any(step["name"] == "container" for step in result["steps"]))

    def test_report_leaves_unmeasured_model_metrics_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            ENVIRONMENT.write_report(out, {"status": "incomplete", "environment": {}})
            report = (out / "report.md").read_text()
            self.assertIn("not measured", report)
            self.assertIn("not completion of the shared team milestone", report)
            self.assertNotIn("100%", report)

    def fake_host(self, *, cleanup_code=0, container_code=0, incomplete=False,
                  docker_code=0, wsl=False):
        from types import SimpleNamespace
        calls = []

        def fake_command(arguments, log, timeout, **kwargs):
            calls.append(arguments)
            output, code = "", 0
            if arguments[:2] == ["git", "rev-parse"]:
                output = "a" * 40
            elif arguments[:2] == ["docker", "info"]:
                output = json.dumps({"version": "fixture", "os": "linux", "architecture": "x86_64"})
                code = docker_code
            elif arguments[:3] == ["docker", "buildx", "build"]:
                Path(arguments[arguments.index("--iidfile") + 1]).write_text("sha256:fixture")
            elif arguments[:2] == ["docker", "run"]:
                cases = [{"suite": target, "name": "fixture", "status": "pass", "elapsed_ms": 1,
                          "log": "fixture.log"} for _, target in ENVIRONMENT.SUITES]
                if incomplete:
                    cases.pop()
                ENVIRONMENT.write_json(log.parent / "fixture-results.json", {"status": "pass", "cases": cases})
                code = container_code
            elif arguments[:2] == ["docker", "inspect"]:
                output = json.dumps({"state": {"OOMKilled": False, "Running": False}})
            elif arguments[:2] == ["docker", "rm"]:
                code = cleanup_code
            log.write_text(output)
            return {"command": arguments, "exit_code": code, "log": log.name,
                    "timed_out": False, "elapsed_ms": 1}

        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(ENVIRONMENT, "command", side_effect=fake_command), \
                patch.object(ENVIRONMENT.sys, "platform", "linux"), \
                patch.object(ENVIRONMENT.os, "getuid", return_value=1000, create=True), \
                patch.object(ENVIRONMENT.os, "getgid", return_value=1000, create=True), \
                patch.object(ENVIRONMENT.platform, "release", return_value=(
                    "6.6.87.2-microsoft-standard-WSL2" if wsl else "native-kernel")), \
                patch.dict(ENVIRONMENT.os.environ,
                           {"WSL_DISTRO_NAME": "Ubuntu-24.04"} if wsl else {}, clear=True), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = ENVIRONMENT.host_run(SimpleNamespace(output=temporary, platform=None))
            result = json.loads(next(Path(temporary).glob("*/results.json")).read_text())
            return code, result, calls

    def test_container_uses_only_owned_output_and_is_isolated(self):
        code, result, calls = self.fake_host()
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "pass")
        run = next(call for call in calls if call[:2] == ["docker", "run"])
        for option in ["--network=none", "--read-only", "--cap-drop=ALL",
                       "--security-opt=no-new-privileges:true", "--pids-limit=256"]:
            self.assertIn(option, run)
        self.assertEqual(run.count("--mount"), 1)
        self.assertTrue(run[run.index("--mount") + 1].endswith(",dst=/results"))
        self.assertNotIn("--privileged", run)
        self.assertNotIn("--env-file", run)
        self.assertEqual(run[run.index("--user") + 1], "1000:1000")
        self.assertTrue(any(call[:2] == ["docker", "rm"] for call in calls))

    def test_cleanup_failure_cannot_leave_a_green_report(self):
        code, result, _ = self.fake_host(cleanup_code=1)
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "error")
        self.assertIn("cleanup failed", result["error"])

    def test_wsl_docker_failure_keeps_report_and_stops_before_build_or_execution(self):
        code, result, calls = self.fake_host(docker_code=1, wsl=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "error")
        self.assertTrue(result["environment"]["wsl_detected"])
        self.assertIn("WSL Integration", result["error"])
        self.assertFalse(any(call[:2] == ["docker", "run"] for call in calls))
        self.assertFalse(any(call[:3] == ["docker", "buildx", "build"] for call in calls))

    def test_wsl_uses_the_existing_linux_container_path_and_retains_host_metadata(self):
        code, result, calls = self.fake_host(wsl=True)
        self.assertEqual(code, 0)
        self.assertEqual(result["environment"]["wsl_distribution"], "Ubuntu-24.04")
        run = next(call for call in calls if call[:2] == ["docker", "run"])
        self.assertEqual(run[run.index("--platform") + 1], "linux/amd64")
        self.assertEqual(run[run.index("--user") + 1], "1000:1000")
        self.assertIn("--network=none", run)
        self.assertTrue(any(call[:2] == ["docker", "rm"] for call in calls))

    def test_container_error_or_missing_suite_cannot_leave_a_green_report(self):
        for kwargs in [{"container_code": 137}, {"incomplete": True}]:
            with self.subTest(kwargs=kwargs):
                code, result, _ = self.fake_host(**kwargs)
                self.assertEqual(code, 1)
                self.assertEqual(result["status"], "error")


if __name__ == "__main__":
    unittest.main()
