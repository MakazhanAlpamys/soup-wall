# SPDX-License-Identifier: Apache-2.0
"""Failure-path regression checks without launching a Gateway or touching services."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit


SCRIPT = Path(__file__).resolve().parents[1] / "self-hosted-local-acceptance.py"
SPEC = importlib.util.spec_from_file_location("local_acceptance_under_test", SCRIPT)
ACCEPTANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACCEPTANCE)


class Child:
    """Model a child that can ignore terminate but must respond to kill."""

    def __init__(self, ignores_terminate=False):
        self.ignores_terminate = ignores_terminate
        self.alive = True
        self.terminate_calls = 0
        self.kill_calls = 0

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.terminate_calls += 1
        if not self.ignores_terminate:
            self.alive = False

    def wait(self, timeout=None):
        if self.alive:
            raise subprocess.TimeoutExpired("nonexecuted-fixture", timeout)
        return 0

    def kill(self):
        self.kill_calls += 1
        self.alive = False


class Response:
    def __init__(self, status, body):
        self.status = status
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return self.body


class MalformedTenantOpener:
    def open(self, request, timeout=None):
        path = urlsplit(request.full_url).path
        method = request.get_method()
        if path in {"/healthz", "/readyz"}:
            return Response(200, b"{}")
        if path == "/admin":
            return Response(200, b"Soup Wall")
        if path == "/admin/v1/tenants" and method == "GET":
            return Response(401, b"{}")
        if path == "/admin/v1/tenants" and method == "POST":
            # HTTP success with a missing id is a failed acceptance result,
            # rather than an unhandled exception that loses the evidence.
            return Response(201, b"{}")
        raise AssertionError(f"Unexpected fixture request: {method} {path}")


class AcceptanceFailures(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="soup-wall-acceptance-test-")
        self.addCleanup(temporary.cleanup)
        self.gateway = Path(temporary.name) / "nonexecuted-gateway.bin"
        self.gateway.write_bytes(b"nonexecuted acceptance fixture")
        self.child = Child()
        self.child_directory = None
        self.provider = Mock(server_port=9102)
        self.admin_token = "fixture-admin-token-must-never-appear-in-evidence"

        def spawn(*_, **kwargs):
            self.child_directory = Path(kwargs["cwd"])
            return self.child

        patches = [
            patch.object(ACCEPTANCE.http.server, "ThreadingHTTPServer", return_value=self.provider),
            patch.object(ACCEPTANCE.threading, "Thread", return_value=Mock()),
            patch.object(ACCEPTANCE, "free_port", return_value=9101),
            patch.object(ACCEPTANCE.subprocess, "run", return_value=SimpleNamespace(returncode=0)),
            patch.object(ACCEPTANCE.subprocess, "Popen", side_effect=spawn),
            patch.object(ACCEPTANCE.secrets, "token_urlsafe", return_value=self.admin_token),
        ]
        for mocked in patches:
            mocked.start()
            self.addCleanup(mocked.stop)

    def assert_failed_and_cleaned(self, evidence):
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(evidence["checks"][-1]["status"], "failed")
        self.assertNotIn(self.admin_token, json.dumps(evidence))
        self.assertFalse(self.child.alive, "The owned startup child must not survive failure.")
        self.assertIsNotNone(self.child_directory)
        self.assertFalse(self.child_directory.exists(), "Stop the child before removing its fixture.")
        self.provider.shutdown.assert_called_once()
        self.provider.server_close.assert_called_once()

    def test_startup_timeout_kills_child_that_ignores_terminate(self):
        self.child = Child(ignores_terminate=True)
        # Advance directly to the readiness deadline without sleeping or HTTP.
        with patch.object(ACCEPTANCE.time, "monotonic", side_effect=[0, 31]):
            evidence = ACCEPTANCE.run(self.gateway, "fixture-commit")
        self.assert_failed_and_cleaned(evidence)
        self.assertEqual(self.child.terminate_calls, 1)
        self.assertEqual(self.child.kill_calls, 1)
        self.assertEqual(evidence["checks"][-1]["error_type"], "RuntimeError")

    def test_malformed_tenant_response_retains_sanitized_failure_evidence(self):
        with patch.object(ACCEPTANCE.urllib.request, "build_opener", return_value=MalformedTenantOpener()):
            evidence = ACCEPTANCE.run(self.gateway, "fixture-commit")
        self.assert_failed_and_cleaned(evidence)
        self.assertEqual(evidence["checks"][-1]["error_type"], "KeyError")
        self.assertNotIn("error", evidence["checks"][-1])
        self.assertEqual(self.child.terminate_calls, 1)
        self.assertEqual(self.child.kill_calls, 0)


if __name__ == "__main__":
    unittest.main()
