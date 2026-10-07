# SPDX-License-Identifier: Apache-2.0
"""Safety and protocol regressions for the portable MCP acceptance driver."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "mcp-local-acceptance.py"
SPEC = importlib.util.spec_from_file_location("mcp_acceptance_under_test", SCRIPT)
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)


class HarnessSafety(unittest.TestCase):
    def test_manifest_mode_starts_no_process(self):
        with patch.object(sys, "argv", [str(SCRIPT)]), patch.object(DEMO.subprocess, "Popen") as spawn, \
                patch.object(DEMO.subprocess, "run") as run, patch("sys.stdout", new_callable=io.StringIO) as out:
            DEMO.main()
        self.assertEqual(json.loads(out.getvalue())["processes_started"], 0)
        spawn.assert_not_called()
        run.assert_not_called()

    def test_reserved_evidence_cannot_replace_existing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            output = DEMO.EvidenceOutput(path)
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                DEMO.EvidenceOutput(path)
            self.assertEqual(path.read_bytes(), original)
            output.publish({"status": "passed", "checks": []})
            self.assertEqual(json.loads(path.read_text())["status"], "passed")
            self.assertEqual(list(path.parent.glob("*.tmp")), [])

    @unittest.skipUnless(os.name == "posix", "Unix symlink regression")
    def test_replaced_evidence_target_is_refused_without_touching_link_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            output = DEMO.EvidenceOutput(path)
            outside = Path(temporary) / "untouched.json"
            outside.write_text("untouched")
            path.unlink()
            path.symlink_to(outside)
            with self.assertRaises(DEMO.AcceptanceError):
                output.publish({"status": "passed"})
            self.assertEqual(outside.read_text(), "untouched")

    def test_environment_drops_credentials_and_redirects_and_uses_owned_profile(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {
                "ANTHROPIC_API_KEY": "private", "OPENAI_API_KEY": "private",
                "AGENTFW_TOKEN": "private", "AGENTFW_NATIVE_TOKEN": "private",
                "HTTP_PROXY": "http://outside.invalid", "PYTHONPATH": "outside",
                "LLM_FW_ADMIN_TOKEN": "private", "HOME": "/outside", "TMPDIR": "/outside"}):
            root = Path(temporary).resolve()
            env = DEMO.child_environment(root)
            for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AGENTFW_TOKEN", "AGENTFW_NATIVE_TOKEN",
                        "HTTP_PROXY", "PYTHONPATH", "LLM_FW_ADMIN_TOKEN"):
                self.assertNotIn(key, env)
            self.assertEqual(env["HOME"], str(root))
            self.assertEqual(env["USERPROFILE"], str(root))
            self.assertEqual(env["TMPDIR"], str(root / "tmp"))
            self.assertEqual(env["APPDATA"], str(root / "appdata"))

    def test_unrelated_tool_error_cannot_count_as_policy_prevention(self):
        raw = json.dumps({"jsonrpc": "2.0", "id": 3,
            "result": {"content": [{"type": "text", "text": "Network unavailable"}], "isError": True}})
        with self.assertRaises(DEMO.AcceptanceError):
            DEMO.refused(raw, "demo-secret-egress")

    def test_transport_eof_and_wrong_id_are_failures_not_policy_refusals(self):
        request = DEMO.call("original", "read_document", {"document": "project"}, 0)
        for raw in (b"", DEMO.SERVER.response("other", DEMO.SERVER.DOCUMENT)):
            process = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(raw))
            with patch.object(DEMO.subprocess, "Popen", return_value=process):
                session = DEMO.Session(["nonexecuted"], ".", {})
            with self.assertRaises(DEMO.AcceptanceError):
                session.exchange(request)

    def test_reply_cannot_substitute_boolean_or_float_for_numeric_id(self):
        request = DEMO.call(1, "read_document", {"document": "project"}, 0)
        for reply_id in (True, 1.0):
            process = SimpleNamespace(stdin=io.BytesIO(),
                                      stdout=io.BytesIO(DEMO.SERVER.response(reply_id, DEMO.SERVER.DOCUMENT)))
            with patch.object(DEMO.subprocess, "Popen", return_value=process):
                session = DEMO.Session(["nonexecuted"], ".", {})
            with self.assertRaisesRegex(DEMO.AcceptanceError, "mcp_response_identity_mismatch"):
                session.exchange(request)

    def test_oversized_or_unterminated_output_is_never_admitted(self):
        request = DEMO.call(3, "read_document", {"document": "project"}, 0)
        for raw in (b"x" * (DEMO.MAX_FRAME + 1) + b"\n", b'{"jsonrpc":"2.0","id":3}'):
            process = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(raw))
            with patch.object(DEMO.subprocess, "Popen", return_value=process):
                session = DEMO.Session(["nonexecuted"], ".", {})
            with self.assertRaises(DEMO.AcceptanceError):
                session.exchange(request)

    def test_read_timeout_closes_owned_session_and_cannot_count_as_prevention(self):
        request = DEMO.call(3, "read_document", {"document": "project"}, 0)
        process = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(b""))
        mailbox = SimpleNamespace(put=lambda _: None)
        def timeout(**_):
            raise DEMO.queue.Empty
        mailbox.get = timeout
        with patch.object(DEMO.subprocess, "Popen", return_value=process):
            session = DEMO.Session(["nonexecuted"], ".", {})
        with patch.object(DEMO.queue, "Queue", return_value=mailbox), \
                patch.object(session, "close") as close:
            with self.assertRaisesRegex(DEMO.AcceptanceError, "mcp_response_timeout"):
                session.exchange(request)
        close.assert_called_once()

    def test_close_gives_collector_eof_before_terminating(self):
        events = []

        class Process:
            stdout = stderr = None
            def __init__(self):
                self.stdin = SimpleNamespace(close=lambda: events.append("eof"))
            def wait(self, timeout):
                events.append("wait")
            def poll(self):
                return 0

        with patch.object(DEMO.subprocess, "Popen", return_value=Process()):
            session = DEMO.Session(["nonexecuted"], ".", {})
        session.close()
        self.assertEqual(events[0:2], ["eof", "wait"])
        self.assertTrue(session.closed)

    def test_owned_server_rejects_any_destination_except_its_exact_receiver(self):
        recipient = "http://127.0.0.1:9000/capture"
        with patch.object(DEMO.SERVER.urllib.request, "build_opener") as request:
            for url in ("https://outside.invalid/capture", "http://localhost:9000/capture",
                        "http://127.0.0.1:9001/capture", recipient + "?redirect=1"):
                with self.assertRaises(ValueError):
                    DEMO.SERVER.execute("send_http", {"url": url, "body": "benign"}, recipient)
        request.assert_not_called()
        for url in ("http://127.0.0.1:9000/capture", "http://127.0.0.1:9000/capture#bad"):
            self.assertEqual(DEMO.SERVER.recipient_allowed(url), url == recipient)

    def test_original_response_contains_native_id_and_escaped_text(self):
        raw = DEMO.SERVER.response("original-id", DEMO.SERVER.POISON)
        self.assertEqual(json.loads(raw)["id"], "original-id")
        self.assertTrue(raw.startswith(b"  "))
        self.assertTrue(raw.endswith(b" \n"))
        self.assertIn(b"\\u0049gnore", raw)
        self.assertEqual(json.loads(raw)["result"]["content"][0]["text"], DEMO.SERVER.POISON)


if __name__ == "__main__":
    unittest.main()
