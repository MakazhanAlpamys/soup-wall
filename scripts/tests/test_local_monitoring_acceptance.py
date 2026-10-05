# SPDX-License-Identifier: Apache-2.0
"""Free authentication, artifact-integrity, and failure-path checks; no monitoring binaries launched."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "local-monitoring-acceptance.py"
SPEC = importlib.util.spec_from_file_location("monitoring_under_test", SCRIPT)
MONITOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MONITOR)
FETCH_SPEC = importlib.util.spec_from_file_location("monitoring_fetch_under_test", SCRIPT.with_name("fetch-monitoring-tools.py"))
FETCH = importlib.util.module_from_spec(FETCH_SPEC)
FETCH_SPEC.loader.exec_module(FETCH)


class MonitoringSafety(unittest.TestCase):
    def test_default_command_does_not_launch_processes(self):
        result = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["processes_started"], 0)

    def payload(self, state="firing", instance="127.0.0.1:9123"):
        return json.dumps({"version": "4", "alerts": [{"status": state,
            "labels": {"alertname": MONITOR.ALERT, "job": MONITOR.JOB, "instance": instance},
            "startsAt": "2026-10-05T00:00:00Z", "endsAt": "2026-10-05T00:03:00Z"}]}).encode()

    def test_receiver_rejects_missing_and_wrong_auth_then_accepts_matched_cycle(self):
        receiver = MONITOR.Receiver("neutral-fixture-key", "127.0.0.1:9123")
        self.addCleanup(receiver.close)
        url = f"http://127.0.0.1:{receiver.server_port}/alerts"
        for headers in [{}, {"Authorization": "Bearer wrong-key"}, {"Authorization": "Bearer wrong-\u00e9"}]:
            with self.assertRaises(urllib.error.HTTPError) as error:
                MONITOR.request(url, self.payload(), headers)
            self.assertEqual(error.exception.code, 401)
            self.assertEqual(receiver.receipts, [])
        headers = {"Authorization": "Bearer neutral-fixture-key"}
        MONITOR.request(url, self.payload(), headers)
        MONITOR.request(url, self.payload("resolved"), headers)
        self.assertEqual(len(receiver.seen("firing")), 1)
        self.assertEqual(len(receiver.seen("resolved")), 1)
        self.assertNotIn("neutral-fixture-key", json.dumps(receiver.receipts))

    def test_authenticated_receiver_rejects_unrelated_instance_and_malformed_body(self):
        receiver = MONITOR.Receiver("neutral-fixture-key", "127.0.0.1:9123")
        self.addCleanup(receiver.close)
        url = f"http://127.0.0.1:{receiver.server_port}/alerts"
        malformed_alert = json.loads(self.payload())
        malformed_alert["alerts"][0]["labels"] = []
        bad_timestamp = json.loads(self.payload())
        bad_timestamp["alerts"][0]["startsAt"] = {"neutral": "fixture"}
        for body in [self.payload(instance="127.0.0.1:9000"), b"{}", b"[]", b"neutral",
                     b'{"version":"4","alerts":[[]]}', json.dumps(malformed_alert).encode(),
                     json.dumps(bad_timestamp).encode()]:
            with self.assertRaises(urllib.error.HTTPError) as error:
                MONITOR.request(url, body, {"Authorization": "Bearer neutral-fixture-key"})
            self.assertEqual(error.exception.code, 400)
        self.assertEqual(receiver.receipts, [])

    def test_local_requests_reject_nonloopback_and_never_follow_redirects(self):
        with patch.object(MONITOR.urllib.request, "build_opener") as transport:
            for url in ["https://127.0.0.1:1/", "http://localhost:1/", "http://203.0.113.1:1/",
                        "http://neutral:fixture@127.0.0.1:1/", "http://127.0.0.1/"]:
                with self.assertRaises(MONITOR.AcceptanceError):
                    MONITOR.request(url)
            transport.assert_not_called()
        class Redirect(MONITOR.http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "https://must-not-be-requested.invalid/")
                self.end_headers()
        server = MONITOR.http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        thread = MONITOR.threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as error:
                MONITOR.request(f"http://127.0.0.1:{server.server_port}/")
            self.assertEqual(error.exception.code, 302)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_target_junction_and_redirected_base_are_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            base = repo / "target"
            base.mkdir()
            docs = repo / "docs"
            docs.mkdir()
            with patch.object(MONITOR, "REPO", repo), \
                    patch.object(Path, "is_junction", lambda path: path == base, create=True):
                with self.assertRaises(MONITOR.AcceptanceError):
                    MONITOR.target_directory()
                with self.assertRaises(RuntimeError):
                    FETCH.checked_destination(repo, base / "monitoring-tools")
            original_resolve = Path.resolve
            def redirected(path, *args, **kwargs):
                return docs if path == base else original_resolve(path, *args, **kwargs)
            with patch.object(MONITOR, "REPO", repo), patch.object(Path, "resolve", redirected):
                with self.assertRaises(MONITOR.AcceptanceError):
                    MONITOR.target_directory()
                with self.assertRaises(RuntimeError):
                    FETCH.checked_destination(repo, base / "monitoring-tools")
            self.assertEqual(list(docs.iterdir()), [])
            self.assertEqual(list(base.iterdir()), [])

    def test_fetch_rejects_linked_descendant_and_outside_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            base = repo / "target"
            base.mkdir()
            descendant = base / "neutral-linked-fixture"
            with patch.object(Path, "is_junction", lambda path: path == descendant, create=True):
                with self.assertRaises(RuntimeError):
                    FETCH.checked_destination(repo, descendant / "tools")
            with self.assertRaises(RuntimeError):
                FETCH.checked_destination(repo, repo / "docs")
            self.assertEqual(FETCH.checked_destination(repo, base / "tools"), base / "tools")

    def test_cleanup_never_removes_an_unowned_or_outside_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            sibling = parent / "unrelated-existing-runtime"
            sibling.mkdir()
            marker = sibling / "neutral-marker"
            marker.write_text("keep")
            with self.assertRaises(MONITOR.AcceptanceError):
                MONITOR.cleanup_directory(sibling, parent)
            self.assertEqual(marker.read_text(), "keep")
            outside = parent / "soup-monitoring-owned-test"
            outside.mkdir()
            with self.assertRaises(MONITOR.AcceptanceError):
                MONITOR.cleanup_directory(outside, parent / "different-parent")
            self.assertTrue(outside.exists())

    def test_denied_cleanup_retains_incomplete_evidence_and_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "target").mkdir()
            (repo / "deploy").mkdir()
            for name in ["prometheus-alerts.yaml", "prometheus-alerts.test.yaml"]:
                (repo / "deploy" / name).write_bytes((MONITOR.REPO / "deploy" / name).read_bytes())
            binary = repo / "nonexecuted.bin"
            binary.write_bytes(b"neutral-not-an-executable")
            args = SimpleNamespace(artifact_label="neutral-fixture", gateway=binary)
            def invocation(command, **_):
                if command[0] == "git":
                    return SimpleNamespace(stdout=b"neutral-baseline")
                raise RuntimeError("fixture infrastructure failure")
            with patch.object(MONITOR, "REPO", repo), patch.object(MONITOR, "verify_inputs", return_value=({}, "neutral")), \
                    patch.object(MONITOR, "restrict_runtime"), patch.object(MONITOR.subprocess, "run", side_effect=invocation), \
                    patch.object(MONITOR, "cleanup_directory", side_effect=PermissionError("neutral denied cleanup")):
                report = MONITOR.run(args)
            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(report["cleanup"]["errors"], ["PermissionError"])
            self.assertFalse(report["cleanup"]["generated_runtime_removed"])
            self.assertEqual(len(list((repo / "target").glob("soup-monitoring-*"))), 1)
            self.assertNotIn("neutral denied cleanup", json.dumps(report))
            output = MONITOR.EvidenceOutput(repo / "evidence.json")
            output.publish(report)
            self.assertEqual(json.loads((repo / "evidence.json").read_text())["status"], "incomplete")

    def test_fresh_evidence_is_reserved_and_existing_output_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "evidence.json"
            output = MONITOR.EvidenceOutput(destination)
            with self.assertRaises(MONITOR.AcceptanceError):
                MONITOR.EvidenceOutput(destination)
            output.publish({"status": "incomplete"})
            self.assertEqual(json.loads(destination.read_text())["status"], "incomplete")
            self.assertFalse(list(destination.parent.glob("*.tmp")))

    def test_child_ignoring_terminate_is_killed_and_waited(self):
        class Child:
            alive = True
            killed = False
            def poll(self):
                return None if self.alive else 0
            def terminate(self):
                pass
            def wait(self, timeout=None):
                if self.alive:
                    raise subprocess.TimeoutExpired("neutral-fixture", timeout)
            def kill(self):
                self.alive = False
                self.killed = True
        child = Child()
        MONITOR.stop_child(child)
        self.assertTrue(child.killed)
        self.assertFalse(child.alive)

    def test_forged_manifest_cannot_rebind_modified_binary_to_official_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            tools = {}
            archive_hashes, checksum_hashes = {}, {}
            binaries = {}
            for name, version, executables in [("prometheus", "3.15.0", ["prometheus.exe", "promtool.exe"]),
                                               ("alertmanager", "0.34.1", ["alertmanager.exe", "amtool.exe"])]:
                archive = directory / f"{name}-{version}.windows-amd64.zip"
                root = directory / archive.stem
                root.mkdir()
                with zipfile.ZipFile(archive, "w") as bundle:
                    for filename in [*executables, "LICENSE", "NOTICE"]:
                        content = ("neutral-fixture-" + filename).encode()
                        bundle.writestr(f"{root.name}/{filename}", content)
                        (root / filename).write_bytes(content)
                        binaries[filename] = root / filename
                archive_hashes[name] = MONITOR.file_hash(archive)
                checksum = directory / f"{name}-{version}-sha256sums.txt"
                checksum.write_text("neutral-checksums")
                checksum_hashes[name] = MONITOR.file_hash(checksum)
                tools[name] = {"version": version, "archive": archive.name,
                    "archive_sha256": archive_hashes[name], "checksums_sha256": checksum_hashes[name],
                    "official_release": f"https://github.com/prometheus/{name}/releases/download/v{version}/",
                    "licenses_sha256": {filename: MONITOR.file_hash(root / filename) for filename in ["LICENSE", "NOTICE"]},
                    "executables_sha256": {filename: MONITOR.file_hash(root / filename) for filename in executables}}
            gateway_archive = directory / "neutral-gateway.zip"
            gateway = directory / "neutral-gateway.bin"
            gateway.write_bytes(b"neutral-gateway")
            with zipfile.ZipFile(gateway_archive, "w") as archive:
                archive.writestr("neutral/llm-firewall.exe", gateway.read_bytes())
            manifest = directory / "manifest.json"
            canonical = {"schema_version": 1, "platform": "windows-amd64", "tools": tools}
            manifest.write_text(json.dumps(canonical))
            args = SimpleNamespace(tools_manifest=manifest, prometheus=binaries["prometheus.exe"],
                promtool=binaries["promtool.exe"], alertmanager=binaries["alertmanager.exe"], gateway=gateway,
                gateway_archive=gateway_archive, artifact_label="v0.4.0")
            with patch.object(MONITOR, "TOOL_ARCHIVE_SHA256", archive_hashes), \
                    patch.object(MONITOR, "TOOL_CHECKSUMS_SHA256", checksum_hashes), \
                    patch.object(MONITOR, "GATEWAY_ARCHIVE_SHA256", MONITOR.file_hash(gateway_archive)):
                MONITOR.verify_inputs(args)
                manifest.write_text(json.dumps({**canonical, "operator_note": "neutral-must-not-be-published"}))
                with self.assertRaisesRegex(MONITOR.AcceptanceError, "schema"):
                    MONITOR.verify_inputs(args)
                canonical["tools"]["alertmanager"]["executables_sha256"]["amtool.exe"] = "neutral-forged-metadata"
                manifest.write_text(json.dumps(canonical))
                with self.assertRaisesRegex(MONITOR.AcceptanceError, "inventory differs"):
                    MONITOR.verify_inputs(args)
                canonical["tools"]["alertmanager"]["executables_sha256"]["amtool.exe"] = MONITOR.file_hash(binaries["amtool.exe"])
                args.promtool.write_bytes(b"neutral-edited-executable")
                tools["prometheus"]["executables_sha256"]["promtool.exe"] = MONITOR.file_hash(args.promtool)
                manifest.write_text(json.dumps(canonical))
                with self.assertRaisesRegex(MONITOR.AcceptanceError, "official archive"):
                    MONITOR.verify_inputs(args)


if __name__ == "__main__":
    unittest.main()
