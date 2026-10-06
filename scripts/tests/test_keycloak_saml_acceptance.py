# SPDX-License-Identifier: Apache-2.0
"""Offline safety checks for the manual vendor-runtime driver; no IdP is started."""

import argparse
import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile
import zlib

MODULE_PATH = Path(__file__).resolve().parents[1] / "keycloak-saml-acceptance.py"
SPEC = importlib.util.spec_from_file_location("keycloak_acceptance", MODULE_PATH)
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)
REQUESTS_AVAILABLE = importlib.util.find_spec("requests") is not None


class DriverSafetyTests(unittest.TestCase):
    def fixture_arguments(self, root, fixture_out):
        return argparse.Namespace(artifact_label="unit-only", gateway=root / "missing.exe",
            bootstrap_helper=root / "missing-helper.exe", keycloak_zip=root / "missing-keycloak.zip",
            jdk_zip=root / "missing-jdk.zip", out=root / "acceptance.json", fixture_out=fixture_out)

    def fixture_capture(self):
        return {"captured_at_unix": 1800000001,
                "sp_entity_id": "urn:soup-wall:keycloak:synthetic-unit",
                "acs_url": "https://127.0.0.1:12345/auth/saml/acs",
                "idp_entity_id": "https://127.0.0.1:23456/realms/soup-synthetic-unit",
                "idp_signing_cert_pem": "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n",
                "request_id": "_original-first-request", "relay_state": "synthetic-state",
                "expected_name_id": "synthetic-unit@example.test",
                "metadata_xml": '<EntityDescriptor entityID="original"><Signature>bytes</Signature></EntityDescriptor>',
                "saml_response": base64.b64encode(b'<Response ID="first-response"><Signature>original bytes</Signature></Response>').decode()}

    def fixture_report(self):
        return {"passed": True, "cleanup_passed": True,
                "checks": [{"name": "vendor-assertion-accepted", "passed": True},
                           {"name": "own-runtime-cleaned", "passed": True}],
                "runtimes": {"keycloak": {"version": "26.8.0", "sha256": "a" * 64},
                             "jdk": {"sha256": "b" * 64}},
                "driver_sha256": "c" * 64, "saml_source_sha256": "d" * 64,
                "gateway_sha256": "e" * 64, "bootstrap_helper_sha256": "f" * 64}

    def test_fixture_output_is_reserved_incomplete_before_missing_input_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.fixture_arguments(root, root / "fixture.json")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(DRIVER.run(args), 1)
            self.assertTrue(args.fixture_out.is_file(), "requested fixture output must be reserved before input reads")
            self.assertEqual(json.loads(args.fixture_out.read_text()), {
                "schema_version": 1, "acceptance_complete": False, "synthetic_fixture": True})
            self.assertNotIn("saml_response", args.fixture_out.read_text())

    def test_fixture_output_aliases_cannot_replace_report_or_protected_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ["out", "gateway", "bootstrap_helper", "keycloak_zip", "jdk_zip"]:
                with self.subTest(name=name):
                    case = root / name
                    case.mkdir()
                    args = self.fixture_arguments(case, case / "placeholder")
                    args.fixture_out = getattr(args, name)
                    args.fixture_out.write_bytes(b"original protected bytes")
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(DRIVER.run(args), 1)
                    self.assertEqual(args.fixture_out.read_bytes(), b"original protected bytes")
                    if name != "out":
                        report = json.loads(args.out.read_text())
                        self.assertEqual(report["failure_phase"], "fixture-output-reservation")

    def test_invalid_fixture_parent_fails_before_any_input_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.fixture_arguments(root, root / "missing-parent" / "fixture.json")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(DRIVER.run(args), 1)
            report = json.loads(args.out.read_text())
            self.assertEqual(report["failure_phase"], "fixture-output-reservation")
            self.assertFalse(args.fixture_out.exists())

    def test_outgoing_request_id_and_relay_are_captured_without_response_input(self):
        self.assertTrue(callable(getattr(DRIVER, "capture_sp_request", None)), "outgoing request capture is missing")
        xml = (b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
               b'ID="_independently-original-request"/>')
        compressed = zlib.compress(xml)[2:-4]
        url = "https://127.0.0.1:23456/auth?" + DRIVER.urllib.parse.urlencode({
            "SAMLRequest": base64.b64encode(compressed).decode(),
            "RelayState": "original+state", "SigAlg": "algorithm", "Signature": "opaque"})
        self.assertEqual(DRIVER.capture_sp_request(url), {
            "request_id": "_independently-original-request", "relay_state": "original+state"})
        for bad in [url + "&RelayState=second", url.replace("SAMLRequest=", "SAMLResponse="),
                    url.replace("RelayState=", "UnknownState=")]:
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                DRIVER.capture_sp_request(bad)

    def test_fixture_corpus_waits_for_all_checks_and_owned_cleanup(self):
        self.assertTrue(callable(getattr(DRIVER, "SyntheticFixtureOutput", None)), "fixture publisher is missing")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.json"
            output = DRIVER.SyntheticFixtureOutput(path, [])
            for changed in [{"passed": False}, {"cleanup_passed": False}, {"checks": []},
                            {"checks": [{"name": "vendor-negative", "passed": False}]}]:
                with self.subTest(changed=changed):
                    report = self.fixture_report()
                    report.update(changed)
                    self.assertFalse(output.publish_capture(self.fixture_capture(), report))
                    saved = json.loads(path.read_text())
                    self.assertFalse(saved["acceptance_complete"])
                    self.assertNotIn("metadata_xml", saved)
                    self.assertNotIn("saml_response", saved)

    def test_fixture_corpus_preserves_original_public_bytes_and_hash_provenance(self):
        self.assertTrue(callable(getattr(DRIVER, "SyntheticFixtureOutput", None)), "fixture publisher is missing")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.json"
            output = DRIVER.SyntheticFixtureOutput(path, [])
            capture = self.fixture_capture()
            self.assertTrue(output.publish_capture(capture, self.fixture_report()))
            saved = json.loads(path.read_text())
            self.assertEqual(set(saved), set(capture) | {
                "schema_version", "acceptance_complete", "synthetic_fixture", "vendor", "provenance"})
            self.assertEqual(saved["vendor"], {"name": "Keycloak", "version": "26.8.0", "archive_sha256": "a" * 64})
            self.assertEqual(saved["provenance"], {"driver_sha256": "c" * 64, "saml_source_sha256": "d" * 64,
                "gateway_sha256": "e" * 64, "bootstrap_helper_sha256": "f" * 64,
                "keycloak_archive_sha256": "a" * 64, "jdk_archive_sha256": "b" * 64})
            self.assertEqual(saved["metadata_xml"], capture["metadata_xml"])
            self.assertEqual(saved["saml_response"], capture["saml_response"])
            self.assertEqual(saved["request_id"], "_original-first-request")
            self.assertTrue(saved["acceptance_complete"])

    def test_fixture_corpus_refuses_private_extra_fields_and_non_synthetic_subject(self):
        self.assertTrue(callable(getattr(DRIVER, "SyntheticFixtureOutput", None)), "fixture publisher is missing")
        with tempfile.TemporaryDirectory() as temporary:
            for number, changes in enumerate([{"password": "must-never-export"},
                    {"expected_name_id": "customer@real.invalid"},
                    {"idp_signing_cert_pem": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"}]):
                path = Path(temporary) / (str(number) + ".json")
                output = DRIVER.SyntheticFixtureOutput(path, [])
                capture = self.fixture_capture()
                capture.update(changes)
                with self.assertRaises(RuntimeError):
                    output.publish_capture(capture, self.fixture_report())
                saved = path.read_text()
                self.assertNotIn("must-never-export", saved)
                self.assertNotIn("metadata_xml", saved)
                self.assertFalse(json.loads(saved)["acceptance_complete"])

    def test_fixture_atomic_publication_failure_keeps_incomplete_snapshot(self):
        self.assertTrue(callable(getattr(DRIVER, "SyntheticFixtureOutput", None)), "fixture publisher is missing")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.json"
            output = DRIVER.SyntheticFixtureOutput(path, [])
            pending = path.read_bytes()
            with patch.object(DRIVER.os, "replace", side_effect=OSError("private detail")):
                with self.assertRaises(OSError):
                    output.publish_capture(self.fixture_capture(), self.fixture_report())
            self.assertEqual(path.read_bytes(), pending)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_edge_rejects_header_injection_before_sending_status_or_headers(self):
        invalid = [("X-Name\r\nInjected", "value"), ("X-Name\n", "value"),
                   ("Bad Name", "value"), ("Bad:Name", "value"), ("", "value"),
                   ("X-Name", "value\r\nInjected: yes"), ("X-Name", "value\n"),
                   ("X-Name", "value\x00"), ("X-Name", "value\x7f"),
                   ("X-Name", "non-Latin-1 \u2603"), ("Connection", "close\r\nInjected")]
        for name, value in invalid:
            with self.subTest(name=name, value=value):
                handler = Mock(wfile=io.BytesIO())
                response = Mock(headers={"X-Valid-First": "preserved", name: value},
                                status_code=200, content=b"private upstream content")
                with self.assertRaises(RuntimeError):
                    DRIVER.write_gateway_response(handler, response)
                handler.send_response.assert_not_called()
                handler.send_header.assert_not_called()
                handler.end_headers.assert_not_called()
                self.assertEqual(handler.wfile.getvalue(), b"")

    def test_edge_preserves_valid_headers_and_body_with_safe_content_length(self):
        handler = Mock(wfile=io.BytesIO())
        headers = {"Content-Type": "text/plain; charset=iso-8859-1",
                   "Set-Cookie": "__Host-session=opaque; Path=/; Secure; HttpOnly; SameSite=Lax",
                   "X-Token!#$%&'*+-.^_`|~": "caf\xe9; exact=value",
                   "Location": "https://127.0.0.1:12345/exact?next=%2F",
                   "Connection": "close", "Content-Length": "999999",
                   "Transfer-Encoding": "chunked", "Content-Encoding": "gzip"}
        content = b"exact decoded body"
        DRIVER.write_gateway_response(handler, Mock(headers=headers, status_code=303, content=content))
        handler.send_response.assert_called_once_with(303)
        self.assertEqual([call.args for call in handler.send_header.call_args_list],
                         list(headers.items())[:4] + [("Content-Length", str(len(content)))])
        handler.end_headers.assert_called_once_with()
        self.assertEqual(handler.wfile.getvalue(), content)

    def test_edge_tls_context_requires_tls_12_or_later(self):
        context = DRIVER.edge_tls_context()
        self.assertEqual(context.protocol, ssl.PROTOCOL_TLS_SERVER)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_redirected_ignored_target_is_rejected_before_private_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            original_resolve = Path.resolve

            def redirected(path, *args, **kwargs):
                if path == root / "target":
                    return root / "docs"
                return original_resolve(path, *args, **kwargs)

            with patch.object(Path, "resolve", autospec=True, side_effect=redirected), \
                    patch.object(Path, "mkdir", autospec=True) as mkdir:
                with self.assertRaisesRegex(RuntimeError, "redirected"):
                    DRIVER.scratch_directory(root)
                mkdir.assert_not_called()
            self.assertFalse((root / "docs").exists())

    def test_bad_archive_hash_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "runtime.zip"
            archive.write_bytes(b"untrusted archive")
            destination = Path(temporary) / "extracted"
            with self.assertRaisesRegex(RuntimeError, "checksum"):
                DRIVER.unpack(archive, destination, {"size": archive.stat().st_size,
                                                    "sha256": "0" * 64})
            self.assertFalse(destination.exists())

    def test_archive_cannot_write_outside_the_new_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "runtime.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../escaped.txt", "malicious member")
            with self.assertRaisesRegex(RuntimeError, "escaped"):
                DRIVER.unpack(archive, root / "extracted", {
                    "size": archive.stat().st_size, "sha256": DRIVER.sha256(archive)})
            self.assertFalse((root / "escaped.txt").exists())

    def test_form_action_entities_and_hidden_fields_are_preserved(self):
        parsed = DRIVER.Forms('<form id="kc-form-login" method="post" '
                              'action="/login?a=1&amp;b=2"><input name="session_code" '
                              'value="opaque&amp;value"></form>').forms[0]
        self.assertEqual(parsed["action"], "/login?a=1&b=2")
        self.assertEqual(parsed["fields"], {"session_code": "opaque&value"})
        self.assertEqual(parsed["method"], "post")

    def test_child_environment_is_minimal_and_owns_profiles_and_search_paths(self):
        environment = {"SYSTEMROOT": "C:/Windows", "LLM_FW_OIDC_STATE_KEY": "do-not-forward",
                       "OPENAI_API_KEY": "do-not-forward", "HTTPS_PROXY": "do-not-forward",
                       "KC_BOOTSTRAP_ADMIN_PASSWORD": "do-not-forward",
                       "JAVA_TOOL_OPTIONS": "do-not-forward", "SSL_CERT_FILE": "do-not-forward",
                       "GOOGLE_API_KEY": "do-not-forward", "COHERE_API_KEY": "do-not-forward",
                       "AWS_ACCESS_KEY_ID": "do-not-forward", "AWS_SECRET_ACCESS_KEY": "do-not-forward",
                       "GITHUB_TOKEN": "do-not-forward", "UNKNOWN_VENDOR_SECRET": "do-not-forward",
                       "HOME": "ambient-profile", "USERPROFILE": "ambient-profile",
                       "APPDATA": "ambient-profile", "LOCALAPPDATA": "ambient-profile",
                       "PATH": "ambient-search-path", "COMSPEC": "ambient-command",
                       "OS": "attacker-selected-platform"}
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict(DRIVER.os.environ, environment, clear=True):
            owned = Path(temporary).resolve()
            result = DRIVER.child_environment(owned)
            self.assertEqual(set(result), {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "OS",
                                          "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"})
            self.assertEqual(result["OS"], "Windows_NT")
            for key in ["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"]:
                self.assertTrue(Path(result[key]).is_relative_to(owned))
                self.assertTrue(Path(result[key]).is_dir())
            self.assertNotIn("ambient", result["PATH"])
            self.assertTrue(result["COMSPEC"].endswith("cmd.exe"))
            self.assertNotIn("do-not-forward", result.values())

    @unittest.skipUnless(DRIVER.os.name == "nt", "official batch launcher regression requires native Windows")
    def test_owned_batch_launcher_resolves_vendor_jar_from_bin_with_untrusted_ambient_os(self):
        windows = Path(DRIVER.os.environ["SYSTEMROOT"]).resolve()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vendor_bin = root / "vendor" / "bin"
            vendor_lib = root / "vendor" / "lib"
            unrelated_cwd = root / "owned-cwd"
            for folder in [vendor_bin, vendor_lib, unrelated_cwd]:
                folder.mkdir(parents=True)
            (vendor_lib / "quarkus-run.jar").write_bytes(b"owned-entrypoint-marker")
            probe = vendor_bin / "probe.bat"
            probe.write_text('@echo off\nif "%OS%"=="Windows_NT" (\n'
                '  set "DIRNAME=%~dp0"\n) else (\n  set "DIRNAME=.\\"\n)\n'
                'if not exist "%DIRNAME%..\\lib\\quarkus-run.jar" exit /b 17\n'
                'type "%DIRNAME%..\\lib\\quarkus-run.jar"\n', encoding="ascii")
            with patch.dict(DRIVER.os.environ, {"SYSTEMROOT": str(windows),
                            "OS": "attacker-selected-platform"}, clear=True):
                environment = DRIVER.child_environment(root / "owned-profile")
            child = subprocess.run([environment["COMSPEC"], "/d", "/c", str(probe)],
                cwd=unrelated_cwd, env=environment, capture_output=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(child.returncode, 0, child.stderr.decode(errors="replace"))
            self.assertEqual(child.stdout, b"owned-entrypoint-marker")

    @unittest.skipUnless(REQUESTS_AVAILABLE, "full transport regressions require pinned requests")
    def test_internal_edge_ignores_ambient_proxy_netrc_and_redirect(self):
        import requests

        calls = []

        def send(_adapter, prepared, **kwargs):
            calls.append((prepared, kwargs))
            response = requests.Response()
            response.status_code = 303
            response.headers["Location"] = "https://outside.invalid/never-request"
            response._content = b"bounded-test"
            response.url = prepared.url
            response.request = prepared
            return response

        environment = {"HTTP_PROXY": "http://outside.invalid:1", "HTTPS_PROXY": "http://outside.invalid:1",
                       "NETRC": "never-read-this-profile"}
        with patch.dict(DRIVER.os.environ, environment, clear=True), \
                patch("requests.sessions.get_netrc_auth", side_effect=AssertionError("netrc consulted")), \
                patch("requests.sessions.get_environ_proxies", side_effect=AssertionError("proxy consulted")), \
                patch.object(requests.adapters.HTTPAdapter, "send", send):
            response = DRIVER.forward_gateway(12345, "/auth/saml/acs?exact=%2F", "POST",
                                               {"Cookie": "synthetic-cookie"}, b"synthetic-body")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(len(calls), 1)
        prepared, kwargs = calls[0]
        self.assertEqual(prepared.url, "http://127.0.0.1:12345/auth/saml/acs?exact=%2F")
        self.assertEqual(prepared.body, b"synthetic-body")
        self.assertNotIn("Authorization", prepared.headers)
        self.assertEqual(kwargs["proxies"], {})

    def test_internal_edge_rejects_non_loopback_request_targets_before_transport(self):
        with patch.dict("sys.modules", {"requests": None}):
            for target in ["https://outside.invalid/", "//outside.invalid/", "relative", "/\\outside", "/#fragment", "/\r\n"]:
                with self.subTest(target=target), self.assertRaises(RuntimeError):
                    DRIVER.forward_gateway(12345, target, "POST", {}, b"synthetic-body")

    def test_negative_nameid_mutation_uses_distinct_provisioned_alias(self):
        assertion = b'<Response><NameID>owner@example.test</NameID><Signed>unchanged</Signed></Response>'
        mutated = DRIVER.tamper_nameid(assertion, "owner@example.test", "alias@example.test")
        self.assertEqual(mutated, b'<Response><NameID>alias@example.test</NameID><Signed>unchanged</Signed></Response>')
        with self.assertRaises(RuntimeError):
            DRIVER.tamper_nameid(assertion, "owner@example.test", "owner@example.test")
        with self.assertRaises(RuntimeError):
            DRIVER.tamper_nameid(assertion + assertion, "owner@example.test", "alias@example.test")

    def test_cleanup_refuses_outside_or_live_child_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary) / "scratch"
            scratch.mkdir()
            outside = Path(temporary) / "soup-wall-keycloak-session-outside"
            outside.mkdir()
            with self.assertRaisesRegex(RuntimeError, "not the newly owned"):
                DRIVER.cleanup_new_directory(outside, scratch, [])
            inside = scratch / "soup-wall-keycloak-session-new"
            inside.mkdir()
            with self.assertRaisesRegex(RuntimeError, "remain active"):
                DRIVER.cleanup_new_directory(inside, scratch,
                                             [Mock(poll=Mock(return_value=None), soup_tree_stopped=False)])
            self.assertTrue(inside.exists())
            self.assertTrue(outside.exists())

    def test_persistent_cleanup_failure_is_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            new_directory = scratch / "soup-wall-keycloak-session-new"
            new_directory.mkdir()
            with patch.object(DRIVER.shutil, "rmtree", side_effect=PermissionError), \
                    patch.object(DRIVER.time, "sleep") as sleep:
                with self.assertRaises(PermissionError):
                    DRIVER.cleanup_new_directory(new_directory, scratch, [])
                self.assertEqual(sleep.call_count, 4)
            self.assertTrue(new_directory.exists())

    def test_input_failure_publishes_nonzero_report_without_exception_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = argparse.Namespace(artifact_label="unit-only", gateway=root / "missing.exe",
                bootstrap_helper=root / "missing-helper.exe", out=root / "result.json")
            with contextlib.redirect_stdout(io.StringIO()), \
                    patch.object(DRIVER, "start_child") as start:
                result = DRIVER.run(args)
            start.assert_not_called()
            report = json.loads(args.out.read_text())
            self.assertEqual(result, 1)
            self.assertFalse(report["passed"])
            self.assertFalse(report["cleanup_passed"])
            self.assertNotIn("missing.exe", args.out.read_text())
            self.assertNotIn("exception", report)

    def test_output_cannot_overwrite_inputs_or_existing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ["gateway", "bootstrap_helper", "keycloak_zip", "jdk_zip", "existing_report"]:
                with self.subTest(name=name):
                    destination = root / name
                    destination.write_bytes(b"protected original bytes")
                    args = argparse.Namespace(artifact_label="unit-only", gateway=root / "gateway",
                        bootstrap_helper=root / "bootstrap_helper", keycloak_zip=root / "keycloak_zip",
                        jdk_zip=root / "jdk_zip", out=destination)
                    with contextlib.redirect_stdout(io.StringIO()), \
                            patch.object(DRIVER, "start_child") as start, \
                            patch.object(DRIVER, "sha256") as digest:
                        self.assertEqual(DRIVER.run(args), 1)
                    self.assertEqual(destination.read_bytes(), b"protected original bytes")
                    start.assert_not_called()
                    digest.assert_not_called()

    def test_invalid_output_parent_prevents_runtime_or_input_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "regular-file"
            parent.write_bytes(b"preserved parent")
            for output in [parent / "report.json", root / "missing-parent" / "report.json"]:
                args = argparse.Namespace(artifact_label="unit-only", gateway=root / "gateway",
                    bootstrap_helper=root / "helper", out=output)
                with contextlib.redirect_stdout(io.StringIO()), \
                        patch.object(DRIVER, "start_child") as start, \
                        patch.object(DRIVER, "certificate_files") as certificates, \
                        patch.object(DRIVER, "sha256") as digest:
                    self.assertEqual(DRIVER.run(args), 1)
                start.assert_not_called()
                certificates.assert_not_called()
                digest.assert_not_called()
                self.assertFalse(output.exists())
            self.assertEqual(parent.read_bytes(), b"preserved parent")

    def test_atomic_output_failure_preserves_incomplete_snapshot_and_rejects_nan(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            pending = {"passed": False, "checks": [{"name": "already-observed", "passed": True}]}
            output = DRIVER.ReportOutput(path, [], pending)
            previous = path.read_bytes()
            with patch.object(DRIVER.os, "replace", side_effect=OSError("private detail")):
                with self.assertRaises(OSError):
                    output.publish({"passed": True})
            self.assertEqual(path.read_bytes(), previous)
            self.assertEqual(json.loads(path.read_text()), pending)
            with self.assertRaises(ValueError):
                output.publish({"passed": True, "invalid": float("nan")})
            self.assertEqual(path.read_bytes(), previous)
            self.assertEqual(list(path.parent.iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
