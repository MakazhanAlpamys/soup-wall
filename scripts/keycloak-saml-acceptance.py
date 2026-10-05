#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Manual Windows SAML acceptance against an isolated, genuine Keycloak runtime.

Requires the pinned official runtime archives, Python cryptography/requests/psutil, an
unchanged Gateway binary, and the disposable database bootstrap example. No
upstream source, metadata, assertions, credentials, or runtime logs are published.
"""

import argparse
import base64
from contextlib import ExitStack
import datetime as dt
import hashlib
from html.parser import HTMLParser
import http.server
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
import zipfile

import ipaddress


RUNTIMES = {
    "keycloak": {
        "version": "26.8.0",
        "size": 174169645,
        "sha256": "7ed1de3fda2598369262613bf682aab7e233d80a38c405e91588f7a7454370a1",
        "url": "https://github.com/keycloak/keycloak/releases/download/26.8.0/keycloak-26.8.0.zip",
        "license": "Apache-2.0",
    },
    "jdk": {
        "version": "Temurin 25.0.4.1+1",
        "size": 141167264,
        "sha256": "00c847d804f4a78e9f04f2683faf14fed898535b177b7fc704486cb0284e9283",
        "url": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/OpenJDK25U-jdk_x64_windows_hotspot_25.0.4.1_1.zip",
        "license": "GPL-2.0 WITH Classpath-exception-2.0; bundled notices apply",
    },
}
NS = {"md": "urn:oasis:names:tc:SAML:2.0:metadata",
      "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
      "ds": "http://www.w3.org/2000/09/xmldsig#"}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scratch_directory(root):
    """Keep private vendor material below the checkout's real ignored target."""
    root = Path(root).resolve()
    target = root / "target"
    scratch = target / "keycloak-saml"
    for folder in (target, scratch):
        if (folder.is_symlink() or (hasattr(folder, "is_junction") and folder.is_junction())
                or folder.resolve() != folder.absolute()):
            raise RuntimeError("private runtime scratch must not be a redirected path")
    scratch.mkdir(parents=True, exist_ok=True)
    if scratch.resolve() != scratch.absolute():
        raise RuntimeError("private runtime scratch changed during preparation")
    return scratch


class ReportOutput:
    """Reserve a fresh writable output before allocating any vendor resources."""

    def __init__(self, destination, protected, report):
        self.path = Path(destination).resolve()
        if any(self.path == Path(source).resolve() for source in protected if source is not None):
            raise RuntimeError("evidence output aliases a protected input")
        if not self.path.parent.is_dir():
            raise RuntimeError("evidence output needs an existing parent directory")
        # Refuse every existing output, including hardlinks to source binaries.
        with self.path.open("xb"):
            pass
        self.identity = self.file_identity()
        self.publish(report)

    def file_identity(self):
        status = self.path.stat()
        return status.st_dev, status.st_ino

    def publish(self, report):
        serialized = json.dumps(report, indent=2, allow_nan=False) + "\n"
        if self.file_identity() != self.identity:
            raise RuntimeError("reserved evidence output identity changed")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                    prefix="." + self.path.name + ".", suffix=".tmp", dir=self.path.parent,
                    delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            if self.file_identity() != self.identity:
                raise RuntimeError("reserved evidence output identity changed")
            os.replace(temporary, self.path)
            temporary = None
            self.identity = self.file_identity()
        finally:
            if temporary is not None:
                # Only this method's freshly allocated output temporary file.
                temporary.unlink(missing_ok=True)


def unpack(archive, destination, spec):
    if archive.stat().st_size != spec["size"] or sha256(archive) != spec["sha256"]:
        raise RuntimeError("official archive checksum mismatch")
    destination.mkdir()
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            if not (destination / member.filename).resolve().is_relative_to(destination.resolve()):
                raise RuntimeError("archive path escaped the disposable runtime")
        bundle.extractall(destination)
    roots = [path for path in destination.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise RuntimeError("unexpected runtime archive layout")
    return roots[0]


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def child_environment(directory):
    # Only the Windows installation root is inherited. Never forward PATH,
    # profiles, provider/deployment credentials, proxies, or runtime overrides.
    windows = Path(os.environ["SYSTEMROOT"]).resolve()
    profile = directory / "profile"
    locations = {"HOME": profile, "USERPROFILE": profile,
                 "APPDATA": profile / "AppData" / "Roaming",
                 "LOCALAPPDATA": profile / "AppData" / "Local",
                 "TEMP": directory / "tmp", "TMP": directory / "tmp"}
    for location in locations.values():
        location.mkdir(parents=True, exist_ok=True)
    return {"SYSTEMROOT": str(windows), "WINDIR": str(windows),
            "COMSPEC": str(windows / "System32" / "cmd.exe"),
            "PATH": os.pathsep.join(str(path) for path in [
                windows / "System32", windows, windows / "System32" / "Wbem"]),
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            **{name: str(location) for name, location in locations.items()}}


def loopback_backend_url(port, path):
    parsed = urllib.parse.urlsplit(path)
    if (not isinstance(port, int) or not 0 < port < 65536 or not path.startswith("/")
            or path.startswith("//") or parsed.scheme or parsed.netloc or parsed.fragment
            or "\\" in path or any(ord(character) < 32 for character in path)):
        raise RuntimeError("edge refused a non-loopback request target")
    return f"http://127.0.0.1:{port}" + path


def forward_gateway(port, path, method, headers, data):
    # A separate session per request is safe for ThreadingHTTPServer. Ambient
    # proxy and netrc lookup are disabled on this internal hop as on the driver.
    destination = loopback_backend_url(port, path)
    import requests

    with requests.Session() as backend:
        backend.trust_env = False
        return backend.request(method, destination, headers=headers, data=data,
                               timeout=10, allow_redirects=False)


def tamper_nameid(assertion, subject, provisioned_alias):
    # Both identities are pre-linked to authorized local workspace owners.
    # An unknown NameID would confound a signature-negative check with an
    # authorization rejection. Preserve XML bytes except this negative mutation.
    if subject == provisioned_alias:
        raise RuntimeError("negative assertion mutation needs a different alias")
    pattern = re.compile(rb"(<(?P<prefix>[A-Za-z_][\w.-]*:)?NameID\b[^>]*>)"
                         + re.escape(subject.encode()) + rb"(</(?P=prefix)?NameID>)")
    matches = list(pattern.finditer(assertion))
    if len(matches) != 1:
        raise RuntimeError("vendor assertion did not contain one expected NameID")
    match = matches[0]
    return (assertion[:match.start()] + match.group(1) + provisioned_alias.encode()
            + match.group(3) + assertion[match.end():])


def stop_child(child):
    import psutil

    if child.poll() is None:
        try:
            parent = psutil.Process(child.pid)
            owned = parent.children(recursive=True) + [parent]
        except psutil.NoSuchProcess:
            child.soup_tree_stopped = True
            return
        # The batch launcher owns a Java descendant. Restrict termination to
        # this live child PID and its descendants; never kill Java by name.
        subprocess.run([str(Path(child.soup_environment["SYSTEMROOT"]) / "System32" / "taskkill.exe"),
                        "/PID", str(child.pid), "/T", "/F"], env=child.soup_environment,
                       capture_output=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        child.wait(timeout=20)
        _, alive = psutil.wait_procs(owned, timeout=10)
        if alive:
            raise RuntimeError("own child descendants did not exit")
    child.soup_tree_stopped = True


def cleanup_new_directory(directory, scratch, children):
    """Only clean the fresh directory allocated by this invocation.

    There is deliberately no CLI for adopting or deleting an existing failed
    profile. Never use this function to retry an approval-denied removal.
    """
    resolved = directory.resolve()
    if not resolved.is_relative_to(scratch.resolve()) or not directory.name.startswith(
            "soup-wall-keycloak-session-"):
        raise RuntimeError("cleanup target is not the newly owned scratch directory")
    if any(child.poll() is None or not child.soup_tree_stopped for child in children):
        raise RuntimeError("own children remain active; preserving the new scratch directory")
    # Only transient Windows unlink failures get brief bounded retries, after
    # the owning child trees have been stopped and waited for. Do not ignore a
    # persistent error or schedule later deletion.
    for attempt in range(5):
        try:
            shutil.rmtree(resolved)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.25)


def start_child(command, directory, environment, log, resources):
    child = subprocess.Popen(command, cwd=directory, env=environment, stdout=log, stderr=log,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    child.soup_tree_stopped = False
    child.soup_environment = environment
    resources.callback(stop_child, child)
    return child


def certificate_files(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable Soup Wall CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=5))
          .not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False),
                         critical=True).sign(ca_key, hashes.SHA256()))
    ca_path = directory / "driver-ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def leaf(name, tls=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                   .issuer_name(ca_name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - dt.timedelta(minutes=5))
                   .not_valid_after(now + dt.timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
        if tls:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False)
        certificate = builder.sign(ca_key, hashes.SHA256())
        cert_path = directory / f"{name}.pem"
        key_path = directory / f"{name}-key.pem"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return cert_path, key_path

    return ca_path, leaf("loopback-server", tls=True), leaf("soup-wall-sp")


class Forms(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {"action": attrs.get("action", ""), "id": attrs.get("id", ""),
                            "method": attrs.get("method", "get").lower(), "fields": {}}
            self.forms.append(self.current)
        if tag == "input" and self.current is not None and attrs.get("name"):
            self.current["fields"][attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


def run(args):
    report = {"schema_version": 1, "scope": "Windows local Keycloak SAML protocol acceptance",
              "started_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "artifact_label": args.artifact_label, "platform": platform.platform(),
              "python_version": platform.python_version(), "runtimes": RUNTIMES,
              "checks": [], "passed": False, "cleanup_passed": False,
              "limitations": ["No OIDC code exchange or vendor SCIM exercised",
                              "HTTP form driver; no browser UI or MFA acceptance",
                              "No managed staging or customer tenant",
                              "No Linux/macOS vendor runtime acceptance",
                              "Windows rsa advisory and issue #19 remain open",
                              "Gateway logout only; vendor SAML SLO not exercised"]}

    output = None

    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        output.publish(report)
        print(json.dumps({"check": name, "passed": bool(condition)}), flush=True)
        if not condition:
            raise RuntimeError(name)

    directory = None
    children = []
    phase = "evidence-output-reservation"
    try:
        output = ReportOutput(args.out, [getattr(args, name, None) for name in [
            "gateway", "bootstrap_helper", "keycloak_zip", "jdk_zip"]]
            + [Path(__file__), Path(__file__).resolve().parents[1]
               / "crates" / "proxy" / "src" / "saml_auth.rs"], report)
        phase = "input-validation"
        if os.name != "nt":
            raise RuntimeError("this pinned runtime checkpoint requires Windows")
        for module in ["requests", "cryptography", "psutil"]:
            if importlib.util.find_spec(module) is None:
                raise RuntimeError("manual vendor runtime dependency is unavailable")
        import requests

        scratch = scratch_directory(Path(__file__).resolve().parents[1])
        report["gateway_sha256"] = sha256(args.gateway)
        report["bootstrap_helper_sha256"] = sha256(args.bootstrap_helper)
        report["driver_sha256"] = sha256(__file__)
        report["saml_source_sha256"] = sha256(
            Path(__file__).resolve().parents[1] / "crates" / "proxy" / "src" / "saml_auth.rs")
        with ExitStack() as resources:
            temporary = tempfile.mkdtemp(prefix="soup-wall-keycloak-session-", dir=scratch)
            directory = Path(temporary).resolve()
            if not directory.is_relative_to(scratch.resolve()):
                raise RuntimeError("disposable runtime escaped the expected scratch directory")
            resources.callback(cleanup_new_directory, directory, scratch, children)
            phase = "portable-runtime-preparation"
            keycloak = unpack(args.keycloak_zip, directory / "keycloak", RUNTIMES["keycloak"])
            jdk = unpack(args.jdk_zip, directory / "jdk", RUNTIMES["jdk"])
            check("official-runtime-archive-checksums", True)
            check("runtime-license-notices-present", (keycloak / "LICENSE.txt").is_file()
                  and (jdk / "legal" / "java.base" / "LICENSE").is_file())
            ca, (tls_cert, tls_key), (sp_cert, sp_key) = certificate_files(directory)
            gateway_port, vendor_port = free_port(), free_port()
            suffix = uuid.uuid4().hex
            realm, unsigned_realm = "soup-" + suffix, "unsigned-" + suffix
            username, password = "synthetic-" + suffix, secrets.token_urlsafe(32)
            subject = username + "@example.test"
            provisioned_alias = "alias-" + subject
            sp_entity = "urn:soup-wall:keycloak:" + suffix
            vendor_base = f"https://127.0.0.1:{vendor_port}"
            issuer = vendor_base + "/realms/" + realm

            class Edge(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass

                def do_GET(self):
                    self.forward()

                def do_POST(self):
                    self.forward()

                def do_PUT(self):
                    self.forward()

                def forward(self):
                    length = int(self.headers.get("Content-Length", "0"))
                    if length > 2 * 1024 * 1024:
                        self.send_error(413)
                        return
                    data = self.rfile.read(length) if length else None
                    headers = {key: value for key, value in self.headers.items()
                               if key.lower() not in {"connection", "transfer-encoding"}}
                    try:
                        response = forward_gateway(gateway_port, self.path, self.command, headers, data)
                    except RuntimeError:
                        self.send_error(400)
                        return
                    self.send_response(response.status_code)
                    for key, value in response.headers.items():
                        if key.lower() not in {"connection", "transfer-encoding", "content-length",
                                               "content-encoding"}:
                            self.send_header(key, value)
                    self.send_header("Content-Length", str(len(response.content)))
                    self.end_headers()
                    self.wfile.write(response.content)

            edge = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Edge)
            resources.callback(edge.server_close)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(tls_cert, tls_key)
            edge.socket = context.wrap_socket(edge.socket, server_side=True)
            threading.Thread(target=edge.serve_forever, daemon=True).start()
            resources.callback(edge.shutdown)
            gateway_base = f"https://127.0.0.1:{edge.server_port}"
            acs = gateway_base + "/auth/saml/acs"
            allowed_origins = {vendor_base, gateway_base}

            session = resources.enter_context(requests.Session())
            session.trust_env = False
            session.verify = str(ca)

            def request(method, url, **kwargs):
                parsed = urllib.parse.urlsplit(url)
                if parsed.scheme + "://" + parsed.netloc not in allowed_origins:
                    raise RuntimeError("driver refused a non-disposable destination")
                return session.request(method, url, timeout=10, allow_redirects=False, **kwargs)

            client = {"clientId": sp_entity, "protocol": "saml", "enabled": True,
                      "redirectUris": [acs], "attributes": {
                          "saml.server.signature": "true", "saml.assertion.signature": "true",
                          "saml.client.signature": "true", "saml.signature.algorithm": "RSA_SHA256",
                          "saml.force.post.binding": "true", "saml.encrypt": "false",
                          "saml_name_id_format": "email", "saml_force_name_id_format": "true",
                          "saml_assertion_consumer_url_post": acs,
                          "saml.signing.certificate": "".join(sp_cert.read_text().splitlines()[1:-1])}}
            import_directory = keycloak / "data" / "import"
            import_directory.mkdir(parents=True)
            for name, signed in [(realm, True), (unsigned_realm, False)]:
                realm_document = {"realm": name, "enabled": True, "sslRequired": "all",
                                  "clients": [client], "users": [{"username": username,
                                    "enabled": True, "email": subject, "emailVerified": True,
                                    "firstName": "Synthetic", "lastName": "Acceptance",
                                    "credentials": [{"type": "password", "value": password,
                                                     "temporary": False}]}]}
                if signed:
                    realm_document["attributes"] = {"saml.signature.algorithm": "RSA_SHA256"}
                (import_directory / f"{name}-realm.json").write_text(
                    json.dumps(realm_document), encoding="utf-8")
            environment = child_environment(directory)
            vendor_environment = dict(environment, JAVA_HOME=str(jdk),
                                      JAVA_OPTS_APPEND='-Duser.home="' + environment["USERPROFILE"] + '"',
                                      PATH=str(jdk / "bin") + os.pathsep + environment.get("PATH", ""))
            vendor_log = resources.enter_context((directory / "vendor.log").open("wb"))
            vendor = start_child([environment["COMSPEC"], "/d", "/c", str(keycloak / "bin" / "kc.bat"),
                "start-dev", "--import-realm", "--http-enabled=false", "--http-host=127.0.0.1",
                f"--https-port={vendor_port}", f"--hostname={vendor_base}",
                f"--https-certificate-file={tls_cert}", f"--https-certificate-key-file={tls_key}",
                "--log-level=warn"], directory, vendor_environment, vendor_log, resources)
            children.append(vendor)
            phase = "vendor-startup"
            metadata_url = issuer + "/protocol/saml/descriptor"
            metadata_response = None
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and vendor.poll() is None:
                try:
                    metadata_response = request("GET", metadata_url)
                    if metadata_response.status_code == 200:
                        break
                except requests.RequestException:
                    pass
                time.sleep(0.5)
            check("vendor-runtime-ready-over-verified-private-ca-https",
                  metadata_response is not None and metadata_response.status_code == 200)
            metadata = metadata_response.text
            signed_tree = ET.fromstring(metadata)
            check("vendor-signed-idp-descriptor", signed_tree.find("ds:Signature", NS) is not None)
            vendor_certificate = signed_tree.find("md:IDPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/"
                                                  "ds:X509Data/ds:X509Certificate", NS).text
            vendor_certificate = "".join(vendor_certificate.split())
            pinned_certificate = "-----BEGIN CERTIFICATE-----\n" + "\n".join(
                vendor_certificate[pos:pos + 64] for pos in range(0, len(vendor_certificate), 64))
            pinned_certificate += "\n-----END CERTIFICATE-----\n"
            report["vendor_metadata_sha256"] = hashlib.sha256(metadata_response.content).hexdigest()
            report["vendor_signing_certificate_sha256"] = hashlib.sha256(
                base64.b64decode(vendor_certificate)).hexdigest()

            database = directory / "gateway.sqlite"
            bootstrap = subprocess.run([str(args.bootstrap_helper), str(database), issuer, subject,
                                        provisioned_alias],
                env=environment, cwd=directory, capture_output=True, timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW)
            check("preprovisioned-local-membership-without-idp-role-grants", bootstrap.returncode == 0)
            scope = json.loads(bootstrap.stdout)
            admin = secrets.token_urlsafe(32)
            admin_headers = {"x-llm-firewall-admin-token": "Bearer " + admin}
            gateway_environment = dict(environment, SOUP_KEYCLOAK_ADMIN_TOKEN=admin,
                LLM_FW_OIDC_STATE_KEY=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="),
                LLM_FW_SAML_SP_ENTITY_ID=sp_entity, LLM_FW_SAML_ACS_URL=acs,
                LLM_FW_SAML_SP_PRIVATE_KEY_PEM=sp_key.read_text(),
                LLM_FW_SAML_SP_CERTIFICATE_PEM=sp_cert.read_text(),
                RUST_LOG="error")
            (directory / "policy.yaml").write_text("policies: []\ndefault: allow\n", encoding="utf-8")
            (directory / "firewall.yaml").write_text(
                f'bind: "127.0.0.1:{gateway_port}"\ntenant_store:\n  enabled: true\n'
                '  backend: sqlite\n  database_path: "gateway.sqlite"\n'
                '  admin_token_env: "SOUP_KEYCLOAK_ADMIN_TOKEN"\npolicy_file: "policy.yaml"\n'
                'fail_mode: fail_closed\n', encoding="utf-8")
            gateway_log = resources.enter_context((directory / "gateway.log").open("wb"))
            gateway = start_child([str(args.gateway)], directory, gateway_environment, gateway_log, resources)
            children.append(gateway)
            phase = "gateway-startup"
            deadline = time.monotonic() + 30
            ready = False
            while time.monotonic() < deadline and gateway.poll() is None:
                try:
                    ready = request("GET", gateway_base + "/readyz").status_code == 200
                    if ready:
                        break
                except requests.RequestException:
                    pass
                time.sleep(0.2)
            check("unchanged-gateway-ready-through-local-https-edge", ready)
            connection_url = gateway_base + "/admin/v1/organizations/" + scope["organization_id"] + "/saml"
            start_url = gateway_base + "/auth/saml/start?" + urllib.parse.urlencode(scope)

            unsigned_response = request("GET", vendor_base + "/realms/" + unsigned_realm
                                        + "/protocol/saml/descriptor")
            unsigned_tree = ET.fromstring(unsigned_response.text)
            check("vendor-default-descriptor-is-unsigned",
                  unsigned_response.status_code == 200 and unsigned_tree.find("ds:Signature", NS) is None)
            unsigned_certificate = unsigned_tree.find("md:IDPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/"
                                                      "ds:X509Data/ds:X509Certificate", NS).text
            unsigned_certificate = "".join(unsigned_certificate.split())
            unsigned_pin = "-----BEGIN CERTIFICATE-----\n" + "\n".join(
                unsigned_certificate[pos:pos + 64] for pos in range(0, len(unsigned_certificate), 64))
            unsigned_pin += "\n-----END CERTIFICATE-----\n"
            unsigned_connection = {"entity_id": vendor_base + "/realms/" + unsigned_realm,
                                   "metadata_xml": unsigned_response.text,
                                   "metadata_signing_cert_pem": unsigned_pin, "active": True}
            check("unsigned-metadata-configuration-stored", request("PUT", connection_url,
                  json=unsigned_connection, headers=admin_headers).status_code == 200)
            rejected = request("GET", start_url)
            check("unsigned-vendor-idp-descriptor-rejected-before-login", rejected.status_code == 400)
            connection = {"entity_id": issuer, "metadata_xml": metadata,
                          "metadata_signing_cert_pem": pinned_certificate, "active": True}
            check("pinned-vendor-signed-metadata-imported", request("PUT", connection_url,
                  json=connection, headers=admin_headers).status_code == 200)

            def obtain_assertion():
                redirect = request("GET", start_url)
                if redirect.status_code != 303:
                    raise RuntimeError("SP login did not redirect")
                auth_url = redirect.headers["Location"]
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(auth_url).query)
                if "Signature" not in query or "SigAlg" not in query:
                    raise RuntimeError("SP request was not signed")
                response = request("GET", auth_url)
                for _ in range(8):
                    if response.status_code in {302, 303}:
                        response = request("GET", urllib.parse.urljoin(response.url, response.headers["Location"]))
                        continue
                    forms = Forms(response.text).forms
                    assertion = next((form for form in forms if "SAMLResponse" in form["fields"]), None)
                    if assertion is not None:
                        action = urllib.parse.urljoin(response.url, assertion["action"])
                        if action != acs or assertion["method"] != "post":
                            raise RuntimeError("vendor response targeted an unexpected ACS")
                        return assertion["fields"]
                    login = next((form for form in forms if form["id"] == "kc-form-login"), None)
                    if login is None or login["method"] != "post":
                        raise RuntimeError("vendor login form was not available")
                    fields = dict(login["fields"], username=username, password=password)
                    response = request("POST", urllib.parse.urljoin(response.url, login["action"]), data=fields)
                raise RuntimeError("vendor browser flow exceeded the bounded redirect count")

            phase = "vendor-saml-login-and-session"
            assertion_fields = obtain_assertion()
            assertion_bytes = base64.b64decode(assertion_fields["SAMLResponse"], validate=True)
            assertion_tree = ET.fromstring(assertion_bytes)
            check("real-vendor-signed-plaintext-assertion",
                  assertion_tree.find("saml:Assertion/ds:Signature", NS) is not None
                  and assertion_tree.find("saml:EncryptedAssertion", NS) is None)
            check("vendor-nameid-matches-preprovisioned-synthetic-identity",
                  assertion_tree.find("saml:Assertion/saml:Subject/saml:NameID", NS).text == subject)
            accepted = request("POST", acs, data=assertion_fields)
            check("real-vendor-assertion-accepted-by-production-acs", accepted.status_code == 303)
            cookie = accepted.headers.get("Set-Cookie", "")
            check("secure-host-only-httponly-session-cookie", cookie.startswith("__Host-llm-fw-session=")
                  and all(value in cookie for value in ["; Path=/", "; Secure", "; HttpOnly", "; SameSite=Lax"])
                  and "Domain=" not in cookie)
            old_cookie = cookie.split(";", 1)[0]
            check("session-resolves-preprovisioned-owner-membership", request("GET",
                  gateway_base + "/customer/v1/session").json()["access"]["role"] == "owner")
            check("vendor-assertion-replay-rejected", request("POST", acs, data=assertion_fields).status_code == 400)

            tampered = obtain_assertion()
            original = base64.b64decode(tampered["SAMLResponse"], validate=True)
            tampered["SAMLResponse"] = base64.b64encode(
                tamper_nameid(original, subject, provisioned_alias)).decode()
            rejected = request("POST", acs, data=tampered)
            check("tampered-vendor-signed-nameid-rejected", rejected.status_code == 400
                  and "Set-Cookie" not in rejected.headers)
            csrf = request("GET", gateway_base + "/customer/v1/csrf").json()["token"]
            rotated = request("POST", gateway_base + "/auth/session/rotate",
                              headers={"x-llm-firewall-csrf-token": csrf})
            new_cookie = rotated.headers.get("Set-Cookie", "").split(";", 1)[0]
            check("saml-session-rotation-issues-new-cookie", rotated.status_code == 204
                  and new_cookie.startswith("__Host-llm-fw-session=") and new_cookie != old_cookie)
            check("old-session-rejected-after-rotation", request("GET", gateway_base
                  + "/customer/v1/session", headers={"Cookie": old_cookie}).status_code == 401)
            check("rotated-session-accepted", request("GET", gateway_base
                  + "/customer/v1/session").status_code == 200)
            check("gateway-session-logout", request("POST", gateway_base + "/auth/logout").status_code == 204)
            check("logged-out-session-rejected", request("GET", gateway_base
                  + "/customer/v1/session", headers={"Cookie": new_cookie}).status_code == 401)
            phase = "owned-runtime-teardown"
        check("own-child-processes-and-disposable-runtime-cleaned", not directory.exists()
              and all(child.poll() is not None for child in children))
        report["cleanup_passed"] = True
        report["passed"] = True
    except Exception as error:
        # Exception text may contain URLs, form fields or credentials. Keep it
        # private; the latest named check identifies the failed acceptance step.
        report["passed"] = False
        report["failure_type"] = type(error).__name__
        report["failure_phase"] = phase
        report["failure_errno"] = getattr(error, "errno", None)
        report["failure_winerror"] = getattr(error, "winerror", None)
        if directory is not None:
            # An exact operator cleanup target is useful; no raw private file
            # contents or exception URLs are included in the evidence.
            report["cleanup_passed"] = not directory.exists() and all(
                child.poll() is not None for child in children)
            if not report["cleanup_passed"]:
                report["operator_cleanup_directory"] = str(directory)
    report["finished_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    publication_failed = output is None
    if output is not None:
        try:
            output.publish(report)
        except Exception:
            # The previous atomic incomplete snapshot remains intact. Do not
            # fall back to a destructive in-place write or disclose exceptions.
            publication_failed = True
    if publication_failed:
        report["passed"] = False
    print(json.dumps({"passed": report["passed"], "checks": len(report["checks"]),
                      "publication_failed": publication_failed}), flush=True)
    return 0 if report["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["keycloak-zip", "jdk-zip", "gateway", "bootstrap-helper", "out"]:
        parser.add_argument("--" + name, required=True, type=lambda value: Path(value).resolve())
    parser.add_argument("--artifact-label", required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
