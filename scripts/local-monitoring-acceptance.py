#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in real Gateway/Prometheus/Alertmanager outage delivery with disposable local state."""
import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile


ALERT = "LLMFirewallGatewayTargetDown"
JOB = "soup-wall-gateway"
BASELINE = "934653821f73dd702dfe5b8977c6c5ea751ad28a"
GATEWAY_ARCHIVE_SHA256 = "0502b8d6f8596d72c1168d8ccd4efc71c707f14b8cc3e36eb062a8169c9c75a7"
TOOL_ARCHIVE_SHA256 = {
    "prometheus": "5d333b385557d9adc2ff015d13da9809baccc52fb800a82d1e5c94b79258f87e",
    "alertmanager": "69624d6ce3674dbcf8cefc5a93d7028d00bbd5e0196a8384907f51593a495fef",
}
TOOL_CHECKSUMS_SHA256 = {
    "prometheus": "023cab1e6b275ee1b8f5f64215a01d74bbb1b19c45183b7296ced4aa4532707b",
    "alertmanager": "0872f3f38d4688872dd9064243d09006ead668690585522e366e624f23931778",
}
REPO = Path(__file__).resolve().parents[1]


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def file_hash(path):
    with path.open("rb") as source:
        return stream_hash(source)


def stream_hash(source):
    result = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        result.update(chunk)
    return result.hexdigest()


class AcceptanceError(RuntimeError):
    pass


class EvidenceOutput:
    def __init__(self, destination):
        self.destination = destination.absolute()
        if not self.destination.parent.is_dir():
            raise AcceptanceError("Evidence parent must already exist")
        try:
            with self.destination.open("x", encoding="utf-8") as output:
                json.dump({"status": "reserved", "managed_staging_validated": False}, output)
                output.flush()
                os.fsync(output.fileno())
                self.identity = os.fstat(output.fileno()).st_ino
        except OSError:
            raise AcceptanceError("Evidence must be fresh and writable") from None

    def publish(self, report):
        if self.destination.stat().st_ino != self.identity:
            raise AcceptanceError("Reserved evidence was replaced")
        descriptor, temporary = tempfile.mkstemp(prefix="monitoring-evidence-", suffix=".tmp", dir=self.destination.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(report, output, indent=2, allow_nan=False)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.destination)
        finally:
            Path(temporary).unlink(missing_ok=True)


def isolated_environment(directory):
    keep = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "SYSTEMDRIVE", "PROGRAMFILES", "PROGRAMFILES(X86)"}
    result = {key: value for key, value in os.environ.items() if key.upper() in keep}
    result.update(HOME=str(directory), USERPROFILE=str(directory), APPDATA=str(directory),
                  LOCALAPPDATA=str(directory), TEMP=str(directory), TMP=str(directory))
    return result


def free_ports(count):
    sockets = [socket.socket() for _ in range(count)]
    try:
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in sockets]
    finally:
        for listener in sockets:
            listener.close()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def target_directory():
    base = REPO.resolve() / "target"
    if (base.is_symlink() or (hasattr(base, "is_junction") and base.is_junction())
            or base.resolve() != base or not base.is_dir()):
        raise AcceptanceError("Generated runtimes require this checkout's existing unlinked target directory")
    return base


def request(url, body=None, headers=None):
    destination = urllib.parse.urlsplit(url)
    if (destination.scheme != "http" or destination.hostname != "127.0.0.1"
            or destination.username is not None or destination.password is not None
            or destination.port is None):
        raise AcceptanceError("Acceptance HTTP requests require an explicit numeric loopback destination")
    transport = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    message = urllib.request.Request(url, body, headers or {})
    with transport.open(message, timeout=3) as response:
        raw = response.read(262145)
        if response.status != 200 or len(raw) > 262144:
            raise AcceptanceError("Unexpected local HTTP response")
        return raw


class Receiver(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, token, instance):
        super().__init__(("127.0.0.1", 0), ReceiverHandler)
        self.token, self.instance = token, instance
        self.receipts = []
        self.rejected = 0
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def seen(self, state):
        with self.lock:
            return [row.copy() for row in self.receipts if row["status"] == state]

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


class ReceiverHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.connection.settimeout(3)
        expected = "Bearer " + self.server.token
        authorized = hmac.compare_digest(self.headers.get("Authorization", "").encode("utf-8"), expected.encode("utf-8"))
        if self.path != "/alerts" or not authorized:
            with self.server.lock:
                self.server.rejected += 1
            # Drain a bounded fixture body before closing, avoiding a reset that
            # can hide the 401 response on Windows when unread bytes remain.
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if 0 < length <= 65536:
                    self.rfile.read(length)
            except (ValueError, OSError):
                pass
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError()
            raw = self.rfile.read(length)
            payload = json.loads(raw)
            if (not isinstance(payload, dict) or payload.get("version") != "4"
                    or not isinstance(payload.get("alerts"), list)):
                raise ValueError()
            rows = []
            for alert in payload["alerts"]:
                if not isinstance(alert, dict) or not isinstance(alert.get("labels"), dict):
                    raise ValueError()
                labels = alert["labels"]
                if (labels.get("alertname") != ALERT or labels.get("job") != JOB
                        or labels.get("instance") != self.server.instance
                        or alert.get("status") not in {"firing", "resolved"}):
                    raise ValueError()
                if not isinstance(alert.get("startsAt"), str) or not isinstance(alert.get("endsAt"), str):
                    raise ValueError()
                rows.append({"status": alert["status"], "observed_at_utc": timestamp(),
                    "authenticated": True, "body_sha256": digest(raw),
                    "starts_at": alert["startsAt"], "ends_at": alert["endsAt"]})
            if not rows:
                raise ValueError()
        except (ValueError, TypeError, KeyError, OSError, http.client.HTTPException):
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        with self.server.lock:
            self.server.receipts.extend(rows)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def stop_child(child):
    if child is None:
        return
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)


def cleanup_directory(directory, parent):
    # No wildcard or stale-path cleanup. Only the directory created by this run.
    if directory.is_symlink() or (hasattr(directory, "is_junction") and directory.is_junction()):
        raise AcceptanceError("Generated runtime became a reparse link; refusing cleanup")
    resolved = directory.resolve()
    if resolved.parent != parent.resolve() or not resolved.name.startswith("soup-monitoring-"):
        raise AcceptanceError("Refusing cleanup outside the owned generated runtime")
    shutil.rmtree(resolved)


def restrict_runtime(directory, environment):
    if os.name != "nt":
        directory.chmod(0o700)
        return
    # Apply the ACL before writing any generated credential. No profile scripts,
    # user trust stores, services, or paths outside this generated directory change.
    command = "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;" \
        "& icacls.exe $env:SOUP_MONITORING_PROFILE /inheritance:r /grant:r ('*'+$sid+':(OI)(CI)F') >$null;" \
        "exit $LASTEXITCODE"
    controlled = dict(environment, SOUP_MONITORING_PROFILE=str(directory))
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        env=controlled, capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode != 0:
        raise AcceptanceError("Could not restrict the generated runtime ACL before writing credentials")


def verify_inputs(args):
    manifest_bytes = args.tools_manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    pins = {"prometheus": "3.15.0", "alertmanager": "0.34.1"}
    inventory = {"prometheus": {"prometheus.exe", "promtool.exe"},
                 "alertmanager": {"alertmanager.exe", "amtool.exe"}}
    required = {"version", "archive", "archive_sha256", "checksums_sha256", "official_release",
                "licenses_sha256", "executables_sha256"}
    if (not isinstance(manifest, dict) or set(manifest) != {"schema_version", "platform", "tools"}
            or manifest["schema_version"] != 1 or manifest["platform"] != "windows-amd64"
            or not isinstance(manifest["tools"], dict) or set(manifest["tools"]) != set(pins)):
        raise AcceptanceError("Monitoring manifest has an unexpected schema")
    for name in pins:
        tool = manifest["tools"][name]
        if (not isinstance(tool, dict) or set(tool) != required
                or not isinstance(tool["executables_sha256"], dict)
                or set(tool["executables_sha256"]) != inventory[name]
                or not isinstance(tool["licenses_sha256"], dict)
                or set(tool["licenses_sha256"]) != {"LICENSE", "NOTICE"}):
            raise AcceptanceError("Monitoring manifest has an unexpected tool inventory")
    for name, binary, executable in [("prometheus", args.prometheus, "prometheus.exe"),
                                     ("prometheus", args.promtool, "promtool.exe"),
                                     ("alertmanager", args.alertmanager, "alertmanager.exe")]:
        tool = manifest["tools"][name]
        expected_archive = f"{name}-{pins[name]}.windows-amd64.zip"
        archive = args.tools_manifest.parent / expected_archive
        checksums = args.tools_manifest.parent / f"{name}-{pins[name]}-sha256sums.txt"
        if (tool["version"] != pins[name] or tool["archive"] != expected_archive
                or tool["archive_sha256"] != TOOL_ARCHIVE_SHA256[name]
                or tool["checksums_sha256"] != TOOL_CHECKSUMS_SHA256[name]
                or file_hash(checksums) != TOOL_CHECKSUMS_SHA256[name]
                or tool["official_release"] != f"https://github.com/prometheus/{name}/releases/download/v{pins[name]}/"
                or file_hash(archive) != TOOL_ARCHIVE_SHA256[name]
                or tool["executables_sha256"][executable] != file_hash(binary)):
            raise AcceptanceError("Selected monitoring executable differs from the verified pinned manifest")
        with zipfile.ZipFile(archive) as bundle, bundle.open(f"{archive.stem}/{executable}") as source:
            if stream_hash(source) != file_hash(binary):
                raise AcceptanceError("Monitoring executable does not equal its verified official archive member")
            for filename in ["LICENSE", "NOTICE"]:
                with bundle.open(f"{archive.stem}/{filename}") as license_file:
                    if tool["licenses_sha256"][filename] != stream_hash(license_file):
                        raise AcceptanceError("Monitoring license metadata differs from its official archive")
            for filename in inventory[name]:
                with bundle.open(f"{archive.stem}/{filename}") as archive_file:
                    if tool["executables_sha256"][filename] != stream_hash(archive_file):
                        raise AcceptanceError("Monitoring executable inventory differs from its official archive")
    if file_hash(args.gateway_archive) != GATEWAY_ARCHIVE_SHA256 or args.artifact_label != "v0.4.0":
        raise AcceptanceError("This published-binary checkpoint requires the verified v0.4.0 Windows archive")
    with zipfile.ZipFile(args.gateway_archive) as archive:
        names = [name for name in archive.namelist() if name.endswith("/llm-firewall.exe")]
        if len(names) != 1:
            raise AcceptanceError("Published Gateway archive has an unexpected inventory")
        with archive.open(names[0]) as source:
            if stream_hash(source) != file_hash(args.gateway):
                raise AcceptanceError("Selected Gateway differs from the verified published archive")
    return manifest, digest(manifest_bytes)


def run(args):
    report = {"schema_version": 1, "started_at_utc": timestamp(), "status": "incomplete",
        "evidence_scope": "local-published-gateway-real-monitoring-authenticated-loopback-receiver",
        "artifact_label": args.artifact_label, "managed_staging_validated": False,
        "staffed_notification_channel_validated": False, "model_requests_sent": 0,
        "checks": [], "phases": [], "notifications": [],
        "settings": {"job_name": JOB, "alertname": ALERT, "for_seconds": 120,
                     "rule_group_interval_seconds": 30, "scrape_interval_seconds": 5,
                     "receiver_group_wait_seconds": 1, "receiver_group_interval_seconds": 5,
                     "send_resolved": True, "alertmanager_cluster_enabled": False},
        "limitations": ["Loopback HTTP with disposable receiver authentication",
            "Gateway process stop exercises scrape-target loss, not PostgreSQL/Redis failure",
            "No detector/block alert, Gateway policy webhook, managed TLS, or staffed channel claim"]}
    children, logs = [], []
    receiver = None
    directory = None
    parent = REPO / "target"

    def check(name, condition):
        report["checks"].append({"name": name, "status": "passed" if condition else "failed"})
        if not condition:
            raise AcceptanceError(name)

    def phase(name, **values):
        report["phases"].append({"name": name, "observed_at_utc": timestamp(), **values})
        print(f"{name}: observed", flush=True)

    def invoke(command, cwd=None):
        return subprocess.run(command, cwd=cwd or directory, env=environment,
            capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)

    def start(binary, arguments, label):
        log = (directory / f"{label}.log").open("ab")
        logs.append(log)
        child = subprocess.Popen([str(binary), *arguments], cwd=directory, env=environment,
            stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        children.append(child)
        return child

    def wait_for(name, predicate, timeout, owned=()):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(child.poll() is not None for child in owned):
                raise AcceptanceError(f"Owned child exited while waiting for {name}")
            try:
                if predicate():
                    check(name, True)
                    return
            except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
                pass
            time.sleep(1)
        check(name, False)

    try:
        manifest, manifest_hash = verify_inputs(args)
        rules_bytes = (REPO / "deploy/prometheus-alerts.yaml").read_bytes()
        test_bytes = (REPO / "deploy/prometheus-alerts.test.yaml").read_bytes()
        baseline = subprocess.run(["git", "-C", str(REPO), "show", BASELINE + ":deploy/prometheus-alerts.yaml"],
                                  capture_output=True, check=True).stdout
        report.update(tools=manifest, tools_manifest_sha256=manifest_hash,
            gateway_binary_sha256=file_hash(args.gateway), gateway_archive_sha256=GATEWAY_ARCHIVE_SHA256,
            harness_sha256=file_hash(Path(__file__)), shipped_rules_sha256=digest(rules_bytes),
            regression_fixture_sha256=digest(test_bytes), baseline_revision=BASELINE,
            baseline_rules_sha256=digest(baseline))
        parent = target_directory()
        directory = Path(tempfile.mkdtemp(prefix="soup-monitoring-", dir=parent)).resolve()
        environment = isolated_environment(directory)
        restrict_runtime(directory, environment)
        environment["SOUP_MONITORING_ADMIN"] = secrets.token_urlsafe(32)
        (directory / "prometheus-alerts.yaml").write_bytes(rules_bytes)
        (directory / "prometheus-alerts.test.yaml").write_bytes(test_bytes)
        (directory / "baseline-rules.yaml").write_bytes(baseline)
        (directory / "baseline.test.yaml").write_bytes(test_bytes.replace(b"prometheus-alerts.yaml", b"baseline-rules.yaml"))
        check("official-archive-and-executable-bindings", True)
        check("shipped-seven-rules-valid", invoke([str(args.promtool), "check", "rules", "prometheus-alerts.yaml"]).returncode == 0)
        negative = invoke([str(args.promtool), "test", "rules", "baseline.test.yaml"])
        check("baseline-missing-target-outage-regression-reproduced", negative.returncode == 1
              and ALERT.encode() in negative.stdout + negative.stderr)
        check("fixed-down-stale-dependency-and-recovery-regressions", invoke(
            [str(args.promtool), "test", "rules", "prometheus-alerts.test.yaml"]).returncode == 0)
        gateway_port, prometheus_port, alertmanager_port = free_ports(3)
        instance = f"127.0.0.1:{gateway_port}"
        receiver_token = secrets.token_urlsafe(32)
        receiver = Receiver(receiver_token, instance)
        credential = directory / "receiver.token"
        credential.write_text(receiver_token, encoding="utf-8")
        if os.name != "nt":
            directory.chmod(0o700)
            credential.chmod(0o600)
        (directory / "policy.yaml").write_text("policies: []\ndefault: block\n", encoding="utf-8")
        (directory / "firewall.yaml").write_text(f"bind: '127.0.0.1:{gateway_port}'\n"
            "tenant_store:\n  enabled: true\n  backend: sqlite\n  database_path: 'acceptance.sqlite'\n"
            "  admin_token_env: 'SOUP_MONITORING_ADMIN'\npolicy_file: 'policy.yaml'\n"
            "upstream:\n  openai_base: 'http://127.0.0.1:9'\nfail_mode: fail_closed\n", encoding="utf-8")
        (directory / "alertmanager.yaml").write_text("route:\n  receiver: discard\n  group_by: [alertname, job, instance]\n"
            "  group_wait: 1s\n  group_interval: 5s\n  repeat_interval: 4h\n  routes:\n"
            f"    - matchers: ['alertname=\"{ALERT}\"']\n      receiver: local-proof\n"
            "receivers:\n  - name: discard\n  - name: local-proof\n    webhook_configs:\n"
            f"      - url: 'http://127.0.0.1:{receiver.server_port}/alerts'\n        send_resolved: true\n"
            "        http_config:\n          follow_redirects: false\n          proxy_from_environment: false\n"
            "          authorization:\n            credentials_file: receiver.token\n", encoding="utf-8")
        (directory / "prometheus.yaml").write_text("global:\n  scrape_interval: 5s\n  evaluation_interval: 30s\n"
            "rule_files: [prometheus-alerts.yaml]\nalerting:\n  alertmanagers:\n"
            f"    - static_configs:\n        - targets: ['127.0.0.1:{alertmanager_port}']\n"
            f"scrape_configs:\n  - job_name: {JOB}\n    follow_redirects: false\n"
            f"    proxy_from_environment: false\n    static_configs:\n      - targets: ['{instance}']\n", encoding="utf-8")
        report["configuration_sha256"] = {name: file_hash(directory / name) for name in
            ["firewall.yaml", "policy.yaml", "prometheus.yaml", "alertmanager.yaml"]}
        check("gateway-preflight", invoke([str(args.gateway), "preflight"]).returncode == 0)
        check("prometheus-config-valid", invoke([str(args.promtool), "check", "config", "prometheus.yaml"]).returncode == 0)
        gateway = start(args.gateway, [], "gateway")
        gateway_url = f"http://127.0.0.1:{gateway_port}"
        prometheus_url = f"http://127.0.0.1:{prometheus_port}"
        alertmanager_url = f"http://127.0.0.1:{alertmanager_port}"
        wait_for("gateway-ready", lambda: bool(request(gateway_url + "/readyz")), 30, [gateway])
        manager = start(args.alertmanager, ["--config.file=alertmanager.yaml", "--storage.path=alertmanager-data",
            f"--web.listen-address=127.0.0.1:{alertmanager_port}", "--cluster.listen-address=", "--log.level=warn"], "alertmanager")
        monitor = start(args.prometheus, ["--config.file=prometheus.yaml", "--storage.tsdb.path=prometheus-data",
            f"--web.listen-address=127.0.0.1:{prometheus_port}", "--storage.tsdb.retention.time=1h", "--log.level=warn"], "prometheus")
        wait_for("alertmanager-ready", lambda: bool(request(alertmanager_url + "/-/ready")), 30, [manager])
        wait_for("prometheus-ready", lambda: bool(request(prometheus_url + "/-/ready")), 30, [monitor])
        try:
            request(f"http://127.0.0.1:{receiver.server_port}/alerts", b"{}", {"Content-Type": "application/json"})
            check("receiver-rejects-missing-authentication", False)
        except urllib.error.HTTPError as error:
            check("receiver-rejects-missing-authentication", error.code == 401)

        def query(expression):
            reply = json.loads(request(prometheus_url + "/api/v1/query?" + urllib.parse.urlencode({"query": expression})))
            if reply.get("status") != "success":
                raise AcceptanceError("Local Prometheus query failed")
            return reply["data"]["result"]

        def state_of_rule():
            reply = json.loads(request(prometheus_url + "/api/v1/alerts"))
            return [row["state"] for row in reply["data"]["alerts"] if row["labels"].get("alertname") == ALERT]

        up = f'up{{job="{JOB}"}}'
        ready = f'llm_firewall_control_plane_ready{{job="{JOB}"}}'
        wait_for("healthy-target-scraped", lambda: query(up) and query(up)[0]["value"][1] == "1", 30, [gateway, monitor, manager])
        check("healthy-control-plane-metric", query(ready)[0]["value"][1] == "1")
        check("no-healthy-target-down-notification", not receiver.seen("firing") and not state_of_rule())
        phase("healthy", up=1, control_plane_ready=1)
        stop_child(gateway)
        stopped = time.monotonic()
        phase("owned-gateway-stopped")
        wait_for("stopped-target-scraped-down", lambda: query(up) and query(up)[0]["value"][1] == "0", 30, [monitor, manager])
        check("stopped-gateway-readiness-metric-is-absent", query(ready) == [])
        wait_for("new-rule-pending-before-firing", lambda: state_of_rule() == ["pending"], 60, [monitor, manager])
        check("for-duration-has-not-fired-early", not receiver.seen("firing"))
        phase("target-down-pending", up=0, control_plane_ready="absent")
        wait_for("authenticated-firing-notification", lambda: bool(receiver.seen("firing")), 200, [monitor, manager])
        elapsed = time.monotonic() - stopped
        check("original-two-minute-for-duration-preserved", elapsed >= 120)
        check("actual-prometheus-rule-firing", state_of_rule() == ["firing"])
        check("dependency-alert-not-fabricated", not query('ALERTS{alertname="LLMFirewallControlPlaneUnavailable",alertstate="firing"}'))
        phase("authenticated-firing", seconds_after_owned_gateway_stop=round(elapsed, 3))
        gateway = start(args.gateway, [], "gateway")
        wait_for("restarted-gateway-ready", lambda: bool(request(gateway_url + "/readyz")), 30, [gateway])
        wait_for("restarted-target-scraped-healthy", lambda: query(up) and query(up)[0]["value"][1] == "1", 30, [gateway, monitor, manager])
        wait_for("authenticated-resolved-notification", lambda: bool(receiver.seen("resolved")), 75, [gateway, monitor, manager])
        check("recovered-rule-inactive", not state_of_rule())
        check("resolved-notification-matches-firing-cycle", receiver.seen("resolved")[0]["starts_at"]
              == receiver.seen("firing")[0]["starts_at"])
        phase("authenticated-resolved", up=1, control_plane_ready=1)
        report["notifications"] = receiver.seen("firing") + receiver.seen("resolved")
        report["status"] = "passed"
    except Exception as error:
        report["failure"] = {"error_type": type(error).__name__}
    finally:
        cleanup_errors = []
        for child in reversed(children):
            try:
                stop_child(child)
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        if receiver is not None:
            report["notifications"] = receiver.seen("firing") + receiver.seen("resolved")
            try:
                receiver.close()
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        for log in logs:
            try:
                log.close()
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        if directory is not None:
            try:
                if any(child.poll() is None for child in children):
                    raise AcceptanceError("An owned child remains running; retaining its runtime")
                cleanup_directory(directory, parent)
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        report["cleanup"] = {"owned_children_stopped": all(child.poll() is not None for child in children),
            "generated_runtime_removed": directory is None or not directory.exists(), "errors": cleanup_errors}
        if cleanup_errors:
            report["status"] = "incomplete"
        report["observed_at_utc"] = timestamp()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Explicitly launch/stop owned local processes")
    for name in ["gateway", "gateway-archive", "prometheus", "promtool", "alertmanager", "tools-manifest", "out"]:
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--artifact-label")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({"mode": "manifest", "processes_started": 0, "alert": ALERT,
                          "for_seconds": 120, "managed_staging_validated": False}, indent=2))
        return 0
    required = [args.gateway, args.gateway_archive, args.prometheus, args.promtool,
                args.alertmanager, args.tools_manifest, args.out, args.artifact_label]
    if not all(required):
        parser.error("Execution requires explicit verified binaries/archive/manifest, artifact label, and fresh output")
    for name in ["gateway", "gateway_archive", "prometheus", "promtool", "alertmanager", "tools_manifest"]:
        setattr(args, name, getattr(args, name).resolve(strict=True))
    output = EvidenceOutput(args.out)
    report = run(args)
    output.publish(report)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
