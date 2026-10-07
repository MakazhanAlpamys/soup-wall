#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Repeatable native MCP execution/result acceptance with only owned local processes."""
import argparse
from contextlib import ExitStack
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "scripts/fixtures/local_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("owned_local_mcp_fixture", FIXTURE)
SERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERVER)
MAX_FRAME = 262144
POLICY = """agent_policies:
  - name: demo-secret-egress
    when: {detector: secret, facet: tool_args, min_action_class: network}
    action: deny
  - name: demo-pii-confirmation
    when: {detector: pii.email, facet: tool_args, min_action_class: network}
    action: ask
  - name: demo-result-confirmation
    when: {detector: injection, facet: tool_result, min_severity: high}
    action: ask
default: allow
"""


class AcceptanceError(RuntimeError):
    """A fixed diagnostic label; never include process output or credentials."""


def require(condition, label):
    if not condition:
        raise AcceptanceError(label)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def registry():
    return {"contract_version": "sw-native/1", "registry_id": "local-mcp-demo-v1", "tools": [
        {"name": tool["name"], "schema_sha256": digest(canonical(tool["inputSchema"])),
         "action_class": "network" if tool["name"] == "send_http" else "read_only",
         "result_provenance": "local_system" if tool["name"] == "send_http" else "untrusted",
         "egress": [{"pointer": "/url", "kind": "url_host", "optional": False}]
         if tool["name"] == "send_http" else []} for tool in SERVER.TOOLS]}


def child_environment(root):
    # Never inherit provider credentials, proxy settings, Python startup options,
    # Agent tokens or the user's real application profile.
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATHEXT",
               "PROGRAMFILES", "PROGRAMFILES(X86)", "LANG", "LC_ALL"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    private = root / "tmp"
    private.mkdir(mode=0o700)
    for key in ("HOME", "USERPROFILE"):
        env[key] = str(root)
    for key in ("TMPDIR", "TMP", "TEMP"):
        env[key] = str(private)
    for key in ("APPDATA", "LOCALAPPDATA"):
        path = root / key.lower()
        path.mkdir(mode=0o700)
        env[key] = str(path)
    return env


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            stream.close()


class Session:
    """Sequential bounded MCP client; transport errors never count as prevention."""
    def __init__(self, command, root, env):
        self.process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.closed = False

    def close(self):
        if not self.closed:
            # EOF lets the actual collector end its session and stop its server.
            # Termination is only a fallback after the bounded graceful wait.
            try:
                if self.process.stdin is not None:
                    try:
                        self.process.stdin.close()
                    except OSError:
                        pass
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            finally:
                stop(self.process)
                self.closed = True

    def exchange(self, raw):
        require(not self.closed and len(raw) <= SERVER.MAX_BYTES
                and raw.endswith(b"\n"), "invalid_harness_frame")
        try:
            self.process.stdin.write(raw)
            self.process.stdin.flush()
        except OSError:
            raise AcceptanceError("mcp_write_failed") from None
        output = queue.Queue(maxsize=1)

        def read():
            try:
                output.put(self.process.stdout.readline(MAX_FRAME + 1))
            except (OSError, ValueError):
                output.put(b"")

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        try:
            result = output.get(timeout=10)
        except queue.Empty:
            self.close()
            reader.join(timeout=1)
            raise AcceptanceError("mcp_response_timeout") from None
        require(bool(result) and len(result) <= MAX_FRAME and result.endswith(b"\n"),
                "mcp_response_missing_or_unbounded")
        request, reply = json.loads(raw), json.loads(result)
        require(isinstance(reply, dict) and reply.get("jsonrpc") == "2.0"
                and type(reply.get("id")) is type(request["id"])
                and reply.get("id") == request["id"], "mcp_response_identity_mismatch")
        return result

    def ready(self):
        self.exchange(frame(1, "initialize", {"protocolVersion": "2024-11-05",
            "capabilities": {}, "clientInfo": {"name": "soup-wall-local-harness", "version": "1"}}))
        self.process.stdin.write(frame(None, "notifications/initialized", {}))
        self.process.stdin.flush()
        manifest = json.loads(self.exchange(frame(2, "tools/list", {})))
        require(manifest.get("result", {}).get("tools") == SERVER.TOOLS, "manifest_not_original")


def frame(request_id, method, params):
    value = {"jsonrpc": "2.0", "method": method, "params": params}
    if request_id is not None:
        value["id"] = request_id
    # Native IDs, string arguments and harmless host metadata stay untouched.
    return (" { " + json.dumps(value, ensure_ascii=False)[1:-1] + " } \n").encode("utf-8")


def call(request_id, tool, arguments, progress):
    return frame(request_id, "tools/call", {"name": tool, "arguments": arguments,
        "_meta": {"claudecode/toolUseId": "toolu_demo_" + str(progress), "progressToken": progress}})


def ledger(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def entries_for(path, request_id):
    return sum(record["id"] == request_id for record in ledger(path))


def refused(raw, rule):
    value = json.loads(raw)
    require(value.get("result") == {"content": [{"type": "text", "text":
        f"Soup Wall withheld MCP {'result' if rule == 'demo-result-confirmation' else 'invocation'} ({rule})"}],
        "isError": True}, "expected_policy_refusal_missing")


class Receiver(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self):
        super().__init__(("127.0.0.1", 0), ReceiverHandler)
        self.receipts = []

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_port}/capture"


class ReceiverHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.connection.settimeout(3)
        length = int(self.headers.get("Content-Length", "0"))
        if self.path != "/capture" or not 0 <= length <= SERVER.MAX_BYTES:
            self.send_error(400)
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self.send_error(400)
            return
        self.server.receipts.append(digest(body))
        self.send_response(200)
        self.send_header("Content-Length", "8")
        self.end_headers()
        self.wfile.write(b"accepted")


def source_snapshot(agent):
    files = [FIXTURE, Path(__file__).resolve(), REPO / "Cargo.lock",
             REPO / "Cargo.toml", REPO / "rust-toolchain.toml"]
    for crate in ("agentfw", "agent", "core", "adapter"):
        files.append(REPO / "crates" / crate / "Cargo.toml")
        files.extend(sorted((REPO / "crates" / crate / "src").rglob("*.*")))
    return {"agent_sha256": digest(agent.read_bytes()),
            "sources": {str(path.relative_to(REPO)): digest(path.read_bytes()) for path in files}}


def wait_ready(process, port):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        require(process.poll() is None, "agent_stopped_before_ready")
        try:
            with opener.open(f"http://127.0.0.1:{port}/health", timeout=0.5) as response:
                health = json.loads(response.read(4096))
                require(health == {"status": "ok", "enforce": True}, "agent_not_enforcing")
                return
        except OSError:
            time.sleep(0.05)
    raise AcceptanceError("agent_readiness_timeout")


def run(agent):
    agent = Path(agent).resolve(strict=True)
    report = {"schema_version": 1, "status": "incomplete", "platform": platform.system(),
              "architecture": platform.machine(), "python_version": platform.python_version(),
              "harness": "deterministic-mcp-client", "real_model_evaluation": False,
              "result_delivery": "mcp_host", "model_context_attestation": False,
              "native_approval_channel": False, "checks": []}
    # Exact source bytes accompany the Git checkpoint because the demo can be run
    # before committing a candidate. Paths/outputs from Git status stay private.
    git_env = {key: value for key, value in os.environ.items()
               if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR"}}
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, env=git_env,
        capture_output=True, text=True, check=True, timeout=5).stdout.strip()
    require(re.fullmatch("[0-9a-f]{40}", revision), "invalid_source_revision")
    report["source_commit"] = revision
    report["source_worktree_modified"] = bool(subprocess.run(
        ["git", "status", "--porcelain"], cwd=REPO, env=git_env,
        capture_output=True, check=True, timeout=5).stdout)
    snapshot = source_snapshot(agent)
    report.update(snapshot)
    report["policy_sha256"] = digest(POLICY.encode())
    report["registry_sha256"] = digest(canonical(registry()))

    def check(name, condition, **counts):
        report["checks"].append({"name": name, "status": "passed" if condition else "failed", **counts})
        require(condition, name)

    root = None
    try:
        with ExitStack() as cleanup:
            temporary = cleanup.enter_context(tempfile.TemporaryDirectory(prefix="soup-wall-mcp-demo-"))
            # Canonicalize our newly reserved temp root, including macOS /var.
            root = Path(temporary).resolve(strict=True)
            env = child_environment(root)
            receiver = Receiver()
            cleanup.callback(receiver.server_close)
            thread = threading.Thread(target=receiver.serve_forever, daemon=True)
            thread.start()
            cleanup.callback(receiver.shutdown)
            downstream = [sys.executable, "-I", "-u", str(FIXTURE)]
            synthetic = "AKIAIOSFODNN7EXAMPLE"
            secret_args = {"url": receiver.url, "body": synthetic}
            secret_call = call("denied-send", "send_http", secret_args, 0)
            control_ledger = root / "control.jsonl"
            control = Session([*downstream, "--ledger", str(control_ledger),
                               "--recipient", receiver.url], root, env)
            cleanup.callback(control.close)
            control.ready()
            original = control.exchange(secret_call)
            check("control_send_reaches_executor_and_receiver",
                  ledger(control_ledger) == [{"id": "denied-send", "tool": "send_http",
                                            "request_sha256": digest(secret_call)}]
                  and receiver.receipts == [digest(synthetic.encode())]
                  and original == SERVER.response("denied-send", "Owned receiver accepted the body"),
                  executor_entries=entries_for(control_ledger, "denied-send"),
                  receiver_deliveries=len(receiver.receipts))
            control.close()

            subprocess.run([str(agent), "install"], cwd=root, env=env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            home = root / ".agentfw"
            policy = root / "policy.yaml"
            policy.write_text(POLICY, encoding="utf-8")
            registry_path = root / "registry.json"
            registry_path.write_bytes(canonical(registry()))
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            # JSON strings are valid YAML quoted scalars, including Windows paths.
            (home / "config.yaml").write_text(
                f"bind: 127.0.0.1\nport: {port}\nenforce: true\npolicy: {json.dumps(str(policy))}\n"
                f"native:\n  registry_path: {json.dumps(str(registry_path))}\n"
                f"  registry_sha256: '{report['registry_sha256']}'\n", encoding="utf-8")
            daemon = subprocess.Popen([str(agent), "serve"], cwd=root, env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cleanup.callback(stop, daemon)
            wait_ready(daemon, port)
            subprocess.run([str(agent), "preflight", "--require-enforce"], cwd=root, env=env,
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            protected_ledger = root / "protected.jsonl"
            protected = Session([str(agent), "mcp", "--native-admission", "--id", "local-demo", "--",
                *downstream, "--ledger", str(protected_ledger), "--recipient", receiver.url], root, env)
            cleanup.callback(protected.close)
            protected.ready()

            read = call("allowed-read", "read_document", {"document": "project"}, 1)
            reply = protected.exchange(read)
            check("allowed_read_preserves_request_and_result",
                  reply == SERVER.response("allowed-read", SERVER.DOCUMENT)
                  and ledger(protected_ledger) == [{"id": "allowed-read", "tool": "read_document",
                                                   "request_sha256": digest(read)}],
                  executor_entries=entries_for(protected_ledger, "allowed-read"))
            before = len(receiver.receipts)
            refused(protected.exchange(secret_call), "demo-secret-egress")
            check("denied_send_never_reaches_executor_or_receiver",
                  len(ledger(protected_ledger)) == 1 and len(receiver.receipts) == before,
                  executor_entries=entries_for(protected_ledger, "denied-send"),
                  receiver_deliveries=len(receiver.receipts) - before)

            ask = call("confirmation-required", "send_http",
                       {"url": receiver.url, "body": "Contact alice@acme.com"}, 2)
            refused(protected.exchange(ask), "demo-pii-confirmation")
            retry = call("confirmation-still-required", "send_http",
                         {"url": receiver.url, "body": "Contact alice@acme.com"}, 3)
            refused(protected.exchange(retry), "demo-pii-confirmation")
            check("confirmation_calls_remain_blocked_without_native_approval",
                  len(ledger(protected_ledger)) == 1 and len(receiver.receipts) == before,
                  executor_entries=entries_for(protected_ledger, "confirmation-required")
                  + entries_for(protected_ledger, "confirmation-still-required"),
                  receiver_deliveries=len(receiver.receipts) - before)

            benign = call("allowed-send", "send_http", {"url": receiver.url, "body": "ordinary update"}, 4)
            reply = protected.exchange(benign)
            check("allowed_send_preserves_bytes_and_reaches_receiver",
                  reply == SERVER.response("allowed-send", "Owned receiver accepted the body")
                  and ledger(protected_ledger)[-1]["request_sha256"] == digest(benign)
                  and receiver.receipts[before:] == [digest(b"ordinary update")],
                  executor_entries=entries_for(protected_ledger, "allowed-send"),
                  receiver_deliveries=len(receiver.receipts) - before)
            poisoned = call("withheld-result", "read_document", {"document": "poisoned"}, 5)
            reply = protected.exchange(poisoned)
            refused(reply, "demo-result-confirmation")
            check("executed_result_is_inspected_before_client_release",
                  SERVER.POISON.encode() not in reply and b"PRIVATE-FIXTURE-MARKER" not in reply
                  and ledger(protected_ledger)[-1]["request_sha256"] == digest(poisoned),
                  executor_entries=entries_for(protected_ledger, "withheld-result"),
                  original_result_released=reply == SERVER.response("withheld-result", SERVER.POISON))
            failure = call(42, "read_document", {"document": "error"}, 6)
            check("original_jsonrpc_error_is_preserved",
                  protected.exchange(failure) == SERVER.response(42, error=True))
            final = call("benign-followup", "read_document", {"document": "project"}, 7)
            check("benign_task_completes_after_call_and_result_refusals",
                  protected.exchange(final) == SERVER.response("benign-followup", SERVER.DOCUMENT))
            protected.close()
            check("collector_exits_cleanly", protected.process.returncode == 0)
            audit = ledger(home / "audit.jsonl")
            decisions = [record for record in audit if record["event"] == "native_call"]
            results = [record for record in audit if record["event"] == "native_result"]
            check("audit_confirms_deny_ask_and_result_gate",
                  [record["verdict"] for record in decisions] ==
                  ["allow", "deny", "ask", "ask", "allow", "allow", "allow", "allow"]
                  and sum(record["released"] is False for record in results) == 1
                  and all(record["delivery"] == "mcp_host" for record in results))
            report["control_request_sha256"] = digest(secret_call)
            report["protected_request_sha256"] = digest(secret_call)
            report["audit_events"] = len(audit)
            check("measured_binary_and_sources_unchanged", source_snapshot(agent) == snapshot)
        report["status"] = "passed"
        report["runtime_cleaned"] = True
    except (AcceptanceError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["failure_type"] = type(error).__name__
        if isinstance(error, AcceptanceError):
            report["failure_code"] = str(error)
    report["runtime_cleaned"] = root is not None and not root.exists()
    return report


class EvidenceOutput:
    """Reserve a fresh destination before starting processes; never clobber evidence."""
    def __init__(self, path):
        path = Path(path).absolute()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path.parent.resolve(strict=True) / path.name
        with self.path.open("x", encoding="utf-8") as output:
            json.dump({"schema_version": 1, "status": "incomplete", "failure_code": "run_not_finished"}, output)
        self.identity = self.path.stat()

    def publish(self, report):
        metadata = self.path.lstat()
        require((metadata.st_dev, metadata.st_ino) == (self.identity.st_dev, self.identity.st_ino)
                and not self.path.is_symlink(), "evidence_destination_changed")
        staged = self.path.with_name(self.path.name + "." + secrets.token_hex(8) + ".tmp")
        try:
            with staged.open("x", encoding="utf-8") as output:
                json.dump(report, output, indent=2)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(staged, self.path)
        finally:
            staged.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="Start the local acceptance demonstration")
    parser.add_argument("--agent-binary", type=Path,
                        default=REPO / ("target/debug/agentfw.exe" if os.name == "nt" else "target/debug/agentfw"))
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"mode": "manifest", "processes_started": 0, "real_model_evaluation": False,
                          "requires": "Built agentfw, Python 3.10+; --run --evidence <fresh path>"}))
        return
    if args.evidence is None:
        parser.error("Explicit runs require a fresh --evidence destination")
    try:
        output = EvidenceOutput(args.evidence)
        report = run(args.agent_binary)
        output.publish(report)
    except (OSError, AcceptanceError, subprocess.SubprocessError):
        raise SystemExit("Local MCP acceptance could not start or publish; use a fresh evidence path.") from None
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
