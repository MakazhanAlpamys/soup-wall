#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded local diagnostics for policy overlap and cancellation during admission.

Reuses the production demo daemon/server/harness and the real Python classifier
bridge. Synthetic classifications are evidence inputs, never a substitute policy.
No build, external model or external destination is used. Exit 0: all bounded
checks pass; 1: observed violation; 2: incomplete/unsupported evidence. Complete
SOU-17 acceptance is always false. An unsupported cancellation is sent before a
blocked classifier is released; its semantic contract still needs agreement.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import platform
from pathlib import Path
import queue
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ("benign-before", ["read"], False, 0.05, "allow"),
    ("write-readonly-low", ["write"], False, 0.05, "deny"),
    ("write-readonly-high", ["write"], False, 0.9, "deny"),
    ("delete-high", ["delete"], False, 1.0, "deny"),
    ("permissions-high", ["change_permissions"], False, 1.0, "deny"),
    ("undeclared-send-high", ["send_data"], False, 1.0, "deny"),
    ("uncertain-read", ["read"], False, 0.9, "ask"),
    ("read-unknown", ["read"], True, 0.05, "ask"),
    ("read-delete-high", ["read", "delete"], False, 1.0, "deny"),
    ("benign-after", ["read"], False, 0.05, "allow"),
]
CANCEL_ID = "pending-classifier-cancel"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(raw):
    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite JSON number")
        return number

    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    return json.loads(raw, parse_float=finite, object_pairs_hook=object_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def ledger(raw):
    """Retain confirmed entries even if another line is malformed; never count bad JSON as zero."""
    entries, errors = [], []
    if not isinstance(raw, str):
        return [], ["missing ledger"]
    for line in raw.splitlines(keepends=True):
        if not line.endswith("\n"):
            errors.append("unterminated executor ledger entry")
        try:
            value = strict_json(line)
            if not isinstance(value, dict) or value.get("method") != "tools/call" \
                    or value.get("jsonrpc") != "2.0" or not isinstance(value.get("params"), dict):
                raise ValueError("invalid executor entry")
            entries.append((line, value))
        except (ValueError, UnicodeError):
            errors.append("malformed executor ledger entry")
    return entries, errors



def reconcile_final_ledger(rows, raw):
    """Assign every final executor byte after shutdown; late effects cannot disappear.

    Bytes for other known calls belong to their corresponding rows. Malformed or
    unrelated bytes invalidate every zero-effect witness, while a confirmed
    forbidden entry remains visible to the grader even alongside corrupt bytes.
    """
    by_call = {row["host_call_id"]: [] for row in rows}
    residual = []
    for line in raw.splitlines(keepends=True):
        entries, errors = ledger(line)
        call_id = entries[0][1].get("id") if len(entries) == 1 else None
        if not errors and isinstance(call_id, str) and call_id in by_call:
            by_call[call_id].append(line)
        else:
            residual.append(line)
    for row in rows:
        row["executor_ledger_at_response_raw"] = row.get("executor_ledger_raw")
        row["executor_ledger_raw"] = "".join(by_call[row["host_call_id"]] + residual)
        row["executor_ledger_final_reconciled"] = True


def telemetry(raw):
    rows = []
    for line in raw.splitlines():
        try:
            value = strict_json(line)
        except (ValueError, UnicodeError):
            continue  # stderr also contains ordinary diagnostic text
        if isinstance(value, dict) and value.get("event") == "mcp_classification":
            rows.append(value)
    return rows


def valid_prediction(value, actions, unknown, uncertainty):
    if not isinstance(value, dict):
        return False
    confidence, actual = value.get("confidence"), value.get("uncertainty")
    valid_scores = all(type(number) in (int, float) and 0 <= number <= 1
                       for number in (confidence, actual))
    return valid_scores and confidence == 0.95 and actual == uncertainty \
        and value.get("actions") == actions and value.get("unknown") is unknown


def classification(row, digest, case):
    values = row.get("classifications")
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        return None
    value = values[0]
    if value.get("host_call_id") != row.get("host_call_id") \
            or value.get("tool") != "read_document" \
            or value.get("trusted_baseline") != "read_only" \
            or value.get("source") != "rule-baseline/python" \
            or value.get("classifier_sha256") != digest \
            or not valid_prediction(value.get("classification"), case[1], case[2], case[3]):
        return None
    return value


def frame_valid(row):
    try:
        value = strict_json(row["submitted_frame"])
        return value == {"jsonrpc": "2.0", "id": row["host_call_id"], "method": "tools/call",
                         "params": {"name": "read_document", "arguments": {"name": "inventory"}}}
    except (KeyError, ValueError, TypeError):
        return False


def digest_valid(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def object_field(value, key):
    found = value.get(key) if isinstance(value, dict) else None
    return found if isinstance(found, dict) else {}


def result(status, reason):
    return {"status": status, "reason": reason}


def grade_overlap(row, stable, digest):
    if stable is not True or not digest_valid(digest) or not isinstance(row, dict) or not frame_valid(row):
        return result("inconclusive", "source, binary or original request evidence missing")
    case = next((case for case in CASES if case[0] == row.get("case")), None)
    if case is None or row.get("host_call_id") != "overlap-" + case[0]:
        return result("inconclusive", "unknown or uncorrelated case")
    evidence = classification(row, digest, case)
    if evidence is None:
        return result("inconclusive", "matching production classifier evidence missing")
    entries, errors = ledger(row.get("executor_ledger_raw"))
    matching = [entry for entry in entries if entry[1].get("id") == row["host_call_id"]]
    if case[4] != "allow" and matching:
        return result("fail", "a forbidden call entered the executor")
    if errors or any(entry[1].get("id") != row["host_call_id"] for entry in entries):
        return result("inconclusive", "malformed or unrelated executor witness")
    response = row.get("response")
    if not isinstance(response, dict) or response.get("id") != row["host_call_id"]:
        return result("inconclusive", "correlated client response missing")
    try:
        if strict_json(row.get("client_response_raw", "")) != response:
            return result("inconclusive", "raw client bytes do not match decoded response")
    except (ValueError, TypeError):
        return result("inconclusive", "raw client response missing or malformed")
    failure = evidence.get("failure")
    if failure:
        if evidence.get("policy") == "not_reached" \
                and failure == "unsupported_classification_mapping" \
                and object_field(response, "error").get("code") == -32603 \
                and failure in str(object_field(response, "error").get("message", "")) and not entries:
            return result("technical_unsupported", "valid classification did not reach policy")
        return result("inconclusive", "classifier or fixture technical failure")
    if evidence.get("policy") != "reached":
        return result("inconclusive", "production policy reachability missing")
    actual = evidence.get("authoritative_verdict")
    if actual not in {"allow", "ask", "deny"}:
        return result("inconclusive", "authoritative verdict missing")
    if actual != case[4]:
        return result("fail", f"expected {case[4]}, observed authoritative {actual}; effects={len(entries)}")
    if case[4] == "allow":
        original = row.get("original_server_results")
        if len(entries) != 1 or entries[0][0] != row["submitted_frame"] + "\n" \
                or not isinstance(original, list) or len(original) != 1 \
                or row.get("client_response_raw") != original[0] \
                or object_field(response, "result").get("isError") is True \
                or object_field(response, "result").get("content") != [
                    {"type": "text", "text": "Inventory: 7 red widgets."}]:
            return result("fail", "Allow did not execute once and release the original useful result")
    else:
        reason = "policy_denied" if case[4] == "deny" else "policy_unconfirmed_ask"
        if row.get("original_server_results") != [] or object_field(response, "result").get("isError") is not True \
                or reason not in json.dumps(response.get("result")):
            return result("inconclusive", "ordinary policy refusal missing")
    return result("pass", "expected verdict and independent execution/result witnesses matched")


def grade_cancellation(row, stable, digest):
    if stable is not True or not digest_valid(digest) or not isinstance(row, dict) or not frame_valid(row) \
            or row.get("host_call_id") != CANCEL_ID:
        return result("inconclusive", "source, binary or original request evidence missing")
    ready = row.get("classifier_ready")
    try:
        cancel = strict_json(row["cancellation_frame"])
        times = [row[key] for key in ("call_written_at", "ready_observed_at", "cancel_written_at", "release_written_at")]
        ordered = all(type(value) in (int, float) and math.isfinite(value) for value in times) \
            and times[0] <= times[1] <= times[2] < times[3] \
            and times[3] - times[0] < 1.5
        handshake = isinstance(ready, dict) and ready.get("classifier_sha256") == digest \
            and object_field(ready, "request").get("tool_name") == "read_document" \
            and object_field(ready, "request").get("raw_arguments") == {"name": "inventory"} \
            and valid_prediction(ready.get("reply"), ["read"], False, 0.05) \
            and cancel == {"jsonrpc": "2.0", "method": "notifications/cancelled",
                           "params": {"requestId": CANCEL_ID, "reason": "synthetic pending admission cancellation"}} \
            and row.get("cancel_write_completed") is True and ordered
    except (KeyError, TypeError, ValueError, OverflowError):
        handshake = False
    if not handshake:
        return result("inconclusive", "confirmed ready/cancel-before-release handshake missing")
    before, before_errors = ledger(row.get("ledger_before_release_raw"))
    entries, errors = ledger(row.get("executor_ledger_raw"))
    matching = [entry for entry in entries if entry[1].get("id") == CANCEL_ID]
    if matching and not before and not before_errors:
        return result("fail", "original call entered executor after unsupported cancellation was sent before classifier release")
    if before_errors or errors or before or entries:
        return result("inconclusive", "invalid or premature executor witness")
    stderr = row.get("collector_stderr")
    if not isinstance(stderr, str):
        return result("inconclusive", "collector transport diagnostic missing")
    # Missing/partial logs and generic timeouts cannot manufacture a successful cancellation.
    if row.get("transport_outcome") != "eof" or type(row.get("gateway_exit_code")) is not int \
            or row["gateway_exit_code"] == 0 or row.get("client_response_raw") != "" \
            or row.get("original_server_results") != [] \
            or not any(text in stderr for text in (
                "unsupported MCP notification", "unsupported MCP method", "concurrent MCP requests")):
        return result("inconclusive", "explicit cancellation transport refusal without effect/result not witnessed")
    return result("pass", "unsupported cancellation closed transport before executor entry; narrow diagnostic only")



def grade_probe(probe, stable):
    """Keep confirmed violations, but never certify an incomplete transport run."""
    graded = []
    cleanup_failed = probe.get("error") is not None or (
        probe["mode"] == "overlap" and (type(probe.get("gateway_exit_code")) is not int
                                        or probe["gateway_exit_code"] != 0))
    for row in probe["rows"]:
        grader = grade_cancellation if probe["mode"] == "cancel" else grade_overlap
        observation = grader(row, stable, probe["classifier_sha256"])
        if cleanup_failed and observation["status"] == "pass":
            row["observed_grade"] = observation
            observation = result("inconclusive", "probe transport or cleanup did not complete successfully")
        row["grade"] = observation
        graded.append({"case": row["case"], **observation})
    return graded


def overall(rows):
    statuses = [row.get("status") for row in rows]
    if "fail" in statuses:
        return "fail", 1
    expected = [case[0] for case in CASES] + ["pending-classifier-cancellation"]
    if [row.get("case") for row in rows] != expected or any(status != "pass" for status in statuses):
        return "inconclusive", 2
    return "pass", 0


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                          text=True, timeout=10).stdout.strip()


def snapshot(repo):
    names = git(repo, "ls-files", "-z").split("\0")
    hashes = {}
    for name in sorted(filter(None, names)):
        path = repo / name
        hashes[name] = sha(path.read_bytes()) if path.is_file() else None
    return {"commit": git(repo, "rev-parse", "HEAD"),
            "dirty": bool(git(repo, "status", "--porcelain=v1", "--untracked-files=all")),
            "inputs_sha256": hashes, "inputs_digest": sha(json.dumps(hashes, sort_keys=True).encode())}


def load_demo(repo):
    spec = importlib.util.spec_from_file_location("sou17_pending_demo", repo / "scripts/mcp-admission-demo.py")
    demo = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = demo
    spec.loader.exec_module(demo)
    return demo


def read(path):
    return path.read_bytes() if path.is_file() else b""


def wait_ready(path, harness, started):
    while time.monotonic() - started < 1.3:
        if path.is_file():
            return strict_json(path.read_bytes())
        if harness.process.poll() is not None:
            break
        time.sleep(0.005)
    raise RuntimeError("classifier ready handshake missing within bounded admission window")


def receive_until_close(harness):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            line = harness.lines.get(timeout=max(0.001, deadline - time.monotonic()))
        except queue.Empty:
            return "timeout"
        if line is None:
            return "eof"
        harness.received.append(line)
    return "timeout"


def stop(harness):
    if harness is None:
        return None
    process = harness.process
    try:
        process.stdin.close()
    except OSError:
        pass
    try:
        return process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        return None


def initialize(harness):
    frames = [
        '{"jsonrpc":"2.0","id":"probe-init","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sou17-pending-admission","version":"1"}}}',
        '{"jsonrpc":"2.0","method":"notifications/initialized"}',
        '{"jsonrpc":"2.0","id":"probe-list","method":"tools/list"}',
    ]
    initialized = harness.send(frames[0])
    harness.send(frames[1], reply=False)
    manifest = harness.send(frames[2])
    if not initialized or "result" not in strict_json(initialized) or not manifest \
            or not any(tool.get("name") == "read_document" for tool in strict_json(manifest).get("result", {}).get("tools", [])):
        raise RuntimeError("production initialization/discovery missing")
    return frames


def call_frame(call_id):
    return json.dumps({"jsonrpc": "2.0", "id": call_id, "method": "tools/call",
                       "params": {"name": "read_document", "arguments": {"name": "inventory"}}}, separators=(",", ":"))


def classifier_source(mode, private):
    replies = [{"status": "ok", "actions": case[1], "unknown": case[2], "confidence": 0.95,
                "uncertainty": case[3], "reason": "Synthetic boundary diagnostic " + case[0]} for case in CASES]
    if mode == "cancel":
        replies = [{"status": "ok", "actions": ["read"], "unknown": False, "confidence": 0.95,
                    "uncertainty": 0.05, "reason": "Synthetic blocked classifier cancellation"}]
    return f'''#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import hashlib,json,pathlib,sys,time
root=pathlib.Path({str(private)!r})
request=json.loads(sys.stdin.readline())
assert request['tool_name']=='read_document' and request['raw_arguments']=={{'name':'inventory'}}
replies=json.loads({json.dumps(replies)!r})
counter=root/'counter'
index=int(counter.read_text()) if counter.exists() else 0
assert index<len(replies)
counter.write_text(str(index+1))
reply=replies[index]
record={{'request':request,'reply':reply,'classifier_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()}}
with (root/'inputs.jsonl').open('a') as stream: stream.write(json.dumps(record)+'\\n')
if {mode!r}=='cancel':
    (root/'ready.tmp').write_text(json.dumps(record))
    (root/'ready.tmp').replace(root/'ready.json')
    deadline=time.monotonic()+1.8
    while not (root/'release').exists():
        if time.monotonic()>deadline: raise RuntimeError('synthetic release missing')
        time.sleep(.002)
    (root/'emitted').write_text('reply emitted')
print(json.dumps(reply,separators=(',',':')))
'''


def collect_artifacts(stack, harness, frames, private, out):
    blobs = {"client-input.jsonl": ("\n".join(frames) + "\n").encode(),
             "client-output.jsonl": b"".join(harness.received) if harness else b"",
             "executor-ledger.jsonl": read(stack.ledger), "server-responses.jsonl": read(stack.responses),
             "collector.log": read(stack.classifications), "daemon.log": read(stack.workspace / "daemon.log"),
             "native-audit.jsonl": read(stack.workspace / ".agentfw/audit.jsonl"),
             "registry.json": read(stack.workspace / "registry.json"), "policy.yaml": read(stack.workspace / "policy.yaml"),
             "daemon-config.json": read(stack.workspace / ".agentfw/config.yaml"),
             "classifier-inputs.jsonl": read(private / "inputs.jsonl")}
    tokens = [read(stack.workspace / ".agentfw" / name).strip() for name in ("token", "native-token")]
    if any(token and token in data for token in tokens for data in blobs.values()):
        raise RuntimeError("fixture credential detected; refusing evidence retention")
    for name, data in blobs.items():
        (out / name).write_bytes(data)
    return {name: {"sha256": sha(data), "bytes": len(data)} for name, data in blobs.items()}


def run_probe(demo, binary, mode, out):
    out.mkdir()
    rows, harness, frames = [], None, []
    with tempfile.TemporaryDirectory(prefix="sou17-pending-") as tmp:
        private = Path(tmp).resolve() / "classifier"
        private.mkdir()
        source = classifier_source(mode, private)
        script = out / "synthetic-classifier.py"
        script.write_text(source, encoding="utf-8")
        digest = sha(source.encode())
        demo.classifier_environment = lambda: {"AGENTFW_CLASSIFIER": "rule-baseline",
            "AGENTFW_RULE_BASELINE": str(script), "AGENTFW_CLASSIFIER_PYTHON": sys.executable}
        with demo.agent_stack(binary, Path(tmp).resolve() / "workspace") as stack:
            error = None
            row = None
            try:
                with stack.classifications.open("wb") as log:
                    harness = demo.Harness(stack.collector, stack.env, log)
                    frames.extend(initialize(harness))
                    if mode == "cancel":
                        frame = call_frame(CANCEL_ID)
                        cancel = json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {
                            "requestId": CANCEL_ID, "reason": "synthetic pending admission cancellation"}}, separators=(",", ":"))
                        row = {"case": "pending-classifier-cancellation", "host_call_id": CANCEL_ID,
                               "submitted_frame": frame, "cancellation_frame": cancel}
                        rows.append(row)
                        frames.append(frame)
                        row["call_written_at"] = time.monotonic()
                        harness.send(frame, reply=False)
                        row["classifier_ready"] = wait_ready(private / "ready.json", harness, row["call_written_at"])
                        row["ready_observed_at"] = time.monotonic()
                        frames.append(cancel)
                        # Harness.send(reply=False) hides broken pipes, so use an explicit successful flush here.
                        harness.process.stdin.write((cancel + "\n").encode())
                        harness.process.stdin.flush()
                        row["cancel_write_completed"] = True
                        row["cancel_written_at"] = time.monotonic()
                        row["ledger_before_release_raw"] = read(stack.ledger).decode("utf-8", "replace")
                        (private / "release").write_text("release after cancellation flush")
                        row["release_written_at"] = time.monotonic()
                        row["transport_outcome"] = receive_until_close(harness)
                    else:
                        for case in CASES:
                            frame = call_frame("overlap-" + case[0])
                            frames.append(frame)
                            before = read(stack.ledger)
                            reply = harness.send(frame)
                            raw = read(stack.ledger)
                            if not raw.startswith(before):
                                raise RuntimeError("executor ledger changed its original prefix")
                            row = {"case": case[0], "host_call_id": "overlap-" + case[0],
                                   "submitted_frame": frame, "executor_ledger_raw": raw[len(before):].decode("utf-8", "replace"),
                                   "client_response_raw": (reply or b"").decode("utf-8", "replace"), "response": None}
                            rows.append(row)
                            if reply:
                                row["response"] = strict_json(reply)
                            if reply is None:
                                raise RuntimeError("transport lost during overlap matrix")
                    exit_code = stop(harness)
            except Exception as exception:
                error = {"type": type(exception).__name__, "message": str(exception)}
                exit_code = None
            finally:
                # Best effort release/cleanup preserves assertions and avoids leaving a blocked fixture.
                (private / "release").touch()
                if harness and harness.process.poll() is None:
                    stop(harness)
                if mode == "overlap":
                    reconcile_final_ledger(rows, read(stack.ledger).decode("utf-8", "replace"))
                classifications = telemetry(read(stack.classifications).decode("utf-8", "replace"))
                responses = read(stack.responses).decode("utf-8", "replace").splitlines(keepends=True)
                decoded_responses = []
                for raw in responses:
                    try:
                        value = strict_json(raw)
                        if isinstance(value, dict):
                            decoded_responses.append((raw, value))
                    except ValueError:
                        pass
                for row in rows:
                    row["classifications"] = [value for value in classifications if value.get("host_call_id") == row["host_call_id"]]
                    row["original_server_results"] = [raw for raw, value in decoded_responses if value.get("id") == row["host_call_id"]]
                if mode == "cancel" and rows:
                    row = rows[0]
                    row.update(executor_ledger_raw=read(stack.ledger).decode("utf-8", "replace"),
                               client_response_raw=b"".join(harness.received[2:]).decode("utf-8", "replace") if harness else "",
                               gateway_exit_code=exit_code,
                               collector_stderr=read(stack.classifications).decode("utf-8", "replace"),
                               classifier_reply_emitted=(private / "emitted").is_file())
                for row in rows:
                    entries, errors = ledger(row.get("executor_ledger_raw"))
                    row["executor_entry_count"] = len(entries) if not errors else None
                    row["ledger_errors"] = errors
                    row["original_server_result_count"] = len(row["original_server_results"])
                    row["client_response_bytes"] = len(row.get("client_response_raw", "").encode("utf-8"))
                artifacts = collect_artifacts(stack, harness, frames, private, out)
    return {"mode": mode, "classifier_sha256": digest, "classifier_sha256_after": sha(script.read_bytes()),
            "rows": rows, "artifacts": artifacts, "error": error, "gateway_exit_code": exit_code}


def run(args):
    repo, binary, out = args.repo.resolve(), args.agentfw.resolve(), args.output.resolve()
    if not re.fullmatch(r"[a-f0-9]{40}", args.expected_commit):
        raise ValueError("--expected-commit requires an exact 40-character lowercase SHA")
    before = snapshot(repo)
    if before["commit"] != args.expected_commit or before["dirty"]:
        raise ValueError("candidate must have exact expected HEAD and clean tracked/untracked source")
    if not binary.is_file():
        raise ValueError("production agentfw must already be built")
    out.mkdir(parents=True, exist_ok=False)
    binary_before = sha(binary.read_bytes())
    script_before = sha(Path(__file__).read_bytes())
    report = {"schema_version": "sou17-pending-admission/1", "acceptance_passed": False,
              "timestamp_utc": datetime.now(timezone.utc).isoformat(), "source": before,
              "agentfw": {"path": str(binary), "sha256_before": binary_before},
              "script_sha256_before": script_before,
              "environment": {"os": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
              "limits": {"active_deadline_seconds": 90, "classifier_handshake_seconds": 1.5,
                         "response_seconds": 3, "gateway_cleanup_seconds": 7},
              "expectations": {"overlap": [{"case": case[0], "verdict": case[4]} for case in CASES],
                  "cancellation": "diagnose unsupported cancellation sent before classifier release; agreed in-flight semantics remain pending"},
              "limitations": ["No external model; synthetic predictions through the production Python bridge.",
                  "An executor ledger records entry; successful original fixture results independently confirm useful execution.",
                  "Source/binary stability does not itself attest their build relationship; attach matching pinned build evidence.",
                  "Cancellation diagnosis is not a claim that an agreed in-flight cancellation contract is implemented.",
                  "No native HTTP-admission gate, arbitrary-server containment, actual host or latency-overhead measurement."]}
    old_handler = signal.getsignal(signal.SIGALRM)
    def deadline(_signum, _frame):
        raise TimeoutError("bounded pending-admission probe exceeded 90 seconds")
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(90)
    probes = []
    try:
        demo = load_demo(repo)
        for mode in ("overlap", "cancel"):
            probes.append(run_probe(demo, binary, mode, out / mode))
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
    after = snapshot(repo)
    binary_after = sha(binary.read_bytes())
    script_after = sha(Path(__file__).read_bytes())
    stable = before == after and binary_before == binary_after and script_before == script_after \
        and all(probe["classifier_sha256"] == probe["classifier_sha256_after"] for probe in probes)
    report.update(source_after=after, stable=stable, probes=probes, script_sha256_after=script_after)
    report["agentfw"]["sha256_after"] = binary_after
    graded = []
    for probe in probes:
        graded.extend(grade_probe(probe, stable))
    status, code = overall(graded)
    report["status"] = status
    report["counts"] = {kind: sum(row["status"] == kind for row in graded)
                        for kind in ("pass", "fail", "technical_unsupported", "inconclusive")}
    (out / "results.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    (out / "report.md").write_text("# SOU-17 pending-admission diagnostic\n\n"
        + f"Status: **{status}**; complete acceptance: **false**.\n\n"
        + f"Candidate: `{before['commit']}`; stable source/binary: `{stable}`.\n\n"
        + "| Case | Status | Observation |\n| --- | --- | --- |\n"
        + "".join(f"| {row['case']} | {row['grade']['status']} | {row['grade']['reason']} |\n"
                  for probe in probes for row in probe["rows"])
        + "\nRaw frames, ledgers, classifier/native logs and input hashes are retained beside results.json.\n"
        + "Technical unsupported classifications are not policy successes. Cancellation semantics require agreement.\n", encoding="utf-8")
    print(json.dumps({"status": status, "counts": report["counts"], "acceptance_passed": False, "results": str(out / "results.json")}))
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory")
    args = parser.parse_args()
    if sys.platform not in {"linux", "darwin"}:
        parser.error("native Linux/macOS Python required for POSIX safety deadline")
    try:
        return run(args)
    except Exception as error:
        print(f"Inconclusive: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
