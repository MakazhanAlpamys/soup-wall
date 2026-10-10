#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual native MCP boundary with bounded synthetic classifier replies.

Uses the repository's agent_stack and Harness with a separately built production
agentfw binary. No model, Cargo build, external server, or production-source edits.
Each case has a fresh isolated daemon and session. This is diagnostic enforcement
evidence, not classifier quality measurement or complete SOU-17 acceptance.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import math

CONTRACT = "sw-classification/candidate-1"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(repo):
    def git(*args):
        return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                              text=True, timeout=10).stdout.strip()
    return {"commit": git("rev-parse", "HEAD"),
            "tracked_dirty": bool(git("status", "--porcelain", "--untracked-files=no"))}


def records(data):
    result = []
    for line in data.splitlines():
        try:
            result.append(json.loads(line))
        except (ValueError, UnicodeDecodeError):
            continue
    return result


def read(path):
    return path.read_bytes() if path.is_file() else b""


def cases():
    base = {"status": "ok", "actions": ["read"], "unknown": False, "confidence": 0.95,
            "uncertainty": 0.05, "reason": "Synthetic native enforcement matrix"}
    def case(name, changes=None, *, executes=False, malformed=None, missing=None):
        reply = dict(base, **(changes or {}))
        if missing:
            reply.pop(missing)
        return {"name": name, "reply": reply, "executes": executes,
                "stdout": malformed if malformed is not None else json.dumps(reply, separators=(",", ":"))}
    return [
        case("benign_read", executes=True),
        case("high_uncertainty_read", {"uncertainty": 0.9}),
        case("unknown", {"status": "unknown", "actions": [], "unknown": True, "uncertainty": 0.9}),
        case("read_plus_unknown", {"unknown": True}),
        case("read_plus_delete", {"actions": ["read", "delete"]}),
        case("read_plus_send_data", {"actions": ["read", "send_data"]}),
        case("read_plus_change_permissions", {"actions": ["read", "change_permissions"]}),
        case("nan_confidence", {"confidence": float("nan")}),
        case("confidence_out_of_range", {"confidence": 1.1}),
        case("uncertainty_out_of_range", {"uncertainty": -0.1}),
        case("missing_confidence", missing="confidence"),
        case("malformed_json", malformed="{not valid JSON"),
    ]


def script_for(case):
    return ("#!/usr/bin/env python3\n# SPDX-License-Identifier: Apache-2.0\n"
            f"# Synthetic {CONTRACT} reply: {case['name']}\n"
            "import json, sys\ninput = json.loads(sys.stdin.readline())\n"
            "assert input['tool_name'] == 'read_document'\n"
            f"sys.stdout.write({(case['stdout'] + chr(10))!r})\n")



def strict_json(data):
    def reject_constant(value):
        raise ValueError("non-JSON numeric constant: " + value)
    def unique_fields(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field: " + key)
            result[key] = value
        return result
    return json.loads(data, parse_constant=reject_constant, object_pairs_hook=unique_fields)


def parse_ledger(raw):
    """Every retained byte must describe a complete native tools/call frame."""
    entries = []
    for line in raw.splitlines(keepends=True):
        if not line.endswith(b"\n"):
            raise ValueError("unterminated executor ledger frame")
        item = strict_json(line)
        params = item.get("params") if isinstance(item, dict) else None
        request_id = item.get("id") if isinstance(item, dict) else None
        if not (isinstance(item, dict) and item.get("jsonrpc") == "2.0"
                and item.get("method") == "tools/call"
                and isinstance(request_id, (str, int)) and not isinstance(request_id, bool)
                and isinstance(params, dict) and isinstance(params.get("name"), str)
                and isinstance(params.get("arguments"), dict)):
            raise ValueError("executor ledger contains a non-call or malformed call")
        entries.append(item)
    return entries


def grade_case(case, row, raw_ledger, delivered, original_results, request_frame):
    """Grade independent bytes and semantic evidence, never a parsed-count shortcut."""
    row = dict(row)
    failures = []
    try:
        executions = parse_ledger(raw_ledger)
        request = strict_json(request_frame)
        response = strict_json(delivered) if delivered else {}
        if not isinstance(response, dict):
            raise ValueError("client response is not an object")
    except (ValueError, TypeError, UnicodeDecodeError) as error:
        row.update(status="inconclusive", grading_errors=[str(error)], execution_count=None,
                   released_original_result_bytes=0)
        return row

    exact_result = bool(delivered and len(original_results) == 1 and delivered == original_results[0])
    cls = row.get("classification_evidence", [])
    evidence = cls[0] if len(cls) == 1 and isinstance(cls[0], dict) else {}
    classification = evidence.get("classification")
    technical = "error" in response
    failure = evidence.get("failure")
    native = row.get("native_decisions", [])
    call_verdicts = [item.get("verdict") for item in native if item.get("event") == "native_call"]
    result_verdicts = [item.get("verdict") for item in native if item.get("event") == "native_result"]
    row.update(
        execution_count=len(executions), client_response_id=response.get("id"),
        client_response_bytes=len(delivered or b""), released_original_result_bytes=len(delivered) if exact_result else 0,
        original_call_bytes_preserved=raw_ledger == (request_frame + "\n").encode(),
        original_result_bytes_preserved=exact_result, native_call_verdicts=call_verdicts,
        native_result_verdicts=result_verdicts, adapter_verdict=evidence.get("adapter_verdict"),
        authoritative_verdict=evidence.get("authoritative_verdict"), policy_reached=evidence.get("policy"),
        technical_failure=failure,
        gate=("technical_unsupported_mapping" if failure == "unsupported_classification_mapping" else
              "technical_classifier_failure" if technical else
              "authoritative_refusal" if response.get("result", {}).get("isError") is True else "native_release"),
    )
    def check(condition, message):
        if not condition:
            failures.append(message)

    check(len(cls) == 1, "missing or duplicate classifier evidence")
    check(evidence.get("classifier_sha256") == row["classifier_sha256"], "classifier revision mismatch")
    check(evidence.get("source") == "rule-baseline/python", "unexpected classifier source")
    check(evidence.get("contract_version") == CONTRACT, "classification contract mismatch")
    check(evidence.get("host_call_id") == request.get("id"), "classifier call identity mismatch")
    check(response.get("jsonrpc") == "2.0" and response.get("id") == request.get("id"), "client response identity mismatch")
    check(row.get("receiver_count") == 0, "unexpected independent receiver delivery")
    check(row.get("gateway_exit_code") == 0, "unexpected gateway termination")

    expected = case["reply"]
    semantic = case["name"] in {"benign_read", "high_uncertainty_read", "unknown", "read_plus_unknown",
                               "read_plus_delete", "read_plus_send_data", "read_plus_change_permissions"}
    if semantic:
        check(isinstance(classification, dict), "semantic reply missing classification")
        if isinstance(classification, dict):
            for field in ("actions", "unknown", "confidence", "uncertainty"):
                check(classification.get(field) == expected[field], "semantic classification mismatch: " + field)
            for field in ("confidence", "uncertainty"):
                value = classification.get(field)
                check(isinstance(value, (int, float)) and not isinstance(value, bool)
                      and math.isfinite(value) and 0 <= value <= 1, "invalid semantic score: " + field)
            check(classification.get("reason_sha256") == sha(expected["reason"].encode()), "semantic reason mismatch")
        expected_verdict = ("allow" if case["executes"] else "deny" if any(
            item in expected["actions"] for item in ("delete", "send_data", "change_permissions")) else "ask")
        check(evidence.get("authoritative_verdict") == expected_verdict, "unexpected authoritative semantic verdict")
        supports_unsupported = expected["unknown"] or len(expected["actions"]) != 1
        if technical:
            check(supports_unsupported and failure == "unsupported_classification_mapping",
                  "semantic reply failed unexpectedly in classifier bridge")
            error_message = response.get("error", {}).get("message", "")
            check("unsupported_classification_mapping" in error_message and "policy not reached" in error_message,
                  "unsupported mapping response lacks explicit technical refusal")
            check(evidence.get("policy") == "not_reached", "unsupported mapping incorrectly claims policy reached")
        else:
            check(failure is None and evidence.get("policy") == "reached", "semantic policy was not reached")
            if not case["executes"]:
                reason = "policy_unconfirmed_ask" if expected_verdict == "ask" else "policy_denied"
                check(reason in json.dumps(response), "missing authoritative refusal reason")
    else:
        labels = {"classifier_error", "classifier_invalid"} if case["name"] in {
            "confidence_out_of_range", "uncertainty_out_of_range"} else {"classifier_error"}
        error_message = response.get("error", {}).get("message", "")
        check(technical and failure in labels and failure in error_message and "policy not reached" in error_message,
              "invalid reply lacks expected explicit classifier failure")
        check(evidence.get("policy") == "not_reached", "invalid classifier reply reached policy")

    if case["executes"]:
        check(len(executions) == 1 and executions[0] == request, "useful execution differs from original call")
        check(row["original_call_bytes_preserved"], "original call bytes were changed")
        check(exact_result, "original useful result bytes were not released")
        check(not technical and response.get("result", {}).get("isError") is not True, "useful result is an error")
        check(call_verdicts == ["allow"] and result_verdicts == ["allow"], "useful native admission was not Allow")
    else:
        check(raw_ledger == b"", "blocked call left executor ledger bytes")
        check(not original_results and not exact_result, "blocked call prepared or released an original result")
        check(not result_verdicts, "blocked call unexpectedly reached native result admission")
        check(technical or response.get("result", {}).get("isError") is True, "non-execution lacks explicit refusal")
    row.update(status="unexpected_observation" if failures else "boundary_expectation_observed", grading_errors=failures)
    return row


def run_case(demo, binary, out, case):
    directory = out / case["name"]
    directory.mkdir()
    source = script_for(case).encode()
    classifier = directory / "classifier.py"
    classifier.write_bytes(source)
    demo.classifier_environment = lambda: {
        "AGENTFW_CLASSIFIER": "rule-baseline", "AGENTFW_RULE_BASELINE": str(classifier),
        "AGENTFW_CLASSIFIER_PYTHON": sys.executable,
    }
    row = {"case": case["name"], "expected_execution_count": int(case["executes"]),
           "classifier_sha256": sha(source), "synthetic_stdout": case["stdout"],
           "status": "inconclusive"}
    harness = None
    try:
        with tempfile.TemporaryDirectory(prefix="sou17-classifier-", dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            with demo.agent_stack(binary, Path(tmp) / "workspace") as stack:
                with stack.classifications.open("wb") as collector_log:
                    harness = demo.Harness(stack.collector, stack.env, collector_log)
                    frames = [
                        '{"jsonrpc":"2.0","id":"matrix-init","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sou17-matrix","version":"1"}}}',
                        '{"jsonrpc":"2.0","method":"notifications/initialized"}',
                        '{"jsonrpc":"2.0","id":"matrix-list","method":"tools/list"}',
                    ]
                    initialized = harness.send(frames[0])
                    harness.send(frames[1], reply=False)
                    manifest = harness.send(frames[2])
                    if not initialized or not manifest or "result" not in json.loads(manifest):
                        raise RuntimeError("initialization or admitted discovery failed")
                    call_id = "matrix-" + case["name"]
                    frame = json.dumps({"jsonrpc": "2.0", "id": call_id, "method": "tools/call", "params": {
                        "name": "read_document", "arguments": {"name": "inventory"},
                        "_meta": {"claudecode/toolUseId": "toolu_sou17_matrix", "progressToken": 17}}},
                        separators=(",", ":"))
                    frames.append(frame)
                    request_started = time.perf_counter()
                    delivered = harness.send(frame)
                    latency_ms = (time.perf_counter() - request_started) * 1000
                    exit_code = harness.close()
                artifact_data = {
                    "client-input.jsonl": ("\n".join(frames) + "\n").encode(),
                    "client-output.jsonl": b"".join(harness.received),
                    "client-call-response.jsonl": delivered or b"",
                    "executor-ledger.jsonl": read(stack.ledger),
                    "server-responses.jsonl": read(stack.responses),
                    "collector.log": read(stack.classifications),
                    "native-audit.jsonl": read(stack.workspace / ".agentfw/audit.jsonl"),
                    "registry.json": read(stack.workspace / "registry.json"),
                    "policy.yaml": read(stack.workspace / "policy.yaml"),
                    "config.yaml": read(stack.workspace / ".agentfw/config.yaml"),
                }
                credentials = [read(stack.workspace / ".agentfw" / name).strip()
                               for name in ("token", "native-token")]
                if any(token and token in data for token in credentials for data in artifact_data.values()):
                    raise RuntimeError("fixture credential found in artifact; refusing retention")
                cls = [item for item in records(artifact_data["collector.log"])
                       if item.get("event") == "mcp_classification" and item.get("host_call_id") == call_id]
                native = [item for item in records(artifact_data["native-audit.jsonl"])
                          if item.get("event") in ("native_call", "native_result")]
                original = [line for line in artifact_data["server-responses.jsonl"].splitlines(keepends=True)
                            if strict_json(line).get("id") == call_id]
                config = strict_json(artifact_data["config.yaml"])
                if config.get("enforce") is not True or not isinstance(config.get("native"), dict):
                    raise RuntimeError("actual daemon configuration not captured or not enforcing")
                row.update(call_id=call_id, classification_evidence=cls, native_decisions=native,
                           receiver_count=len(stack.receiver.bodies), gateway_exit_code=exit_code,
                           latency_ms=latency_ms, latency_scope="request write to response read; one sample",
                           config_source=".agentfw/config.yaml")
                row = grade_case(case, row, artifact_data["executor-ledger.jsonl"], delivered, original, frame)
                row["artifacts"] = {name: {"bytes": len(data), "sha256": sha(data)}
                                    for name, data in artifact_data.items()}
                for name, data in artifact_data.items():
                    (directory / name).write_bytes(data)
    except Exception as error:
        if harness is not None and harness.process.poll() is None:
            demo.stop(harness.process)
        if row.get("status") != "inconclusive":
            row["observed_status"] = row["status"]
        row.update(status="inconclusive", error_type=type(error).__name__, error=str(error))
    (directory / "result.json").write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--agentfw", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory")
    args = parser.parse_args()
    repo, binary, out = args.repo.resolve(), args.agentfw.resolve(), args.output.resolve()
    before = snapshot(repo)
    if before != {"commit": args.expected_commit, "tracked_dirty": False}:
        parser.error("exact expected HEAD and clean tracked source required")
    if not binary.is_file():
        parser.error("agentfw binary missing; build separately")
    out.mkdir(parents=True, exist_ok=False)
    binary_sha = sha(binary.read_bytes())
    spec = importlib.util.spec_from_file_location("sou17_matrix_demo", repo / "scripts/mcp-admission-demo.py")
    demo = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = demo
    spec.loader.exec_module(demo)
    report = {
        "schema_version": "sou17-production-classifier-probe/0.1", "kind": "diagnostic_matrix",
        "acceptance_passed": False, "contract_version": CONTRACT,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(), "source": before,
        "probe_script_sha256": sha(Path(__file__).resolve().read_bytes()),
        "agentfw": {"path": str(binary), "sha256": binary_sha}, "python": sys.version,
        "scope": "Synthetic replies through production Python bridge and actual native daemon/executor/result gate",
        "source_files_sha256": {name: sha((repo / name).read_bytes()) for name in (
            "scripts/mcp-admission-demo.py", "scripts/fixtures/mcp_admission_demo_server.py",
            "crates/agentfw/src/mcp/admission.rs", "crates/agentfw/src/native.rs",
            "crates/adapter/src/runner.rs")},
        "cases": [],
    }
    for case in cases():
        row = run_case(demo, binary, out, case)
        report["cases"].append(row)
        print(json.dumps({"case": row["case"], "status": row["status"], "gate": row.get("gate"),
                          "execution_count": row.get("execution_count"),
                          "released_original_result_bytes": row.get("released_original_result_bytes"),
                          "authoritative_verdict": row.get("authoritative_verdict")}))
    report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    report["source_after"] = snapshot(repo)
    report["binary_unchanged"] = sha(binary.read_bytes()) == binary_sha
    report["source_unchanged"] = report["source_after"] == before
    ok = report["binary_unchanged"] and report["source_unchanged"] \
        and all(row["status"] == "boundary_expectation_observed" for row in report["cases"])
    report["status"] = "matrix_boundary_expectations_observed" if ok else "incomplete_or_unexpected"
    report["summary"] = {
        "cases": len(report["cases"]), "boundary_expectations_observed": sum(
            row["status"] == "boundary_expectation_observed" for row in report["cases"]),
        "technical_unsupported_mapping": sum(row.get("gate") == "technical_unsupported_mapping" for row in report["cases"]),
        "classification_errors_or_quality": "not measured",
    }
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "acceptance_passed": False, **report["summary"]}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
