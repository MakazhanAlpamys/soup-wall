#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Paired local read latency: production admission versus a measurement-only control.

Uses the existing demo fixture and Harness, the real rule-baseline Python bridge,
and persistent sessions. This is bounded fixture evidence, not host acceptance or
population FPR. The direct server is an unprotected measurement control only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(raw):
    def reject(_value):
        raise ValueError("non-finite JSON")
    def floating(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        return value
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, parse_constant=reject, parse_float=floating, object_pairs_hook=pairs)


def records(raw):
    if raw and not raw.endswith(b"\n"):
        raise ValueError("unterminated witness")
    rows = [strict_json(line) for line in raw.splitlines()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("witness is not an object")
    return rows


def read(path):
    return path.read_bytes() if path.exists() else b""


def snapshot(repo):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo, timeout=15).decode()
    names = git("ls-files", "-z").split("\0")
    hashes = {name: sha((repo / name).read_bytes()) for name in names if name}
    return {"commit": git("rev-parse", "HEAD").strip(),
            "dirty": bool(git("status", "--porcelain", "--untracked-files=all").strip()),
            "tracked_inputs_sha256": hashes,
            "inputs_digest": sha(json.dumps(hashes, sort_keys=True).encode())}


def percentile(values, fraction):
    if not values or not 0 < fraction <= 1 or any(not finite(value) for value in values):
        raise ValueError("invalid percentile inputs")
    return sorted(values)[math.ceil(len(values) * fraction) - 1]


def finite(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def grade(row, protected, classifier_digest):
    """Missing/malformed evidence cannot certify an Allow or produce latency statistics."""
    row.update(status="incomplete", false_interruption=None)
    try:
        pair, warmup = row.get("pair"), row.get("warmup")
        if (type(pair) is not int or type(warmup) is not bool or pair < -1
                or (warmup and pair != -1) or (not warmup and pair < 0)):
            raise ValueError("invalid sample identity")
        expected_id = "warmup" if warmup else f"latency-{pair}"
        if (row.get("host_call_id") != expected_id or row.get("path") not in ("direct", "protected")
                or protected != (row["path"] == "protected")):
            raise ValueError("invalid host/sample identity")
        request = strict_json(row["submitted_frame"])
        if (not isinstance(request, dict) or not isinstance(request.get("params"), dict)
                or request.get("id") != expected_id):
            raise ValueError("invalid call shape or identity")
        effects = records(row["executor_delta_raw"].encode())
        prepared = records(row["server_delta_raw"].encode())
        delivered = strict_json(row["released_raw"]) if row["released_raw"] else None
        if not finite(row["request_latency_ms"]) or not 0 <= row["request_latency_ms"] <= 15000:
            raise ValueError("invalid request timing")
        if request.get("jsonrpc") != "2.0" or request.get("id") != row["host_call_id"] \
                or request.get("method") != "tools/call" or request.get("params", {}).get("name") != "read_document" \
                or request["params"].get("arguments") != {"name": "inventory"}:
            raise ValueError("unexpected call")
        row.update(executor_count=len(effects), prepared_result_count=len(prepared),
                   released_bytes=len(row["released_raw"].encode()))
        if delivered is None or not isinstance(delivered, dict):
            raise ValueError("missing response")
        failures = []
        if effects != [request] or row["executor_delta_raw"] != row["submitted_frame"] + "\n":
            failures.append("expected one exact original executor frame")
        expected = {"jsonrpc": "2.0", "id": request["id"],
                    "result": {"content": [{"type": "text", "text": "Inventory: 7 red widgets."}]}}
        if delivered != expected or prepared != [expected] or row["server_delta_raw"] != row["released_raw"]:
            failures.append("expected one original successful result with matching ID and bytes")
        row["execution_anomaly"] = effects != [request]
        row["useful_result_delivered"] = delivered == expected
        row["expected_execution_seen"] = request in effects
        if protected:
            cls, native = row["classifications"], row["native_decisions"]
            if not isinstance(cls, list) or len(cls) != 1 or not isinstance(native, list) or len(native) != 2:
                raise ValueError("missing or duplicate production gate evidence")
            evidence = cls[0]
            if (not isinstance(evidence, dict) or not isinstance(evidence.get("classification"), dict)
                    or any(not isinstance(item, dict) for item in native)
                    or not isinstance(classifier_digest, str) or len(classifier_digest) != 64
                    or any(c not in "0123456789abcdef" for c in classifier_digest)):
                raise ValueError("invalid classifier/native evidence shape or expected revision")
            scores = evidence["classification"]
            if evidence.get("host_call_id") != request["id"] or evidence.get("source") != "rule-baseline/python" \
                    or evidence.get("classifier_sha256") != classifier_digest \
                    or evidence.get("tool") != "read_document" \
                    or evidence.get("contract_version") != "sw-classification/candidate-1" \
                    or evidence.get("args_sha256") != sha(b'{"name":"inventory"}'):
                raise ValueError("classifier identity/revision mismatch")
            if any(not finite(scores.get(field)) or not 0 <= scores[field] <= 1
                   for field in ("confidence", "uncertainty")):
                raise ValueError("invalid classifier scores")
            if scores.get("actions") != ["read"] or scores.get("unknown") is not False \
                    or evidence.get("authoritative_verdict") != "allow" \
                    or evidence.get("policy") != "reached" or evidence.get("failure") is not None:
                failures.append("real baseline did not produce useful authoritative Allow")
            if [item.get("event") for item in native] != ["native_call", "native_result"] \
                    or any(item.get("verdict") != "allow" or item.get("released") is not True
                           or item.get("tool") != "read_document" or item.get("shadow") is not False for item in native) \
                    or not isinstance(native[0].get("call_id"), str) or not native[0]["call_id"] \
                    or native[0]["call_id"] != native[1].get("call_id") \
                    or not isinstance(native[0].get("session"), str) or not native[0]["session"] \
                    or native[0]["session"] != native[1].get("session") \
                    or not isinstance(native[0].get("binding_sha256"), str) \
                    or len(native[0]["binding_sha256"]) != 64 \
                    or any(c not in "0123456789abcdef" for c in native[0]["binding_sha256"]) \
                    or native[0]["binding_sha256"] != native[1].get("binding_sha256"):
                failures.append("native invocation/result Allow evidence differs")
        row.update(status="fail" if failures else "pass", errors=failures,
                   false_interruption=(not row["useful_result_delivered"] or not row["expected_execution_seen"])
                   if protected else False)
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError) as error:
        row["error"] = str(error)
    return row


def summarize(rows, count, stable, evidence_complete=True):
    measured = [row for row in rows if row.get("warmup") is False]
    identities = [(row.get("pair"), row.get("path")) for row in measured]
    warmups = [row for row in rows if row.get("warmup") is True]
    expected = {(index, path) for index in range(count) for path in ("direct", "protected")}
    complete = (len(rows) == count * 2 + 2 and len(identities) == len(set(identities))
                and set(identities) == expected and len(warmups) == 2
                and {(row.get("pair"), row.get("path")) for row in warmups} == {(-1, "direct"), (-1, "protected")}
                and all(row.get("status") == "pass" for row in rows))
    summary = {"status": "pass" if complete and stable and evidence_complete else "incomplete",
               "requested_pairs": count, "observed_rows": len(measured), "source_binary_stable": stable,
               "complete_final_witnesses": evidence_complete,
               "failed_rows": sum(row.get("status") == "fail" for row in rows),
               "incomplete_rows": sum(row.get("status") == "incomplete" for row in rows),
               "fixture_false_interruptions": sum(row.get("false_interruption") is True for row in measured),
               "unknown_interruption_rows": sum(row.get("false_interruption") is None for row in measured
                                                if row.get("path") == "protected"),
               "execution_anomalies": sum(row.get("execution_anomaly") is True for row in measured),
               "population_false_interruption_rate": "not measured", "latency_limit": "not agreed; no numeric gate"}
    if summary["failed_rows"]:
        summary["status"] = "fail"
    if not complete or not stable or not evidence_complete or any(row.get("status") != "pass" for row in rows):
        if summary["status"] != "fail":
            summary["status"] = "incomplete"
        return summary
    pairs = []
    for index in range(count):
        pair = {row["path"]: row for row in measured if row["pair"] == index}
        if set(pair) != {"direct", "protected"} or pair["direct"]["submitted_frame"] != pair["protected"]["submitted_frame"] \
                or pair["direct"]["released_raw"] != pair["protected"]["released_raw"]:
            summary["status"] = "incomplete"
            return summary
        pairs.append(pair["protected"]["request_latency_ms"] - pair["direct"]["request_latency_ms"])
    for path in ("direct", "protected"):
        values = [row["request_latency_ms"] for row in measured if row["path"] == path]
        summary[path + "_request_ms"] = {f"p{p}": percentile(values, p / 100) for p in (50, 95, 99)}
    summary["paired_overhead_ms"] = {"mean": sum(pairs) / count,
                                     **{f"p{p}": percentile(pairs, p / 100) for p in (50, 95, 99)}, "raw": pairs}
    return summary


def reconcile(rows, ledger, server_results, client_results, path):
    """The complete post-stop witness must agree with every submitted call/result."""
    try:
        executions, responses = records(ledger), records(server_results)
        expected = [row for row in rows if row["path"] == path]
        return (len(executions) == len(expected)
                and ledger == "".join(row["submitted_frame"] + "\n" for row in expected).encode()
                and len(responses) == len(expected) + 2 and server_results == client_results
                and [response.get("id") for response in responses] == ["init", "list"]
                    + [row["host_call_id"] for row in expected])
    except (KeyError, TypeError, ValueError, UnicodeError):
        return False


def retain(out, artifacts, credentials):
    if any(token and token in data for token in credentials for data in artifacts.values()):
        raise ValueError("credential found in artifact; refusing retention")
    for name, data in artifacts.items():
        (out / name).write_bytes(data)
    return {name: {"bytes": len(data), "sha256": sha(data)} for name, data in artifacts.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--agentfw", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--pairs", type=int, default=30)
    args = parser.parse_args()
    if not 30 <= args.pairs <= 60 or sys.platform not in ("linux", "darwin"):
        parser.error("native Linux/macOS and 30–60 pairs required")
    repo, binary, out = args.repo.resolve(), args.agentfw.resolve(), args.output.resolve()
    if out.is_relative_to(repo):
        parser.error("evidence must be outside the source checkout")
    before = snapshot(repo)
    if before["dirty"] or before["commit"] != args.expected_commit or not binary.is_file():
        parser.error("clean exact source and a separately built production binary required")
    out.mkdir(parents=True, exist_ok=False)
    binary_sha = sha(binary.read_bytes())
    probe_file = Path(__file__).resolve()
    probe_sha = sha(probe_file.read_bytes())
    spec = importlib.util.spec_from_file_location("sou17_latency_demo", repo / "scripts/mcp-admission-demo.py")
    demo = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = demo
    spec.loader.exec_module(demo)
    demo.REAL_BASELINE = True
    classifier_sha = sha((repo / "rule_baseline/rule_baseline.py").read_bytes())
    report = {"schema_version": "sou17-paired-latency/0.1", "timestamp_utc": datetime.now(timezone.utc).isoformat(),
              "source_before": before, "probe_script_sha256": probe_sha,
              "agentfw": {"path": str(binary), "sha256": binary_sha,
                          "build_provenance": "caller supplies separately built binary; this script does not attest its build"},
              "classifier": {"mode": "rule-baseline", "sha256": classifier_sha, "synthetic": False},
              "python": sys.version, "platform": platform.platform(), "machine": platform.machine(),
              "hardware": {"logical_cpu_count": os.cpu_count(), "processor": platform.processor()},
              "pairs": args.pairs, "excluded_warmup_pairs": 1, "expected_fixture_false_interruptions": 0,
              "latency_scope": "Harness request write to original response read; persistent sessions; includes per-call Python classifier startup and collector/daemon/local fixture work",
              "control_scope": "unprotected same safe fixture only for measurement; not an authorized production execution path",
              "accepted_numeric_latency_limit": None, "acceptance_passed": False, "rows": []}
    harnesses, credentials = {}, []
    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("180-second measurement deadline")))
    signal.alarm(180)
    try:
        with tempfile.TemporaryDirectory(prefix="sou17-latency-", dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            with demo.agent_stack(binary, Path(tmp) / "workspace") as stack:
                ledgers = {"protected": stack.ledger, "direct": stack.workspace / "direct-executed.jsonl"}
                direct = list(stack.collector[stack.collector.index("--") + 1:])
                direct[direct.index("--ledger") + 1] = str(ledgers["direct"])
                credentials = [read(stack.workspace / ".agentfw" / name).strip() for name in ("token", "native-token")]
                report["runtime"] = {"protected_command": stack.collector, "direct_control_command": direct,
                    "classifier_environment": demo.classifier_environment()}
                with stack.classifications.open("wb") as protected_log, (stack.workspace / "direct.log").open("wb") as direct_log:
                    harnesses = {"protected": demo.Harness(stack.collector, stack.env, protected_log),
                                 "direct": demo.Harness(direct, stack.env, direct_log)}
                    for path, harness in harnesses.items():
                        init = harness.send('{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sou17-latency","version":"1"}}}')
                        harness.send('{"jsonrpc":"2.0","method":"notifications/initialized"}', reply=False)
                        manifest = harness.send('{"jsonrpc":"2.0","id":"list","method":"tools/list"}')
                        if not init or strict_json(init).get("id") != "init" \
                                or strict_json(init).get("result", {}).get("protocolVersion") != "2024-11-05" \
                                or not manifest or strict_json(manifest).get("id") != "list" \
                                or strict_json(manifest).get("result", {}).get("tools") != stack.tools:
                            raise ValueError("initialization/discovery failed: " + path)
                    for index in range(-1, args.pairs):
                        call_id = "warmup" if index == -1 else f"latency-{index}"
                        frame = json.dumps({"jsonrpc": "2.0", "id": call_id, "method": "tools/call", "params": {
                            "name": "read_document", "arguments": {"name": "inventory"},
                            "_meta": {"claudecode/toolUseId": f"toolu_{call_id}", "progressToken": index + 2}}}, separators=(",", ":"))
                        order = ("direct", "protected") if index % 2 else ("protected", "direct")
                        for path in order:
                            ledger = ledgers[path]
                            before_call, before_result = len(read(ledger)), len(read(ledger.with_suffix(".responses")))
                            audit_before = len(records(read(stack.workspace / ".agentfw/audit.jsonl")))
                            start = time.perf_counter_ns()
                            reply = harnesses[path].send(frame)
                            latency = (time.perf_counter_ns() - start) / 1_000_000
                            report["rows"].append({"pair": index, "warmup": index == -1, "path": path,
                                "host_call_id": call_id, "submitted_frame": frame, "request_latency_ms": latency,
                                "executor_delta_raw": read(ledger)[before_call:].decode(),
                                "server_delta_raw": read(ledger.with_suffix(".responses"))[before_result:].decode(),
                                "released_raw": (reply or b"").decode(),
                                "native_decisions": [r for r in records(read(stack.workspace / ".agentfw/audit.jsonl"))[audit_before:]
                                    if r.get("event") in ("native_call", "native_result")] if path == "protected" else []})
                    report["exit_codes"] = {path: harness.close() for path, harness in harnesses.items()}
                classifications = demo.classification_evidence(stack.classifications)
                for row in report["rows"]:
                    row["classifications"] = [r for r in classifications if r.get("host_call_id") == row["host_call_id"]]
                    grade(row, row["path"] == "protected", classifier_sha)
                config = strict_json(read(stack.workspace / ".agentfw/config.yaml"))
                if config.get("enforce") is not True or config.get("native", {}).get("registry_sha256") != stack.registry_sha256 \
                        or any(code != 0 for code in report["exit_codes"].values()) or stack.receiver.bodies:
                    raise ValueError("configuration, exit or unexpected egress witness failed")
                artifacts = {"protected-ledger.jsonl": read(ledgers["protected"]),
                    "direct-ledger.jsonl": read(ledgers["direct"]), "protected-server-results.jsonl": read(stack.responses),
                    "direct-server-results.jsonl": read(ledgers["direct"].with_suffix(".responses")),
                    "collector.log": read(stack.classifications), "daemon.log": read(stack.workspace / "daemon.log"),
                    "direct.log": read(stack.workspace / "direct.log"), "native-audit.jsonl": read(stack.workspace / ".agentfw/audit.jsonl"),
                    "config.yaml": read(stack.workspace / ".agentfw/config.yaml"), "registry.json": read(stack.workspace / "registry.json"),
                    "policy.yaml": read(stack.workspace / "policy.yaml"), "rows.json": json.dumps(report["rows"], allow_nan=False).encode(),
                    "protected-client-output.jsonl": b"".join(harnesses["protected"].received),
                    "direct-client-output.jsonl": b"".join(harnesses["direct"].received)}
                report["post_stop_reconciliation"] = {path: reconcile(report["rows"],
                    artifacts[path + "-ledger.jsonl"], artifacts[path + "-server-results.jsonl"],
                    artifacts[path + "-client-output.jsonl"], path) for path in ("direct", "protected")}
                report["artifacts"] = retain(out, artifacts, credentials)
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)
        for harness in harnesses.values():
            if harness.process.poll() is None:
                demo.stop(harness.process)
        try:
            report["source_after"] = snapshot(repo)
            report["probe_script_sha256_after"] = sha(probe_file.read_bytes())
            stable = (before == report["source_after"] and sha(binary.read_bytes()) == binary_sha
                      and report["probe_script_sha256_after"] == probe_sha)
        except (OSError, subprocess.SubprocessError) as error:
            stable = False
            report["recheck_error"] = type(error).__name__
    report["summary"] = summarize(report["rows"], args.pairs, stable,
        "error" not in report and all(report.get("post_stop_reconciliation", {}).get(path) is True
                                     for path in ("direct", "protected")))
    serialized = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if any(token and token in serialized.encode() for token in credentials):
        report = {"schema_version": "sou17-paired-latency/0.1", "error": "credential found; observations withheld",
                  "summary": {"status": "incomplete"}, "acceptance_passed": False}
        serialized = json.dumps(report, indent=2) + "\n"
    (out / "results.json").write_text(serialized, encoding="utf-8")
    print(json.dumps(report["summary"], allow_nan=False))
    print("Evidence:", out)
    return {"pass": 0, "fail": 1, "incomplete": 2}[report["summary"]["status"]]


if __name__ == "__main__":
    sys.exit(main())
