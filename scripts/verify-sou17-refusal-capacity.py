#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check that 64 refused reads do not consume permits for a useful 65th call.

Uses the existing production demo's daemon, registry, executor and stdio harness.
Only the Python classifier output is synthetic. No Cargo build or source edit.
Exit 0: this bounded regression passed; exit 1: observed regression; exit 2:
inconclusive. A pass never establishes complete SOU-17 acceptance.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ASK_COUNT = 64
BENIGN_ID = "sou17-benign-after-asks"


def grade(observed, stable, expected_classifier_sha256=None):
    """Grade witnessed behavior; incomplete fixture evidence cannot pass.

    A witnessed effect for a confirmed authoritative Ask is a failure even when
    later fixture output is incomplete. Source/binary instability cannot support
    a claim against this exact candidate.
    """
    if stable is not True or not isinstance(observed, dict):
        return "inconclusive"
    asks = observed.get("ask_calls")
    classifications = observed.get("classifications")
    if not isinstance(asks, list) or not isinstance(classifications, list):
        return "inconclusive"
    classifier_digest = expected_classifier_sha256 or observed.get("expected_classifier_sha256")
    if not isinstance(classifier_digest, str) or len(classifier_digest) != 64 \
            or any(character not in "0123456789abcdef" for character in classifier_digest):
        return "inconclusive"
    expected_ids = [f"sou17-ask-{index+1:02d}" for index in range(ASK_COUNT)]

    def count(value):
        return type(value) is int and value >= 0

    def valid_classification(row, call_id, verdict, uncertainty):
        if not isinstance(row, dict):
            return False
        prediction = row.get("classification")
        if not isinstance(prediction, dict):
            return False
        confidence, actual_uncertainty = prediction.get("confidence"), prediction.get("uncertainty")
        scores_valid = all(type(score) in (int, float) and 0.0 <= score <= 1.0
                           and math.isfinite(score) for score in (confidence, actual_uncertainty))
        return scores_valid and confidence == 0.95 and actual_uncertainty == uncertainty \
            and prediction.get("actions") == ["read"] and prediction.get("unknown") is False \
            and row.get("host_call_id") == call_id and row.get("tool") == "read_document" \
            and row.get("source") == "rule-baseline/python" \
            and row.get("classifier_sha256") == classifier_digest \
            and row.get("authoritative_verdict") == verdict

    confirmed_ask_ids = {
        call_id for call_id in expected_ids
        if sum(valid_classification(row, call_id, "ask", 0.9) for row in classifications) == 1
    }
    # Check forbidden effects before requiring the entire 65-call transcript.
    for row in asks:
        if isinstance(row, dict) and row.get("host_call_id") in confirmed_ask_ids \
                and count(row.get("executor_count")) and row["executor_count"] > 0:
            return "fail"
    if len(confirmed_ask_ids) == ASK_COUNT and count(observed.get("ask_executor_count")) \
            and observed["ask_executor_count"] > 0:
        return "fail"

    if len(asks) != ASK_COUNT or len(classifications) != ASK_COUNT+1:
        return "inconclusive"
    if observed.get("ledger_valid") is not True:
        return "inconclusive"
    if [row.get("host_call_id") if isinstance(row, dict) else None for row in asks] != expected_ids:
        return "inconclusive"
    if not all(valid_classification(row, call_id, "ask", 0.9)
               for row, call_id in zip(classifications[:ASK_COUNT], expected_ids)):
        return "inconclusive"
    if not valid_classification(classifications[-1], BENIGN_ID, "allow", 0.05) \
            or observed.get("classifier_invocations") != ASK_COUNT+1:
        return "inconclusive"

    for row, call_id in zip(asks, expected_ids):
        response = row.get("response")
        if not isinstance(response, dict) or response.get("id") != call_id:
            return "inconclusive"
        result = response.get("result")
        if row.get("correlated_ask_refusal") is not True or not isinstance(result, dict) \
                or result.get("isError") is not True or "policy_unconfirmed_ask" not in json.dumps(result) \
                or not count(row.get("executor_count")) or row["executor_count"] != 0:
            return "inconclusive"
    required_counts = ("ask_executor_count", "total_executor_count", "benign_executor_delta",
                       "benign_client_bytes", "receiver_count")
    if not all(count(observed.get(key)) for key in required_counts) \
            or observed["ask_executor_count"] != 0 or observed["receiver_count"] != 0 \
            or observed["total_executor_count"] != observed["benign_executor_delta"]:
        return "inconclusive"
    required_booleans = ("benign_original_call_bytes_preserved", "benign_original_result_released")
    if not all(type(observed.get(key)) is bool for key in required_booleans) \
            or type(observed.get("gateway_exit_code")) is not int or "benign_response" not in observed:
        return "inconclusive"

    benign_response = observed.get("benign_response")
    benign_result = benign_response.get("result") if isinstance(benign_response, dict) else None
    useful = observed["benign_executor_delta"] == 1 \
        and observed["benign_original_call_bytes_preserved"] \
        and observed["benign_original_result_released"] and observed["benign_client_bytes"] > 0 \
        and observed["gateway_exit_code"] == 0 and isinstance(benign_result, dict) \
        and benign_response.get("id") == BENIGN_ID and benign_result.get("isError") is not True
    if useful:
        return "pass"
    if observed["benign_executor_delta"] == 0 and observed["benign_response"] is None:
        native = observed.get("native_decisions")
        confirmed_prefix = isinstance(native, list) and len(native) == ASK_COUNT \
            and all(isinstance(row, dict) and row.get("event") == "native_call"
                    and row.get("verdict") == "allow" and row.get("released") is True
                    for row in native)
        exhausted = confirmed_prefix and observed.get("benign_transport_outcome") == "eof" \
            and observed.get("benign_original_server_result_count") == 0 \
            and observed["benign_client_bytes"] == 0 and observed["gateway_exit_code"] != 0 \
            and observed["benign_original_result_released"] is False
        return "fail" if exhausted else "inconclusive"
    return "fail"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *arguments):
    return subprocess.run(["git", *arguments], cwd=repo, check=True,
                          capture_output=True, text=True, timeout=10).stdout.strip()


def snapshot(repo):
    return {"commit": git(repo, "rev-parse", "HEAD"),
            "tracked_dirty": bool(git(repo, "status", "--porcelain", "--untracked-files=no"))}


def read(path):
    return path.read_bytes() if path.is_file() else b""


def records(data):
    result = []
    for raw in data.splitlines():
        try:
            result.append(json.loads(raw))
        except (ValueError, UnicodeDecodeError):
            continue
    return result


def ledger_records(data):
    """An invalid nonempty executor ledger must not become a zero-effect witness."""
    entries = []
    for raw in data.splitlines():
        entry = json.loads(raw)
        if not isinstance(entry, dict) or entry.get("method") != "tools/call":
            raise ValueError("malformed executor ledger entry")
        entries.append(entry)
    return entries


def load_demo(repo):
    spec = importlib.util.spec_from_file_location("sou17_capacity_demo", repo / "scripts/mcp-admission-demo.py")
    demo = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = demo
    spec.loader.exec_module(demo)
    return demo


def classifier_source(counter):
    # The production seam omits host IDs from semantic input and launches a new
    # process for each call. A private local counter selects the 65th reply;
    # it does not change any runtime admission state or tool arguments.
    return """#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import json, pathlib, sys
request = json.loads(sys.stdin.readline())
assert request['tool_name'] == 'read_document'
assert request['raw_arguments'] == {'name': 'inventory'}
counter = pathlib.Path(COUNTER)
count = int(counter.read_text()) + 1
counter.write_text(str(count))
reply = {'status':'ok','actions':['read'],'unknown':False,'confidence':0.95,
         'uncertainty':0.9 if count <= 64 else 0.05,
         'reason':'Synthetic read uncertainty for bounded refusal capacity regression'}
print(json.dumps(reply, separators=(',', ':')))
""".replace("COUNTER", repr(str(counter)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--agentfw", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory")
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    repo, binary, out = args.repo.resolve(), args.agentfw.resolve(), args.output.resolve()
    before = snapshot(repo)
    if before["commit"] != args.expected_commit or before["tracked_dirty"]:
        parser.error("candidate must have exact expected HEAD and clean tracked source")
    if not binary.is_file():
        parser.error("production agentfw binary must already be built")
    out.mkdir(parents=True, exist_ok=False)
    binary_sha = sha(binary.read_bytes())
    demo = load_demo(repo)
    report = {
        "schema_version": "sou17-refusal-capacity-probe/0.1", "kind": "independent_regression",
        "acceptance_passed": False, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source": before, "agentfw": {"path": str(binary), "sha256": binary_sha},
        "probe_script_sha256": sha(Path(__file__).read_bytes()),
        "limits": {"ask_calls": ASK_COUNT, "benign_followups": 1, "total_deadline_seconds": 60},
        "expected": {"ask_responses": ASK_COUNT, "ask_executor_count": 0,
                     "benign_executor_delta": 1, "benign_result_released": True},
        "source_files_sha256": {name: sha((repo / name).read_bytes()) for name in (
            "scripts/mcp-admission-demo.py", "scripts/fixtures/mcp_admission_demo_server.py",
            "crates/agentfw/src/mcp/admission.rs", "crates/agentfw/src/native.rs")},
    }
    artifacts, frames, ask_observations = {}, [], []
    harness = None
    previous_handler = signal.getsignal(signal.SIGALRM)

    def deadline(_signal, _frame):
        raise TimeoutError("bounded refusal capacity diagnostic exceeded 60 seconds")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(60)
    try:
        with tempfile.TemporaryDirectory(prefix="sou17-capacity-", dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            counter = Path(tmp) / "private-classifier-count"
            counter.write_text("0")
            source = classifier_source(counter)
            classifier = out / "synthetic-capacity-classifier.py"
            classifier.write_text(source, encoding="utf-8")
            report["classifier"] = {
                "synthetic": True, "contract_version": demo.CLASSIFIER_CONTRACT,
                "sha256": sha(source.encode()), "profile": "64 Read uncertainty=0.9, then Read uncertainty=0.05",
                "confidence": 0.95, "counter_storage": "private temporary fixture file; not an execution witness",
            }
            demo.classifier_environment = lambda: {
                "AGENTFW_CLASSIFIER": "rule-baseline", "AGENTFW_RULE_BASELINE": str(classifier),
                "AGENTFW_CLASSIFIER_PYTHON": sys.executable,
            }
            with demo.agent_stack(binary, Path(tmp) / "workspace") as stack:
                try:
                    with stack.classifications.open("wb") as collector_log:
                        harness = demo.Harness(stack.collector, stack.env, collector_log)
                        frames = [
                            '{"jsonrpc":"2.0","id":"capacity-init","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sou17-capacity","version":"1"}}}',
                            '{"jsonrpc":"2.0","method":"notifications/initialized"}',
                            '{"jsonrpc":"2.0","id":"capacity-list","method":"tools/list"}',
                        ]
                        initialized = harness.send(frames[0])
                        harness.send(frames[1], reply=False)
                        manifest = harness.send(frames[2])
                        if not initialized or not manifest or "result" not in json.loads(manifest):
                            raise RuntimeError("initialization/discovery was not admitted")
                        for index in range(ASK_COUNT):
                            call_id = f"sou17-ask-{index + 1:02d}"
                            frame = json.dumps({"jsonrpc":"2.0", "id":call_id, "method":"tools/call",
                                "params":{"name":"read_document", "arguments":{"name":"inventory"},
                                          "_meta":{"claudecode/toolUseId":f"toolu_capacity_{index+1}",
                                                   "progressToken":index+1}}}, separators=(",", ":"))
                            frames.append(frame)
                            started = time.perf_counter()
                            reply = harness.send(frame)
                            decoded = json.loads(reply) if reply else None
                            ask_observations.append({
                                "host_call_id":call_id, "response":decoded, "client_response_bytes":len(reply or b""),
                                "executor_count":len(ledger_records(read(stack.ledger))),
                                "latency_ms":(time.perf_counter()-started)*1000,
                                "correlated_ask_refusal":bool(decoded and decoded.get("id")==call_id
                                    and decoded.get("result",{}).get("isError") is True
                                    and "policy_unconfirmed_ask" in json.dumps(decoded)),
                            })
                            if reply is None:
                                raise RuntimeError(f"transport closed before completing Ask {index+1}")
                        count_before = len(ledger_records(read(stack.ledger)))
                        benign_id = BENIGN_ID
                        benign_frame = json.dumps({"jsonrpc":"2.0", "id":benign_id, "method":"tools/call",
                            "params":{"name":"read_document", "arguments":{"name":"inventory"},
                                      "_meta":{"claudecode/toolUseId":"toolu_capacity_control", "progressToken":65}}}, separators=(",", ":"))
                        frames.append(benign_frame)
                        benign_reply = harness.send(benign_frame)
                        benign_transport = "response" if benign_reply else "timeout"
                        if benign_reply is None:
                            try:
                                harness.process.wait(timeout=2)
                                benign_transport = "eof"
                            except subprocess.TimeoutExpired:
                                pass
                        exit_code = harness.close()
                    raw_ledger, raw_responses = read(stack.ledger), read(stack.responses)
                    original = [raw for raw in raw_responses.splitlines(keepends=True)
                                if json.loads(raw).get("id")==benign_id]
                    classification = [row for row in records(read(stack.classifications))
                                      if row.get("event")=="mcp_classification"]
                    native = [row for row in records(read(stack.workspace / ".agentfw/audit.jsonl"))
                              if row.get("event") in ("native_call","native_result")]
                    report["observed"] = {
                        "ask_calls":ask_observations, "classifications":classification,
                        "native_decisions":native, "classifier_invocations":int(counter.read_text()),
                        "expected_classifier_sha256":sha(source.encode()), "ledger_valid":True,
                        "ask_executor_count":count_before, "total_executor_count":len(ledger_records(raw_ledger)),
                        "benign_executor_delta":len(ledger_records(raw_ledger))-count_before,
                        "benign_response":json.loads(benign_reply) if benign_reply else None,
                        "benign_transport_outcome":benign_transport,
                        "benign_original_server_result_count":len(original),
                        "benign_client_bytes":len(benign_reply or b""),
                        "benign_original_result_released":bool(benign_reply and len(original)==1 and benign_reply==original[0]),
                        "benign_original_call_bytes_preserved":raw_ledger==(benign_frame+"\n").encode(),
                        "receiver_count":len(stack.receiver.bodies), "gateway_exit_code":exit_code,
                    }
                finally:
                    if harness is not None and harness.process.poll() is None:
                        demo.stop(harness.process)
                    artifacts = {
                        "client-input.jsonl":("\n".join(frames)+"\n").encode(),
                        "client-output.jsonl":b"".join(harness.received) if harness else b"",
                        "executor-ledger.jsonl":read(stack.ledger), "server-responses.jsonl":read(stack.responses),
                        "collector.log":read(stack.classifications),
                        "native-audit.jsonl":read(stack.workspace / ".agentfw/audit.jsonl"),
                        "registry.json":read(stack.workspace / "registry.json"), "policy.yaml":read(stack.workspace / "policy.yaml"),
                    }
                    credentials = [read(stack.workspace / ".agentfw" / name).strip() for name in ("token","native-token")]
                    if any(token and token in data for token in credentials for data in artifacts.values()):
                        artifacts = {}
                        raise RuntimeError("fixture credentials detected; refusing artifact retention")
        after = snapshot(repo)
        report["source_after"] = after
        stable = before==after and sha(binary.read_bytes())==binary_sha
        observed = report["observed"]
        report["status"] = grade(observed, stable, report["classifier"]["sha256"])
        benign_failure = report["status"] == "fail" and observed["ask_executor_count"] == 0 \
            and observed["benign_executor_delta"] == 0
        report["interpretation"] = (
            "After 64 unexecuted Ask refusals, the separately classified benign Allow did not execute or release its original result. Source inspection identifies retained native permits and the 64-call session cap; the collector discards the rejected HTTP response body, so no native_call_cap response code is claimed as a directly observed artifact."
            if benign_failure else "Bounded same-session useful-call check only; not complete SOU-17 acceptance.")
    except Exception as error:
        report.update(status="inconclusive", error_type=type(error).__name__, error=str(error))
        report.setdefault("partial_ask_observations",ask_observations)
        partial = {"ask_calls":ask_observations,
                   "classifications":[row for row in records(artifacts.get("collector.log",b""))
                                      if isinstance(row,dict) and row.get("event")=="mcp_classification"],
                   "expected_classifier_sha256":report.get("classifier",{}).get("sha256")}
        try:
            partial["ask_executor_count"] = len(ledger_records(artifacts.get("executor-ledger.jsonl",b"")))
            partial["ledger_valid"] = True
        except (ValueError, UnicodeDecodeError):
            partial["ledger_valid"] = False
        try:
            after = snapshot(repo)
            report["source_after"] = after
            stable = before == after and sha(binary.read_bytes()) == binary_sha
        except (OSError, subprocess.SubprocessError):
            stable = False
        report["partial_observed"] = partial
        if grade(partial, stable, report.get("classifier",{}).get("sha256")) == "fail":
            report["status"] = "fail"
            report["interpretation"] = "An authoritative Ask had an independently witnessed executor effect; later fixture output was incomplete."
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)
        report["artifacts"] = {name:{"bytes":len(data),"sha256":sha(data)} for name,data in artifacts.items()}
        for name,data in artifacts.items():
            (out/name).write_bytes(data)
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        (out/"results.json").write_text(json.dumps(report,indent=2,allow_nan=False)+"\n",encoding="utf-8")
    print(json.dumps({"status":report["status"],"output":str(out),
                      "asks_observed":len(report.get("observed",{}).get("ask_calls",ask_observations)),
                      "benign_executor_delta":report.get("observed",{}).get("benign_executor_delta")},indent=2))
    return {"pass":0,"fail":1,"inconclusive":2}[report["status"]]


if __name__=="__main__":
    raise SystemExit(main())
