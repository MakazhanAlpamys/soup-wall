# SOU-17 candidate verification — 2026-10-10

Owner: konung3. Review coordinator: Nari_Ab. Scope: R06, bounded P01–P02.

**Outcome: regression checks passed; integrated acceptance remains blocked.**
The exact [SOU-15 candidate a8b237d](https://github.com/SoupTeam/soup-wall/commit/a8b237d8237bdda534ca294bf1ebed7af8d469bd)
from [PR #62](https://github.com/SoupTeam/soup-wall/pull/62) was tested from a clean
checkout. All 91 enumerated SOU-17 regressions and 18 additional input/resource
tests passed. The passing tests do not establish the claimed authoritative
classification/resource-policy composition. The independently reviewed gaps below
keep [SOU-17](https://linear.app/soup-wall/issue/SOU-17/task-11-independently-verify-failure-overlap-and-replay-behavior)
open pending an updated SOU-15 candidate and verification of agreed limits.

## Source and reproducibility

- Candidate: `a8b237d8237bdda534ca294bf1ebed7af8d469bd`; tracked and untracked
  source clean before and after verification; input digest unchanged:
  `60b6437520cd7e58ffc220f266169d9df1269bc0a59af66f5026a283295aba91`.
- Host: macOS/Darwin 25.3.0, arm64; Rust/Cargo 1.99.0, CPython 3.14.3.
- Locked offline dependencies, default features, debug build;
  `CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`,
  `CARGO_INCREMENTAL=0`; canonical macOS `TMPDIR`.
- Actual `agentfw` executable SHA-256:
  `c92545ddb0cc38ad5a342fba5ad58591d9d468572e281d128704b8758fb3f0f5`.
- Local loopback fixtures only. No external model, model credential or paid API.
  Registry, policy, classifier, test source and binary hashes are retained in
  [sanitized outcomes](sou17_candidate_a8b237d_2026-10-10.json).

From a clean checkout of the candidate, using the prerequisites in
[DEVELOPMENT](../../DEVELOPMENT.md):

```sh
git rev-parse HEAD
cargo fetch --locked
python3 scripts/verify-sou17.py \
  --expected-commit a8b237d8237bdda534ca294bf1ebed7af8d469bd \
  --offline --out target/sou17-candidate-a8b237d
cargo test --locked --offline -p agentfw \
  --test mcp_inputs --test mcp_resources -- --test-threads=1
python3 scripts/mcp-admission-demo.py --classifier rule-baseline \
  --agentfw target/debug/agentfw --keep \
  --out target/sou17-demo-a8b237d.json
```

The first offline attempt stopped before tests because `tokio 1.53.2` was absent
from the local cache. After `cargo fetch --locked`, the complete rerun passed.
This infrastructure attempt is retained separately; no test failure was erased.
The verifier still labels its scope `sou17-early-regression` and acceptance
`pending-sou15-integration`; its success status is not final acceptance.

## Observed outcomes

| Surface | Observed result | Scope |
| --- | --- | --- |
| Shared adapter resilience runner | 19 passed, 0 failed/skipped | Imported shared policy/runner; independent executor count and disk marker |
| Actual MCP admission | 43 passed, 0 failed/skipped | Real gateway, daemon and synthetic executor; classifier enabled only in selected cases |
| Native HTTP admission | 29 passed, 0 failed/skipped | Real daemon protocol and permit/result binding |
| Additional MCP input validation | 7 passed, 0 failed/skipped | Nested schemas, malformed/unsupported inputs and discovery configuration |
| Additional typed resource extraction | 11 passed, 0 failed/skipped | Extraction, ambiguity, symlinks, destinations and unsupported executor capabilities |
| Real Python rule-baseline demonstration | 9 scenarios and 7 checks passed | Actual local admission and protected host result release |
| Actual Claude Code executable | Skipped: executable unavailable | Scripted Claude-format frames were exercised; no real host/model observation claimed |

The 91-case run emitted 35 separate witness records. Its individual outcomes,
elapsed times and witnesses are retained in the JSON above and
[sanitized raw test output](sou17_candidate_a8b237d_2026-10-10.txt).
PR #62's description lists 83 tests; the launcher actually discovered 91 on this
revision. These are discovered counts, not an expanded claim of acceptance.

Pre-execution refusal is checked against the server's independent execution
ledger, rather than inferred from an error or `executed: false`. Result-stage
refusal is checked against actual client bytes and prepared-result markers.
The allowed executor-error case honestly retains one execution and returns the
original correlated error. Withholding a result does not undo that effect.

Useful native cases passed for replay with changed arguments, unsupported batches
and concurrent calls, before-call and after-effect cancellation, daemon outage,
admission timeout, restart and session isolation. Most of those resilience
fixtures run without an automatic classifier/resource profile; they establish
native boundary behavior, not the complete new integrated configuration.

The rule-baseline demo observed executor deltas of exactly one for its four
benign expected-Allow calls, successful result release for all four, and the
expected two loopback HTTP deliveries. Thus **0 of 4 benign calls were interrupted
in this fixture run**. This is not a held-out false-positive rate. The intentionally
withheld injected result is excluded from that denominator. The demo's generic
`allow_samples=5` counter includes that executed-but-withheld case, so it is not
used as the benign denominator.

Across the nine demo calls, request-to-response elapsed time was **35.56–71.05 ms**,
median **36.93 ms**, one sample per scenario. This includes the collector, real
Python classifier, native daemon and fixture executor, on loopback with a debug
build. There is no paired unguarded control or repeated performance sample:
**enforcement overhead and accepted latency limits remain unverified**.
Classification labels matched all nine synthetic expectations; this is a local
regression observation, not novel-tool accuracy or uncertainty calibration.

## Blocking integration findings

These findings agree with the existing
[requested-changes review](https://github.com/SoupTeam/soup-wall/pull/62#pullrequestreview-5479231908).
Implementation fixes and boundary regressions belong to Nari_Ab's SOU-15 change;
SOU-17 will independently rerun them on the new exact revision.

1. **The shared policy result is advisory telemetry.**
   [Collector::classify](https://github.com/SoupTeam/soup-wall/blob/a8b237d8237bdda534ca294bf1ebed7af8d469bd/crates/agentfw/src/mcp/admission.rs#L693-L723)
   computes and logs `adapter_verdict`, then admits a supported singleton mapping
   without enforcing that verdict. The existing
   [SOU-15 test](https://github.com/SoupTeam/soup-wall/blob/a8b237d8237bdda534ca294bf1ebed7af8d469bd/crates/agentfw/tests/mcp_admission.rs#L1929-L1957)
   explicitly requires one executed call while its adapter verdict is Deny.
   Native operator policy still governs execution and its trusted restrictions
   must remain intact. Define the authoritative production policy composition;
   require independent zero-effect witnesses for its Deny and unconfirmed Ask.
   Making the Task 3 stub's unconditional send-data Deny authoritative would break
   the useful operator-permitted send and is not an acceptable substitute.
   A separate diagnostic used the actual Python classifier subprocess seam with
   valid `Read`, confidence `0.95`, uncertainty `0.9`. Telemetry recorded Ask,
   native call/result decisions were Allow, the independent ledger contained one
   original call, and the client received the original **122 bytes** of result.
   The diagnostic exited **1** (`diagnostic_blocker_confirmed`), not a pass.
   This demonstrates advisory/shared-policy divergence, not a bypass of the
   native operator policy. See the runnable appendix and JSON/byte witnesses.
2. **Extracted resources do not reach the policy/receipt.**
   [The runtime block](https://github.com/SoupTeam/soup-wall/blob/a8b237d8237bdda534ca294bf1ebed7af8d469bd/crates/agentfw/src/mcp/admission.rs#L1224-L1268)
   checks extraction completeness, then discards the typed resources and
   profile/executor identities. Native admission still receives tool, arguments
   and schema hash. Valid extraction is not permission. Require versioned binding
   to the exact invocation/profile/executor/revisions and actual policy checks on
   full URL/port, mailbox and path constraints. Add useful allowed/refused pairs
   with valid syntax and different permissions, plus replay/binding checks.
3. **Executor destination confinement is asserted without verification.**
   [The context](https://github.com/SoupTeam/soup-wall/blob/a8b237d8237bdda534ca294bf1ebed7af8d469bd/crates/agentfw/src/mcp/admission.rs#L1248-L1253)
   hardcodes `fixed_destinations: true` for arbitrary launched MCP commands.
   Require reviewed and enforced executor capabilities; otherwise preserve the
   extractor's explicit unsupported refusal. Path snapshots alone do not prove
   execution-time confinement.

Mixed/Unknown classifications are currently refused as unsupported mappings
before shared policy. This is fail-closed, but it does not demonstrate the agreed
generic classifier and multi-action policy composition. Mixed-action and hard-Deny
overlap tests mainly exercise the adapter surface; repeat the required matrix
through the authoritative production boundary when available.

Cancellation arriving while classifier/admission is awaited is not covered by the
two cancellation tests. Source inspection shows client input is read again only
after that await/dispatch branch. No measured reproduction of this timing window
is claimed here. Define the supported cancellation contract and add an independent
executor/release witness for in-flight admission before accepting that behavior.

## Code scanning recheck

Authorized read-only GitHub UI access on October 10 showed **6 open Critical and
74 closed alerts** on `main`. All six remain the same test-vector findings
[#85–#90](https://github.com/SoupTeam/soup-wall/security/code-scanning?query=is%3Aopen+branch%3Amain).
Each alert's current source link and the working Rust scan configuration identify
`bb1265c5369bdea1eecc1be71ba7e260b4fe8095`, scanned October 10. CodeQL is 2.27.2,
rust-queries 0.1.44, rust-all 0.2.23, threat-models 1.0.59. The two affected test
files are byte-identical to the previously reviewed source and this candidate.

[Updated per-alert inventory](../../operations/evidence/CODE_SCANNING_TRIAGE_2026-10-10.json)
preserves the evidence-backed false-positive recommendations for fixed known-answer,
provider-parity and rejection-test inputs. No deployed credential was established
at those locations. All alerts remain open pending technical disposition; no
dismissal, confirmed-defect remediation issue, fix PR or remediation rescan is
claimed. Nari_Ab coordinates affected-code review; SOU-18 owns scan/check
configuration verification.

The candidate's
[CodeQL PR check](https://github.com/SoupTeam/soup-wall/pull/62/checks?check_run_id=114228049623)
passed with no new alerts in changed code, and its
[CodeQL workflow](https://github.com/SoupTeam/soup-wall/actions/runs/38057184888)
completed. This exact-candidate PR delta does not clear the six existing main
alerts and does not establish tool-call enforcement effectiveness.

## Handoff and remaining acceptance

Nari_Ab should provide the corrected authoritative policy/resource binding and
verified executor capabilities, the supported cancellation behavior, and a new
exact commit/configuration. Preserve native formats, identifiers, trusted Deny
barriers and useful permitted calls. SOU-17 then reruns the affected integration
matrix, negative cases and execution/release witnesses. Coordinate accepted
latency/false-interruption limits with the evaluation owner; unagreed or unmet
limits keep this task open. Confirmed scanning defects, if review establishes any,
need the affected-code owner's focused fix/regression and a scan of that fix commit.

This evidence change is based on current main, not a competing runtime pipeline or
production-policy fix. It neither merges PR #62 nor approves SOU-15/SOU-17 acceptance.

## Appendix: bounded policy diagnostic

Save the following example as `local-notes/sou17-high-uncertainty-probe.py` in a
checkout with the documented candidate available. It imports the existing local
MCP demo's fixture and harness; it does not define another policy, event contract
or execution pipeline. Only the classifier output is synthetic. Build the binary
with the exact-source verifier first. Use the candidate checkout as `--repo` and
that build as `--agentfw`; the diagnostic records both source and binary hashes.
The recorded run used the same binary hash as the 91-case run.

```sh
python3 local-notes/sou17-high-uncertainty-probe.py \
  --repo /path/to/clean/candidate \
  --agentfw /path/to/candidate/target/debug/agentfw \
  --output /path/to/new/evidence-directory
```

The output directory must not already exist. Exit 1 reproduces the advisory Ask
versus native execution divergence; exit 2 is inconclusive; exit 0 only means this
single probe observed blocking, never complete task acceptance. The first attempt
used unsupported string `progressToken` metadata and was correctly refused before
classification; it is retained as an inconclusive harness-input attempt. The
successful diagnostic preserved the string call ID and used numeric progressToken
17. The corrected script below has SHA-256
`413e5ad49a5eae2b6d2861e2aacee8eb3727eea8f4bcb8512b01aed3412272e2`.

```python
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Diagnose shared Ask versus native execution using Soup Wall's local MCP fixture.

No Cargo builds, source edits, real model, external server, or user credentials.
Exit 1 means the suspected acceptance blocker was reproduced; exit 2 means the
probe was inconclusive. Exit 0 only means this one diagnostic observed blocking.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

CANDIDATE = "a8b237d8237bdda534ca294bf1ebed7af8d469bd"
CLASSIFIER_REPLY = {
    "status": "ok", "actions": ["read"], "unknown": False,
    "confidence": 0.95, "uncertainty": 0.9,
    "reason": "Synthetic valid high uncertainty read for enforcement diagnosis",
}
CLASSIFIER_SOURCE = """#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Synthetic sw-classification/candidate-1 output, not a quality benchmark.
import json, sys
request = json.loads(sys.stdin.readline())
assert request['tool_name'] == 'read_document'
print(json.dumps(REPLY, separators=(',', ':')))
""".replace("REPLY", repr(CLASSIFIER_REPLY))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *arguments):
    return subprocess.run(["git", *arguments], cwd=repo, check=True,
                          capture_output=True, text=True, timeout=10).stdout.strip()


def snapshot(repo):
    return {"commit": git(repo, "rev-parse", "HEAD"),
            "tracked_dirty": bool(git(repo, "status", "--porcelain", "--untracked-files=no"))}


def load_demo(repo):
    spec = importlib.util.spec_from_file_location("sou17_local_mcp_demo", repo / "scripts/mcp-admission-demo.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--agentfw", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new directory; never overwrites evidence")
    parser.add_argument("--expected-commit", default=CANDIDATE)
    args = parser.parse_args()
    repo, binary, out = args.repo.resolve(), args.agentfw.resolve(), args.output.resolve()
    before = snapshot(repo)
    if before["commit"] != args.expected_commit or before["tracked_dirty"]:
        parser.error("candidate must have the exact expected HEAD and clean tracked source")
    if not binary.is_file():
        parser.error("build the production agentfw binary separately before this diagnostic")
    out.mkdir(parents=True, exist_ok=False)
    binary_sha = sha(binary.read_bytes())
    classifier = out / "synthetic-high-uncertainty.py"
    classifier.write_text(CLASSIFIER_SOURCE, encoding="utf-8")
    demo = load_demo(repo)
    # agent_stack remains the production native-daemon/registry setup. Only the
    # explicitly selected classifier returns a synthetic valid contract reply.
    demo.classifier_environment = lambda: {
        "AGENTFW_CLASSIFIER": "rule-baseline", "AGENTFW_RULE_BASELINE": str(classifier),
        "AGENTFW_CLASSIFIER_PYTHON": sys.executable,
    }
    report = {
        "schema_version": "sou17-high-uncertainty-probe/0.1", "kind": "diagnostic",
        "acceptance_passed": False, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source": before, "agentfw": {"path": str(binary), "sha256": binary_sha},
        "classifier": {"contract_version": demo.CLASSIFIER_CONTRACT, "synthetic": True,
                       "reply": CLASSIFIER_REPLY, "sha256": sha(CLASSIFIER_SOURCE.encode())},
        "expected": {"adapter_verdict": "ask", "execution_count": 0, "released_original_result_bytes": 0},
        "source_files_sha256": {name: sha((repo / name).read_bytes()) for name in (
            "scripts/mcp-admission-demo.py", "scripts/fixtures/mcp_admission_demo_server.py",
            "crates/agentfw/src/mcp/admission.rs", "crates/agentfw/src/native.rs",
            "crates/adapter/src/runner.rs")},
    }
    artifacts = {}
    harness = None
    try:
        # Canonical temp paths satisfy the existing fixture's ownership guards.
        with tempfile.TemporaryDirectory(prefix="sou17-high-uncertainty-", dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            with demo.agent_stack(binary, Path(tmp) / "workspace") as stack:
                with stack.classifications.open("wb") as collector_log:
                    harness = demo.Harness(stack.collector, stack.env, collector_log)
                    frames = [
                        '{"jsonrpc":"2.0","id":"probe-init","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sou17-diagnostic","version":"1"}}}',
                        '{"jsonrpc":"2.0","method":"notifications/initialized"}',
                        '{"jsonrpc":"2.0","id":"probe-list","method":"tools/list"}',
                    ]
                    init = harness.send(frames[0])
                    harness.send(frames[1], reply=False)
                    manifest = harness.send(frames[2])
                    if not init or not manifest or "result" not in json.loads(manifest):
                        raise RuntimeError("native MCP initialization or admitted discovery failed")
                    started = time.perf_counter()
                    frame = json.dumps({"jsonrpc": "2.0", "id": "sou17-high-uncertainty", "method": "tools/call", "params": {
                        "name": "read_document", "arguments": {"name": "inventory"},
                        "_meta": {"claudecode/toolUseId": "toolu_sou17_probe", "progressToken": 17}}}, separators=(",", ":"))
                    reply = harness.send(frame)
                    latency = (time.perf_counter() - started) * 1000
                    frames.append(frame)
                    exit_code = harness.close()
                raw_ledger, raw_responses = read(stack.ledger), read(stack.responses)
                raw_collector = read(stack.classifications)
                raw_audit = read(stack.workspace / ".agentfw/audit.jsonl")
                classification = [item for item in records(raw_collector)
                                  if item.get("event") == "mcp_classification"
                                  and item.get("host_call_id") == "sou17-high-uncertainty"]
                audit = [item for item in records(raw_audit) if item.get("tool") == "read_document"
                         and item.get("event") in ("native_call", "native_result")]
                server_results = [line for line in raw_responses.splitlines(keepends=True)
                                  if json.loads(line).get("id") == "sou17-high-uncertainty"]
                original_result = server_results[0] if len(server_results) == 1 else b""
                ledger = records(raw_ledger)
                exactly_original = bool(reply and original_result and reply == original_result)
                observed = {
                    "classifications": classification, "native_decisions": audit,
                    "execution_count": len(ledger), "receiver_count": len(stack.receiver.bodies),
                    "original_call_bytes_preserved": raw_ledger == (frame + "\n").encode(),
                    "original_result_bytes_preserved": exactly_original,
                    "client_result_bytes": len(reply or b""),
                    "released_original_result_bytes": len(reply) if exactly_original else 0,
                    "client_response_id": json.loads(reply).get("id") if reply else None,
                    "gateway_exit_code": exit_code, "latency_ms": latency,
                }
                report["observed"] = observed
                artifacts = {
                    "client-input.jsonl": ("\n".join(frames) + "\n").encode(),
                    "client-output.jsonl": b"".join(harness.received),
                    "client-call-response.jsonl": reply or b"", "executor-ledger.jsonl": raw_ledger,
                    "server-responses.jsonl": raw_responses, "collector.log": raw_collector,
                    "native-audit.jsonl": raw_audit, "registry.json": read(stack.workspace / "registry.json"),
                    "policy.yaml": read(stack.workspace / "policy.yaml"),
                }
                # Never retain authentication files or accidentally copied token values.
                credentials = [read(stack.workspace / ".agentfw" / name).strip() for name in ("token", "native-token")]
                if any(token and token in data for token in credentials for data in artifacts.values()):
                    raise RuntimeError("artifact contains a fixture credential; refusing retention")
        after = snapshot(repo)
        report["source_after"] = after
        stable = before == after and sha(binary.read_bytes()) == binary_sha
        observed = report["observed"]
        cls = observed["classifications"]
        native_allow = any(row.get("event") == "native_call" and row.get("verdict") == "allow"
                           for row in observed["native_decisions"])
        ask = len(cls) == 1 and cls[0].get("adapter_verdict") == "ask"
        valid_probe = stable and ask and observed["receiver_count"] == 0
        blocker = valid_probe and native_allow and observed["execution_count"] == 1 \
            and observed["original_call_bytes_preserved"] and observed["original_result_bytes_preserved"] \
            and observed["gateway_exit_code"] == 0
        report["status"] = "diagnostic_blocker_confirmed" if blocker else (
            "fail_closed_observed" if valid_probe and observed["execution_count"] == 0
            and observed["released_original_result_bytes"] == 0 else "inconclusive")
        report["interpretation"] = (
            "Shared Ask was recorded, but native Allow executed the original call and released the original result."
            if blocker else "One diagnostic only; this does not establish full SOU-17 acceptance.")
        report["artifacts"] = {name: {"bytes": len(data), "sha256": sha(data)} for name, data in artifacts.items()}
        for name, data in artifacts.items():
            (out / name).write_bytes(data)
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": report["status"], "adapter_verdict": cls[0].get("adapter_verdict") if cls else None,
                          "execution_count": observed["execution_count"],
                          "released_original_result_bytes": observed["released_original_result_bytes"],
                          "output": str(out)}, indent=2))
        return 1 if blocker else (0 if report["status"] == "fail_closed_observed" else 2)
    except Exception as error:
        if harness is not None and harness.process.poll() is None:
            demo.stop(harness.process)
        report.update(status="inconclusive", error_type=type(error).__name__, error=str(error))
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"inconclusive: {type(error).__name__}; see {out / 'results.json'}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
```
