#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run bounded SOU-17 early regressions using the existing shared test helpers.

This local command does not establish final acceptance: SOU-15 integration and
verification of the agreed clean candidate remain required. No model is called.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("soup_test_environment", ROOT / "scripts/test-environment.py")
HELPERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPERS)
SUITES = (("soup-wall-adapter", "resilience_tests"),
          ("agentfw", "mcp_admission"), ("agentfw", "native_endpoint"))
LIMITATIONS = [
    "Early regression only; final acceptance is pending SOU-15 integration on an exact clean commit.",
    "Existing shared adapter runner and real native/MCP fixtures are distinct integration surfaces.",
    "Classification accuracy, false-interruption rate and request/classifier latency are not measured.",
    "Fixture elapsed time includes process startup, setup, execution and cleanup.",
    "Deterministic local fixtures only; no live model, provider credentials or model downloads.",
    "Local tests use loopback; this launcher does not impose OS-level network isolation.",
]


def evidence_lines(output):
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite JSON number")
        return number

    records, diagnostics = [], []
    for number, line in enumerate(output.splitlines(), 1):
        if "SOU17_EVIDENCE " not in line:
            continue
        try:
            value = json.loads(line.split("SOU17_EVIDENCE ", 1)[1],
                               parse_float=finite_float,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))
            if not isinstance(value, dict):
                raise ValueError("evidence must be a JSON object")
            records.append(value)
        except ValueError as error:
            diagnostics.append({"line": number, "error": str(error)})
    return records, diagnostics


def write_report(out, report):
    HELPERS.write_json(out / "results.json", report)
    counts = Counter(case["status"] for case in report["cases"])
    source = report.get("source", {})
    lines = ["# SOU-17 early regression evidence", "",
             f"Regression status: **{report['status']}**. Final acceptance: **pending SOU-15**.", "",
             f"Source: `{source.get('commit', 'unavailable')}`; dirty: `{source.get('dirty', 'unknown')}`.",
             "Exact inputs, toolchain, binary hashes and commands are recorded in [results.json](results.json).", "",
             f"Pass: {counts['pass']}; fail: {counts['fail']}; error: {counts['error']}; skip: {counts['skip']}.", ""]
    if report.get("error"):
        lines.extend([f"Run error: {report['error']}", ""])
    lines.extend(["| Suite / case | Status | Fixture elapsed (ms) | Raw log |",
                  "| --- | --- | ---: | --- |"])
    for case in report["cases"]:
        lines.append(f"| {case['suite']} / {case['name']} | {case['status']} | "
                     f"{case['elapsed_ms']} | [{case['log']}]({case['log']}) |")
    lines.extend(["", "## Limits", ""] + [f"- {item}" for item in LIMITATIONS])
    lines.extend(["", "A pass does not close SOU-17. Missing integration, skips and unmet acceptance limits remain open.", ""])
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")


def run(args):
    if sys.platform not in {"linux", "darwin"}:
        raise ValueError("Run with native Linux/macOS Python; the shared process-group helper requires POSIX.")
    base = Path(args.out).resolve()
    base.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    report = {"schema_version": 1, "scope": "sou17-early-regression", "status": "error",
              "acceptance": "pending-sou15-integration", "started_at": HELPERS.utc_now(),
              "expected_commit": args.expected_commit, "allow_dirty": args.allow_dirty,
              "offline": args.offline, "cases": [], "steps": [], "suites": [],
              "limits": {"test_timeout_seconds": 60, "build_timeout_seconds": 1800},
              "environment": HELPERS.host_environment(), "limitations": LIMITATIONS,
              "classification_accuracy": "not measured", "false_interruption_rate": "not measured",
              "latency_scope": "per-test fixture including startup and cleanup; not request/classifier overhead"}
    print(f"Results: {out}", flush=True)
    write_report(out, report)

    def step(label, arguments, timeout=15, *, env=None):
        result = HELPERS.command(arguments, out / f"{label}.log", timeout, cwd=ROOT, env=env)
        report["steps"].append({"name": label, **result})
        write_report(out, report)
        if result["exit_code"] != 0 or result.get("timed_out") or result.get("error"):
            raise RuntimeError(f"{label} failed; see {result['log']}")
        return (out / result["log"]).read_text(encoding="utf-8", errors="replace")

    def snapshot(label):
        commit = step(f"{label}-commit", ["git", "rev-parse", "HEAD"]).strip()
        state = step(f"{label}-state", ["git", "status", "--porcelain", "--untracked-files=no"])
        step(f"{label}-patch", ["git", "diff", "--binary", "HEAD", "--"])
        tracked = step(f"{label}-tracked", ["git", "ls-files", "-z"]).split("\0")
        untracked = step(f"{label}-untracked", ["git", "ls-files", "--others", "--exclude-standard", "-z"]).split("\0")
        untracked = [name for name in untracked if name and not (ROOT / name).is_relative_to(out)]
        hashes = {}
        for name in sorted(set(tracked + untracked) - {""}):
            path = ROOT / name
            if path.is_symlink():
                hashes[name] = {"symlink_sha256": hashlib.sha256(os.readlink(path).encode()).hexdigest()}
            else:
                hashes[name] = HELPERS.sha256(path) if path.is_file() else None
        return {"commit": commit, "dirty": bool(state.strip() or untracked),
                "tracked_state": state.splitlines(), "untracked_files": untracked,
                "tracked_patch_log": f"{label}-patch.log",
                "tracked_patch_sha256": HELPERS.sha256(out / f"{label}-patch.log"),
                "inputs_sha256": hashes,
                "inputs_digest": hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()}

    try:
        report["source"] = snapshot("source")
        source = report["source"]
        if args.expected_commit and source["commit"] != args.expected_commit:
            raise ValueError("HEAD differs from --expected-commit; refusing to build or run")
        if source["dirty"] and not args.allow_dirty:
            raise ValueError("Worktree is dirty; use --allow-dirty only for preparation evidence")
        for tool in ("rustc", "cargo"):
            report["environment"][tool] = step(f"version-{tool}", [tool, "--version"]).strip()
        report["environment"]["build_settings"] = {key: os.environ[key] for key in (
            "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG",
            "CARGO_PROFILE_DEV_OPT_LEVEL", "CARGO_PROFILE_TEST_OPT_LEVEL", "CARGO_INCREMENTAL",
            "RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS")
            if key in os.environ}
        report["environment"]["python_executable"] = sys.executable
        clean_env = {key: os.environ[key] for key in (
            "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL")
                     if key in os.environ}
        clean_env["PYTHONDONTWRITEBYTECODE"] = "1"
        report["environment"]["runtime_environment"] = clean_env
        fixture_python = shutil.which("python3", path=clean_env.get("PATH", os.defpath))
        if fixture_python is None:
            raise RuntimeError("python3 required by the MCP fixture is not available on the runtime PATH")
        report["environment"]["fixture_python"] = json.loads(step("fixture-python", [fixture_python, "-I", "-c",
            "import json,platform,sys; print(json.dumps({'executable':sys.executable,"
            "'version':platform.python_version(),'implementation':platform.python_implementation()}))"], env=clean_env))
        report["environment"]["fixture_python"]["resolved_command"] = fixture_python
        report["configuration"] = {
            "suite_revision": source["commit"],
            "cargo_features": {"default_features": True, "all_features": False, "features": []},
            "cargo_profile": "test",
            "policy_and_manifest_scope": "Fixture constants and registry builders in the hashed test sources; not shipped-policy efficacy",
            "enforcement": "Real native/MCP enforcing fixtures; explicit shadow/outage negative cases",
            "judge": "Disabled for native/MCP admission",
            "contracts": ["sw-tool-event/0.1", "sw-native/1"],
            "relevant_inputs": {name: digest for name, digest in source["inputs_sha256"].items()
                                if name in {"Cargo.lock", "rust-toolchain.toml", "scripts/test-environment.py",
                                            "scripts/verify-sou17.py", "crates/agent/policies/agent-default.yaml"}
                                or name.startswith(("crates/adapter/", "crates/agent/src/", "crates/agentfw/"))},
        }
        for package, target in SUITES:
            print(f"Build: {package}/{target}", flush=True)
            cargo = ["cargo", "test", "--locked", "--no-run", "--message-format=json",
                     "-p", package, "--test", target]
            if args.offline:
                cargo.append("--offline")
            output = step(f"build-{target}", cargo, 1800)
            artifacts = []
            for line in output.splitlines():
                try:
                    item = json.loads(line)
                except ValueError:
                    continue  # Cargo diagnostics share the retained raw build log.
                if isinstance(item, dict) and item.get("reason") == "compiler-artifact" and item.get("executable"):
                    artifacts.append(item)
            tests = {item["executable"] for item in artifacts
                     if item["target"]["name"] == target and item["profile"]["test"]}
            if len(tests) != 1:
                raise RuntimeError(f"Expected exactly one test executable for {package}/{target}")
            executable = Path(tests.pop())
            report["suites"].append({"package": package, "target": target,
                                     "executable": str(executable), "sha256": HELPERS.sha256(executable)})
            for item in artifacts:
                if item["target"]["name"] == "agentfw" and "bin" in item["target"]["kind"] and not item["profile"]["test"]:
                    report["agentfw"] = {"executable": item["executable"], "sha256": HELPERS.sha256(item["executable"])}
        if "agentfw" not in report:
            raise RuntimeError("Cargo did not identify the agentfw binary used by the MCP fixture")
        for suite in report["suites"]:
            executable, target = suite["executable"], suite["target"]
            if HELPERS.sha256(executable) != suite["sha256"]:
                raise RuntimeError(f"Test binary changed before execution: {target}")
            names = HELPERS.discovery(step(f"discover-{target}", [executable, "--list", "--format=terse"]))
            suite["discovered_cases"] = names
            for index, name in enumerate(names):
                log = out / f"{target}-{index:03}.log"
                executed = HELPERS.command([executable, "--exact", name, "--nocapture", "--test-threads=1"],
                                           log, 60, cwd=ROOT, env=clean_env)
                text = log.read_text(encoding="utf-8", errors="replace")
                evidence, diagnostics = evidence_lines(text)
                status = HELPERS.classify_test(executed, text)
                case = {"suite": target, "name": name, "status": "error" if diagnostics else status,
                        "test_status": status, "evidence": evidence, "evidence_diagnostics": diagnostics, **executed}
                report["cases"].append(case)
                print(f"{case['status'].upper()}: {target}::{name}", flush=True)
                write_report(out, report)
        report["source_after"] = snapshot("source-after")
        for key in ("commit", "inputs_digest", "tracked_patch_sha256"):
            if report["source_after"][key] != source[key]:
                raise RuntimeError("Source changed during verification; rerun on a fixed candidate")
        for binary in report["suites"] + [report["agentfw"]]:
            if HELPERS.sha256(binary["executable"]) != binary["sha256"]:
                raise RuntimeError("A tested binary changed during verification")
        report["status"] = HELPERS.overall(report["cases"])
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        report["error"] = str(error)
        report["status"] = "error"
    finally:
        report["finished_at"] = HELPERS.utc_now()
        write_report(out, report)
    print(f"Early regression: {report['status']}; final acceptance pending SOU-15. {out / 'report.md'}", flush=True)
    return 0 if report["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", help="full commit hash; a mismatch always refuses execution")
    parser.add_argument("--allow-dirty", action="store_true", help="permit recorded worktree changes for preparation only")
    parser.add_argument("--offline", action="store_true", help="refuse Cargo dependency downloads")
    parser.add_argument("--out", default=str(ROOT / "target/sou17-verification"), help="parent for a fresh evidence directory")
    args = parser.parse_args()
    if args.expected_commit and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", args.expected_commit):
        parser.error("--expected-commit requires a full lowercase hexadecimal commit hash")
    try:
        return run(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
