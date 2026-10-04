#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Import pinned public AgentDojo traces for offline policy replay, without execution.

No upstream code is imported. Raw traces and the license remain in ignored datasets/.
The source lock freezes selection before policy outcomes are observed.
"""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

REPOSITORY = "ethz-spylab/agentdojo"
REVISION = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
MODEL = "gpt-4o-2024-05-13"
SEED = "soup-wall-independent-history-v1"
ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "scripts/benchmarks/agentdojo-history.source-lock.json"
TRACE_PATH = re.compile(
    rf"runs/{re.escape(MODEL)}/workspace/user_task_(\d+)/"
    r"(none|direct|tool_knowledge)/(none|injection_task_\d+)\.json"
)
NATIVE_TOOL = re.compile(r"[a-z][a-z0-9_]*")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    # Git's SHA-1 identifies the pinned source object; SHA-256 is also recorded.
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def encode(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "soup-wall-history-import/1"})
    # No credentials, model requests, external tools, or upstream code execution.
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise ValueError("source request did not return HTTP 200")
        return response.read(20_000_001)


def parse_json(data: bytes) -> object:
    def invalid_constant(_: str) -> None:
        raise ValueError("non-finite JSON numbers are unsupported")

    return json.loads(data, parse_constant=invalid_constant)


def select(tree: dict) -> tuple[list[dict], int]:
    """All 40 benign traces, plus one hash-selected attack per matching user task."""
    if tree.get("truncated") is not False:
        raise ValueError("a complete upstream tree is required")
    groups: dict[int, dict[str, list[dict]]] = {}
    for entry in tree["tree"]:
        match = TRACE_PATH.fullmatch(entry["path"])
        if entry["type"] != "blob" or not match:
            continue
        task, attack, injection = match.groups()
        if (attack == "none") != (injection == "none"):
            raise ValueError("inconsistent source path")
        groups.setdefault(int(task), {"benign": [], "attack": []})[
            "benign" if attack == "none" else "attack"
        ].append({"path": entry["path"], "git_blob_sha1": entry["sha"]})
    if set(groups) != set(range(40)):
        raise ValueError("the pinned 40 workspace tasks are required")
    rows = []
    candidates = 0
    for task in sorted(groups):
        group = groups[task]
        if len(group["benign"]) != 1 or not group["attack"]:
            raise ValueError("each task must have one benign trace and attack candidates")
        candidates += len(group["attack"])
        selected_attack = min(group["attack"], key=lambda row: (
            digest((SEED + "\n" + row["path"]).encode()), row["path"]))
        rows.extend([group["benign"][0], selected_attack])
    return rows, candidates


def validate_selection(lock: dict, tree: dict) -> None:
    if lock.get("schema_version") != 1:
        raise ValueError("unsupported source lock schema")
    if (lock["repository"], lock["revision"], lock["model"], lock["selection_seed"]) != (
        REPOSITORY, REVISION, MODEL, SEED
    ):
        raise ValueError("unsupported source lock")
    selected, candidates = select(tree)
    if selected != lock["traces"] or candidates != lock["attack_candidate_count"]:
        raise ValueError("source lock does not match the predeclared selection")
    if tree["sha"] != lock["git_tree_sha1"]:
        raise ValueError("upstream tree object mismatch")
    license_entry = next(row for row in tree["tree"] if row["path"] == "LICENSE")
    if license_entry["sha"] != lock["license"]["git_blob_sha1"]:
        raise ValueError("license object mismatch")


def project(trace: dict, path: str) -> tuple[dict, dict]:
    """Project only observed calls/results; retain native names, values and order."""
    match = TRACE_PATH.fullmatch(path)
    if not match:
        raise ValueError("unsupported trace path")
    task, attack, injection = match.groups()
    expected_injection = None if injection == "none" else injection
    expected_attack = None if attack == "none" else attack
    if (trace.get("suite_name"), trace.get("pipeline_name"), trace.get("user_task_id"),
        trace.get("injection_task_id"), trace.get("attack_type")) != (
        "workspace", MODEL, "user_task_" + task, expected_injection, expected_attack
    ):
        raise ValueError("trace identity does not match its pinned path")
    if trace.get("error") is not None:
        raise ValueError("upstream run error; selection is not replaced")
    events = []
    pending: dict[str, dict] = {}
    seen_ids: set[str] = set()
    tool_counts: Counter = Counter()
    error_results = 0
    for index, message in enumerate(trace["messages"]):
        role = message.get("role")
        if role in ("system", "user"):
            # EventKind has no prompt-message event. Full originals stay local.
            continue
        if role == "assistant":
            calls = message.get("tool_calls")
            if calls is None:
                continue
            if not isinstance(calls, list):
                raise ValueError(f"unsupported calls schema at message {index}")
            for call in calls:
                name, args, call_id = call.get("function"), call.get("args"), call.get("id")
                if (not isinstance(name, str) or not NATIVE_TOOL.fullmatch(name)
                    or name.startswith("mcp__") or not isinstance(args, dict)
                    or not isinstance(call_id, str) or not call_id or call_id in seen_ids):
                    raise ValueError(f"unsupported native call schema at message {index}")
                seen_ids.add(call_id)
                pending[call_id] = call
                tool_counts[name] += 1
                events.append({"kind": "tool_call", "tool": name, "args": args})
        elif role == "tool":
            call_id = message.get("tool_call_id")
            call = pending.pop(call_id, None) if isinstance(call_id, str) else None
            if call is None or message.get("tool_call") != call:
                raise ValueError(f"unmatched or modified result call at message {index}")
            content = message.get("content")
            if not isinstance(content, str):
                raise ValueError(f"non-string tool output at message {index}")
            error_results += message.get("error") is not None
            events.append({"kind": "tool_result", "tool": call["function"], "content": content,
                           "source": {"origin": "local_system"}})
        else:
            raise ValueError(f"unsupported message role at message {index}")
    if pending or not tool_counts:
        raise ValueError("incomplete or empty tool trace; selection is not replaced")
    session_id = f"agentdojo/workspace/user_task_{task}/{attack}/{injection}"
    session = {"id": session_id, "label": "benign" if attack == "none" else "attack",
               "category": "agentdojo-workspace-" + attack, "events": events,
               "note": "Historical native-tool replay; attack label denotes an upstream injection attempt, not success."}
    metadata = {"id": session_id, "path": path, "event_count": len(events),
                "tool_call_counts": dict(sorted(tool_counts.items())),
                "tool_error_result_count": error_results}
    return session, metadata


def destination(path: Path) -> Path:
    resolved = path.resolve()
    datasets = (ROOT / "datasets").resolve()
    if not resolved.is_relative_to(datasets) or resolved == datasets:
        raise ValueError("output must be a new directory inside this checkout's ignored datasets/")
    if resolved.exists():
        raise ValueError("output directory exists; choose a fresh directory")
    return resolved


def run(output: Path | None) -> dict:
    lock = parse_json(LOCK.read_bytes())
    # Canonical JSON makes the identity independent of checkout LF/CRLF settings.
    lock_bytes = encode(lock)
    tree = parse_json(fetch(f"https://api.github.com/repos/{REPOSITORY}/git/trees/{REVISION}?recursive=1"))
    validate_selection(lock, tree)
    if output is None:
        return {"scope": "selection-only", "revision": REVISION,
                "source_lock_sha256": digest(lock_bytes), "trace_count": len(lock["traces"]),
                "attack_candidates": lock["attack_candidate_count"]}
    output = destination(output)
    output.mkdir(parents=True)
    license_bytes = fetch(f"https://raw.githubusercontent.com/{REPOSITORY}/{REVISION}/LICENSE")
    if (git_blob(license_bytes) != lock["license"]["git_blob_sha1"]
        or digest(license_bytes) != lock["license"]["sha256"]):
        raise ValueError("license bytes do not match the reviewed MIT notice")
    (output / "UPSTREAM_LICENSE.txt").write_bytes(license_bytes)

    def download(row: dict) -> tuple[dict, dict]:
        data = fetch(f"https://raw.githubusercontent.com/{REPOSITORY}/{REVISION}/{row['path']}")
        if len(data) > 20_000_000 or git_blob(data) != row["git_blob_sha1"]:
            raise ValueError("trace bytes do not match the pinned object: " + row["path"])
        local_path = output / "raw" / row["path"]
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(data)
        try:
            session, metadata = project(parse_json(data), row["path"])
        except (KeyError, TypeError, ValueError) as error:
            # Do not print source content or attacker-controlled error messages.
            raise ValueError("unsupported trace (no replacement): " + row["path"]) from error
        metadata.update({"git_blob_sha1": row["git_blob_sha1"], "sha256": digest(data)})
        return session, metadata

    # executor.map preserves frozen row order despite independent downloads.
    with ThreadPoolExecutor(max_workers=4) as executor:
        imported = list(executor.map(download, lock["traces"]))
    sessions = [item[0] for item in imported]
    tool_counts: Counter = Counter()
    for _, metadata in imported:
        tool_counts.update(metadata["tool_call_counts"])
    corpus = b"".join((json.dumps(session, ensure_ascii=False, sort_keys=True, allow_nan=False)
                       + "\n").encode("utf-8") for session in sessions)
    manifest = {
        "schema_version": 1,
        "name": "AgentDojo independently sourced historical workspace trace replay v1",
        "license_spdx": "MIT",
        "provenance": "Public upstream recorded model runs, pinned and selected before replay. Independent authorship is not an unbiased held-out evaluation. No generated attacks or outcomes are added.",
        "record_count": len(sessions), "attack_count": 40, "benign_count": 40,
        "categories": sorted({session["category"] for session in sessions}),
        "evidence_scope": "independent-historical-native-tool-policy-replay",
        "source": {"repository": REPOSITORY, "revision": REVISION, "model": MODEL,
                   "git_tree_sha1": lock["git_tree_sha1"], "source_lock_sha256": digest(lock_bytes),
                   "license": lock["license"], "selection_seed": SEED,
                   "selection": lock["selection"], "attack_candidate_count": lock["attack_candidate_count"]},
        "adapter": {"tool_names": "verbatim; no MCP or Bash renaming",
                    "arguments": "original JSON values; no substitutions",
                    "outputs": "original string values; no prefixes or concatenation",
                    "result_provenance": "local_system: current native-hook fallback for all these unknown native tool names",
                    "unknown_native_tool_call_counts": dict(sorted(tool_counts.items())),
                    "prompt_and_assistant_text": "not projected: no matching EventKind; full originals retained locally",
                    "unsupported": ["non-string outputs", "non-native tool names", "unmatched call/result IDs", "incomplete traces", "upstream run errors"],
                    "unsupported_trace_policy": "fail the entire import; do not replace or omit selected traces"},
        "task_utility": None, "attack_success": None,
        "limitations": [
            "Attack labels denote injection attempts, including attempts that the original model resisted or never encountered.",
            "All native tool names are outside the shipped coding-tool vocabulary; outputs receive semi-trusted LocalSystem fallback and calls start at generic SideEffecting, with existing argument-pattern upgrades still applied.",
            "This fallback does not preserve AgentDojo external-resource trust and action-specific semantics; replay cannot isolate the causes of individual misses.",
            "No model, tool, daemon enforcement, attacker strategy or counterfactual trajectory executes.",
            "The upstream utility/security results belong to the upstream model and are not attributed to Soup Wall.",
            "Only one public workspace model and two attack strategies are selected; publication and selection bias remain.",
            "The field gate needs a reviewed live native-tool adapter and matched defended/undefended task evaluators."
        ],
        "traces": [metadata for _, metadata in imported],
    }
    (output / "agent_sessions.manifest.json").write_bytes(encode(manifest))
    # Publish the usable corpus only after every selected trace passes validation.
    (output / "agent_sessions.jsonl").write_bytes(corpus)
    return {"scope": manifest["evidence_scope"], "revision": REVISION,
            "record_count": len(sessions), "corpus_sha256": digest(corpus),
            "manifest_sha256": digest(encode(manifest)), "native_tool_count": len(tool_counts)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, help="fresh ignored datasets/ subdirectory; omitting verifies selection only")
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.output_dir), sort_keys=True))
        return 0
    except Exception as error:
        # Remote data never becomes a command and never appears in diagnostics.
        print(f"Import failed ({type(error).__name__}); no complete corpus produced.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
