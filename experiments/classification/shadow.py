# SPDX-License-Identifier: Apache-2.0
"""Offline comparison plumbing with explicitly simulated Jev responses.

This command measures adapter mechanics and the frozen baseline, not Jev quality.
No HTTP transport is selected here. No fixture tool or policy is executed.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import platform
import statistics
import subprocess
import time
from pathlib import Path

from eval import eval_runner
from experiments.classification.jev import ClassificationFailure, JevClassifier, QUESTION_IDS


def uncertain_mock(request: dict, timeout_s: float) -> dict:
    """Fixed ambiguous answers independent of case IDs, expected labels or input."""
    return {"model": request["model"], "answers": {
        q: {"type": "noul", "noul": 0.5} for q in QUESTION_IDS
    }, "usage": {"input_tokens": 0, "output_tokens": 0}}


def load_baseline(path: Path):
    source = path / "rule_baseline.py"
    spec = importlib.util.spec_from_file_location("frozen_shadow_baseline", source)
    if spec is None or spec.loader is None:
        raise ValueError("baseline module not found")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.classify, hashlib.sha256(source.read_bytes()).hexdigest()


def _timed(classifier, latencies: list[float], unknowns: list[bool], failures: list[dict]):
    def run(inp):
        start = time.perf_counter()
        try:
            out = classifier(copy.deepcopy(inp))
            if isinstance(out, dict) and isinstance(out.get("unknown"), bool):
                unknowns.append(out["unknown"])
            return out
        except ClassificationFailure as exc:
            failures.append({"code": exc.code, "detail": exc.detail, "policy_reached": False})
            raise
        finally:
            latencies.append((time.perf_counter() - start) * 1000)
    return run


def _latency(values: list[float]) -> dict:
    if not values:
        return {"count": 0, "p50_ms": None, "p95_ms": None}
    ordered = sorted(values)
    return {"count": len(values), "p50_ms": statistics.median(values),
            "p95_ms": ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--baseline-path", type=Path, required=True)
    parser.add_argument("--fixtures", nargs="+", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("target/jev-shadow"))
    args = parser.parse_args(argv)
    baseline, baseline_hash = load_baseline(args.baseline_path)
    candidate = JevClassifier(uncertain_mock)
    runs = {}
    for name, classify in (("rule_baseline", baseline), ("jev_simulated_ambiguous", candidate.classify)):
        latencies, unknowns, failures = [], [], []
        records, summary, meta, errors = eval_runner.run(
            args.fixtures, _timed(classify, latencies, unknowns, failures),
            {"spec": name, "baseline_sha256": baseline_hash if name == "rule_baseline" else None},
        )
        if errors:
            raise ValueError("invalid evaluation fixtures: " + "; ".join(errors))
        known_rows = [r for r in records if r["expectation_status"] in eval_runner.SCORED]
        valid_scored = [r for r in known_rows if r.get("outcome") != "technical_error"]
        runs[name] = {"meta": meta, "summary": summary, "cases": records,
                      "latency": _latency(latencies), "typed_failures": failures,
                      "valid_response_unknown_fraction": sum(unknowns) / len(unknowns) if unknowns else None,
                      "valid_scored_cases": len(valid_scored),
                      "classification_quality_interpretation": (
                          "synthetic developer diagnostic; provisional labels" if name == "rule_baseline"
                          else "not Jev quality: fixed mocked probabilities; plumbing observation only")}
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        commit = None
    report = {"format": "soup-wall/jev-shadow-report/1", "source_commit": commit,
              "source_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                for name in ("jev.py", "shadow.py")},
              "python": platform.python_version(), "mode": "mock-only",
              "external_requests": 0, "model_api_cost_usd": 0,
              "real_jev_quality": None, "real_jev_latency_ms": None,
              "real_jev_cost_usd": None, "policy_evaluations": 0, "tool_executions": 0,
              "recommendation": "do_not_adopt_pending_reviewed_access_budget_and_measured_shadow_results",
              "runs": runs}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "comparison.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    for name, run in runs.items():
        (args.output_dir / f"{name}.csv").write_text(eval_runner.render_csv(run["cases"]), encoding="utf-8")
        print(name, run["summary"]["overall"], run["latency"])
    print("Mock mechanics only; external requests=0; real Jev evaluation unavailable.")
    return 0  # Classification mismatches are retained evidence, not enforcement passes.


if __name__ == "__main__":
    raise SystemExit(main())
