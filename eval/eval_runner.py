# SPDX-License-Identifier: Apache-2.0
"""Task 1 classification evaluation runner (standard library only).

Evaluates a classifier against v0.4-style fixtures:
  * only each case's ``input`` (a deep copy) is passed to the classifier;
  * action sets are compared ignoring order, and ``unknown`` is compared separately;
  * exceptions, ``status="error"`` and invalid outputs are technical errors, never passes;
  * pending cases are run for observation but excluded from every denominator;
  * results are bucketed by suite, origin, group, shell dependence and contract assumption.

It never executes anything from the fixtures: command strings are data handed to classify().

Exit codes: 0 = all scored cases pass, no technical errors, no constraint violations;
            1 = at least one classification failure or constraint violation;
            2 = at least one technical error (takes precedence over 1);
            3 = invalid fixture or usage error (nothing evaluated).

usage:
  python3 eval_runner.py FIXTURE.json [FIXTURE.json ...] --classifier-path DIR \
      [--classifier rule_baseline:classify] [--out-dir results]
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import importlib
import io
import json
import math
import platform
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

ACTIONS = ("read", "write", "delete", "send_data", "change_permissions")
CRITICAL = ("delete", "send_data", "change_permissions")
STATUSES = {"ok", "unknown", "error"}
EXPECTATION_STATUSES = {"confirmed", "provisional", "pending"}
SCORED = {"confirmed", "provisional"}
INPUT_KEYS = {"tool_name", "tool_description", "tool_schema", "raw_arguments", "pinned_schema", "server_id"}
CASE_KEYS = {"id", "group", "origin", "expectation_status", "requires", "contract_assumptions",
             "input", "expected", "evaluator_only"}
REQUIRES = {"shell_parsing"}


# ---------------------------------------------------------------- fixture validation
def validate_fixture(data: Any, source: str = "<fixture>") -> list[str]:
    """Return a list of structural problems; an empty list means the fixture is usable."""
    errs: list[str] = []
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        return [f"{source}: top level must be an object with a 'cases' list"]
    if not isinstance(data.get("fixture_version"), str):
        errs.append(f"{source}: missing fixture_version")
    seen: set[str] = set()
    for i, c in enumerate(data["cases"]):
        where = f"{source} case[{i}]"
        if not isinstance(c, dict):
            errs.append(f"{where}: not an object")
            continue
        cid = c.get("id")
        if not isinstance(cid, str) or not cid:
            errs.append(f"{where}: missing id")
            continue
        where = f"{source} {cid}"
        if cid in seen:
            errs.append(f"{where}: duplicate id")
        seen.add(cid)
        missing = CASE_KEYS - set(c)
        if missing:
            errs.append(f"{where}: missing keys {sorted(missing)}")
            continue
        st = c["expectation_status"]
        if st not in EXPECTATION_STATUSES:
            errs.append(f"{where}: expectation_status {st!r} not allowed")
        if not isinstance(c["requires"], list) or set(c["requires"]) - REQUIRES:
            errs.append(f"{where}: requires must be a list from {sorted(REQUIRES)}")
        if not isinstance(c["contract_assumptions"], list):
            errs.append(f"{where}: contract_assumptions must be a list")
        inp = c["input"]
        if not isinstance(inp, dict) or set(inp) - INPUT_KEYS or "tool_name" not in inp:
            errs.append(f"{where}: input must be an object with keys from {sorted(INPUT_KEYS)} incl. tool_name")
        elif re.search(rf"\b{re.escape(cid)}\b", json.dumps(inp)):
            errs.append(f"{where}: case id appears inside input (possible leakage)")
        exp = c["expected"]
        if not isinstance(exp, dict) or not {"actions", "unknown", "status"} <= set(exp):
            errs.append(f"{where}: expected must contain actions, unknown, status")
            continue
        acts, unk = exp["actions"], exp["unknown"]
        if st in SCORED:
            if not isinstance(acts, list) or any(a not in ACTIONS for a in acts) or len(acts) != len(set(acts)):
                errs.append(f"{where}: expected.actions must be a duplicate-free list of {ACTIONS}")
            if not isinstance(unk, bool):
                errs.append(f"{where}: expected.unknown must be true/false for a scored case")
        elif acts is not None or unk is not None:
            errs.append(f"{where}: pending cases must have expected.actions and expected.unknown = null")
        if exp["status"] is not None and exp["status"] not in STATUSES:
            errs.append(f"{where}: expected.status {exp['status']!r} not allowed")
        fb = exp.get("forbidden_actions")
        if fb is not None and (not isinstance(fb, list) or any(a not in ACTIONS for a in fb)):
            errs.append(f"{where}: forbidden_actions must be a list of {ACTIONS}")
        if fb and isinstance(acts, list) and set(fb) & set(acts):
            errs.append(f"{where}: forbidden_actions overlaps expected.actions")
    return errs


# ---------------------------------------------------------------- output checking
def check_output(out: Any) -> str | None:
    """Return a technical-error description, or None if the output is a valid classification."""
    if not isinstance(out, dict):
        return f"invalid_output: expected an object, got {type(out).__name__}"
    status = out.get("status")
    if status is not None and (not isinstance(status, str) or status not in STATUSES):
        return f"invalid_output: status {status!r} not in {sorted(STATUSES)}"
    if status == "error":
        return "classifier_reported_error: " + str(out.get("reason", ""))[:200]
    acts = out.get("actions")
    if not isinstance(acts, list):
        return "invalid_output: actions missing or not a list"
    bad = [a for a in acts if a not in ACTIONS]
    if bad:
        return f"invalid_output: actions contains non-action labels {bad}"
    if len(acts) != len(set(acts)):
        return "invalid_output: duplicate actions"
    if not isinstance(out.get("unknown"), bool):
        return "invalid_output: unknown missing or not a Boolean"
    # SOU-10 allows these fields to be absent; supplied values must be finite
    # probabilities. Booleans are JSON booleans, not numeric confidence values.
    for field in ("confidence", "uncertainty"):
        if field in out:
            value = out[field]
            if (type(value) not in (int, float) or not 0 <= value <= 1
                    or not math.isfinite(value)):
                return f"invalid_output: {field} must be a finite number in [0,1]"
    return None


def _canon(actions) -> list[str]:
    return [a for a in ACTIONS if a in set(actions or [])]


# ---------------------------------------------------------------- one case
def evaluate_case(case: dict, classify: Callable[[dict], Any], suite: str) -> dict:
    exp = case["expected"]
    scored = case["expectation_status"] in SCORED
    rec: dict[str, Any] = {
        "suite": suite, "id": case["id"], "group": case["group"], "origin": case["origin"],
        "expectation_status": case["expectation_status"], "requires": list(case["requires"]),
        "contract_assumptions": list(case["contract_assumptions"]),
        "expected_actions": None if exp["actions"] is None else _canon(exp["actions"]),
        "expected_unknown": exp["unknown"], "expected_status": exp["status"],
        "predicted_actions": None, "predicted_unknown": None, "predicted_status": None,
        "raw_output": None, "technical_error": None,
        "actions_match": None, "unknown_match": None, "status_check": "not_evaluated",
        "missing": [], "spurious": [], "critical_missing": [],
        "forbidden_actions": exp.get("forbidden_actions") or [], "constraint_violations": [],
        "outcome": None,
    }
    payload = copy.deepcopy(case["input"])  # the ONLY thing the classifier sees
    try:
        out = classify(payload)
    except Exception as e:  # noqa: BLE001 - any classifier crash is a technical error
        out, rec["technical_error"] = None, f"exception: {type(e).__name__}: {e}"[:300]
    if rec["technical_error"] is None:
        try:
            rec["raw_output"] = json.loads(json.dumps(out, default=repr))
        except (TypeError, ValueError):
            rec["raw_output"] = repr(out)
        problem = check_output(out)
        if problem:
            rec["technical_error"] = problem
        else:
            rec["predicted_actions"] = _canon(out["actions"])
            rec["predicted_unknown"] = out["unknown"]
            rec["predicted_status"] = out.get("status")
    if rec["technical_error"] is None and rec["forbidden_actions"]:
        rec["constraint_violations"] = [a for a in rec["forbidden_actions"] if a in rec["predicted_actions"]]

    if not scored:
        rec["outcome"] = "unscored"
        return rec
    if rec["technical_error"]:
        rec["outcome"] = "technical_error"
        return rec
    e, p = set(rec["expected_actions"]), set(rec["predicted_actions"])
    rec["missing"], rec["spurious"] = _canon(e - p), _canon(p - e)
    rec["critical_missing"] = [a for a in rec["missing"] if a in CRITICAL]
    rec["actions_match"] = e == p
    rec["unknown_match"] = rec["expected_unknown"] == rec["predicted_unknown"]
    if exp["status"] is not None:
        rec["status_check"] = "pass" if rec["predicted_status"] == exp["status"] else "fail"
    ok = rec["actions_match"] and rec["unknown_match"] and rec["status_check"] != "fail"
    rec["outcome"] = "pass" if ok else "fail"
    return rec


# ---------------------------------------------------------------- aggregation
def _tally(recs: list[dict]) -> dict:
    sc = [r for r in recs if r["expectation_status"] in SCORED]
    c = Counter(r["outcome"] for r in sc)
    return {"scored": len(sc), "pass": c["pass"], "fail": c["fail"], "technical_error": c["technical_error"],
            "unscored": sum(r["outcome"] == "unscored" for r in recs)}


def summarize(recs: list[dict]) -> dict:
    scored_cls = [r for r in recs if r["outcome"] in ("pass", "fail")]
    buckets: dict[str, dict[str, dict]] = {}
    for name, key in (("suite", lambda r: [r["suite"]]), ("origin", lambda r: [r["origin"]]),
                      ("group", lambda r: [f"{r['suite']} / {r['group']}"]),
                      ("shell_dependent", lambda r: [f"{r['suite']} / " + ("requires shell_parsing" if "shell_parsing" in r["requires"] else "no shell parsing")]),
                      ("assumption", lambda r: r["contract_assumptions"])):
        groups: dict[str, list] = defaultdict(list)
        for r in recs:
            for k in key(r):
                groups[k].append(r)
        buckets[name] = {k: _tally(v) for k, v in sorted(groups.items())}
    per_label = {a: {"missing": sum(a in r["missing"] for r in scored_cls),
                     "spurious": sum(a in r["spurious"] for r in scored_cls),
                     "expected_present": sum(a in r["expected_actions"] for r in scored_cls)} for a in ACTIONS}
    unknown = {
        "expected_true_predicted_false": [r["id"] for r in scored_cls if r["expected_unknown"] and not r["predicted_unknown"]],
        "expected_false_predicted_true": [r["id"] for r in scored_cls if not r["expected_unknown"] and r["predicted_unknown"]],
        "actions_right_but_unknown_wrong": [r["id"] for r in scored_cls if r["actions_match"] and not r["unknown_match"]],
    }
    return {
        "overall": _tally(recs),
        "buckets": buckets,
        "per_label": per_label,
        "critical_misses": [{"id": r["id"], "suite": r["suite"], "missing": r["critical_missing"]}
                            for r in scored_cls if r["critical_missing"]],
        "unknown_mismatches": unknown,
        "technical_errors": [{"id": r["id"], "suite": r["suite"], "scored": r["expectation_status"] in SCORED,
                              "error": r["technical_error"]} for r in recs if r["technical_error"]],
        "constraint_violations": [{"id": r["id"], "suite": r["suite"], "violated": r["constraint_violations"]}
                                  for r in recs if r["constraint_violations"]],
        "constraint_checked": [r["id"] for r in recs if r["forbidden_actions"] and not r["technical_error"]],
        "status_field": "not evaluated (expected.status is null in every case)" if all(
            r["expected_status"] is None for r in recs) else "evaluated where expected.status is set",
    }


def exit_code(summary: dict) -> int:
    if summary["technical_errors"]:
        return 2
    if summary["overall"]["fail"] or summary["constraint_violations"]:
        return 1
    return 0


# ---------------------------------------------------------------- reporting
def _fmt(acts, unk) -> str:
    if acts is None:
        return "—"
    return f"[{', '.join(acts)}] unk={'T' if unk else 'F'}"


def render_markdown(summary: dict, recs: list[dict], meta: dict) -> str:
    o = summary["overall"]
    L = ["# Task 1 classification evaluation — results", "",
         "Generated by `eval_runner.py`. Pass = action set AND unknown both match. "
         "Pending cases are run for observation only and excluded from every denominator.", "",
         f"**Overall (scored):** {o['pass']}/{o['scored']} pass, {o['fail']} fail, "
         f"{o['technical_error']} technical error(s); {o['unscored']} unscored.", "",
         f"**status field:** {summary['status_field']}.", "", "## Results by bucket", ""]
    for name in ("suite", "origin", "group", "shell_dependent", "assumption"):
        L += [f"### by {name}", "", "| bucket | pass | fail | technical | scored | unscored |", "|---|---|---|---|---|---|"]
        for k, t in summary["buckets"][name].items():
            L.append(f"| {k} | {t['pass']} | {t['fail']} | {t['technical_error']} | {t['scored']} | {t['unscored']} |")
        L.append("")
    L += ["## Per-label errors (scored, non-technical cases)", "",
          "| label | expected present | missing (FN) | spurious (FP) |", "|---|---|---|---|"]
    for a, v in summary["per_label"].items():
        crit = " **critical**" if a in CRITICAL else ""
        L.append(f"| {a}{crit} | {v['expected_present']} | {v['missing']} | {v['spurious']} |")
    L += ["", "## Critical misses (missing delete / send_data / change_permissions)", ""]
    L += [f"- {c['suite']} {c['id']}: missing {', '.join(c['missing'])}" for c in summary["critical_misses"]] or ["- none"]
    u = summary["unknown_mismatches"]
    L += ["", "## unknown mismatches", "",
          f"- expected unknown=true, predicted false: {', '.join(u['expected_true_predicted_false']) or 'none'}",
          f"- expected unknown=false, predicted true: {', '.join(u['expected_false_predicted_true']) or 'none'}",
          f"- actions correct but unknown wrong: {', '.join(u['actions_right_but_unknown_wrong']) or 'none'}",
          "", "## Technical errors (not classification results)", ""]
    L += [f"- {t['suite']} {t['id']} ({'scored' if t['scored'] else 'unscored'}): {t['error']}"
          for t in summary["technical_errors"]] or ["- none"]
    L += ["", "## Constraint checks (forbidden_actions)", "",
          f"- checked: {', '.join(summary['constraint_checked']) or 'none'}"]
    L += [f"- VIOLATED {c['suite']} {c['id']}: {', '.join(c['violated'])}" for c in summary["constraint_violations"]] or ["- no violations"]
    L += ["", "## Failing cases", "", "| suite | id | group | shell | expected | predicted | missing | spurious |",
          "|---|---|---|---|---|---|---|---|"]
    for r in recs:
        if r["outcome"] == "fail":
            L.append(f"| {r['suite']} | {r['id']} | {r['group']} | {'yes' if 'shell_parsing' in r['requires'] else 'no'} | "
                     f"{_fmt(r['expected_actions'], r['expected_unknown'])} | {_fmt(r['predicted_actions'], r['predicted_unknown'])} | "
                     f"{', '.join(r['missing']) or '—'} | {', '.join(r['spurious']) or '—'} |")
    L += ["", "## Unscored (pending) cases — observation only", "", "| suite | id | group | predicted | note |", "|---|---|---|---|---|"]
    for r in recs:
        if r["outcome"] == "unscored":
            pred = r["technical_error"] or _fmt(r["predicted_actions"], r["predicted_unknown"]) + (
                f" status={r['predicted_status']}" if r["predicted_status"] else "")
            L.append(f"| {r['suite']} | {r['id']} | {r['group']} | {pred} | not in any denominator |")
    L += ["", "## Run metadata", "", "```json", json.dumps(meta, indent=2), "```", ""]
    return "\n".join(L)


CSV_FIELDS = ["suite", "id", "group", "origin", "expectation_status", "shell_dependent", "contract_assumptions", "outcome",
              "expected_actions", "expected_unknown", "predicted_actions", "predicted_unknown", "predicted_status",
              "missing", "spurious", "critical_missing", "constraint_violations", "technical_error"]


def render_csv(recs: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    j = lambda v: "" if v is None else ("|".join(v) if isinstance(v, list) else v)  # noqa: E731
    for r in recs:
        row = {k: j(r.get(k)) for k in CSV_FIELDS if k != "shell_dependent"}
        row["shell_dependent"] = "shell_parsing" in r["requires"]
        w.writerow(row)
    return buf.getvalue()


# ---------------------------------------------------------------- driver
def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_classifier(spec: str, path: str | None) -> tuple[Callable, dict]:
    mod_name, _, func = spec.partition(":")
    if path:
        sys.path.insert(0, str(Path(path).resolve()))
    sys.dont_write_bytecode = True  # do not leave __pycache__ next to the classifier under test
    mod = importlib.import_module(mod_name)
    fn = getattr(mod, func or "classify")
    info = {"spec": spec, "module_file": Path(mod.__file__).name}
    try:
        info["module_sha256"] = _sha256(Path(mod.__file__))
    except OSError:
        pass
    return fn, info


def run(fixture_paths: list[str], classify: Callable, classifier_info: dict) -> tuple[list[dict], dict, dict, list[str]]:
    recs: list[dict] = []
    errors: list[str] = []
    meta = {"runner": "eval_runner.py", "runner_sha256": _sha256(Path(__file__)), "python": platform.python_version(),
            "classifier": classifier_info, "fixtures": []}
    loaded = []
    all_ids: set[str] = set()
    for p in fixture_paths:
        data = json.loads(Path(p).read_text(encoding="utf-8"))
        errors += validate_fixture(data, Path(p).name)
        ids = {c.get("id") for c in data.get("cases", []) if isinstance(c, dict)}
        dup = all_ids & ids
        if dup:
            errors.append(f"{Path(p).name}: ids also used in another fixture: {sorted(dup)}")
        all_ids |= ids
        meta["fixtures"].append({"file": Path(p).name, "fixture_version": data.get("fixture_version"), "sha256": _sha256(Path(p))})
        loaded.append(data)
    if errors:
        return [], {}, meta, errors
    for data in loaded:
        for case in data["cases"]:
            recs.append(evaluate_case(case, classify, data["fixture_version"]))
    return recs, summarize(recs), meta, []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("fixtures", nargs="+")
    ap.add_argument("--classifier", default="rule_baseline:classify", help="module:function")
    ap.add_argument("--classifier-path", default=None, help="directory containing the classifier module")
    ap.add_argument("--out-dir", default="results")
    a = ap.parse_args(argv)
    try:
        classify, info = load_classifier(a.classifier, a.classifier_path)
    except (ImportError, AttributeError) as e:
        print(f"usage error: cannot load classifier {a.classifier}: {e}", file=sys.stderr)
        return 3
    recs, summary, meta, errors = run(a.fixtures, classify, info)
    if errors:
        print("fixture validation failed:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 3
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps({"meta": meta, "summary": summary, "cases": recs}, indent=2,
                                                 ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "results.csv").write_text(render_csv(recs), encoding="utf-8")
    (out / "summary.md").write_text(render_markdown(summary, recs, meta), encoding="utf-8")
    o = summary["overall"]
    print(f"scored: {o['pass']}/{o['scored']} pass, {o['fail']} fail, {o['technical_error']} technical; "
          f"unscored: {o['unscored']}; critical misses: {len(summary['critical_misses'])}; "
          f"constraint violations: {len(summary['constraint_violations'])}")
    for name, t in summary["buckets"]["suite"].items():
        print(f"  {name}: {t['pass']}/{t['scored']} pass, {t['fail']} fail, {t['technical_error']} technical, {t['unscored']} unscored")
    print(f"wrote {out/'results.json'}, {out/'results.csv'}, {out/'summary.md'}")
    return exit_code(summary)


if __name__ == "__main__":
    raise SystemExit(main())
