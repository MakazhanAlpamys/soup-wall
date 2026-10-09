#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render saved schema-v1 GitHub scanning evidence as Markdown, entirely offline."""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import sys


OBJECT_OBSERVATIONS = {"main", "pull_request", "default_setup", "branch_protection",
                       "open_alert_inventory", "target_recheck"}
LIST_OBSERVATIONS = {"repository_languages", "workflows", "rulesets",
                     "effective_main_rules", "checks", "analyses"}
GATE_CASES = ("clean", "missing_or_pending", "qualifying_finding")


def validate(report):
    """Validate the consumed shape without inventing missing evidence."""
    if not isinstance(report, dict):
        raise ValueError("The audit must be a JSON object.")
    if type(report.get("schema_version")) is not int or report["schema_version"] != 1:
        raise ValueError("Unsupported audit schema_version; expected 1.")
    for name in ("repository", "observed_at", "status"):
        if not isinstance(report.get(name), str):
            raise ValueError(f"Audit field {name} must be a string.")
    for name in ("observations", "live_gate_cases"):
        if not isinstance(report.get(name), dict):
            raise ValueError(f"Audit field {name} must be an object.")
    for name in ("read_only", "merge_protection_verified", "qualifying_rule_observed",
                 "target_changed_during_read"):
        if report.get(name) is not None and type(report[name]) is not bool:
            raise ValueError(f"Audit field {name} must be a boolean or null.")
    for name in ("target_sha", "target_ref"):
        if report.get(name) is not None and not isinstance(report[name], str):
            raise ValueError(f"Audit field {name} must be a string or null.")
    limitations = report.get("limitations", [])
    if not isinstance(limitations, list) or any(not isinstance(item, str) for item in limitations):
        raise ValueError("Audit limitations must be a list of strings.")
    for name in GATE_CASES:
        value = report["live_gate_cases"].get(name)
        if value is not None and not isinstance(value, str):
            raise ValueError("Live gate case statuses must be strings or null.")
    for name, observation in report["observations"].items():
        if (not isinstance(observation, dict) or not isinstance(observation.get("status"), str)
                or observation["status"] not in {"read", "unavailable"}):
            raise ValueError("Each observation must have a read or unavailable status.")
        if observation["status"] == "unavailable":
            if not isinstance(observation.get("reason"), str):
                raise ValueError("Unavailable observations must include a reason string.")
            continue
        data = observation.get("data")
        if name in OBJECT_OBSERVATIONS and not isinstance(data, dict):
            raise ValueError("Object observations must contain an object in data.")
        if name in LIST_OBSERVATIONS:
            item_type = str if name == "repository_languages" else dict
            if not isinstance(data, list) or any(not isinstance(item, item_type) for item in data):
                raise ValueError("List observations must contain a correctly typed list in data.")


def cell(value):
    """Keep saved values literal, including Markdown/HTML and multiline names."""
    if value is None:
        return "not recorded"
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    value = html.escape(value, quote=False)
    for character in "\\|`*_[]~":
        value = value.replace(character, "\\" + character)
    return "<br>".join(value.splitlines()) or "(empty string)"


def table(headers, rows):
    return ["| " + " | ".join(cell(value) for value in headers) + " |",
            "| " + " | ".join("---" for _ in headers) + " |",
            *("| " + " | ".join(cell(value) for value in row) + " |" for row in rows), ""]


def render_report(report):
    validate(report)
    lines = ["# GitHub code scanning evidence", "",
             "This is an offline rendering of saved audit data, not a new GitHub check.",
             "Creating this report does not verify merge protection. Analysis/upload success",
             "and observed configuration do not prove that findings block a merge.", ""]
    lines += table(("Recorded field", "Value"), [(name, report.get(name)) for name in (
        "repository", "observed_at", "status", "target_ref", "target_sha", "read_only",
        "target_changed_during_read", "qualifying_rule_observed", "merge_protection_verified")])
    if report.get("target_changed_during_read") is True:
        lines += ["**The audit could not establish a stable head. Do not treat these records",
                  "as evidence for one current revision; collect a fresh audit.**", ""]
    lines += ["Saved flags and case statuses are reproduced without upgrading them to a pass.",
              "Missing or null values are shown as 'not recorded', never as false or success.", ""]

    observations = report["observations"]
    lines += ["## Evidence availability", ""]
    names = OBJECT_OBSERVATIONS | LIST_OBSERVATIONS | observations.keys()
    # A main-only audit has no pull-request observation by design.
    if "pull_request" not in observations and report.get("target_ref") == "refs/heads/main":
        names = names - {"pull_request"}
    lines += table(("Observation", "Status", "Unavailable reason"), [
        (name, observations.get(name, {}).get("status"), observations.get(name, {}).get("reason"))
        for name in sorted(names)])
    lines += ["Unavailable (including HTTP 403/404) means evidence could not be read.",
              "It does not establish that protection or alerts are absent.", ""]

    def section(title, name, columns):
        lines.extend(["## " + title, ""])
        observation = observations.get(name)
        if observation is None:
            lines.extend(["Not recorded.", ""])
        elif observation["status"] == "unavailable":
            lines.extend(["Unavailable: " + cell(observation["reason"]) + ".", ""])
        else:
            data = observation["data"]
            if isinstance(data, dict):
                lines.extend(table(("Recorded field", "Value"), [(key, data.get(key)) for key in columns]))
            elif not data:
                lines.extend(["The saved read returned no records. This is not proof of protection.", ""])
            elif name == "repository_languages":
                lines.extend(table(("Language",), [(item,) for item in data]))
            else:
                lines.extend(table(columns, [[row.get(key) for key in columns] for row in data]))

    section("Main branch", "main", ("sha", "protected"))
    if "pull_request" in observations or str(report.get("target_ref", "")).startswith("refs/pull/"):
        section("Pull request", "pull_request", ("number", "head_sha", "base", "state", "draft", "mergeable_state", "url"))
    section("Head recheck", "target_recheck", ("sha",))
    section("Default scanning setup", "default_setup", ("state", "languages", "query_suite", "updated_at", "schedule"))
    section("Repository languages", "repository_languages", ())
    section("Workflow inventory", "workflows", ("name", "path", "state"))
    lines += ["Workflow names and language inventory alone do not prove trigger or language coverage.", ""]
    section("Analysis jobs and results checks", "checks",
            ("name", "kind", "app", "head_sha", "matches_target", "status", "conclusion", "url"))
    lines += ["`analysis_job` identifies analysis/upload; `results_check_candidate` must be checked",
              "against the actual GitHub app and configured rule. Pending, neutral or missing",
              "conclusions are not rewritten as success.", ""]
    section("Uploaded analyses", "analyses",
            ("id", "tool", "category", "commit_sha", "ref", "matches_target", "created_at", "has_error", "has_warning"))
    lines += ["`matches_target` is the saved exact-SHA comparison. Old or merge-ref analyses",
              "are not promoted to current-head evidence. No live head is checked by this converter.", ""]
    section("Observed rulesets", "rulesets", ("id", "name", "enforcement", "source_type", "source"))
    section("Effective main rules", "effective_main_rules",
            ("type", "parameters", "ruleset_id", "ruleset_source_type", "ruleset_source"))
    section("Classic branch protection", "branch_protection",
            ("required_status_checks", "required_pull_request_reviews", "enforce_admins"))
    section("Open alert inventory", "open_alert_inventory", ("open_count", "by_severity"))
    lines += ["Alert counts are an inventory, not a triage result or proof of exploitability.", "",
              "## Administrator gate checks", ""]
    lines += table(("Case", "Recorded status"), [(name, report["live_gate_cases"].get(name)) for name in GATE_CASES])
    lines += ["Confirm all three cases on a disposable, nonmerged PR: a clean analyzed head,",
              "missing/pending analysis, and a controlled qualifying finding. Retain the tested",
              "head, configured thresholds and actual rule result. A generic blocked merge",
              "state may be caused by missing reviews and does not prove a scanning rejection.", "",
              "## Saved limitations", ""]
    lines += ["- " + cell(value) for value in report.get("limitations", [])] or ["Not recorded."]
    return "\n".join(lines) + "\n"


def reject_constant(_value):
    raise ValueError("Non-finite numbers are not valid audit JSON.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Saved schema-v1 audit JSON")
    parser.add_argument("--output", type=Path, required=True, help="New Markdown file; never overwritten")
    args = parser.parse_args()
    try:
        saved = args.input.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        print("Cannot read the input as a UTF-8 audit file.", file=sys.stderr)
        return 2
    try:
        report = json.loads(saved, parse_constant=reject_constant)
        markdown = render_report(report)
    except json.JSONDecodeError:
        print("Invalid audit JSON.", file=sys.stderr)
        return 2
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        print("Cannot write the Markdown report: its parent directory is unavailable.", file=sys.stderr)
        return 2
    try:
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(markdown)
    except FileExistsError:
        print("Output already exists; choose a new path. No file was overwritten.", file=sys.stderr)
        return 2
    except OSError:
        print("Cannot write the Markdown report; output may be incomplete.", file=sys.stderr)
        return 2
    print("Markdown report created. This does not verify merge protection.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
