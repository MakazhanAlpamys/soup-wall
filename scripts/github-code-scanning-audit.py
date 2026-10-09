#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read GitHub scanning evidence with gh; never edit settings, alerts, PRs or rulesets."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlencode


class GitHubReadError(RuntimeError):
    def __init__(self, status):
        super().__init__(status)
        self.status = status


def get(endpoint):
    try:
        result = subprocess.run(["gh", "api", "--hostname", "github.com", "--method", "GET", endpoint],
                                capture_output=True, text=True, timeout=30, check=False)
    except FileNotFoundError:
        raise GitHubReadError("gh_unavailable") from None
    except subprocess.TimeoutExpired:
        raise GitHubReadError("timeout") from None
    if result.returncode:
        status = re.search(r"HTTP (\d{3})", result.stderr)
        raise GitHubReadError("http_" + status.group(1) if status else "request_failed")
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise GitHubReadError("invalid_json") from None


def pages(endpoint, key=None, parameters=None):
    records = []
    for page in range(1, 101):
        data = get(endpoint + "?" + urlencode({**(parameters or {}), "per_page": 100, "page": page}))
        batch = data.get(key) if key and isinstance(data, dict) else data
        if not isinstance(batch, list):
            raise GitHubReadError("invalid_collection")
        records.extend(batch)
        if len(batch) < 100:
            return records
    raise GitHubReadError("pagination_limit")


def meets_threshold(rule):
    if rule.get("type") != "code_scanning":
        return False
    return any(tool.get("tool") == "CodeQL"
               and tool.get("alerts_threshold") in {"errors", "errors_and_warnings", "all"}
               and tool.get("security_alerts_threshold") in {"high_or_higher", "medium_or_higher", "all"}
               for tool in rule.get("parameters", {}).get("code_scanning_tools", []))


def summarize_checks(checks, expected_sha):
    # Analysis/upload jobs and the separate alert-bearing check must remain distinct.
    return [{"name": row.get("name"), "head_sha": row.get("head_sha"),
             "matches_target": row.get("head_sha") == expected_sha,
             "status": row.get("status"), "conclusion": row.get("conclusion"),
             "app": row.get("app", {}).get("slug"), "url": row.get("html_url"),
             "kind": "analysis_job" if row.get("name", "").startswith("Analyze (") else "results_check_candidate"}
            for row in checks if "codeql" in row.get("name", "").lower()
            or row.get("name", "").startswith("Analyze (")]


def summarize_analyses(rows, expected_sha):
    return [{"id": row.get("id"), "commit_sha": row.get("commit_sha"), "ref": row.get("ref"),
             "matches_target": row.get("commit_sha") == expected_sha, "category": row.get("category"),
             "tool": row.get("tool", {}).get("name"), "created_at": row.get("created_at"),
             "has_error": bool(row.get("error")), "has_warning": bool(row.get("warning"))}
            for row in rows]


def audit(repository, pr=None):
    prefix = "repos/" + repository
    report = {"schema_version": 1, "repository": repository, "status": "incomplete",
              "observed_at": datetime.now(timezone.utc).isoformat(), "read_only": True,
              "merge_protection_verified": False, "live_gate_cases": {"clean": "not_run", "missing_or_pending": "not_run",
                                                                     "qualifying_finding": "not_run"},
              "observations": {}, "limitations": [
                  "A successful analysis/upload job is not proof that alert thresholds block merge.",
                  "Effective rules are observed configuration; three disposable-PR acceptance cases still require independent evidence.",
                  "403/404 responses mean unavailable evidence, not absence of protection or alerts.",
                  "Only the exact requested head is credited; merge-ref analysis is recorded separately without inferring head coverage.",
                  "Open-alert counts are an inventory, not SOU-17 triage or proof of exploitability."]}
    observations = report["observations"]
    def observe(name, operation, select=lambda value: value):
        try:
            value = operation()
            observations[name] = {"status": "read", "data": select(value)}
            return value
        except GitHubReadError as error:
            observations[name] = {"status": "unavailable", "reason": error.status}
            return None
    branch = observe("main", lambda: get(prefix + "/branches/main"),
                     lambda row: {"sha": row["commit"]["sha"], "protected": row.get("protected")})
    pull = None
    if pr is not None:
        pull = observe("pull_request", lambda: get(prefix + f"/pulls/{pr}"),
                       lambda row: {"number": row["number"], "head_sha": row["head"]["sha"],
                                    "base": row["base"]["ref"], "state": row["state"], "draft": row.get("draft"),
                                    "mergeable_state": row.get("mergeable_state"), "url": row["html_url"]})
    sha = pull["head"]["sha"] if pull else branch["commit"]["sha"] if branch and pr is None else None
    report["target_sha"] = sha
    ref = f"refs/pull/{pr}/head" if pr is not None else "refs/heads/main"
    report["target_ref"] = ref
    observe("default_setup", lambda: get(prefix + "/code-scanning/default-setup"),
            lambda row: {key: row.get(key) for key in ("state", "languages", "query_suite", "updated_at", "schedule")})
    observe("repository_languages", lambda: get(prefix + "/languages"), lambda row: sorted(row))
    observe("workflows", lambda: pages(prefix + "/actions/workflows", "workflows"),
            lambda rows: [{key: row.get(key) for key in ("name", "path", "state")} for row in rows])
    observe("rulesets", lambda: pages(prefix + "/rulesets"),
            lambda rows: [{key: row.get(key) for key in ("id", "name", "enforcement", "source_type", "source")} for row in rows])
    effective = observe("effective_main_rules", lambda: pages(prefix + "/rules/branches/main"))
    report["qualifying_rule_observed"] = any(meets_threshold(row) for row in effective) if effective is not None else None
    observe("branch_protection", lambda: get(prefix + "/branches/main/protection"),
            lambda row: {key: row.get(key) for key in ("required_status_checks", "required_pull_request_reviews", "enforce_admins")})
    if sha:
        observe("checks", lambda: pages(prefix + f"/commits/{sha}/check-runs", "check_runs", {"filter": "latest"}),
                lambda rows: summarize_checks(rows, sha))
        observe("analyses", lambda: pages(prefix + "/code-scanning/analyses", parameters={"ref": ref}),
                lambda rows: summarize_analyses(rows, sha))
        def alerts(rows):
            counts = {}
            for row in rows:
                key = row.get("rule", {}).get("security_severity_level") or row.get("rule", {}).get("severity") or "unknown"
                counts[key] = counts.get(key, 0) + 1
            return {"open_count": len(rows), "by_severity": counts}
        observe("open_alert_inventory", lambda: pages(prefix + "/code-scanning/alerts", parameters={"ref": ref, "state": "open"}), alerts)
        # Detect a moving head instead of mixing evidence from two revisions.
        current = observe("target_recheck", lambda: get(prefix + (f"/pulls/{pr}" if pr is not None else "/branches/main")),
                          lambda row: {"sha": row["head"]["sha"] if pr is not None else row["commit"]["sha"]})
        report["target_changed_during_read"] = current is None or (current["head"]["sha"] if pr is not None else current["commit"]["sha"]) != sha
    else:
        report["target_changed_during_read"] = None
    if all(row["status"] == "read" for row in observations.values()) and sha and not report["target_changed_during_read"]:
        report["status"] = "collected"  # Collection success never means merge protection passed.
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="SoupTeam/soup-wall")
    parser.add_argument("--pr", type=int)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo) or (args.pr is not None and args.pr < 1):
        parser.error("use owner/repository and a positive PR number")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        report = audit(args.repo, args.pr)
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(f"Read-only audit: {report['status']}. Evidence: {args.output}")
    return 0 if report["status"] == "collected" else 2


if __name__ == "__main__":
    sys.exit(main())
