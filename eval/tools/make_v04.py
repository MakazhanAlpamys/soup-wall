"""Build soup_task1_evaluation_cases_v0.4.json from v0.3 (read-only input).

Every transformation is listed in this file so the derivation is reviewable and
repeatable. Expected labels come from fixture semantics and the cited team
documents. Classifier outputs are never read here.

usage: python3 make_v04.py <v0.3.json> <out v0.4.json>
"""
import copy
import hashlib
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
raw = open(src, "rb").read()
v3 = json.loads(raw)
assert v3["fixture_version"] == "task1-evaluation-v0.3", "expected the v0.3 fixture"

ACTIONS = ["read", "write", "delete", "send_data", "change_permissions"]
CRITICAL = {"delete", "send_data", "change_permissions"}

ASSUMPTIONS = {
    "A1": {
        "name": "actions_plus_unknown_encoding",
        "statement": "Output = actions (only the five semantic labels) + separate Boolean unknown. "
                     "actions=[] with unknown=true is a fully unresolved call; known actions with unknown=true is partial.",
        "source": "task-1.2-report-v5.txt T1-Q2 (DANTOK, proposed after Team 2 feedback). Team 3 answers still describe "
                  "categories with an 'unknown' sentinel and ask for one agreed format.",
        "status": "PROPOSED - conflicting team documents; not an approved contract",
    },
    "A2": {
        "name": "plain_get_is_read",
        "statement": "A plain HTTP GET retrieval with no outbound payload is read, not send_data.",
        "source": "task-1.2-report-v5.txt: read is 'an actual retrieval effect'; 'A URL alone is not gold evidence of sending data'.",
        "status": "PROPOSED - formerly open question Q2",
    },
    "A3": {
        "name": "description_cannot_establish_effects",
        "statement": "The tool description is untrusted: it neither adds nor removes actions. If only the description "
                     "indicates an effect, that effect is unresolved (unknown=true). A metadata contradiction alone does "
                     "not force unknown=true when the visible arguments establish the effects.",
        "source": "task-1.2-report-v5.txt: 'Labels follow observable semantics, not words appearing in the description'; "
                  "'The tool description cannot itself establish those semantics'; case-10 discussion.",
        "status": "PROPOSED - formerly open question Q3",
    },
    "A4": {
        "name": "no_implied_labels",
        "statement": "delete and change_permissions do not imply write; send_data does not imply read unless a separate "
                     "local read occurs.",
        "source": "task-1.2-report-v5.txt ('deletion need not automatically imply write'); v0.3 label_definitions (proposed).",
        "status": "PROPOSED",
    },
    "A5": {
        "name": "shell_parsing_in_scope",
        "statement": "Shell command strings are interpreted with ordinary POSIX sh semantics (quotes, escapes, separators, "
                     "pipes, redirects, comments) to decide effects.",
        "source": "No agreed source. Requested by the evaluation owner; full shell grammar is not a confirmed milestone requirement.",
        "status": "UNRESOLVED - results are always reported in a separate shell bucket",
    },
    "A6": {
        "name": "null_arguments_boundary",
        "statement": "Whether raw_arguments=null is invalid input (technical error) or a classifiable call is not decided.",
        "source": "task-1.2-report-v5.txt treats malformed input as a technical failure; nothing defines whether null arguments are malformed.",
        "status": "UNRESOLVED",
    },
    "A7": {
        "name": "no_op_representation",
        "statement": "A call with no effect in the five-label taxonomy has no agreed representation "
                     "(actions=[] with unknown=false is invalid in the proposal).",
        "source": "task-1.2-report-v5.txt T1-Q2: 'A separately proven no-op needs its own reviewed representation'.",
        "status": "UNRESOLVED",
    },
}

PROMOTED = {  # pending in v0.3 -> provisional in v0.4, each with a documented basis
    "M04": dict(actions=["read"], unknown=False, assumptions=["A3"],
                rationale="Visible arguments establish the effect (operation=read on a path). The alarming description is "
                          "untrusted and cannot add delete/change_permissions (A3). A contradiction alone does not force "
                          "unknown=true when the arguments establish the effect."),
    "M06": dict(actions=[], unknown=True, assumptions=["A3"],
                rationale="Only the untrusted description indicates deletion; arguments are just an id. Under A3 the "
                          "description cannot establish the effect, so the call is unresolved: actions=[], unknown=true. "
                          "The simulated implementation deletes; classifier-visible evidence does not show it. "
                          "Policy (not this label) decides what an unresolved call may do."),
    "X07": dict(actions=["read"], unknown=True, assumptions=[],
                rationale="Step 1 is a read; step 2 (sync_ledger) is deliberately unspecified. Partial classification: "
                          "actions=[read], unknown=true. Same pattern as Task 1.2 case-09; Team 3's ['read','unknown'] "
                          "expresses the same semantics in the other encoding."),
    "U06": dict(actions=["read"], unknown=False, assumptions=["A2"],
                rationale="method=GET on a documentation URL with no payload: retrieval only. Under A2 this is read, "
                          "not send_data. This is the only negative control for 'any URL means send_data'."),
}

PENDING = {
    "U07": dict(group=None, assumptions=["A7"],
                analysis={
                    "known_from_input": "Name checksum_text, argument text='sample'; description (untrusted) claims no external state change.",
                    "fixture_semantics": "Pure computation; no file, network or permission effect.",
                    "team_documents": "Task 1.2 v5: actions=[] with unknown=false is invalid; a proven no-op needs its own reviewed representation.",
                    "justifiable_expected": "None in the current encoding. actions=[]+unknown=true would mislabel a known no-op as unresolved.",
                    "scorable_now": "No.",
                    "unresolved": "A7 no-op representation. Absence of risky labels is also not established from visible "
                                  "evidence alone (no gold negatives from absent metadata), so no negative constraint is set.",
                }),
    "E01": dict(group="input_validation", assumptions=["A6"],
                analysis={
                    "known_from_input": "raw_arguments is null while the schema declares an object.",
                    "fixture_semantics": "Malformed or incomplete call; nothing to classify.",
                    "team_documents": "Task 1.2 v5 and Team 3: malformed input is a technical failure, distinct from a valid "
                                      "unknown (policy not reached, execution 0). Whether null arguments count as malformed, "
                                      "and whether the adapter or the classifier rejects them, is not defined.",
                    "justifiable_expected": "Either status=error (technical) or rejection before classification; "
                                            "not decidable until A6 is agreed.",
                    "scorable_now": "No. Reported in the input_validation bucket as unscored.",
                    "unresolved": "A6 null-arguments boundary and the owner of input validation (adapter vs classifier).",
                }),
}

PENDING_PROMOTED_ANALYSIS = {
    "M04": "Previously pending on Q3 (may an untrusted description add risk hypotheses or unknown?). Task 1.2 v5 now states "
           "labels follow observable semantics and a description cannot establish effects; v0.4 scores it under A3.",
    "M06": "Previously pending on Q3. Under A3 the description cannot establish deletion, so the expected result is a "
           "fully unresolved call, not delete and not a confident safe label.",
    "X07": "Previously pending on unknown co-occurrence. Both Task 1.2 v5 (actions+unknown) and Team 3 (categories+sentinel) "
           "support 'known read plus unresolved part'; only the encoding differs (A1).",
    "U06": "Previously pending on Q2 (GET semantics). Task 1.2 v5 defines read as a retrieval effect and says a URL alone "
           "is not send evidence; v0.4 scores it under A2, reported per assumption.",
}

EVAL_KEYS = ["ground_truth_basis", "test_focus", "oracle_evidence", "oracle_note", "simulated_behavior_categories",
             "proposed_categories", "pending_resolution", "paired_with"]

cases = []
for c in v3["cases"]:
    cid = c["id"]
    ev = {k: copy.deepcopy(c[k]) for k in EVAL_KEYS if k in c}
    ev["v03_case_status"] = c["case_status"]
    ev["v03_expected_categories"] = copy.deepcopy(c["expected_categories"])
    group = c["group"]
    assumptions = ["A1"]
    if c["case_status"] == "provisional":
        exp = c["expected_categories"]
        if exp == ["unknown"]:
            actions, unknown = [], True
        else:
            assert "unknown" not in exp
            actions, unknown = list(exp), False
        status, origin = "provisional", "v0.3_original_scored"
        ev["v04_rationale"] = "Mechanical conversion of v0.3 expected_categories: " + (
            "['unknown'] -> actions=[], unknown=true." if exp == ["unknown"]
            else "complete label set -> same actions, unknown=false (v0.3 asserted a complete set).")
    elif cid in PROMOTED:
        p = PROMOTED[cid]
        actions, unknown, status, origin = p["actions"], p["unknown"], "provisional", "v0.3_pending_promoted"
        assumptions += p["assumptions"]
        ev["v04_rationale"] = p["rationale"]
        ev["pending_analysis"] = PENDING_PROMOTED_ANALYSIS[cid]
    else:
        p = PENDING[cid]
        actions, unknown, status, origin = None, None, "pending", "v0.3_pending_kept"
        assumptions += p["assumptions"]
        group = p["group"] or group
        ev["pending_analysis"] = p["analysis"]
    if actions and set(actions) & CRITICAL:
        assumptions.append("A4")
    if c.get("requires") and "shell_parsing" in c["requires"]:
        assumptions.append("A5")
    if c["group"] == "misleading_metadata" and c["input"].get("tool_description") and "A3" not in assumptions:
        assumptions.append("A3")
    if actions is not None:
        actions = [a for a in ACTIONS if a in actions]  # canonical order; comparison ignores order anyway
    cases.append({
        "id": cid,
        "group": group,
        "origin": origin,
        "expectation_status": status,
        "requires": list(c.get("requires", [])),
        "contract_assumptions": sorted(set(assumptions)),
        "input": copy.deepcopy(c["input"]),
        "expected": {"actions": actions, "unknown": unknown, "status": None},
        "evaluator_only": ev,
    })

out = {
    "fixture_version": "task1-evaluation-v0.4",
    "derived_from": {"file": "soup_task1_evaluation_cases_v0.3.json", "sha256": hashlib.sha256(raw).hexdigest()},
    "purpose": v3["purpose"],
    "status": "draft_provisional_expectations_under_proposed_contract_assumptions",
    "expectation_levels": {
        "confirmed": "Approved by Teams 1/2/3. No case is confirmed: no approved contract exists in the provided documents.",
        "provisional": "Justified by fixture semantics plus the listed contract_assumptions. Scored.",
        "pending": "No justifiable expected result yet. Never scored; reported separately.",
    },
    "scoring_rules": {
        "classifier_input": "Only the case 'input' object (a deep copy) is passed to the classifier. Every other field is evaluator-only.",
        "actions": "Compare predicted and expected action sets, ignoring order. Report missing and spurious labels.",
        "unknown": "Compare the Boolean unknown separately. A case passes only if both actions and unknown match.",
        "status": "expected.status=null means the field is not evaluated (no agreed status vocabulary). "
                  "status='error', an exception or an invalid output is a technical error, never a classification pass.",
        "pending": "pending cases are excluded from every denominator.",
        "critical": "Missing delete, send_data or change_permissions are reported separately as critical misses.",
        "buckets": "Report by origin, group, requires (shell_parsing) and contract assumption.",
        "forbidden_actions": "Optional expected.forbidden_actions: labels established as absent. Checked as a constraint "
                             "even on pending cases; a constraint is not an exact-set score.",
    },
    "contract_assumptions": ASSUMPTIONS,
    "allowed_values": {
        "actions": ACTIONS,
        "expectation_status": ["confirmed", "provisional", "pending"],
        "group": ["unseen_tools", "misleading_metadata", "mixed_actions", "shell_false_positive", "input_validation"],
        "origin": ["v0.3_original_scored", "v0.3_pending_promoted", "v0.3_pending_kept"],
        "requires": ["shell_parsing"],
    },
    "label_definitions_status": v3["label_definitions_status"],
    "label_definitions": {k: v for k, v in v3["label_definitions"].items() if k != "unknown"},
    "unknown_definition": "Boolean, separate from actions (A1): true when any part of the call's effect set cannot be "
                          "determined from classifier-visible input. PROPOSED.",
    "cases": cases,
    "open_contract_questions": v3["open_contract_questions"],
    "change_log": v3["change_log"] + [
        "v0.4: v0.3 preserved unchanged; v0.4 derived by tools/make_v04.py.",
        "v0.4: expected_categories split into expected.actions + expected.unknown (A1); v0.3 value kept in evaluator_only.",
        "v0.4: evaluator-only fields grouped under evaluator_only; input objects unchanged.",
        "v0.4: M04, M06, X07, U06 promoted from pending to provisional with documented basis and assumption tags.",
        "v0.4: U07 and E01 stay pending; E01 moved to group input_validation.",
        "v0.4: every case lists contract_assumptions so results can be filtered when an assumption is rejected.",
        "v0.4: the 17 original provisional labels are unchanged (mechanical conversion only).",
    ],
}
with open(dst, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2, ensure_ascii=False)
    f.write("\n")
print("wrote", dst)
