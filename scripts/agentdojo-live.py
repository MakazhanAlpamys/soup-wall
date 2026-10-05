#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate or fixture-check the pinned runtime; live requires explicit operator inputs."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import time
import tempfile
import types

sys.dont_write_bytecode = True
MODULE_PATH = Path(__file__).resolve().parent / "benchmarks/agentdojo_live.py"
MODULE_BYTES = MODULE_PATH.read_bytes()
CLI_BYTES = Path(__file__).read_bytes()
sys.path.insert(0, str(MODULE_PATH.parent))
# Compile the exact bytes recorded in evidence; do not execute a stale helper pyc.
adapter = types.ModuleType("agentdojo_live")
adapter.__file__ = str(MODULE_PATH)
sys.modules["agentdojo_live"] = adapter
exec(compile(MODULE_BYTES, str(MODULE_PATH), "exec", dont_inherit=True), adapter.__dict__)
NATIVE_PATH = MODULE_PATH.with_name("agentdojo_native.py")
NATIVE_BYTES = NATIVE_PATH.read_bytes()
native = types.ModuleType("agentdojo_native")
native.__file__ = str(NATIVE_PATH)
sys.modules["agentdojo_native"] = native
exec(compile(NATIVE_BYTES, str(NATIVE_PATH), "exec", dont_inherit=True), native.__dict__)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["manifest", "validate", "fixture", "native-fixture", "live"], default="manifest")
    parser.add_argument("--upstream-checkout", type=Path)
    parser.add_argument("--agent-binary", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--plan", type=Path, help="Explicit frozen native task/injection selection JSON")
    parser.add_argument("--native-registry", type=Path,
                        help="Explicit operator-installed sw-native/1 semantics registry; fallback remains default")
    parser.add_argument("--provider", choices=["openai-compatible"])
    parser.add_argument("--model")
    parser.add_argument("--base-url")
    parser.add_argument("--credential-env", help="Only this explicitly selected variable is read; no default provider key")
    parser.add_argument("--max-calls", type=int)
    parser.add_argument("--max-total-request-bytes", type=int)
    parser.add_argument("--max-output-tokens", type=int)
    parser.add_argument("--max-reserved-usd", type=float)
    parser.add_argument("--input-usd-per-million", type=float)
    parser.add_argument("--output-usd-per-million", type=float)
    parser.add_argument("--acknowledge-cost-estimate", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    if args.mode == "manifest":
        print(json.dumps({"schema_version": 1, "upstream_revision": adapter.REVISION,
                          "adapter": native.CONTRACT if args.native_registry else "existing-hook-native-name-fallback-v1", "model_calls": 0,
                          "policy": "unchanged shipped agent-default.yaml; judge disabled",
                          "post_result_behavior": "explicit native result/context admission" if args.native_registry else "observe only; no result gating",
                          "live_requires": ["pinned upstream checkout", "Agent binary", "frozen task plan",
                                            "explicit provider/model/base URL/credential variable", "call/byte/output/cost limits"]}, indent=2))
        return
    if args.upstream_checkout is None:
        parser.error("Select --upstream-checkout explicitly")
    if args.mode == "validate":
        print(json.dumps(adapter.verify_checkout(args.upstream_checkout), indent=2))
        return
    if args.agent_binary is None or not args.agent_binary.is_file():
        parser.error("Select --agent-binary explicitly")
    if args.mode in {"fixture", "native-fixture"}:
        fixture_output = None
        if args.mode == "native-fixture":
            if args.evidence is None:
                parser.error("Native fixture requires a fresh explicit --evidence destination")
            fixture_output = adapter.EvidenceOutput(args.evidence)
        sanitize_environment()
        snapshots = {"cli": adapter.digest(CLI_BYTES), "agentdojo_live": adapter.digest(MODULE_BYTES),
                     "agentdojo_native": adapter.digest(NATIVE_BYTES)}
        helpers = ["test_agentdojo_live"]
        if args.mode == "native-fixture":
            helpers.append("test_agentdojo_native")
        compiled_helpers = {}
        for name in helpers:
            path = MODULE_PATH.with_name(name + ".py")
            source = path.read_bytes()
            helper = types.ModuleType(name)
            helper.__file__ = str(path)
            sys.modules[name] = helper
            exec(compile(source, str(path), "exec", dont_inherit=True), helper.__dict__)
            compiled_helpers[name] = helper
            snapshots[name] = adapter.digest(source)
        run_fixture_checks = compiled_helpers[helpers[-1]].run_fixture_checks
        try:
            if args.mode == "native-fixture":
                result = run_fixture_checks(args.upstream_checkout, args.agent_binary, repo / "target", snapshots)
            else:
                result = run_fixture_checks(args.upstream_checkout, args.agent_binary, repo / "target")
            if fixture_output is not None:
                result["cli_source_sha256"] = adapter.digest(CLI_BYTES)
                fixture_output.publish(result)
        except Exception as error:
            if fixture_output is not None:
                fixture_output.publish({"status": "incomplete", "field_gate_complete": False,
                                        "error_type": type(error).__name__})
            raise
    else:
        required = [args.plan, args.provider, args.model, args.base_url, args.credential_env,
                    args.max_calls, args.max_total_request_bytes, args.max_output_tokens]
        rates = [args.max_reserved_usd, args.input_usd_per_million, args.output_usd_per_million]
        if not all(required) or any(value is None for value in rates) or not args.acknowledge_cost_estimate:
            parser.error("Live requires an explicit plan, provider/model/URL/credential variable and all budget options; acknowledge the cost estimate")
        if args.evidence is None or args.evidence.exists():
            parser.error("Live requires a fresh explicit --evidence destination")
        output = adapter.EvidenceOutput(args.evidence)
        try:
            result = run_live(args, repo)
        except Exception as error:
            output.publish({"status": "incomplete", "live_gate_complete": False, "error_type": type(error).__name__})
            raise adapter.AdapterError("Live setup failed; sanitized failure evidence was preserved") from None
        output.publish(result)
    if args.evidence and args.mode not in {"live", "native-fixture"}:
        args.evidence.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if result.get("status") == "incomplete":
        raise adapter.AdapterError("Live run incomplete; sanitized partial evidence was preserved")


def sanitize_environment():
    keep = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PROGRAMFILES", "SYSTEMDRIVE"}
    retained = {name: os.environ[name] for name in keep if name in os.environ}
    os.environ.clear()
    os.environ.update(retained)


def run_live(args, repo):
    plan_bytes = args.plan.read_bytes()
    plan = json.loads(plan_bytes)
    policy_bytes = (repo / "crates/agent/policies/agent-default.yaml").read_bytes()
    policy_hash = adapter.digest(policy_bytes)
    binary_hash = adapter.file_hash(args.agent_binary)
    native_registry_path = getattr(args, "native_registry", None)
    native_registry = native.Registry(native_registry_path.read_bytes()) if native_registry_path else None
    if (set(plan) != {"schema_version", "upstream_revision", "benchmark_version", "suite", "cases"}
            or plan["schema_version"] != 1 or plan["upstream_revision"] != adapter.REVISION
            or not isinstance(plan["cases"], list) or not plan["cases"]):
        raise adapter.AdapterError("Invalid frozen experiment plan")
    for case in plan["cases"]:
        if (set(case) != {"user_task_id", "injection_task_id", "injections"}
                or not isinstance(case["injections"], dict)
                or not all(isinstance(key, str) and isinstance(value, str) for key, value in case["injections"].items())):
            raise adapter.AdapterError("Invalid experiment case")
    # No ambient credentials are consulted. Imports/daemon children see only runtime paths.
    key = os.environ.get(args.credential_env)
    if not key:
        raise adapter.AdapterError("The explicitly selected credential variable is empty")
    sanitize_environment()
    upstream = adapter.load_upstream(args.upstream_checkout)
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
    from agentdojo.task_suite.load_suites import get_suite
    provider = adapter.BudgetProvider(args.base_url, key, args.model, max_calls=args.max_calls,
                                      max_total_request_bytes=args.max_total_request_bytes,
                                      max_output_tokens=args.max_output_tokens, max_reserved_usd=args.max_reserved_usd,
                                      input_usd_per_million=args.input_usd_per_million,
                                      output_usd_per_million=args.output_usd_per_million)
    suite = get_suite(plan["benchmark_version"], plan["suite"])
    if native_registry is not None:
        for function in suite.tools:
            native_registry.schema(function)
    registry = [{"name": function.name, "description": function.description,
                 "schema": function.parameters.model_json_schema(), "docstring": function.full_docstring,
                 "dependencies": {name: dependency.env_dependency if isinstance(dependency.env_dependency, str)
                                  else "callable-bound-by-source-inventory" for name, dependency in function.dependencies.items()}}
                for function in suite.tools]
    selected = []
    for case in plan["cases"]:
        task = suite.get_user_task_by_id(case["user_task_id"])
        injection = suite.get_injection_task_by_id(case["injection_task_id"]) if case["injection_task_id"] else None
        suite.load_and_inject_default_environment(case["injections"])
        selected.append((case, task, injection))
    dependencies = ["openai", "pydantic", "docstring-parser", "typing-extensions", "PyYAML", "tenacity",
                    "google-genai", "rich", "deepdiff", "anthropic", "cohere", "requests"]
    dependency_versions = {name: importlib.metadata.version(name) for name in dependencies}
    # Every daemon uses the same private snapshot, never the mutable repository policy path.
    adapter.safe_temporary_parent(repo / "target")
    snapshot_directory = tempfile.TemporaryDirectory(prefix="agentdojo-policy-", dir=repo / "target")
    policy = Path(snapshot_directory.name) / "policy.yaml"
    policy.write_bytes(policy_bytes)
    rows = []
    failure = None
    try:
        for case, task, injection in selected:
            for defended in [False, True]:
                started = time.monotonic()
                daemon = None
                try:
                    llm = OpenAILLM(provider, args.model)
                    llm.name = args.model
                    pipeline = AgentPipeline.from_config(PipelineConfig(llm=llm, model_id=args.model, defense=None,
                                                                        system_message_name=None, system_message=None))
                    if adapter.file_hash(args.agent_binary) != binary_hash or policy.read_bytes() != policy_bytes:
                        raise adapter.AdapterError("Frozen executable or policy snapshot changed")
                    daemon = adapter.DisposableAgent(args.agent_binary, policy, repo / "target",
                                                      native_registry=native_registry if defended else None)
                    with daemon:
                        if defended and native_registry is not None:
                            runtime = native.runtime_class(upstream, daemon.client)
                            native.guard_pipeline(pipeline, upstream, daemon.client)
                        else:
                            runtime = adapter.runtime_class(upstream, daemon.client) if defended else upstream.runtime.FunctionsRuntime
                        utility, injection_success = adapter.run_original_task(suite, pipeline, task, injection, case["injections"], runtime)
                        if daemon.client.failed or getattr(daemon.client, "withheld", False):
                            raise adapter.AdapterError("Task has incomplete inspection evidence; evaluators are not reported")
                        row = {"user_task_id": case["user_task_id"], "injection_task_id": case["injection_task_id"],
                                 "defended": defended, "utility": utility,
                                 "injection_success": injection_success if injection else None,
                                 "elapsed_ms": round((time.monotonic() - started) * 1000),
                                 "pre_calls": sum(row["event"] == "PreToolUse" for row in daemon.client.receipts),
                                 "post_results_observed": sum(row["event"] == "PostToolUse" for row in daemon.client.receipts),
                                 "deny": sum(row["decision"] == "deny" for row in daemon.client.receipts),
                                 "approval_required": sum(row["decision"] == "ask" for row in daemon.client.receipts),
                                 "receipt_sha256": adapter.digest(adapter.encoded(daemon.client.receipts))}
                        if defended and native_registry is not None:
                            row.update(pre_calls=sum(item["event"] == "call" for item in daemon.client.receipts),
                                       post_results_observed=sum(item["event"] == "result" for item in daemon.client.receipts),
                                       contexts_admitted=sum(item["event"] == "context" and item["release"]
                                                             for item in daemon.client.receipts))
                    rows.append(row)
                except Exception as error:
                    failure = {"user_task_id": case["user_task_id"], "injection_task_id": case["injection_task_id"],
                               "defended": defended, "error_type": type(error).__name__,
                               "evaluators_reported": False}
                    if defended and native_registry is not None and daemon is not None and hasattr(daemon, "client"):
                        failure.update(native_policy_withheld=getattr(daemon.client, "withheld", False),
                                       inspection_failed=daemon.client.failed,
                                       native_receipt_sha256=adapter.digest(adapter.encoded(daemon.client.receipts)))
                    break
            if failure:
                break
    finally:
        snapshot_root = Path(snapshot_directory.name).resolve()
        if snapshot_root.parent != (repo / "target").resolve() or not snapshot_root.name.startswith("agentdojo-policy-"):
            raise adapter.AdapterError("Refusing cleanup outside the generated policy snapshot directory")
        snapshot_directory.cleanup()
    report = {"schema_version": 1, "mode": "live-native" if native_registry else "live-fallback", "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": "incomplete" if failure else "completed", "incomplete_case": failure,
            "upstream": upstream.verified, "plan_sha256": adapter.digest(plan_bytes),
            "policy_sha256": policy_hash, "agent_binary_sha256": binary_hash,
            "adapter_source_sha256": adapter.digest(MODULE_BYTES), "cli_source_sha256": adapter.digest(CLI_BYTES),
            "native_registry_sha256": adapter.digest(adapter.encoded(registry)),
            "native_tool_names": [function.name for function in suite.tools],
            "python_version": ".".join(str(part) for part in sys.version_info[:3]),
            "dependency_versions": dependency_versions,
            "model": args.model, "provider": args.provider, "provider_url_sha256": adapter.digest(args.base_url.encode()),
            "selection": {"suite": plan["suite"], "benchmark_version": plan["benchmark_version"],
                          "case_count": len(plan["cases"]), "matched_modes": ["undefended", "enforced"]},
            "settings": {"formatter": "upstream_default_yaml", "ask_handling": "refuse_without_approval",
                         "judge_enabled": False, "concurrency": 1, "tools_loop_max_iterations": 15,
                         "upstream_task_attempts": 3, "upstream_llm_retries": 3, "http_timeout_seconds": 30,
                         "output_limit_parameter": "max_tokens"},
            "budget": {"max_calls": args.max_calls, "max_total_request_bytes": args.max_total_request_bytes,
                       "max_output_tokens": args.max_output_tokens, "max_reserved_usd": args.max_reserved_usd,
                       "input_usd_per_million": args.input_usd_per_million, "output_usd_per_million": args.output_usd_per_million,
                       "reservation": "UTF-8 request-byte input units plus requested output cap; failed attempts retained"},
            "provider_attempts": provider.calls, "request_bytes": provider.request_bytes,
            "reserved_estimated_usd": provider.reserved_usd, "cases": rows,
            "limitations": ["Unknown native names retain coding-tool action/trust fallback",
                            "PostToolUse records only; no result approval gate",
                            "Unattended Ask refuses execution, without a human approval channel",
                            "Input cost reservation uses UTF-8 request bytes, not a verified model tokenizer or invoice",
                            "No native-semantic adaptation or attack effectiveness claim from fixture checks"]}
    if native_registry is not None:
        report.update(native_contract=native.CONTRACT, native_semantics_registry_sha256=native_registry.sha256,
                      native_adapter_source_sha256=adapter.digest(NATIVE_BYTES),
                      limitations=["HTTP authenticates a trusted local collector; it cannot attest actual tool execution",
                                   "Operator-installed registry accuracy remains an explicit trust boundary",
                                   "No human native approval channel; Ask/Deny stop and suppress evaluators",
                                   "Calls failing before the validated native callable abort without prevention credit",
                                   "Nested calls may already have effects before an outer call or result is withheld",
                                   "Withheld results cannot undo completed tool effects",
                                   "Serial pipeline, one original ToolsExecutor, fixed server bounds and expiry",
                                   "Cost reservation uses request bytes, not verified tokens or a provider invoice",
                                   "Fixture evidence is not independent attack effectiveness or task utility"])
    return report


if __name__ == "__main__":
    try:
        main()
    except adapter.AdapterError as error:
        print(json.dumps({"status": "failed", "error": str(error), "live_gate_complete": False}), file=sys.stderr)
        sys.exit(2)
