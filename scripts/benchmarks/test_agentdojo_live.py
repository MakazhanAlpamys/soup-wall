# SPDX-License-Identifier: Apache-2.0
"""Free contract checks against actual pinned upstream classes and a disposable Agent."""
import http.server
from datetime import datetime, timezone
import importlib.metadata
import json
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
from typing import Annotated
import unittest
from unittest.mock import patch

import agentdojo_live as adapter

UPSTREAM = None
AGENT_BINARY = None
TEMP_PARENT = None


class FixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, behavior="allow"):
        super().__init__(("127.0.0.1", 0), FixtureHandler)
        self.behavior = behavior
        self.payloads = []
        self.on_request = None
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_port}"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.shutdown()
        self.server_close()


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.payloads.append(payload)
        if self.server.on_request:
            self.server.on_request(payload)
        if self.server.behavior == "bad-status" or (
                self.server.behavior == "bad-pre-status" and payload.get("hook_event_name") == "PreToolUse"):
            self.wfile.write(b"neutral-invalid-http-status\r\n\r\n")
            self.close_connection = True
            return
        response = {}
        if self.path.endswith("/chat/completions"):
            response = {"id": "neutral-fixture", "object": "chat.completion", "created": 0,
                        "model": "neutral-fixture", "choices": [{"index": 0, "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "neutral-complete"}}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
            if self.server.behavior == "native-pipeline" and not any(message["role"] == "tool" for message in payload["messages"]):
                response["choices"][0].update(finish_reason="tool_calls", message={"role": "assistant", "content": None,
                    "tool_calls": [{"id": "call_neutral_fixture", "type": "function", "function": {
                        "name": "fixture_record", "arguments": '{"value":"neutral"}'}}]})
        elif self.server.behavior == "malformed":
            response = []
        elif self.server.behavior == "permissive":
            response = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}
        elif payload["hook_event_name"] == "PreToolUse":
            rule = self.server.behavior
            if rule == "deny-resolved":
                rule = "deny" if payload.get("tool_input", {}).get("value") == "nested-resolved" else "allow"
            if rule == "deny-inner":
                rule = "deny" if payload.get("tool_name") == "fixture_value" else "allow"
            if rule in {"deny", "ask"}:
                response = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": rule}}
        raw = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def functions(upstream):
    from pydantic import BaseModel
    Depends = upstream.runtime.Depends

    class Environment(upstream.runtime.TaskEnvironment):
        writes: int = 0
        seen: str = ""

    class Report(BaseModel):
        value: int

    def fixture_value(value: str = "nested-resolved") -> str:
        """Return a neutral fixture value.
        :param value: The value to return.
        """
        return value

    def fixture_record(env: Annotated[Environment, Depends(lambda env: env)], value: str, extra: int = 7) -> str:
        """Record a neutral value in the disposable fixture environment.
        :param value: The value to record.
        :param extra: A validation and defaulting fixture.
        """
        env.writes += 1
        env.seen = value
        return f"{value}:{extra}"

    def fixture_error(message: str) -> str:
        """Raise a neutral fixture error.
        :param message: A neutral error message.
        """
        raise ValueError(message)

    def fixture_structured(value: int) -> Report:
        """Return a neutral structured value.
        :param value: The value in the structured result.
        """
        return Report(value=value)

    return Environment, [upstream.runtime.make_function(function) for function in
                         [fixture_value, fixture_record, fixture_error, fixture_structured]]


class CoreSafety(unittest.TestCase):
    def test_default_cli_is_manifest_without_credentials_or_runtime(self):
        script = Path(__file__).resolve().parents[1] / "agentdojo-live.py"
        result = subprocess.run([sys.executable, "-I", str(script)], capture_output=True, text=True,
                                env={name: os.environ[name] for name in ["PATH", "SYSTEMROOT"] if name in os.environ})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["model_calls"], 0)

    def test_live_cli_requires_explicit_operator_gates(self):
        script = Path(__file__).resolve().parents[1] / "agentdojo-live.py"
        result = subprocess.run([sys.executable, "-I", str(script), "--mode", "live", "--upstream-checkout", ".",
                                 "--agent-binary", sys.executable], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Live requires", result.stderr)

    def test_unpinned_checkout_rejected_before_import(self):
        with self.assertRaisesRegex(adapter.AdapterError, "pinned revision"):
            adapter.verify_checkout(Path(__file__).resolve().parents[2])

    def test_bytecode_only_contamination_rejected_without_source_change(self):
        if UPSTREAM is None:
            self.skipTest("Explicit pinned checkout required for bytecode contamination check")
        checkout = Path(UPSTREAM.runtime.__file__).resolve().parents[2]
        source = checkout / "src/agentdojo/functions_runtime.py"
        source_hash = adapter.digest(source.read_bytes())
        cache = source.parent / "__pycache__"
        self.assertFalse(cache.exists())
        cache.mkdir()
        bytecode = cache / "functions_runtime.cpython-312.pyc"
        try:
            bytecode.write_bytes(b"neutral-bytecode-contamination")
            with self.assertRaisesRegex(adapter.AdapterError, "cache-free"):
                adapter.verify_checkout(checkout)
            self.assertEqual(adapter.digest(source.read_bytes()), source_hash)
        finally:
            bytecode.unlink()
            cache.rmdir()

    def test_non_loopback_agent_and_invalid_token_rejected(self):
        for url, token in [("http://example.com", "neutral"), ("http://127.0.0.1", ""),
                           ("http://127.0.0.1.evil.test", "neutral"), ("http://127.0.0.1/?extra", "neutral")]:
            with self.subTest(url=url), self.assertRaises(adapter.AdapterError):
                adapter.HookClient(url, token)

    def test_unexpected_allow_is_not_an_approval(self):
        with FixtureServer("permissive") as server:
            client = adapter.HookClient(server.url, "neutral")
            with self.assertRaises(adapter.AdapterError):
                client.event("PreToolUse", "fixture_record", {"value": "neutral"})
            self.assertTrue(client.failed)

    def test_oversized_results_do_not_get_silently_truncated(self):
        with FixtureServer() as server:
            client = adapter.HookClient(server.url, "neutral")
            with self.assertRaises(adapter.AdapterError):
                client.event("PostToolUse", "fixture_record", {}, "x" * (adapter.MAX_RESULT + 1))
            self.assertTrue(client.failed)
            self.assertFalse(server.payloads)

    def test_nonfinite_budget_is_rejected(self):
        with self.assertRaises(adapter.AdapterError):
            adapter.BudgetProvider("http://127.0.0.1/v1", "neutral", "neutral", max_calls=1,
                max_total_request_bytes=100, max_output_tokens=1, max_reserved_usd=float("nan"),
                input_usd_per_million=0, output_usd_per_million=0)

    def test_fresh_evidence_reservation_and_atomic_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "evidence.json"
            output = adapter.EvidenceOutput(destination)
            self.assertEqual(json.loads(destination.read_text())["status"], "reserved")
            with self.assertRaises(adapter.AdapterError):
                adapter.EvidenceOutput(destination)
            output.publish({"status": "incomplete", "cases": []})
            self.assertEqual(json.loads(destination.read_text())["status"], "incomplete")
            self.assertFalse(list(Path(directory).glob("*.tmp")))

    def test_invalid_evidence_parent_blocks_cli_before_credential_or_provider(self):
        script = Path(__file__).resolve().parents[1] / "agentdojo-live.py"
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "-I", str(script), "--mode", "live", "--upstream-checkout", ".",
                "--agent-binary", sys.executable, "--plan", "unused-plan.json", "--provider", "openai-compatible",
                "--model", "neutral-fixture", "--base-url", "http://127.0.0.1:9/v1", "--credential-env", "UNSELECTED_EMPTY",
                "--max-calls", "1", "--max-total-request-bytes", "1000", "--max-output-tokens", "1",
                "--max-reserved-usd", "0", "--input-usd-per-million", "0", "--output-usd-per-million", "0",
                "--acknowledge-cost-estimate", "--evidence", str(Path(directory) / "missing/evidence.json")],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("Evidence parent directory", result.stderr)


class PinnedRuntimeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if UPSTREAM is None:
            raise unittest.SkipTest("Use explicit --mode fixture --upstream-checkout to exercise installed pinned classes")
        cls.upstream = UPSTREAM
        cls.Environment, cls.functions = functions(UPSTREAM)

    def runtime(self, server):
        self.client = adapter.HookClient(server.url, "neutral-fixture-token")
        return adapter.runtime_class(self.upstream, self.client)(self.functions)

    def test_schema_docs_dependencies_are_preserved_without_original_mutation(self):
        with FixtureServer() as server:
            runtime = self.runtime(server)
            for original in self.functions:
                guarded = runtime.functions[original.name]
                self.assertIsNot(original, guarded)
                self.assertEqual(original.model_dump(exclude={"run"}), guarded.model_dump(exclude={"run"}))
                self.assertIs(original.parameters, guarded.parameters)
                self.assertIs(original.dependencies, guarded.dependencies)
                self.assertFalse(hasattr(original.run, "_soup_wall_client"))

    def test_nested_actual_arguments_validate_default_and_precede_execution(self):
        with FixtureServer() as server:
            runtime = self.runtime(server)
            env = self.Environment()
            nested = self.upstream.runtime.FunctionCall(function="fixture_value", args={})
            self.assertEqual(runtime.run_function(env, "fixture_record", {"value": nested, "extra": "9"}),
                             ("nested-resolved:9", None))
            self.assertEqual(env.writes, 1)
            pre = [p for p in server.payloads if p["hook_event_name"] == "PreToolUse"]
            self.assertEqual([p["tool_name"] for p in pre], ["fixture_value", "fixture_record"])
            self.assertEqual(pre[-1]["tool_input"], {"value": "nested-resolved", "extra": 9})
            self.assertNotIn("env", pre[-1]["tool_input"])

    def test_deny_on_resolved_outer_arguments_prevents_outer_execution(self):
        with FixtureServer("deny-resolved") as server:
            runtime = self.runtime(server)
            env = self.Environment()
            # The inner call differs, so its value becomes a denied outer parameter.
            nested = self.upstream.runtime.FunctionCall(function="fixture_value", args={"value": "nested-resolved"})
            # Allow the inner result, deny the outer actual boundary only.
            original_behavior = server.behavior
            server.behavior = "allow"
            original_event = self.client.event
            def event(kind, tool=None, arguments=None, result=None):
                server.behavior = original_behavior if tool == "fixture_record" else "allow"
                return original_event(kind, tool, arguments, result)
            self.client.event = event
            result, error = runtime.run_function(env, "fixture_record", {"value": nested})
            self.assertEqual(result, "")
            self.assertIn("FirewallDenied", error)
            self.assertEqual(env.writes, 0)
            self.assertEqual(server.payloads[-2]["tool_input"], {"value": "nested-resolved", "extra": 7})

    def test_nested_denial_propagates_and_outer_never_executes(self):
        with FixtureServer("deny-inner") as server:
            runtime = self.runtime(server)
            env = self.Environment()
            nested = self.upstream.runtime.FunctionCall(function="fixture_value", args={})
            _, error = runtime.run_function(env, "fixture_record", {"value": nested})
            self.assertIn("FirewallDenied", error)
            self.assertEqual(env.writes, 0)
            self.assertFalse(any(p.get("tool_name") == "fixture_record" and p["hook_event_name"] == "PreToolUse"
                                 for p in server.payloads))

    def test_ask_does_not_execute(self):
        with FixtureServer("ask") as server:
            runtime = self.runtime(server)
            env = self.Environment()
            _, error = runtime.run_function(env, "fixture_record", {"value": "neutral"})
            self.assertIn("ApprovalRequired", error)
            self.assertEqual(env.writes, 0)

    def test_errors_keep_upstream_return_and_raise_semantics(self):
        with FixtureServer() as server:
            runtime = self.runtime(server)
            original = self.upstream.runtime.FunctionsRuntime(self.functions)
            self.assertEqual(runtime.run_function(None, "fixture_error", {"message": "neutral-error"}),
                             original.run_function(None, "fixture_error", {"message": "neutral-error"}))
            self.assertEqual(server.payloads[-1]["tool_response"], "ValueError: neutral-error")
            with self.assertRaisesRegex(ValueError, "neutral-error"):
                runtime.run_function(None, "fixture_error", {"message": "neutral-error"}, raise_on_error=True)

    def test_structured_result_uses_exact_upstream_formatter(self):
        with FixtureServer() as server:
            runtime = self.runtime(server)
            result, error = runtime.run_function(None, "fixture_structured", {"value": "3"})
            self.assertIsNone(error)
            self.assertEqual(server.payloads[-1]["tool_response"], self.upstream.execution.tool_result_to_str(result))
            self.assertEqual(server.payloads[-2]["tool_input"], {"value": 3})

    def test_registry_replacements_remain_guarded(self):
        with FixtureServer("deny") as server:
            runtime = self.runtime(server)
            runtime.update_functions({function.name: function for function in self.functions})
            env = self.Environment()
            _, error = runtime.run_function(env, "fixture_record", {"value": "neutral"})
            self.assertIn("FirewallDenied", error)
            self.assertEqual(env.writes, 0)
            runtime.register_function(self.functions[1])
            _, error = runtime.run_function(env, "fixture_record", {"value": "neutral"})
            self.assertIn("FirewallDenied", error)
            self.assertEqual(env.writes, 0)

    def test_malformed_reply_and_persistent_failure_do_not_execute(self):
        with FixtureServer("malformed") as server:
            runtime = self.runtime(server)
            env = self.Environment()
            with self.assertRaises(adapter.AdapterError):
                runtime.run_function(env, "fixture_record", {"value": "neutral"})
            server.behavior = "allow"
            with self.assertRaises(adapter.AdapterError):
                runtime.run_function(env, "fixture_record", {"value": "neutral"})
            self.assertEqual(env.writes, 0)

    def test_transport_failure_does_not_execute(self):
        with FixtureServer() as server:
            runtime = self.runtime(server)
        env = self.Environment()
        with self.assertRaises(adapter.AdapterError):
            runtime.run_function(env, "fixture_record", {"value": "neutral"})
        self.assertEqual(env.writes, 0)

    def test_bad_pre_http_status_is_sticky_despite_later_valid_post_response(self):
        with FixtureServer("bad-pre-status") as server:
            runtime = self.runtime(server)
            env = self.Environment()
            with self.assertRaises(adapter.AdapterError):
                runtime.run_function(env, "fixture_record", {"value": "neutral"})
            self.assertTrue(self.client.failed)
            self.assertEqual(env.writes, 0)
            server.behavior = "allow"
            with self.assertRaises(adapter.AdapterError):
                self.client.event("PostToolUse", "fixture_record", {}, "neutral")
            self.assertEqual(len(server.payloads), 1)

    def test_provider_bad_http_status_is_sanitized_and_attempt_reserved(self):
        with FixtureServer("bad-status") as server:
            provider = adapter.BudgetProvider(server.url + "/v1", "neutral-key", "neutral-fixture", max_calls=1,
                max_total_request_bytes=10000, max_output_tokens=1, max_reserved_usd=0,
                input_usd_per_million=0, output_usd_per_million=0)
            with self.assertRaises(adapter.AdapterError) as raised:
                provider.create(model="neutral-fixture", messages=[])
            self.assertNotIn("neutral-invalid-http-status", str(raised.exception))
            self.assertEqual(provider.calls, 1)
            self.assertGreater(provider.request_bytes, 0)

    def test_budgeted_original_provider_fixture_and_request_limits(self):
        with FixtureServer() as server:
            provider = adapter.BudgetProvider(server.url + "/v1", "neutral-key", "neutral-fixture", max_calls=1,
                max_total_request_bytes=10000, max_output_tokens=16, max_reserved_usd=0,
                input_usd_per_million=0, output_usd_per_million=0)
            from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
            llm = OpenAILLM(provider, "neutral-fixture")
            runtime = self.upstream.runtime.FunctionsRuntime(self.functions)
            messages = [{"role": "user", "content": [{"type": "text", "content": "neutral fixture"}]}]
            result = llm.query("neutral fixture", runtime, self.Environment(), messages)
            self.assertEqual(result[3][-1]["content"][0]["content"], "neutral-complete")
            self.assertEqual(server.payloads[0]["max_tokens"], 16)
            # Call directly to avoid upstream's retry backoff; reservation stops before traffic.
            with self.assertRaises(adapter.AdapterError):
                provider.create(model="neutral-fixture", messages=messages)
            self.assertEqual(len(server.payloads), 1)

    def test_byte_and_reserved_cost_limits_stop_before_provider_traffic(self):
        with FixtureServer() as server:
            for max_bytes, input_rate, max_usd in [(1, 0, 0), (10000, 1, 0)]:
                with self.subTest(max_bytes=max_bytes, input_rate=input_rate):
                    provider = adapter.BudgetProvider(server.url + "/v1", "neutral-key", "neutral-fixture", max_calls=2,
                        max_total_request_bytes=max_bytes, max_output_tokens=1, max_reserved_usd=max_usd,
                        input_usd_per_million=input_rate, output_usd_per_million=0)
                    with self.assertRaises(adapter.AdapterError):
                        provider.create(model="neutral-fixture", messages=[])
            self.assertFalse(server.payloads)

    def test_original_task_suite_invocation_and_evaluators(self):
        from agentdojo.base_tasks import BaseUserTask
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
        from agentdojo.types import text_content_block_from_string
        Environment, definitions = self.Environment, self.functions
        class Task(BaseUserTask):
            PROMPT = "Run a neutral in-memory fixture."
            ID = "neutral_fixture_task"
            def ground_truth(self, env):
                return []
            def utility(self, model_output, pre_environment, post_environment):
                return pre_environment.writes == 0 and post_environment.writes == 1 and model_output == "neutral-complete"
        class Pipeline(BasePipelineElement):
            def query(self, query, runtime, env, messages=(), extra_args=None):
                runtime.run_function(env, "fixture_record", {"value": "neutral"})
                return query, runtime, env, [{"role": "assistant", "tool_calls": [],
                    "content": [text_content_block_from_string("neutral-complete")]}], {}
        suite = self.upstream.suite.TaskSuite("neutral_fixture", Environment, definitions)
        with FixtureServer() as server:
            runtime = adapter.runtime_class(self.upstream, adapter.HookClient(server.url, "neutral-token"))
            # Supply a fresh environment so this neutral suite has no upstream dataset dependency.
            result = suite.run_task_with_pipeline(Pipeline(), Task(), None, {}, runtime_class=runtime, environment=Environment())
            self.assertEqual(result, (True, True))  # Second boolean is the benign sentinel.

    def test_bad_pre_http_status_aborts_original_task_suite_before_evaluators(self):
        from agentdojo.base_tasks import BaseUserTask
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
        from agentdojo.types import text_content_block_from_string
        evaluated = []
        class Task(BaseUserTask):
            PROMPT = "Run a neutral in-memory fixture."
            ID = "neutral_fixture_task"
            def ground_truth(self, env):
                return []
            def utility(self, model_output, pre_environment, post_environment):
                evaluated.append(True)
                return True
        class Pipeline(BasePipelineElement):
            def query(self, query, runtime, env, messages=(), extra_args=None):
                runtime.run_function(env, "fixture_record", {"value": "neutral"})
                return query, runtime, env, [{"role": "assistant", "tool_calls": [],
                    "content": [text_content_block_from_string("neutral-complete")]}], {}
        suite = self.upstream.suite.TaskSuite("neutral_fixture", self.Environment, self.functions)
        env = self.Environment()
        with FixtureServer("bad-pre-status") as server:
            client = adapter.HookClient(server.url, "neutral-token")
            runtime = adapter.runtime_class(self.upstream, client)
            with self.assertRaises(adapter.AdapterError):
                suite.run_task_with_pipeline(Pipeline(), Task(), None, {}, runtime_class=runtime, environment=env)
            self.assertTrue(client.failed)
            self.assertEqual(env.writes, 0)
            self.assertEqual(evaluated, [])
            self.assertEqual(len(server.payloads), 1)


class DisposableDaemonContract(PinnedRuntimeContract):
    def test_real_agent_deny_and_ask_prevent_execution_and_cleanup(self):
        for verdict in ["deny", "ask", "allow"]:
            with self.subTest(verdict=verdict), tempfile.TemporaryDirectory(dir=TEMP_PARENT) as directory:
                policy = Path(directory) / "fixture-policy.yaml"
                policy.write_text(f"default: {verdict}\n", encoding="utf-8")
                daemon = adapter.DisposableAgent(AGENT_BINARY, policy, TEMP_PARENT)
                with daemon:
                    runtime = adapter.runtime_class(self.upstream, daemon.client)(self.functions)
                    env = self.Environment()
                    result, error = runtime.run_function(env, "fixture_record", {"value": "neutral"})
                    self.assertEqual(env.writes, 1 if verdict == "allow" else 0)
                    self.assertEqual(error is None, verdict == "allow")
                    if verdict != "allow":
                        self.assertIn("FirewallDenied" if verdict == "deny" else "ApprovalRequired", error)
                    profile = daemon.directory
                self.assertFalse(profile.exists())
                self.assertIsNotNone(daemon.process.poll())

    def test_shadow_preflight_rejection_cleans_own_process_and_profile(self):
        with tempfile.TemporaryDirectory(dir=TEMP_PARENT) as directory:
            policy = Path(directory) / "fixture-policy.yaml"
            policy.write_text("default: allow\n", encoding="utf-8")
            daemon = adapter.DisposableAgent(AGENT_BINARY, policy, TEMP_PARENT, enforce=False)
            with self.assertRaisesRegex(adapter.AdapterError, "enforcing preflight"):
                with daemon:
                    self.fail("Shadow daemon must not reach runtime execution")
            self.assertFalse(daemon.directory.exists())
            self.assertIsNotNone(daemon.process.poll())

    def test_production_live_orchestration_with_original_pipeline_and_neutral_local_provider(self):
        from agentdojo.base_tasks import BaseUserTask
        Environment, definitions = self.Environment, self.functions
        class Task(BaseUserTask):
            ID = "neutral_fixture_task"
            PROMPT = "Run a neutral in-memory fixture."
            def ground_truth(self, env):
                return []
            def utility(self, model_output, pre_environment, post_environment):
                return pre_environment.writes == 0 and post_environment.writes == 1 and model_output == "neutral-complete"
        class Suite(self.upstream.suite.TaskSuite):
            def load_and_inject_default_environment(self, injections):
                return Environment()
            def get_user_task_by_id(self, _task_id):
                return Task()
        suite = Suite("neutral_fixture", Environment, definitions)
        source = Path(__file__).resolve().parents[1] / "agentdojo-live.py"
        spec = importlib.util.spec_from_file_location("soup_wall_live_cli", source)
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        repo = source.parents[1]
        with FixtureServer("native-pipeline") as server, tempfile.TemporaryDirectory(dir=TEMP_PARENT) as directory:
            neutral_repo = Path(directory) / "repo"
            source_policy = neutral_repo / "crates/agent/policies/agent-default.yaml"
            source_policy.parent.mkdir(parents=True)
            initial_policy = (repo / "crates/agent/policies/agent-default.yaml").read_bytes()
            source_policy.write_bytes(initial_policy)
            plan = Path(directory) / "neutral-plan.json"
            plan.write_text(json.dumps({"schema_version": 1, "upstream_revision": adapter.REVISION,
                "benchmark_version": "v1", "suite": "neutral_fixture", "cases": [{
                    "user_task_id": "neutral_fixture_task", "injection_task_id": None, "injections": {}}]}))
            initial_plan = plan.read_bytes()
            def mutate_inputs(_payload):
                plan.write_text("neutral-changed-plan", encoding="utf-8")
                source_policy.write_text("default: deny\n", encoding="utf-8")
            server.on_request = mutate_inputs
            args = SimpleNamespace(plan=plan, credential_env="SOUP_WALL_NEUTRAL_FIXTURE_KEY",
                upstream_checkout=Path(UPSTREAM.runtime.__file__).resolve().parents[2],
                base_url=server.url + "/v1", model="neutral-fixture", provider="openai-compatible",
                max_calls=4, max_total_request_bytes=200000, max_output_tokens=16, max_reserved_usd=0,
                input_usd_per_million=0, output_usd_per_million=0, agent_binary=AGENT_BINARY)
            with patch.dict(os.environ, {"SOUP_WALL_NEUTRAL_FIXTURE_KEY": "neutral-key"}), patch(
                    "agentdojo.task_suite.load_suites.get_suite", return_value=suite):
                result = cli.run_live(args, neutral_repo)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["plan_sha256"], adapter.digest(initial_plan))
            self.assertEqual(result["policy_sha256"], adapter.digest(initial_policy))
            self.assertNotEqual(result["plan_sha256"], adapter.file_hash(plan))
            self.assertNotEqual(result["policy_sha256"], adapter.file_hash(source_policy))
            self.assertFalse(list((neutral_repo / "target").glob("agentdojo-policy-*")))
            self.assertIn("max_calls", result["budget"])
            self.assertIn("formatter", result["settings"])
            self.assertIn("openai", result["dependency_versions"])
            self.assertEqual(result["provider_attempts"], 4)
            self.assertEqual([row["utility"] for row in result["cases"]], [True, True])
            self.assertEqual([row["pre_calls"] for row in result["cases"]], [0, 1])
            self.assertEqual(result["cases"][1]["post_results_observed"], 1)
            self.assertEqual(result["cases"][1]["deny"], 0)
            self.assertEqual(len(server.payloads), 4)
        from agentdojo.agent_pipeline.llms.openai_llm import chat_completion_request
        from tenacity import wait_none
        with FixtureServer("native-pipeline") as server, tempfile.TemporaryDirectory(dir=TEMP_PARENT) as directory:
            plan = Path(directory) / "neutral-plan.json"
            plan.write_text(json.dumps({"schema_version": 1, "upstream_revision": adapter.REVISION,
                "benchmark_version": "v1", "suite": "neutral_fixture", "cases": [{
                    "user_task_id": "neutral_fixture_task", "injection_task_id": None, "injections": {}}]}))
            args.plan, args.base_url, args.max_calls = plan, server.url + "/v1", 1
            with patch.dict(os.environ, {"SOUP_WALL_NEUTRAL_FIXTURE_KEY": "neutral-key"}), patch(
                    "agentdojo.task_suite.load_suites.get_suite", return_value=suite), patch.object(
                    chat_completion_request.retry, "wait", wait_none()):
                result = cli.run_live(args, repo)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["provider_attempts"], 1)
            self.assertEqual(result["cases"], [])
            self.assertFalse(result["incomplete_case"]["evaluators_reported"])
            self.assertEqual(len(server.payloads), 1)
        with FixtureServer("bad-status") as server, tempfile.TemporaryDirectory(dir=TEMP_PARENT) as directory:
            plan = Path(directory) / "neutral-plan.json"
            plan.write_text(json.dumps({"schema_version": 1, "upstream_revision": adapter.REVISION,
                "benchmark_version": "v1", "suite": "neutral_fixture", "cases": [{
                    "user_task_id": "neutral_fixture_task", "injection_task_id": None, "injections": {}}]}))
            args.plan, args.base_url, args.max_calls = plan, server.url + "/v1", 3
            with patch.dict(os.environ, {"SOUP_WALL_NEUTRAL_FIXTURE_KEY": "neutral-key"}), patch(
                    "agentdojo.task_suite.load_suites.get_suite", return_value=suite), patch.object(
                    chat_completion_request.retry, "wait", wait_none()):
                result = cli.run_live(args, repo)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["provider_attempts"], 3)
            self.assertEqual(result["cases"], [])
            self.assertFalse(result["incomplete_case"]["evaluators_reported"])
            self.assertEqual(len(server.payloads), 3)


def run_fixture_checks(checkout, binary, temporary_parent):
    global UPSTREAM, AGENT_BINARY, TEMP_PARENT
    UPSTREAM = adapter.load_upstream(checkout)
    AGENT_BINARY, TEMP_PARENT = binary.resolve(), temporary_parent.resolve()
    TEMP_PARENT.mkdir(parents=True, exist_ok=True)
    suite = unittest.TestSuite()
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(CoreSafety))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(PinnedRuntimeContract))
    # Add only daemon-specific tests, without repeating inherited runtime tests.
    for name in ["test_real_agent_deny_and_ask_prevent_execution_and_cleanup", "test_shadow_preflight_rejection_cleans_own_process_and_profile",
                 "test_production_live_orchestration_with_original_pipeline_and_neutral_local_provider"]:
        suite.addTest(DisposableDaemonContract(name))
    check_names = [test.id().removeprefix("test_agentdojo_live.") for group in suite
                   for test in (group if isinstance(group, unittest.TestSuite) else [group])]
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise adapter.AdapterError("Pinned runtime fixture contract checks failed")
    repo = Path(__file__).resolve().parents[2]
    sources = ["scripts/agentdojo-live.py", "scripts/benchmarks/agentdojo_live.py",
               "scripts/benchmarks/test_agentdojo_live.py", "scripts/benchmarks/agentdojo-live.requirements.txt",
               "crates/agent/policies/agent-default.yaml"]
    dependencies = ["openai", "pydantic", "docstring-parser", "typing-extensions", "PyYAML", "tenacity",
                    "google-genai", "rich", "deepdiff", "anthropic", "cohere", "requests"]
    return {"schema_version": 1, "mode": "fixture", "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "source_base_revision": "b7c8866", "upstream": UPSTREAM.verified,
            "agent_binary_sha256": adapter.file_hash(AGENT_BINARY),
            "source_file_sha256": {name: adapter.file_hash(repo / name) for name in sources},
            "python_version": ".".join(str(part) for part in sys.version_info[:3]),
            "dependency_versions": {name: importlib.metadata.version(name) for name in dependencies},
            "checks": check_names,
            "tests_passed": result.testsRun, "model_calls": 0, "paid_provider_calls": 0,
            "local_provider_fixture_only": True, "original_runtime_classes_exercised": True,
            "isolated_agent_profiles_cleaned": True,
            "limitations": ["Neutral contract fixtures and disposable custom policies",
                            "No independent live model benchmark or native semantic coverage claim"]}


if __name__ == "__main__":
    unittest.main()
