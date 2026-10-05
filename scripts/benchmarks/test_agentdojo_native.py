# SPDX-License-Identifier: Apache-2.0
"""Native admission invariants; pinned runtime and disposable daemon checks are explicit."""
from datetime import datetime, timezone
import http.server
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request

import agentdojo_live as adapter
import agentdojo_native as native

UPSTREAM = None
AGENT_BINARY = None
TEMP_PARENT = None
EXPECTED_BINARY = None
LOCAL_PROVIDER_REQUESTS = 0


def registry(functions=()):
    tools = [{"name": function.name, "schema_sha256": adapter.digest(native.canonical(function.parameters.model_json_schema())),
              "action_class": "side_effecting" if function.name == "fixture_record" else "read_only",
              "result_provenance": "untrusted", "egress": []} for function in functions]
    if not tools:
        tools = [{"name": "fixture", "schema_sha256": "1" * 64, "action_class": "read_only",
                  "result_provenance": "untrusted", "egress": []}]
    return native.Registry(adapter.encoded({"contract_version": native.CONTRACT,
                                          "registry_id": "original-disposable-native-fixture", "tools": tools}))


class NativeServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, behavior="allow"):
        super().__init__(("127.0.0.1", 0), NativeHandler)
        self.behavior, self.payloads = behavior, []
        self.counter = 0
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.shutdown()
        self.server_close()

    def client(self, selected_registry=None):
        return native.NativeClient(f"http://127.0.0.1:{self.server_port}", "synthetic-native-fixture-key",
                                   selected_registry or registry())


class NativeHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.payloads.append(payload)
        event = payload["event"]
        verdict = "deny" if self.server.behavior == "deny-" + event else "allow"
        if self.server.behavior == "deny-context-poison" and event == "context" and "POISON" in payload["content"]:
            verdict = "deny"
        reply = {key: payload[key] for key in ("contract_version", "registry_sha256", "session_id", "event")}
        reply.update(verdict=verdict, enforced=True, release=verdict == "allow", call_id=None,
                     binding_sha256=None, content_sha256=None, reason_codes=[])
        if event == "call" and verdict == "allow":
            self.server.counter += 1
            reply.update(call_id=f"synthetic-call-{self.server.counter:04}", binding_sha256="2" * 64)
        elif event in {"result", "context"}:
            reply.update(call_id=payload["call_id"], binding_sha256="2" * 64,
                         content_sha256=adapter.digest(payload["content"].encode("utf-8")))
        if self.server.behavior == "wrong-binding" and event == "result":
            reply["binding_sha256"] = "3" * 64
        if self.server.behavior == "wrong-bytes" and event == "context":
            reply["content_sha256"] = "4" * 64
        if self.server.behavior == "implicit":
            reply = {}
        if self.server.behavior == "shadow":
            reply["enforced"] = False
        raw = adapter.encoded(reply)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class NativeSafety(unittest.TestCase):
    def test_lifecycle_failure_cannot_skip_cleanup_and_failed_teardown_retains_profile(self):
        class Child:
            def __init__(self, fail):
                self.fail, self.live, self.waited = fail, True, False

            def poll(self):
                return None if self.live else 0

            def kill(self):
                if self.fail:
                    raise RuntimeError("synthetic owned-child teardown failure")
                self.live = False

            def wait(self, timeout):
                self.waited = True
                return 0

        def failed_lifecycle(event):
            raise RuntimeError("synthetic notification failure from another module")

        for fail in (False, True):
            with self.subTest(teardown_fails=fail), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory).resolve()
                profile = parent / "agentdojo-live-owned-fixture"
                profile.mkdir()
                owner = adapter.DisposableAgent.__new__(adapter.DisposableAgent)
                owner.process, owner.directory, owner.temporary_parent = Child(fail), profile, parent
                owner.client = SimpleNamespace(event=failed_lifecycle)
                if fail:
                    with self.assertRaisesRegex(RuntimeError, "teardown failure"):
                        owner.__exit__()
                    self.assertTrue(profile.exists())
                    self.assertTrue(owner.process.live)
                    self.assertFalse(owner.process.waited)
                else:
                    owner.__exit__()
                    self.assertFalse(profile.exists())
                    self.assertFalse(owner.process.live)
                    self.assertTrue(owner.process.waited)

    def test_redirected_profile_parent_is_refused_before_private_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "target"
            with patch.object(Path, "is_symlink", lambda path: path == parent):
                with self.assertRaises(adapter.AdapterError):
                    adapter.safe_temporary_parent(parent)
            self.assertFalse(parent.exists())

    def test_duplicate_fields_and_semantic_changes_are_rejected(self):
        with self.assertRaises(adapter.AdapterError):
            native.Registry(b'{"contract_version":"sw-native/1","contract_version":"other"}')
        value = json.loads(registry().raw)
        value["tools"][0]["trusted"] = True
        with self.assertRaises(adapter.AdapterError):
            native.Registry(adapter.encoded(value))

    def test_request_contains_no_authoritative_action_or_provenance(self):
        with NativeServer() as server:
            client = server.client()
            client.request("call", tool="fixture", args={"value": "neutral"}, schema_sha256="1" * 64)
            self.assertEqual(set(server.payloads[0]), {"contract_version", "registry_sha256", "session_id", "event",
                                                      "tool", "args", "schema_sha256"})

    def test_exact_binding_and_content_admissions_are_required(self):
        with NativeServer() as server:
            client = server.client()
            row = client.request("call", tool="fixture", args={}, schema_sha256="1" * 64)
            client.request("result", call_id=row["call_id"], tool="fixture", args={}, result_kind="value",
                           delivery="model", content="neutral")
            client.request("context", call_id=row["call_id"], tool="fixture", args={}, content="exact final envelope")
            self.assertEqual([entry["event"] for entry in client.receipts], ["call", "result", "context"])

    def test_changed_binding_halts_without_continuing(self):
        with NativeServer("wrong-binding") as server:
            client = server.client()
            row = client.request("call", tool="fixture", args={}, schema_sha256="1" * 64)
            with self.assertRaises(adapter.AdapterError):
                client.request("result", call_id=row["call_id"], tool="fixture", args={}, result_kind="value",
                               delivery="model", content="neutral")
            self.assertTrue(client.failed)
            with self.assertRaises(adapter.AdapterError):
                client.event("SessionStart")
            self.assertEqual(len(server.payloads), 2)

    def test_changed_final_bytes_are_not_released(self):
        with NativeServer("wrong-bytes") as server:
            client = server.client()
            row = client.request("call", tool="fixture", args={}, schema_sha256="1" * 64)
            with self.assertRaises(adapter.AdapterError):
                client.request("context", call_id=row["call_id"], tool="fixture", args={}, content="neutral")
            self.assertTrue(client.failed)

    def test_implicit_or_shadow_response_is_never_admission(self):
        for behavior in ("implicit", "shadow"):
            with self.subTest(behavior=behavior), NativeServer(behavior) as server:
                client = server.client()
                with self.assertRaises(adapter.AdapterError):
                    client.event("SessionStart")
                self.assertTrue(client.failed)

    def test_oversize_content_prevents_transport(self):
        with NativeServer() as server:
            client = server.client()
            with self.assertRaises(adapter.AdapterError):
                client.request("result", call_id="unknown", tool="fixture", args={}, result_kind="value",
                               delivery="model", content="x" * (adapter.MAX_RESULT + 1))
            self.assertEqual(server.payloads, [])

    def test_policy_withheld_is_separate_from_infrastructure_failure(self):
        with NativeServer("deny-call") as server:
            client = server.client()
            with self.assertRaises(native.NativeWithheld):
                client.request("call", tool="fixture", args={}, schema_sha256="1" * 64)
            self.assertTrue(client.withheld)
            self.assertFalse(client.failed)


@unittest.skipUnless(UPSTREAM is not None, "requires explicitly selected pinned AgentDojo runtime")
class NativeRuntimeTests(unittest.TestCase):
    def setUp(self):
        from test_agentdojo_live import functions
        self.Environment, self.functions = functions(UPSTREAM)
        self.registry = registry(self.functions)

    def execute(self, client, function="fixture_record", args=None, formatter=None, env=None):
        runtime = native.runtime_class(UPSTREAM, client)(self.functions)
        executor = native.executor_class(UPSTREAM, client)(formatter or UPSTREAM.execution.tool_result_to_str)
        call = UPSTREAM.runtime.FunctionCall(function=function, args=args or {"value": "neutral"}, id="neutral-model-call")
        messages = [{"role": "assistant", "content": None, "tool_calls": [call]}]
        return executor.query("neutral fixture", runtime, env if env is not None else self.Environment(), messages)

    def test_original_schema_dependencies_defaults_and_final_bytes_preserved(self):
        with NativeServer() as server:
            env = self.Environment()
            output = self.execute(server.client(self.registry), env=env)
            self.assertEqual(env.writes, 1)
            self.assertEqual(env.seen, "neutral")
            self.assertEqual(output[3][-1]["content"][0]["content"], "neutral:7")
            call, result, context = server.payloads
            self.assertEqual(call["args"], {"value": "neutral", "extra": 7})
            self.assertEqual(result["content"], "neutral:7")
            self.assertEqual(json.loads(context["content"])["content"], output[3][-1]["content"])

    def test_precall_denial_prevents_original_native_side_effect(self):
        with NativeServer("deny-call") as server:
            env, client = self.Environment(), server.client(self.registry)
            with self.assertRaises(adapter.AdapterError):
                self.execute(client, env=env)
            self.assertEqual(env.writes, 0)
            self.assertTrue(client.withheld)
            self.assertEqual([item["event"] for item in server.payloads], ["call"])

    def test_result_denial_prevents_nested_value_reaching_parent(self):
        with NativeServer("deny-result") as server:
            env, client = self.Environment(), server.client(self.registry)
            nested = UPSTREAM.runtime.FunctionCall(function="fixture_value", args={"value": "nested"})
            with self.assertRaises(adapter.AdapterError):
                self.execute(client, args={"value": nested}, env=env)
            self.assertEqual(env.writes, 0)
            self.assertTrue(client.withheld)

    def test_second_formatter_poison_is_gated_before_final_messages_return(self):
        with NativeServer("deny-context-poison") as server:
            env, client = self.Environment(), server.client(self.registry)
            with self.assertRaises(native.NativeWithheld):
                self.execute(client, formatter=lambda _: "POISON", env=env)
            self.assertEqual(env.writes, 1)  # withholding does not undo a completed effect
            self.assertEqual(server.payloads[1]["content"], "neutral:7")
            self.assertIn("POISON", server.payloads[2]["content"])

    def test_original_native_error_is_preserved_and_inspected(self):
        with NativeServer() as server:
            output = self.execute(server.client(self.registry), function="fixture_error", args={"message": "neutral-error"})
            self.assertEqual(output[3][-1]["error"], "ValueError: neutral-error")
            self.assertEqual(server.payloads[1]["result_kind"], "error")
            self.assertEqual(json.loads(server.payloads[2]["content"])["error"], "ValueError: neutral-error")

    def test_validation_failure_aborts_without_a_fake_prevention(self):
        with NativeServer() as server:
            env, client = self.Environment(), server.client(self.registry)
            with self.assertRaises(adapter.AdapterError):
                self.execute(client, args={"extra": "bad"}, env=env)
            self.assertTrue(client.failed)
            with self.assertRaises(adapter.AdapterError):
                self.execute(client, env=env)
            self.assertEqual(env.writes, 0)
            self.assertEqual(server.payloads, [])

    def test_formatter_failure_is_sticky_and_sanitized_before_retry(self):
        def broken(_):
            raise ValueError("private fixture payload must not escape")
        with NativeServer() as server:
            env, client = self.Environment(), server.client(self.registry)
            with self.assertRaises(adapter.AdapterError) as failure:
                self.execute(client, formatter=broken, env=env)
            self.assertNotIn("private fixture payload", str(failure.exception))
            self.assertTrue(client.failed)
            with self.assertRaises(adapter.AdapterError):
                self.execute(client, env=env)
            self.assertEqual(env.writes, 1)

    def test_uninstalled_schema_fails_before_any_transport(self):
        with NativeServer() as server:
            client = server.client(registry())
            with self.assertRaises(adapter.AdapterError):
                native.runtime_class(UPSTREAM, client)(self.functions)
            self.assertTrue(client.failed)
            self.assertEqual(server.payloads, [])

    def test_pipeline_wraps_only_original_executor_and_requires_one(self):
        with NativeServer() as server:
            client = server.client(self.registry)
            original = UPSTREAM.execution.ToolsExecutor()
            pipeline = SimpleNamespace(elements=[SimpleNamespace(elements=[original])])
            native.guard_pipeline(pipeline, UPSTREAM, client)
            self.assertIsNot(type(pipeline.elements[0].elements[0]), type(original))
            self.assertIs(type(original), UPSTREAM.execution.ToolsExecutor)
            with self.assertRaises(adapter.AdapterError):
                native.guard_pipeline(SimpleNamespace(elements=[]), UPSTREAM, client)

    def test_original_pipeline_factory_preserves_shared_inert_llm_leaf(self):
        from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement

        class InertLLM(BasePipelineElement):
            name = "native-no-network-fixture"

            def query(self, *args, **kwargs):
                raise AssertionError("Pipeline construction must not call a model")

        with NativeServer() as server:
            client, llm = server.client(self.registry), InertLLM()
            pipeline = AgentPipeline.from_config(PipelineConfig(
                llm=llm, model_id=None, defense=None,
                system_message="neutral fixture", system_message_name=None))
            self.assertIs(pipeline.elements[2], pipeline.elements[3].elements[1])
            original = pipeline.elements[3].elements[0]
            native.guard_pipeline(pipeline, UPSTREAM, client)
            self.assertIs(pipeline.elements[2], llm)
            self.assertIs(pipeline.elements[3].elements[1], llm)
            self.assertIsNot(type(pipeline.elements[3].elements[0]), type(original))
            self.assertIs(type(original), UPSTREAM.execution.ToolsExecutor)
            self.assertFalse(client.failed)
            self.assertEqual(server.payloads, [])


@unittest.skipUnless(UPSTREAM is not None and AGENT_BINARY is not None,
                     "requires explicitly selected disposable native Agent")
class NativeDaemonTests(unittest.TestCase):
    def setUp(self):
        if adapter.file_hash(AGENT_BINARY) != EXPECTED_BINARY:
            raise adapter.AdapterError("Native fixture executable changed")
        NativeRuntimeTests.setUp(self)
    execute = NativeRuntimeTests.execute
    def test_real_agent_declared_action_blocks_before_body(self):
        with tempfile.TemporaryDirectory(prefix="native-policy-", dir=TEMP_PARENT) as directory:
            policy = Path(directory) / "policy.yaml"
            policy.write_text("agent_policies:\n  - name: deny-fixture-write\n    when: {action_class: side_effecting}\n"
                              "    action: deny\ndefault: allow\n", encoding="utf-8")
            env = self.Environment()
            with adapter.DisposableAgent(AGENT_BINARY, policy, TEMP_PARENT, native_registry=self.registry) as daemon:
                with self.assertRaises(adapter.AdapterError):
                    self.execute(daemon.client, env=env)
                self.assertEqual(env.writes, 0)
                self.assertTrue(daemon.client.withheld)

    def test_real_agent_result_gate_and_clean_original_context(self):
        with tempfile.TemporaryDirectory(prefix="native-policy-", dir=TEMP_PARENT) as directory:
            policy = Path(directory) / "policy.yaml"
            policy.write_text("agent_policies:\n  - name: deny-fixture-result\n"
                              "    when: {detector: secret, facet: tool_result}\n    action: deny\ndefault: allow\n",
                              encoding="utf-8")
            with adapter.DisposableAgent(AGENT_BINARY, policy, TEMP_PARENT, native_registry=self.registry) as daemon:
                output = self.execute(daemon.client, function="fixture_value", args={"value": "neutral"})
                self.assertEqual(output[3][-1]["content"][0]["content"], "neutral")
                self.assertEqual([row["event"] for row in daemon.client.receipts],
                                 ["session_start", "call", "result", "context"])
                with self.assertRaises(adapter.AdapterError):
                    self.execute(daemon.client, function="fixture_value",
                                 args={"value": "-----BEGIN " + "PRIVATE KEY-----"})
                self.assertTrue(daemon.client.withheld)
                self.assertFalse(daemon.client.receipts[-1]["release"])

    def test_real_native_and_hook_keys_are_separate(self):
        with tempfile.TemporaryDirectory(prefix="native-policy-", dir=TEMP_PARENT) as directory:
            policy = Path(directory) / "policy.yaml"
            policy.write_text("agent_policies: []\ndefault: allow\n", encoding="utf-8")
            with adapter.DisposableAgent(AGENT_BINARY, policy, TEMP_PARENT, native_registry=self.registry) as daemon:
                hook_key = (daemon.directory / ".agentfw" / "token").read_text().strip()
                self.assertTrue(hook_key != daemon.client.token)
                request = Request(daemon.client.url + "/native/v1",
                                  adapter.encoded({"contract_version": native.CONTRACT,
                                                   "registry_sha256": self.registry.sha256,
                                                   "session_id": "unauthorized-fixture", "event": "session_start"}),
                                  {"Authorization": "Bearer " + hook_key, "Content-Type": "application/json"})
                with self.assertRaises(HTTPError) as rejected:
                    adapter.opener().open(request, timeout=2)
                self.assertEqual(rejected.exception.code, 401)
                adapter.HookClient(daemon.client.url, hook_key).event("SessionStart")

    def test_real_nested_parent_delivery_does_not_exhaust_pending_capacity(self):
        with tempfile.TemporaryDirectory(prefix="native-policy-", dir=TEMP_PARENT) as directory:
            policy = Path(directory) / "policy.yaml"
            policy.write_text("agent_policies: []\ndefault: allow\n", encoding="utf-8")
            with adapter.DisposableAgent(AGENT_BINARY, policy, TEMP_PARENT, native_registry=self.registry) as daemon:
                for _ in range(2):
                    value = "neutral"
                    for _ in range(35):
                        value = UPSTREAM.runtime.FunctionCall(function="fixture_value", args={"value": value})
                    output = self.execute(daemon.client, args={"value": value})
                    self.assertEqual(output[3][-1]["content"][0]["content"], "neutral:7")
                self.assertEqual(len(daemon.client._bindings), 0)
                self.assertEqual(sum(item["event"] == "call" for item in daemon.client.receipts), 72)
                self.assertFalse(daemon.client.failed)

    def test_native_live_orchestration_freezes_inputs_and_suppresses_withheld_evaluators(self):
        from agentdojo.base_tasks import BaseUserTask
        from test_agentdojo_live import FixtureServer

        Environment, definitions = self.Environment, self.functions

        class Task(BaseUserTask):
            ID = "neutral_fixture_task"
            PROMPT = "Run a neutral in-memory fixture."

            def ground_truth(self, env):
                return []

            def utility(self, model_output, pre_environment, post_environment):
                return pre_environment.writes == 0 and post_environment.writes == 1 and model_output == "neutral-complete"

        class Suite(UPSTREAM.suite.TaskSuite):
            def load_and_inject_default_environment(self, injections):
                return Environment()

            def get_user_task_by_id(self, task_id):
                return Task()

        suite = Suite("neutral_fixture", Environment, definitions)
        source = Path(__file__).resolve().parents[1] / "agentdojo-live.py"
        spec = importlib.util.spec_from_file_location("soup_wall_native_live_cli_fixture", source)
        cli = importlib.util.module_from_spec(spec)
        exec(compile(source.read_bytes(), str(source), "exec", dont_inherit=True), cli.__dict__)
        with FixtureServer("native-pipeline") as server, tempfile.TemporaryDirectory(dir=TEMP_PARENT) as directory:
            root = Path(directory)
            policy = root / "crates/agent/policies/agent-default.yaml"
            policy.parent.mkdir(parents=True)
            policy.write_bytes(b"agent_policies: []\ndefault: allow\n")
            registry_path, plan_path = root / "registry.json", root / "plan.json"
            registry_path.write_bytes(self.registry.raw)
            plan_path.write_bytes(adapter.encoded({
                "schema_version": 1, "upstream_revision": adapter.REVISION,
                "benchmark_version": "v1", "suite": "neutral_fixture", "cases": [{
                    "user_task_id": Task.ID, "injection_task_id": None, "injections": {}}]}))
            initial_plan, initial_policy = plan_path.read_bytes(), policy.read_bytes()

            def observe_provider_request(payload):
                global LOCAL_PROVIDER_REQUESTS
                LOCAL_PROVIDER_REQUESTS += 1

            def mutate_inputs(payload):
                observe_provider_request(payload)
                registry_path.write_bytes(b"invalid changed registry")
                plan_path.write_bytes(b"invalid changed plan")
                policy.write_bytes(b"default: deny\n")

            server.on_request = mutate_inputs
            args = SimpleNamespace(plan=plan_path, native_registry=registry_path,
                credential_env="SOUP_WALL_NATIVE_NEUTRAL_FIXTURE_KEY",
                upstream_checkout=Path(UPSTREAM.runtime.__file__).resolve().parents[2],
                base_url=server.url + "/v1", model="neutral-fixture", provider="openai-compatible",
                max_calls=4, max_total_request_bytes=200000, max_output_tokens=16, max_reserved_usd=0,
                input_usd_per_million=0, output_usd_per_million=0, agent_binary=AGENT_BINARY)
            with patch.dict(os.environ, {args.credential_env: "neutral-key"}), patch(
                    "agentdojo.task_suite.load_suites.get_suite", return_value=suite):
                report = cli.run_live(args, root)
            self.assertEqual(report["status"], "completed")
            self.assertEqual(report["mode"], "live-native")
            self.assertEqual(report["native_contract"], native.CONTRACT)
            self.assertEqual(report["native_semantics_registry_sha256"], self.registry.sha256)
            self.assertEqual(report["plan_sha256"], adapter.digest(initial_plan))
            self.assertEqual(report["policy_sha256"], adapter.digest(initial_policy))
            self.assertEqual([row["utility"] for row in report["cases"]], [True, True])
            self.assertEqual(report["cases"][1]["pre_calls"], 1)
            self.assertEqual(report["cases"][1]["post_results_observed"], 1)
            self.assertEqual(report["cases"][1]["contexts_admitted"], 1)
            self.assertEqual(report["provider_attempts"], 4)
            self.assertEqual(len(server.payloads), 4)
            self.assertFalse(list((root / "target").glob("agentdojo-*")))

            server.on_request = observe_provider_request
            server.payloads.clear()
            registry_path.write_bytes(self.registry.raw)
            plan_path.write_bytes(initial_plan)
            policy.write_bytes(b"agent_policies:\n  - name: deny-fixture-write\n"
                               b"    when: {action_class: side_effecting}\n    action: deny\ndefault: allow\n")
            with patch.dict(os.environ, {args.credential_env: "neutral-key"}), patch(
                    "agentdojo.task_suite.load_suites.get_suite", return_value=suite):
                withheld = cli.run_live(args, root)
            self.assertEqual(withheld["status"], "incomplete")
            self.assertEqual(len(withheld["cases"]), 1)
            self.assertFalse(withheld["incomplete_case"]["evaluators_reported"])
            self.assertTrue(withheld["incomplete_case"]["native_policy_withheld"])
            self.assertFalse(withheld["incomplete_case"]["inspection_failed"])
            self.assertFalse(list((root / "target").glob("agentdojo-*")))


def run_fixture_checks(checkout, binary, temporary_parent, source_snapshots=None):
    global UPSTREAM, AGENT_BINARY, TEMP_PARENT, EXPECTED_BINARY, LOCAL_PROVIDER_REQUESTS
    LOCAL_PROVIDER_REQUESTS = 0
    required = {"cli", "agentdojo_live", "agentdojo_native", "test_agentdojo_live", "test_agentdojo_native"}
    if (not isinstance(source_snapshots, dict) or set(source_snapshots) != required
            or not all(native.is_hash(value) for value in source_snapshots.values())):
        raise adapter.AdapterError("Native fixture requires compiled source snapshots from its explicit CLI")
    snapshots = dict(source_snapshots)
    EXPECTED_BINARY = adapter.file_hash(binary)
    UPSTREAM = adapter.load_upstream(checkout)
    AGENT_BINARY, TEMP_PARENT = binary.resolve(), temporary_parent.resolve()
    TEMP_PARENT.mkdir(exist_ok=True)
    # unittest skip decorators are evaluated before explicit dependencies are set.
    NativeRuntimeTests.__unittest_skip__ = False
    NativeDaemonTests.__unittest_skip__ = False
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                               for case in (NativeSafety, NativeRuntimeTests, NativeDaemonTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    binary_unchanged = adapter.file_hash(AGENT_BINARY) == EXPECTED_BINARY
    return {"schema_version": 1, "mode": "native-fixture", "contract": native.CONTRACT,
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": "passed" if result.wasSuccessful() and binary_unchanged else "incomplete", "tests_run": result.testsRun,
            "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
            "upstream": UPSTREAM.verified, "agent_binary_sha256": EXPECTED_BINARY,
            "agent_binary_unchanged": binary_unchanged, "compiled_source_sha256": snapshots,
            "model_requests_sent": 0, "paid_provider_calls": 0,
            "local_provider_fixture_requests": LOCAL_PROVIDER_REQUESTS,
            "local_provider_fixture_only": True, "field_gate_complete": False,
            "limits": ["Original pinned runtime, harmless fixture functions, custom policies and scripted numeric-loopback provider",
                       "No real provider/model, held-out effectiveness, managed deployment or shadow-soak evidence"]}
