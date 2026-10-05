# SPDX-License-Identifier: Apache-2.0
"""Opt-in native admission; semantics come only from an installed operator registry."""
from __future__ import annotations

import copy
from http.client import HTTPException
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request

import agentdojo_live as adapter

CONTRACT = "sw-native/1"
MAX_REGISTRY = 262_144


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result

    def bad_constant(_):
        raise ValueError("Non-finite JSON value")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)


def is_hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


class NativeWithheld(adapter.AdapterError):
    """Policy withheld an invocation; its evaluators must not become a prevention score."""


class Registry:
    def __init__(self, raw: bytes):
        if not raw or len(raw) > MAX_REGISTRY:
            raise adapter.AdapterError("Native registry exceeds the supported bound")
        try:
            value = strict_json(raw)
            if (set(value) != {"contract_version", "registry_id", "tools"}
                    or value["contract_version"] != CONTRACT or not isinstance(value["registry_id"], str)
                    or not value["registry_id"] or not isinstance(value["tools"], list)
                    or not 1 <= len(value["tools"]) <= 256):
                raise ValueError("Invalid registry")
            tools = {}
            for tool in value["tools"]:
                if (set(tool) != {"name", "schema_sha256", "action_class", "result_provenance", "egress"}
                        or not isinstance(tool["name"], str) or not tool["name"] or tool["name"] in tools
                        or not is_hash(tool["schema_sha256"])
                        or tool["action_class"] not in {"read_only", "side_effecting", "network", "privilege_changing", "destructive"}
                        or tool["result_provenance"] not in {"untrusted", "local_system", "local_project"}
                        or not isinstance(tool["egress"], list)):
                    raise ValueError("Invalid tool declaration")
                for selector in tool["egress"]:
                    if (set(selector) != {"pointer", "kind", "optional"}
                            or not isinstance(selector["pointer"], str) or not selector["pointer"].startswith("/")
                            or selector["kind"] not in {"url_host", "email_domain"}
                            or type(selector["optional"]) is not bool):
                        raise ValueError("Invalid destination selector")
                tools[tool["name"]] = tool
        except (ValueError, TypeError, KeyError):
            raise adapter.AdapterError("Invalid explicit native registry") from None
        self.raw = bytes(raw)
        self.sha256 = adapter.digest(self.raw)
        self._tools = copy.deepcopy(tools)

    def schema(self, function):
        name = function.name
        schema = adapter.digest(canonical(function.parameters.model_json_schema()))
        if name not in self._tools or self._tools[name]["schema_sha256"] != schema:
            raise adapter.AdapterError("Native function is absent from the installed schema registry")
        return schema

    def client(self, url, token):
        # Keep registry, transport and exception identities in this frozen module
        # snapshot even when another CLI instance loads its own helper snapshot.
        return NativeClient(url, token, self)


class NativeClient(adapter.HookClient):
    def __init__(self, url, token, registry, session=None):
        super().__init__(url, token, session)
        self.registry = registry
        self.withheld = False
        self._bindings = {}

    def request(self, event, **fields):
        if self.failed or self.withheld:
            raise adapter.AdapterError("Native trajectory already stopped")
        payload = {"contract_version": CONTRACT, "registry_sha256": self.registry.sha256,
                   "session_id": self.session, "event": event, **fields}
        try:
            expected = {"session_start": set(), "session_end": set(),
                        "call": {"tool", "args", "schema_sha256"},
                        "result": {"call_id", "tool", "args", "result_kind", "delivery", "content"},
                        "context": {"call_id", "tool", "args", "content"}}
            if event not in expected or set(fields) != expected[event]:
                raise adapter.AdapterError("Unexpected native request fields")
            if event == "call" and len(self._bindings) >= 256:
                raise adapter.AdapterError("Native collector invocation bound exhausted")
            if "content" in fields and (not isinstance(fields["content"], str)
                    or len(fields["content"].encode("utf-8")) > adapter.MAX_RESULT):
                raise adapter.AdapterError("Native content exceeds the full-inspection bound")
            body = adapter.encoded(payload)
            if len(body) > adapter.MAX_BODY:
                raise adapter.AdapterError("Native request exceeds the body bound")
            request = Request(self.url + "/native/v1", body,
                              {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
            with self.transport.open(request, timeout=5) as response:
                raw = response.read(32_769)
                if response.status != 200 or len(raw) > 32_768:
                    raise adapter.AdapterError("Invalid native HTTP response")
            reply = strict_json(raw)
            keys = {"contract_version", "registry_sha256", "session_id", "event", "verdict", "enforced",
                    "release", "call_id", "binding_sha256", "content_sha256", "reason_codes"}
            if (not isinstance(reply, dict) or set(reply) != keys or reply["contract_version"] != CONTRACT
                    or reply["registry_sha256"] != self.registry.sha256 or reply["session_id"] != self.session
                    or reply["event"] != event or reply["enforced"] is not True
                    or reply["verdict"] not in {"allow", "ask", "deny"} or type(reply["release"]) is not bool
                    or reply["release"] != (reply["verdict"] == "allow")
                    or not isinstance(reply["reason_codes"], list)
                    or not all(isinstance(code, str) for code in reply["reason_codes"])):
                raise adapter.AdapterError("Invalid native admission envelope")
            call_id = reply["call_id"]
            if event in {"session_start", "session_end"}:
                if any(reply[key] is not None for key in ("call_id", "binding_sha256", "content_sha256")):
                    raise adapter.AdapterError("Invalid native lifecycle envelope")
            elif event == "call":
                if reply["content_sha256"] is not None:
                    raise adapter.AdapterError("Unexpected native call content hash")
                if reply["release"]:
                    if (not isinstance(call_id, str) or not 16 <= len(call_id) <= 128
                            or call_id in self._bindings or not is_hash(reply["binding_sha256"])):
                        raise adapter.AdapterError("Invalid native invocation identity")
                    self._bindings[call_id] = reply["binding_sha256"]
                elif call_id is not None or reply["binding_sha256"] is not None:
                    raise adapter.AdapterError("Withheld native call issued an invocation identity")
            elif event in {"result", "context"}:
                if (call_id != fields["call_id"] or call_id not in self._bindings
                        or reply["binding_sha256"] != self._bindings[call_id]
                        or reply["content_sha256"] != adapter.digest(fields["content"].encode("utf-8"))):
                    raise adapter.AdapterError("Native admission did not bind the exact invocation and content")
                if event == "context" or (event == "result" and fields["delivery"] == "parent" and reply["release"]):
                    del self._bindings[call_id]
            else:
                raise adapter.AdapterError("Unsupported native event")
            self.receipts.append({"event": event, "tool": fields.get("tool"),
                                  "request_sha256": adapter.digest(body), "response_sha256": adapter.digest(raw),
                                  "decision": reply["verdict"], "release": reply["release"],
                                  "binding_sha256": reply["binding_sha256"], "content_sha256": reply["content_sha256"]})
            if event == "session_end":
                self._bindings.clear()
        except (adapter.AdapterError, OSError, ValueError, TypeError, KeyError, HTTPException, HTTPError, URLError):
            self.failed = True
            raise adapter.AdapterError("Native transport or admission contract failed") from None
        if not reply["release"]:
            self.withheld = True
            raise NativeWithheld("Native policy withheld the call or content; no evaluator result is reported")
        return reply

    def event(self, event, tool=None, arguments=None, result=None):
        if event not in {"SessionStart", "SessionEnd"} or tool is not None or result is not None:
            raise adapter.AdapterError("Native admission requires its explicit staged contract")
        return self.request("session_start" if event == "SessionStart" else "session_end")


def runtime_class(upstream, client, formatter=None):
    """Preserve the original validated runtime; add admission at its real callable boundary."""
    formatter = formatter or upstream.execution.tool_result_to_str
    original_runtime = upstream.runtime.FunctionsRuntime

    class NativeRuntime(original_runtime):
        def __init__(self, functions=()):
            super().__init__(functions)
            self._native_calls = []
            self._native_context = []
            self._native_executor_active = False
            self._native_wrappers = {}
            self._guard_all()

        def _guard_all(self):
            try:
                self.functions = dict(self.functions)
                for name, function in self.functions.items():
                    schema = client.registry.schema(function)
                    if function.run is self._native_wrappers.get(name):
                        continue
                    original, dependencies = function.run, frozenset(function.dependencies)

                    def guarded(*args, _name=name, _run=original, _deps=dependencies, _schema=schema, **kwargs):
                        if args:
                            raise adapter.AdapterError("Native runtime used unexpected positional arguments")
                        frame = self._native_calls[-1]
                        inspected = {key: value for key, value in kwargs.items() if key not in _deps}
                        frame["args"] = copy.deepcopy(inspected)
                        receipt = client.request("call", tool=_name, args=inspected, schema_sha256=_schema)
                        frame["call_id"] = receipt["call_id"]
                        return _run(**kwargs)

                    self._native_wrappers[name] = guarded
                    self.functions[name] = function.model_copy(update={"run": guarded})
            except Exception:
                client.failed = True
                raise adapter.AdapterError("Native registry or runtime identity failed") from None

        def register_function(self, function):
            result = super().register_function(function)
            self._guard_all()
            return result

        def update_functions(self, functions):
            super().update_functions(functions)
            self._guard_all()

        def run_function(self, env, function, kwargs, raise_on_error=False):
            if client.failed or client.withheld:
                raise adapter.AdapterError("Native trajectory already stopped")
            self._guard_all()
            frame = {"tool": function, "args": None, "call_id": None}
            self._native_calls.append(frame)
            raised = None
            original_error_admitted = False
            try:
                try:
                    result, error = super().run_function(env, function, kwargs, raise_on_error=raise_on_error)
                except Exception as failure:
                    if client.failed or client.withheld:
                        raise adapter.AdapterError("Native invocation stopped before result admission") from None
                    result, error, raised = "", f"{type(failure).__name__}: {failure}", failure
                if client.failed or client.withheld:
                    raise NativeWithheld("Native policy withheld the invocation")
                if frame["call_id"] is None:
                    raise adapter.AdapterError("Native invocation never reached its validated callable boundary")
                content = error or formatter(result)
                client.request("result", call_id=frame["call_id"], tool=function, args=frame["args"],
                               result_kind="error" if error else "value",
                               delivery="model" if len(self._native_calls) == 1 else "parent", content=content)
                if len(self._native_calls) == 1:
                    if not self._native_executor_active:
                        raise adapter.AdapterError("Native model-facing result requires the guarded original executor")
                    self._native_context.append(frame)
                if raised is not None:
                    original_error_admitted = True
                    raise raised
                return result, error
            except Exception as failure:
                if original_error_admitted and failure is raised:
                    raise
                if client.withheld:
                    raise NativeWithheld("Native policy withheld the invocation or content") from None
                client.failed = True
                raise adapter.AdapterError("Native runtime admission failed; trajectory stopped") from None
            finally:
                self._native_calls.pop()

    return NativeRuntime


def executor_class(upstream, client):
    """Gate final messages produced by the original ToolsExecutor before returning them."""
    original = upstream.execution.ToolsExecutor

    class NativeExecutor(original):
        def query(self, query, runtime, env, messages=(), extra_args=None):
            if runtime._native_executor_active or runtime._native_context:
                client.failed = True
                raise adapter.AdapterError("Native executor requires serial clean invocation state")
            runtime._native_executor_active = True
            try:
                value = super().query(query, runtime, env, messages, {} if extra_args is None else extra_args)
                appended = value[3][len(messages):]
                if len(appended) != len(runtime._native_context):
                    raise adapter.AdapterError("Original native executor produced an unbound tool message")
                for message, frame in zip(appended, runtime._native_context, strict=True):
                    if (message.get("role") != "tool" or message["tool_call"].function != frame["tool"]
                            or message.get("tool_call_id") != message["tool_call"].id):
                        raise adapter.AdapterError("Native executor returned an unexpected tool identity")
                    # Original FunctionCall is a Pydantic model; preserve its exact JSON representation.
                    snapshot = dict(message)
                    snapshot["tool_call"] = message["tool_call"].model_dump(mode="json")
                    content = adapter.encoded(snapshot).decode("utf-8")
                    client.request("context", call_id=frame["call_id"], tool=frame["tool"],
                                   args=frame["args"], content=content)
                runtime._native_context.clear()
                return value
            except Exception:
                if client.withheld:
                    raise NativeWithheld("Native policy withheld final model context") from None
                client.failed = True
                raise adapter.AdapterError("Native final context admission failed; trajectory stopped") from None
            finally:
                runtime._native_executor_active = False

    return NativeExecutor


def guard_pipeline(pipeline, upstream, client):
    """Replace only exact original executor nodes; never patch upstream global classes."""
    guarded = executor_class(upstream, client)
    seen = set()
    count = 0

    def visit(node):
        nonlocal count
        if not hasattr(node, "elements"):
            return
        if id(node) in seen:
            raise adapter.AdapterError("Native pipeline containers must be acyclic and independently owned")
        seen.add(id(node))
        elements = []
        for element in node.elements:
            if type(element) is upstream.execution.ToolsExecutor:
                elements.append(guarded(element.output_formatter))
                count += 1
            elif isinstance(element, upstream.execution.ToolsExecutor):
                raise adapter.AdapterError("Unsupported native executor subclass")
            else:
                visit(element)
                elements.append(element)
        node.elements = elements

    try:
        visit(pipeline)
        if count != 1:
            raise adapter.AdapterError("Pinned native pipeline must contain one original tool executor")
    except Exception:
        client.failed = True
        raise adapter.AdapterError("Native pipeline identity failed; trajectory stopped") from None
    return pipeline
