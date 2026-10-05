# SPDX-License-Identifier: Apache-2.0
"""Original AgentDojo runtime collector; native-tool classification remains unchanged."""
from __future__ import annotations

import hashlib
import copy
from http.client import HTTPException
import importlib
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

REVISION = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
MAX_BODY = 8 * 1024 * 1024
MAX_RESULT = 262_144


class AdapterError(RuntimeError):
    """Sanitized infrastructure failure; never an attack-prevention result."""


class FirewallDenied(RuntimeError):
    pass


class ApprovalRequired(RuntimeError):
    pass


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_hash(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class EvidenceOutput:
    """Reserve a fresh writable destination before traffic; publish complete JSON atomically."""
    def __init__(self, destination: Path):
        self.destination = destination.absolute()
        if not self.destination.parent.is_dir():
            raise AdapterError("Evidence parent directory must already exist")
        try:
            with self.destination.open("x", encoding="utf-8") as reserved:
                json.dump({"status": "reserved", "live_gate_complete": False}, reserved)
                reserved.flush()
                os.fsync(reserved.fileno())
                self.identity = os.fstat(reserved.fileno()).st_ino
        except OSError:
            raise AdapterError("Evidence destination must be fresh and writable") from None

    def publish(self, report):
        if self.destination.stat().st_ino != self.identity:
            raise AdapterError("Reserved evidence destination was replaced")
        descriptor, temporary = tempfile.mkstemp(prefix="agentdojo-evidence-", suffix=".tmp", dir=self.destination.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(report, output, indent=2, allow_nan=False)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.destination)
        finally:
            Path(temporary).unlink(missing_ok=True)


def encoded(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def verify_checkout(checkout: Path) -> dict:
    checkout = checkout.resolve()

    source = checkout / "src"
    # dont_write_bytecode does not prevent Python from reading an existing pyc.
    # Reject caches/reparse links instead of trusting source hashes alone.
    entries = [source, *source.rglob("*")]
    for entry in entries:
        if (entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction())
                or entry.name == "__pycache__" or entry.suffix.lower() in {".pyc", ".pyo"}):
            raise AdapterError("Pinned source must be cache-free and contain no symlinks or junctions")

    def git(*arguments):
        result = subprocess.run(["git", "-C", str(checkout), *arguments], capture_output=True, check=True)
        return result.stdout.decode("utf-8").strip()

    if git("rev-parse", "HEAD") != REVISION:
        raise AdapterError("Upstream checkout is not the required pinned revision")
    if git("status", "--porcelain", "--untracked-files=all", "--", "src", "pyproject.toml", "LICENSE"):
        raise AdapterError("Upstream source, data, or license has local changes")
    tracked = git("ls-files", "src").splitlines()
    committed = {}
    for line in git("ls-tree", "-r", REVISION, "--", "src").splitlines():
        attributes, name = line.split("\t", 1)
        mode, kind, blob = attributes.split()
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise AdapterError("Unsupported upstream source tree entry")
        committed[name] = blob
    if set(tracked) != set(committed):
        raise AdapterError("Upstream source index differs from the pinned tree")
    actual_python = {path.relative_to(checkout).as_posix() for path in (checkout / "src").rglob("*.py")}
    if actual_python != {name for name in tracked if name.endswith(".py")}:
        raise AdapterError("Upstream Python source inventory differs from its Git tree")
    hashes = {}
    for name in tracked:
        content = (checkout / name).read_bytes()
        def blob_hash(value):
            return hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()
        if committed[name] not in {blob_hash(content), blob_hash(content.replace(b"\r\n", b"\n"))}:
            raise AdapterError("Upstream source/data bytes differ from their pinned Git blobs")
        hashes[name] = digest(content)
    # Also verify ignored files under src: a local module/data shadow is not pinned code.
    actual = {path.relative_to(checkout).as_posix() for path in (checkout / "src").rglob("*")
              if path.is_file()}
    if actual != set(tracked):
        raise AdapterError("Upstream source/data inventory contains unexpected files")
    return {"revision": REVISION, "source_inventory_sha256": digest(encoded(hashes)),
            "source_files": len(hashes), "license_sha256": digest((checkout / "LICENSE").read_bytes())}


def load_upstream(checkout: Path):
    verified = verify_checkout(checkout)
    sys.dont_write_bytecode = True
    source = (checkout.resolve() / "src").resolve()
    sys.path.insert(0, str(source))
    runtime = importlib.import_module("agentdojo.functions_runtime")
    execution = importlib.import_module("agentdojo.agent_pipeline.tool_execution")
    suite = importlib.import_module("agentdojo.task_suite.task_suite")
    for module in list(sys.modules.values()):
        name = getattr(module, "__name__", "")
        if module and (name == "agentdojo" or name.startswith("agentdojo.")):
            location = getattr(module, "__file__", None)
            if location and not Path(location).resolve().is_relative_to(source):
                raise AdapterError("AgentDojo import did not come from the selected pinned source")
    return SimpleNamespace(runtime=runtime, execution=execution, suite=suite, verified=verified)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise AdapterError("HTTP redirects are not accepted")


def opener():
    # Never inherit proxy configuration or its credentials.
    return build_opener(ProxyHandler({}), NoRedirect())


class HookClient:
    def __init__(self, url: str, token: str, session: str | None = None):
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"} or parsed.path not in {"", "/"}:
            raise AdapterError("Agent must use an explicit numeric loopback HTTP address")
        if parsed.username or parsed.password or parsed.query or parsed.fragment or not token:
            raise AdapterError("Invalid Agent connection configuration")
        self.url, self.token = url.rstrip("/"), token
        self.session = session or str(uuid.uuid4())
        self.failed = False
        self.receipts: list[dict] = []
        self.transport = opener()

    def event(self, event: str, tool: str | None = None, arguments=None, result: str | None = None):
        if self.failed:
            raise AdapterError("Agent inspection already failed for this trajectory")
        payload = {"session_id": self.session, "hook_event_name": event}
        if tool is not None:
            payload.update(tool_name=tool, tool_input=arguments)
        if result is not None:
            if len(result.encode("utf-8")) > MAX_RESULT:
                self.failed = True
                raise AdapterError("Tool result exceeds the unchanged Agent inspection limit")
            payload["tool_response"] = result
        try:
            body = encoded(payload)
            if len(body) > MAX_BODY:
                raise AdapterError("Hook request exceeds the unchanged Agent body limit")
            request = Request(self.url + "/hook", body, {"Authorization": "Bearer " + self.token,
                                                        "Content-Type": "application/json"})
            with self.transport.open(request, timeout=5) as response:
                raw = response.read(32_769)
                if response.status != 200 or len(raw) > 32_768:
                    raise AdapterError("Agent returned an invalid HTTP response")
            reply = json.loads(raw)
            verdict = "no_opinion"
            if event == "PreToolUse" and reply != {}:
                if not isinstance(reply, dict) or set(reply) != {"hookSpecificOutput"}:
                    raise AdapterError("Agent returned an unexpected decision shape")
                specific = reply["hookSpecificOutput"]
                if (not isinstance(specific, dict) or specific.get("hookEventName") != "PreToolUse"
                        or specific.get("permissionDecision") not in {"deny", "ask"}
                        or ("permissionDecisionReason" in specific and not isinstance(specific["permissionDecisionReason"], str))
                        or set(specific) - {"hookEventName", "permissionDecision", "permissionDecisionReason"}):
                    raise AdapterError("Agent returned an invalid pre-call decision")
                verdict = specific["permissionDecision"]
            elif reply != {}:
                raise AdapterError("Non-pre-call event returned an unexpected decision")
            self.receipts.append({"event": event, "tool": tool, "request_sha256": digest(body),
                                  "response_sha256": digest(raw), "decision": verdict})
        except (AdapterError, OSError, ValueError, TypeError, HTTPException, HTTPError, URLError):
            self.failed = True
            raise AdapterError("Agent hook transport or contract failed") from None
        if verdict == "deny":
            raise FirewallDenied("Soup Wall denied this native tool call")
        if verdict == "ask":
            raise ApprovalRequired("Soup Wall requires approval; this unattended adapter does not execute the tool")


def runtime_class(upstream, client: HookClient, formatter=None):
    """Guard actual validated calls without copying/reimplementing the upstream runtime."""
    formatter = formatter or upstream.execution.tool_result_to_str
    original_runtime = upstream.runtime.FunctionsRuntime

    class SoupWallRuntime(original_runtime):
        def __init__(self, functions=()):
            super().__init__(functions)
            self._calls = []
            self._guard_all()

        def _guard_all(self):
            self.functions = dict(self.functions)
            for name, function in self.functions.items():
                if getattr(function.run, "_soup_wall_client", None) is client:
                    continue
                original = function.run
                dependencies = frozenset(function.dependencies)

                def guarded(*args, _name=name, _original=original, _deps=dependencies, **kwargs):
                    if args:
                        raise AdapterError("Pinned runtime unexpectedly used positional tool parameters")
                    # Upstream has resolved nested calls and validated/defaulted its parameters.
                    # Dependency environment objects are neither tool arguments nor model input.
                    inspected = {key: value for key, value in kwargs.items() if key not in _deps}
                    self._calls[-1]["arguments"] = copy.deepcopy(inspected)
                    client.event("PreToolUse", _name, inspected)
                    return _original(**kwargs)

                guarded._soup_wall_client = client
                # A new Function retains the exact schema/docs/dependencies. No global object mutation.
                self.functions[name] = function.model_copy(update={"run": guarded})

        def register_function(self, function):
            registered = super().register_function(function)
            self._guard_all()
            return registered

        def update_functions(self, functions):
            super().update_functions(functions)
            self._guard_all()

        def run_function(self, env, function, kwargs, raise_on_error=False):
            self._guard_all()
            call = {}
            self._calls.append(call)
            try:
                result, error = super().run_function(env, function, kwargs, raise_on_error=raise_on_error)
                # Errors are delivered by original provider serializers in place of content.
                # Nested raise_on_error remains an exception. An invalid outer call may
                # return an error without ever reaching the actual Function.run boundary.
                if function in self.functions:
                    client.event("PostToolUse", function, call.get("arguments", {}), error or formatter(result))
                return result, error
            finally:
                self._calls.pop()

    return SoupWallRuntime


def isolated_environment(profile: Path):
    keep = {"SYSTEMROOT", "WINDIR", "PATH", "COMSPEC", "PROGRAMFILES", "PROGRAMFILES(X86)",
            "SYSTEMDRIVE", "NUMBER_OF_PROCESSORS"}
    env = {key: value for key, value in os.environ.items() if key.upper() in keep}
    env.update(HOME=str(profile), USERPROFILE=str(profile), APPDATA=str(profile / "appdata"),
               LOCALAPPDATA=str(profile / "localappdata"), TEMP=str(profile), TMP=str(profile))
    return env


def safe_temporary_parent(parent: Path):
    """Reject redirected scratch ancestry before writing private profiles or policy snapshots."""
    selected = parent.absolute()
    if selected != selected.resolve():
        raise AdapterError("Temporary parent must be canonical and unlinked")
    for candidate in [selected, *selected.parents]:
        if candidate.is_symlink() or (hasattr(candidate, "is_junction") and candidate.is_junction()):
            raise AdapterError("Temporary parent ancestry must be unlinked")
    selected.mkdir(parents=True, exist_ok=True)
    return selected


class DisposableAgent:
    """Owns only a fresh temporary profile and its own explicitly selected binary."""
    def __init__(self, binary: Path, policy: Path, temporary_parent: Path, enforce=True, native_registry=None):
        self.binary, self.policy = binary.resolve(), policy.resolve()
        self.temporary_parent = safe_temporary_parent(temporary_parent)
        self.directory = None
        self.process = None
        self.enforce = enforce
        self.native_registry = native_registry

    def __enter__(self):
        self.directory = Path(tempfile.mkdtemp(prefix="agentdojo-live-", dir=self.temporary_parent)).resolve()
        self.env = isolated_environment(self.directory)
        agent_dir = self.directory / ".agentfw"
        agent_dir.mkdir()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        policy = self.policy.as_posix().replace("'", "''")
        (agent_dir / "config.yaml").write_text(f"bind: 127.0.0.1\nport: {port}\nenforce: {str(self.enforce).lower()}\n"
                                               f"policy: '{policy}'\n", encoding="utf-8")
        if self.native_registry is not None:
            registry_path = agent_dir / "native-registry.json"
            registry_path.write_bytes(self.native_registry.raw)
            registry_yaml = registry_path.as_posix().replace("'", "''")
            with (agent_dir / "config.yaml").open("a", encoding="utf-8") as config:
                config.write(f"native:\n  registry_path: '{registry_yaml}'\n"
                             f"  registry_sha256: {self.native_registry.sha256}\n")
        try:
            installed = subprocess.run([str(self.binary), "install"], env=self.env, capture_output=True,
                                       cwd=self.directory, timeout=10)
            if installed.returncode != 0:
                raise AdapterError("Disposable Agent installation failed")
            token = (agent_dir / "token").read_text().strip()
            self.client = HookClient(f"http://127.0.0.1:{port}", token)
            self.process = subprocess.Popen([str(self.binary), "serve"], env=self.env, cwd=self.directory,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise AdapterError("Disposable Agent failed startup")
                try:
                    with opener().open(self.client.url + "/health", timeout=0.5) as response:
                        health = json.loads(response.read(4096))
                        if health.get("status") != "ok" or health.get("enforce") is not self.enforce:
                            raise AdapterError("Disposable Agent health/posture mismatch")
                        break
                except (OSError, URLError):
                    time.sleep(0.05)
            else:
                raise AdapterError("Disposable Agent startup timed out")
            preflight = subprocess.run([str(self.binary), "preflight", "--require-enforce"], env=self.env,
                                       cwd=self.directory, capture_output=True, timeout=10)
            if preflight.returncode != 0:
                raise AdapterError("Disposable Agent did not pass enforcing preflight")
            if self.native_registry is not None:
                from agentdojo_native import NativeClient
                native_token = (agent_dir / "native-token").read_text().strip()
                self.client = NativeClient(f"http://127.0.0.1:{port}", native_token, self.native_registry)
            self.client.event("SessionStart")
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def __exit__(self, *_):
        import shutil
        if self.process is not None:
            if self.process.poll() is None:
                try:
                    self.client.event("SessionEnd")
                except AdapterError:
                    pass
                self.process.kill()
            self.process.wait(timeout=10)
        if self.directory is not None and self.directory.exists():
            if self.directory.parent != self.temporary_parent or not self.directory.name.startswith("agentdojo-live-"):
                raise AdapterError("Refusing cleanup outside the generated Agent profile")
            shutil.rmtree(self.directory)


class BudgetProvider:
    """Original OpenAILLM consumes this explicit, bounded Chat Completions transport."""
    def __init__(self, base_url, key, model, *, max_calls, max_total_request_bytes, max_output_tokens,
                 max_reserved_usd, input_usd_per_million, output_usd_per_million, timeout_seconds=30):
        parsed = urlsplit(base_url)
        if (parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1"})):
            raise AdapterError("Provider requires HTTPS, or numeric HTTP loopback for a selected local runtime")
        if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname or not key:
            raise AdapterError("Invalid explicit provider configuration")
        numbers = (max_reserved_usd, input_usd_per_million, output_usd_per_million, timeout_seconds)
        if (not all(math.isfinite(value) and value >= 0 for value in numbers) or timeout_seconds == 0
                or min(max_calls, max_total_request_bytes, max_output_tokens) < 1):
            raise AdapterError("Invalid provider budget")
        self.endpoint, self.key, self.model = base_url.rstrip("/") + "/chat/completions", key, model
        self.max_calls, self.max_bytes, self.output_limit = max_calls, max_total_request_bytes, max_output_tokens
        self.max_usd, self.input_rate, self.output_rate = max_reserved_usd, input_usd_per_million, output_usd_per_million
        self.timeout = timeout_seconds
        self.calls = self.request_bytes = 0
        self.reserved_usd = 0.0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        from openai import NOT_GIVEN
        from openai.types.chat import ChatCompletion
        if kwargs.get("model") != self.model:
            raise AdapterError("Provider model differs from the operator selection")
        body = {key: value for key, value in kwargs.items() if value is not NOT_GIVEN}
        body["max_tokens"] = self.output_limit
        raw = encoded(body)
        reserve = (len(raw) * self.input_rate + self.output_limit * self.output_rate) / 1_000_000
        if (self.calls >= self.max_calls or self.request_bytes + len(raw) > self.max_bytes
                or self.reserved_usd + reserve > self.max_usd):
            raise AdapterError("Operator-selected provider budget exhausted before the request")
        # Failed attempts consume their reservation too; upstream retries cannot evade these bounds.
        self.calls += 1
        self.request_bytes += len(raw)
        self.reserved_usd += reserve
        try:
            request = Request(self.endpoint, raw, {"Authorization": "Bearer " + self.key, "Content-Type": "application/json"})
            with opener().open(request, timeout=self.timeout) as response:
                content = response.read(8 * 1024 * 1024 + 1)
                if len(content) > 8 * 1024 * 1024:
                    raise AdapterError("Provider response exceeds the response limit")
            completion = ChatCompletion.model_validate_json(content)
            if completion.usage and completion.usage.completion_tokens > self.output_limit:
                raise AdapterError("Provider exceeded the requested output limit")
            return completion
        except (OSError, ValueError, HTTPException, HTTPError, URLError):
            raise AdapterError("Selected provider transport or response failed") from None


def run_original_task(suite, pipeline, user_task, injection_task, injections, runtime):
    # Own orchestration passes runtime_class; original TaskSuite owns fresh task state and evaluators.
    return suite.run_task_with_pipeline(pipeline, user_task, injection_task, injections, runtime_class=runtime)
