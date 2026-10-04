#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the installed Claude host with local model fixtures and disposable state."""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
import urllib.request

API_KEY = "sk-ant-soup-wall-local-fixture-not-a-real-key"
RULE = "host-fixture-deny-side-effects"
PROOF = "soup-wall-host-proof"
COMMAND = f"printf {PROOF} > ./proof-marker.txt"
MODEL = "claude-sonnet-4-20250514"
CHECKS: list[str] = []


def check(condition: bool, label: str) -> None:
    if not condition:
        raise RuntimeError(f"Acceptance failed: {label}")
    CHECKS.append(label)


def text_of(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(text_of(item) for item in value)
    if isinstance(value, dict):
        return text_of(value.get("text", value.get("content", "")))
    return ""


def binary_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class LocalServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, handler, workspace: Path | None = None):
        super().__init__(("127.0.0.1", 0), handler)
        self.workspace = workspace
        self.requests = 0
        self.token_counts = 0
        self.errors: list[str] = []
        self.authenticated_requests = 0
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_port}"

    def close(self):
        self.shutdown()
        self.server_close()


class BlockingProxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reject(self):
        self.server.requests += 1
        self.send_response(403)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_CONNECT = do_GET = do_POST = reject


class ModelFixture(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 8 * 1024 * 1024:
            self.server.errors.append("invalid request size")
            self.send_error(400)
            return
        body = json.loads(self.rfile.read(size))
        if self.headers.get("x-api-key") != API_KEY:
            self.server.errors.append("fixture API key was not used")
            self.send_error(401)
            return
        self.server.authenticated_requests += 1
        path = urlsplit(self.path).path
        if path == "/v1/messages/count_tokens":
            self.server.token_counts += 1
            encoded = b'{"input_tokens":100}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return
        if path != "/v1/messages":
            self.server.errors.append("unexpected API path")
            self.send_error(404)
            return
        self.server.requests += 1
        if self.server.requests > 8:
            self.server.errors.append("fixture request bound exceeded")
            self.send_error(429)
            return
        names = {tool.get("name") for tool in body.get("tools", [])}
        if names != {"Read", "Bash"}:
            self.server.errors.append("unexpected available tools")
            self.send_error(400)
            return
        results = [
            block for message in body.get("messages", [])
            for block in (message.get("content", []) if isinstance(message.get("content"), list) else [])
            if block.get("type") == "tool_result"
        ]
        ids = {result.get("tool_use_id") for result in results}
        content = [{"type": "text", "text": "fixture-complete"}]
        if "toolu_fixture_read" not in ids:
            content = [{"type": "tool_use", "id": "toolu_fixture_read", "name": "Read",
                        "input": {"file_path": str(self.server.workspace / "README.md")}}]
        elif "toolu_fixture_bash" not in ids:
            content = [{"type": "tool_use", "id": "toolu_fixture_bash", "name": "Bash",
                        "input": {"command": COMMAND, "description": "Write a disposable proof marker"}}]
        message = {
            "id": "msg_local_fixture", "type": "message", "role": "assistant",
            "model": body.get("model", MODEL), "content": [], "stop_reason": None,
            "stop_sequence": None, "usage": {"input_tokens": 100, "output_tokens": 0,
                                             "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0},
        }
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()

        def event(kind, value):
            self.wfile.write(f"event: {kind}\ndata: {json.dumps(value)}\n\n".encode())
            self.wfile.flush()

        event("message_start", {"type": "message_start", "message": message})
        for index, block in enumerate(content):
            if block["type"] == "tool_use":
                start = dict(block, input={})
                delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
            else:
                start = dict(block, text="")
                delta = {"type": "text_delta", "text": block["text"]}
            event("content_block_start", {"type": "content_block_start", "index": index, "content_block": start})
            event("content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta})
            event("content_block_stop", {"type": "content_block_stop", "index": index})
        reason = "tool_use" if content[0]["type"] == "tool_use" else "end_turn"
        event("message_delta", {"type": "message_delta", "delta": {"stop_reason": reason, "stop_sequence": None},
                                "usage": {"output_tokens": 10}})
        event("message_stop", {"type": "message_stop"})


def environment(profile: Path, proxy: LocalServer, bash: Path) -> dict[str, str]:
    # Copy OS/runtime paths only. Never inherit actual provider, GitHub, or Claude credentials.
    keep = {"SYSTEMROOT", "WINDIR", "PATH", "COMSPEC", "PROGRAMFILES", "PROGRAMFILES(X86)",
            "SYSTEMDRIVE", "NUMBER_OF_PROCESSORS"}
    env = {key: value for key, value in os.environ.items() if key.upper() in keep}
    env.update({
        "USERPROFILE": str(profile), "APPDATA": str(profile / "appdata"),
        "LOCALAPPDATA": str(profile / "localappdata"), "TEMP": str(profile), "TMP": str(profile),
        "CLAUDE_CONFIG_DIR": str(profile / "claude"), "ANTHROPIC_API_KEY": API_KEY,
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_UPDATES": "1",
        "DISABLE_GROWTHBOOK": "1", "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
        "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1", "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
        "CLAUDE_CODE_DISABLE_BACKGROUND_TASKS": "1", "CLAUDE_CODE_DISABLE_BUNDLED_SKILLS": "1",
        "CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS": "1", "CLAUDE_CODE_GIT_BASH_PATH": str(bash),
        "API_TIMEOUT_MS": "10000", "CLAUDE_CODE_MAX_RETRIES": "0",
        "HTTP_PROXY": proxy.url, "HTTPS_PROXY": proxy.url,
        "NO_PROXY": "127.0.0.1,localhost,::1",
    })
    return env


def run(arguments, workspace, env, timeout=45):
    return subprocess.run(arguments, cwd=workspace, env=env, capture_output=True,
                          encoding="utf-8", errors="replace", timeout=timeout,
                          creationflags=subprocess.CREATE_NO_WINDOW)


def stop(process):
    if process is not None:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)


def remove_profile_tree(root: Path, parent: Path):
    # Verify the resolved absolute target before recursive Windows cleanup.
    if root.resolve().parent != parent or not root.name.startswith("soup-wall-claude-host-acceptance-"):
        raise RuntimeError("Refusing cleanup outside the generated acceptance directory")
    # Claude's per-workspace state can exceed MAX_PATH even in a short temp root.
    extended = "\\\\?\\" + str(root)

    def missing_is_already_removed(_function, _path, details):
        error = details[1]
        if not isinstance(error, FileNotFoundError):
            raise error

    shutil.rmtree(extended, onerror=missing_is_already_removed)


def scenario(mode, root, agent, claude, bash, proxy):
    directory = root / mode
    profile = directory / "profile with spaces and 'quote"
    workspace = directory / "workspace"
    workspace.mkdir(parents=True)
    for relative in ["claude", "appdata", "localappdata", ".agentfw"]:
        (profile / relative).mkdir(parents=True, exist_ok=True)
    (workspace / "README.md").write_text("Soup Wall benign host fixture.\n", encoding="utf-8")
    policy = directory / "fixture-policy.yaml"
    policy.write_text(f"agent_policies:\n  - name: {RULE}\n    when:\n      min_action_class: side_effecting\n"
                      "    action: deny\n    message: Disposable host fixture rejects side effects.\ndefault: allow\n", encoding="utf-8")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    enforce = "false" if mode == "shadow" else "true"
    agent_dir = profile / ".agentfw"
    (agent_dir / "config.yaml").write_text(f"bind: 127.0.0.1\nport: {port}\nenforce: {enforce}\n"
                                          f"policy: '{policy.as_posix().replace(chr(39), chr(39)*2)}'\n", encoding="utf-8")
    env = environment(profile, proxy, bash)
    installed = run([str(agent), "install"], workspace, env)
    check(installed.returncode == 0, f"{mode}: isolated Agent installation")
    token = (agent_dir / "token").read_text().strip()
    check(token not in installed.stdout, f"{mode}: install does not reveal token")
    env["AGENTFW_TOKEN"] = token
    block = json.loads(installed.stdout[installed.stdout.index("{"):installed.stdout.rindex("}")+1])
    settings = workspace / "fixture-settings.json"
    settings.write_text(json.dumps(block), encoding="utf-8")
    model = LocalServer(ModelFixture, workspace)
    env["ANTHROPIC_BASE_URL"] = model.url
    daemon = None
    started = time.monotonic()
    try:
        if mode != "offline":
            daemon = subprocess.Popen([str(agent), "serve"], cwd=workspace, env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
            deadline = time.monotonic() + 10
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            while time.monotonic() < deadline:
                if daemon.poll() is not None:
                    raise RuntimeError("Acceptance daemon stopped during startup")
                try:
                    with opener.open(f"http://127.0.0.1:{port}/health", timeout=1):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Acceptance daemon health timed out")
        preflight = run([str(agent), "preflight", "--require-enforce", "--timeout-seconds", "2"], workspace, env)
        check(preflight.returncode == {"enforce": 0, "shadow": 4, "offline": 2}[mode], f"{mode}: preflight posture")
        arguments = [str(claude), "--restricted", "-p", "Run the local acceptance fixture.",
                     "--settings", str(settings), "--tools", "Read,Bash", "--allowedTools", "Read,Bash",
                     "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--no-session-persistence",
                     "--output-format", "stream-json", "--verbose", "--include-hook-events",
                     "--permission-mode", "dontAsk", "--model", MODEL,
                     "--system-prompt", "Execute only the fixed local fixture tool calls returned by the local mock."]
        result = run(arguments, workspace, env)
        check(result.returncode == 0, f"{mode}: real Claude host exits successfully")
        messages = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        final = [message for message in messages if message.get("type") == "result"]
        check(len(final) == 1 and final[0].get("result") == "fixture-complete", f"{mode}: bounded fixture completes")
        initialized = [message for message in messages if message.get("subtype") == "init"]
        check(len(initialized) == 1 and not initialized[0].get("mcp_servers"), f"{mode}: no MCP servers loaded")
        results = {block["tool_use_id"]: block for message in messages if message.get("type") == "user"
                   for block in message.get("message", {}).get("content", []) if block.get("type") == "tool_result"}
        read = results.get("toolu_fixture_read", {})
        proposed = results.get("toolu_fixture_bash", {})
        check(not read.get("is_error") and "Soup Wall benign host fixture." in text_of(read), f"{mode}: benign Read actually executes")
        hooks = [message for message in messages if message.get("subtype") == "hook_response"]
        check(len(hooks) >= 3, f"{mode}: real host HTTP hook responses observed")
        marker = workspace / "proof-marker.txt"
        if mode == "enforce":
            check(bool(proposed.get("is_error")) and RULE in text_of(proposed), "enforce: host receives Agent policy denial")
            check(not marker.exists(), "enforce: proposed shell effect prevented")
        else:
            check("toolu_fixture_bash" in results and not proposed.get("is_error"), f"{mode}: controlled Bash executes")
            check(marker.exists() and marker.read_text() == PROOF, f"{mode}: only harmless disposable marker written")
        check(not model.errors and model.requests == 3 and model.authenticated_requests == 3,
              f"{mode}: all three model calls use authenticated loopback fixtures")
        stop(daemon)
        daemon = None
        audit_path = agent_dir / "audit.jsonl"
        audit = [json.loads(line) for line in audit_path.read_text().splitlines()] if audit_path.exists() else []
        if mode == "offline":
            check(not audit, "offline: absent daemon creates no audit evidence")
            check("ECONNREFUSED" in result.stderr + json.dumps(hooks), "offline: actual host observes connection failure")
            bash_audit = None
        else:
            bash_audit = [event for event in audit if event["event"] == "pre_tool_use" and event.get("tool") == "Bash"]
            check(len(bash_audit) == 1 and bash_audit[0]["verdict"] == "deny" and bash_audit[0]["rule"] == RULE
                  and bash_audit[0]["shadow"] == (mode == "shadow"), f"{mode}: Agent denial and posture audited")
        check(proxy.requests == 0, f"{mode}: no outbound proxy attempts")
        return {"mode": mode, "preflight_exit": preflight.returncode, "claude_exit": result.returncode,
                "benign_read_executed": True, "bash_tool_error": bool(proposed.get("is_error")),
                "proof_marker_written": marker.exists(), "hook_responses": len(hooks), "audit_events": len(audit),
                "audit_bash_verdict": "deny" if bash_audit else None, "mock_messages_requests": model.requests,
                "mock_token_count_requests": model.token_counts, "elapsed_ms": round((time.monotonic()-started)*1000)}
    finally:
        stop(daemon)
        model.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-binary", type=Path, default=Path(__file__).resolve().parents[1]/"target/debug/agentfw.exe")
    parser.add_argument("--claude-binary", type=Path, default=shutil.which("claude") or Path(os.environ.get("USERPROFILE", ""))/".local/bin/claude.exe")
    parser.add_argument("--git-bash", type=Path, default=Path(os.environ.get("ProgramFiles", "C:/Program Files"))/"Git/bin/bash.exe")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("This harness verifies the native Windows Claude host.")
    binaries = [args.agent_binary.resolve(), args.claude_binary.resolve(), args.git_bash.resolve()]
    if not all(path.is_file() for path in binaries):
        parser.error("Build agentfw and provide installed Claude Code and Git Bash executable paths.")
    parent = Path(tempfile.gettempdir()).resolve()
    root = Path(tempfile.mkdtemp(prefix="soup-wall-claude-host-acceptance-")).resolve()
    proxy = LocalServer(BlockingProxy)
    try:
        profile = root / "version-profile"
        profile.mkdir()
        env = environment(profile, proxy, binaries[2])
        version = run([str(binaries[1]), "--version"], root, env).stdout.strip()
        help_output = run([str(binaries[1]), "--help"], root, env).stdout
        check(all(flag in help_output for flag in ["--restricted", "--include-hook-events", "--strict-mcp-config"]),
              "installed Claude supports required isolation and hook observation flags")
        cases = [scenario(mode, root, *binaries, proxy) for mode in ["enforce", "shadow", "offline"]]
        evidence = {"schema_version": 1, "acceptance": "passed", "observed_at_utc": datetime.now(timezone.utc).isoformat(),
                    "claude_version": version, "agent_binary_sha256": binary_hash(binaries[0]),
                    "claude_binary_sha256": binary_hash(binaries[1]), "checks_passed": len(CHECKS), "checks": CHECKS,
                    "cases": cases, "external_provider_requests_sent": 0, "outbound_proxy_attempts": proxy.requests,
                    "synthetic_api_key_only": True, "real_claude_host_executed": True,
                    "policy": "custom fixture policy denies side-effecting actions; shipped attack policy is not evaluated",
                    "offline_fail_open_observed": True, "controlled_shell_commands_executed": 2,
                    "limitation": "Local deterministic fixtures; no real-model task, field soak, adversarial effectiveness, or OS network containment claim."}
    finally:
        proxy.close()
        remove_profile_tree(root, parent)
    evidence["isolated_profiles_removed"] = not root.exists()
    encoded = json.dumps(evidence, indent=2) + "\n"
    if args.evidence:
        args.evidence.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
