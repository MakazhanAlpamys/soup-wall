#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage agentfw in a disposable profile and verify install/preflight/loss/recovery.

This is setup/status preparation, not MCP enforcement or host acceptance.
Only --run starts the supplied binary. No real user settings are installed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
POLICY = "agent_policies: []\ndefault: allow\n"
LIMITATIONS = [
    "Staging an existing binary is not a clean source build or a system-wide installation.",
    "Preflight and health report daemon posture, not independently verified tool protection.",
    "HTTP hooks may fail open; direct server launches and calls outside native admission are unprotected.",
    "Native MCP execution/result witnesses, actual Claude, classifier revisions and the SOU-10 matrix remain separate acceptance work.",
    "Probe timing includes CLI startup and HTTP health; it is not classifier or MCP overhead.",
]


class CheckFailed(RuntimeError):
    pass


def require(condition, label):
    if not condition:
        raise CheckFailed(label)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hashlib.sha256(stream.read()).hexdigest()


def private_environment(profile):
    keep = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "SYSTEMDRIVE"}
    env = {key: value for key, value in os.environ.items() if key.upper() in keep}
    # These are child-process home directories, never changes to the user's shell.
    env.update(HOME=str(profile), USERPROFILE=str(profile), APPDATA=str(profile / "appdata"),
               LOCALAPPDATA=str(profile / "localappdata"), XDG_CONFIG_HOME=str(profile / "config"),
               XDG_CACHE_HOME=str(profile / "cache"), TMPDIR=str(profile), TEMP=str(profile),
               TMP=str(profile), PYTHONDONTWRITEBYTECODE="1")
    return env


def run_cli(binary, arguments, profile, env):
    try:
        return subprocess.run([str(binary), *arguments], cwd=profile, env=env,
                              capture_output=True, timeout=8, check=False)
    except subprocess.TimeoutExpired:
        raise CheckFailed("cli_timeout") from None


def percentile(values, percent):
    require(bool(values), "empty_timing_sample")
    return sorted(values)[max(0, math.ceil(len(values) * percent / 100) - 1)]


def check_probe(binary, profile, env, expected):
    result = run_cli(binary, ["preflight", "--require-enforce", "--timeout-seconds", "1"], profile, env)
    require(result.returncode == expected, "unexpected_preflight_exit")
    marker = {0: b"OK:", 4: b"FAIL:", 2: b"FAIL:"}[expected]
    require(marker in result.stdout + result.stderr, "preflight_status_text_missing")
    return result.returncode


def health(port):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://127.0.0.1:{port}/health", timeout=0.5) as response:
        require(response.status == 200, "health_http_status")
        raw = response.read(4097)
        require(len(raw) <= 4096, "health_body_over_limit")
        value = json.loads(raw)
        require(isinstance(value, dict) and value.get("status") == "ok" and type(value.get("enforce")) is bool, "health_unknown_posture")
        return value["enforce"]


def stop(process):
    if process is not None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        process.wait(timeout=5)


def start(binary, profile, env, port, enforce):
    process = subprocess.Popen([str(binary), "serve"], cwd=profile, env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            require(process.poll() is None, "daemon_exited_before_health")
            try:
                require(health(port) is enforce, "health_posture_mismatch")
                return process
            except (OSError, ValueError):
                time.sleep(0.05)
        raise CheckFailed("daemon_start_timeout")
    except BaseException:
        stop(process)
        raise


def source_identity():
    result = {}
    for name, arguments in [("commit", ["rev-parse", "HEAD"]), ("dirty", ["status", "--porcelain"])]:
        try:
            value = subprocess.run(["git", *arguments], cwd=ROOT, capture_output=True, timeout=5)
            if value.returncode == 0:
                result[name] = bool(value.stdout.strip()) if name == "dirty" else value.stdout.decode().strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
    manifest = ROOT / "fixture-build.json"
    if manifest.is_file():
        result["fixture_build_manifest_sha256"] = sha(manifest)
    result["script_sha256"] = sha(Path(__file__))
    lock = ROOT / "Cargo.lock"
    if lock.is_file():
        result["cargo_lock_sha256"] = sha(lock)
    return result


def acceptance(binary, samples):
    report = {"schema_version": 1, "scope": "disposable-install-and-daemon-status",
              "started_at": datetime.now(timezone.utc).isoformat(), "status": "fail", "checks": [],
              "source": source_identity(), "environment": {"os": platform.system(), "architecture": platform.machine(),
                  "kernel": platform.release(), "python": platform.python_version(), "cpu_count": os.cpu_count()},
              "protection_verified": False, "integrated_candidate_acceptance": "not_run",
              "classifier_revision": None, "profile_revision": None, "limitations": LIMITATIONS,
              "coverage": {"daemon_cli": "not_verified", "native_mcp": "not_tested",
                           "actual_claude": "not_tested", "direct_server": "unprotected"}}
    parent = Path(tempfile.gettempdir()).resolve()
    root = Path(tempfile.mkdtemp(prefix="soup-wall-setup-", dir=parent)).resolve()
    daemon = None
    phase = "stage_binary"
    try:
        started = time.perf_counter()
        binary = binary.resolve(strict=True)
        require(binary.is_file(), "binary_not_a_file")
        installed = root / ("agentfw.exe" if os.name == "nt" else "agentfw")
        shutil.copy2(binary, installed)
        installed.chmod(0o700)
        report["binary_sha256"] = sha(installed)
        report["source_binding"] = "supplied_binary; see caller build record for source binding"
        report["stage_install_ms"] = (time.perf_counter() - started) * 1000
        profile = root / "profile"
        profile.mkdir()
        env = private_environment(profile)
        # Verify that installation does not overwrite an existing unrelated hook setting.
        sentinel = profile / ".claude" / "settings.json"
        sentinel.parent.mkdir()
        sentinel.write_text('{"env":{"SOUP_FIXTURE_SENTINEL":"preserve"}}\n', encoding="utf-8")
        sentinel_hash = sha(sentinel)
        phase = "install"
        installed_result = run_cli(installed, ["install"], profile, env)
        require(installed_result.returncode == 0, "install_failed")
        token_path = profile / ".agentfw" / "token"
        require(token_path.is_file(), "install_token_missing")
        token = token_path.read_bytes().strip()
        require(bool(token) and token not in installed_result.stdout + installed_result.stderr, "install_exposed_token")
        require(sha(sentinel) == sentinel_hash, "unrelated_settings_changed")
        report["checks"].append({"name": "install_preserves_settings_and_hides_token", "status": "pass"})
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        policy = profile / "fixture-policy.yaml"
        policy.write_text(POLICY, encoding="utf-8")
        report["policy_sha256"] = sha(policy)
        config = profile / ".agentfw" / "config.yaml"
        report["config_sha256"] = {}
        def configure(enforce):
            config.write_text(f"bind: 127.0.0.1\nport: {port}\nenforce: {str(enforce).lower()}\n"
                              f"policy: '{policy.as_posix().replace(chr(39), chr(39) * 2)}'\n", encoding="utf-8")
            report["config_sha256"]["enforcing" if enforce else "shadow"] = sha(config)
        for mode, enforce, exit_code in [("shadow", False, 4), ("enforcing", True, 0)]:
            phase = mode
            configure(enforce)
            daemon = start(installed, profile, env, port, enforce)
            probe = check_probe(installed, profile, env, exit_code)
            report["checks"].append({"name": mode, "status": "pass", "preflight_exit": probe,
                                      "health_enforce": enforce, "execution_verified": False})
            if enforce:
                check_probe(installed, profile, env, 0)  # Excluded warm-up sample.
                durations = []
                for _ in range(samples):
                    before = time.perf_counter()
                    check_probe(installed, profile, env, 0)
                    durations.append((time.perf_counter() - before) * 1000)
                report["warm_preflight_cli_ms"] = {"samples": samples, "p50": percentile(durations, 50),
                                                   "p95": percentile(durations, 95), "values": durations}
            stop(daemon)
            daemon = None
        phase = "unavailable"
        check_probe(installed, profile, env, 2)
        report["checks"].append({"name": phase, "status": "pass", "preflight_exit": 2})
        phase = "recovery"
        daemon = start(installed, profile, env, port, True)
        check_probe(installed, profile, env, 0)
        report["checks"].append({"name": phase, "status": "pass", "preflight_exit": 0})
        require(sha(sentinel) == sentinel_hash, "unrelated_settings_changed")
        report["coverage"]["daemon_cli"] = "verified_posture_only"
        report["status"] = "pass"
    except (OSError, ValueError, CheckFailed, subprocess.SubprocessError) as error:
        # Do not retain subprocess output, environment, credentials or private path values.
        report["checks"].append({"name": phase, "status": "fail", "error_type": type(error).__name__,
                                  "errno": getattr(error, "errno", None),
                                  "reason": str(error) if isinstance(error, CheckFailed) else "operation_failed"})
    finally:
        try:
            stop(daemon)
            require(root.parent == parent and root.name.startswith("soup-wall-setup-") and not root.is_symlink(), "unsafe_cleanup_target")
            shutil.rmtree(root)
            require(not root.exists(), "rollback_incomplete")
            report["checks"].append({"name": "remove_owned_install_and_profile", "status": "pass"})
        except (OSError, CheckFailed, subprocess.SubprocessError):
            report["status"] = "fail"
            report["checks"].append({"name": "remove_owned_install_and_profile", "status": "fail"})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--agentfw", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--samples", type=int, default=20)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "not_run", "processes_started": 0, "limitations": LIMITATIONS}, indent=2))
        return 0
    if not args.agentfw or not args.output or not 5 <= args.samples <= 100:
        parser.error("--run requires --agentfw, a fresh --output path, and 5..100 samples")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Reserve before starting anything; never overwrite existing evidence or follow a symlink.
    with args.output.open("x", encoding="utf-8") as stream:
        report = acceptance(args.agentfw, args.samples)
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(f"Setup/status: {report['status']}. Evidence: {args.output}")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
