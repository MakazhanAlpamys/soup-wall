#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build and run the owned, network-isolated Agent/MCP fixture baseline.

Public entry point: python3 scripts/test-environment.py
The two internal modes prepare the image and execute its precompiled tests.
This wrapper never rewrites MCP messages or defines a new tool-event contract.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
SUITES = (
    ("soup-wall-agent", "scenarios"),
    ("agentfw", "mcp_admission"),
    ("agentfw", "native_endpoint"),
    ("agentfw", "judge_endpoint"),
)
LIMITATIONS = [
    "Existing custom-policy/local fixtures only; no agreed new ToolCallEvent integration yet.",
    "Judge failures use deterministic HTTP mocks, not a trained/live classifier.",
    "No external model calls, model weights, GPU or provider credentials.",
    "MCP call execution is witnessed by the fixture server ledger; result release by client stdout.",
    "No general OS sandbox, native macOS/Windows host acceptance or bubblewrap positive-path proof.",
    "Docker on macOS runs Linux containers; a container pass is not native macOS acceptance.",
    "Windows uses Linux Python inside WSL2; a Linux CI pass is not WSL2/Docker Desktop acceptance.",
    "Per-test elapsed time includes fixture startup/cleanup, not classifier or request latency.",
    "Accuracy, uncertainty, false-block rate and request latency require the team's labelled scenarios.",
]
SUMMARY = re.compile(
    r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;"
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def command(arguments, log, timeout, *, cwd=ROOT, env=None):
    """Bound each process group and keep partial diagnostics on failure/timeout."""
    started = time.monotonic()
    result = {"command": list(map(str, arguments)), "log": log.name,
              "exit_code": None, "timed_out": False}
    with log.open("w", encoding="utf-8") as stream:
        try:
            with subprocess.Popen(arguments, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                  stdout=stream, stderr=subprocess.STDOUT,
                                  start_new_session=True) as child:
                try:
                    result["exit_code"] = child.wait(timeout=timeout)
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                    result["timed_out"] = True
                    result["error"] = "command timed out or was interrupted"
        except OSError as error:
            result["error"] = str(error)
            stream.write(str(error) + "\n")
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def classify_test(result, output):
    if result.get("timed_out") or result.get("error"):
        return "error"
    summaries = SUMMARY.findall(output)
    if len(summaries) != 1:
        return "error"
    label, passed, failed, ignored = summaries[0]
    passed, failed, ignored = int(passed), int(failed), int(ignored)
    if passed + failed + ignored != 1:
        return "error"  # An empty/misfiltered invocation is never a pass.
    if ignored == 1 or re.search(r"(?im)(?:^|\.\.\.\s)(?:skipping\b|SKIP:)", output):
        return "skip" if result["exit_code"] == 0 else "error"
    if result["exit_code"] == 0 and label == "ok" and passed == 1:
        return "pass"
    if result["exit_code"] == 101 and label == "FAILED" and failed == 1:
        return "fail"
    return "error"


def overall(cases):
    if not cases or any(case["status"] not in {"pass", "fail", "skip"} for case in cases):
        return "error"
    if any(case["status"] == "fail" for case in cases):
        return "fail"
    if any(case["status"] == "skip" for case in cases):
        return "incomplete"
    return "pass"


def discovery(output):
    names = [line[:-6] for line in output.splitlines() if line.endswith(": test")]
    if not names or len(names) != len(set(names)):
        raise ValueError("test discovery was empty or contained duplicate names")
    return names


def prepare_image():
    """Retain executable paths: Rust embeds CARGO_BIN_EXE_agentfw in MCP tests."""
    inputs = {str(path.relative_to(ROOT)): sha256(path)
              for path in sorted(ROOT.rglob("*")) if path.is_file()
              and "target" not in path.relative_to(ROOT).parts}
    bundle = Path("/bundle")
    manifest = {"suites": [], "inputs_sha256": inputs,
                "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
                "cargo": subprocess.check_output(["cargo", "--version"], text=True).strip(),
                "build_architecture": platform.machine()}
    for package, target in SUITES:
        cargo = ["cargo", "test", "--locked", "--no-run", "--message-format=json",
                 "-p", package, "--test", target]
        with tempfile.TemporaryFile(mode="w+") as messages:
            compiled = subprocess.run(cargo, stdout=messages, check=False)
            messages.seek(0)
            artifacts = [json.loads(line) for line in messages if line.strip()]
        for item in artifacts:
            if item.get("reason") == "compiler-message":
                print(item["message"].get("rendered", item["message"]["message"]), file=sys.stderr)
        compiled.check_returncode()
        executables = [item["executable"] for item in artifacts
                       if item.get("reason") == "compiler-artifact"
                       and item.get("executable") and item["profile"]["test"]
                       and item["target"]["name"] == target]
        if len(executables) != 1:
            raise RuntimeError(f"expected exactly one executable for {package}/{target}")
        executable = Path(executables[0])
        destination = bundle / executable.relative_to("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(executable, destination)
        manifest["suites"].append({"package": package, "target": target,
                                    "executable": str(executable), "sha256": sha256(executable)})
    for relative in ["target/debug/agentfw", "scripts/test-environment.py", "scripts/clean-setup-acceptance.py",
                     "scripts/tests/test_test_environment.py", "LICENSE", "NOTICE"]:
        destination = bundle / ROOT.relative_to("/") / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    manifest["agentfw_sha256"] = sha256(ROOT / "target/debug/agentfw")
    write_json(bundle / ROOT.relative_to("/") / "fixture-build.json", manifest)


def run_inside():
    out = Path("/results")
    build = json.loads((ROOT / "fixture-build.json").read_text())
    result = {"build": build, "cases": [], "status": "error", "started_at": utc_now(),
              "python": platform.python_version(), "architecture": platform.machine(),
              "kernel": platform.release(),
              "packages": subprocess.check_output(
                  ["dpkg-query", "-W", "-f=${Package}=${Version}\n"], text=True).splitlines()}
    write_json(out / "fixture-results.json", result)
    clean_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp/fixture-home",
                 "TMPDIR": "/tmp", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
    Path(clean_env["HOME"]).mkdir(exist_ok=True)
    for suite in build["suites"]:
        executable, target = suite["executable"], suite["target"]
        listed = command([executable, "--list", "--format=terse"],
                         out / f"{target}-discovery.log", 15, env=clean_env)
        try:
            if listed["exit_code"] != 0:
                raise ValueError("test executable could not enumerate cases")
            if sha256(executable) != suite["sha256"]:
                raise ValueError("test executable digest changed")
            names = discovery((out / listed["log"]).read_text())
        except ValueError as error:
            result["cases"].append({"suite": target, "name": "discovery", "status": "error",
                                    "reason": str(error), **listed})
            write_json(out / "fixture-results.json", result)
            continue
        for index, name in enumerate(names):
            log = out / f"{target}-{index:03}.log"
            executed = command([executable, "--exact", name, "--nocapture", "--test-threads=1"],
                               log, 60, env=clean_env)
            status = classify_test(executed, log.read_text(encoding="utf-8", errors="replace"))
            result["cases"].append({"suite": target, "name": name, "status": status, **executed})
            print(f"{status.upper()}: {target}::{name}", flush=True)
            write_json(out / "fixture-results.json", result)
    result["status"] = overall(result["cases"])
    result["finished_at"] = utc_now()
    write_json(out / "fixture-results.json", result)
    return 0 if result["status"] == "pass" else 1


def write_report(out, report):
    write_json(out / "results.json", report)
    cases = report.get("fixture", {}).get("cases", [])
    counts = Counter(case["status"] for case in cases)
    lines = ["# Local Agent/MCP fixture baseline", "", f"Status: **{report['status']}**", "",
             "This is the environment baseline, not completion of the shared team milestone.", "",
             "## Environment", "", "```json", json.dumps(report["environment"], indent=2), "```", "",
             "The exact image inputs, binary hashes and runtime packages are in results.json.", "",
             "## Outcomes", "", f"Pass: {counts['pass']}; fail: {counts['fail']}; "
             f"error: {counts['error']}; skip: {counts['skip']}.", ""]
    if report.get("error"):
        lines.extend([f"Infrastructure error: {report['error']}", ""])
    lines.extend(["| Suite / case | Status | Fixture elapsed (ms) | Log |",
                  "| --- | --- | ---: | --- |"])
    for case in cases:
        lines.append(f"| {case['suite']} / {case['name']} | {case['status']} | "
                     f"{case['elapsed_ms']} | [{case['log']}]({case['log']}) |")
    lines.extend(["", "## Coverage and limits", ""] + [f"- {item}" for item in LIMITATIONS])
    lines.extend(["", "## Not measured", "",
                  "Classification accuracy, uncertainty, false-block rate and request latency: "
                  "**not measured**. Unit-test pass counts are not classifier metrics.", "",
                  "## Reproduce", "", "Run from the recorded source revision with the same "
                  "platform. Dirty worktrees require the exact recorded input files as well.", "",
                  "```sh", f"python3 scripts/test-environment.py --platform "
                  f"{report['environment'].get('platform', 'linux/amd64')}", "```", "",
                  "First build downloads dependencies; the test container has no external network.", ""])
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")


def host_environment():
    """Describe the launcher host separately from the Docker container platform."""
    kernel = platform.release()
    wsl = sys.platform == "linux" and (
        "microsoft" in kernel.lower() or "wsl" in kernel.lower()
        or bool(os.environ.get("WSL_DISTRO_NAME"))
        or bool(os.environ.get("WSL_INTEROP"))
    )
    result = {"host_os": platform.system(), "host_architecture": platform.machine(),
              "host_python": platform.python_version(), "host_kernel": kernel,
              "wsl_detected": wsl}
    if wsl:
        # Detection is not proof of WSL generation; record `wsl --list --verbose`
        # separately on Windows. Do not collect the rest of the host environment.
        result["wsl_distribution"] = os.environ.get("WSL_DISTRO_NAME", "unknown")
    return result


def host_run(args):
    if sys.platform == "win32":
        raise ValueError(
            "Windows: open your WSL2 Linux distribution (for example Ubuntu) and run "
            "python3 scripts/test-environment.py using Linux Python. Enable Docker Desktop's "
            "WSL integration for that distribution. Native Windows Python is not supported; "
            "see docs/DEVELOPMENT.md#running-from-windows-with-wsl2")
    if sys.platform not in {"linux", "darwin"}:
        raise ValueError("the host launcher requires Linux (including WSL2) or macOS")
    if os.getuid() == 0:
        raise ValueError("run the launcher as a normal user with Docker access, not through sudo")
    base = Path(args.output).resolve()
    base.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=base))
    report = {"schema_version": 1, "scope": "local-fixture-baseline", "status": "error",
              "started_at": utc_now(), "environment": host_environment(),
              "steps": [], "limitations": LIMITATIONS}
    name = "soup-wall-fixtures-" + out.name.lower()
    container_attempted = False
    print(f"Results: {out}", flush=True)
    write_report(out, report)

    def step(label, arguments, timeout):
        print(f"{label}...", flush=True)
        result = command(arguments, out / f"{label}.log", timeout)
        report["steps"].append({"name": label, **result})
        write_report(out, report)
        if result["exit_code"] != 0:
            hint = ""
            if label in {"docker-info", "buildx-version"} and report["environment"]["wsl_detected"]:
                hint = (" Start Docker Desktop in Linux-container mode and enable Settings > "
                        "Resources > WSL Integration for this distribution. Retry from its "
                        "Linux terminal; see docs/DEVELOPMENT.md#running-from-windows-with-wsl2.")
            raise RuntimeError(f"{label} failed; see {label}.log.{hint}")
        return (out / result["log"]).read_text(encoding="utf-8", errors="replace")

    try:
        revision = step("source-revision", ["git", "rev-parse", "HEAD"], 10).strip()
        dirty = step("source-state", ["git", "status", "--porcelain"], 10)
        report["environment"].update(source_revision=revision, dirty_worktree=bool(dirty.strip()))
        info = json.loads(step("docker-info", ["docker", "info", "--format",
                              '{"version":"{{.ServerVersion}}","os":"{{.OSType}}",'
                              '"architecture":"{{.Architecture}}"}'], 30))
        if info["os"] != "linux":
            raise RuntimeError("Docker must use Linux containers")
        architectures = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
        selected = args.platform or "linux/" + architectures[info["architecture"]]
        report["environment"].update(platform=selected, docker=info,
                                     cross_architecture=selected != "linux/" + architectures[info["architecture"]])
        report["environment"]["buildx"] = step("buildx-version", ["docker", "buildx", "version"], 15).strip()
        step("build", ["docker", "buildx", "build", "--load", "--platform", selected, "--progress=plain",
                       "--file", "deploy/Dockerfile.test", "--iidfile", str(out / "image-id"), "."], 2400)
        image = (out / "image-id").read_text().strip()
        report["environment"].update(image_id=image, network="none", cpus=2, memory="2g",
                                      readonly_root=True, capabilities="none")
        container_attempted = True
        # Only the fresh output directory is mounted. No source, profile, tokens or Docker socket.
        run = command(["docker", "run", "--name", name, "--platform", selected,
                       "--network=none", "--read-only", "--cap-drop=ALL",
                       "--security-opt=no-new-privileges:true", "--pids-limit=256",
                       "--cpus=2", "--memory=2g", "--user", f"{os.getuid()}:{os.getgid()}",
                       "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
                       "--mount", f"type=bind,src={out},dst=/results", image],
                      out / "container.log", 900)
        report["steps"].append({"name": "container", **run})
        if (out / "fixture-results.json").is_file():
            report["fixture"] = json.loads((out / "fixture-results.json").read_text())
        report["status"] = report.get("fixture", {}).get("status", "error")
        cases = report.get("fixture", {}).get("cases", [])
        if report["status"] == "pass" and (
            overall(cases) != "pass" or {case["suite"] for case in cases} != {target for _, target in SUITES}
        ):
            report["status"] = "error"
        if run["exit_code"] != 0 and report["status"] == "pass":
            report["status"] = "error"
        inspection = json.loads(step("container-state", ["docker", "inspect", "--format",
            '{"state":{{json .State}},"network":{{json .HostConfig.NetworkMode}},'
            '"read_only":{{json .HostConfig.ReadonlyRootfs}},"user":{{json .Config.User}},'
            '"cap_drop":{{json .HostConfig.CapDrop}},"memory":{{json .HostConfig.Memory}},'
            '"nano_cpus":{{json .HostConfig.NanoCpus}}}', name], 15))
        report["environment"]["container"] = inspection
        if inspection["state"]["OOMKilled"] or inspection["state"]["Running"]:
            report["status"] = "error"
        if report["status"] == "error":
            report["error"] = "container run incomplete or unavailable; see container.log"
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        report["error"] = str(error)
        report["status"] = "error"
    finally:
        if container_attempted:
            cleanup = command(["docker", "rm", "--force", name], out / "cleanup.log", 30)
            report["steps"].append({"name": "cleanup", **cleanup})
            if cleanup["exit_code"] != 0:
                report["status"] = "error"
                report["error"] = f"container cleanup failed; inspect {name} and cleanup.log"
        report["finished_at"] = utc_now()
        write_report(out, report)
    print(f"Baseline: {report['status']}. Report: {out / 'report.md'}", flush=True)
    if report.get("error"):
        print(f"Error: {report['error']}", file=sys.stderr)
    return 0 if report["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=["linux/amd64", "linux/arm64"],
                        help="default: the Docker daemon's architecture")
    parser.add_argument("--output", default=str(ROOT / "target/test-environment"),
                        help="parent directory for a new, unique result directory")
    internal = parser.add_mutually_exclusive_group()
    internal.add_argument("--prepare-image", action="store_true", help=argparse.SUPPRESS)
    internal.add_argument("--inside-container", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.prepare_image:
        prepare_image()
        return 0
    if args.inside_container:
        return run_inside()
    try:
        return host_run(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
