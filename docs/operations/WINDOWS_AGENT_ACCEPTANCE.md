# Windows Agent installation and acceptance

The native Agent uses `%USERPROFILE%\.agentfw` on Windows. `agentfw install`
creates a private token and prints the Claude Code hook settings; it does not
edit Claude settings or create `config.yaml`. An absent config uses loopback
port 8787 and shadow mode. Directory, token, and audit access is restricted to
the current Windows user and LocalSystem through protected DACLs.

From a release archive, run these commands in PowerShell:

```powershell
.\agentfw.exe install
$env:AGENTFW_TOKEN = (Get-Content -Raw -LiteralPath "$env:USERPROFILE\.agentfw\token").Trim()
.\agentfw.exe serve
```

Merge the JSON printed by `install` into the existing Claude Code settings.
Start Claude Code from a shell containing `AGENTFW_TOKEN`. Keep the daemon
running in the first terminal. In another terminal, check before a session:

```powershell
.\agentfw.exe preflight
if ($LASTEXITCODE -ne 0) { throw 'Agent daemon is unavailable or unhealthy.' }
claude
```

Shadow mode computes and audits decisions but emits no hook interruption. After
reviewing real sessions with `agentfw replay`, create or edit
`%USERPROFILE%\.agentfw\config.yaml` with `enforce: true`, restart the daemon,
and gate sessions with `agentfw preflight --require-enforce`. Exit status 4 means
shadow mode when enforcement is required; 2 means unreachable; 3 means an
unhealthy or unrecognized health response. Replay refuses to recommend promotion
below 500 events across 20 sessions. A synthetic acceptance run cannot satisfy
that field evidence requirement.

## Reproducible local check

Build from the repository root and run with Windows PowerShell 5.1 or PowerShell 7:

```powershell
cargo build --locked -p agentfw --bin agentfw
if ($LASTEXITCODE -ne 0) { throw 'Agent build failed.' }
.\scripts\windows-agent-acceptance.ps1 -EvidencePath .\target\windows-agent-acceptance.json
```

To test an unpacked release archive instead of the development build:

```powershell
.\scripts\windows-agent-acceptance.ps1 -AgentBinary C:\release\agentfw.exe -EvidencePath .\target\release-agent-acceptance.json
```

The script creates a disposable profile with spaces and an apostrophe in its
path and injects `USERPROFILE` only into Agent child processes. It selects an
unused loopback port, starts and stops its own daemon, and removes the generated
profile on success or failure. It preserves the shell's prior `AGENTFW_TOKEN`.
It does not touch the actual user's Agent files or Claude settings.

The run checks clean installation, the printed PowerShell token command, token
reuse, default and configured hook settings, protected directory/token/audit
DACLs, health posture and authenticated hook behavior, benign calls, and a synthetic
untrusted result followed by a credential-upload proposal. It repeats the hook
scenario in default shadow mode and enforcement mode. The proposed command is
sent as JSON only; it is never executed. The `.invalid` URLs are never fetched.
Missing and incorrect tokens must return HTTP 401. Audit decisions and flags,
replay's evidence threshold, and offline preflight failure are checked too.

Evidence is timestamped aggregate JSON containing checks, audit counts, mode
decisions, observed latency, binary hash, and runtime versions. It contains no
token, profile path, hook payload, or raw audit content. The Windows CI job runs
the same script and uploads its evidence artifact.

A [recorded local run](evidence/windows-agent-acceptance-2026-10-04.json) passed
70 checks on Windows with PowerShell 5.1 and 7.6.5 on October 4, 2026. It used a
debug build; its latency values are diagnostic observations, not release
performance results. Caller token preservation and cleanup after an intentional
failure were verified separately.

## What this check establishes

This verifies the native daemon and CLI over real loopback HTTP and Windows
filesystem access controls. It does not launch Claude Code, execute an agent
task, measure novel-attack effectiveness, or verify Linux process containment.
The offline step establishes that the endpoint is unavailable and preflight
exits 2 with a fail-open explanation. Claude Code's documented behavior of
proceeding after an HTTP-hook timeout remains a host limitation, not a behavior
measured by this daemon-only run. Keep the host's own permissions configured;
use preflight to stop a wrapper before starting an unchecked session.
