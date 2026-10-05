# Claude Code host acceptance on Windows

This check launches the installed Claude Code CLI against a deterministic local
Anthropic Messages fixture. It tests the real HTTP-hook consumer and real tool
execution without a paid model request. The local response sequence proposes
one `Read` of a synthetic README, then one fixed Bash command that writes a
harmless marker inside a disposable workspace. A custom Agent policy denies
side-effecting actions. It is a host integration check, not an effectiveness
evaluation of the shipped attack policy.

## Run

Use Python 3.10 or later, an installed native Claude Code with `--restricted`
and `--include-hook-events`, and Git for Windows. From the repository root:

```powershell
cargo build --locked -p agentfw --bin agentfw
if ($LASTEXITCODE -ne 0) { throw 'Agent build failed.' }
python .\scripts\windows-claude-host-acceptance.py --evidence .\target\windows-claude-host-acceptance.json
```

For executables installed elsewhere, supply `--agent-binary`, `--claude-binary`,
or `--git-bash` with their absolute paths. The harness never downloads or updates
Claude Code. Unsupported CLI flags or any unexpected outcome fail the check.

The harness creates fresh profiles, explicit settings, and workspaces. It copies
only OS/runtime paths into child environments, sets `USERPROFILE` and
`CLAUDE_CONFIG_DIR` to disposable directories, and uses a fixture API key with
`ANTHROPIC_BASE_URL` pointing to loopback. Nonessential traffic, updates, feature
flag fetching, account MCP servers, plugin auto-install, memory, background
tasks, and bundled skills are disabled using documented [Anthropic environment
options](https://code.claude.com/docs/en/env-vars).

The real host runs with `--restricted`, the generated Agent hooks supplied
through `--settings`, only `Read,Bash` tools, an empty strict MCP configuration,
and no session persistence. These [CLI options](https://code.claude.com/docs/en/cli-reference)
keep user/project customizations out of the run. Managed machine policy still
applies; the harness does not modify it. A loopback proxy refuses outbound proxy
requests, and acceptance requires zero such attempts. This is not a claim of
OS-level network isolation.

## Expected outcomes

| Case | Benign Read | Fixed marker proposal | Agent audit | Required preflight |
| --- | --- | --- | --- | --- |
| Enforce | Executes | Denied before execution; marker absent | `deny`, `shadow: false` | Exit 0 |
| Shadow | Executes | Executes; only the harmless marker is written | `deny`, `shadow: true` | Exit 4 |
| Offline | Executes | Executes after actual HTTP-hook connection failure | No daemon audit | Exit 2 |

The controls establish that the Agent's denial causes the enforcing host to
prevent the proposed effect. The same host permission setup permits the fixed
command in shadow and offline cases. Both marker writes are confined to
disposable workspaces, and the harness removes them together with its profiles
after stopping its own daemon processes. It checks resolved cleanup paths and
handles Claude state paths longer than Windows `MAX_PATH`.

Offline behavior is deliberately visible: a caller that ignores preflight can
continue without Agent inspection. Anthropic documents HTTP connection errors
as non-blocking; a block requires a successful response containing decision
JSON. See the [HTTP-hook response contract](https://code.claude.com/docs/en/hooks#http-response-handling).
A refused connection can return immediately. The configured five-second timeout
limits a stalled request; it does not mean every offline call waits five seconds.

The JSON evidence includes host version and binary hashes, check names, hook
counts, audit counts, preflight exits, marker outcomes, timing, and local request
counts. It excludes tokens, provider keys, paths, prompts, tool arguments, raw
host output, and audit bodies. SDK-computed costs for fixture token counts are
not provider charges and are not copied into the evidence.

A [recorded run](evidence/windows-claude-host-acceptance-2026-10-04.json) passed
with native Claude Code 2.1.289 on October 4, 2026. All nine Messages requests
reached the authenticated local fixture, with zero outbound proxy attempts.
This does not replace real-model task evaluation, shadow soaking, or testing
new attacks. It directly establishes the installed host's decision handling and
connection-failure behavior for these controlled tool calls.
