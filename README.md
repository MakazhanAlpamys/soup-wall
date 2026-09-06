<!--
DRAFT README for the public thin-Core repository (core + agent + agentfw + adapter + bench).
`{{PROJECT_NAME}}` is a placeholder: the name is not decided. Binary names (`agentfw`,
`llm-firewall-bench`) are the current ones and will likely follow the rename.
Every claim below is one the repository can back today; nothing here is aspirational.
-->

# {{PROJECT_NAME}}

A firewall for what an AI agent *does* — every tool call, tool result, MCP handshake and
subagent spawn — that runs on one machine, needs no account, and makes no network call of
its own.

Detection tells you content looks dangerous. This layer decides whether the *action* is
allowed to happen: untrusted content driving a destructive command, a secret heading out
over the network, a subagent asking for tools its parent never had, an MCP server quietly
rewriting a tool description. It is deterministic, local, and shadow-first.

Pure Rust. Apache-2.0.

## What is in this repository

| Crate | Purpose |
|---|---|
| `core` | Text detectors — prompt injection (signatures, heuristics, optional local classifier), secrets, PII, improper output — with OWASP LLM Top 10 and MITRE ATLAS tags, risk scoring, YAML policy |
| `agent` | The agent reference monitor: taint tracking, action classes, egress-host control, subagent authority, MCP manifest signals, first-match policy |
| `agentfw` | The daemon: Claude Code hook collector, MCP proxy with manifest pinning, local JSONL audit, replay, preflight, human approval grants, guarded execution |
| `adapter` | The versioned local decision contract a control plane would speak, if you add one |
| `bench` | Reproducible regression corpus and the policy-change gate |

Not in this repository: the HTTP proxy for OpenAI/Anthropic traffic, SSO, SCIM, multi-tenant
administration, usage ledgers and billing. Those are the commercial layer.

## Quickstart

```sh
cargo build --release
./target/release/agentfw install        # prints the settings.json hook block + instructions
export AGENTFW_TOKEN=$(cat ~/.agentfw/token)
./target/release/agentfw serve          # shadow mode: records verdicts, blocks nothing
./target/release/agentfw preflight      # exit 2 if the daemon is down
```

Run your normal sessions. Nothing is blocked yet — that is deliberate, see below.

## How enforcement is turned on

The daemon starts in **shadow mode** and stays there until you switch it. The way out is a
sequence, not a flag flip:

1. **Soak.** Run real work in shadow mode. `agentfw replay` refuses to recommend anything
   below 500 events across 20 sessions, because a recommendation drawn from an afternoon of
   traffic is a guess.
2. **Read the verdict.** `agentfw replay` ends in one of three lines: `not enough evidence`,
   `review required`, or `evidence supports enforcing`. When it says review is required it
   deliberately does **not** call the interruptions false positives — it cannot tell a caught
   attack from a false alarm, only you know what you intended.
3. **Narrow the wrong rule, then gate it.** If a rule interrupted legitimate work, narrow it in
   your policy YAML, then prove the edit did not weaken anything:
   ```sh
   llm-firewall-bench --agent crates/bench/corpora/agent_sessions.jsonl --policy my-policy.yaml
   ```
   This replays the reviewed attack and benign corpus under your policy and exits non-zero if
   any reviewed attack is now missed or any reviewed benign session is now interrupted.
4. **Enforce, then confirm it took.** Set `enforce: true` in `~/.agentfw/config.yaml`, restart,
   and run `agentfw preflight --require-enforce` — it exits 4 if you are still in shadow.

## Approving one dangerous call

When policy says `ask`, you can approve exactly that call and nothing else:

```sh
agentfw approve --session <id> --tool Bash --args '{"command":"rm -rf ./build"}'
```

The approval is signed, expires in five minutes, is single-use, and is bound to those exact
arguments: approving `rm -rf ./build` does not authorize `rm -rf /`. It withdraws this
firewall's objection to one `ask`; it does not override your own Claude Code permission
rules, and a policy `deny` stays denied. Revoke before use by deleting the file it prints.

## MCP servers

Run a server through the proxy and its tool manifest is pinned at handshake:

```sh
agentfw mcp --id docs -- npx some-mcp-server
```

If the manifest later changes, the daemon reports exactly what moved — which tool, which
field, and the new description text — rather than only that something changed. The excerpt
is bounded, because that text comes from the server under suspicion. The last ten superseded
manifests are kept per server.

## Limitations, stated plainly

- **The Claude Code hook fails open.** If the daemon is not running, the host waits out the
  hook timeout and runs the tool anyway. The host decides that and this project cannot override
  it. The hook is a decision and audit layer, not a security boundary; `agentfw preflight` exists
  so a stopped daemon is a loud, scriptable failure instead of a silent one. Only the guarded
  execution path (`agentfw guarded-shell` and the typed file/fetch commands) fails closed,
  because it owns process creation rather than advising the host.
- **Shadow mode is the default.** Until you complete the sequence above, nothing is blocked.
- **The regression corpus is hand-authored.** Nineteen attack and twenty-one benign sessions,
  written for this repository. Passing it means the reviewed attack shapes are still caught and
  the reviewed benign sessions still run; it says nothing about novel attacks. No held-out or
  third-party evaluation (AgentDojo, InjecAgent) has been run. No detection percentage is
  published here on purpose.
- **Classifiers are triage, not gates.** Every published prompt-injection classifier has been
  bypassed by adaptive attacks. The deterministic policy on actions is the control; the text
  detectors reduce risk, they do not prevent it.
- **Approval grants defend against the agent approving itself, not against you.** A sandboxed
  tool process cannot read the daemon key and so cannot mint or replay an approval. A local
  attacker already running as the operator can read the key; the grant does not defend against
  that and does not claim to.
- **Guarded execution is Linux-only** (bubblewrap). Other hosts fail closed.
- **The optional ML classifier needs model assets** you fetch yourself (`scripts/fetch-model.sh`)
  and the `ml` feature. Without it the injection detector runs signatures and heuristics only.

## Security posture you can check

- Builds and passes its tests with the commercial proxy crate absent; `cargo audit` on that
  tree reports no vulnerabilities.
- `unsafe` appears in exactly two places, both memory-mapping a model file, both documented
  with the invariant they rely on.
- Every source file carries an SPDX identifier.
- The full Git history was scanned with the project's own secret detector: every hit is a
  detection pattern, a test fixture, or a declared test-only key pair.
- Audit lines record the trust class of tainted content and the nonce of any human approval,
  so a log reader can tell "policy allowed this" from "a human allowed this" without reading
  the source.

## Layout note

`policies/default.yaml` must stay at the repository root: `core` embeds it at compile time
and a checkout without it fails to build with the path in the error.

## Provenance and license

Apache-2.0. Derived from [carbon-evolution/llm-firewall](https://github.com/carbon-evolution/llm-firewall)
by Arthur Lin and contributors; upstream history and attribution are retained, see `NOTICE`.
The intake rules for any external code, model, or dataset are in `docs/PROVENANCE.md`.
