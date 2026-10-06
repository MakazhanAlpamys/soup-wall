# Soup Wall

<img src="docs/img/soup-wall-mark.svg" alt="Soup Wall mark" width="88">

**Open-source protection for AI apps and agents.** Soup Wall inspects model traffic and the actions an agent takes, applies local policy, and records decisions for review. The complete source for the agent, gateway, and self-hosted control plane is available under Apache-2.0.

[![CI](https://github.com/MakazhanAlpamys/soup-wall/actions/workflows/ci.yml/badge.svg)](https://github.com/MakazhanAlpamys/soup-wall/actions/workflows/ci.yml)
[![Supply chain](https://github.com/MakazhanAlpamys/soup-wall/actions/workflows/supply-chain.yml/badge.svg)](https://github.com/MakazhanAlpamys/soup-wall/actions/workflows/supply-chain.yml)
![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)

## Choose where to start

| Surface | What it does | Runs as |
| --- | --- | --- |
| **Soup Wall Agent** | Reviews tool calls, tool results, MCP manifests, and subagent authority. Starts in shadow mode. | `agentfw` daemon and CLI |
| **Soup Wall Gateway** | Inspects OpenAI Chat Completions and Responses, and Anthropic Messages traffic before and after provider calls. | `llm-firewall` HTTP binary |
| **Soup Wall Console** | Manages self-hosted tenants, tokens, policy, audit, identity, and usage. | Built into the Gateway when `tenant_store` is enabled |

The `llm-firewall` binary and `LLM_FW_*` settings retain their established names for compatibility; release archives also provide a `soup-wall-gateway` binary name. They are part of Soup Wall; no paid license or Soup Wall account is required to build or self-host them. The local Agent does not send telemetry to Soup Wall. The Gateway contacts the model providers you configure, and optional features can contact your PostgreSQL, Redis, identity provider, or webhook destination.

## Build

Install the current stable Rust toolchain with `rustfmt` and `clippy`, then run from the repository root:

```sh
cargo build --locked --release --workspace
cargo test --locked --workspace
```

The checked-in `firewall.yaml` loads `policies/default.yaml` at runtime, and a shipped-policy test expects that path at the repository root. Optional ML features need model assets fetched separately; the default build uses signatures and heuristics.

## Agent: protect a local Claude Code session

```sh
./target/release/agentfw install
./target/release/agentfw serve
```

`install` creates the local daemon token and prints the hook block and instructions to add to Claude Code's `settings.json`; apply that printed block before starting a session. In the shell that launches Claude Code, export the token as the printed instructions show (for example, `export AGENTFW_TOKEN="$(cat ~/.agentfw/token)"`). Keep `serve` running. In another terminal, check the daemon:

```sh
./target/release/agentfw preflight
```

The default `~/.agentfw/config.yaml` posture is **shadow mode**: verdicts are written to `~/.agentfw/audit.jsonl`, but the hook does not block tools. After reviewing real sessions with `agentfw replay`, gate any policy changes against the reviewed corpus:

```sh
./target/release/soup-wall-bench --agent crates/bench/corpora/agent_sessions.jsonl --policy my-policy.yaml
```

Then set `enforce: true` in `~/.agentfw/config.yaml`, restart the daemon, and confirm with `agentfw preflight --require-enforce`. The replay command requires at least 500 events across 20 sessions before it recommends enforcement; a human still has to review interruptions. See [Agent enforcement and limitations](#agent-enforcement-and-limitations).

On Windows, `install` prints a PowerShell token command and uses `%USERPROFILE%\.agentfw`. See [Windows Agent installation and acceptance](docs/operations/WINDOWS_AGENT_ACCEPTANCE.md) for native setup and a disposable check of installation, ACLs, shadow/enforcement decisions, audit, and offline preflight.

For a reviewed stdio MCP server, [opt-in MCP admission](docs/operations/MCP_STDIO_ADMISSION.md)
gates supported calls before execution and text results before release to the
client. Enable it explicitly with `agentfw mcp --native-admission -- ...` and
an operator-installed native registry. Its bounded contract fails closed;
the legacy manifest proxy and Claude HTTP hooks retain their existing behavior.

## Gateway: inspect provider traffic

The checked-in `firewall.yaml` binds to `127.0.0.1:8080` by default. With its default settings, your application sends its existing provider authorization header through the Gateway, which forwards it upstream. From the repository root:

```sh
./target/release/llm-firewall preflight
./target/release/llm-firewall
```

`preflight` validates configuration and policy without opening an HTTP listener or making external connections. In another terminal, `curl http://127.0.0.1:8080/healthz` checks the running process. Set an OpenAI SDK base URL to `http://127.0.0.1:8080/v1` for Chat Completions or Responses; set an Anthropic SDK base URL to `http://127.0.0.1:8080` for native Messages. Real model requests contact the provider and may incur provider charges.

On the local default bind, `proxy_auth` and `tenant_store` are off. A non-loopback bind requires one of those authentication modes, and you should terminate HTTPS at a trusted edge. `agent_inspection` and `capability_policy` are separate, opt-in controls that start in shadow mode when enabled. The Gateway's request/response policy is configured by `firewall.yaml` and `policies/default.yaml`; inspect those files before sending production traffic. See [Self-hosting guide](docs/SELF_HOSTING.md).

## Console: run your own control plane

For a local, single-instance operator console, set `tenant_store.enabled: true` in `firewall.yaml` and provide a long random `LLM_FW_ADMIN_TOKEN` through the environment or a local `.env` file that you do not commit. Leave `tenant_store.backend: sqlite` for this first run. Restart the Gateway, then open [http://127.0.0.1:8080/admin](http://127.0.0.1:8080/admin) and enter the admin token. `proxy_auth` and `tenant_store` cannot be enabled together.

The customer workspace at `/customer` requires configured OIDC or SAML federation and an active membership; there is no local password login. This source also includes an organization-scoped SCIM subset, service accounts, immutable usage events, reconciliation, quotas, retention, and an **invoice preview**. The preview is read-only and non-final. There is no final-invoice or payment-collection workflow. See [Self-hosting guide](docs/SELF_HOSTING.md) for deployment boundaries and prerequisites.

## What is in the workspace

| Crate | Purpose |
| --- | --- |
| `soup-wall-core` | Text detectors, scoring, masking, taxonomy, and YAML policy |
| `soup-wall-agent` | Agent events, taint, action and egress checks, subagent authority, and policy |
| `agentfw` | Local daemon, Claude Code hook collector, MCP proxy, audit, replay, approval, and guarded execution |
| `llm-firewall` | Gateway, provider adapters, and self-hosted control plane |
| `soup-wall-adapter` | Versioned decision and audit contract |
| `soup-wall-bench` | Reproducible detector and agent-policy regression tooling |

## Agent enforcement and limitations

- **The Claude Code hook fails open if the daemon is unavailable.** Connection errors or timeouts do not prevent tool execution; the host's own permissions still apply. Run `agentfw preflight` before a session. The guarded execution commands fail closed because they own process creation; guarded shell execution requires Linux and bubblewrap. A [Windows host acceptance](docs/operations/CLAUDE_HOST_ACCEPTANCE.md) exercises this boundary against local deterministic model fixtures.
- **Shadow mode is the Agent default.** It audits would-be decisions until you explicitly enable enforcement. The Gateway's agent and capability controls are also off by default. Inspect each policy and mode before relying on a block.
- **The reviewed agent corpus is hand-authored.** Its 19 attack and 21 benign sessions are a regression check, not a measure of protection against new attacks. A [pinned independent historical replay](docs/benchmarks/independent-history-replay.md) records the original adapter's semantic limits. Opt-in [native admission](docs/benchmarks/native-admission.md) adds installed tool semantics and result/context gates; actual tool-registry coverage and a live held-out third-party agent benchmark remain open. Text classifier results and their limits are in [benchmark methodology](docs/methodology.md).
- **A detector score is not a guarantee.** Adaptive attacks can evade text detectors; the action policy and the host's own permissions remain part of the security boundary. A Soup Wall approval for one `ask` call does not override the host's permissions or a `deny` rule.
- **Identity and billing need operational review.** Local OIDC/SAML fixtures and a constrained SCIM implementation do not establish compatibility with a real customer IdP. Usage evidence and invoice previews are not final invoices, taxes, credits, refunds, or payment collection.

Security reports, including Gateway and control-plane bypasses, belong in [SECURITY.md](SECURITY.md). Contributions are described in [CONTRIBUTING.md](CONTRIBUTING.md).

The [public roadmap](docs/ROADMAP.md) lists the remaining full-workspace release checks and field validation; the [changelog](CHANGELOG.md) records released changes.
The [architecture guide](docs/ARCHITECTURE.md) maps the three product surfaces to their crates and decision boundaries. The [upgrade guide](docs/UPGRADING.md) covers existing installations, and the [production runbook](docs/operations/PRODUCTION_RUNBOOK.md) covers readiness and alerts. Operators can also use the [Agent sandbox guide](docs/operations/SANDBOX.md), [identity checks](docs/operations/IDENTITY_INTEROPERABILITY.md), and [manual staging drills](docs/operations/STAGING_DRILLS.md).

## Provenance and license

Soup Wall is licensed under [Apache-2.0](LICENSE). It is derived from [carbon-evolution/llm-firewall](https://github.com/carbon-evolution/llm-firewall) by Arthur Lin and contributors. Keep the upstream attribution in [NOTICE](NOTICE) and the source intake rules in [docs/PROVENANCE.md](docs/PROVENANCE.md). Model weights and third-party datasets have separate terms and are not silently bundled with this source.
