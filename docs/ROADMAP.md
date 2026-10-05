# Soup Wall roadmap

Status: public full-source direction, October 2026. This is a forward-looking plan, not a certification or a list of completed deployments. `[x]` means implemented in this workspace; `[ ]` means release or field evidence is still needed.

## Product direction

Soup Wall is one Apache-2.0 project with three self-hosted surfaces: **Agent** for local agent actions, **Gateway** for provider traffic, and **Console** for organization controls. The source distribution has no paid feature gate or required Soup Wall service. Hosting and support may be offered separately without reserving product features in a closed codebase.

Security claims are based on actions and outcomes, not a classifier score alone. A detector may identify suspicious content; policies and the host runtime determine whether an action can proceed. The Agent's default shadow posture and the Claude Code hook's fail-open behavior must stay visible to operators.

## Available in the combined source

- [x] Local Agent daemon, Claude Code hooks, MCP manifest checks, audit/replay, approval grants, and Linux guarded execution.
- [x] OpenAI Chat Completions and Responses, and Anthropic Messages Gateway with input/output inspection, bounded streaming, policy, and audit.
- [x] Self-hosted operator and customer control-plane code: tenants, tokens, server-side roles, OIDC/SAML, a constrained SCIM subset, policy delivery, usage evidence, reconciliation, quotas, retention, and read-only invoice previews.
- [x] Local build, tests, policy regression corpus, deployment examples, and supply-chain workflow definitions.

These are implementation statements. They do not mean every provider, IdP, or deployment environment has been validated externally.

## Next release gates

The active [execution checkpoints](operations/ROADMAP_EXECUTION.md) track the
remaining work, reviewed issues and maintenance PRs, and the evidence for each
completed step.

1. [x] **Verify the full import.** Review code and Git history for secrets and customer material; preserve license and attribution; review every bundled dependency, model, dataset, and image. Confirm the source snapshot builds without access to the former private repository.
2. [x] **Make the full workspace green.** PR #15 and the v0.4.0 release ran formatting, Clippy, default and all-feature tests, advisory review, SBOM generation, CodeQL, Docker, PostgreSQL, Redis, and identity fixtures. The one narrowly justified RSA advisory exception is documented in `docs/PROVENANCE.md`.
3. [ ] **Verify a self-hosted deployment.** [v0.4.0](https://github.com/MakazhanAlpamys/soup-wall/releases/tag/v0.4.0) publishes four platform archives, checksums, six SBOMs, a public Gateway image, known limitations, and upgrade guidance. [Local release acceptance](operations/LOCAL_RELEASE_ACCEPTANCE.md) now records archive verification, preflight, SQLite Console, loopback provider traffic, PostgreSQL/Redis failure recovery, and encrypted restore. Managed staging, TLS, real-provider traffic, and alert-routing evidence remain to be recorded.
4. [x] **Unify the brand and operator experience.** Use Soup Wall consistently across documentation and the three browser pages. Keep stable API headers, token prefixes, stored data, and cryptographic labels compatible until a tested migration is available.
5. [ ] **Validate in the field.** [Native Claude host acceptance](operations/CLAUDE_HOST_ACCEPTANCE.md) verifies actual hook enforcement and fail-open behavior against local model fixtures. [Independent historical replay](benchmarks/independent-history-replay.md) freezes external trace provenance and exposes the current native-tool adapter gap. The [live fallback adapter](benchmarks/agentdojo-live-fallback.md) now has 29 pinned-runtime and disposable-Agent checks; operator-selected model evaluation and native semantic coverage remain open. Real IdP interoperability, managed staging and recovery, live defended task utility, held-out attacks, and shadow soaking still need their own evidence. Report both missed attacks and legitimate work interrupted.

## Boundaries to keep clear

The hand-authored agent corpus is a regression check, not an external effectiveness score. Local identity fixtures are not vendor certification. Spend admission counters and read-only invoice previews are not final billing; invoices, payments, tax, credits, and refunds remain unimplemented. The local Agent does not require a Soup Wall account or telemetry service, while the Gateway intentionally contacts configured model providers and optional deployment services.
