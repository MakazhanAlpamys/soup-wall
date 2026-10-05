# Soup Wall roadmap

Status: October 2026. This is the current roadmap for the public source,
remaining acceptance gates, and proposed next stages. Implementation, local
acceptance, hosted CI, and external field evidence are separate outcomes.
A completed fixture does not close a deployment or effectiveness gate.
Proposed work requires its own execution decision; this document does not
authorize deployments, provider spending, or pilots.

## Product direction

Soup Wall is one Apache-2.0 project with three self-hosted surfaces: **Agent**
for local agent actions, **Gateway** for provider traffic, and **Console** for
organization controls. The source distribution has no paid feature gate or
required Soup Wall service. Hosting and support may be offered separately
without reserving product features in a closed codebase.

Security claims depend on actions and outcomes. Detectors identify suspicious
content; policies and the host runtime decide whether an action can proceed.
Keep the Agent's default shadow posture and the Claude Code hook's fail-open
behavior visible to operators. Preserve compatible API headers, token prefixes,
stored data, and cryptographic labels until a tested migration is available.

## Implemented capabilities

The list describes the current source branch. The stdio MCP change is in
open [PR #30](https://github.com/MakazhanAlpamys/soup-wall/pull/30), which has not
merged into main or a published release.

- Local Agent daemon, Claude Code hooks, MCP manifest inspection, audit/replay,
  approval grants, and Linux guarded execution.
- Opt-in [native admission](benchmarks/native-admission.md) with an immutable
  operator-installed tool registry, separate collector authentication, and
  correlated invocation/result/context inspection.
- Opt-in [stdio MCP admission](operations/MCP_STDIO_ADMISSION.md) before
  supported original calls execute and before their original text/error results
  reach the MCP host. The current contract is sequential and bounded; it does
  not provide general MCP authority or attest eventual model context.
- OpenAI Chat Completions and Responses, and Anthropic Messages Gateway with
  input/output inspection, bounded streaming, policy, and audit.
- Self-hosted control-plane code: tenants, tokens, server-side roles, OIDC/SAML,
  a constrained SCIM subset, policy delivery, usage evidence, reconciliation,
  quotas, retention, and read-only invoice previews.
- Local builds, tests, a synthetic policy regression corpus, deployment examples,
  and supply-chain workflows.

The source import, license/attribution review, workspace integration, and Soup
Wall branding checkpoints are complete. The
[v0.4.0 release](https://github.com/MakazhanAlpamys/soup-wall/releases/tag/v0.4.0)
publishes four platform archives, checksums, six SBOMs, a Gateway image, and
upgrade guidance. Its release checks included default/all-feature tests,
formatting, Clippy, advisory review, SBOM generation, CodeQL, Docker, storage,
and identity fixtures. Every subsequent change still requires checks on its
exact HEAD before merge; earlier green releases do not establish current CI
success. See [CHANGELOG](../CHANGELOG.md), [contribution guidance](../CONTRIBUTING.md),
and [provenance](PROVENANCE.md) for release history and the narrow RSA exception.

These are implementation and release statements, not certification of every
provider, identity provider, or deployment environment.

## Remaining acceptance gates

| Gate | Required evidence | Current boundary |
| --- | --- | --- |
| Managed self-hosting | Install a published artifact, pass preflight, authenticate to Console, observe a benign provider request and a blocked request, apply PostgreSQL migrations, and record the TLS deployment. | Local release fixtures pass; managed staging, TLS, real-provider traffic, and staffed alert routing remain open. |
| Recovery and operations | Record PostgreSQL/Redis failure and recovery phases, restore an encrypted backup into an isolated database, verify restored state and authentication, and observe the deployment's alert routing. | Local dependency, populated restore, and loopback monitoring evidence exists; customer-data recovery and managed notification delivery remain open. |
| Identity interoperability | Verify real OIDC login/logout/session lifecycle, signed SAML assertion acceptance and rejection, and supported SCIM provisioning/revocation against an operator-selected IdP. | Local fixtures and public metadata probes are bounded checks; corrected vendor acceptance and real-IdP interoperability remain open. |
| SAML crypto [#19](https://github.com/MakazhanAlpamys/soup-wall/issues/19) | Remove the vulnerable RSA dependency from the locked release graph; review portable crypto; preserve encrypted-assertion rejection; retain target-build, signature, and interoperability evidence. | Four-platform signature fixtures pass. Windows still uses RSA 0.9.10 with the documented advisory exception; supported Windows XML crypto and real-IdP acceptance remain separate work. |
| Agent effectiveness | Retain independent held-out provenance, matched attack and benign outcomes, missed attacks, legitimate task utility, false interruptions, latency, and exact source/policy/evaluator versions. | Native/fallback contracts and one actual Claude scripted MCP pair pass; broader registry coverage, live defended utility, held-out attacks, and shadow soaking remain open. |

No managed staging address, customer IdP, live model access, or provider budget
is implied by these local results. Use operator-authorized infrastructure and
explicit dependencies before attempting the external gates.

## Completed bounded MCP proof

The [2026-10-05 Claude Code/MCP proof](benchmarks/evidence/CLAUDE_MCP_STDIO_2026-10-05.md)
uses committed implementation 9530017c8c52ec88ba347f646719833a1b99d751 and an
actual installed Claude Code 2.1.289 with a deterministic loopback provider.
An infected document reaches the host and scripted provider. The control
executes the original send_http and the owned receiver obtains the synthetic
secret. The matched protected case records zero send executions and receiver
requests, one native secret-egress Deny, and successful independently evaluated
ordinary-task completion. Both proposal and useful-result hashes match.

The custom policy deliberately allows the infected read to exercise the send
boundary. Six Messages requests are scripted; no real model or paid provider ran.
The evidence preserves incomplete attempts, source/binary hashes, protected
private storage, and cleanup limitations. The measured implementation belongs to
[PR #30](https://github.com/MakazhanAlpamys/soup-wall/pull/30); inspect its exact head
and current checks for hosted integration status.

This proves execution and continuation for two reviewed tools. It does not
complete general tool semantics, child authority, human result approval,
shipped-policy effectiveness, or live evaluation. Host release is distinct
from model-context admission. Withholding a result cannot undo an already
executed side effect.

## Proposed order and acceptance

| Order | Next direction | Acceptance criteria and dependencies |
| --- | --- | --- |
| 1 | Operator-controlled native semantics | Extend the reviewed registry to real tools with fixed schema/action/provenance and every typed destination. Preserve original names, validated arguments, results, and evaluator inputs. Specify unknown/inconsistent-tool outcomes and test defaults, errors, mismatches, replay, nested calls, resource limits, and concurrent completion without model calls. Model/plugin declarations cannot grant authority. |
| 2 | Broader MCP admission and authority | Select a controllable runtime and define supported direct, nested, error, and batched paths before promising coverage. Gate each supported call before execution and each result before its declared release; prove session/parent-child authority cannot expand, cross-bind, or replay. Define result withholding and any approval contract. The bounded proof above is one prerequisite, not completion of this direction. |
| 3 | Policy overlap regressions | Freeze baseline policy and intended precedence. Exercise overlapping taint, unknown destinations, sensitive paths, secrets, and manifest changes with no judge, judge Allow/Ask, judge errors, and unavailable judges. Preserve stronger decisions and evaluate benign interruptions. Use concrete runtime facets from directions 1–2. |
| 4 | Matched live evaluation | Use matched tasks, attacks, model configuration, and seeds where supported. Publish attack success, legitimate task utility, false interruptions, and latency with denominators, unsuccessful runs, and uncertainty. Freeze code/policy/registry/evaluators before held-out adaptive evaluation. Requires reviewed runtime/policy boundaries, an operator-selected provider, access, and an explicit spend budget. |
| 5 | Minutes to first run | A new operator installs a published artifact, starts the daemon, attaches supported hooks/runtime, and sees accurate shadow/enforce, connection, and active-policy status. A safe sham-secret demo and benign task pass. Measure setup time plus failure/recovery behavior on supported platforms; requires a reviewed runtime and published artifacts. |
| 6 | Team rollout, then 5–10 pilots | Extend existing policy versions/approval/delivery with authenticated applied acknowledgements, staged activation, and tested rollback. Make offline/stale hosts visible. Then explicitly opted-in teams complete a defined pilot with utility, interruption, support, and recovery evidence. Requires evaluation, tenant/host authorization, key lifecycle, managed staging, and a staffed response path. |

## Constraints for the next stages

The operator or trusted host owns tool declarations. Names, descriptions,
annotations, or a model's claimed read-only status cannot grant authority.
Registry bytes/version stay fixed at daemon startup; typed extraction must
cover every recipient and relevant field. Bind result provenance and declared
delivery to the admitted call. The current MVP can withhold an Ask result;
human approval needs separate scope, expiry, and replay design before release.

Inventory actual execution and result-consumption paths before extending MCP.
Manifest pinning and PostToolUse observations alone do not gate execution.
Preserve upstream payloads rather than inventing Bash equivalents. Define
session ownership, child authority, cancellation, expiry, restarts, bounded
outstanding work, and private audit behavior. Preserve the existing Claude
hook's documented fail-open contract while extending runtime-owned admission.

The shipped policy uses first-match precedence. Native PR #28 corrected a
confirmed overlap where weaker tainted-side-effect fallback Allow could
override unknown-host Ask, with actual hook/native regressions.
[Review evidence](operations/evidence/OPEN_CODE_REVIEW_2026-10-05.md) records the
finding and limits. The wider judge/overlap matrix remains separate work.

Separate development, held-out, and adaptive evaluation sets. Do not tune on
held-out outcomes; retain failed runs and state budget-limited sample boundaries.
Local fixture counts remain contract evidence even after a live evaluation.
First-run guidance must explain what is actually enforced and what happens
when the daemon is unavailable; a configured hook or running process is
insufficient. Demos must avoid real secrets and automatic external traffic.

Rollout must distinguish policy issued, delivered, and observed applied states,
pin the activated digest, and scope acknowledgements to authenticated hosts.
Test unavailable hosts and rollback before pilots. The first 5–10 teams are a
learning gate, not certification; require evidence-retention permission and a
staffed response path.

Each milestone needs a separate implementation decision, review, reproducible
checks, and dated evidence. If result release, infrastructure, access, or budget
is unavailable, record the missing dependency instead of widening the claim.
A source-only checkpoint does not authorize a new release or a field-validation claim.
Banking and final billing remain separate proposals.

## Evidence and reproduction

| Area | Procedure and retained evidence |
| --- | --- |
| Release and local services | [Local release acceptance](operations/LOCAL_RELEASE_ACCEPTANCE.md), [Windows Agent acceptance](operations/WINDOWS_AGENT_ACCEPTANCE.md), and [staging/recovery drills](operations/STAGING_DRILLS.md) separate released binaries and isolated recovery from managed acceptance. |
| Actual Claude hooks | [Claude host acceptance](operations/CLAUDE_HOST_ACCEPTANCE.md) records enforce/shadow/offline behavior against local scripted responses and the hook's fail-open boundary. |
| Native and fallback runtimes | [Native admission](benchmarks/native-admission.md), [fallback adapter](benchmarks/agentdojo-live-fallback.md), and [native fixture evidence](benchmarks/evidence/agentdojo-native-fixture-2026-10-05.md) retain original runtime/schema/result boundaries without real-model effectiveness claims. |
| Independent historical replay | [Reproduction and fidelity](benchmarks/independent-history-replay.md) and the [dated outcome](benchmarks/evidence/AGENTDOJO_HISTORY_2026-10-04.md) preserve the original adapter's negative policy result, not an attack-success measurement. |
| Current stdio MCP integration | [Operator contract](operations/MCP_STDIO_ADMISSION.md) and [committed-source proof](benchmarks/evidence/CLAUDE_MCP_STDIO_2026-10-05.md) retain matched receiver/utility witnesses, failed attempts, immutable hashes, and cleanup limits. |
| Restore and monitoring | [Populated restore](operations/evidence/POPULATED_RESTORE_2026-10-05.md) and [local monitoring](operations/evidence/LOCAL_MONITORING_2026-10-05.md) record isolated restored state and loopback firing/resolved delivery; customer recovery, managed TLS, and staffed routing remain open. |
| Identity | [Interoperability guide](operations/IDENTITY_INTEROPERABILITY.md), [SAML provider evidence](operations/evidence/SAML_PROVIDER_2026-10-04.md), and [Keycloak checkpoint](operations/evidence/KEYCLOAK_SAML_2026-10-05.md) preserve metadata/fixture limits and incomplete vendor acceptance. |
| Review and provenance | [OpenCodeReview delegation](operations/evidence/OPEN_CODE_REVIEW_2026-10-05.md), [CodeQL triage](operations/evidence/CODEQL_TRIAGE_2026-10-05.md), and [source provenance](PROVENANCE.md) retain reviewed findings and historical boundaries. |

Dated evidence and sanitized JSON remain the historical records; Git history
and CHANGELOG retain implementation/release chronology. Public records must
not contain bearer tokens, provider credentials, identity assertions, prompts,
customer data, or private snapshots. Retain unsuccessful runs and cleanup
failures with the evidence needed for review.

## Boundaries to keep clear

The hand-authored agent corpus is a regression check, not an external
effectiveness score. Local identity fixtures and metadata probes are not vendor
certification. Queued webhook records do not establish receiver delivery.
Spend admission counters and read-only invoice previews are not final billing;
invoices, payments, tax, credits, and refunds remain unimplemented. The local
Agent needs no Soup Wall account or telemetry service, while the Gateway
intentionally contacts configured model providers and optional deployment
services.
