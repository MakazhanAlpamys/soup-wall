# Soup Wall product roadmap

## Where we stand

Soup Wall is an Apache-2.0 AI firewall with Agent, Gateway and Console surfaces.
Its product goal is to control what an agent can execute, where it can send
data, what it can change, and which authority it can delegate, while preserving
legitimate task completion.

The source baseline is the annotated tag `baseline/team-handoff`, pointing to
commit `2304818b6f461ecbef97fe68bfad50be55c17ec0`. It includes the pending MCP
implementation in [PR #30](https://github.com/SoupTeam/soup-wall/pull/30)
and contributor preparation in [PR #31](https://github.com/SoupTeam/soup-wall/pull/31).
Main was `c6045d30341dbc784cb219472c93f5b35921c928` when this baseline was frozen.
The tag records source state; it is not a product release or field certification.
Existing releases remain historical artifacts. This plan has one final release,
after every required phase and acceptance gate is complete.

Repository facts:

- The reviewed synthetic corpus interrupts **19 of 19 attack sessions** and
  **0 of 21 benign sessions**. It is a regression check, not a protection rate.
- The original independent AgentDojo replay recorded **0 interruptions across
  40 injection-labelled histories**. Attack success and defended utility were
  not measured. Its generic action and `LocalSystem` provenance fallbacks do
  not represent the semantics of those native tools. Preserve that result.
- Main already contains operator-installed native call/result/context admission.
  The schema identity and registry are pinned, but the trusted collector still
  supplies original runtime validation and complete semantic declarations.
- The baseline also contains bounded stdio MCP admission. An actual Claude Code
  control/protected pair shows a synthetic-secret send executing without the
  gate and not executing with it; an independent ordinary-task check succeeds
  in both. The provider responses are scripted, not live-model efficacy evidence.
- The known unknown-host/tainted-fallback precedence defect has been corrected
  with hook/native regressions. A wider policy overlap matrix remains open.
- The [taint tracker](../crates/agent/src/taint.rs) bounds retained history with
  FIFO eviction. Long-session loss of earlier provenance is a documented limit
  that needs explicit runtime acceptance.
- Console policy approval, activation, rollback and webhook queues exist. They
  do not prove that a local Agent received or applied a policy.
- Local installation, host, identity, storage, encrypted restore and monitoring
  checks exist. Managed deployment, corrected full vendor acceptance, real IdP
  interoperability and live defended effectiveness still require evidence.

See [architecture](ARCHITECTURE.md), [methodology](methodology.md),
[historical replay](benchmarks/independent-history-replay.md),
[native admission](benchmarks/native-admission.md), and
[MCP admission](operations/MCP_STDIO_ADMISSION.md) for reproduction and limits.

## Principles

- A security verdict must bind to actual execution or result release. A detector
  finding, manifest pin, hook configuration or interrupted trajectory is insufficient.
- The operator controls tool semantics and authority. Model text, tool descriptions
  and plugin annotations cannot grant permissions or declare content trusted.
- Keep original tool names, validated arguments, results and evaluator inputs.
  Unsupported protected paths must have an explicit refusal, never a silent bypass.
- Keep call, parent-result and model-context boundaries distinct. Withholding a
  result cannot undo a side effect that already executed.
- Stronger policy decisions must survive overlaps and judge failures. Optional
  judges cannot weaken a hard refusal or create authority.
- Report attack success, legitimate task utility, false interruptions and latency
  together. Retain unsuccessful runs and separate development from held-out data.
- Show the active policy, integration coverage, shadow/enforcing state and outage
  behavior. Legacy Claude HTTP hooks remain documented as fail-open.
- Preserve compatible APIs, configuration, stored state and cryptographic labels
  until an explicit migration is reviewed and verified.
- Keep public documentation, comments and user-facing prose in English. Preserve
  multilingual security fixtures, protocol bytes, upstream attribution and evidence.
- Keep internal drafts, specifications and personal notes under ignored
  `local-notes/`. Publish accepted interfaces, decisions and sanitized evidence.

## What exists and what we are building

| Surface | Existing implementation | Work to complete |
| --- | --- | --- |
| Core | Detection, normalization, masking, text policy and optional ML code | Reviewed detector use and pinned optional assets for the accepted scope; no classifier-only security claims |
| Agent | Taint, action/egress policy, grants, audit/replay and Linux guarded execution | Complete selected real-tool semantics, runtime child identity/authority, and policy composition |
| Native and MCP integration | Immutable registry, authenticated admission and correlated result receipts; bounded stdio collector in the baseline | Coverage of selected runtime paths, explicit unsupported cases, and independently witnessed prevention with useful continuation |
| Gateway | Chat Completions, Responses and Messages inspection with bounded streaming | Accepted provider/platform behavior, compatibility and operational checks on the final candidate |
| Console | Tenants, roles, identity, tenant policy versions, webhook queues and usage evidence | Authenticated Agent enrollment, verified policy bundles, observed application, staged rollout and confirmed rollback |
| Evaluation | Synthetic regressions, pinned historical importer, runtime adapters and scripted integration proofs | Frozen matched live evaluation using original independent attack/task evaluators |
| Operations | Published archives, deployment examples, local recovery and monitoring procedures | Supported installation lifecycle, portable crypto, real identity acceptance, managed TLS, recovery and notification delivery |

Final billing, payment collection and banking are outside this product scope.
Usage evidence and invoice previews retain their current limits.

## Foundation

The foundation is a prerequisite for the phases below, not an early release.
Keep the tagged baseline immutable and reconcile pending changes through review.
Each accepted change must remain traceable to its source, tests and evidence.

The foundation is ready when:

1. A reviewed support matrix identifies platforms, hosts, transports, tool
   families, provider APIs, storage backends and identity integrations. Every
   path is supported, conditional or explicitly unsupported, with its fail mode.
2. Build and experiment inputs identify exact source, lockfile, toolchain,
   registry/schema, policy, dataset and optional asset revisions/hashes. Floating
   `stable` and model downloads from `main` are resolved before claiming reproduction.
3. Acceptance protocols define numeric effectiveness, utility, interruption,
   latency, setup and recovery limits before measurement. Critical denied-action
   tests require an independent witness of zero executions or deliveries.
4. Component responsibilities, review boundaries and required checks are recorded
   by role, then assigned to actual owners. No ownership is inferred from code history.
5. License, dependency, secret-scan and security-review procedures cover the full
   workspace. Local credentials/raw payloads remain private; public claims have
   retained sanitized evidence. Internal working material stays ignored locally.
6. The integration decision identifies how main, the baseline and open PRs converge.
   CI success on one revision is not inherited by another revision.

Use [DEVELOPMENT](DEVELOPMENT.md), [CONTRIBUTING](../CONTRIBUTING.md),
[SECURITY](../SECURITY.md), and [provenance](PROVENANCE.md) as the working rules.

## Phases

Work may proceed in parallel when its prerequisites are satisfied. Each phase
closes only when its completion evidence is reviewed. Passing source checks
does not substitute for unavailable runtime, evaluation or deployment evidence.
Use controlled internal candidate builds for validation and pilots; do not
publish intermediate releases, prereleases or public container candidates.

### Phase 1 — Complete reviewed tool semantics

**Depends on:** the foundation and selected runtime/tool coverage.

Extend the existing native registry and adapters instead of disguising tools as
Bash commands. A `send_email` declares a network action and every recipient;
`delete_file` declares destruction; an external-document read declares an
untrusted result. Review defaults, optional fields and nested values.

**Ready when:**

- Every supported tool has reviewed schema validation, action class, provenance
  and complete typed destination extraction, fixed by operator-owned identities.
- Tests use original names, arguments, errors and results. Unknown tools, schema
  drift, malformed destinations and inconsistent declarations cannot execute
  through an enforcing path.
- Defaults, coercion, nested arguments, all recipients and resource bounds have
  explicit accepted/refused cases; model-provided semantic claims grant nothing.
- Reviewed benign cases succeed and security cases retain their intended decisions.

### Phase 2 — Bind enforcement to execution and delegated authority

**Depends on:** Phase 1 and a reviewed collector/host integration contract.

Close the selected execution and consumption paths around the existing admission
protocol. Bind authenticated agent/session identity, parent grants, invocations,
results and declared release points. Preserve the current bounded proof as a
regression while extending only explicitly selected MCP capabilities.

**Ready when:**

- An independent receiver or execution marker proves that a denied action never
  ran. The infected input is encountered and useful work completes after refusal.
- Direct, nested, error and batched paths are either admitted at their declared
  boundaries or explicitly refused. No alternate transport or callback bypasses
  the supported gate; original accepted payloads remain intact.
- Child tools, destinations and resources cannot exceed authenticated parent
  grants. Cross-session substitution, replay, expiry, cancellation, restart and
  concurrency cases cannot expand authority or release unadmitted results.
- Long sessions, taint eviction and oversized inputs have reviewed tested
  outcomes. Missing required inspection or provenance is never silently reported
  as successful protection on an enforcing path.
- Enforcement stops safely on collector/daemon uncertainty. Hook fail-open,
  server stderr, OS effects and unattested model serialization remain explicit
  limits wherever the selected runtime cannot control them.
- Any human Ask continuation has a reviewed single-use scope and replay contract;
  unsupported approval paths remain closed and are reported accurately.

### Phase 3 — Freeze policy composition

**Depends on:** the semantic fields and runtime boundaries from Phases 1–2.
The case matrix can be prepared alongside those phases.

Build on the corrected first-match precedence rather than re-opening the same
known defect as new work. Review combined taint, secret/PII findings, destinations,
sensitive paths, manifest drift and action classes.

**Ready when:**

- An executable reviewed matrix covers overlaps with no judge, judge outcomes,
  malformed replies, errors and unavailable judges for each supported path.
- A weaker fallback never overrides a required Ask/Deny; hard denials persist.
  Native paths continue rejecting judge configuration until a reviewed extension
  establishes the same boundary.
- The shipped regression corpus and additional benign combinations pass without
  relabelling cases or hiding misses. Policies and expected outcomes are frozen
  before held-out evaluation.

### Phase 4 — Demonstrate live effectiveness

**Depends on:** Phases 1–3, frozen acceptance thresholds, reviewed evaluation
data/runtime, selected model access, explicit budgets and private evidence handling.

Run matched control and protected tasks with the same original task/attack
evaluators, model configuration and seeds where supported. Evaluate the shipped
policy and proposed variants as distinct frozen experiments.

**Ready when:**

- Attack success is measured from actual effects/evaluators, with independently
  measured legitimate utility, false interruptions and end-to-end latency.
- Reports include denominators, incomplete runs, missed attacks, interrupted
  benign work, uncertainty, resource usage and exact source/policy/registry hashes.
  Aborted trajectories are not assigned fabricated evaluator results.
- Development, held-out and adaptive sets are separate; no tuning occurs against
  held-out results. Failed outcomes and the historical negative baseline remain visible.
- Reviewed results meet the acceptance limits recorded before the runs. Missing
  access, budget or evaluator fidelity leaves this phase open.

### Phase 5 — Make setup and status verifiable

**Depends on:** the accepted integration and policy from Phases 1–3; Phase 4
must support the protection claim shown in onboarding. Preparation can run in parallel.

Make the first useful experience an installed binary, safe host integration,
managed daemon lifecycle, an accurate status display and a synthetic-secret demo.

**Ready when:**

- Clean installation, upgrade, rollback and removal work on every supported
  platform without replacing unrelated host settings or exposing credentials.
- Status identifies the actual active policy/registry digests, integration
  coverage and shadow/enforcing/unavailable state, verified against host behavior.
- A user can run the safe receiver demo and a benign task; independent witnesses
  confirm both prevention and useful completion within the accepted setup budget.
- Startup failures, daemon loss, stale configuration and recovery have documented
  outcomes that match tests. The README starts with this verified experience.
- Setup and demonstration do not require real secrets or automatic provider traffic.

### Phase 6 — Complete team rollout and operational validation

**Depends on:** Phases 1–5 and selected deployment/identity environments.
Operational preparation can start after the foundation is agreed.

Connect Console to enrolled Agents with verified policy bundles and authenticated
application acknowledgements. Distinguish policy issued, delivered and observed
applied. Validate the complete deployment with opted-in pilot users on controlled
candidate builds.

**Ready when:**

- Cryptographic bundle verification, tenant/host authorization, rotation and
  revocation reject forged, stale, replayed and cross-tenant policies. Adapter
  signature metadata validation alone does not satisfy this requirement.
- Agents acknowledge the exact active revision/digest after atomic application.
  Staged activation, offline/stale hosts and rollback are visible; post-rollback
  behavior and application acknowledgements match the restored version.
- The complete release graph passes advisory review without the RSA exception.
  [Issue #19](https://github.com/SoupTeam/soup-wall/issues/19) has reviewed
  portable crypto, native signature/tampering evidence and real-IdP assertion
  interoperability; encrypted assertions remain rejected without decryption keys.
- Managed TLS, real OIDC/SAML/SCIM lifecycle and negative authorization cases,
  migrations, dependency failure, populated encrypted restore and credential
  revocation pass against the declared deployment matrix and recovery objectives.
- Actual policy webhook delivery and authenticated firing/resolved notifications
  reach the selected receiver; retry, deduplication, failure states and operational
  response are exercised. Queue records and loopback fixtures remain distinct evidence.
- Pilots report observed task utility, interruptions, support and recovery against
  agreed criteria, with consent and safe evidence retention. Findings are resolved
  or explicitly remove the affected capability from the accepted scope through review.

### Phase 7 — Accept and publish the complete product once

**Depends on:** the foundation and every preceding phase being complete.

Freeze one integrated commit and build one identified candidate artifact set.
Validate the exact bytes that will be published, including compatibility,
security, runtime, effectiveness, installation and deployment acceptance.

**Ready when:**

- Required default/all-feature tests, native platform checks, Python suites,
  policy corpus, containers, storage, identity, scan/license/advisory review and
  all product acceptance evidence pass for that source/artifact set.
- Documentation matches measured capabilities and limitations; migration,
  rollback, checksums, SBOMs, attribution and support procedures are reviewed.
- The publication workflow gates **every** external push, including GHCR, on
  the complete accepted candidate. The current container job can push after
  `verify` before other builds finish; that dependency must be corrected first.
- Publish one final release and its accepted artifacts. Confirm downloaded
  hashes, installation and rollback without silently rebuilding different bytes.
  Failed acceptance returns to the relevant phase without publishing a partial product.

## Open decisions and recommendations

Resolve each decision before its dependent phase starts. Record the chosen
scope, rationale, alternatives and acceptance consequences in English.

| Decision | Recommendation | Needed before |
| --- | --- | --- |
| Initial host and platform scope | Start with Claude Code and reviewed stdio MCP tools, where the existing execution proof is strongest. Preserve the existing platform matrix; extend transports/content only with explicit acceptance. | Foundation / Phase 1 |
| Registry and schema validation ownership | Operator-reviewed immutable declarations plus original runtime validation in the trusted collector; enumerate all destinations. Resolve any additional admission-side validation for the selected schemas explicitly. | Phase 1 |
| Child identity and grants | Bind grants to authenticated parent/session identity and constrain tools, destinations and resources. Treat runtime identity propagation as required implementation, not a library-only claim. | Phase 2 |
| Ask and result release | Keep unsupported approval paths closed. Add exact single-use human authorization only where the selected runtime can pause and resume safely; never grant a denied action or infer model consumption. | Phase 2 |
| Judge use | Use the shipped no-judge baseline first. Keep judges advisory/tightening only and native judge configuration rejected until its extension is reviewed. | Phase 3 |
| Live benchmark and thresholds | Use pinned original evaluators and matched runs, preregister numeric limits and sampling/uncertainty rules, and retain failed runs. Select model access and an explicit budget before execution. | Phase 4 |
| Distributed policy trust | Verify signed bundles with reviewed cryptography and enrolled host identities; test key lifecycle, offline cache rules, atomic activation and applied acknowledgements. | Phase 6 |
| SAML provider maintenance | Keep the pinned Windows platform patch until an upstream release passes the same native signature and genuine vendor-document checks. Keep the complete graph free of vulnerable RSA and preserve encrypted-assertion rejection. | Phase 6 |
| Deployment, identity and recovery scope | Keep existing SQLite/PostgreSQL boundaries, select actual IdPs and supported SCIM operations, and agree recovery, retention and notification responsibilities by role. | Phase 6 |
| Compatibility and publication | Preserve existing interfaces until a tested migration is accepted. Keep the baseline tag separate from semver release triggers and gate all publication on the final candidate. | Foundation / Phase 7 |

## Working process

Use one public roadmap and focused issues/PRs. Each issue names its phase,
prerequisites, supported behavior and independently verifiable completion criteria.
The author supplies implementation, relevant docs and evidence; reviewers check
the unsafe and benign paths, compatibility and trust boundaries. Operators run
the applicable external acceptance with explicitly selected infrastructure.

Keep internal working notes and unaccepted design drafts in `local-notes/`,
which stays local through `.gitignore` and outside container build contexts.
Keep source contracts, provenance, sanitized public evidence and the generated
regression scorecard versioned. The documentation index identifies canonical guides.

Use small reviewed changes. Run the [contribution checks](../CONTRIBUTING.md)
and affected integration/policy checks. Report skips and failures precisely;
do not overwrite historical evidence or relabel cases to make a gate pass.
Update the public plan when a reviewed decision changes scope or acceptance.
Commits and internal candidate builds are checkpoints; the only planned product
publication is the final release after complete acceptance.
