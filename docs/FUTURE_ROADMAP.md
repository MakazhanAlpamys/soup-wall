# Future Soup Wall roadmap

Planning record: 2026-10-05. These proposals describe work after the current
release checkpoints. The proposals authorize no implementation, deployment or
live evaluation; separate execution decisions are recorded below. The current [roadmap](ROADMAP.md) and
[execution record](operations/ROADMAP_EXECUTION.md) remain the status records.
The initial execution stopped after the native admission, populated restore
and open review corrections. Banking remains a separate proposal.

Execution update: the separately authorized first bounded Claude Code/MCP
proof now has an [opt-in stdio implementation](operations/MCP_STDIO_ADMISSION.md)
and [matched scripted integration evidence](benchmarks/evidence/CLAUDE_MCP_STDIO_2026-10-05.md).
It prevents the sham-secret send and preserves the independently evaluated
ordinary task. This does not complete the broader semantics/authority steps
or the live-effectiveness gate in the proposed order below.

## Starting point

Agent, Gateway and Console already exist, including Claude Code hooks, MCP
manifest inspection, policy versions, approvals and delivery. Future work must
extend those surfaces without treating manifest checks or a hook verdict as
control over every tool runtime.

Native PR [#28](https://github.com/MakazhanAlpamys/soup-wall/pull/28) implements
the reviewed native admission MVP and merged after all 19 hosted checks passed.
Its 26 passing checks comprise 11 offline tests, 10 checks using
the pinned AgentDojo runtime and five actual local Agent daemon checks. The
production CLI path makes seven scripted numeric-loopback HTTP fixture
requests. The separate 29 passing fallback checks cover pinned-runtime
compatibility, using the actual daemon where gated. Both use zero real model
or provider calls. They establish contract and compatibility behavior; they
measure neither attack success nor defended task effectiveness. Broader
operator-reviewed registry coverage and live task efficacy remain open.

The native MVP preserves original tool names, arguments, results and evaluator
inputs in its supported runtime. It does not establish arbitrary native tool
semantics, a general MCP enforcement path or Claude Code result admission.
Keep the existing Claude `/hook` contract, including its PostToolUse response
and documented fail-open behavior, intact. New runtime control needs its own
reviewed integration and evidence.

Local restore and monitoring evidence likewise leave managed TLS, real IdP
interoperability, staffed routing and customer recovery gates open. The new
populated restore checkpoint now has an actual isolated passing run recorded in
[local evidence](operations/evidence/POPULATED_RESTORE_2026-10-05.md). Its synthetic
queued webhook records do not establish delivery to a receiver.

## First future proof

Use Claude Code with an explicitly selected MCP client/server runtime. An
ordinary task reads a document containing an injected instruction to send a
synthetic secret to a reserved destination. Soup Wall prevents that attempted
send, and the ordinary task still completes. Use only a sham secret and an
owned local receiver; no customer credential or public destination is needed
for the initial proof.

Acceptance requires a recorded control run showing the attempted send and a
matched defended run showing it was prevented. The receiver records no sham
secret in the defended run; the independent task evaluator records successful
ordinary completion. The retained trace identifies the exact source, tool,
destination, policy version and admission point, with sensitive artifacts
private and a sanitized public result. A detector finding or an interrupted
whole task alone does not satisfy this scenario. Treat this as one reproducible
proof, not an effectiveness score across attacks.

## Proposed order and acceptance

| Order | Proposed work | Acceptance criteria | Dependencies |
| --- | --- | --- | --- |
| 1 | Operator-controlled native semantics | A reviewed registry maps each supported real tool to its action, source provenance and typed destinations. Registry bytes/version are fixed at daemon startup. Unknown or inconsistent tools have an explicit bounded outcome. Original names, validated call arguments, original result envelopes and evaluator inputs remain intact. Tests cover nested calls, defaults, errors, mismatches, replay, resource limits and concurrent completion without model calls. | Current native MVP merged and reviewed; host-owned registry and runtime integration selected. Model/plugin declarations cannot grant authority. |
| 2 | MCP admission and authority | The selected runtime gates every supported call before execution and every result before model/parent release. Tests prove that direct, nested, error and batched paths cannot bypass admission; session and parent-child authority cannot expand, cross-bind or replay. The first future proof above passes while ordinary work completes. | Step 1 semantics; an actual controllable MCP client/runtime; a defined withheld-result and approval contract. |
| 3 | Policy overlap regressions | Executable cases establish the verdict when tainted side effects, unknown destinations, sensitive paths, secrets and manifest changes overlap, with and without a judge. Any correction preserves required stronger decisions and is reviewed for benign interruptions. | Concrete runtime facets from steps 1–2; frozen baseline policy and explicit intended precedence. Can be prepared in parallel before the proof policy freezes. |
| 4 | Matched live evaluation | Baseline and defended runs use matched tasks, attacks, model configuration and seeds where supported. Publish attack success, legitimate task utility, false interruptions and latency, with denominators, failures and uncertainty. Freeze code/policy/registry before held-out adaptive evaluation. | Steps 1–3; operator-selected provider credentials and an explicit spend budget; independent evaluators and private evidence handling. |
| 5 | Minutes to first run | A new operator installs a published artifact, starts the daemon, attaches the supported hooks/runtime and sees accurate status. A safe sham-secret demo shows enforcement and a benign task succeeds. Report measured setup time and failure/recovery behavior on supported platforms. | Reviewed runtime admission and proof scenario; published artifacts; visible shadow/enforce, connection failure and integration status. |
| 6 | Team rollout, then 5–10 pilots | Extend existing policy versions/approval/delivery with observed applied acknowledgements, staged rollout and tested rollback. A host can prove the policy digest actually active; offline/stale hosts are visible. After that, 5–10 explicitly opted-in teams complete a defined pilot with utility, interruptions, support and recovery evidence. | Steps 4–5; tenant/host authorization, key lifecycle, managed staging and staffed operational channels. |

## Design constraints to settle before implementation

For native semantics, the operator or trusted host supplies the reviewed tool
registry. A model-provided name, description or claimed read-only status cannot
become authority. Typed destination extraction must account for every recipient
and relevant field. Result provenance and delivery to a parent or model must
be explicit and bound to the admitted call. The current MVP may withhold an
`ask` result; future human result approval needs a separate scope and replay
design before it can release that result.

For MCP, inventory the actual client execution and result-consumption paths
first. Manifest pinning is useful evidence but does not implement call/result
admission. Preserve upstream payloads and distinguish parent release from
model-context admission; avoid inventing equivalent Bash/MCP translations of
native tools. Define session ownership, child authority, cancellation, expiry,
restarts, bounded outstanding calls and private audit behavior before promising
general coverage.

The shipped default policy uses first-match precedence. Independent checks
confirmed through the actual hook and native library entrypoints that an
untainted send to an unknown host produced `ask`, while admitted foreign
content tainted the same send and let the earlier
`escalate-tainted-side-effect` with `fallback: allow` override
`ask-unknown-host`. The current security correction orders the unknown-host
rule before that weaker fallback and adds regressions; it is included in
merged Native PR #28.
Future work expands the combination matrix to no judge, judge allow/ask,
errors and unavailable judges, and verifies the intended result for each
overlap. That wider evaluation is separate from correcting this confirmed
ordering defect.

Live evaluation must retain unsuccessful runs, missed attacks, legitimate work
interrupted and added latency. Separate the development corpus from held-out
and adaptive sets, avoid tuning on held-out results, and freeze source/policy
hashes and evaluator definitions. Any budget-limited sample must state its
limits. Local fixture counts remain contract evidence even after a live run.

First-run status must show what is actually enforced, which runtime is covered,
which policy is active, and what happens when the daemon is unavailable. A
configured hook or running process alone is insufficient. The setup/demo must
support safe recovery and avoid real secrets or automatic external traffic.

Team rollout builds on the existing control plane. Separate policy issued,
delivered and observed applied states; pin the activated version/digest and
scope acknowledgements to authenticated hosts. Test staged activation,
unavailable hosts and rollback before pilots. Pilot reporting needs explicit
success criteria, permission to retain evidence, and a staffed response path;
the initial 5–10 teams are a learning gate, not a certification claim.

## Evidence and stop conditions

Each future milestone needs a separate implementation decision, review,
reproducible checks and a dated evidence record. Source checks can proceed
without providers for contract, state and policy behavior. Live benchmark and
managed pilot work require their stated operator dependencies. If a runtime
cannot control result release or a provider budget is absent, record the
specific missing gate instead of broadening the claim.

This document remains the proposed broader plan. The separately recorded first
bounded proof does not start the installer, rollout or pilot proposals.
