# Optional classification experiments

These candidates run separately from native admission and the policy engine.
They never execute a tool, produce Allow/Ask/Deny, authenticate tool metadata,
change permissions or replace a trusted baseline restriction.

## SOU-6: experimental Jev adapter

The adapter implements the semantic core `actions` plus Boolean `unknown`.
`call_id` and evaluator-only fields stay outside the semantic payload. Technical
failure uses `ClassificationFailure` with `classifier_invalid`,
`classifier_timeout` or `classifier_internal_error`; the orchestrator must stop
before policy/execution. A valid unknown classification reaches policy normally.
The accepted D07 no-op is `actions=[]`, `unknown=false`; a model claiming this
is still an untrusted prediction and grants no authority.

Reference: [owner-recorded SOU-10 contract candidate](https://github.com/SoupTeam/soup-wall/blob/5a3ff08fae333cd15bdf80345a240ca527a8872b/contract/updated_contract2.md),
labelled `0.4-approved` by its owner, D01-D10, recorded on 9 October.
This experiment uses its semantic subset; full contract review and production
compatibility remain separate SOU-10 work. It does not change the older in-crate
test-support categories wire.

### Run offline

From the repository root, Python 3.10+ and its standard library suffice:

```sh
python -m unittest experiments.classification.test_jev experiments.classification.test_shadow -v
python -m experiments.classification.shadow \
  --baseline-path rule_baseline \
  --fixtures eval/fixtures/soup_task1_evaluation_cases_v0.4.json \
             eval/fixtures/soup_task1_challenge_cases_v0.1.json \
  --output-dir target/jev-shadow
```

Use the owner-maintained baseline now merged into main in
[PR #53](https://github.com/SoupTeam/soup-wall/pull/53); the experiment records
the module hash. The initial comparison freezes source
`000136c51884e0c204ac51b77c29c5c302f7256a` and shared evaluation from `main`.
The fixtures remain untouched and never enter training. Their labels are
developer diagnostics, some provisional/pending, rather than held-out evidence.

The default candidate returns deliberately ambiguous, **mocked** probabilities,
independent of inputs or gold labels. Its classification counts exercise the
plumbing and must not be described as Jev accuracy. JSON/CSV retain all mismatches,
critical misses, abstention observations, pending cases, typed failures and timings.
The adapter unit tests separately cover positive, negative, mixed, unknown,
partially known and no-op responses, metadata injection, bounds and failure modes.

### Dated evaluation, 9 October 2026

[Sanitized measured evidence](evidence/2026-10-09-mock.json) retains source and
fixture hashes, per-label errors and all six baseline mismatches. Python 3.11.14
on Windows ran 58 fixture calls: 55 provisional scored cases and three pending.
The shared runner checks the complete action set and the unknown flag together;
it does not score an absent status field in these fixtures.

| Observation | Frozen rule baseline | Deliberately ambiguous Jev mock |
|---|---:|---:|
| Scored exact matches | 49 / 55 | 4 / 55, mechanics only |
| Scored technical errors | 0 | 0 |
| Pending cases, excluded from scores | 3 | 3 |
| Technical errors across all calls | 0 | 1 invalid input in a pending case |
| Valid responses carrying unknown | 14 / 58 | 57 / 57 |
| Local p50 / p95, ms | 0.122 / 0.565 | 0.059 / 0.158 |
| External API requests / API cost | 0 / $0 | 0 / $0 |

The mock invalid-input observation correctly uses `classifier_invalid` rather
than converting null arguments into an unknown prediction. All valid mock
responses abstain. The timings include local input checking and adapter work,
not provider inference or network latency; a single run is not a latency gate.

Baseline mismatches are CU01, CU02, CU03, CM01, CX06 and CS06. Its one critical
missing label is `delete` on CU02, with unknown retained. Under the agreed
contract this result reaches policy, which must Ask or apply a trusted Deny.
CX06 loses `read` while retaining `delete` and unknown=false; a policy that
restricts reads independently therefore needs evaluation of all predicted
actions. These are prospective implications, not measured policy outcomes.
Descriptions remain untrusted and the fixtures include unfamiliar tools and
misleading metadata. No tool executor or policy was invoked in this comparison.

The default mock establishes reproducible comparison plumbing. Real Jev errors,
abstentions, inference latency and cost remain unmeasured. The access-limited
recommendation below follows from that absence of evidence, not mock scores.

### Provider mapping and limits

The [official API](https://docs.typesafe.ai/api) accepts a state and named typed
questions. We use five independent action questions plus one unresolved-effects
question. Each [Noul answer](https://docs.typesafe.ai/primitives/noul) is a yes
probability. Initial experimental thresholds are negative <=0.2 and positive
>=0.8; intermediate action scores retain known actions and set unknown. An
unresolved-effects score >0.2 also sets unknown. Thresholds need calibration on
a separate approved split before quality conclusions.

Input is bounded to 16 KiB, 2 KiB description, 16 nesting edges and 2,048 JSON
nodes; oversize input is rejected before dispatch without truncating arguments.
Descriptions stay data under fixed instructions. This boundary reduces direct
instruction mixing but cannot guarantee a model resists injection. Schema
content is semantic evidence; admitted/pinned-schema validation remains the
runtime adapter's responsibility. The experiment requires validated non-null
arguments and does not claim to implement arbitrary JSON Schema validation.

All six answers, their types, finite [0,1] values, pinned returned model and usage
are checked. Supporting confidence is a minimum binary-certainty summary, not
calibrated joint correctness. It is separate from policy. Unknown remains a
Boolean rather than a sixth action.

### Access feasibility and adoption decision

The official reference was checked on 9 October 2026. No approved API account,
key or paid experiment budget has been supplied. Public docs establish a wire
shape, not account access, guaranteed availability or a price quotation. The
current model pin is `jev-1.13.0`; availability under the approved account must
be confirmed before a live run, and moving aliases are rejected.

**Recommendation: do not adopt Jev into execution decisions at this stage.**
Deliver the tested shadow adapter and retain the current deterministic path.
Continue a live shadow evaluation only after approved access, budget, pinned
model availability and safe inputs are supplied. No real Jev accuracy, cost,
latency or calibration is claimed. This is an access-limited recommendation,
not evidence that the provider model is inaccurate.

`HttpTransport` is available for a reviewed future experiment but is never
selected by the CLI. Construction requires an approval reference, exact safe
state-hash allowlist and request cap. It uses the official HTTPS endpoint,
suppresses proxies/redirects, reserves requests before dispatch, bounds responses
and performs no retries. Request admission and reservation are protected by one
lock, including concurrent callers; failure never restores a possibly billed
request. Admission and dispatch use the same copied request. The caller must
separately verify the dollar budget; the request cap does not enforce billing.

DNS, connect, headers and body reads run in a separate spawned process supervised
by one deadline. Late work is terminated rather than left in a background
thread, and late output is discarded. Cleanup allows up to two 0.1-second joins;
OS process-start/termination scheduling is not a hard real-time guarantee.
The worker returns only a bounded, validated probability/usage envelope and
never raw provider errors or extra fields. Python callers must use a normal
spawn-compatible entry point (including a main guard on Windows). The default
mock CLI does not start a network worker. Safe local regressions cover blocked
worker termination, successful delivery and concurrent request-cap admission.
No credentials or raw provider errors are written to evidence.

SOU-6 tracking: [Experimental Jev classifier](https://linear.app/soup-wall/issue/SOU-6/task-11-experimental-jev-classifier).
