# Operator-installed native admission

The opt-in `sw-native/1` path keeps native function names, argument validation,
dependencies, returned values and the original upstream formatter. It adds
declared action and result-source semantics and a separate admission boundary
before a result enters the model. The existing Claude `/hook` contract and the
default [AgentDojo fallback](agentdojo-live-fallback.md) remain available.

This is a local collector contract, not proof of attack effectiveness. HTTP
authentication does not attest that a named function actually executed. The
collector, the operator-installed registry and its accurate semantic declarations
are trust boundaries. A compromised process running as the operator can read
the private keys or change the registry before startup.

## Immutable registry

The operator configures an absolute registry path and its exact SHA-256 in the
private Agent configuration:

```yaml
enforce: true
native:
  registry_path: 'C:/absolute/private/native-registry.json'
  registry_sha256: '<SHA-256 of the exact registry bytes>'
```

The daemon reads and validates that snapshot once at startup. Native admission
is disabled without it and requires enforcement. It uses a separately generated,
protected `.agentfw/native-token`; the regular Claude/MCP token cannot authorize
native requests. There is no HTTP registry installation/update endpoint.

Registry shape:

```json
{
  "contract_version": "sw-native/1",
  "registry_id": "operator-reviewed-runtime-v1",
  "tools": [
    {
      "name": "original_function_name",
      "schema_sha256": "<SHA-256 of canonical original JSON input schema>",
      "action_class": "read_only",
      "result_provenance": "untrusted",
      "egress": []
    }
  ]
}
```

Schema canonicalization is sorted-key compact JSON encoded as UTF-8, without
ASCII escaping or non-finite numbers. The original pinned function's
`parameters.model_json_schema()` supplies the schema; the Python adapter checks
that digest before execution. Semantics are reviewed operator inputs, never
inferred from a model-generated name, description or per-call declaration.

Action classes are `read_only`, `side_effecting`, `network`,
`privilege_changing` and `destructive`. Existing argument-pattern checks can
tighten the declared baseline. Result provenance is `untrusted`, `local_system`
or `local_project`; untrusted native content has its own `native` origin. It
does not pretend to be an MCP server or a fetched URL. The shipped policy adds
that actual origin to its existing untrusted-taint rules.

An egress selector is an explicit object such as
`{"pointer":"/recipients","kind":"email_domain","optional":false}`.
`url_host` and `email_domain` select actual destination strings or arrays from
validated arguments. Declare optional fields explicitly. Missing required or
malformed destinations fail inspection; destinations are never fabricated to
trigger a policy rule. Review tools that can send through several parameters
and include every relevant destination.

## Admission stages

Every `POST /native/v1` request includes `contract_version`, `registry_sha256`,
`session_id` and `event`. Unknown versions, fields, tools or schema identities
are errors. The collector supplies no authoritative action or trust fields.

| Event | Additional fields | Boundary |
| --- | --- | --- |
| `session_start`, `session_end` | none | Start/end the bounded native session |
| `call` | `tool`, `args`, `schema_sha256` | Validated native invocation before its real callable runs |
| `result` | `call_id`, `tool`, `args`, `result_kind`, `delivery`, `content` | Exact original formatted value or error before returning to its caller |
| `context` | `call_id`, `tool`, `args`, `content` | Exact serialized original tool-result message before release to the model |

An admitted call receives an unpredictable daemon-generated invocation ID bound
to the session epoch, registry, tool, schema and canonical arguments. Result
and context stages must match that binding and occur once in order. Records
expire and are removed at session end or daemon restart. `delivery` is `parent`
for a nested return or `model` for an outer result, derived by the trusted
collector from the original runtime stack. Parent admission completes that
record immediately and records its admitted source for subsequent calls. A
model-bound result stays internal and does not update taint or spans until its
actual context is admitted; preplanned calls in a batch cannot inherit taint
from content the model has not seen. Parent admission does not fabricate a
model-context event. The server bounds
sessions, invocations and content; oversized content is rejected in full.

Every successful response explicitly names the contract, registry, session and
event and returns `verdict`, `enforced`, `release`, `call_id`,
`binding_sha256`, `content_sha256` and `reason_codes`. The collector verifies the
exact invocation/content hashes. Empty responses, a changed binding, shadow
responses, malformed envelopes and transport failures never admit a result.

The context stage inspects the actual error when the original OpenAI serializer
would prefer it; otherwise it inspects the original text blocks individually.
It hashes the entire original serialized message. This catches a formatter
whose later output differs from an earlier inspected snapshot. Detection runs
before the original ToolsExecutor returns its messages, so subsequent model
calls and logging receive only admitted content. The adapter leaves the original
function result and formatter intact.

Context audit findings are the union of actual independently inspected blocks,
and `risk_score` is their maximum observed block score. Policy decisions are
evaluated on those original blocks; the adapter does not invent a concatenated
result for inspection or scoring.

Ask and Deny withhold content. This MVP has no human native approval channel
and does not redeem action grants for results. A withheld or uninspected
trajectory stops before reporting task evaluators; it is not counted as a
successful prevention. Withholding a result cannot undo effects the function
already performed. Nested functions retain their original ordering, including
effects that occurred before an outer invocation was withheld.

Native escalation uses the policy's declared fallback (or Ask if absent). This
MVP does not call the optional local judge through the native endpoint, including
when a judge is configured for the existing hook path. Review escalation
fallbacks as part of the installed native policy.

## Explicit evaluation

The default CLI remains a traffic-free manifest. A native live run adds
`--native-registry '<reviewed registry path>'` to the existing explicit
[live command](agentdojo-live-fallback.md#operator-selected-live-run). It still
requires a frozen task plan, selected model/provider/endpoint/credential
variable and every call, byte, output and estimated-cost budget. No credential
or model is selected automatically. The registry bytes are frozen before the
run and copied into each disposable defended daemon profile; evidence binds
that exact registry, adapter, executable and policy.

The manual free fixture uses actual pinned AgentDojo classes and harmless
original fixture functions, plus a disposable native-enabled Agent:

```text
target/agentdojo-venv/Scripts/python.exe -I scripts/agentdojo-live.py --mode native-fixture --upstream-checkout target/agentdojo-upstream --agent-binary target/debug/agentfw.exe --evidence target/native-fixture-new.json
```

This mode reserves fresh atomic evidence before startup and requires no model
or provider calls. Existing CI discovers transport/registry safety regressions
without runtime downloads. The manual runtime/daemon checks remain explicitly
gated on the pinned checkout and selected executable.

Current restrictions: one original ToolsExecutor, serial nested execution,
bounded/expiring invocation state, and no recovery after transport uncertainty.
Calls failing before their validated callable boundary stop the native run;
supporting original validation-error observations needs a separate correlated
no-execution admission record. Do not silently skip inspection or turn those
aborts into benchmark success. Live defended task utility, held-out outcomes,
registry coverage for actual selected tools and shadow soaking still need their
own evidence.
