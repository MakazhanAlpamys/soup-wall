# Local learned classifier preparation (SOU-16)

This optional CPU pipeline prepares a learned reference candidate for
[SOU-16](https://linear.app/soup-wall/issue/SOU-16/task-10-run-an-open-model-classifier-pilot-in-shadow-mode).
It returns semantic `actions` and separate Boolean `unknown`, never a policy
verdict, permission or executed tool call. The semantic reference is the owner's candidate
[contract 0.4-approved, D01-D10](https://github.com/SoupTeam/soup-wall/blob/5a3ff08fae333cd15bdf80345a240ca527a8872b/contract/updated_contract2.md).
Full SOU-10 contract review and production integration remain separate.
Technical inference exceptions remain separate failures for the caller to stop
before policy/execution; the evaluator records them separately from labels.

**Status: pipeline preparation, not a completed approved pilot.** On 9 October,
@aisarasd confirmed that the local linear baseline is suitable
for the first pilot. SOU-13 data remains preliminary; she expects split manifests
by 11 October and training/calibration data after review. No approved dataset
has yet been supplied. Shared evaluation fixtures from PR #52
never enter training or calibration. Development smoke results below cannot
establish holdout generalization, production gates or task acceptance.

## Candidate and limits

The candidate is newly trained logistic regression with five sigmoid action
heads and a separate unknown head. It is original Apache-2.0 code under this
repository's license. Python 3.10+ and the standard library suffice: no external
weights, model downloads, Torch dependency, API or paid compute. It is a learned
reference baseline, not a pretrained language model or encoder fine-tune.
The coordinator accepted this candidate for the first SOU-16 pilot; a reviewed
open encoder can be compared later if required. No encoder has been trained.

Hashed binary features use name, schema/property keys and actual arguments.
Descriptions stay bounded input data but are excluded from learned features;
changing a description cannot change a prediction. Runtime validation against
the admitted pinned schema belongs to the adapter. Hash collisions and limited
linear capacity can harm generalization. This is not a security boundary.
Inputs are bounded to 16 KiB, 2,048 JSON nodes, depth 16 and 512 distinct tokens.
Oversize/malformed input fails without truncating actual arguments. Inference
receives no IDs, family, split or gold labels.

## Unknown labels and calibration

Each action label is `true`, `false` or `null`. `null` contributes **no action
loss, decay or gradient** for that head. A fully unknown example can supervise
only the separate unknown head; a completely unannotated row changes no weights.
`false` explicitly supervises absence and is never inferred from missing data.
Partial examples preserve known positive effects and mask undetermined heads.

Training uses only train rows, shuffled with a fixed seed. Calibration changes
only thresholds on a separate family-disjoint split. The exploratory grid is
negative {0.1,0.2,0.3}, positive {0.7,0.8,0.9}; its objective weights critical
misses at 20, other misses at 1, false positives at 2, lost unknown at 20 and
abstention at 0.5. These starting values need review; they are not agreed
production criteria. Confidence is binary certainty, not calibrated joint
correctness or authorization.

Actions above the positive threshold survive. Intermediate scores, a positive
unknown-head score or more than half unseen feature bins retain unknown. This
heuristic can still miss unfamiliar semantics or abstain too often. Predicted
no-op remains an untrusted model claim and grants no permission.

## Development smoke check

```sh
python -m unittest experiments.local_classifier.test_model -v
python -m unittest experiments.local_classifier.test_ledger -v
python -m experiments.local_classifier.pilot smoke \
  --baseline-path rule_baseline \
  --output-dir target/local-classifier-smoke
```

Smoke builds its own tiny synthetic examples. Its toy split tags do not
establish unseen tool families: names/patterns intentionally repeat for plumbing
checks. Evidence always says `development_smoke`, `approval=null` and
`official_heldout_run=false`. Output must be new or empty; weights stay in ignored
`target/`. The baseline is now available in main from
[PR #53](https://github.com/SoupTeam/soup-wall/pull/53), initially frozen at
`000136c51884e0c204ac51b77c29c5c302f7256a`.

## Approved-data experiment

The loader accepts this experimental local dataset shape; it does not redefine
the shared adapter/classifier/policy contract:

```json
{
  "format": "soup-wall/classifier-dataset/1",
  "cases": [{
    "id": "training-example", "family": "reviewed-file-family", "split": "train",
    "input": {"tool_name": "read_file", "raw_arguments": {"path": "fixture/notes.txt"}},
    "labels": {"read": true, "write": null, "delete": null, "send_data": null,
               "change_permissions": null, "unknown": true}
  }]
}
```

An actual dataset requires nonempty train/calibration/holdout splits, unique IDs
and reviewed family annotations. The loader rejects family overlap and
cross-split semantic duplicates, including description-only variations.
Validation cannot prove annotation correctness. The example above is not an
approved dataset. A separate review file records its exact byte digest:

```json
{
  "format": "soup-wall/classifier-data-approval/1",
  "approval_reference": "<actual coordinator review link>",
  "source": "<reviewed dataset origin>",
  "license": "<reviewed dataset license>",
  "dataset_sha256": "<exact reviewed SHA-256>"
}
```

The review record asserts experimental provenance, not execution authorization.
Do not invent review references or relabel evaluation fixtures as training data.
Dataset JSON is bounded to 16 MiB/10,000 rows. Duplicate keys and non-finite
constants are rejected; validation and digesting consume the same bytes.

```sh
python -m experiments.local_classifier.pilot train \
  --dataset /path/to/approved.json --approval /path/to/review.json \
  --seed 42 --dimensions 512 --epochs 60 --output-dir target/approved-linear
python -m experiments.local_classifier.pilot evaluate \
  --dataset /path/to/approved.json --approval /path/to/review.json \
  --model-dir target/approved-linear \
  --baseline-path /path/to/frozen-rule-baseline \
  --run-authorization /custodian/pilot-run.json \
  --run-ledger-dir /custodian/shared-run-ledger
```

Train never passes holdout rows into fitting or threshold selection. Explicit
evaluation verifies the calibrated model digest and reviewed dataset, then
reserves holdout before inference using exclusive file creation. Repeating in
that artifact directory fails, even after an interrupted attempt. This local
guard cannot prevent copying artifacts or recreating runs: honest one-shot
evaluation also requires coordinator review and an external run ledger. After
inspecting holdout results, do not retune and call the same split untouched.

### Reviewed run ledger

Official evaluation now also requires a custodian-issued run record and an
existing shared ledger directory outside the model artifacts. The run record
binds the reviewed dataset bytes, frozen calibrated model and the exact baseline
source used in the comparison. It is an experimental bookkeeping format, not
the shared classification or execution-approval contract:

```json
{
  "format": "soup-wall/classifier-run-authorization/1",
  "run_id": "<reviewed experiment identity>",
  "holdout_id": "<custodian's stable identity for the untouched test manifest>",
  "approval_reference": "<actual review link for the frozen experiment>",
  "dataset_sha256": "<exact reviewed dataset SHA-256>",
  "model_sha256": "<frozen calibrated model SHA-256>",
  "baseline_sha256": "<frozen rule_baseline.py SHA-256>"
}
```

The custodian retains the same `holdout_id` and ledger for all copies/rebuilds
using those held-out cases. Changing model directories or `run_id` cannot reserve
that identity again in the same ledger. Exclusive file creation reserves the
attempt before holdout inference; interrupted attempts stay consumed. A separate
completion receipt binds the reservation and saved evaluation digests, while the
original reservation remains intact. Copying artifacts without their local marker
is covered by a regression check. Concurrent reservations admit only one attempt.

The JSON review reference is an assertion, not authenticated approval. The caller
can still select another ledger, forge a record or change `holdout_id`; filesystem
bookkeeping cannot prevent a dishonest experimenter. The reviewer/custodian must
control and reconcile the ledger, review identities and retain failed attempts.
This workflow grants no tool execution permissions or production acceptance.

### SOU-13 handoff prerequisites

The 10 October checkpoint contains only provisional development fixtures. It
does not supply approved pilot data, a final dataset license or frozen family
manifests. A technical review of these fixtures does not invent human sign-off.
Do not train or issue a real run authorization from that checkpoint alone.

Before training, SOU-13's owner and named reviewer must release reviewed labels
with rationale/evidence and the agreed dataset license. Export the five tri-state
action targets and separate unknown directly; check each known mask against null.
Do not derive negative targets from missing actions in `contract_view`. Pending
disputes and technical-error cases stay outside the training/evaluation export.

Freeze train/validation/calibration/test manifests before candidate variants or
tuning, with aliases and near-duplicate templates grouped by family. Keep the
validation manifest in the reviewed provenance; this linear pilot fits only train
and calibrates only calibration. The experimental export calls test `holdout`.
The export and all original manifests need review before their digest is approved;
the local three-split loader cannot independently establish the original four-way
family partition. A separate test custodian reviews held-out gold without exposing
it to the candidate author during development. Lock the same baseline source for
both the model comparison and the externally recorded experiment.

Evidence reports per-label critical misses/false positives with known-label
denominators, technical failures, unknown/coverage, mixed examples, p50/p95,
source/model/dataset hashes and peak process RSS. Traced Python allocation and
process RSS are distinct measurements. No GPU, external API or executor is used.
Zero API spend does not mean local CPU use is free. Policy outcomes and execution
enforcement are not measured.

## Dated evidence and recommendation

[9 October development evidence](evidence/2026-10-09-smoke.json) records an actual
60-epoch CPU training attempt on eight development examples, eight calibration
examples and eight development probes. This is learned training, not mocked
probabilities. It retains source hashes, masked-label counts, external baseline
hash, timings and resource observations; weights and datasets are not published.

**Recommendation: continue with the agreed linear candidate after data review.**
A small local linear run is feasible on this workstation. Developer
results do not support adoption/rejection of an open encoder and do not satisfy
SOU-16's untouched-family evaluation. Keep the issue in progress until code
review, agreed data, actual pilot comparison and continue/revise/reject decision
are reviewed.
