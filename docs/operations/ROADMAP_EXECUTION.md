# Roadmap execution checkpoints

Started: 2026-10-04. Scope: the public Soup Wall roadmap, open Soup Wall
issues, and maintenance pull requests in the former private LLM-Firewall
repository. This record distinguishes implementation, reproducible local
acceptance, hosted CI, and external field evidence.

Each checkpoint is committed and pushed after its relevant checks. A passing
local fixture does not complete a managed staging or real-IdP gate. Failures
remain visible; dependencies are never marked complete to make the plan green.

## Baseline

- Public source: `058a6cebab9bfb38e2c7f1da9d24da33ffa41b44`.
- Public main CI, identity-sandbox, benchmark, and supply-chain workflows passed
  on that commit, as checked on 2026-10-04.
- Core and agent tests passed locally on Windows before this execution began.
- Open public issue: [#19](https://github.com/MakazhanAlpamys/soup-wall/issues/19),
  portable SAML crypto and removal of the RSA advisory exception.
- Open legacy dependency PRs: #22 Redis, #23 HMAC, #24 Docker build action,
  #25 jsonwebtoken, #26 clap, #27 rustls.
- No managed staging address or real customer/test IdP has been supplied.

## Checkpoints

1. [x] **Execution plan and inventory.** Commit this record and link it from the
   roadmap; inspect all open issues and PRs and establish explicit acceptance
   criteria for the remaining release gates.
2. [x] **Windows Agent acceptance.** Exercise isolated installation, token and
   audit permissions, daemon health, shadow/enforce decisions, and daemon outage
   behavior. Add a repeatable acceptance command and retain aggregate evidence.
   Also verify actual Claude Code hook enforcement, shadow and connection
   failure with deterministic local model responses.
3. [x] **Self-hosted local acceptance.** Exercise Gateway preflight, SQLite
   Console, provider protocol handling against a disposable fixture, deployment
   configuration, PostgreSQL/Redis integration, dependency failure and restore
   where local tools permit. Record environment and actual results.
4. [ ] **Security and maintenance.** Review and test the six legacy PRs; resolve
   safe updates. Investigate #19 using current upstream evidence and retain
   encrypted-assertion rejection and portable release builds. Close it only when
   its stated acceptance criteria are satisfied.
   Legacy PR maintenance is complete; four-platform SAML signature/provider
   checks are complete. Removal of RSA on Windows and real-IdP acceptance remain.
5. [ ] **Evaluation and field readiness.** Provide a reproducible evaluation
   path with pinned sources, policy, attack and benign outcomes, and latency.
   Run the checks possible in this environment, then run managed staging,
   restore and real-IdP acceptance if authorized infrastructure is available.
   Keep a precise record of any remaining external dependencies.
   The pinned historical importer, fidelity checks, outcome JSON and negative
   baseline and the verified native-runtime fallback adapter are complete.
   Native semantic coverage and the operator-selected live field run remain.
6. [x] **Integration and release review.** Review changes, run required checks,
   push focused PRs, record CI results, and reconcile roadmap, operator guidance,
   and changelog with the evidence. Do not publish a new release or claim field
   validation on the strength of source-level tests alone.

## Remaining external acceptance criteria

| Gate | Required evidence |
| --- | --- |
| Managed self-hosting | Installation from a published artifact; successful preflight; authenticated Console; a benign provider request and a blocked request; PostgreSQL migrations; TLS deployment record |
| Recovery | Timestamped PostgreSQL and Redis failure/recovery phases, encrypted backup restored into an isolated database, alert routing observed |
| Identity | Real OIDC login/session lifecycle, signed SAML acceptance and rejection, supported SCIM provisioning/revocation against an operator-selected IdP |
| Agent effectiveness | Independent held-out provenance, missed attacks and interrupted benign tasks, task utility and latency, exact source and policy versions |
| SAML crypto #19 | No vulnerable RSA crate in locked release graph; reviewed portable crypto; no encrypted assertion decryption; target build and signature/interoperability evidence |

## Evidence log

Entries below will name the source commit, command or CI run, result, and the
scope that result establishes. Public records must contain no bearer tokens,
provider credentials, identity assertions, prompts, or customer data.

- Plan checkpoint: `53f35e8`, committed and pushed on 2026-10-04.
- Gateway release acceptance: Windows archive `v0.4.0`, verified against the
  release `SHA256SUMS` (`0502b8d6f8596d72c1168d8ccd4efc71c707f14b8cc3e36eb062a8169c9c75a7`).
  `self-hosted-local-acceptance.py` passed all 15 checks at
  `2026-10-04T17:18:42.447018+00:00`. Gateway binary SHA-256:
  `3818ba06b6a8191e3c5a5a1ca7c8f6044468e87484c9dfcbd00107b78ee8b85a`.
  This establishes release binary, preflight, SQLite Console, tenant auth,
  loopback-provider forwarding/blocking, and restart persistence on Windows.
  It does not establish a managed staging deployment or real-provider behavior.
- Offline evaluation checkpoint: `--agent-out` records exact input/binary hashes,
  policy outcomes, misses, benign interruptions and cold policy-replay latency.
  The shipped regression corpus reports 19 interrupted attacks, 21 uninterrupted
  benign sessions, no misses and no benign interruptions. An allow-all candidate
  exits 1 and retains all 19 missed attacks in its JSON evidence. This is still
  the synthetic regression baseline, not independent field effectiveness.
- Windows checkpoints: `c764f3f` adds native setup and 70-check acceptance;
  `35adf01` fixes configured loopback addresses and raises the acceptance to
  72 checks for IPv4, IPv6 and localhost. Agent tests and Clippy passed; see
  [native Windows evidence](WINDOWS_AGENT_ACCEPTANCE.md).
- Local dependency/recovery checkpoint: PostgreSQL and Redis integration tests
  passed. The verified v0.4.0 Gateway passed preflight, migrations and baseline
  acceptance with disposable PostgreSQL 18.6 and Redis 8.0.5. Both failure
  phases returned readiness 503 with liveness 200; recovery returned readiness
  200. The encrypted restore passed into a separate database, retaining two
  tenants and two security events, and rejected a source-database alias.
  [Commands, limits and timestamped evidence](LOCAL_RELEASE_ACCEPTANCE.md).
- Legacy maintenance checkpoint: `4898d49` is pushed in
  [LLM-Firewall PR #31](https://github.com/MakazhanAlpamys/LLM-Firewall/pull/31).
  All 695 default tests, Clippy, compatibility vectors, package-contract checks,
  advisory gate with the existing RSA exception, and explicit Redis/PostgreSQL
  integration checks passed. All nine configured hosted jobs passed, including
  PostgreSQL 16 and Redis 7 integration. Windows/all-features/actual CodeQL were
  deliberately skipped in that private CI configuration; the green explanation
  job is not a CodeQL scan. PR #31 merged as `ab3b34de923242bfc1b5ed45d5dc3e2a26a76e14`.
  Original #22/#23/#25/#26/#27 are closed as superseded; #24 is closed as obsolete
  because the legacy release workflow was deleted. No legacy PRs remain open.
- SAML provider checkpoint: `9174490` is pushed in
  [Soup Wall PR #23](https://github.com/MakazhanAlpamys/soup-wall/pull/23).
  It merged as `65bee72917e34f260da34162094f1a21030f7005` after independent
  provider/feature review and all hosted checks passed.
  Windows/Linux signed, tampered and encrypted-assertion fixtures, Gateway
  library tests, Clippy and Microsoft's public signed-metadata probe passed.
  The supported Linux/macOS graphs exclude RSA; Windows still includes it.
  All 18 hosted checks passed, including the four SAML release targets, full
  source checks, identity sandbox, CodeQL, and Docker. Issue #19 remains open:
  the Windows provider and real-IdP assertion acceptance still require their own
  evidence.
- Independent replay checkpoints: `08f9157` freezes 80 public AgentDojo histories
  and verifies selection, source hashes and native tool fidelity; `99c4e6c` records
  354 events with 0/40 interrupted injection attempts and 0/40 interrupted benign
  sessions under the unchanged default policy. The explicit policy gate fails
  and retains JSON evidence. This exposes the native-tool adapter boundary,
  not a count of successful attacks. Eight importer tests pass without network
  access. [Source review, reproduction and live-run plan](../benchmarks/independent-history-replay.md).
- Real host checkpoint: `e9679d1` runs native Claude Code 2.1.289 with the actual
  Agent HTTP hooks, Read and a harmless disposable shell marker. All 41 checks
  pass: enforce prevents the marker; shadow and offline permit it. Nine model
  requests reach the authenticated loopback fixture, with zero outbound proxy
  attempts. This establishes host integration and fail-open behavior for the
  custom fixture policy, not shipped-policy effectiveness or field soaking.
  [Command and evidence](CLAUDE_HOST_ACCEPTANCE.md).
- Integration verification: `0a9fa83` incorporates merged SAML hardening into
  the checkpoint branch. Required Windows formatting and workspace Clippy pass;
  all 719 default workspace tests pass, with five explicitly ignored checks
  (live local-model, dependency services, and external identity). The earlier
  isolated storage tests and hosted storage jobs exercise the dependency cases.
  Both Gateway failure-evidence regressions and all eight importer tests pass.
  The rebuilt root Agent again passes all 41 real-host checks. Own disposable
  Gateway, PostgreSQL and Redis processes are stopped after the recovery drill.
  `e89d802` rejects symlink/junction redirection of the ignored datasets base;
  independent review found and verified this privacy boundary.
- Hosted integration: all 18 checks on `b7c8866` passed, including default and
  all-feature tests, CodeQL for Rust/Python/actions, four native SAML targets,
  Windows acceptance, Docker, storage integrations, advisory review and SBOM.
  [PR #22](https://github.com/MakazhanAlpamys/soup-wall/pull/22) merged as
  `6b150aa005cf311858272bb28c3d2b38296540e5`. This completes the implementation
  integration checkpoint; managed deployment and field gates above stay open.
- CodeQL follow-up: seven existing open alerts were reviewed against their
  scanned source. Six are test-only OIDC/SCIM fixtures; the production allocation
  is bounded by validation to 1000 records. Its runtime boundary rejects 0/1001
  before persistence and accepts 1000. Alerts are dismissed with individual
  reasons, retaining their history and all queries. Zero open alerts were
  verified afterward. [Review and reopening criteria](evidence/CODEQL_TRIAGE_2026-10-05.md).
- External OIDC discovery: the optional Google test first failed twice at the
  existing five-second connect timeout. An isolated probe of the exact production
  client then accepted discovery and two JWKS keys in 2.067 seconds; a later
  connection again timed out. Direct TCP/curl probes showed variable connection
  establishment. No reproducible client/TLS/proxy defect was demonstrated and no
  timeout or TLS checks were weakened. This is bounded metadata evidence plus
  an environment reliability limit, not interactive real-IdP login acceptance.
- Native runtime adapter: `0961bdf` adds an original, opt-in AgentDojo adapter
  for the existing `/hook` contract, preserving pinned native tool names,
  schemas, validation, dependencies, results and evaluators. All 29 actual
  runtime/disposable-Agent checks passed independently on Windows. The existing
  hosted benchmark discovers the free tests without provider credentials.
  Broken HTTP, malformed decisions and missing inspection stop a trajectory
  before reporting evaluators; immutable plan/policy snapshots, source hashes,
  explicit provider budgets and atomic evidence bind the measured experiment.
  The unchanged shipped policy retains its native semantic and result-gating
  limits; no real model or paid provider was called. [Reproduction and bounds](../benchmarks/agentdojo-live-fallback.md).
