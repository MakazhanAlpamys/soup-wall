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

1. [ ] **Execution plan and inventory.** Commit this record and link it from the
   roadmap; inspect all open issues and PRs and establish explicit acceptance
   criteria for the remaining release gates.
2. [ ] **Windows Agent acceptance.** Exercise isolated installation, token and
   audit permissions, daemon health, shadow/enforce decisions, and daemon outage
   behavior. Add a repeatable acceptance command and retain aggregate evidence.
3. [ ] **Self-hosted local acceptance.** Exercise Gateway preflight, SQLite
   Console, provider protocol handling against a disposable fixture, deployment
   configuration, PostgreSQL/Redis integration, dependency failure and restore
   where local tools permit. Record environment and actual results.
4. [ ] **Security and maintenance.** Review and test the six legacy PRs; resolve
   safe updates. Investigate #19 using current upstream evidence and retain
   encrypted-assertion rejection and portable release builds. Close it only when
   its stated acceptance criteria are satisfied.
5. [ ] **Evaluation and field readiness.** Provide a reproducible evaluation
   path with pinned sources, policy, attack and benign outcomes, and latency.
   Run the checks possible in this environment, then run managed staging,
   restore and real-IdP acceptance if authorized infrastructure is available.
   Keep a precise record of any remaining external dependencies.
6. [ ] **Integration and release review.** Review changes, run required checks,
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
