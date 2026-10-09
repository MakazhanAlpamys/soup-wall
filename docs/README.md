# Soup Wall documentation

The canonical repository is [SoupTeam/soup-wall](https://github.com/SoupTeam/soup-wall).
Start with the [project README](../README.md) for the Agent, Gateway and Console
overview. Choose a guide below for development, operation or evaluation.

## Development and project navigation

| Guide | Purpose |
| --- | --- |
| [Development](DEVELOPMENT.md) | Prerequisites, platform differences, first build, local baseline and focused checks |
| [Clean setup and status preparation](operations/CLEAN_SETUP_ACCEPTANCE.md) | Disposable Agent installation, truthful daemon-status evidence and read-only scanning audit |
| [Contributing](../CONTRIBUTING.md) | Pull request expectations, regression cases and compatibility rules |
| [Architecture](ARCHITECTURE.md) | Workspace source map and decision boundaries |
| [Source provenance](PROVENANCE.md) | License intake, attribution and the current dependency/advisory boundary |
| [Security](../SECURITY.md) | Threat limitations and private vulnerability reporting |
| [Changelog](../CHANGELOG.md) | Released changes |

## Product and operator guides

| Guide | Purpose |
| --- | --- |
| [Self-hosting](SELF_HOSTING.md) | Build and run the Agent, Gateway and optional Console |
| [Upgrading](UPGRADING.md) | Existing deployment compatibility and migration guidance |
| [Production runbook](operations/PRODUCTION_RUNBOOK.md) | Readiness, operations, alerts and recovery |
| [Staging drills](operations/STAGING_DRILLS.md) | Explicit dependency and restore acceptance procedures |
| [Guarded execution](operations/SANDBOX.md) | Supported process, file and retrieval boundaries |
| [Windows Agent acceptance](operations/WINDOWS_AGENT_ACCEPTANCE.md) | Native installation, ACLs, hook posture and loopback configuration |
| [Claude HTTP-hook acceptance](operations/CLAUDE_HOST_ACCEPTANCE.md) | Actual host behavior with deterministic local model fixtures |
| [Opt-in stdio MCP admission](operations/MCP_STDIO_ADMISSION.md) | Reviewed schemas, pre-execution calls and result release to the MCP host |
| [Identity interoperability](operations/IDENTITY_INTEROPERABILITY.md) | Local identity fixtures, external metadata probes and pilot gates |
| [Keycloak SAML acceptance](operations/KEYCLOAK_SAML_ACCEPTANCE.md) | Pinned vendor-runtime setup and signed SAML checks |
| [Local release acceptance](operations/LOCAL_RELEASE_ACCEPTANCE.md) | Downloaded binary and archive acceptance scope |
| [Local monitoring acceptance](operations/LOCAL_MONITORING_ACCEPTANCE.md) | Scrape-outage and authenticated alert-delivery evidence |

## Benchmarks and evaluation

| Guide | Purpose |
| --- | --- |
| [Methodology](methodology.md) | Corpus, classifier and evidence methods with claim limits |
| [Generated scorecard](benchmarks/agent-security-scorecard.generated.md) | Exact output compared by CI; regenerate through the benchmark command |
| [Independent historical replay](benchmarks/independent-history-replay.md) | Pinned historical evidence and the original adapter's semantic limits |
| [AgentDojo runtime adapter](benchmarks/agentdojo-live-fallback.md) | Pinned runtime fixtures and explicit live-evaluation prerequisites |
| [Task 3 resilience](benchmarks/task3_resilience.md) | Malformed events, unknown tools, daemon failures and independent execution witnesses |
| [SOU-17 verification](benchmarks/sou17_verification.md) | Failure, overlap, replay and native witnesses; exact-source reproduction and code-scanning triage |
| [Native admission](benchmarks/native-admission.md) | Installed tool semantics, invocation binding and result/context contracts |
| [Corpus documentation](../crates/bench/corpora/README.md) | Versioned synthetic agent-session labels and provenance |
| [Local learned classifier preparation](../experiments/local_classifier/README.md) | Masked-label training, separate calibration and approved-data shadow pilot commands |

## Status and retained evidence

[ROADMAP](ROADMAP.md) records the tagged baseline, product principles,
dependency-ordered phases, open decisions and one final release gate. Internal
drafts and personal notes stay locally under ignored `local-notes/`.
Generated planning output under `docs/plans/`, `docs/superpowers/` and
`.superpowers/` also stays local. One-off review and alert-triage notes are kept
in `local-notes/reviews/`; public aggregate evidence remains versioned.
Dated evidence records refer to their original source commit and environment
and may mention historical paths. They are not automatic claims about the latest
checkout.

Reviewed aggregates and explanatory records are retained under
[operation evidence](operations/evidence) and
[benchmark evidence](benchmarks/evidence). Useful entry points include the
[Claude Code stdio MCP proof](benchmarks/evidence/CLAUDE_MCP_STDIO_2026-10-05.md),
[native runtime checkpoint](benchmarks/evidence/agentdojo-native-fixture-2026-10-05.md),
[Windows AWS-LC and Keycloak checkpoint](operations/evidence/SAML_PROVIDER_2026-10-06.md),
[historical Keycloak checkpoint](operations/evidence/KEYCLOAK_SAML_2026-10-05.md) and
[populated restore checkpoint](operations/evidence/POPULATED_RESTORE_2026-10-05.md).
Keep these records separate from onboarding instructions so their versions,
failures and limitations remain reviewable.
