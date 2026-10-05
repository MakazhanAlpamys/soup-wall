# Developing Soup Wall

This guide is the starting point for contributors working on the Agent, Gateway
or Console. The default build and local regression checks need no model weights,
provider account or paid API key. See the [documentation index](README.md) for
product and deployment guides, and [CONTRIBUTING](../CONTRIBUTING.md) for pull
request expectations.

## Prerequisites

- Git and the stable Rust toolchain installed through rustup. The repository's
  [rust-toolchain.toml](../rust-toolchain.toml) selects `stable`, `rustfmt` and
  `clippy`; [Cargo.lock](../Cargo.lock) fixes dependency versions.
- Python 3.10 or later, including the standard library. On Windows, `python`
  must resolve to that interpreter; on Linux and macOS, use `python3`. The Rust
  MCP integration tests use those exact executable names to start a harmless
  local server. Check `python --version` or `python3 --version` before testing.
- A native C/C++ compiler and linker for dependencies such as AWS-LC and bundled
  SQLite. Rust alone is not the complete native build environment.

| Platform | Native build environment | Additional platform distinction |
| --- | --- | --- |
| Windows x86_64 MSVC | Visual Studio C++ Build Tools and the Windows SDK | Use PowerShell for Windows acceptance scripts. The Gateway enables AWS-LC's `prebuilt-nasm` feature; supported non-FIPS x86_64 builds can use its prebuilt objects when NASM is absent. |
| Linux | A C/C++ development toolchain, such as GCC or Clang with the system linker | Guarded shell execution additionally needs `bubblewrap` and working user namespaces. |
| macOS | Xcode Command Line Tools | The Linux shell sandbox and native Windows ACL/DPAPI checks cannot be exercised here. |

Consult the official AWS-LC requirements for [Linux](https://aws.github.io/aws-lc-rs/requirements/linux.html),
[macOS](https://aws.github.io/aws-lc-rs/requirements/apple.html) and
[Windows](https://aws.github.io/aws-lc-rs/requirements/windows.html), including
target-specific compiler and assembly requirements. These are native build
prerequisites; Soup Wall does not claim a FIPS-validated release. The current
SAML provider selection and unresolved advisory are documented in
[source provenance](PROVENANCE.md).

## First checkout and build

The initial clone and dependency download require network access. Neither step
calls a model provider or fetches model weights. Clone the repository, then run
Cargo commands from its root:

```sh
git clone https://github.com/MakazhanAlpamys/soup-wall.git
cd soup-wall
cargo fetch --locked
cargo build --locked --workspace
```

Debug executables are under `target/debug`; Windows executable names end in
`.exe`. Add `--release` for binaries under `target/release`. The Gateway's Cargo
package and executable remain `llm-firewall`, and its `LLM_FW_*` environment
variables remain compatibility interfaces. See [upgrading](UPGRADING.md) before
changing an existing installation.

Keep the repository root as the working directory: `firewall.yaml` references
`policies/default.yaml`, and the shipped-policy tests check that configuration.
Use the [self-hosting guide](SELF_HOSTING.md) when you want to run a daemon or
Console; development checks do not require installing hooks into your own
Claude Code profile.

## Verification

After the Rust dependencies are cached, the following Cargo checks refuse
dependency downloads through `--offline`. The tests use local fixtures,
temporary files and loopback listeners; they do not require a real model
provider, external IdP, PostgreSQL or Redis.

```sh
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets -- -D warnings
cargo test --locked --offline --workspace
```

Run both Python regression suites. On Windows:

```powershell
python -m unittest discover -s scripts/tests -p 'test_*.py' -v
python -m unittest discover -s scripts/benchmarks -p 'test_*.py' -v
```

On Linux or macOS:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
python3 -m unittest discover -s scripts/benchmarks -p 'test_*.py' -v
```

For an agent policy or action-classification change, also run the reviewed
corpus gate:

```sh
cargo run --locked --offline -p soup-wall-bench -- --agent crates/bench/corpora/agent_sessions.jsonl
```

Use `--policy path/to/your-policy.yaml` to check a candidate policy. The corpus
checks known attack and benign cases; it is not evidence of protection against
new attacks. The [methodology](methodology.md) explains the generated scorecard
and evidence requirements.

These commands are a contributor baseline, not the complete CI matrix. The
workflows under [.github/workflows](../.github/workflows) also cover optional
features, platform targets, service integrations, release assets and security
checks. On Windows, [ci-local.ps1](../scripts/ci-local.ps1) provides a configurable
wrapper for selected Rust, advisory and scorecard checks.

Check local documentation links and heading anchors without network access:

```sh
python3 scripts/check_docs.py
```

On Windows, use `python`. Stage new linked files before this check so Git can
identify them as versioned targets. The checker reads inline Markdown links and
images, HTML image sources and ATX heading anchors; it skips fenced code and
external URLs. It does not validate remote websites or every Markdown extension.
Links into ignored personal notes fail even if the files exist locally. The
`Documentation links` CI job runs for every pull request base branch.

## Source map and focused checks

Read the [architecture](ARCHITECTURE.md) for component relationships and actual
decision boundaries. Cargo package names differ from some directory names:

| Source | Responsibility | Focused starting check |
| --- | --- | --- |
| [`crates/core`](../crates/core) | Text detectors, normalization, scoring, masking and YAML policy | `cargo test --locked -p soup-wall-core` |
| [`crates/agent`](../crates/agent) | Agent events, taint, action/egress policy and subagent authority | `cargo test --locked -p soup-wall-agent` |
| [`crates/agentfw`](../crates/agentfw) | Local daemon, hooks, MCP admission, grants, audit and guarded execution | `cargo test --locked -p agentfw`; for the stdio boundary, add `--test mcp_admission` |
| [`crates/proxy`](../crates/proxy) | Gateway protocols, streaming, identity, tenant store and Console | `cargo test --locked -p llm-firewall`; select a relevant test target such as `--test proxy_streaming` |
| [`crates/adapter`](../crates/adapter) | Versioned decision and audit types | `cargo test --locked -p soup-wall-adapter` |
| [`crates/bench`](../crates/bench) | Corpus readers, policy gates and reports | `cargo test --locked -p soup-wall-bench`, then the corpus gate above |

The Console's HTML and JavaScript are embedded in
`crates/proxy/src/admin_dashboard.html`, `customer_dashboard.html` and
`workspace_invitation.html`; there is no separate Node frontend build.
`scripts/tests` covers acceptance-driver safety, and `scripts/benchmarks` covers
historical-import and runtime-adapter contracts. Deployment examples live in
`deploy/`; text and agent policies live in `policies/` and
`crates/agent/policies/`, respectively.

## Optional checks and environment limits

Read the test output for skips and ignored cases. A passing baseline does not
establish coverage of an environment that was unavailable:

- Native Windows ACL and DPAPI checks require Windows. Positive Linux shell
  sandbox tests may skip when `bubblewrap` or user namespaces are unavailable;
  the production path still refuses unsupported execution. Use the
  [sandbox guide](operations/SANDBOX.md) and
  [Windows Agent acceptance guide](operations/WINDOWS_AGENT_ACCEPTANCE.md).
- Redis and PostgreSQL integration tests are ignored by default. They require
  explicitly configured disposable instances through `LLM_FW_TEST_REDIS_URL`
  and `LLM_FW_TEST_POSTGRES_URL`. Run the selected ignored test only after
  reviewing its setup; do not point it at customer state. See the
  [staging drills](operations/STAGING_DRILLS.md) and
  [production runbook](operations/PRODUCTION_RUNBOOK.md).
- External identity probes are ignored by default. Local OIDC/SAML/SCIM fixtures
  and the optional Keycloak driver have separate prerequisites. Some driver
  safety tests skip without `requests`; use the pinned environment described in
  [Keycloak acceptance](operations/KEYCLOAK_SAML_ACCEPTANCE.md) for full coverage.
  [Identity interoperability](operations/IDENTITY_INTEROPERABILITY.md) distinguishes
  local fixtures from real-IdP checks.
- Actual Claude Code host checks require an installed native Claude Code and
  Git Bash on Windows. Their deterministic loopback providers need no paid
  model. Follow [HTTP-hook acceptance](operations/CLAUDE_HOST_ACCEPTANCE.md) or
  [stdio MCP admission](operations/MCP_STDIO_ADMISSION.md); these fixtures do not
  measure live-model effectiveness.
- AgentDojo runtime fixtures require the explicitly selected pinned upstream
  checkout and its separate Python environment. Follow the
  [runtime adapter guide](benchmarks/agentdojo-live-fallback.md) and
  [native admission contract](benchmarks/native-admission.md). Real-model
  evaluation additionally requires selected access and explicit spend limits.

## Optional ML and contribution workflow

The default features use signatures and heuristics. `--all-features` compiles
the optional ML stack, but compilation alone does not supply or validate model
assets. Classifier assets are fetched separately through
[`scripts/fetch-model.sh`](../scripts/fetch-model.sh). Review their provenance,
licenses and the [benchmark methodology](methodology.md) before downloading or
evaluating them; model weights and third-party datasets have separate terms.

Keep project prose, public instructions and UI text in English. Preserve
intentional multilingual, Unicode, homoglyph and byte-boundary fixtures that
exercise security or transport behavior. Follow [CONTRIBUTING](../CONTRIBUTING.md)
for regression cases, compatibility and pull request descriptions, and
[SECURITY](../SECURITY.md) for private vulnerability reports.

Keep internal notes, draft specifications and personal scratch work under
ignored `local-notes/`; generated `docs/plans/`, `docs/superpowers/` and
`.superpowers/` directories are also local. They are excluded from Docker build
contexts. Publish
reviewed interfaces and sanitized evidence in their canonical guides. The
[roadmap](ROADMAP.md) identifies the source baseline, dependency-ordered phases
and the single final release gate.

Use fresh evidence destinations under `target/` for local runs. Commit reviewed,
sanitized evidence only when it supports a stated claim; retain the distinction
between unit tests, local integration, hosted CI and external evaluation.
The [documentation index](README.md) links the status and evidence records.
