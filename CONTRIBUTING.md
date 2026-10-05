# Contributing to Soup Wall

Soup Wall is an Apache-2.0 project. The Agent, Gateway, Console, and their supporting crates live in this repository. Contributions to detectors, policy, provider handling, identity, administration, usage evidence, documentation, and deployment are welcome.

The current Gateway executable is named `llm-firewall`; its `LLM_FW_*` variables and existing HTTP headers are compatibility interfaces. Please discuss a migration before changing names that affect clients, stored tokens, cryptographic domain separation, or deployment state.

## Working as a team

Use English for documentation, code comments, user-facing messages, issue descriptions, pull requests, and review discussions. Keep multilingual security payloads, Unicode regression fixtures, protocol data, upstream names, and immutable historical evidence intact; their original bytes can be part of the behavior under test.

Start with the [development guide](docs/DEVELOPMENT.md) for prerequisites, the workspace map, and focused checks. Use the [documentation index](docs/README.md) to find the current guide rather than adding another planning or status document. The [roadmap](docs/ROADMAP.md) is the single current plan; dated evidence belongs beside its reproduction procedure.

Keep internal drafts, unaccepted specifications and personal notes in ignored `local-notes/`. Accepted interfaces, decision rationale, reproduction procedures and sanitized evidence belong in the public documentation. The source baseline is `baseline/team-handoff`; the roadmap plans one final product release after all required phases pass. Ordinary commits and private candidate builds do not publish a release.

1. Choose a bounded issue or describe the intended behavior before a large API or architecture change. Report vulnerabilities through [SECURITY.md](SECURITY.md).
2. Create a topic branch, conventionally `codex/<short-description>` for Codex-assisted work. External contributors can use a fork. Keep unrelated changes in separate pull requests.
3. Implement the change, update the relevant documentation, and run the checks below plus the focused checks for the affected surface.
4. Open a pull request describing the problem, resulting behavior, compatibility impact, and verification. Identify skipped checks and any required environment. Link the issue when one exists.
5. The author addresses review findings; reviewers check behavior, boundaries, compatibility, and evidence. Release or deployment acceptance requires an operator to run the applicable procedure in the intended environment. A local fixture result does not replace that acceptance.

Do not commit local credentials, `.env` files, customer payloads, model weights, build outputs, or unreviewed external datasets. Use minimal synthetic examples in issues and pull requests. Keep attribution and evidence that support published claims when removing obsolete documentation.

## Before opening a pull request

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
python3 -m unittest discover -s scripts/benchmarks -p 'test_*.py' -v
```

On Windows, use `python` instead of `python3`. These Python suites contain environment-dependent skips; report them explicitly. Full CI also checks optional features, platform-specific behavior, dependency and license policy, containers, and service integrations. The [development guide](docs/DEVELOPMENT.md#verification) explains their scope. For documentation-only changes, verify relative links, commands, and the affected claims; no new behavior tests are needed.

For an optional ML change, fetch only the reviewed model asset required by the feature and run its focused checks. Model weights and datasets have separate licenses and are not covered by the Rust workspace's Apache-2.0 declaration. See [source provenance](docs/PROVENANCE.md).

Keep a pull request focused. Describe the behavior, threat or user need, compatibility impact, and how you verified it. Update the user-facing instructions when a setting, API, or default changes.

## Security changes

For a security-relevant behavior change, include a regression case that exercises the intended boundary. For a bypass, retain a safe version of the payload that demonstrated it. State whether failures allow or block the action, and make audit output useful without logging prompts, completions, credentials, raw tokens, or identity assertions.

Check both sides of an authorization boundary: a permitted action still works, and the same action is refused for an unauthorized user, workspace, tenant, or agent. Browser visibility is not authorization; enforce roles in the server and storage layers. Changes to provider streaming must account for fragmented events and tool calls as well as buffered responses.

If you change an agent rule or the shipped policy, run the reviewed corpus:

```sh
cargo run --locked --release -p soup-wall-bench -- \
  --agent crates/bench/corpora/agent_sessions.jsonl \
  --policy path/to/your-policy.yaml
```

The gate fails if a reviewed attack is missed or a reviewed benign session is interrupted. Do not change corpus labels merely to make a rule pass. Add new cases with provenance and an explanation of the intended verdict.

## Evidence and claims

The agent-session corpus is hand-authored. It checks known cases but does not establish detection rates on novel attacks. Report malicious recall and benign false-positive rate together for a genuinely held-out evaluation, and document its data, method, model assets, and limitations in [benchmark methodology](docs/methodology.md). Do not advertise a percentage from the in-repository agent corpus.

Do not describe local OIDC, SAML, or SCIM fixtures as certification against a customer identity provider. Do not describe read-only invoice previews or spend admission counters as final billing. Update [README.md](README.md) and [self-hosting guidance](docs/SELF_HOSTING.md) when release evidence changes these limits.

## License and attribution

Keep SPDX identifiers, [LICENSE](LICENSE), and [NOTICE](NOTICE). Soup Wall derives from [carbon-evolution/llm-firewall](https://github.com/carbon-evolution/llm-firewall) by Arthur Lin and contributors. Record the origin, version, license, and required notices for any new external code, model, dataset, or frontend asset under the [provenance rules](docs/PROVENANCE.md).
