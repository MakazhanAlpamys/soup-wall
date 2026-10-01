# Contributing to Soup Wall

Soup Wall is an Apache-2.0 project. The Agent, Gateway, Console, and their supporting crates live in this repository. Contributions to detectors, policy, provider handling, identity, administration, usage evidence, documentation, and deployment are welcome.

The current Gateway executable is named `llm-firewall`; its `LLM_FW_*` variables and existing HTTP headers are compatibility interfaces. Please discuss a migration before changing names that affect clients, stored tokens, cryptographic domain separation, or deployment state.

## Before opening a pull request

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

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
