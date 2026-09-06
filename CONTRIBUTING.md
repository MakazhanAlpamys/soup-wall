# Contributing

## What belongs here

This repository is the local Core: detectors, the agent reference monitor, the daemon, the
adapter contract, and the regression tooling. It protects one developer on one machine, needs no
account, and makes no network call of its own.

It deliberately does not contain the HTTP proxy for provider traffic, SSO, SCIM, multi-tenant
administration, usage ledgers, or billing. A change that needs any of those is not a Core change.
CI enforces one consequence of that: a dependency that only ever belonged to that layer
(`saml-rs`, `rsa`, `tokio-postgres`, `redis`, `jsonwebtoken`) fails the build if it enters
`Cargo.lock`.

## Before opening a pull request

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Every security-relevant change needs, in the same pull request:

- a regression test, and for a bypass, the payload that demonstrated it;
- an explicit fail-open or fail-closed decision, stated in a comment where the decision is made;
- audit evidence that stays privacy-safe (no prompts, tokens, or secrets in telemetry).

If you change an agent policy rule or the default policy, gate it against the reviewed corpus
before enforcing it anywhere:

```sh
llm-firewall-bench --agent crates/bench/corpora/agent_sessions.jsonl --policy <your-policy.yaml>
```

It exits non-zero if any reviewed attack is now missed or any reviewed benign session is now
interrupted. Fix the rule, not the corpus.

## Numbers

Do not add a detection or false-positive percentage to the README or documentation from the
hand-authored corpus. It measures coverage of reviewed attack shapes, not generalization; raw
counts are the honest form. Held-out results belong in `docs/methodology.md` with the method
that produced them.

## Provenance

External code, models, and datasets go through the intake lanes in `docs/PROVENANCE.md` before
they are introduced. Keep SPDX headers on every source file.
