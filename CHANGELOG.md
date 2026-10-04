# Changelog

Changes to the public Soup Wall source distribution are recorded here. Release artifacts and their checksums are published on [GitHub Releases](https://github.com/MakazhanAlpamys/soup-wall/releases).

## Unreleased

- Fixed Windows Agent installation instructions and honored IPv4, IPv6, and
  localhost binds consistently across daemon clients. Added disposable Windows
  ACL, enforcement, shadow, and outage acceptance checks.
- Added an isolated Gateway binary acceptance command covering SQLite Console,
  authentication, provider forwarding, blocked requests, and restart persistence.
  Recorded published v0.4.0 binary checks and local PostgreSQL/Redis recovery and
  encrypted restore evidence.
- Added native Claude Code HTTP-hook acceptance using deterministic loopback
  model fixtures. Corrected outage guidance: connection failure can return
  immediately; the configured timeout is a ceiling, not a mandatory delay.
- Added agent evaluation JSON with immutable input snapshots, exact hashes,
  interruption outcomes, replay latency, and atomic output. Failed candidate
  gates retain evidence in CI. Added a pinned independent AgentDojo historical
  importer and recorded the current native-tool coverage gap without claiming
  live effectiveness.
- Added a checkpointed roadmap execution record. Managed staging, real-IdP,
  live-model evaluation, and shadow soaking remain open acceptance gates.

## v0.4.0 — full-source Soup Wall

- Added the Gateway and self-hosted Console source to the public Apache-2.0 workspace. This is a reviewed source snapshot; the former private repository's Git history is not part of the public history.
- Added OpenAI Chat Completions and Responses, Anthropic Messages, tenant policy and identity, usage evidence, read-only invoice previews, and the associated deployment and operations templates to the public distribution.
- Unified the Soup Wall mark and visual identity across the README and browser pages. Existing `llm-firewall` executable, `LLM_FW_*` settings, headers, token prefixes, and stored identifiers remain for compatibility; release archives also carry a `soup-wall-gateway` executable alias.
- Expanded CI, advisory scanning, SBOM generation, and the release workflow to the complete workspace and Gateway container. Added self-hosting, upgrade, architecture, provenance, and security guidance.
- Updated `rustls` for the TLS handshake advisory and incorporated the reviewed `clap` and `rand` patch updates.

See the [roadmap](docs/ROADMAP.md) for field validation work and the [upgrade guide](docs/UPGRADING.md) for existing installations. Release artifacts and checksums are published with the v0.4.0 release after verification.

## [v0.3.0](https://github.com/MakazhanAlpamys/soup-wall/releases/tag/v0.3.0) — Agent release

First public binary release of Soup Wall Agent, including the local `agentfw` daemon and CLI, Claude Code hooks, MCP proxy, policy and audit path, guarded execution, and the `soup-wall-bench` regression corpus. Its default was shadow mode. The Gateway and Console source were not in that tag.
