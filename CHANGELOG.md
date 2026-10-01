# Changelog

Changes to the public Soup Wall source distribution are recorded here. Release artifacts and their checksums are published on [GitHub Releases](https://github.com/MakazhanAlpamys/soup-wall/releases).

## v0.4.0 — full-source Soup Wall

- Added the Gateway and self-hosted Console source to the public Apache-2.0 workspace. This is a reviewed source snapshot; the former private repository's Git history is not part of the public history.
- Added OpenAI Chat Completions and Responses, Anthropic Messages, tenant policy and identity, usage evidence, read-only invoice previews, and the associated deployment and operations templates to the public distribution.
- Unified the Soup Wall mark and visual identity across the README and browser pages. Existing `llm-firewall` executable, `LLM_FW_*` settings, headers, token prefixes, and stored identifiers remain for compatibility; release archives also carry a `soup-wall-gateway` executable alias.
- Expanded CI, advisory scanning, SBOM generation, and the release workflow to the complete workspace and Gateway container. Added self-hosting, upgrade, architecture, provenance, and security guidance.
- Updated `rustls` for the TLS handshake advisory and incorporated the reviewed `clap` and `rand` patch updates.

See the [roadmap](docs/ROADMAP.md) for field validation work and the [upgrade guide](docs/UPGRADING.md) for existing installations. Release artifacts and checksums are published with the v0.4.0 release after verification.

## [v0.3.0](https://github.com/MakazhanAlpamys/soup-wall/releases/tag/v0.3.0) — Agent release

First public binary release of Soup Wall Agent, including the local `agentfw` daemon and CLI, Claude Code hooks, MCP proxy, policy and audit path, guarded execution, and the `soup-wall-bench` regression corpus. Its default was shadow mode. The Gateway and Console source were not in that tag.
