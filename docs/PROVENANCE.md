# Source provenance and intake rules

This repository is derived from `carbon-evolution/llm-firewall` under Apache-2.0. Upstream
code keeps its copyright and patent terms; changes here must not remove SPDX headers,
`LICENSE`, `NOTICE`, or attribution. Attribution is carried by `NOTICE`, not by per-file
copyright lines, because a per-file line is a claim that cannot be established for every file.

## Intake lanes

Every external source belongs to exactly one lane before it is used:

1. **Permissive reuse** — MIT, Apache-2.0, BSD, ISC and similar. May be integrated after its
   origin, version, license and required notices are recorded.
2. **Reviewed copyleft** — GPL, LGPL, MPL, AGPL. Not added to a distributed binary, linked
   runtime, container image, or bundle until a documented review approves the exact use.
3. **Specification-only** — proprietary, non-commercial, research-only, source-available,
   unknown or incompatible terms. No source may be copied. Requirements may come from public
   documentation, standards, papers, interoperability behaviour, and independently written
   tests. A clean-room task uses a source-free behavioural specification and an independent
   implementation, with no fragments, distinctive names, comments, or line-by-line
   translations.

Model weights, benchmark datasets, and container images need their own review: their
licenses are not determined by this workspace's license.

## What this tree's dependencies look like

The `cargo audit` job in CI runs with no exceptions. The dependency tree here contains no
copyleft, unknown, or MPL crate. Two advisories are tolerated as warnings because they have no
upstream fix and are transitive: `paste` (unmaintained) and `chacha20` (yanked). They are stated
here so they are read rather than discovered.

## Test-only material

Nothing under `crates/*/tests` or `crates/bench/corpora` is a customer artifact. The agent
regression corpus is synthetic and hand-authored for this repository; its manifest records that
provenance.
