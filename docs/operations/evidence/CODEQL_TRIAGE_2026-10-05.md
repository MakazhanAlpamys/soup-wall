# CodeQL alert review — 2026-10-05

Reviewed the seven open default-branch alerts against scanned source
`65bee72917e34f260da34162094f1a21030f7005` and checkpoint head
`b7c8866d64d218554a9661568c00972b10a08954`. The relevant Rust files are identical
between these revisions. This review classifies those individual findings; it
does not disable queries or establish the absence of other vulnerabilities.

| Alerts | Finding and boundary | Classification |
| --- | --- | --- |
| [26](https://github.com/MakazhanAlpamys/soup-wall/security/code-scanning/26) | Fixed protocol nonce in a URL-serialization unit test inside `#[cfg(test)]`; no request is sent. | Used in tests |
| [27](https://github.com/MakazhanAlpamys/soup-wall/security/code-scanning/27) | Fixed nonce in a negative callback-path test; the invalid callback is rejected before a URL is constructed. | Used in tests |
| [28](https://github.com/MakazhanAlpamys/soup-wall/security/code-scanning/28), [29](https://github.com/MakazhanAlpamys/soup-wall/security/code-scanning/29) | Fixed OIDC correlation values bind locally generated state/JWT fixtures in test-only, in-memory HTTP flows. They are not AES-GCM IVs or production session tokens. | Used in tests |
| [30](https://github.com/MakazhanAlpamys/soup-wall/security/code-scanning/30) | Production reconciliation calls `validate_usage_reconciliation_import(import)?` before `Vec::with_capacity(import.records.len())`. The validator accepts only 1–1000 immutable records. | False positive: bounded allocation |
| [31](https://github.com/MakazhanAlpamys/soup-wall/security/code-scanning/31), [32](https://github.com/MakazhanAlpamys/soup-wall/security/code-scanning/32) | A SCIM integration test PATCHes/DELETEs its own synthetic user over a listener bound to `127.0.0.1:0`, using a new expiring test bearer and in-memory database. The resource ID is not a credential or customer data. | Used in tests |

The SCIM fixture does use plaintext HTTP. Its `Client::new()` retains ambient
proxy settings, so this record asserts a loopback URL, not proof that every
physical route bypasses a configured proxy. No customer directory is contacted.
Production TLS termination remains an operator deployment requirement.

## Production OIDC boundary

[`start_login_for_workspace`](https://github.com/MakazhanAlpamys/soup-wall/blob/b7c8866d64d218554a9661568c00972b10a08954/crates/proxy/src/oidc_auth.rs#L820)
generates a PKCE pair and 32 bytes of OS entropy for its protocol nonce. State
encryption separately generates fresh AES-GCM nonces. Production state uses the
configured state key, with no fixture-key fallback. The signed token is checked
against authenticated issuer, audience and nonce; state is single use. Session
tokens use fresh entropy and are stored by hash. Test literals are excluded from
release builds.

## Reconciliation runtime boundary

An isolated standalone Rust probe linked the current public Gateway library and
used SQLite `:memory:`. Imports with 0 and 1001 records failed with the count-bound
error and persisted no reconciliation rows. A 1000-record import succeeded and
reported 1000 orphan records. PostgreSQL uses the same validator. The caller
receives an immutable plain `Vec`; its length cannot grow between validation and
the flagged allocation. The HTTP body limit is additional defense, not the basis
for dismissing this alert.

No blanket alert suppression, production key replacement, transport weakening,
or query exclusion is needed for these seven findings. Reopen the applicable
alert if a later change removes the count guard, moves fixtures into production,
or introduces customer data into the plaintext test path.

All seven alerts were dismissed on October 5 with individual reasons and
comments preserving this distinction. An authenticated query afterward returned
zero open alerts. The alert history and scan queries remain enabled.
