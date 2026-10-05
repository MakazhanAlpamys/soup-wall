# Incomplete local Keycloak SAML checkpoint, 2026-10-05

**Overall acceptance is incomplete.** The original Windows local vendor run
recorded 22 named functional checks with expected results, then exited 1 after
`PermissionError` during teardown. Cleanup did not pass. The public
[aggregate record](KEYCLOAK_SAML_2026-10-05.json) preserves that outcome and
original executed source/binary hashes. It contains no assertions, credentials,
metadata XML, private keys or runtime logs.

The actual run was 05:50:42–05:51:27 UTC on Windows 11 build 26200, Python
3.12.10. Official Keycloak 26.8.0 and Temurin 25.0.4.1+1 archives were verified
against release digests and sidecars. The Gateway was built from
`bcf66a01f3559e7cf7cc1ffeb25db45a2b94519f` in a debug Rust 1.98.1 build; its SAML
production code was unchanged. Bootstrap and driver were uncommitted source
snapshots identified by their exact file/binary hashes, not by that Gateway
commit. [Runtime provenance and future instructions](../KEYCLOAK_SAML_ACCEPTANCE.md)
describe pinned sources and license notices.

Keycloak supplied a genuinely signed IdP descriptor and a signed plaintext
assertion after its real password/SSO form flow. The unchanged production ACS
returned 303 and a secure host-only HttpOnly SameSite=Lax session cookie; the
session resolved the pre-provisioned Owner. Assertion replay returned 400.
Session rotation issued a new cookie, invalidated the old cookie and preserved
the new session. Gateway logout invalidated that session.

Two historical negative observations have confounds. The unsigned-descriptor
attempt also used the signed realm's certificate pin, so its 400 cannot isolate
the missing signature from the wrong pin. The mutated NameID was unprovisioned,
so its 400 cannot isolate bad-signature rejection from denied authorization.
They are observations, not independent cryptographic regression proof. Existing
production SAML fixtures provide that isolated signature-negative coverage.

Independent review also found that the executed driver's internal edge request
could consult ambient proxy/netrc configuration and its child environment used
a broad denylist that retained unknown provider credentials and user profiles.
The historical run does not establish the intended environment isolation.
The corrected committed driver uses proxy-free bounded edge sessions, an OS
root allowlist and owned profiles/JVM home, the unsigned realm's own pin, and a
second explicitly authorized synthetic principal for NameID mutation. Evidence
output is now reserved before runtime allocation, rejects existing/input files,
and atomically preserves incomplete checkpoints on write failure. Thirteen
offline regressions passed for that prepared snapshot. Root review added the
ignored-directory guard, bringing the driver checks to fourteen. A native
bootstrap execution then exposed an incorrect OIDC authorization check before
any IdP connection existed; the helper now verifies its stored active SAML
identity links and Owner memberships. Two mandatory native bootstrap regressions
cover fresh provisioning and refusing an existing file unchanged. The corrected
driver/bootstrap **have not** been
rerun against Keycloak, and their hashes are separate preparation evidence.
File hashes describe the measured checkout bytes; newline conversion can alter
them across checkouts. Root verification is recorded separately in the JSON.

No filename, numeric errno or specific cause was preserved for the initial
`PermissionError`. Subsequent native removal attempts were rejected before
execution by automatic approval review, whose entire stated reason was
`blocked by policy`. This was a cleanup rejection, not a vendor login failure.
Read-only post-run process inventory found no `java.exe` or `llm-firewall.exe`.
Private material remains in the original disposable checkout. The public
record redacts the absolute machine path and generated profile identifier;
the local operator has the exact directory requiring cleanup:

```text
target/keycloak-saml/<failed-run-directory>
```

Removal was not retried through Python, another tool, an altered harness or
weaker guard. An operator-authorized environment change must resolve this
directory before a fresh full vendor run; portable archives outside it remain
available. Acceptance requires both valid functional evidence and successful
private-profile cleanup.

This checkpoint does not close managed staging, customer IdP acceptance,
OIDC code/PKCE login, browser/MFA flows, vendor SCIM, vendor SAML single logout,
Linux/macOS vendor coverage, or the timing-safe Windows provider and complete
`rsa` removal required by
[issue #19](https://github.com/MakazhanAlpamys/soup-wall/issues/19).
