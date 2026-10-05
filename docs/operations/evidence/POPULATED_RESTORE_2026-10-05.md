# Populated encrypted restore checkpoint

The isolated Linux run passed on clean source
`75a0e76834bf99cfb14ba537480106c3e69db348` at
`2026-10-05T11:20:16.780909+00:00`. It used an exported source tree on an owner-only
ext4 directory, Rust 1.98.1, PostgreSQL 18.6, age 1.2.1 and PowerShell 7.6.6.
Only reusable runtime binaries/caches were reused. A fresh owned loopback cluster,
role, source database and drill database were allocated; historical databases
were never used as targets. The owned cluster stopped successfully afterwards.

The original Gateway `migrate` command created the schema without starting a
Gateway listener or delivery worker. Original TenantStore APIs created two
tenants, an owner membership, limits/approved policies, two service accounts
(retained and already revoked), one active webhook destination, two security
events and one genuine pending delivery. No direct fixture INSERT bypassed
these product APIs. The destination is reserved `.test` DNS and was not contacted.

The original encrypted PowerShell drill dumped, age-encrypted, decrypted and
restored the source into the separately fingerprinted drill database. Complete
private public-schema rows and sequence state matched before behavioral changes,
including credential hashes, revocation/expiry, policy bodies and delivery fields.
Read-only probes authenticated the retained token with the restored tenant,
limits and model policy, rejected the revoked token and checked tenant isolation.
The restored-only exercise revoked the retained token and verified immediate
rejection, deployed another approved policy to enqueue a second delivery, and
deactivated the destination to suppress the next enqueue. Source rows/sequences
were unchanged after the exercise. No actual delivery or provider request ran.

All 21 Python orchestration tests passed on Linux/Python 3.14, including both Unix
permission/symlink cases. All nine Rust helper tests passed. The expanded existing
PostgreSQL integration test also passed on a separate fresh database: successful
issuance returns the stored metadata and authenticating token; outsider issuance
and revocation create no records/audit effects; authorized/repeated revocation
preserves the expected audit behavior. These runs are local acceptance evidence.

Subsequent [PR #29 CI](https://github.com/MakazhanAlpamys/soup-wall/pull/29)
at `fa8304e` passed the PostgreSQL integration regression but failed the restore
driver before fixture creation. Ubuntu's PostgreSQL client aliases dispatch
through `pg_wrapper` using their invocation name, as described in the
[Debian wrapper documentation](https://manpages.debian.org/bookworm/postgresql-client-common/pg_wrapper.1.en.html).
Executable selection now preserves the selected alias instead of resolving its
symlink. A Unix regression reproduces the earlier failure and passes with the
fix; all 22 local Python checks pass. Private-artifact symlink and permission
checks remain unchanged. This follow-up does not alter the frozen local evidence
above; the corrected CI acceptance run must independently pass.

At `bbfc906`, the psql alias reached the server successfully, but CI rejected the database
fingerprint before migration or seeding. The guard equated the loopback client
route with the server-side address/port behind Docker's published port.
[PostgreSQL documents these functions as the server's accepted endpoint](https://www.postgresql.org/docs/16/functions-info.html#FUNCTIONS-INFO-SESSION-TABLE).
The driver now pins the numeric server address/port through the explicitly
selected admin connection before database mutations. Both reserved database
names must match that frozen server identity on every check; different servers,
identity drift and malformed identities remain failures. Input URLs still require
numeric loopback routing. The original PowerShell drill and Rust target binding
are unchanged. This compatibility repair also requires a new passing CI run.

Observed numeric addresses are normalized for comparison rather than requiring
Python's formatting to equal PostgreSQL's formatting; IPv4-mapped IPv6 spelling
differs across Python versions. Raw database fingerprints remain bound to the
original restored-target checks. Child temporary-directory settings now point
to an owner-only directory inside the fresh private run, instead of inheriting
ambient redirection. The original drill still removes its temporary plaintext.

CodeQL at `bbfc906` also flagged the helper's unrestricted `Result<Value>` output
boundary as potentially carrying service-account/signing-key data to stdout
([alert #41](https://github.com/MakazhanAlpamys/soup-wall/security/code-scanning/41)).
The existing aggregate contained fixed counts/flags, so this is not evidence of
an observed credential disclosure. Verification now returns `Result<()>`; the
public report is separately constructed from a validated phase with explicitly
typed counts/flags and fixed labels. No database metadata, arbitrary JSON or
verification error enters the stdout report. The exact phase-specific output
contract remains checked. The alert is not dismissed or suppressed; corrected
CodeQL analysis must pass independently.

A fresh isolated local run after these repairs passed on clean
`7ff3a0c6123616ba08fe38f160637a5c2ae61612` at
`2026-10-05T13:06:29.004977+00:00`. It rebuilt the helper and Gateway from the
exported source, allocated a fresh cluster/databases/role, completed the encrypted
restore and restored-only behavior checks, and stopped its owned cluster. All 33
Linux Python tests, 11 Rust helper tests and the separate actual PostgreSQL
regression passed. Private full-state equality and an unchanged source were
confirmed; both executables stayed unchanged during the run. Zero model/provider
or webhook requests ran. The [follow-up aggregate](POPULATED_RESTORE_AFTER_CI_FIXES_2026-10-05.json)
records the new source/archive/executable hashes without changing the initial
checkpoint above. Windows Python 3.12 separately passed 27 tests with six
Unix-only skips; Linux Python 3.14 passed all 33. Hosted Docker acceptance and
fresh CodeQL analysis still require their own passing results.

Actual execution found a production issuance defect: an INSERT CTE returned only
the ID, then its outer SELECT scanned the base table using the statement's earlier
snapshot. The account and audit persisted while the API returned an error and
withheld its one-time token. `a938cc8` returns metadata directly from the INSERT's
RETURNING relation, preserving authorization and atomic audit. This matches
[PostgreSQL's documented data-modifying WITH semantics](https://www.postgresql.org/docs/current/queries-with.html#QUERIES-WITH-MODIFYING).
Independent source review checked column order, role/active predicates and audit
execution. The new actual PostgreSQL regression fails on the earlier behavior.

Earlier incomplete attempts remain in the aggregate record and ignored private
artifacts. They exposed literal-address/CIDR comparison, read-only URI encoding
and platform-mock errors, all corrected before the passing run. An ignored
diagnostic helper stored the earlier error privately; the final passing helper
contains no diagnostic modification. Failed fixture runs were never resumed or
reseeded; every new acceptance attempt used fresh data. Diagnostic inspection
was read-only. The earlier run whose tests later failed had already passed the
restore exercise, as its retained aggregate explicitly records.

The [aggregate evidence](POPULATED_RESTORE_2026-10-05.json) binds source archive and
executable hashes. Both executables stayed unchanged through the run. Private
credentials, master signing key, age identity, full rows, database names and tool
transcripts are not published. Private fixture data remains for operator review;
the original restore script removes its own temporary plaintext files.

Reproduce using [STAGING_DRILLS](../STAGING_DRILLS.md#populated-local-restore-fixture)
on an explicitly disposable loopback PostgreSQL instance. This closes the local
populated database/queue/authentication checkpoint. Managed TLS, actual webhook
delivery, real IdP interoperability and recovery of customer data remain separate
gates, as do live model effectiveness and staffed routing.
