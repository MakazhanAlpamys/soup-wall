# Clean setup, status and scanning preparation

This procedure implements the independent preparation for
[SOU-18](https://linear.app/soup-wall/issue/SOU-18/task-12-verify-clean-setup-and-actual-active-protection-status)
(F02, U01, U04 and F06/L02). It reuses the existing Agent and fixture build.
It does not introduce another classifier, MCP harness or admission contract.

## Disposable installation and status checks

The [setup script](../../scripts/clean-setup-acceptance.py) needs Python 3.10+
and an `agentfw` binary built for the machine running it. It copies that binary
into a fresh temporary directory, runs `agentfw install` with a private child
profile, and starts only its own loopback daemon. Real user settings and service
registrations are not edited. The generated profile, tokens and copied binary
are removed on both success and ordinary failure. An interrupted machine or
forced termination can require removal of the generated `soup-wall-setup-*`
directory from the OS temporary directory after confirming no owned process remains.

With no arguments, the script prints its scope and starts no processes:

```sh
python3 scripts/clean-setup-acceptance.py
```

Use the [development prerequisites](../DEVELOPMENT.md) for a native source
build. For an explicitly selected toolchain, install Rust 1.98.1 and run:

```sh
rustup run 1.98.1 cargo build --locked -p agentfw --bin agentfw
python3 scripts/clean-setup-acceptance.py --run --agentfw target/debug/agentfw --output target/clean-setup.json
```

On native Windows use `python` and `target/debug/agentfw.exe`. An output path
must be fresh. Existing evidence is never overwritten. Keep the build command,
compiler version, source commit, dirty-state information and binary hash with
the report. A supplied binary's hash does not by itself prove its source commit.

The script checks installation output for token disclosure and verifies that
an unrelated synthetic Claude settings file is unchanged. It then checks:

| Stage | Expected health / required-enforcement preflight |
| --- | --- |
| Shadow daemon | `enforce=false`, exit 4 |
| Enforcing daemon | `enforce=true`, exit 0 |
| Owned daemon stopped | Unavailable, exit 2 |
| Owned daemon restarted | `enforce=true`, exit 0 |
| Rollback | Owned installation and profile removed |

The JSON contains config/policy/binary hashes and status assertions. It omits
tokens, raw subprocess output, raw private arguments and inherited credentials.
Missing classifier/profile revision support is reported as `null`, not inferred.
Source identity is recorded separately from supplied-binary provenance.

`stage_install_ms` measures copying the supplied binary, excluding compilation
and downloads. `warm_preflight_cli_ms` contains 20 measured samples after an
excluded warm-up, with nearest-rank p50/p95. These include CLI startup and the
health request. They are **not MCP/classifier overhead or complete setup time**.
Keep the OS, architecture, CPU model, memory and build/download duration alongside
the report for a performance comparison. No acceptance threshold is invented here.

### Pinned Docker route

Run the existing fixture baseline using its pinned Rust/base-image/package
inputs and `Cargo.lock`:

```sh
python3 scripts/test-environment.py
```

Its output names a unique directory under `target/test-environment/`. Set
`RUN_DIR` to that printed directory, then run the setup check against the exact
built image, using a fresh output filename:

```sh
RUN_DIR='/absolute/path/to/the/printed/result-directory'
IMAGE_ID="$(cat "$RUN_DIR/image-id")"
docker run --rm --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges:true --pids-limit=256 --cpus=2 --memory=2g \
  --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,exec,nosuid,nodev,size=256m \
  --mount "type=bind,src=$RUN_DIR,dst=/results" --entrypoint python3 "$IMAGE_ID" \
  /opt/soup-wall/scripts/clean-setup-acceptance.py --run \
  --agentfw /opt/soup-wall/target/debug/agentfw --output /results/clean-setup.json
```

Use Linux or the documented [WSL2 route](../DEVELOPMENT.md#running-from-windows-with-wsl2)
for these shell commands. Docker on macOS/WSL2 proves Linux-container behavior
only. Keep `results.json`, `fixture-results.json`, `image-id` and
`clean-setup.json` together: the build manifest records source-input hashes.
This separate setup container needs `exec` on its temporary filesystem because
it executes the staged binary there. The normal fixture baseline is unchanged.

Existing Linux, macOS and Windows CI jobs also run the setup script and retain
separate artifacts. Their addition is not evidence that those jobs passed.
The accepted OS/architecture matrix remains owned by SOU-10; record every
missing target as unverified rather than expanding coverage from a container pass.

### What still requires the integrated candidate

The script always reports `protection_verified=false`. Daemon posture alone
cannot establish that any host call was protected. The HTTP hook can fail open;
direct MCP server launches bypass native admission. See
[the existing MCP boundary](MCP_STDIO_ADMISSION.md).

Use the reviewed initial harness and the same pinned SOU-15 candidate as SOU-17
for the remaining acceptance. Record actual binary/config/policy/classifier/profile
revisions and the supported host, transport, schemas and result content.
Compare displayed posture with independent server/file/receiver observations:
Allow executes and returns a checked result; Deny/Ask do not execute; daemon
loss does not forward a protected call; recovery allows a fresh valid call.
Track execution and result release separately. List direct unprotected paths.
Run the existing real-Claude acceptance separately when available.

For MCP overhead, warm the same supported call and measure direct versus
protected execution on declared hardware with the same inputs. Preserve sample
counts, raw durations, p50/p95 and failures. Set limits from the reviewed SOU-10
protocol. Do not substitute the preflight timings above for this measurement.

## Read-only GitHub scanning audit

The [audit script](../../scripts/github-code-scanning-audit.py) uses an already
authenticated GitHub CLI. It only makes GET requests and writes a local report.
It never modifies security settings, dismisses alerts or creates PRs.

```sh
python3 scripts/github-code-scanning-audit.py --output target/github-main-audit.json
python3 scripts/github-code-scanning-audit.py --pr 35 --output target/github-pr35-audit.json
```

Replace the example PR number with the candidate under review. Reports include
the target SHA, a final head recheck, observed languages, default setup,
workflow inventory, effective main rules, branch-protection details, checks,
analysis revisions and open-alert counts. They exclude alert snippets and
private diagnostic text. Lists are paginated; access failures are explicit.

Exit 0 means evidence collection completed, not that merge protection works.
Exit 2 means evidence is incomplete, such as a 403/404 or a moving head.
The report never sets `merge_protection_verified=true` from configuration alone.
Old analyses do not count as current. Merge-ref analyses require separate
verification that their tested merge contains the current PR head.

The existing repository has CodeQL analysis checks for Rust, Python and GitHub
Actions. A successful `Analyze (rust)` job proves analysis/upload success, not
the alert-bearing merge decision. Confirm the actual results-check name and
GitHub app on the candidate; do not require an unrelated job just because its
name contains CodeQL. Confirm actual PR-to-main and default-branch coverage.
Repository languages without analysis evidence remain coverage gaps.

Before adding a workflow, inspect the active default setup with an administrator.
No CodeQL workflow in the checkout does not mean scanning is disabled. This
preparation deliberately adds no duplicate CodeQL workflow.

### Readable offline report

After collecting the JSON above, convert it to Markdown with the
[report script](../../scripts/github-code-scanning-report.py):

```sh
python3 scripts/github-code-scanning-report.py \
  --input target/github-main-audit.json \
  --output target/github-main-audit.md
```

For a PR, use its saved audit JSON instead. On Windows, use `python` instead of
`python3`. The converter needs Python 3.10+ and only its standard library;
it needs neither GitHub credentials nor network access. Keep the original JSON
beside the Markdown report. Conversion does not refresh the saved observations.

An audit exit code of 2 can still leave a valid, incomplete JSON report. Inspect
that file and run the converter separately; do not discard access failures or
replace missing evidence with a pass. The converter accepts schema version 1,
preserves recorded statuses, and labels missing/null values as `not recorded`.
It refuses invalid input, unsupported schema versions and existing output paths.
Use a fresh Markdown filename for each report.

The converter's exit code 0 means **the document was created**, even when the
audit is incomplete. Exit code 2 means conversion failed. Neither a generated
report nor a successful analysis/upload job proves that a finding blocks merge.

For the administrator handoff, review the recorded target SHA, observation time
and head recheck first. Then compare the analysis jobs with the separate results
check, including its app, exact-head match and conclusion. Review the observed
rulesets, effective main rules and thresholds alongside unavailable observations.
An empty rule list or a 403/404 response does not prove the absence of protection.
The final table keeps all three administrator gate cases and their saved statuses,
including `not_run`; conversion never runs those cases or changes GitHub settings.

### Administrator configuration and live gate evidence

Coordinate with @winux125; @manettibenetti coordinates PR review. The
[disabled ruleset example](../../deploy/github-code-scanning-ruleset.example.json)
targets `main`, requires CodeQL, High-or-higher security alerts and error-level
alerts. It is an additive example, not a replacement for existing review/status
protections. Importing it disabled does not enable a merge gate. Record the
administrator, applied ruleset ID, thresholds, bypass actors, plan/access limits
and before/after configuration when an administrator enables the reviewed rule.

Verify on a disposable PR targeting main, which must never be merged:

| Case | Required evidence |
| --- | --- |
| Clean analyzed head | Current head analysis and results check; scanning rule permits progression, subject to other review/check requirements |
| Missing or pending analysis after a new commit | New head SHA and the actual rule rejection/pending reason; previous-head success is insufficient |
| Controlled qualifying finding | Scanner-detected synthetic finding at the configured threshold, results check and actual rule rejection |

Coordinate the harmless detection fixture with the administrator and security
reviewer. Keep it only on the disposable branch, never execute its vulnerable
path, and close the test PR without merging. A generic `BLOCKED` merge state
caused by missing reviews does not prove a scanning-rule rejection. Preserve the
head SHA, analysis ID, rule result, thresholds and timestamps for each case.

Until all three cases are observed, retain `not_run`/unverified evidence.
False-positive dismissals need the authorized reviewer's recorded rationale;
do not lower thresholds or silently bypass findings. Link
[SOU-17](https://linear.app/soup-wall/issue/SOU-17/task-11-independently-verify-failure-overlap-and-replay-behavior)'s
triage report and remediation issues when supplied. A clean PR does not resolve
the existing alert inventory.

Configuration references:
[GitHub merge protection](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/manage-your-configuration/set-merge-protection),
[ruleset API](https://docs.github.com/en/rest/repos/rules#create-a-repository-ruleset),
[code scanning API](https://docs.github.com/en/rest/code-scanning/code-scanning).
