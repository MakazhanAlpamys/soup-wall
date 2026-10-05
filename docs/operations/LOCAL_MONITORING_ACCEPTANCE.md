# Local monitoring acceptance

The local checkpoint exercises the published Windows Gateway with real
Prometheus, promtool and Alertmanager, then receives authenticated firing and
resolved webhooks on a disposable loopback server. It stops and restarts only
the Gateway process that it started. It sends no model requests or external
notifications and does not require PostgreSQL or Redis.

This establishes local scrape-outage detection and delivery. Managed TLS,
deployment routing, receiver ownership, staffed critical notifications and
dependency-specific alert delivery still require the
[staging drill](STAGING_DRILLS.md). The Gateway's separate `policy.deployed`
webhook is not a security alert and is not exercised by this procedure.

## The outage rule

`deploy/prometheus-alerts.yaml` now contains seven rules. The new
`LLMFirewallGatewayTargetDown` selects `up{job="soup-wall-gateway"} == 0` for
two minutes, with the existing 30-second rule-group evaluation interval.
Configure the matching named scrape job: changing its name without updating
the rule disables this coverage.

An unavailable Gateway stops exporting its readiness metric. A missing or
stale sample does not become zero; therefore the existing readiness rule
cannot replace scrape-target outage detection. The existing dependency and
evidence-loss rules remain unchanged. See Prometheus's
[staleness semantics](https://prometheus.io/docs/prometheus/latest/querying/basics/#staleness)
and [rule-test format](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/).

The regression fixture covers a healthy target, stopped target with a stale
readiness metric, an unrelated failed job, the two-minute pending interval,
recovery, and a genuine zero-readiness dependency failure while the target
remains reachable:

```text
promtool check rules deploy/prometheus-alerts.yaml
promtool test rules deploy/prometheus-alerts.test.yaml
```

The acceptance harness also runs this fixture against the exact pre-change
rules at `934653821f73dd702dfe5b8977c6c5ea751ad28a`. It requires the missing
target-down alert to fail that baseline, and the current rules to pass.
Keep that Git object available; a shallow checkout may need its history.

## Portable Windows reproduction

Use Python 3.12 or later. No Python packages, global services, Docker or
certificate-trust changes are needed. The current executable/archive check
is intentionally bound to the Windows AMD64 v0.4.0 Gateway release. It does
not claim execution coverage for other platforms or arbitrary source builds.

From a source checkout, fetch the official pinned portable archives:

```powershell
python scripts/fetch-monitoring-tools.py
```

The explicit command downloads Prometheus 3.15.0 (114,650,144 bytes) and
Alertmanager 0.34.1 (40,131,065 bytes), about 147.61 MiB total. It verifies
the pinned SHA-256 of each official archive and official checksum inventory
before extracting into this checkout's ignored `target/monitoring-tools`.
It keeps the original archives, LICENSE, NOTICE and a manifest. It refuses
different existing files, linked target directories and paths outside target.
Release sources are
[Prometheus 3.15.0](https://github.com/prometheus/prometheus/releases/tag/v3.15.0)
and [Alertmanager 0.34.1](https://github.com/prometheus/alertmanager/releases/tag/v0.34.1).

Obtain the published v0.4.0 Windows Gateway archive and extract it using the
[release verification procedure](LOCAL_RELEASE_ACCEPTANCE.md#gateway-and-sqlite-console). The harness checks
both the pinned archive SHA-256 and the selected Gateway's equality with
its archive member. Set the two paths below to those verified files:

```powershell
$gatewayArchive = 'C:/absolute/path/soup-wall-v0.4.0-x86_64-pc-windows-msvc.zip'
$gatewayBinary = 'C:/absolute/path/extracted/llm-firewall.exe'
python scripts/local-monitoring-acceptance.py
python scripts/local-monitoring-acceptance.py --execute `
  --gateway $gatewayBinary --gateway-archive $gatewayArchive --artifact-label v0.4.0 `
  --prometheus target/monitoring-tools/prometheus-3.15.0.windows-amd64/prometheus.exe `
  --promtool target/monitoring-tools/prometheus-3.15.0.windows-amd64/promtool.exe `
  --alertmanager target/monitoring-tools/alertmanager-0.34.1.windows-amd64/alertmanager.exe `
  --tools-manifest target/monitoring-tools/manifest.json `
  --out target/local-monitoring-evidence.json
```

The first command prints a manifest and starts no processes. `--execute`
reserves a fresh writable evidence output before running any executable;
an existing output is never overwritten. Use a new filename for each run.
Allow about three to five minutes: the real rule keeps its original two-minute
duration, and the harness waits for both firing and resolved delivery.

The harness verifies official archives, executable and license bytes, copies
the rule/test snapshots, validates configuration, scrapes the healthy Gateway,
stops it, observes `up=0` with readiness absent, verifies pending then firing,
and restarts it. The authenticated resolved receipt must match the firing
cycle's `startsAt`. The unchanged readiness rule must not be misreported as
firing from an invented zero. Receiver tests reject missing/wrong credentials,
unrelated targets and malformed payloads.

Generated tokens, SQLite state, child profiles and logs live in one fresh
private directory beneath this checkout's unlinked ignored target. Windows
uses a current-user DACL before writing credentials; POSIX permissions apply
to the free tests. Child environments omit inherited provider keys and proxies.
All listeners bind to numeric loopback. Alertmanager clustering is disabled;
HTTP requests and notification delivery reject redirects. The receiver's
random bearer token stays in its private credential file and memory. Evidence
contains source/archive/binary/configuration hashes, timings and aggregate
receipt metadata, without tokens or raw logs.

Normal completion stops owned processes and removes only the directory created
by that run. A process-stop or cleanup failure leaves `status=incomplete`,
records a sanitized error type and returns a nonzero exit code. Inspect any
retained owned runtime before manually removing it; the harness does not clean
unrelated or interrupted historical directories.

Free regressions run in the existing Python CI job without downloads or
monitoring executable startup:

```text
python -m unittest discover -s scripts/tests -p 'test_*.py' -v
```

## Operator configuration

[Prometheus example](../../deploy/prometheus.example.yaml) provides the exact
named scrape job and rule file. Reach `/metrics` through the private monitoring
network: the public Caddy example returns 404 for that path. Configure the
actual internal Gateway and Alertmanager targets and validate with the deployed
promtool version before rollout.

[Alertmanager example](../../deploy/alertmanager.example.yaml) uses a reserved
example receiver hostname and a protected bearer credential file. Replace both
with the selected owned receiver, preserve TLS verification, and test firing
and resolved routing. Review who receives each severity and whether the
critical route is staffed. Alertmanager's
[webhook configuration](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config)
supports `send_resolved` and HTTP authentication; configure receiver retention
and deduplication explicitly. Examples are configuration guidance, not evidence
that a production receiver exists.
