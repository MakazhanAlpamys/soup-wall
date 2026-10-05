# Published Gateway outage and notification evidence

Observed on Windows on 2026-10-05, from `09:02:42.588197` through
`09:06:01.817040` UTC. The independent root run used source commit
`7206a35e6f1d09ec6f5b884bc6d1c403f5aca93f` without source changes during
execution. [Aggregate record](LOCAL_MONITORING_2026-10-05.json) contains all
26 passed checks, exact tool/source/archive/binary hashes, timings and
authenticated notification receipt hashes. It contains no credentials or
raw logs. [Reproduction](../LOCAL_MONITORING_ACCEPTANCE.md) describes the
explicit portable command and its scope.

The verified published Windows v0.4.0 Gateway ran with real Prometheus 3.15.0
and Alertmanager 0.34.1. The original six-rule baseline failed the new
scrape-outage fixture; the fixed seven-rule file passed. The new rule retains
its two-minute `for` duration and the existing 30-second evaluation interval.

After the owned Gateway stopped at `09:03:02.340509` UTC, Prometheus observed
`up=0` and an absent readiness metric. The new rule became pending, then fired
without treating the missing readiness series as zero. The authenticated
receiver recorded firing at `09:05:31.292303` UTC; the harness observed it
149.547 seconds after the stop. The restarted Gateway returned `up=1` and
readiness `1`. The receiver recorded resolution at `09:06:01.296838` UTC with
the same firing-cycle `startsAt`; the rule returned inactive.

Missing receiver authentication was rejected. All owned children stopped and
the fresh generated runtime was removed; cleanup errors are empty and the
overall status is `passed`. Independent free regressions passed all 13 Python
script tests, including 11 monitoring safety tests and two existing Gateway
failure-evidence tests. No model requests or external notifications were sent.
Both deployment-asset tests and workspace formatting also passed. Final
documentation review reconciled the security policy with the existing Windows
protected-DACL implementation and the observed immediate hook fail-open
behavior; these are documentation corrections to previously verified code.

This establishes local scrape-target outage detection and authenticated
firing/resolved delivery. It does not establish managed TLS, a staffed
notification channel, PostgreSQL/Redis-specific alert delivery, detector/block
alerts, or the Gateway's separate policy-deployment webhook. Those managed
deployment and field gates remain open.
