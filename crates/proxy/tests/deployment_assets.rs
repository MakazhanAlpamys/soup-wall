// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use serde_yaml::Value;

#[test]
fn prometheus_alert_rules_track_only_exported_operational_metrics() {
    let document: Value =
        serde_yaml::from_str(include_str!("../../../deploy/prometheus-alerts.yaml"))
            .expect("Prometheus alert rules must be valid YAML");
    let groups = document
        .get("groups")
        .and_then(Value::as_sequence)
        .expect("Prometheus alert rules need groups");
    assert_eq!(groups.len(), 2, "keep readiness and evidence-loss groups");

    let mut alerts = BTreeSet::new();
    let mut expressions = String::new();
    for group in groups {
        let rules = group
            .get("rules")
            .and_then(Value::as_sequence)
            .expect("each Prometheus group needs rules");
        for rule in rules {
            let alert = rule
                .get("alert")
                .and_then(Value::as_str)
                .expect("each rule needs an alert name");
            assert!(alerts.insert(alert), "alert names must be unique");
            let expression = rule
                .get("expr")
                .and_then(Value::as_str)
                .expect("each rule needs a PromQL expression");
            expressions.push_str(expression);
            expressions.push('\n');

            let labels = rule
                .get("labels")
                .and_then(Value::as_mapping)
                .expect("each rule needs static labels");
            let label_names = labels
                .keys()
                .map(|key| key.as_str().expect("label names must be strings"))
                .collect::<BTreeSet<_>>();
            assert_eq!(
                label_names,
                BTreeSet::from(["component", "severity"]),
                "alert labels must stay low-cardinality"
            );
        }
    }

    assert_eq!(
        alerts,
        BTreeSet::from([
            "LLMFirewallAuditEventsDropped",
            "LLMFirewallAuditPersistenceFailed",
            "LLMFirewallAuditQueueDisabled",
            "LLMFirewallControlPlaneUnavailable",
            "LLMFirewallRedisLimitsUnavailable",
            "LLMFirewallUsagePersistenceFailed",
        ])
    );

    let metrics_source = include_str!("../src/handlers.rs");
    for metric in [
        "llm_firewall_control_plane_ready",
        "llm_firewall_audit_queue_enabled",
        "llm_firewall_audit_queue_dropped_events",
        "llm_firewall_audit_queue_failed_events",
        "llm_firewall_usage_ledger_failed_events",
        "llm_firewall_redis_limits_enabled",
        "llm_firewall_redis_limits_ready",
    ] {
        assert!(
            metrics_source.contains(metric),
            "alert rules may only use metrics exported by /metrics: {metric}"
        );
        assert!(
            expressions.contains(metric),
            "every production operational metric must be covered by an alert: {metric}"
        );
    }
}

#[test]
fn production_templates_keep_secrets_and_runtime_isolation_explicit() {
    // Git checkout may normalize repository text to CRLF on Windows.  The
    // assertions below describe YAML structure, not the platform's line
    // ending, so normalize before checking multiline invariants.
    let compose =
        include_str!("../../../deploy/docker-compose.production.yaml").replace("\r\n", "\n");
    assert!(
        compose.contains("127.0.0.1:8080:8080"),
        "the compose firewall port must stay behind the local TLS edge"
    );
    assert!(compose.contains("read_only: true"));
    assert!(compose.contains("cap_drop:\n      - ALL"));
    assert!(compose.contains("no-new-privileges:true"));
    for variable in [
        "LLM_FW_ADMIN_TOKEN",
        "LLM_FW_OIDC_STATE_KEY",
        "LLM_FW_WEBHOOK_SIGNING_KEY",
        "LLM_FW_POSTGRES_URL",
        "LLM_FW_REDIS_URL",
    ] {
        assert!(
            compose.contains(variable),
            "compose must require the runtime secret/config variable {variable}"
        );
    }
    assert!(
        !compose.contains("LLM_FW_OPENAI_API_KEY"),
        "hosted tenant-store mode must not inject a provider API key"
    );

    let kubernetes = include_str!("../../../deploy/k8s-sidecar.yaml").replace("\r\n", "\n");
    for invariant in [
        "automountServiceAccountToken: false",
        "allowPrivilegeEscalation: false",
        "readOnlyRootFilesystem: true",
        "capabilities:\n              drop: [\"ALL\"]",
        "runAsNonRoot: true",
        "LLM_FW_POSTGRES_URL",
        "LLM_FW_REDIS_URL",
    ] {
        assert!(
            kubernetes.contains(invariant),
            "Kubernetes template lost runtime isolation invariant: {invariant}"
        );
    }

    let caddy = include_str!("../../../deploy/Caddyfile.example");
    assert!(caddy.contains("request_body"));
    assert!(caddy.contains("max_size 8MB"));
    assert!(caddy.contains("respond @metrics 404"));

    let local_caddy = include_str!("../../../deploy/Caddyfile.local.test");
    assert!(local_caddy.contains("tls internal"));
    assert!(local_caddy.contains("reverse_proxy firewall:8080"));
    assert!(local_caddy.contains("respond @metrics 404"));

    let production_config = include_str!("../../../deploy/production.firewall.yaml");
    assert!(production_config.contains("bind: \"0.0.0.0:8080\""));
    assert!(production_config.contains("fail_mode: fail_closed"));
    assert!(production_config.contains("backend: postgres"));
    assert!(production_config.contains("url_env: \"LLM_FW_REDIS_URL\""));

    let restore_drill = include_str!("../../../scripts/postgres-restore-drill.ps1");
    assert!(restore_drill.contains("current_database()"));
    assert!(restore_drill.contains("inet_server_addr()"));
    assert!(restore_drill.contains("same PostgreSQL target/database"));

    let staging_acceptance = include_str!("../../../scripts/staging-acceptance.ps1");
    for invariant in [
        "healthz",
        "readyz",
        "llm_firewall_control_plane_ready",
        "llm_firewall_audit_queue_failed_events",
        "llm_firewall_usage_ledger_failed_events",
        "llm_firewall_redis_limits_ready",
        "model_requests_sent = 0",
        "-AllowHttpForLocal is restricted to a loopback host",
    ] {
        assert!(
            staging_acceptance.contains(invariant),
            "staging acceptance gate lost invariant: {invariant}"
        );
    }
    assert!(
        staging_acceptance.contains("tenant[_-]id|https?://|authorization|api[_-]?key|secret"),
        "staging acceptance gate must reject sensitive metric values"
    );

    let local_compose_drill = include_str!("../../../scripts/local-compose-drill.ps1");
    for phase in ["PostgresDown", "Baseline", "RedisDown", "Recovered"] {
        assert!(
            local_compose_drill.contains(phase),
            "local Compose drill must cover phase {phase}"
        );
    }

    let container_sandbox = include_str!("../../../scripts/container-sandbox-smoke.ps1");
    for invariant in [
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "no-new-privileges:true",
        "--pids-limit",
        "--memory",
        "--cpus",
        "writable_mount = \"/workspace\"",
    ] {
        assert!(
            container_sandbox.contains(invariant),
            "container sandbox smoke lost hardening invariant: {invariant}"
        );
    }
}
