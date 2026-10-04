// SPDX-License-Identifier: Apache-2.0

//! Reproducible evidence for offline policy replay. Raw events are never emitted.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::agent_eval::AgentEval;

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn percentile(sorted: &[f64], percentile: usize) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (sorted.len() * percentile).div_ceil(100).max(1);
    sorted.get(rank - 1).copied()
}

pub fn build(corpus: &str, policy_path: Option<&str>, eval: &AgentEval) -> anyhow::Result<Value> {
    let manifest = Path::new(corpus).with_extension("manifest.json");
    let manifest_bytes = std::fs::read(&manifest)?;
    let provenance: Value = serde_json::from_slice(&manifest_bytes)?;
    let policy = match policy_path {
        Some(path) => std::fs::read(path)?,
        None => include_bytes!("../../agent/policies/agent-default.yaml").to_vec(),
    };
    let mut latencies: Vec<_> = eval.sessions.iter().map(|s| s.policy_replay_ms).collect();
    latencies.sort_by(f64::total_cmp);
    Ok(json!({
        "schema_version": 1,
        "observed_at_unix": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "evidence_scope": "offline-policy-replay",
        "dataset_provenance": provenance,
        "corpus_sha256": hash(&std::fs::read(corpus)?),
        "manifest_sha256": hash(&manifest_bytes),
        "policy_sha256": hash(&policy),
        "binary_sha256": hash(&std::fs::read(std::env::current_exe()?)?),
        "build": { "package_version": env!("CARGO_PKG_VERSION"),
                   "os": std::env::consts::OS, "architecture": std::env::consts::ARCH,
                   "logical_cpus": std::thread::available_parallelism()?.get(),
                   "agent_detectors": "rules-and-heuristics", "judge": "not-configured" },
        "counts": eval.confusion,
        "missed_attacks": eval.misses,
        "interrupted_benign_sessions": eval.false_positives,
        "per_category": eval.per_category,
        "policy_replay_latency_ms": {
            "p50": percentile(&latencies, 50), "p99": percentile(&latencies, 99),
            "includes": "fresh-firewall-construction-and-replay-until-first-interruption"
        },
        "task_utility": null,
        "limitations": [
            "Corpus provenance is supplied by its author; independence and held-out status need separate review.",
            "An interruption is a policy verdict, not proof that a host prevented execution.",
            "No LLM or tools execute; task success, attack success and end-to-end latency are not measured.",
            "Latency includes fresh detector construction per session; this is not warmed daemon throughput."
        ],
        "passes_reviewed_policy_gate": eval.passes_gate(),
        "sessions": eval.sessions
    }))
}

pub fn write(
    corpus: &str,
    policy: Option<&str>,
    eval: &AgentEval,
    output: &str,
) -> anyhow::Result<()> {
    let destination = Path::new(output);
    if destination.exists() {
        let destination = destination.canonicalize()?;
        let manifest = Path::new(corpus).with_extension("manifest.json");
        for source in [
            Some(Path::new(corpus)),
            Some(manifest.as_path()),
            policy.map(Path::new),
        ]
        .into_iter()
        .flatten()
        {
            ensure!(
                destination != source.canonicalize()?,
                "agent output must not overwrite corpus, manifest or policy"
            );
        }
        ensure!(
            destination != std::env::current_exe()?.canonicalize()?,
            "agent output must not overwrite the running binary"
        );
    }
    let report = build(corpus, policy, eval)?;
    std::fs::write(destination, serde_json::to_string_pretty(&report)? + "\n")
        .context("cannot write agent evaluation evidence")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> String {
        concat!(env!("CARGO_MANIFEST_DIR"), "/corpora/agent_sessions.jsonl").into()
    }

    #[test]
    fn a_failed_gate_retains_missed_attacks_and_pinned_inputs_without_raw_events() {
        let sessions = crate::agent_dataset::load_reviewed(&corpus()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("allow.yaml");
        std::fs::write(&policy, "agent_policies: []\ndefault: allow\n").unwrap();
        let parsed =
            soup_wall_agent::AgentPolicySet::from_yaml(&std::fs::read_to_string(&policy).unwrap())
                .unwrap();
        let eval = crate::agent_eval::evaluate_with(&sessions, Some(&parsed));
        let output = directory.path().join("report.json");
        write(
            &corpus(),
            Some(policy.to_str().unwrap()),
            &eval,
            output.to_str().unwrap(),
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(report["passes_reviewed_policy_gate"], false);
        assert_eq!(report["counts"]["fn"], 19);
        assert_eq!(report["counts"]["fp"], 0);
        assert_eq!(report["missed_attacks"].as_array().unwrap().len(), 19);
        assert_eq!(report["sessions"].as_array().unwrap().len(), 40);
        assert_eq!(
            report["policy_sha256"],
            hash(&std::fs::read(policy).unwrap())
        );
        assert!(report["task_utility"].is_null());
        for result in report["sessions"].as_array().unwrap() {
            assert!(result.get("events").is_none());
            assert!(result["policy_replay_ms"].as_f64().unwrap() >= 0.0);
        }
    }

    #[test]
    fn output_cannot_destroy_its_corpus_or_policy() {
        let sessions = crate::agent_dataset::load_reviewed(&corpus()).unwrap();
        let eval = crate::agent_eval::evaluate_with(&sessions, None);
        let before = std::fs::read(corpus()).unwrap();
        assert!(write(&corpus(), None, &eval, &corpus()).is_err());
        assert_eq!(std::fs::read(corpus()).unwrap(), before);
        let manifest = Path::new(&corpus()).with_extension("manifest.json");
        assert!(write(&corpus(), None, &eval, manifest.to_str().unwrap()).is_err());
    }

    #[test]
    fn latency_percentiles_cover_small_and_empty_samples() {
        assert_eq!(percentile(&[], 50), None);
        assert_eq!(percentile(&[2.0], 99), Some(2.0));
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 50), Some(2.0));
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 99), Some(4.0));
    }
}
