// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

mod agent_dataset;
mod agent_eval;
mod agent_guard;
mod dataset;
mod evaluate;
mod metrics;
mod report;
mod rivals;
mod scorecard;

use clap::Parser;
#[cfg(feature = "ml")]
use soup_wall_core::ModerationDetector;
use soup_wall_core::{
    Direction, Firewall, InjectionDetector, Normalizer, OutputDetector, PiiDetector, PolicySet,
    SecretDetector,
};

use crate::evaluate::{evaluate, CoreGuard, EvalResult, Guard};
use crate::rivals::SubprocessGuard;

#[derive(Parser)]
#[command(name = "soup-wall-bench")]
struct Cli {
    /// One or more dataset .jsonl files (text benchmark).
    #[arg(long, num_args = 1..)]
    dataset: Vec<String>,
    /// Agent-attack corpus .jsonl. Runs the agent scorecard instead of the text one.
    #[arg(long)]
    agent: Option<String>,
    /// Candidate agent policy YAML to gate. Replays the reviewed corpus under it
    /// and exits non-zero if any reviewed attack is missed or any reviewed benign
    /// session is interrupted. Requires --agent.
    #[arg(long, requires = "agent")]
    policy: Option<String>,
    /// Risk-score threshold for CoreGuard.
    #[arg(long, default_value_t = 50)]
    threshold: u8,
    /// Optional rival: "name=program arg arg" (protocol: text on stdin -> 0/1 on stdout).
    #[arg(long)]
    rival: Vec<String>,
    /// Write results.json here.
    #[arg(long, default_value = "results.json")]
    out: String,
    /// Diagnostic (ml feature only): dump per-example {label, cheap_score, cheap_block,
    /// ml_p} to this JSONL path in a single ML pass, for offline threshold sweeps.
    #[arg(long)]
    dump_features: Option<String>,
    /// Write an OWASP LLM Top 10 (2025) coverage/risk report (Markdown) to this path.
    #[arg(long)]
    report: Option<String>,
    /// Include the content-moderation (harmful-content) detector. Off by default so the
    /// injection scorecard stays clean; enable to evaluate harmful-content datasets.
    #[arg(long, default_value_t = false)]
    moderation: bool,
    /// Probability at/above which the moderation detector flags. Defaults to the
    /// detector's own 0.5; the proxy's `output_moderation.threshold` ships at 0.8,
    /// so pass `--moderation-threshold 0.8` to measure the deployed default.
    #[arg(long, default_value_t = 0.5)]
    moderation_threshold: f32,
    /// Disable the obfuscation/evasion normalization pre-pass (on by default). Use to
    /// measure the baseline vs. protected recall on obfuscated corpora.
    #[arg(long, default_value_t = false)]
    no_normalize: bool,
    /// Also enable the base64-decode normalization tier (opt-in; off by default).
    #[arg(long, default_value_t = false)]
    normalize_base64: bool,
    /// Which path to evaluate: `input` (prompt corpora, the default) or `output`
    /// (corpora of model *replies*, e.g. output moderation). Mirrors the direction
    /// the proxy stamps, so direction-scoped policy rules are measured honestly.
    #[arg(long, default_value = "input")]
    direction: DirectionArg,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum DirectionArg {
    Input,
    Output,
}

impl From<DirectionArg> for Direction {
    fn from(d: DirectionArg) -> Self {
        match d {
            DirectionArg::Input => Direction::Input,
            DirectionArg::Output => Direction::Output,
        }
    }
}

fn core_guard(
    threshold: u8,
    moderation: bool,
    moderation_threshold: f32,
    normalize: bool,
    base64: bool,
    direction: Direction,
) -> CoreGuard {
    // Mirrors the shipped `policies/default.yaml`: the injection rules are scoped to
    // `input` there, so the bench must scope them too or it measures rules nobody runs.
    let policy = PolicySet::from_yaml(
        "policies:\n  - name: block-injection-high\n    when: { detector: injection, min_severity: high, direction: input }\n    action: block\n  - name: block-ml-positive\n    when: { detector: injection.ml, direction: input }\n    action: block\n  - name: block-moderation\n    when: { detector: moderation }\n    action: block\ndefault: allow\n",
    )
    .expect("builtin policy");
    // With the `ml` feature, attach the DeBERTa Stage-C classifier when its asset is
    // present; fall back to regex+heuristics (with a warning) if the model is missing.
    #[cfg(feature = "ml")]
    let injection = match soup_wall_core::MlClassifier::load("models/injection") {
        Ok(clf) => {
            eprintln!("ML stage: loaded models/injection (DeBERTa Stage C active)");
            InjectionDetector::new().with_ml(clf)
        }
        Err(e) => {
            eprintln!("ML stage: model unavailable ({e}); using regex+heuristics only");
            InjectionDetector::new()
        }
    };
    #[cfg(not(feature = "ml"))]
    let injection = InjectionDetector::new();

    #[allow(unused_mut)] // `mut` is only exercised when the `ml` moderation branch pushes.
    let mut detectors: Vec<Box<dyn soup_wall_core::Detector>> = vec![
        Box::new(injection),
        Box::new(SecretDetector::new()),
        Box::new(PiiDetector::new()),
        Box::new(OutputDetector::new()),
    ];

    // Content moderation (harmful-content classifier) is opt-in: it improves
    // harmful-content recall but adds over-defense on general traffic, so it must not
    // silently degrade the injection scorecard.
    if moderation {
        #[cfg(not(feature = "ml"))]
        let _ = moderation_threshold;
        #[cfg(feature = "ml")]
        match soup_wall_core::ModerationClassifier::load_with_labels(
            "models/moderation",
            vec!["harmful".into(), "safe".into()],
        ) {
            Ok(clf) => {
                eprintln!(
                    "Moderation: loaded models/moderation (harmful-content classifier active)"
                );
                detectors.push(Box::new(
                    ModerationDetector::new()
                        .with_model(clf)
                        .with_threshold(moderation_threshold),
                ));
            }
            Err(e) => eprintln!("Moderation: model unavailable ({e}); moderation disabled"),
        }
        #[cfg(not(feature = "ml"))]
        eprintln!("Moderation: requires the `ml` feature; ignored.");
    }

    let mut firewall = Firewall::new(detectors, policy);
    if normalize {
        firewall = firewall.with_normalizer(Normalizer {
            decode_encoded: base64,
            ..Normalizer::default()
        });
    }
    CoreGuard {
        firewall,
        threshold,
        direction,
    }
}

/// Dump per-example features in one ML pass: the cheap-stage (regex+heuristics) score
/// and block flag, plus the raw DeBERTa P(injection). Lets us sweep both the score
/// threshold and the ML cutoff offline without re-running the model each time.
#[cfg(feature = "ml")]
fn dump_features(data: &[dataset::Example], path: &str) -> anyhow::Result<()> {
    use soup_wall_core::{Action, Direction, MlClassifier};
    use std::io::Write;

    let policy = PolicySet::from_yaml(
        "policies:\n  - name: b\n    when: { detector: injection, min_severity: high }\n    action: block\ndefault: allow\n",
    )?;
    // Cheap firewall = regex + heuristics only (no ML), so cheap_score isolates the
    // rule stages; ml_p is the model's raw probability.
    let cheap = Firewall::new(
        vec![
            Box::new(InjectionDetector::new()),
            Box::new(SecretDetector::new()),
            Box::new(PiiDetector::new()),
        ],
        policy,
    );
    let clf = MlClassifier::load("models/injection")?;

    let mut f = std::fs::File::create(path)?;
    for ex in data {
        let out = cheap.run(&ex.text, Direction::Input);
        let ml_p = clf.predict(&ex.text).unwrap_or(0.0);
        let rec = serde_json::json!({
            "label": ex.label,
            "cheap_score": out.score.score,
            "cheap_block": out.decision.action == Action::Block,
            "ml_p": ml_p,
        });
        writeln!(f, "{rec}")?;
    }
    Ok(())
}

fn parse_rival(spec: &str) -> Option<SubprocessGuard> {
    let (name, cmd) = spec.split_once('=')?;
    let mut parts = cmd.split_whitespace();
    let program = parts.next()?.to_string();
    let args = parts.map(String::from).collect();
    Some(SubprocessGuard {
        name: name.to_string(),
        program,
        args,
    })
}

/// Run the agent-attack corpus and print its scorecard.
///
/// With `policy_path`, this is the **policy-change gate**: the corpus is replayed
/// under the candidate policy instead of the shipped one, and the process exits
/// non-zero if any reviewed attack is missed or any reviewed benign session is
/// interrupted. That is the check an operator runs after narrowing a rule and
/// before enforcing the edit against live work.
fn run_agent_benchmark(corpus: &str, policy_path: Option<&str>) -> anyhow::Result<()> {
    let sessions = agent_dataset::load_reviewed(corpus)?;
    let candidate = match policy_path {
        Some(path) => {
            let yaml = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("cannot read policy {path}: {e}"))?;
            Some(
                soup_wall_agent::AgentPolicySet::from_yaml(&yaml)
                    .map_err(|e| anyhow::anyhow!("policy {path} does not parse: {e}"))?,
            )
        }
        None => None,
    };
    let eval = agent_eval::evaluate_with(&sessions, candidate.as_ref());
    let n_attack = sessions.iter().filter(|s| s.is_attack).count();
    let n_benign = sessions.len() - n_attack;

    println!("# Agent-attack benchmark\n");
    println!(
        "Corpus: {} attack + {} benign = {} sessions. Hand-authored — measures coverage of \
         known attack shapes, not generalization to novel attacks.\n",
        n_attack,
        n_benign,
        sessions.len()
    );
    println!("| Metric | Result |");
    println!("|---|---|");
    println!(
        "| **Detection rate** | {:.1}% ({}/{}) |",
        eval.detection_rate() * 100.0,
        eval.confusion.tp,
        eval.confusion.tp + eval.confusion.fn_
    );
    println!(
        "| **False-positive rate** | {:.1}% ({}/{}) |",
        eval.false_positive_rate() * 100.0,
        eval.confusion.fp,
        eval.confusion.fp + eval.confusion.tn
    );

    println!("\n## Detection by category\n");
    println!("| Category | Detected |");
    println!("|---|---|");
    for (cat, (hit, total)) in &eval.per_category {
        println!("| {cat} | {hit}/{total} |");
    }

    if !eval.false_positives.is_empty() {
        println!(
            "\n**False positives** (benign sessions flagged): {:?}",
            eval.false_positives
        );
    }
    if !eval.misses.is_empty() {
        println!(
            "\n**Misses** (attack sessions not flagged): {:?}",
            eval.misses
        );
    }

    if let Some(path) = policy_path {
        println!("\n## Policy gate: {path}\n");
        if eval.passes_gate() {
            println!(
                "PASS: every reviewed attack still interrupts and every reviewed benign \
                 session still runs uninterrupted under this policy."
            );
        } else {
            println!(
                "FAIL: this policy regresses the reviewed corpus and must not be enforced.\n\
                 \x20 Missed attacks:        {:?}\n\
                 \x20 Interrupted benign:    {:?}\n\
                 \x20 A missed attack means the edit weakened a defense; an interrupted \
                 benign session means operators will switch it off. Fix the rule, not the \
                 corpus.",
                eval.misses, eval.false_positives
            );
            std::process::exit(1);
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Agent-attack benchmark: a separate corpus + scorecard from the text one.
    if let Some(corpus) = cli.agent.as_deref() {
        return run_agent_benchmark(corpus, cli.policy.as_deref());
    }
    anyhow::ensure!(
        !cli.dataset.is_empty(),
        "provide --dataset <file...> (text benchmark) or --agent <corpus> (agent benchmark)"
    );

    // Merge all datasets.
    let mut data = Vec::new();
    for p in &cli.dataset {
        data.extend(dataset::load_jsonl(p)?);
    }
    eprintln!("loaded {} examples", data.len());

    // Diagnostic feature dump (single ML pass) for offline threshold sweeps.
    if let Some(path) = &cli.dump_features {
        #[cfg(feature = "ml")]
        {
            dump_features(&data, path)?;
            eprintln!("wrote features to {path}");
            return Ok(());
        }
        #[cfg(not(feature = "ml"))]
        {
            let _ = path;
            anyhow::bail!("--dump-features requires the `ml` feature");
        }
    }

    let mut results: Vec<EvalResult> = Vec::new();
    let core = core_guard(
        cli.threshold,
        cli.moderation,
        cli.moderation_threshold,
        !cli.no_normalize,
        cli.normalize_base64,
        cli.direction.into(),
    );

    if let Some(path) = &cli.report {
        std::fs::write(path, report::build_report(&core.firewall, &data))?;
        eprintln!("wrote compliance report to {path}");
    }

    results.push(evaluate(&core, &data));

    for spec in &cli.rival {
        match parse_rival(spec) {
            Some(g) => {
                let name = g.name();
                results.push(evaluate(&g as &dyn Guard, &data));
                eprintln!("evaluated rival {name}");
            }
            None => {
                eprintln!("skipping malformed --rival (expected \"name=program args\"): {spec}")
            }
        }
    }

    std::fs::write(
        &cli.out,
        serde_json::to_string_pretty(&scorecard::to_json(&results))?,
    )?;
    println!("{}", scorecard::to_markdown(&results));
    eprintln!("wrote {}", cli.out);
    Ok(())
}
