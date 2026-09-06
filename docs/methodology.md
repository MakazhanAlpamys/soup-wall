# Benchmark methodology (fairness rules)

- **Same corpora, same labels** for every guard (ours + rivals), loaded from `datasets/*.jsonl`.
- **Two headline metrics**, always reported together: malicious accuracy (recall on attacks) and
  over-defense FPR (false positives on benign sets like NotInject). One without the other is not a
  valid comparison.
- **Rivals run isolated**: each Python rival in its own venv, warmed once before timing.
- **Same hardware / same process invocation overhead**; subprocess startup is included for all
  subprocess-based guards so latency is apples-to-apples (or noted when it isn't).
- **Missing rival = visible under-count**, never a silent skip: if a rival isn't installed the
  adapter emits benign, which *lowers* its measured recall rather than inflating ours.
- **Published numbers** for guards we don't re-run (e.g. Lakera) are cited with source + date, and
  clearly separated from numbers we measured locally.

The reviewed agent-session scorecard is reproducible with:

```sh
cargo run --locked --release -p soup-wall-bench -- \
  --agent crates/bench/corpora/agent_sessions.jsonl
```

CI publishes the generated Markdown as an artifact. The committed snapshot is
coverage of the versioned hand-authored corpus only; it is not a claim of
generalization or a substitute for a held-out public agent benchmark.

## Corpus notes

We report against four recognized public corpora (all pulled by `./scripts/fetch-datasets.sh` from
the Hugging Face datasets-server REST API — standard library only, no `pip install datasets`):

- **`xTRam1/safe-guard-prompt-injection`** (test split, 2060 prompts, 650 inj / 1410 benign) — our
  largest and most representative prompt-injection set. Full system: **84.3% recall @ 0.2% FPR**.
- **`jackhhao/jailbreak-classification`** (test split, 262 prompts, 139 / 123) — jailbreak vs. benign.
  Full system: **85.6% recall @ 1.6% FPR**.
- **`deepset/prompt-injections`** (train+test, 662 prompts, 263 / 399) — its "injection" label is
  *broad*: it tags many roleplay, capability ("write SQL that…"), and non-English benign prompts as
  injection, so a strict injection detector shows conservative recall (41.4%). That is a property of
  the ground truth, not muted detection — verify classifier fidelity directly with
  `cargo run -p soup-wall-core --features ml --release --example ml_probe` (unambiguous attacks
  score P(injection) ≈ 1.00, clean prompts ≈ 0.00).
- **`JailbreakBench/JBB-Behaviors`** (harmful split, 100 goals) — **out of scope**: it measures
  harmful-*content* requests, not prompt injection. Reported (0% recall) only for scope transparency;
  this firewall is not a content-moderation classifier.
- **Latency** is measured per-prompt on Apple Silicon CPU, single-threaded. The ML stage runs unless
  a cheap stage already produced a blocking (High) finding, so the default (rules-only) build stays in
  the microseconds while the full system pays the model cost (~0.1–0.3 s) only when needed.
- **Operating point.** The ML stage flags at the classifier's own decision boundary
  (`P(injection) ≥ 0.5`, `InjectionDetector::with_ml_threshold`) and a positive detection blocks
  directly (policy rule on the `injection.ml` detector id), independent of the risk-score banding.
  Because the DeBERTa model is well-calibrated (benign ≈ 0), honoring the 0.5 boundary rather than an
  accidental ~0.85 cutoff lifts recall ~5–12 points with no measurable FPR change.

## Obfuscation resilience

- **Method.** We transform the *malicious* rows of a recognized corpus with the same evasion
  techniques trusted red-team tools apply — **Unicode UTS #39** confusables (homoglyphs),
  **Trojan-Source** zero-width insertion, and **NVIDIA garak / Microsoft PyRIT** base64 wrapping
  (`scripts/obfuscate-dataset.py`) — then compare recall `--no-normalize` (baseline) vs. with the
  dual-scan normalization pre-pass. Benign rows are left untouched so FPR is measured on controls,
  including a **multilingual benign set** (Russian/Greek/Arabic/Japanese/accented + emoji).
- **Result (safe-guard, rule-based build, no ML).** Homoglyph and zero-width obfuscation drop recall
  from the clean 14.6% to **0.0%** (regex cannot match the altered bytes); the pre-pass restores it to
  **~14.5%** (and base64 to 30.6%), with **0.00% FPR** on the multilingual control — no over-defense.
- **Honest caveat.** The **DeBERTa ML stage is already largely robust** to these obfuscations on its
  own (homoglyph ~97–99%, zero-width ~100% recall even without the pre-pass, because anomalous text
  scores high). So the pre-pass's decisive value is (a) protecting the fast **rule-only default build**
  and (b) making detection *principled* — acting on the decoded attack, not merely on "looks weird."
- **Dual-scan / no over-defense.** Obfuscation is never itself a block reason; the pre-pass only adds
  signal when the de-obfuscated text triggers a real detector, so legitimate multilingual/data-bearing
  prompts pass through unchanged (see `firewall.rs`). Base64 decoding is opt-in.
