#!/usr/bin/env bash
# Download standardized benchmark corpora and normalize to datasets/*.jsonl
# ({"text","label"} where label=true means malicious/attack).
#
# Uses the Hugging Face datasets-server REST API (JSON) via the Python standard
# library only -- no `pip install datasets`, no pyarrow, no network auth.
set -euo pipefail
mkdir -p datasets

python3 - <<'PY'
import json, urllib.request, urllib.parse, time

def fetch_split(dataset, config, split):
    rows, offset = [], 0
    while True:
        q = urllib.parse.urlencode(
            {"dataset": dataset, "config": config, "split": split,
             "offset": offset, "length": 100})
        url = "https://datasets-server.huggingface.co/rows?" + q
        with urllib.request.urlopen(url, timeout=30) as r:
            d = json.load(r)
        batch = d.get("rows", [])
        if not batch:
            break
        rows += [item["row"] for item in batch]
        total = d.get("num_rows_total", 0)
        offset += len(batch)
        if offset >= total:
            break
        time.sleep(0.2)
    return rows

def dump(pairs, path):
    pairs = [(t, l) for t, l in pairs if t]
    with open(path, "w") as f:
        for text, label in pairs:
            f.write(json.dumps({"text": text, "label": bool(label)}) + "\n")
    n_mal = sum(1 for _, l in pairs if l)
    print(f"wrote {path}: {len(pairs)} rows ({n_mal} malicious / {len(pairs)-n_mal} benign)")

# 1) deepset/prompt-injections -- label 1 = injection, 0 = benign (train+test).
pairs = []
for split in ("train", "test"):
    for r in fetch_split("deepset/prompt-injections", "default", split):
        pairs.append((r["text"], int(r["label"]) == 1))
dump(pairs, "datasets/deepset_injection.jsonl")

# 2) jackhhao/jailbreak-classification -- type in {benign, jailbreak} (test split).
pairs = [(r["prompt"], r["type"].strip().lower() == "jailbreak")
         for r in fetch_split("jackhhao/jailbreak-classification", "default", "test")]
dump(pairs, "datasets/jailbreak_classification.jsonl")

# 3) xTRam1/safe-guard-prompt-injection -- label 1 = injection (test split).
pairs = [(r["text"], int(r["label"]) == 1)
         for r in fetch_split("xTRam1/safe-guard-prompt-injection", "default", "test")]
dump(pairs, "datasets/safe_guard.jsonl")

# 4) JailbreakBench/JBB-Behaviors -- all harmful goals (recall-only; a DIFFERENT
#    threat -- harmful-content, not prompt injection -- kept as an out-of-scope ref).
pairs = [(r["Goal"], True)
         for r in fetch_split("JailbreakBench/JBB-Behaviors", "behaviors", "harmful")]
dump(pairs, "datasets/jailbreakbench.jsonl")
PY
echo "Datasets ready in ./datasets"
