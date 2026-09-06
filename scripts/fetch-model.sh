#!/usr/bin/env bash
# Fetch the ML model assets with plain curl (resumable, no huggingface CLI, no auth
# needed for these open models). If the primary host is slow/throttled, set
# HF_HOST=https://hf-mirror.com for a mirror.
#
#   ./scripts/fetch-model.sh            # both: injection + moderation
#   ./scripts/fetch-model.sh injection  # just the prompt-injection classifier
#   ./scripts/fetch-model.sh moderation # just the harmful-content classifier
set -euo pipefail

HF_HOST="${HF_HOST:-https://huggingface.co}"
WHICH="${1:-all}"

fetch() {
  local repo="$1" dest="$2"
  mkdir -p "$dest"
  echo "Fetching $repo from $HF_HOST -> $dest"
  for f in config.json tokenizer.json model.safetensors; do
    echo "  - $f"
    curl -L -C - --retry 8 --retry-delay 3 --fail -o "$dest/$f" \
      "$HF_HOST/$repo/resolve/main/$f"
  done
}

if [ "$WHICH" = "all" ] || [ "$WHICH" = "injection" ]; then
  fetch "${INJECTION_REPO:-protectai/deberta-v3-base-prompt-injection-v2}" models/injection
fi
if [ "$WHICH" = "all" ] || [ "$WHICH" = "moderation" ]; then
  # Harmful-request classifier (BeaverTails). Serves OWASP-adjacent harmful-content /
  # jailbreak-goal detection. Labels: index 0 = harmful, 1 = safe.
  fetch "${MODERATION_REPO:-domenicrosati/deberta-v3-xsmall-beavertails-harmful-qa-classifier}" models/moderation
fi

echo "Done."
