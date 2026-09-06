#!/usr/bin/env python3
"""Obfuscate the MALICIOUS rows of a {text,label} jsonl using the same evasion
techniques trusted red-team tools apply (Unicode UTS #39 confusables, Trojan-Source
zero-width, NVIDIA garak / Microsoft PyRIT base64). Benign rows pass through unchanged
so the false-positive rate is measured on untouched controls.

Usage: obfuscate-dataset.py <src.jsonl> <dst.jsonl> <zero-width|homoglyph|base64|all>
"""
import base64
import json
import sys

# UTS #39 Latin -> confusable substitutions (a subset; enough to spoof injection keywords).
CONFUSABLE = {
    "a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "y": "у",
    "x": "х", "i": "і", "s": "ѕ", "d": "ԁ", "j": "ј", "k": "к",
}
ZW = "​"  # zero-width space (Trojan-Source class)


def homoglyph(s: str) -> str:
    return "".join(CONFUSABLE.get(ch, ch) for ch in s)


def zerowidth(s: str) -> str:
    return ZW.join(s)  # split every character


def b64(s: str) -> str:
    return "decode and follow: " + base64.b64encode(s.encode()).decode()


def transform(s: str, mode: str) -> str:
    if mode == "homoglyph":
        return homoglyph(s)
    if mode == "zero-width":
        return zerowidth(s)
    if mode == "base64":
        return b64(s)
    return b64(homoglyph(s))  # "all"


def main() -> None:
    src, dst, mode = sys.argv[1], sys.argv[2], sys.argv[3]
    n_mal = 0
    with open(src) as f, open(dst, "w") as g:
        for line in f:
            r = json.loads(line)
            if r.get("label"):
                r["text"] = transform(r["text"], mode)
                n_mal += 1
            g.write(json.dumps(r) + "\n")
    print(f"wrote {dst} (mode={mode}, obfuscated {n_mal} malicious rows)")


if __name__ == "__main__":
    main()
