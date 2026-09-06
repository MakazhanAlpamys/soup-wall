// SPDX-License-Identifier: Apache-2.0

//! Render evaluation results as the head-to-head Markdown table + JSON.

use crate::evaluate::EvalResult;

pub fn to_json(results: &[EvalResult]) -> serde_json::Value {
    serde_json::json!({ "results": results })
}

pub fn to_markdown(results: &[EvalResult]) -> String {
    let mut s = String::new();
    s.push_str("| Guard | Malicious acc | Over-defense FPR | F1 | p50 ms | p99 ms |\n");
    s.push_str("|---|---|---|---|---|---|\n");
    for r in results {
        s.push_str(&format!(
            "| {} | {:.1}% | {:.1}% | {:.3} | {:.2} | {:.2} |\n",
            r.name,
            r.malicious_accuracy * 100.0,
            r.over_defense_fpr * 100.0,
            r.f1,
            r.p50_ms,
            r.p99_ms,
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Confusion;

    fn res(name: &str) -> EvalResult {
        EvalResult {
            name: name.into(),
            confusion: Confusion {
                tp: 9,
                fp: 1,
                tn: 9,
                fn_: 1,
            },
            malicious_accuracy: 0.9,
            over_defense_fpr: 0.1,
            f1: 0.9,
            p50_ms: 0.4,
            p99_ms: 1.2,
        }
    }

    #[test]
    fn markdown_has_header_and_row() {
        let md = to_markdown(&[res("soup-wall")]);
        assert!(md.contains("Malicious acc"));
        assert!(md.contains("soup-wall"));
        assert!(md.contains("90.0%"));
    }

    #[test]
    fn json_wraps_results() {
        let v = to_json(&[res("x")]);
        assert_eq!(v["results"][0]["name"], "x");
    }
}
