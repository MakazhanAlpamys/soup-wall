// SPDX-License-Identifier: Apache-2.0

//! Confusion matrix + derived metrics. `true` = malicious (positive class).

use serde::Serialize;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize)]
pub struct Confusion {
    pub tp: u64,
    pub fp: u64,
    pub tn: u64,
    #[serde(rename = "fn")]
    pub fn_: u64,
}

impl Confusion {
    pub fn record(&mut self, predicted: bool, actual: bool) {
        match (predicted, actual) {
            (true, true) => self.tp += 1,
            (true, false) => self.fp += 1,
            (false, false) => self.tn += 1,
            (false, true) => self.fn_ += 1,
        }
    }

    pub fn recall(&self) -> f64 {
        let d = self.tp + self.fn_;
        if d == 0 {
            0.0
        } else {
            self.tp as f64 / d as f64
        }
    }
    pub fn precision(&self) -> f64 {
        let d = self.tp + self.fp;
        if d == 0 {
            0.0
        } else {
            self.tp as f64 / d as f64
        }
    }
    /// False-positive rate on benign inputs — the "over-defense" number.
    pub fn fpr(&self) -> f64 {
        let d = self.fp + self.tn;
        if d == 0 {
            0.0
        } else {
            self.fp as f64 / d as f64
        }
    }
    pub fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
    /// Overall accuracy. Exposed for completeness; not part of the headline scorecard.
    #[allow(dead_code)]
    pub fn accuracy(&self) -> f64 {
        let t = self.tp + self.tn;
        let d = t + self.fp + self.fn_;
        if d == 0 {
            0.0
        } else {
            t as f64 / d as f64
        }
    }
}

/// Nearest-rank percentile of latency samples (ms). `sorted` must be ascending.
pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (((p / 100.0) * (sorted.len() - 1) as f64).round() as usize).min(sorted.len() - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_match_hand_calc() {
        // 8 TP, 2 FN, 1 FP, 9 TN
        let c = Confusion {
            tp: 8,
            fp: 1,
            tn: 9,
            fn_: 2,
        };
        assert!((c.recall() - 0.8).abs() < 1e-9);
        assert!((c.precision() - 8.0 / 9.0).abs() < 1e-9);
        assert!((c.fpr() - 0.1).abs() < 1e-9);
        assert!((c.accuracy() - 17.0 / 20.0).abs() < 1e-9);
        assert!(c.f1() > 0.8 && c.f1() < 0.9);
    }

    #[test]
    fn percentile_picks_expected() {
        let xs = vec![1.0, 2.0, 3.0, 4.0, 100.0];
        assert_eq!(percentile(&xs, 50.0), 3.0);
        assert_eq!(percentile(&xs, 99.0), 100.0);
        assert_eq!(percentile(&[], 50.0), 0.0);
    }
}
