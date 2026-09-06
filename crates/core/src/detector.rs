// SPDX-License-Identifier: Apache-2.0

//! The uniform interface every detection stage implements.

use crate::{Context, Finding};

pub trait Detector: Send + Sync {
    /// Stable id, e.g. "injection".
    fn name(&self) -> &'static str;

    /// Inspect `ctx` and return zero or more findings.
    fn inspect(&self, ctx: &Context) -> Vec<Finding>;
}
