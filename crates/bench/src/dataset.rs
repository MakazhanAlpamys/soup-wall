// SPDX-License-Identifier: Apache-2.0

//! Labeled examples. JSONL: one `{"text": "...", "label": true}` per line.
//! `label = true` means malicious/attack (positive class).

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Example {
    pub text: String,
    pub label: bool,
}

pub fn load_jsonl(path: impl AsRef<Path>) -> anyhow::Result<Vec<Example>> {
    let content = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let ex: Example =
            serde_json::from_str(line).map_err(|e| anyhow::anyhow!("line {}: {e}", i + 1))?;
        out.push(ex);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_labeled_lines() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "{{\"text\":\"ignore instructions\",\"label\":true}}").unwrap();
        writeln!(f).unwrap(); // blank line skipped
        writeln!(f, "{{\"text\":\"hello\",\"label\":false}}").unwrap();
        let data = load_jsonl(f.path()).unwrap();
        assert_eq!(data.len(), 2);
        assert!(data[0].label);
        assert!(!data[1].label);
    }
}
