// SPDX-License-Identifier: Apache-2.0

//! Run an external (e.g. Python) guard as a subprocess. Protocol: we send the text on
//! stdin; the process prints "1" (malicious) or "0" (benign) on stdout.

use anyhow::{bail, Context};
use std::io::Write;
use std::process::{Command, Stdio};

use crate::evaluate::Guard;

pub struct SubprocessGuard {
    pub name: String,
    pub program: String,
    pub args: Vec<String>,
}

impl Guard for SubprocessGuard {
    fn name(&self) -> String {
        self.name.clone()
    }
    fn predict(&self, text: &str) -> anyhow::Result<bool> {
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .with_context(|| format!("cannot launch rival {} ({})", self.name, self.program))?;
        let mut stdin = child
            .stdin
            .take()
            .context("rival subprocess has no stdin pipe")?;
        if let Err(error) = stdin.write_all(text.as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error)
                .with_context(|| format!("cannot write input to rival {}", self.name));
        }
        drop(stdin);
        let out = child
            .wait_with_output()
            .with_context(|| format!("cannot read output from rival {}", self.name))?;
        if !out.status.success() {
            bail!("rival {} exited with status {}", self.name, out.status);
        }
        let verdict = std::str::from_utf8(&out.stdout)
            .with_context(|| format!("rival {} output is not UTF-8", self.name))?
            .trim();
        match verdict {
            "1" => Ok(true),
            "0" => Ok(false),
            _ => bail!(
                "rival {} returned invalid verdict; expected exactly 0 or 1",
                self.name
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_guard(name: &str, verdict: &str) -> SubprocessGuard {
        #[cfg(windows)]
        let (program, args) = (
            "cmd".to_string(),
            vec!["/C".to_string(), format!("more >NUL & echo {verdict}")],
        );
        #[cfg(not(windows))]
        let (program, args) = (
            "sh".to_string(),
            vec!["-c".to_string(), format!("cat >/dev/null; echo {verdict}")],
        );

        SubprocessGuard {
            name: name.into(),
            program,
            args,
        }
    }

    #[test]
    fn parses_subprocess_verdict() {
        // Cross-platform stand-in for a rival: echo 1 => malicious.
        let g = echo_guard("echo-1", "1");
        assert!(g.predict("anything").unwrap());

        let g0 = echo_guard("echo-0", "0");
        assert!(!g0.predict("anything").unwrap());
    }

    #[test]
    fn missing_rival_is_an_error() {
        let g = SubprocessGuard {
            name: "missing".into(),
            program: "".into(),
            args: Vec::new(),
        };
        assert!(g.predict("anything").is_err());
    }

    #[test]
    fn failed_rival_is_an_error() {
        #[cfg(windows)]
        let (program, args) = (
            "cmd".to_string(),
            vec!["/C".to_string(), "exit /B 7".to_string()],
        );
        #[cfg(not(windows))]
        let (program, args) = (
            "sh".to_string(),
            vec!["-c".to_string(), "exit 7".to_string()],
        );
        let g = SubprocessGuard {
            name: "failed".into(),
            program,
            args,
        };
        assert!(g.predict("anything").is_err());
    }

    #[test]
    fn malformed_verdict_is_an_error() {
        assert!(echo_guard("invalid", "10").predict("anything").is_err());
        assert!(echo_guard("missing", "").predict("anything").is_err());
    }
}
