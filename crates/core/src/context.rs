// SPDX-License-Identifier: Apache-2.0

//! The unit of text a detector inspects, plus its direction of travel.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Input,
    Output,
}

/// A borrowed view of the text under inspection. Zero-copy by design.
pub struct Context<'a> {
    pub text: &'a str,
    pub direction: Direction,
}

impl<'a> Context<'a> {
    pub fn input(text: &'a str) -> Self {
        Self {
            text,
            direction: Direction::Input,
        }
    }

    pub fn output(text: &'a str) -> Self {
        Self {
            text,
            direction: Direction::Output,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_set_direction() {
        assert_eq!(Context::input("hi").direction, Direction::Input);
        assert_eq!(Context::output("hi").direction, Direction::Output);
    }

    #[test]
    fn direction_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&Direction::Input).unwrap(),
            "\"input\""
        );
        assert_eq!(
            serde_json::to_string(&Direction::Output).unwrap(),
            "\"output\""
        );
        let round: Direction = serde_json::from_str("\"output\"").unwrap();
        assert_eq!(round, Direction::Output);
    }
}
