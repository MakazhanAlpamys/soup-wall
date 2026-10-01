// SPDX-License-Identifier: Apache-2.0

//! OpenAI Responses API wire model and typed SSE helpers.
//!
//! Responses intentionally stays separate from Chat Completions: its `input` and
//! `output` values are arrays of typed items, and its streaming protocol emits
//! typed server-sent events rather than chat `delta` chunks.

use serde::{Deserialize, Serialize};

/// A permissive request model that keeps provider extensions byte-for-byte at the
/// JSON field level while exposing the fields the firewall must inspect.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponsesRequest {
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
    #[serde(default)]
    pub stream: bool,
    /// Preserve tools, previous_response_id, reasoning, metadata, and future fields.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// Concatenate text emitted in `response.output[].content[]` message items.
pub fn output_text(response: &serde_json::Value) -> String {
    let mut text = Vec::new();
    let Some(items) = response.get("output").and_then(serde_json::Value::as_array) else {
        return response
            .get("output_text")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
    };

    for item in items {
        if item.get("type").and_then(serde_json::Value::as_str) != Some("message") {
            continue;
        }
        let Some(content) = item.get("content").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for part in content {
            if part.get("type").and_then(serde_json::Value::as_str) == Some("output_text") {
                if let Some(value) = part.get("text").and_then(serde_json::Value::as_str) {
                    text.push(value);
                }
            }
        }
    }
    text.join("\n")
}

const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

/// Why a frame could not be decoded. The distinction matters at the enforcement
/// point: an oversized frame hid content that still reaches the client and that
/// the client will parse, whereas a payload that is not JSON at all is not
/// something a provider client could turn into a tool call either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseDecodeError {
    /// The event exceeded the inspection size limit; its content was never seen.
    TooLarge,
    /// The `data:` payload was not valid JSON.
    NotJson,
}

impl SseDecodeError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::TooLarge => "SSE event exceeded the 1 MiB inspection limit",
            Self::NotJson => "SSE data was not valid JSON",
        }
    }
}

/// Incrementally splits SSE frames and decodes only their JSON `data:` payloads.
/// Holding incomplete UTF-8 and event boundaries as bytes prevents chunk splits
/// from changing what the firewall inspects.
#[derive(Debug, Default)]
pub struct SseJsonDecoder {
    pending: Vec<u8>,
    saw_done: bool,
}

impl SseJsonDecoder {
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<serde_json::Value>, SseDecodeError> {
        self.pending.extend_from_slice(chunk);
        let mut events = Vec::new();

        while let Some((end, separator_len)) = find_frame_end(&self.pending) {
            if end > MAX_SSE_EVENT_BYTES {
                self.pending.drain(..end + separator_len);
                return Err(SseDecodeError::TooLarge);
            }
            let frame = self
                .pending
                .drain(..end + separator_len)
                .collect::<Vec<_>>();
            if frame_is_done(&frame[..end]) {
                self.saw_done = true;
                continue;
            }
            if let Some(value) = decode_frame(&frame[..end])? {
                events.push(value);
            }
        }

        if self.pending.len() > MAX_SSE_EVENT_BYTES {
            self.pending.clear();
            return Err(SseDecodeError::TooLarge);
        }
        Ok(events)
    }

    pub fn saw_done(&self) -> bool {
        self.saw_done
    }
}

fn frame_is_done(frame: &[u8]) -> bool {
    let frame = String::from_utf8_lossy(frame);
    frame.lines().any(|line| {
        line.strip_suffix('\r')
            .unwrap_or(line)
            .strip_prefix("data:")
            .map(|value| value.trim() == "[DONE]")
            .unwrap_or(false)
    })
}

fn find_frame_end(bytes: &[u8]) -> Option<(usize, usize)> {
    let lf = bytes.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2));
    let crlf = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4));
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn decode_frame(frame: &[u8]) -> Result<Option<serde_json::Value>, SseDecodeError> {
    let frame = String::from_utf8_lossy(frame);
    let data = frame
        .lines()
        .filter_map(|line| {
            line.strip_suffix('\r')
                .unwrap_or(line)
                .strip_prefix("data:")
        })
        .map(|value| value.strip_prefix(' ').unwrap_or(value))
        .collect::<Vec<_>>()
        .join("\n");
    if data.is_empty() || data == "[DONE]" {
        return Ok(None);
    }
    serde_json::from_str(&data)
        .map(Some)
        .map_err(|_| SseDecodeError::NotJson)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_typed_items_and_unknown_fields() {
        let raw = r#"{
            "model":"gpt-5.6",
            "instructions":"Be concise",
            "input":[
                {"role":"user","content":[{"type":"input_text","text":"hello"}]},
                {"type":"function_call_output","call_id":"c1","output":"sunny"}
            ],
            "reasoning":{"effort":"medium"}
        }"#;
        let request: ResponsesRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(request.model, "gpt-5.6");
        assert_eq!(request.instructions.as_deref(), Some("Be concise"));
        assert!(request.rest.contains_key("reasoning"));
        let round_trip = serde_json::to_value(request).unwrap();
        assert_eq!(round_trip["input"][1]["call_id"], "c1");
    }

    #[test]
    fn extracts_only_output_message_text() {
        let response = serde_json::json!({
            "output": [
                {"type":"reasoning","summary":[]},
                {"type":"function_call","name":"lookup","arguments":"{}"},
                {"type":"message","content":[
                    {"type":"output_text","text":"first"},
                    {"type":"refusal","refusal":"no"},
                    {"type":"output_text","text":"second"}
                ]}
            ]
        });
        assert_eq!(output_text(&response), "first\nsecond");
    }

    #[test]
    fn decoder_handles_crlf_and_arbitrary_chunk_boundaries() {
        let wire = concat!(
            "event: response.output_text.delta\r\n",
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"привет\"}\r\n\r\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\"}}\n\n"
        )
        .as_bytes();
        let mut decoder = SseJsonDecoder::default();
        let mut events = Vec::new();
        for chunk in wire.chunks(7) {
            events.extend(decoder.push(chunk).unwrap());
        }
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["delta"], "привет");
        assert_eq!(events[1]["response"]["id"], "r1");
        assert!(!decoder.saw_done());
        decoder.push(b"data: [DO").unwrap();
        decoder.push(b"NE]\n\n").unwrap();
        assert!(decoder.saw_done());
    }

    /// The size limit is reported distinctly from malformed JSON, because the
    /// enforcement point treats them differently: an oversized frame hid content
    /// the client still receives, so it fails closed, while non-JSON does not.
    #[test]
    fn an_oversized_frame_assembled_from_chunks_reports_too_large() {
        let mut decoder = SseJsonDecoder::default();
        let half = vec![b'x'; 600 * 1024];
        assert!(decoder.push(b"data: ").unwrap().is_empty());
        assert!(decoder.push(&half).unwrap().is_empty());
        let error = decoder.push(&half).unwrap_err();
        assert_eq!(error, SseDecodeError::TooLarge);
    }

    #[test]
    fn decoder_rejects_malformed_data_instead_of_silently_skipping_it() {
        let mut decoder = SseJsonDecoder::default();
        let error = decoder.push(b"data: {not-json}\n\n").unwrap_err();
        assert_eq!(error, SseDecodeError::NotJson);
    }
}
