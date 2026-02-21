use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSpec {
    pub version: String,
    #[serde(default)]
    pub input: InputOptions,
    #[serde(default)]
    pub ops: Vec<Op>,
    #[serde(default)]
    pub output: OutputOptions,
}

impl Default for PipelineSpec {
    fn default() -> Self {
        Self {
            version: "v1".to_string(),
            input: InputOptions::default(),
            ops: Vec::new(),
            output: OutputOptions::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputOptions {
    #[serde(default)]
    pub encoding: InputEncoding,
}

impl Default for InputOptions {
    fn default() -> Self {
        Self {
            encoding: InputEncoding::Utf8,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InputEncoding {
    #[default]
    Utf8,
    BytesLossy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputOptions {
    #[serde(default)]
    pub terminal_policy: TerminalPolicy,
    #[serde(default)]
    pub newline: NewlineMode,
}

impl Default for OutputOptions {
    fn default() -> Self {
        Self {
            terminal_policy: TerminalPolicy::Balanced,
            newline: NewlineMode::Preserve,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TerminalPolicy {
    #[default]
    Balanced,
    StrictPrintable,
    Raw,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NewlineMode {
    #[default]
    Preserve,
    EnsureTrailing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnicodeForm {
    Nfc,
    Nfkc,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrimMode {
    Left,
    Right,
    Both,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractMode {
    First,
    All,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStyle {
    Json,
    ShellSingle,
    MarkdownCode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TableDelimiter {
    Comma,
    Tab,
    Pipe,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TableAlign {
    Left,
    Right,
    Center,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactPattern {
    Email,
    Ipv4,
    ApiKeyLike,
    Url,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    NormalizeUnicode {
        form: UnicodeForm,
    },
    Trim {
        mode: TrimMode,
    },
    CollapseWhitespace {
        preserve_newlines: bool,
    },
    Wrap {
        width: u16,
        break_long_words: bool,
    },
    Truncate {
        max_chars: u32,
        ellipsis: String,
    },
    ExtractBetween {
        start: String,
        end: String,
        mode: ExtractMode,
    },
    ReplaceLiteral {
        from: String,
        to: String,
        max_replacements: Option<u32>,
    },
    RegexReplace {
        pattern: String,
        to: String,
        max_replacements: Option<u32>,
    },
    Redact {
        patterns: Vec<RedactPattern>,
        replacement: String,
    },
    Quote {
        style: QuoteStyle,
    },
    Table {
        delimiter: TableDelimiter,
        align: TableAlign,
    },
    SortLines {
        unique: bool,
        numeric: bool,
        reverse: bool,
    },
}

#[derive(Debug, Error)]
pub enum SpecError {
    #[error("invalid JSON spec: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid spec: {0}")]
    Invalid(String),
}

pub fn parse_spec_from_str(input: &str) -> Result<PipelineSpec, SpecError> {
    let spec: PipelineSpec = serde_json::from_str(input)?;
    validate_spec(&spec)?;
    Ok(spec)
}

pub fn validate_spec(spec: &PipelineSpec) -> Result<(), SpecError> {
    if spec.version != "v1" {
        return Err(SpecError::Invalid(format!(
            "unsupported version '{}'; expected 'v1'",
            spec.version
        )));
    }

    for (idx, op) in spec.ops.iter().enumerate() {
        match op {
            Op::Wrap { width, .. } => {
                if *width == 0 {
                    return Err(SpecError::Invalid(format!(
                        "ops[{idx}] wrap.width must be > 0"
                    )));
                }
            }
            Op::Truncate { max_chars, .. } => {
                if *max_chars == 0 {
                    return Err(SpecError::Invalid(format!(
                        "ops[{idx}] truncate.max_chars must be > 0"
                    )));
                }
            }
            Op::ExtractBetween { start, end, .. } => {
                if start.is_empty() || end.is_empty() {
                    return Err(SpecError::Invalid(format!(
                        "ops[{idx}] extract_between requires non-empty start/end"
                    )));
                }
            }
            Op::ReplaceLiteral { from, .. } => {
                if from.is_empty() {
                    return Err(SpecError::Invalid(format!(
                        "ops[{idx}] replace_literal.from must be non-empty"
                    )));
                }
            }
            Op::RegexReplace { pattern, .. } => {
                Regex::new(pattern).map_err(|e| {
                    SpecError::Invalid(format!(
                        "ops[{idx}] regex_replace.pattern failed to compile: {e}"
                    ))
                })?;
            }
            Op::Redact { patterns, .. } => {
                if patterns.is_empty() {
                    return Err(SpecError::Invalid(format!(
                        "ops[{idx}] redact.patterns must include at least one pattern"
                    )));
                }
            }
            Op::NormalizeUnicode { .. }
            | Op::Trim { .. }
            | Op::CollapseWhitespace { .. }
            | Op::Quote { .. }
            | Op::Table { .. }
            | Op::SortLines { .. } => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_basic_spec() {
        let spec = PipelineSpec {
            ops: vec![Op::Wrap {
                width: 80,
                break_long_words: false,
            }],
            ..PipelineSpec::default()
        };
        assert!(validate_spec(&spec).is_ok());
    }

    #[test]
    fn rejects_bad_regex() {
        let spec = PipelineSpec {
            ops: vec![Op::RegexReplace {
                pattern: "(".to_string(),
                to: "x".to_string(),
                max_replacements: None,
            }],
            ..PipelineSpec::default()
        };
        assert!(validate_spec(&spec).is_err());
    }
}
