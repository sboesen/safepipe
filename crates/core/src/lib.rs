use regex::Regex;
use safepipe_spec::{
    validate_spec, ExtractMode, InputEncoding, NewlineMode, Op, PipelineSpec, QuoteStyle,
    RedactPattern, TableAlign, TableDelimiter, TerminalPolicy, TrimMode, UnicodeForm,
};
use std::cmp::Ordering;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone)]
pub struct EngineLimits {
    pub max_output_bytes: usize,
    pub max_lines: usize,
    pub timeout: Option<Duration>,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: 8 * 1024 * 1024,
            max_lines: 200_000,
            timeout: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("spec error: {0}")]
    Spec(String),
    #[error("input is not valid UTF-8; set input.encoding=bytes_lossy to accept arbitrary bytes")]
    InvalidUtf8,
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("operation timed out")]
    Timeout,
    #[error("regex compilation failed: {0}")]
    Regex(#[from] regex::Error),
    #[error("json encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn run_pipeline(
    input: &[u8],
    spec: &PipelineSpec,
    limits: &EngineLimits,
) -> Result<String, EngineError> {
    validate_spec(spec).map_err(|e| EngineError::Spec(e.to_string()))?;

    let start = Instant::now();
    let mut text = decode_input(input, spec.input.encoding)?;
    enforce_timeout(start, limits.timeout)?;

    for op in &spec.ops {
        text = apply_op(text, op)?;
        enforce_timeout(start, limits.timeout)?;
        enforce_limits(&text, limits)?;
    }

    apply_newline_mode(&mut text, spec.output.newline);

    let sanitized = match spec.output.terminal_policy {
        TerminalPolicy::Raw => text,
        TerminalPolicy::StrictPrintable => sanitize_strict_printable(&text),
        TerminalPolicy::Balanced => sanitize_balanced(&text),
    };

    enforce_limits(&sanitized, limits)?;
    Ok(sanitized)
}

fn decode_input(input: &[u8], encoding: InputEncoding) -> Result<String, EngineError> {
    match encoding {
        InputEncoding::Utf8 => std::str::from_utf8(input)
            .map(|s| s.to_owned())
            .map_err(|_| EngineError::InvalidUtf8),
        InputEncoding::BytesLossy => Ok(String::from_utf8_lossy(input).into_owned()),
    }
}

fn apply_newline_mode(text: &mut String, mode: NewlineMode) {
    if matches!(mode, NewlineMode::EnsureTrailing) && !text.ends_with('\n') {
        text.push('\n');
    }
}

fn enforce_timeout(start: Instant, timeout: Option<Duration>) -> Result<(), EngineError> {
    if let Some(timeout) = timeout {
        if start.elapsed() > timeout {
            return Err(EngineError::Timeout);
        }
    }
    Ok(())
}

fn enforce_limits(text: &str, limits: &EngineLimits) -> Result<(), EngineError> {
    if text.len() > limits.max_output_bytes {
        return Err(EngineError::LimitExceeded(format!(
            "output bytes {} exceeded max_output_bytes {}",
            text.len(),
            limits.max_output_bytes
        )));
    }

    let line_count = if text.is_empty() {
        0
    } else {
        text.as_bytes().iter().filter(|&&b| b == b'\n').count() + 1
    };

    if line_count > limits.max_lines {
        return Err(EngineError::LimitExceeded(format!(
            "output lines {} exceeded max_lines {}",
            line_count, limits.max_lines
        )));
    }

    Ok(())
}

fn apply_op(input: String, op: &Op) -> Result<String, EngineError> {
    match op {
        Op::NormalizeUnicode { form } => Ok(match form {
            UnicodeForm::Nfc => input.nfc().collect(),
            UnicodeForm::Nfkc => input.nfkc().collect(),
        }),
        Op::Trim { mode } => Ok(match mode {
            TrimMode::Left => input.trim_start().to_string(),
            TrimMode::Right => input.trim_end().to_string(),
            TrimMode::Both => input.trim().to_string(),
        }),
        Op::CollapseWhitespace { preserve_newlines } => {
            if *preserve_newlines {
                let out = input
                    .split('\n')
                    .map(collapse_horizontal_whitespace)
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(out)
            } else {
                Ok(input.split_whitespace().collect::<Vec<_>>().join(" "))
            }
        }
        Op::Wrap {
            width,
            break_long_words,
        } => Ok(wrap_text(&input, *width as usize, *break_long_words)),
        Op::Truncate {
            max_chars,
            ellipsis,
        } => Ok(truncate_chars(&input, *max_chars as usize, ellipsis)),
        Op::ExtractBetween { start, end, mode } => Ok(extract_between(&input, start, end, *mode)),
        Op::ReplaceLiteral {
            from,
            to,
            max_replacements,
        } => Ok(match max_replacements {
            Some(n) => input.replacen(from, to, *n as usize),
            None => input.replace(from, to),
        }),
        Op::RegexReplace {
            pattern,
            to,
            max_replacements,
        } => {
            let re = Regex::new(pattern)?;
            Ok(match max_replacements {
                Some(n) => re.replacen(&input, *n as usize, to.as_str()).to_string(),
                None => re.replace_all(&input, to.as_str()).to_string(),
            })
        }
        Op::Redact {
            patterns,
            replacement,
        } => {
            let mut out = input;
            for pattern in patterns {
                out = redact_regex(pattern)
                    .replace_all(&out, replacement.as_str())
                    .to_string();
            }
            Ok(out)
        }
        Op::Quote { style } => Ok(match style {
            QuoteStyle::Json => serde_json::to_string(&input)?,
            QuoteStyle::ShellSingle => shell_single_quote(&input),
            QuoteStyle::MarkdownCode => markdown_code_quote(&input),
        }),
        Op::Table { delimiter, align } => Ok(format_table(&input, *delimiter, *align)),
        Op::SortLines {
            unique,
            numeric,
            reverse,
        } => Ok(sort_lines(&input, *unique, *numeric, *reverse)),
        Op::SelectColumns {
            delimiter,
            fields,
            output_delimiter,
            skip_missing,
        } => Ok(select_columns(
            &input,
            delimiter,
            fields,
            output_delimiter.as_deref(),
            *skip_missing,
        )),
        Op::FilterContains { needle, invert } => Ok(filter_contains(&input, needle, *invert)),
        Op::FilterRegex { pattern, invert } => Ok(filter_regex(&input, pattern, *invert)?),
    }
}

fn collapse_horizontal_whitespace(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut last_was_ws = false;
    for ch in line.chars() {
        if ch.is_whitespace() {
            if !last_was_ws {
                out.push(' ');
                last_was_ws = true;
            }
        } else {
            out.push(ch);
            last_was_ws = false;
        }
    }
    out.trim().to_string()
}

fn wrap_text(input: &str, width: usize, break_long_words: bool) -> String {
    let mut wrapped_lines: Vec<String> = Vec::new();

    for line in input.split('\n') {
        if line.is_empty() {
            wrapped_lines.push(String::new());
            continue;
        }

        let words: Vec<&str> = line.split_whitespace().collect();
        if words.is_empty() {
            wrapped_lines.push(String::new());
            continue;
        }

        let mut current = String::new();

        for word in words {
            let word_len = word.chars().count();
            if break_long_words && word_len > width {
                if !current.is_empty() {
                    wrapped_lines.push(current);
                    current = String::new();
                }

                let mut chunk = String::new();
                for ch in word.chars() {
                    chunk.push(ch);
                    if chunk.chars().count() == width {
                        wrapped_lines.push(chunk);
                        chunk = String::new();
                    }
                }

                if !chunk.is_empty() {
                    current = chunk;
                }
                continue;
            }

            if current.is_empty() {
                current.push_str(word);
                continue;
            }

            let candidate_len = current.chars().count() + 1 + word_len;
            if candidate_len <= width {
                current.push(' ');
                current.push_str(word);
            } else {
                wrapped_lines.push(current);
                current = word.to_string();
            }
        }

        if !current.is_empty() {
            wrapped_lines.push(current);
        }
    }

    wrapped_lines.join("\n")
}

fn truncate_chars(input: &str, max_chars: usize, ellipsis: &str) -> String {
    let char_count = input.chars().count();
    if char_count <= max_chars {
        return input.to_string();
    }

    let mut out = String::new();
    for ch in input.chars().take(max_chars) {
        out.push(ch);
    }
    out.push_str(ellipsis);
    out
}

fn extract_between(input: &str, start: &str, end: &str, mode: ExtractMode) -> String {
    match mode {
        ExtractMode::First => {
            let Some(start_idx) = input.find(start) else {
                return String::new();
            };
            let after_start = &input[start_idx + start.len()..];
            let Some(end_rel) = after_start.find(end) else {
                return String::new();
            };
            after_start[..end_rel].to_string()
        }
        ExtractMode::All => {
            let mut out = Vec::new();
            let mut cursor = input;

            loop {
                let Some(start_idx) = cursor.find(start) else {
                    break;
                };
                let tail = &cursor[start_idx + start.len()..];
                let Some(end_idx) = tail.find(end) else {
                    break;
                };
                out.push(tail[..end_idx].to_string());
                cursor = &tail[end_idx + end.len()..];
            }

            out.join("\n")
        }
    }
}

fn shell_single_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\\''"))
}

fn markdown_code_quote(input: &str) -> String {
    let fence = if input.contains("```") { "````" } else { "```" };
    format!("{fence}\n{input}\n{fence}")
}

fn delimiter_char(delimiter: TableDelimiter) -> char {
    match delimiter {
        TableDelimiter::Comma => ',',
        TableDelimiter::Tab => '\t',
        TableDelimiter::Pipe => '|',
    }
}

fn format_table(input: &str, delimiter: TableDelimiter, align: TableAlign) -> String {
    if input.is_empty() {
        return String::new();
    }

    let delim = delimiter_char(delimiter);
    let mut rows: Vec<Vec<String>> = input
        .lines()
        .map(|line| {
            line.split(delim)
                .map(|cell| cell.trim().to_string())
                .collect()
        })
        .collect();

    if rows.is_empty() {
        return input.to_string();
    }

    let cols = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    for row in &mut rows {
        while row.len() < cols {
            row.push(String::new());
        }
    }

    let mut widths = vec![0usize; cols];
    for row in &rows {
        for (idx, cell) in row.iter().enumerate() {
            widths[idx] = widths[idx].max(cell.chars().count());
        }
    }

    let mut out_lines = Vec::with_capacity(rows.len());
    for row in rows {
        let formatted = row
            .into_iter()
            .enumerate()
            .map(|(idx, cell)| align_cell(&cell, widths[idx], align))
            .collect::<Vec<_>>()
            .join(" | ");
        out_lines.push(formatted);
    }

    let mut out = out_lines.join("\n");
    if input.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn align_cell(cell: &str, width: usize, align: TableAlign) -> String {
    let current = cell.chars().count();
    if current >= width {
        return cell.to_string();
    }

    let pad = width - current;
    match align {
        TableAlign::Left => format!("{cell}{}", " ".repeat(pad)),
        TableAlign::Right => format!("{}{cell}", " ".repeat(pad)),
        TableAlign::Center => {
            let left = pad / 2;
            let right = pad - left;
            format!("{}{}{}", " ".repeat(left), cell, " ".repeat(right))
        }
    }
}

fn sort_lines(input: &str, unique: bool, numeric: bool, reverse: bool) -> String {
    let had_trailing_newline = input.ends_with('\n');
    let mut lines: Vec<String> = input.lines().map(|line| line.to_string()).collect();

    lines.sort_by(|a, b| {
        if numeric {
            compare_numeric_lines(a, b)
        } else {
            a.cmp(b)
        }
    });

    if unique {
        lines.dedup();
    }

    if reverse {
        lines.reverse();
    }

    let mut out = lines.join("\n");
    if had_trailing_newline {
        out.push('\n');
    }
    out
}

fn compare_numeric_lines(a: &str, b: &str) -> Ordering {
    let a_num = a.trim().parse::<f64>();
    let b_num = b.trim().parse::<f64>();

    match (a_num, b_num) {
        (Ok(x), Ok(y)) => x.total_cmp(&y).then_with(|| a.cmp(b)),
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => a.cmp(b),
    }
}

fn select_columns(
    input: &str,
    delimiter: &str,
    fields: &[u16],
    output_delimiter: Option<&str>,
    skip_missing: bool,
) -> String {
    let had_trailing_newline = input.ends_with('\n');
    let normalized = normalize_delimiter(delimiter);
    let out_delim = match (output_delimiter, normalized) {
        (Some(explicit), _) => explicit,
        (None, None) => " ",
        (None, Some(delim)) => delim,
    };

    let mut out_lines = Vec::new();
    for line in input.lines() {
        let columns = split_columns(line, delimiter);
        let mut selected = Vec::with_capacity(fields.len());
        for field in fields {
            let idx = (*field as usize).saturating_sub(1);
            if let Some(value) = columns.get(idx) {
                selected.push((*value).to_string());
            } else if !skip_missing {
                selected.push(String::new());
            }
        }
        out_lines.push(selected.join(out_delim));
    }

    let mut out = out_lines.join("\n");
    if had_trailing_newline {
        out.push('\n');
    }
    out
}

fn filter_contains(input: &str, needle: &str, invert: bool) -> String {
    let had_trailing_newline = input.ends_with('\n');
    let mut kept = Vec::new();
    for line in input.lines() {
        let contains = line.contains(needle);
        if contains ^ invert {
            kept.push(line.to_string());
        }
    }

    let mut out = kept.join("\n");
    if had_trailing_newline {
        out.push('\n');
    }
    out
}

fn filter_regex(input: &str, pattern: &str, invert: bool) -> Result<String, EngineError> {
    let had_trailing_newline = input.ends_with('\n');
    let re = Regex::new(pattern)?;
    let mut kept = Vec::new();
    for line in input.lines() {
        let matches = re.is_match(line);
        if matches ^ invert {
            kept.push(line.to_string());
        }
    }

    let mut out = kept.join("\n");
    if had_trailing_newline {
        out.push('\n');
    }
    Ok(out)
}

fn split_columns<'a>(line: &'a str, delimiter: &str) -> Vec<&'a str> {
    match normalize_delimiter(delimiter) {
        None => line.split_whitespace().collect(),
        Some(delim) => line.split(delim).collect(),
    }
}

fn normalize_delimiter(delimiter: &str) -> Option<&str> {
    match delimiter {
        "whitespace" => None,
        "\\t" => Some("\t"),
        other => Some(other),
    }
}

fn redact_regex(pattern: &RedactPattern) -> &'static Regex {
    static EMAIL: OnceLock<Regex> = OnceLock::new();
    static IPV4: OnceLock<Regex> = OnceLock::new();
    static API_KEY: OnceLock<Regex> = OnceLock::new();
    static URL: OnceLock<Regex> = OnceLock::new();

    match pattern {
        RedactPattern::Email => EMAIL.get_or_init(|| {
            Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
                .expect("email regex must compile")
        }),
        RedactPattern::Ipv4 => IPV4.get_or_init(|| {
            Regex::new(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
                .expect("ipv4 regex must compile")
        }),
        RedactPattern::ApiKeyLike => API_KEY.get_or_init(|| {
            Regex::new(r"(?i)\b(?:sk|api|token|key)[-_]?[a-z0-9]{8,}\b")
                .expect("api-key-like regex must compile")
        }),
        RedactPattern::Url => {
            URL.get_or_init(|| Regex::new(r"https?://[^\s]+").expect("url regex must compile"))
        }
    }
}

fn sanitize_strict_printable(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if matches!(ch, '\n' | '\t') {
            out.push(ch);
        } else if ch == '\r' {
            out.push('\n');
        } else if ch.is_control() {
            out.push_str(&format!(r"\u{{{:x}}}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

fn sanitize_balanced(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];

        if b == 0x1b {
            if i + 1 >= bytes.len() {
                i += 1;
                continue;
            }

            match bytes[i + 1] {
                b'[' => {
                    let mut j = i + 2;
                    let mut final_byte = None;

                    while j < bytes.len() {
                        let bj = bytes[j];
                        if (0x40..=0x7E).contains(&bj) {
                            final_byte = Some((j, bj));
                            break;
                        }

                        if !((0x30..=0x3F).contains(&bj) || (0x20..=0x2F).contains(&bj)) {
                            break;
                        }
                        j += 1;
                    }

                    if let Some((end, fb)) = final_byte {
                        if fb == b'm' {
                            let params = &bytes[i + 2..end];
                            if is_safe_sgr_params(params) {
                                if let Ok(seq) = std::str::from_utf8(&bytes[i..=end]) {
                                    out.push_str(seq);
                                }
                            }
                        }
                        i = end + 1;
                        continue;
                    }

                    i += 1;
                    continue;
                }
                b']' => {
                    let mut j = i + 2;
                    while j < bytes.len() {
                        if bytes[j] == 0x07 {
                            j += 1;
                            break;
                        }
                        if bytes[j] == 0x1b && j + 1 < bytes.len() && bytes[j + 1] == b'\\' {
                            j += 2;
                            break;
                        }
                        j += 1;
                    }
                    i = j;
                    continue;
                }
                _ => {
                    i += 2;
                    continue;
                }
            }
        }

        let slice = &input[i..];
        let Some(ch) = slice.chars().next() else {
            break;
        };

        if matches!(ch, '\n' | '\t') {
            out.push(ch);
        } else if ch == '\r' {
            out.push('\n');
        } else if !ch.is_control() {
            out.push(ch);
        }

        i += ch.len_utf8();
    }

    out
}

fn is_safe_sgr_params(params: &[u8]) -> bool {
    if params.len() > 128 {
        return false;
    }

    params
        .iter()
        .all(|b| b.is_ascii_digit() || *b == b';' || *b == b':')
}

#[cfg(test)]
mod tests {
    use super::*;
    use safepipe_spec::{InputOptions, OutputOptions};

    fn spec_with_policy(policy: TerminalPolicy) -> PipelineSpec {
        PipelineSpec {
            input: InputOptions {
                encoding: InputEncoding::BytesLossy,
            },
            output: OutputOptions {
                terminal_policy: policy,
                newline: NewlineMode::Preserve,
            },
            ..PipelineSpec::default()
        }
    }

    #[test]
    fn balanced_allows_sgr_but_blocks_clear_screen() {
        let input = b"\x1b[31mred\x1b[0m \x1b[2Jboom";
        let out = run_pipeline(
            input,
            &spec_with_policy(TerminalPolicy::Balanced),
            &EngineLimits::default(),
        )
        .expect("pipeline should succeed");
        assert_eq!(out, "\x1b[31mred\x1b[0m boom");
    }

    #[test]
    fn balanced_blocks_osc_sequences() {
        let input = b"\x1b]8;;https://evil.example\x07click\x1b]8;;\x07";
        let out = run_pipeline(
            input,
            &spec_with_policy(TerminalPolicy::Balanced),
            &EngineLimits::default(),
        )
        .expect("pipeline should succeed");
        assert_eq!(out, "click");
    }

    #[test]
    fn strict_printable_escapes_controls() {
        let input = b"a\x1bb\x07c";
        let out = run_pipeline(
            input,
            &spec_with_policy(TerminalPolicy::StrictPrintable),
            &EngineLimits::default(),
        )
        .expect("pipeline should succeed");
        assert_eq!(out, "a\\u{1b}b\\u{7}c");
    }

    #[test]
    fn enforces_output_byte_limits() {
        let mut spec = spec_with_policy(TerminalPolicy::Raw);
        spec.ops.push(Op::ReplaceLiteral {
            from: "a".to_string(),
            to: "aaaa".to_string(),
            max_replacements: None,
        });
        let limits = EngineLimits {
            max_output_bytes: 4,
            max_lines: 10,
            timeout: None,
        };

        let result = run_pipeline(b"aa", &spec, &limits);
        assert!(matches!(result, Err(EngineError::LimitExceeded(_))));
    }

    #[test]
    fn lossy_mode_handles_arbitrary_bytes_without_panicking() {
        let spec = spec_with_policy(TerminalPolicy::Balanced);
        let limits = EngineLimits::default();

        for byte in 0u8..=255 {
            let input = vec![byte; 64];
            let result = run_pipeline(&input, &spec, &limits);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn select_columns_whitespace_behaves_like_safe_awk_fields() {
        let mut spec = spec_with_policy(TerminalPolicy::Raw);
        spec.ops.push(Op::SelectColumns {
            delimiter: "whitespace".to_string(),
            fields: vec![1, 3],
            output_delimiter: Some("|".to_string()),
            skip_missing: true,
        });

        let out = run_pipeline(
            b"alice 10 dev\nbob 20 ops\n",
            &spec,
            &EngineLimits::default(),
        )
        .expect("pipeline should succeed");
        assert_eq!(out, "alice|dev\nbob|ops\n");
    }

    #[test]
    fn filter_contains_and_filter_regex_chain() {
        let mut spec = spec_with_policy(TerminalPolicy::Raw);
        spec.ops.push(Op::FilterContains {
            needle: "ERROR".to_string(),
            invert: false,
        });
        spec.ops.push(Op::FilterRegex {
            pattern: r"timeout|quota".to_string(),
            invert: false,
        });

        let out = run_pipeline(
            b"INFO startup\nERROR timeout reached\nERROR bad password\nERROR quota exceeded\n",
            &spec,
            &EngineLimits::default(),
        )
        .expect("pipeline should succeed");
        assert_eq!(out, "ERROR timeout reached\nERROR quota exceeded\n");
    }
}
