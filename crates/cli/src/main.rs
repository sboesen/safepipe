use clap::{Parser, Subcommand, ValueEnum};
use safepipe_core::{run_pipeline, EngineError, EngineLimits};
use safepipe_spec::{
    parse_spec_from_str, validate_spec, ExtractMode, Op, PipelineSpec, QuoteStyle, RedactPattern,
    TableAlign, TableDelimiter, TerminalPolicy, TrimMode, UnicodeForm,
};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(name = "safepipe")]
#[command(about = "Deterministic safe text shaping for local pipelines")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Run(RunCommand),
    Validate(ValidateCommand),
    Explain(ExplainCommand),
}

#[derive(Debug, Parser)]
struct RunCommand {
    #[arg(long, help = "Spec JSON string or @path/to/spec.json")]
    spec: Option<String>,

    #[arg(long = "op", help = "Mini op expression, can be repeated")]
    ops: Vec<String>,

    #[arg(long, default_value_t = 8 * 1024 * 1024, help = "Maximum input bytes to read from stdin")]
    max_bytes: usize,

    #[arg(long, default_value_t = 8 * 1024 * 1024, help = "Maximum output bytes after transforms")]
    max_output_bytes: usize,

    #[arg(long, default_value_t = 200_000, help = "Maximum output line count")]
    max_lines: usize,

    #[arg(long, help = "Optional timeout in milliseconds")]
    timeout_ms: Option<u64>,

    #[arg(long, value_enum, help = "Output terminal policy override")]
    terminal_policy: Option<TerminalPolicyArg>,

    #[arg(long, help = "No-op compatibility flag; balanced policy is default")]
    allow_style: bool,
}

#[derive(Debug, Parser)]
struct ValidateCommand {
    #[arg(long, help = "Spec JSON string or @path/to/spec.json")]
    spec: String,
}

#[derive(Debug, Parser)]
struct ExplainCommand {
    #[arg(long, help = "Spec JSON string or @path/to/spec.json")]
    spec: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
enum TerminalPolicyArg {
    Balanced,
    StrictPrintable,
    Raw,
}

impl From<TerminalPolicyArg> for TerminalPolicy {
    fn from(value: TerminalPolicyArg) -> Self {
        match value {
            TerminalPolicyArg::Balanced => TerminalPolicy::Balanced,
            TerminalPolicyArg::StrictPrintable => TerminalPolicy::StrictPrintable,
            TerminalPolicyArg::Raw => TerminalPolicy::Raw,
        }
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("spec error: {0}")]
    Spec(String),
    #[error("operation parse error: {0}")]
    OpParse(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("pipeline error: {0}")]
    Engine(#[from] EngineError),
    #[error("limit exceeded: {0}")]
    Limit(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl CliError {
    fn exit_code(&self) -> i32 {
        match self {
            CliError::Spec(_) | CliError::OpParse(_) => 2,
            CliError::Limit(_) => 3,
            CliError::Engine(EngineError::LimitExceeded(_))
            | CliError::Engine(EngineError::Timeout) => 3,
            CliError::Io(_) | CliError::Engine(_) | CliError::Internal(_) => 4,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let result = dispatch(cli);
    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(err.exit_code());
    }
}

fn dispatch(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Commands::Run(cmd) => run_command(cmd),
        Commands::Validate(cmd) => validate_command(cmd),
        Commands::Explain(cmd) => explain_command(cmd),
    }
}

fn run_command(cmd: RunCommand) -> Result<(), CliError> {
    let mut spec = load_base_spec(cmd.spec.as_deref())?;

    for op_expr in &cmd.ops {
        spec.ops.push(parse_op_expr(op_expr)?);
    }

    if let Some(policy) = cmd.terminal_policy {
        spec.output.terminal_policy = policy.into();
    }

    if cmd.allow_style && matches!(spec.output.terminal_policy, TerminalPolicy::StrictPrintable) {
        // User explicitly requested strict_printable; do not override.
    }

    validate_spec(&spec).map_err(|e| CliError::Spec(e.to_string()))?;

    let input = read_stdin_limited(cmd.max_bytes)?;

    let limits = EngineLimits {
        max_output_bytes: cmd.max_output_bytes,
        max_lines: cmd.max_lines,
        timeout: cmd.timeout_ms.map(Duration::from_millis),
    };

    let out = run_pipeline(&input, &spec, &limits)?;

    let mut stdout = io::stdout().lock();
    stdout.write_all(out.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

fn validate_command(cmd: ValidateCommand) -> Result<(), CliError> {
    let spec = load_spec_arg(&cmd.spec)?;
    parse_spec_from_str(&spec).map_err(|e| CliError::Spec(e.to_string()))?;

    println!("valid");
    Ok(())
}

fn explain_command(cmd: ExplainCommand) -> Result<(), CliError> {
    let spec_raw = load_spec_arg(&cmd.spec)?;
    let spec = parse_spec_from_str(&spec_raw).map_err(|e| CliError::Spec(e.to_string()))?;

    let normalized =
        serde_json::to_string_pretty(&spec).map_err(|e| CliError::Internal(e.to_string()))?;
    println!("{normalized}");
    Ok(())
}

fn load_base_spec(spec_arg: Option<&str>) -> Result<PipelineSpec, CliError> {
    match spec_arg {
        Some(raw) => {
            let spec_json = load_spec_arg(raw)?;
            parse_spec_from_str(&spec_json).map_err(|e| CliError::Spec(e.to_string()))
        }
        None => Ok(PipelineSpec::default()),
    }
}

fn load_spec_arg(spec_arg: &str) -> Result<String, CliError> {
    if let Some(path) = spec_arg.strip_prefix('@') {
        fs::read_to_string(path).map_err(CliError::from)
    } else {
        Ok(spec_arg.to_string())
    }
}

fn read_stdin_limited(max_bytes: usize) -> Result<Vec<u8>, CliError> {
    let mut stdin = io::stdin().lock();
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        let read = stdin.read(&mut chunk)?;
        if read == 0 {
            break;
        }

        if out.len() + read > max_bytes {
            return Err(CliError::Limit(format!(
                "stdin exceeded --max-bytes limit ({} bytes)",
                max_bytes
            )));
        }

        out.extend_from_slice(&chunk[..read]);
    }

    Ok(out)
}

fn parse_op_expr(expr: &str) -> Result<Op, CliError> {
    let (name_raw, args_raw) = expr.split_once(':').unwrap_or((expr, ""));
    let name = normalize_key(name_raw);
    let (kv, positional) = parse_args(args_raw);

    match name.as_str() {
        "normalize" | "normalize_unicode" => {
            let form =
                get_value(&kv, &positional, &["form"], 0).unwrap_or_else(|| "nfc".to_string());
            let form = parse_unicode_form(&form)?;
            Ok(Op::NormalizeUnicode { form })
        }
        "trim" => {
            let mode =
                get_value(&kv, &positional, &["mode"], 0).unwrap_or_else(|| "both".to_string());
            Ok(Op::Trim {
                mode: parse_trim_mode(&mode)?,
            })
        }
        "collapse" | "collapse_whitespace" => {
            let preserve = get_value(&kv, &positional, &["preserve_newlines", "preserve"], 0)
                .map(|v| parse_bool(&v))
                .transpose()?
                .unwrap_or(false);
            Ok(Op::CollapseWhitespace {
                preserve_newlines: preserve,
            })
        }
        "wrap" => {
            let width = get_value(&kv, &positional, &["width"], 0).ok_or_else(|| {
                CliError::OpParse("wrap requires width (e.g. wrap:width=80)".to_string())
            })?;
            let width = parse_u16(&width, "wrap.width")?;
            let break_long_words =
                get_value(&kv, &positional, &["break_long_words", "break_long"], 1)
                    .map(|v| parse_bool(&v))
                    .transpose()?
                    .unwrap_or(false);
            Ok(Op::Wrap {
                width,
                break_long_words,
            })
        }
        "truncate" => {
            let max_chars = get_value(&kv, &positional, &["max_chars", "max", "len"], 0)
                .ok_or_else(|| CliError::OpParse("truncate requires max_chars".to_string()))?;
            let ellipsis =
                get_value(&kv, &positional, &["ellipsis"], 1).unwrap_or_else(|| "...".to_string());
            Ok(Op::Truncate {
                max_chars: parse_u32(&max_chars, "truncate.max_chars")?,
                ellipsis,
            })
        }
        "extract" | "extract_between" => {
            let start = get_value(&kv, &positional, &["start"], 0)
                .ok_or_else(|| CliError::OpParse("extract_between requires start".to_string()))?;
            let end = get_value(&kv, &positional, &["end"], 1)
                .ok_or_else(|| CliError::OpParse("extract_between requires end".to_string()))?;
            let mode =
                get_value(&kv, &positional, &["mode"], 2).unwrap_or_else(|| "first".to_string());
            Ok(Op::ExtractBetween {
                start,
                end,
                mode: parse_extract_mode(&mode)?,
            })
        }
        "replace" | "replace_literal" => {
            let from = get_value(&kv, &positional, &["from"], 0)
                .ok_or_else(|| CliError::OpParse("replace_literal requires from".to_string()))?;
            let to = get_value(&kv, &positional, &["to"], 1)
                .ok_or_else(|| CliError::OpParse("replace_literal requires to".to_string()))?;
            let max_replacements = get_value(&kv, &positional, &["max_replacements", "max"], 2)
                .map(|v| parse_u32(&v, "replace_literal.max_replacements"))
                .transpose()?;
            Ok(Op::ReplaceLiteral {
                from,
                to,
                max_replacements,
            })
        }
        "regex" | "regex_replace" => {
            let pattern = get_value(&kv, &positional, &["pattern"], 0)
                .ok_or_else(|| CliError::OpParse("regex_replace requires pattern".to_string()))?;
            let to = get_value(&kv, &positional, &["to"], 1)
                .ok_or_else(|| CliError::OpParse("regex_replace requires to".to_string()))?;
            let max_replacements = get_value(&kv, &positional, &["max_replacements", "max"], 2)
                .map(|v| parse_u32(&v, "regex_replace.max_replacements"))
                .transpose()?;
            Ok(Op::RegexReplace {
                pattern,
                to,
                max_replacements,
            })
        }
        "redact" => {
            let replacement = get_value(&kv, &positional, &["replacement"], usize::MAX)
                .unwrap_or_else(|| "[REDACTED]".to_string());

            let patterns = if let Some(raw) = kv.get("patterns") {
                parse_redact_patterns(raw)?
            } else {
                let mut parsed = Vec::new();
                for token in &positional {
                    let lowered = normalize_key(token);
                    if lowered == "replacement" || lowered.starts_with("replacement=") {
                        continue;
                    }
                    if let Ok(p) = parse_redact_pattern(token) {
                        parsed.push(p);
                    }
                }
                if parsed.is_empty() {
                    vec![RedactPattern::Email]
                } else {
                    parsed
                }
            };

            Ok(Op::Redact {
                patterns,
                replacement,
            })
        }
        "quote" => {
            let style =
                get_value(&kv, &positional, &["style"], 0).unwrap_or_else(|| "json".to_string());
            Ok(Op::Quote {
                style: parse_quote_style(&style)?,
            })
        }
        "table" => {
            let delimiter = get_value(&kv, &positional, &["delimiter"], 0)
                .unwrap_or_else(|| "comma".to_string());
            let align =
                get_value(&kv, &positional, &["align"], 1).unwrap_or_else(|| "left".to_string());
            Ok(Op::Table {
                delimiter: parse_table_delimiter(&delimiter)?,
                align: parse_table_align(&align)?,
            })
        }
        "sort" | "sort_lines" => {
            let mut unique = false;
            let mut numeric = false;
            let mut reverse = false;

            for token in &positional {
                match normalize_key(token).as_str() {
                    "unique" => unique = true,
                    "numeric" => numeric = true,
                    "reverse" | "desc" => reverse = true,
                    _ => {}
                }
            }

            if let Some(raw) = kv.get("unique") {
                unique = parse_bool(raw)?;
            }
            if let Some(raw) = kv.get("numeric") {
                numeric = parse_bool(raw)?;
            }
            if let Some(raw) = kv.get("reverse") {
                reverse = parse_bool(raw)?;
            }

            Ok(Op::SortLines {
                unique,
                numeric,
                reverse,
            })
        }
        _ => Err(CliError::OpParse(format!("unknown op '{name_raw}'"))),
    }
}

fn parse_args(raw: &str) -> (HashMap<String, String>, Vec<String>) {
    if raw.trim().is_empty() {
        return (HashMap::new(), Vec::new());
    }

    let mut kv = HashMap::new();
    let mut positional = Vec::new();

    for token in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if let Some((k, v)) = token.split_once('=') {
            kv.insert(normalize_key(k), v.trim().to_string());
        } else {
            positional.push(token.to_string());
        }
    }

    (kv, positional)
}

fn normalize_key(input: &str) -> String {
    input.trim().to_ascii_lowercase().replace('-', "_")
}

fn get_value(
    kv: &HashMap<String, String>,
    positional: &[String],
    keys: &[&str],
    pos_idx: usize,
) -> Option<String> {
    for key in keys {
        if let Some(value) = kv.get(&normalize_key(key)) {
            return Some(value.clone());
        }
    }

    if pos_idx == usize::MAX {
        return None;
    }

    positional.get(pos_idx).cloned()
}

fn parse_bool(raw: &str) -> Result<bool, CliError> {
    match normalize_key(raw).as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(CliError::OpParse(format!("invalid boolean '{raw}'"))),
    }
}

fn parse_u16(raw: &str, field: &str) -> Result<u16, CliError> {
    raw.parse::<u16>()
        .map_err(|_| CliError::OpParse(format!("invalid {field}: '{raw}'")))
}

fn parse_u32(raw: &str, field: &str) -> Result<u32, CliError> {
    raw.parse::<u32>()
        .map_err(|_| CliError::OpParse(format!("invalid {field}: '{raw}'")))
}

fn parse_trim_mode(raw: &str) -> Result<TrimMode, CliError> {
    match normalize_key(raw).as_str() {
        "left" => Ok(TrimMode::Left),
        "right" => Ok(TrimMode::Right),
        "both" => Ok(TrimMode::Both),
        _ => Err(CliError::OpParse(format!("invalid trim mode '{raw}'"))),
    }
}

fn parse_unicode_form(raw: &str) -> Result<UnicodeForm, CliError> {
    match normalize_key(raw).as_str() {
        "nfc" => Ok(UnicodeForm::Nfc),
        "nfkc" => Ok(UnicodeForm::Nfkc),
        _ => Err(CliError::OpParse(format!("invalid unicode form '{raw}'"))),
    }
}

fn parse_extract_mode(raw: &str) -> Result<ExtractMode, CliError> {
    match normalize_key(raw).as_str() {
        "first" => Ok(ExtractMode::First),
        "all" => Ok(ExtractMode::All),
        _ => Err(CliError::OpParse(format!("invalid extract mode '{raw}'"))),
    }
}

fn parse_quote_style(raw: &str) -> Result<QuoteStyle, CliError> {
    match normalize_key(raw).as_str() {
        "json" => Ok(QuoteStyle::Json),
        "shell_single" | "shell" => Ok(QuoteStyle::ShellSingle),
        "markdown_code" | "markdown" => Ok(QuoteStyle::MarkdownCode),
        _ => Err(CliError::OpParse(format!("invalid quote style '{raw}'"))),
    }
}

fn parse_table_delimiter(raw: &str) -> Result<TableDelimiter, CliError> {
    match normalize_key(raw).as_str() {
        "comma" | "," => Ok(TableDelimiter::Comma),
        "tab" | "\\t" => Ok(TableDelimiter::Tab),
        "pipe" | "|" => Ok(TableDelimiter::Pipe),
        _ => Err(CliError::OpParse(format!(
            "invalid table delimiter '{raw}'"
        ))),
    }
}

fn parse_table_align(raw: &str) -> Result<TableAlign, CliError> {
    match normalize_key(raw).as_str() {
        "left" => Ok(TableAlign::Left),
        "right" => Ok(TableAlign::Right),
        "center" => Ok(TableAlign::Center),
        _ => Err(CliError::OpParse(format!("invalid table align '{raw}'"))),
    }
}

fn parse_redact_pattern(raw: &str) -> Result<RedactPattern, CliError> {
    match normalize_key(raw).as_str() {
        "email" => Ok(RedactPattern::Email),
        "ipv4" => Ok(RedactPattern::Ipv4),
        "api_key_like" | "apikey" | "key" | "token" => Ok(RedactPattern::ApiKeyLike),
        "url" => Ok(RedactPattern::Url),
        _ => Err(CliError::OpParse(format!("invalid redact pattern '{raw}'"))),
    }
}

fn parse_redact_patterns(raw: &str) -> Result<Vec<RedactPattern>, CliError> {
    let parsed: Result<Vec<_>, _> = raw
        .split('|')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_redact_pattern)
        .collect();

    let patterns = parsed?;
    if patterns.is_empty() {
        return Err(CliError::OpParse(
            "redact patterns list cannot be empty".to_string(),
        ));
    }

    Ok(patterns)
}
