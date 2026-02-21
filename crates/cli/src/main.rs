mod template_dsl;

use chrono::Local;
use clap::{Parser, Subcommand, ValueEnum};
use safepipe_core::{run_pipeline, EngineError, EngineLimits};
use safepipe_spec::{
    parse_spec_from_str, validate_spec, ExtractMode, InputEncoding, InputOptions, NewlineMode, Op,
    OutputOptions, PipelineSpec, QuoteStyle, RedactPattern, TableAlign, TableDelimiter,
    TerminalPolicy, TrimMode, UnicodeForm,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use template_dsl::SourceKind;
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
    Template(TemplateCommand),
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

    #[arg(
        long,
        value_enum,
        default_value_t = TerminalPolicyArg::Balanced,
        help = "Caller-selected terminal policy (spec value is ignored)"
    )]
    terminal_policy: TerminalPolicyArg,

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

#[derive(Debug, Parser)]
struct TemplateCommand {
    #[command(subcommand)]
    command: TemplateSubcommand,
}

#[derive(Debug, Subcommand)]
enum TemplateSubcommand {
    Run(TemplateRunCommand),
    Install(TemplateInstallCommand),
    List,
    Show(TemplateShowCommand),
}

#[derive(Debug, Parser)]
struct TemplateRunCommand {
    #[arg(long, help = "Template source: local path, URL, or @installed-name")]
    template: String,

    #[arg(
        long,
        default_value = ".",
        help = "Root directory for template file() reads"
    )]
    root: PathBuf,

    #[arg(long, default_value_t = 8 * 1024 * 1024, help = "Maximum bytes for each source read")]
    max_source_bytes: usize,

    #[arg(long, default_value_t = 128 * 1024, help = "Maximum template bytes to load")]
    max_template_bytes: usize,

    #[arg(long, default_value_t = 8 * 1024 * 1024, help = "Maximum output bytes after rendering")]
    max_output_bytes: usize,

    #[arg(long, default_value_t = 200_000, help = "Maximum output line count")]
    max_lines: usize,

    #[arg(long, help = "Optional timeout in milliseconds")]
    timeout_ms: Option<u64>,

    #[arg(
        long,
        value_enum,
        help = "Terminal safety policy (required for untrusted templates)"
    )]
    terminal_policy: TerminalPolicyArg,

    #[arg(
        long,
        value_enum,
        default_value_t = NewlineModeArg::Preserve,
        help = "Newline mode applied after render"
    )]
    newline: NewlineModeArg,

    #[arg(
        long,
        help = "Optional SHA-256 hex digest for template bytes (64 hex chars)"
    )]
    template_sha256: Option<String>,

    #[arg(long, help = "Allow HTTP template URLs (HTTPS is default/required)")]
    allow_insecure_http: bool,

    #[arg(
        long,
        help = "Allow template URL hosts that resolve to private/localhost IPs"
    )]
    allow_private_hosts: bool,

    #[arg(
        long = "allow-read",
        help = "Limit template file() reads to these root-relative paths (repeatable)"
    )]
    allow_read: Vec<String>,
}

#[derive(Debug, Parser)]
struct TemplateInstallCommand {
    #[arg(long, help = "Installed template name")]
    name: String,

    #[arg(long, help = "Template source: local path or URL")]
    from: String,

    #[arg(long, default_value_t = 128 * 1024, help = "Maximum template bytes to load")]
    max_template_bytes: usize,

    #[arg(
        long,
        help = "Optional SHA-256 hex digest for template bytes (64 hex chars)"
    )]
    template_sha256: Option<String>,

    #[arg(long, help = "Allow HTTP template URLs (HTTPS is default/required)")]
    allow_insecure_http: bool,

    #[arg(
        long,
        help = "Allow template URL hosts that resolve to private/localhost IPs"
    )]
    allow_private_hosts: bool,
}

#[derive(Debug, Parser)]
struct TemplateShowCommand {
    #[arg(long, help = "Installed template name")]
    name: String,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
enum NewlineModeArg {
    Preserve,
    EnsureTrailing,
}

#[derive(Debug, Clone, Default)]
struct TemplateFetchPolicy {
    allow_insecure_http: bool,
    allow_private_hosts: bool,
    expected_sha256: Option<String>,
}

#[derive(Debug, Clone)]
struct TemplateReadPolicy {
    allowed_paths: Vec<PathBuf>,
}

impl TemplateReadPolicy {
    fn new(allowed_paths: Vec<PathBuf>) -> Self {
        Self { allowed_paths }
    }

    fn allows(&self, path: &Path) -> bool {
        if self.allowed_paths.is_empty() {
            return true;
        }

        self.allowed_paths
            .iter()
            .any(|allowed| path == allowed || path.starts_with(allowed))
    }
}

impl From<NewlineModeArg> for NewlineMode {
    fn from(value: NewlineModeArg) -> Self {
        match value {
            NewlineModeArg::Preserve => NewlineMode::Preserve,
            NewlineModeArg::EnsureTrailing => NewlineMode::EnsureTrailing,
        }
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("spec error: {0}")]
    Spec(String),
    #[error("template error: {0}")]
    Template(String),
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
            CliError::Spec(_) | CliError::Template(_) | CliError::OpParse(_) => 2,
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
        Commands::Template(cmd) => template_command(cmd),
    }
}

fn run_command(cmd: RunCommand) -> Result<(), CliError> {
    let mut spec = load_base_spec(cmd.spec.as_deref())?;

    for op_expr in &cmd.ops {
        spec.ops.push(parse_op_expr(op_expr)?);
    }

    // Runtime safety comes from CLI flags, not untrusted spec text.
    spec.output.terminal_policy = cmd.terminal_policy.into();

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

fn template_command(cmd: TemplateCommand) -> Result<(), CliError> {
    match cmd.command {
        TemplateSubcommand::Run(run) => template_run_command(run),
        TemplateSubcommand::Install(install) => template_install_command(install),
        TemplateSubcommand::List => template_list_command(),
        TemplateSubcommand::Show(show) => template_show_command(show),
    }
}

fn template_run_command(cmd: TemplateRunCommand) -> Result<(), CliError> {
    let fetch_policy = build_template_fetch_policy(
        cmd.allow_insecure_http,
        cmd.allow_private_hosts,
        cmd.template_sha256.as_deref(),
    )?;
    let template_text = load_template_source(&cmd.template, cmd.max_template_bytes, &fetch_policy)?;
    let script = template_dsl::parse_template(&template_text).map_err(CliError::Template)?;

    let root = cmd.root.canonicalize().map_err(|e| {
        CliError::Template(format!(
            "failed to resolve root '{}': {e}",
            cmd.root.display()
        ))
    })?;
    if !root.is_dir() {
        return Err(CliError::Template(format!(
            "root path '{}' is not a directory",
            root.display()
        )));
    }

    if template_source_requires_explicit_allow_read(&cmd.template)
        && script
            .sources
            .iter()
            .any(|source| matches!(source.kind, SourceKind::File(_)))
        && cmd.allow_read.is_empty()
    {
        return Err(CliError::Template(
            "templates from URL or @installed source using file() require explicit --allow-read entries".to_string(),
        ));
    }

    let read_policy = build_template_read_policy(&root, &cmd.allow_read)?;

    let stdin_data = if script.has_stdin_source() {
        Some(read_stdin_limited(cmd.max_source_bytes)?)
    } else {
        None
    };

    let limits = EngineLimits {
        max_output_bytes: cmd.max_output_bytes,
        max_lines: cmd.max_lines,
        timeout: cmd.timeout_ms.map(Duration::from_millis),
    };

    let mut vars = HashMap::new();
    for source in &script.sources {
        let raw = load_source_bytes(
            source,
            &root,
            &read_policy,
            stdin_data.as_deref(),
            cmd.max_source_bytes,
        )?;
        let mut ops = Vec::with_capacity(source.ops.len());
        for op_expr in &source.ops {
            ops.push(parse_op_expr(op_expr)?);
        }

        let source_spec = PipelineSpec {
            input: InputOptions {
                encoding: InputEncoding::BytesLossy,
            },
            ops,
            output: OutputOptions {
                terminal_policy: TerminalPolicy::Raw,
                newline: NewlineMode::Preserve,
            },
            ..PipelineSpec::default()
        };

        let transformed = run_pipeline(&raw, &source_spec, &limits)?;
        vars.insert(source.name.clone(), transformed);
    }

    let rendered = template_dsl::render_body(&script.body, &vars).map_err(CliError::Template)?;
    let final_output = render_template_output(
        rendered.as_bytes(),
        cmd.terminal_policy.into(),
        cmd.newline.into(),
        &limits,
    )?;

    let mut stdout = io::stdout().lock();
    stdout.write_all(final_output.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

fn render_template_output(
    rendered: &[u8],
    terminal_policy: TerminalPolicy,
    newline: NewlineMode,
    limits: &EngineLimits,
) -> Result<String, CliError> {
    let final_spec = PipelineSpec {
        input: InputOptions {
            encoding: InputEncoding::BytesLossy,
        },
        output: OutputOptions {
            terminal_policy,
            newline,
        },
        ..PipelineSpec::default()
    };

    run_pipeline(rendered, &final_spec, limits).map_err(CliError::from)
}

fn load_source_bytes(
    source: &template_dsl::SourceDecl,
    root: &Path,
    read_policy: &TemplateReadPolicy,
    stdin_data: Option<&[u8]>,
    max_source_bytes: usize,
) -> Result<Vec<u8>, CliError> {
    match &source.kind {
        SourceKind::File(path) => {
            let (mut file, resolved) = open_safe_template_file(root, read_policy, path)?;
            read_to_end_limited(
                &mut file,
                max_source_bytes,
                &format!("file '{}'", resolved.display()),
            )
        }
        SourceKind::Stdin => Ok(stdin_data.unwrap_or_default().to_vec()),
        SourceKind::Now(format) => Ok(Local::now().format(format).to_string().into_bytes()),
        SourceKind::Literal(value) => Ok(value.as_bytes().to_vec()),
    }
}

fn template_install_command(cmd: TemplateInstallCommand) -> Result<(), CliError> {
    validate_template_name(&cmd.name)?;
    if cmd.from.starts_with('@') {
        return Err(CliError::Template(
            "install source must be a local path or URL, not @installed-name".to_string(),
        ));
    }

    let fetch_policy = build_template_fetch_policy(
        cmd.allow_insecure_http,
        cmd.allow_private_hosts,
        cmd.template_sha256.as_deref(),
    )?;
    let template_text = load_template_source(&cmd.from, cmd.max_template_bytes, &fetch_policy)?;
    template_dsl::parse_template(&template_text).map_err(CliError::Template)?;

    let dir = templates_dir()?;
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.spt", cmd.name));
    fs::write(&path, template_text)?;
    println!("installed {}", path.display());
    Ok(())
}

fn template_list_command() -> Result<(), CliError> {
    let dir = templates_dir()?;
    if !dir.exists() {
        return Ok(());
    }

    let mut names = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("spt") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            names.push(stem.to_string());
        }
    }

    names.sort();
    for name in names {
        println!("{name}");
    }
    Ok(())
}

fn template_show_command(cmd: TemplateShowCommand) -> Result<(), CliError> {
    validate_template_name(&cmd.name)?;
    let content = load_installed_template(&cmd.name)?;
    println!("{content}");
    Ok(())
}

fn build_template_fetch_policy(
    allow_insecure_http: bool,
    allow_private_hosts: bool,
    template_sha256: Option<&str>,
) -> Result<TemplateFetchPolicy, CliError> {
    let expected_sha256 = template_sha256.map(parse_sha256_hex).transpose()?;
    Ok(TemplateFetchPolicy {
        allow_insecure_http,
        allow_private_hosts,
        expected_sha256,
    })
}

fn parse_sha256_hex(raw: &str) -> Result<String, CliError> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::Template(
            "template SHA-256 must be exactly 64 hexadecimal characters".to_string(),
        ));
    }
    Ok(normalized)
}

fn verify_template_sha256(
    template_bytes: &[u8],
    source: &str,
    expected_sha256: Option<&str>,
) -> Result<(), CliError> {
    let Some(expected) = expected_sha256 else {
        return Ok(());
    };

    let digest = Sha256::digest(template_bytes);
    let mut actual = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut actual, "{byte:02x}")
            .map_err(|e| CliError::Internal(format!("failed to render SHA-256 digest: {e}")))?;
    }

    if actual != expected {
        return Err(CliError::Template(format!(
            "template SHA-256 mismatch for '{source}' (expected {expected}, got {actual})"
        )));
    }

    Ok(())
}

fn load_template_source(
    source: &str,
    max_bytes: usize,
    fetch_policy: &TemplateFetchPolicy,
) -> Result<String, CliError> {
    let text = if let Some(name) = source.strip_prefix('@') {
        load_installed_template(name)?
    } else if is_remote_template_source(source) {
        fetch_url_text(source, max_bytes, fetch_policy)?
    } else {
        read_file_string_limited(Path::new(source), max_bytes)?
    };

    verify_template_sha256(
        text.as_bytes(),
        source,
        fetch_policy.expected_sha256.as_deref(),
    )?;
    Ok(text)
}

fn is_remote_template_source(source: &str) -> bool {
    source.starts_with("http://") || source.starts_with("https://")
}

fn template_source_requires_explicit_allow_read(source: &str) -> bool {
    is_remote_template_source(source) || source.starts_with('@')
}

fn read_file_string_limited(path: &Path, max_bytes: usize) -> Result<String, CliError> {
    let bytes = read_file_bytes_limited(path, max_bytes)?;
    String::from_utf8(bytes).map_err(|_| {
        CliError::Template(format!(
            "template file '{}' is not valid UTF-8",
            path.display()
        ))
    })
}

fn fetch_url_text(
    url: &str,
    max_bytes: usize,
    fetch_policy: &TemplateFetchPolicy,
) -> Result<String, CliError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| CliError::Template(format!("invalid template URL '{url}': {e}")))?;
    validate_template_url(&parsed, fetch_policy)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| CliError::Internal(format!("failed to build HTTP client: {e}")))?;

    let response = client
        .get(url)
        .send()
        .map_err(|e| CliError::Internal(format!("failed to fetch template URL: {e}")))?;
    if response.status().is_redirection() {
        return Err(CliError::Template(
            "template URL redirects are blocked; use a direct URL".to_string(),
        ));
    }
    let mut response = response
        .error_for_status()
        .map_err(|e| CliError::Internal(format!("failed to fetch template URL: {e}")))?;

    let bytes = read_to_end_limited(&mut response, max_bytes, "template response")?;
    String::from_utf8(bytes)
        .map_err(|_| CliError::Template(format!("template URL '{url}' returned non-UTF-8 content")))
}

fn validate_template_url(
    url: &reqwest::Url,
    fetch_policy: &TemplateFetchPolicy,
) -> Result<(), CliError> {
    match url.scheme() {
        "https" => {}
        "http" if fetch_policy.allow_insecure_http => {}
        "http" => {
            return Err(CliError::Template(
                "refusing insecure HTTP template URL; pass --allow-insecure-http to override"
                    .to_string(),
            ));
        }
        other => {
            return Err(CliError::Template(format!(
                "unsupported template URL scheme '{other}'; use https://"
            )));
        }
    }

    if fetch_policy.allow_private_hosts {
        return Ok(());
    }

    let host = url
        .host_str()
        .ok_or_else(|| CliError::Template("template URL is missing host".to_string()))?;

    if is_local_hostname(host) {
        return Err(CliError::Template(format!(
            "template URL host '{host}' is private/local; pass --allow-private-hosts to override"
        )));
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(ip) {
            return Err(CliError::Template(format!(
                "template URL IP '{ip}' is private/local; pass --allow-private-hosts to override"
            )));
        }
        return Ok(());
    }

    let Some(port) = url.port_or_known_default() else {
        return Ok(());
    };

    if let Ok(addrs) = (host, port).to_socket_addrs() {
        for addr in addrs {
            let ip = addr.ip();
            if is_private_ip(ip) {
                return Err(CliError::Template(format!(
                    "template URL host '{host}' resolved to private/local IP '{ip}'; pass --allow-private-hosts to override"
                )));
            }
        }
    }

    Ok(())
}

fn is_local_hostname(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host.eq_ignore_ascii_case("local")
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

fn templates_dir() -> Result<PathBuf, CliError> {
    let home = dirs::home_dir()
        .ok_or_else(|| CliError::Internal("could not resolve home directory".to_string()))?;
    Ok(home.join(".safepipe").join("templates"))
}

fn load_installed_template(name: &str) -> Result<String, CliError> {
    validate_template_name(name)?;
    let path = templates_dir()?.join(format!("{name}.spt"));
    fs::read_to_string(&path)
        .map_err(|e| CliError::Template(format!("failed to read installed template '{name}': {e}")))
}

fn validate_template_name(name: &str) -> Result<(), CliError> {
    if name.is_empty() {
        return Err(CliError::Template(
            "template name cannot be empty".to_string(),
        ));
    }

    let mut chars = name.chars();
    let first = chars.next().expect("checked non-empty");
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err(CliError::Template(format!(
            "invalid template name '{name}': must start with [A-Za-z_]"
        )));
    }

    if !chars.all(|c| c == '_' || c.is_ascii_alphanumeric() || c == '-') {
        return Err(CliError::Template(format!(
            "invalid template name '{name}': only [A-Za-z0-9_-] allowed"
        )));
    }

    Ok(())
}

fn build_template_read_policy(
    root: &Path,
    allow_read: &[String],
) -> Result<TemplateReadPolicy, CliError> {
    let mut allowed_paths = Vec::new();
    for raw in allow_read {
        let normalized = normalize_template_relative_path(raw, true)?;
        ensure_no_symlink_components(root, &normalized, "--allow-read path")?;
        let full = if normalized.as_os_str().is_empty() {
            root.to_path_buf()
        } else {
            root.join(normalized)
        };

        let canonical = full.canonicalize().map_err(|e| {
            CliError::Template(format!(
                "failed to resolve --allow-read path '{}': {e}",
                full.display()
            ))
        })?;
        if !canonical.starts_with(root) {
            return Err(CliError::Template(format!(
                "--allow-read path '{}' escapes root '{}'",
                canonical.display(),
                root.display()
            )));
        }
        allowed_paths.push(canonical);
    }
    Ok(TemplateReadPolicy::new(allowed_paths))
}

fn normalize_template_relative_path(
    raw: &str,
    allow_root_alias: bool,
) -> Result<PathBuf, CliError> {
    let rel = Path::new(raw);
    if rel.is_absolute() {
        return Err(CliError::Template(format!(
            "absolute paths are not allowed in template file access: '{}'",
            rel.display()
        )));
    }

    let mut normalized = PathBuf::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(CliError::Template(format!(
                    "parent path segments are not allowed in template file access: '{}'",
                    rel.display()
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(CliError::Template(format!(
                    "invalid template file path '{}'",
                    rel.display()
                )));
            }
        }
    }

    if !allow_root_alias && normalized.as_os_str().is_empty() {
        return Err(CliError::Template(
            "template file path cannot be empty".to_string(),
        ));
    }

    Ok(normalized)
}

fn open_safe_template_file(
    root: &Path,
    read_policy: &TemplateReadPolicy,
    relative: &str,
) -> Result<(fs::File, PathBuf), CliError> {
    let normalized = normalize_template_relative_path(relative, false)?;
    ensure_no_symlink_components(root, &normalized, "template file path")?;
    let full = root.join(&normalized);
    let canonical = full.canonicalize().map_err(|e| {
        CliError::Template(format!(
            "failed to resolve template file '{}': {e}",
            full.display()
        ))
    })?;

    if !canonical.starts_with(root) {
        return Err(CliError::Template(format!(
            "template file path '{}' escapes root '{}'",
            canonical.display(),
            root.display()
        )));
    }
    if !read_policy.allows(&canonical) {
        return Err(CliError::Template(format!(
            "template file '{}' is not allowed by --allow-read policy",
            canonical.display()
        )));
    }

    let file = open_file_read_only_no_symlink(&canonical)?;
    Ok((file, canonical))
}

fn ensure_no_symlink_components(root: &Path, relative: &Path, label: &str) -> Result<(), CliError> {
    if relative.as_os_str().is_empty() {
        return Ok(());
    }

    let mut cursor = root.to_path_buf();
    for component in relative.components() {
        if let Component::Normal(part) = component {
            cursor.push(part);
            let meta = fs::symlink_metadata(&cursor).map_err(|e| {
                CliError::Template(format!(
                    "failed to resolve {label} '{}': {e}",
                    cursor.display()
                ))
            })?;
            if meta.file_type().is_symlink() {
                return Err(CliError::Template(format!(
                    "{label} '{}' cannot include symlink components",
                    cursor.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_file_read_only_no_symlink(path: &Path) -> Result<fs::File, CliError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;

    // Best-effort race detection: ensure opened inode still matches current path target.
    let file_meta = file.metadata()?;
    let path_meta = fs::metadata(path)?;
    if file_meta.dev() != path_meta.dev() || file_meta.ino() != path_meta.ino() {
        return Err(CliError::Template(format!(
            "detected concurrent path swap while opening '{}'",
            path.display()
        )));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_file_read_only_no_symlink(path: &Path) -> Result<fs::File, CliError> {
    fs::File::open(path).map_err(CliError::from)
}

fn read_file_bytes_limited(path: &Path, max_bytes: usize) -> Result<Vec<u8>, CliError> {
    let mut file = fs::File::open(path)?;
    read_to_end_limited(&mut file, max_bytes, &format!("file '{}'", path.display()))
}

fn read_to_end_limited<R: Read>(
    reader: &mut R,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, CliError> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }

        if out.len() + read > max_bytes {
            return Err(CliError::Limit(format!(
                "{label} exceeded maximum of {max_bytes} bytes"
            )));
        }

        out.extend_from_slice(&chunk[..read]);
    }

    Ok(out)
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
        "select_columns" | "select_fields" | "awk_select" => {
            let fields_raw = get_value(&kv, &positional, &["fields"], 0).ok_or_else(|| {
                CliError::OpParse(
                    "select_columns requires fields (e.g. fields=1;3 or positional 1;3)"
                        .to_string(),
                )
            })?;
            let delimiter = get_value(&kv, &positional, &["delimiter", "delim"], 1)
                .unwrap_or_else(|| "whitespace".to_string());
            let output_delimiter = get_value(
                &kv,
                &positional,
                &["output_delimiter", "out_delimiter", "out"],
                2,
            );
            let skip_missing = get_value(&kv, &positional, &["skip_missing"], 3)
                .map(|v| parse_bool(&v))
                .transpose()?
                .unwrap_or(true);

            Ok(Op::SelectColumns {
                delimiter: parse_column_delimiter(&delimiter)?,
                fields: parse_fields_list(&fields_raw)?,
                output_delimiter,
                skip_missing,
            })
        }
        "filter_contains" => {
            let needle = get_value(&kv, &positional, &["needle"], 0).ok_or_else(|| {
                CliError::OpParse(
                    "filter_contains requires needle (e.g. filter_contains:needle=ERROR)"
                        .to_string(),
                )
            })?;
            let invert = get_value(&kv, &positional, &["invert"], 1)
                .map(|v| parse_bool(&v))
                .transpose()?
                .unwrap_or(false);
            Ok(Op::FilterContains { needle, invert })
        }
        "filter_regex" => {
            let pattern = get_value(&kv, &positional, &["pattern"], 0).ok_or_else(|| {
                CliError::OpParse(
                    "filter_regex requires pattern (e.g. filter_regex:pattern=timeout|quota)"
                        .to_string(),
                )
            })?;
            let invert = get_value(&kv, &positional, &["invert"], 1)
                .map(|v| parse_bool(&v))
                .transpose()?
                .unwrap_or(false);
            Ok(Op::FilterRegex { pattern, invert })
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

fn parse_fields_list(raw: &str) -> Result<Vec<u16>, CliError> {
    let fields: Result<Vec<_>, _> = raw
        .split(['|', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| parse_u16(s, "select_columns.fields"))
        .collect();
    let fields = fields?;
    if fields.is_empty() {
        return Err(CliError::OpParse(
            "select_columns.fields must include at least one field index".to_string(),
        ));
    }
    if fields.contains(&0) {
        return Err(CliError::OpParse(
            "select_columns fields are 1-based and must be >= 1".to_string(),
        ));
    }
    Ok(fields)
}

fn parse_column_delimiter(raw: &str) -> Result<String, CliError> {
    match normalize_key(raw).as_str() {
        "space" | "spaces" | "whitespace" => Ok("whitespace".to_string()),
        "tab" => Ok("\\t".to_string()),
        "" => Err(CliError::OpParse(
            "select_columns delimiter cannot be empty".to_string(),
        )),
        _ => Ok(raw.to_string()),
    }
}
