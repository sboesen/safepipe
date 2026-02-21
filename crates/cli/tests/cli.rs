use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn run_safepipe(args: &[&str], stdin: &[u8]) -> std::process::Output {
    run_safepipe_with(args, stdin, None, &[])
}

fn run_safepipe_with(
    args: &[&str],
    stdin: &[u8],
    cwd: Option<&Path>,
    envs: &[(&str, &str)],
) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_safepipe");
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }

    for (key, value) in envs {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().expect("failed to spawn safepipe");

    if !stdin.is_empty() {
        let mut handle = child.stdin.take().expect("stdin should be piped");
        handle
            .write_all(stdin)
            .expect("failed to write stdin to safepipe");
    }

    child
        .wait_with_output()
        .expect("failed to wait for safepipe")
}

#[test]
fn run_trim_operation() {
    let output = run_safepipe(&["run", "--op", "trim:both"], b"  hello  ");
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "hello");
}

#[test]
fn validate_spec_command() {
    let output = run_safepipe(
        &[
            "validate",
            "--spec",
            r#"{"version":"v1","ops":[{"op":"trim","mode":"both"}]}"#,
        ],
        b"",
    );
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "valid\n");
}

#[test]
fn balanced_mode_strips_dangerous_escape_sequences() {
    let output = run_safepipe(&["run"], b"\x1b[2Jsafe");
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "safe");
}

#[test]
fn untrusted_spec_cannot_force_raw_terminal_policy() {
    let output = run_safepipe(
        &[
            "run",
            "--spec",
            r#"{"version":"v1","output":{"terminal_policy":"raw"},"ops":[]}"#,
        ],
        b"\x1b[2Jsafe",
    );
    assert!(output.status.success());
    // run mode policy is CLI-owned; untrusted spec output policy is ignored.
    assert_eq!(String::from_utf8_lossy(&output.stdout), "safe");
}

#[test]
fn raw_policy_name_is_explicitly_dangerous() {
    let output = run_safepipe(&["run", "--terminal-policy", "raw"], b"safe");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("dangerously_allow_raw"));
}

#[test]
fn dangerously_allow_raw_policy_passes_escape_sequences() {
    let output = run_safepipe(
        &["run", "--terminal-policy", "dangerously_allow_raw"],
        b"\x1b[2Jsafe",
    );
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "\u{1b}[2Jsafe");
}

#[test]
fn template_run_reads_file_and_renders_body() {
    let dir = tempdir().expect("tempdir should be created");
    let template_path = dir.path().join("example.spt");
    let input_path = dir.path().join("profile.txt");

    std::fs::write(&input_path, "  Agent Smith  \n").expect("should write input file");
    std::fs::write(
        &template_path,
        r#"
template v1
source profile = file("profile.txt") | trim:both
emit """
Hello {{profile}}
"""
"#,
    )
    .expect("should write template file");

    let output = run_safepipe_with(
        &[
            "template",
            "run",
            "--template",
            template_path.to_str().expect("valid path"),
            "--root",
            dir.path().to_str().expect("valid path"),
            "--terminal-policy",
            "strict_printable",
        ],
        b"",
        Some(dir.path()),
        &[],
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "Hello Agent Smith");
}

#[test]
fn template_install_and_show_round_trip() {
    let home = tempdir().expect("temp home should be created");
    let work = tempdir().expect("temp work dir should be created");
    let source_template = work.path().join("source.spt");

    std::fs::write(
        &source_template,
        r#"
template v1
source name = literal("agent")
emit """
{{name}}
"""
"#,
    )
    .expect("should write source template");

    let home_path = home.path().to_str().expect("valid home path");
    let source_path = source_template.to_str().expect("valid source path");

    let install = run_safepipe_with(
        &[
            "template",
            "install",
            "--name",
            "demo",
            "--from",
            source_path,
        ],
        b"",
        Some(work.path()),
        &[("HOME", home_path)],
    );
    assert!(
        install.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&install.stderr)
    );

    let show = run_safepipe_with(
        &["template", "show", "--name", "demo"],
        b"",
        Some(work.path()),
        &[("HOME", home_path)],
    );
    assert!(
        show.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&show.stderr)
    );
    let shown = String::from_utf8_lossy(&show.stdout);
    assert!(shown.contains("source name = literal(\"agent\")"));
}

#[test]
fn template_rejects_set_directive() {
    let dir = tempdir().expect("tempdir should be created");
    let template_path = dir.path().join("bad.spt");
    std::fs::write(
        &template_path,
        r#"
template v1
set terminal_policy = raw
emit """
hello
"""
"#,
    )
    .expect("should write bad template");

    let output = run_safepipe_with(
        &[
            "template",
            "run",
            "--template",
            template_path.to_str().expect("valid path"),
            "--root",
            dir.path().to_str().expect("valid path"),
            "--terminal-policy",
            "strict_printable",
        ],
        b"",
        Some(dir.path()),
        &[],
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("set directives are not allowed"));
}

#[test]
fn safe_awk_like_select_and_filter_ops_work() {
    let output = run_safepipe(
        &[
            "run",
            "--op",
            "select_columns:fields=1|3,delimiter=whitespace,output_delimiter=|",
            "--op",
            "filter_contains:needle=ops",
        ],
        b"alice 10 dev\nbob 20 ops\ncharlie 30 ops\n",
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "bob|ops\ncharlie|ops\n"
    );
}

#[test]
fn template_allow_read_blocks_non_allowlisted_file() {
    let dir = tempdir().expect("tempdir should be created");
    let template_path = dir.path().join("example.spt");
    let allowed_path = dir.path().join("allowed.txt");
    let blocked_path = dir.path().join("blocked.txt");

    std::fs::write(&allowed_path, "safe").expect("should write allowed file");
    std::fs::write(&blocked_path, "secret").expect("should write blocked file");
    std::fs::write(
        &template_path,
        r#"
template v1
source blocked = file("blocked.txt")
emit """
{{blocked}}
"""
"#,
    )
    .expect("should write template file");

    let output = run_safepipe_with(
        &[
            "template",
            "run",
            "--template",
            template_path.to_str().expect("valid path"),
            "--root",
            dir.path().to_str().expect("valid path"),
            "--terminal-policy",
            "strict_printable",
            "--allow-read",
            "allowed.txt",
        ],
        b"",
        Some(dir.path()),
        &[],
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not allowed by --allow-read policy"));
}

#[test]
fn template_allow_read_dot_allows_root_scoped_reads() {
    let dir = tempdir().expect("tempdir should be created");
    let template_path = dir.path().join("example.spt");
    let blocked_path = dir.path().join("blocked.txt");

    std::fs::write(&blocked_path, "secret").expect("should write blocked file");
    std::fs::write(
        &template_path,
        r#"
template v1
source blocked = file("blocked.txt")
emit """
{{blocked}}
"""
"#,
    )
    .expect("should write template file");

    let output = run_safepipe_with(
        &[
            "template",
            "run",
            "--template",
            template_path.to_str().expect("valid path"),
            "--root",
            dir.path().to_str().expect("valid path"),
            "--terminal-policy",
            "strict_printable",
            "--allow-read",
            ".",
        ],
        b"",
        Some(dir.path()),
        &[],
    );

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "secret");
}

#[test]
fn template_command_requires_allow_command() {
    let dir = tempdir().expect("tempdir should be created");
    let template_path = dir.path().join("cmd.spt");
    std::fs::write(
        &template_path,
        r#"
template v1
source now = command("date_utc")
emit """
{{now}}
"""
"#,
    )
    .expect("should write template file");

    let output = run_safepipe_with(
        &[
            "template",
            "run",
            "--template",
            template_path.to_str().expect("valid path"),
            "--root",
            dir.path().to_str().expect("valid path"),
            "--terminal-policy",
            "strict_printable",
        ],
        b"",
        Some(dir.path()),
        &[],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("blocked; pass --allow-command"));
}

#[test]
fn template_command_runs_when_allowed() {
    let dir = tempdir().expect("tempdir should be created");
    let template_path = dir.path().join("cmd.spt");
    std::fs::write(
        &template_path,
        r#"
template v1
source now = command("unix_time")
emit """
{{now}}
"""
"#,
    )
    .expect("should write template file");

    let output = run_safepipe_with(
        &[
            "template",
            "run",
            "--template",
            template_path.to_str().expect("valid path"),
            "--root",
            dir.path().to_str().expect("valid path"),
            "--terminal-policy",
            "strict_printable",
            "--allow-command",
            "unix_time",
        ],
        b"",
        Some(dir.path()),
        &[],
    );
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(!stdout.is_empty());
    assert!(stdout.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn unknown_allow_command_is_rejected() {
    let dir = tempdir().expect("tempdir should be created");
    let template_path = dir.path().join("cmd.spt");
    std::fs::write(
        &template_path,
        r#"
template v1
source now = command("date_utc")
emit """
{{now}}
"""
"#,
    )
    .expect("should write template file");

    let output = run_safepipe_with(
        &[
            "template",
            "run",
            "--template",
            template_path.to_str().expect("valid path"),
            "--root",
            dir.path().to_str().expect("valid path"),
            "--terminal-policy",
            "strict_printable",
            "--allow-command",
            "whoami",
        ],
        b"",
        Some(dir.path()),
        &[],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown trusted command"));
}

#[test]
fn template_run_rejects_remote_urls() {
    let dir = tempdir().expect("tempdir should be created");
    let output = run_safepipe_with(
        &[
            "template",
            "run",
            "--template",
            "https://example.com/template.spt",
            "--root",
            dir.path().to_str().expect("valid path"),
            "--terminal-policy",
            "strict_printable",
        ],
        b"",
        Some(dir.path()),
        &[],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("remote template URLs are disabled"));
}

#[test]
fn template_install_rejects_remote_urls() {
    let dir = tempdir().expect("tempdir should be created");
    let output = run_safepipe_with(
        &[
            "template",
            "install",
            "--name",
            "demo",
            "--from",
            "https://example.com/template.spt",
        ],
        b"",
        Some(dir.path()),
        &[],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("remote template URLs are disabled"));
}

#[test]
fn installed_template_with_file_requires_allow_read() {
    let home = tempdir().expect("temp home should be created");
    let work = tempdir().expect("temp work dir should be created");
    let source_template = work.path().join("source.spt");
    let data_path = work.path().join("data.txt");

    std::fs::write(&data_path, "secret").expect("should write data file");
    std::fs::write(
        &source_template,
        r#"
template v1
source data = file("data.txt")
emit """
{{data}}
"""
"#,
    )
    .expect("should write source template");

    let home_path = home.path().to_str().expect("valid home path");
    let source_path = source_template.to_str().expect("valid source path");

    let install = run_safepipe_with(
        &[
            "template",
            "install",
            "--name",
            "needs_allowlist",
            "--from",
            source_path,
        ],
        b"",
        Some(work.path()),
        &[("HOME", home_path)],
    );
    assert!(
        install.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&install.stderr)
    );

    let run = run_safepipe_with(
        &[
            "template",
            "run",
            "--template",
            "@needs_allowlist",
            "--root",
            work.path().to_str().expect("valid path"),
            "--terminal-policy",
            "strict_printable",
        ],
        b"",
        Some(work.path()),
        &[("HOME", home_path)],
    );
    assert!(!run.status.success());
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(stderr.contains("require explicit --allow-read entries"));
}

#[cfg(unix)]
#[test]
fn template_rejects_symlink_components() {
    let dir = tempdir().expect("tempdir should be created");
    let template_path = dir.path().join("example.spt");
    let real_path = dir.path().join("real.txt");
    let link_path = dir.path().join("link.txt");

    std::fs::write(&real_path, "secret").expect("should write real file");
    symlink(&real_path, &link_path).expect("should create symlink");
    std::fs::write(
        &template_path,
        r#"
template v1
source data = file("link.txt")
emit """
{{data}}
"""
"#,
    )
    .expect("should write template file");

    let output = run_safepipe_with(
        &[
            "template",
            "run",
            "--template",
            template_path.to_str().expect("valid path"),
            "--root",
            dir.path().to_str().expect("valid path"),
            "--terminal-policy",
            "strict_printable",
            "--allow-read",
            ".",
        ],
        b"",
        Some(dir.path()),
        &[],
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot include symlink components"));
}
