use std::io::Write;
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
