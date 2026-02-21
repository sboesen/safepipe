use std::io::Write;
use std::process::{Command, Stdio};

fn run_safepipe(args: &[&str], stdin: &[u8]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_safepipe");
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn safepipe");

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
