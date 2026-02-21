use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TemplateScript {
    pub sources: Vec<SourceDecl>,
    pub body: String,
}

impl TemplateScript {
    pub fn has_stdin_source(&self) -> bool {
        self.sources
            .iter()
            .any(|s| matches!(s.kind, SourceKind::Stdin))
    }
}

#[derive(Debug, Clone)]
pub struct SourceDecl {
    pub name: String,
    pub kind: SourceKind,
    pub ops: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum SourceKind {
    File(String),
    Stdin,
    Now(String),
    Literal(String),
    Command(String),
}

pub fn parse_template(input: &str) -> Result<TemplateScript, String> {
    let lines: Vec<&str> = input.lines().collect();
    let mut idx = 0usize;

    let mut sources = Vec::new();
    let mut saw_emit = false;

    while idx < lines.len() {
        let line = lines[idx].trim();
        idx += 1;

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line == "template v1" {
            continue;
        }

        if let Some(rest) = line.strip_prefix("set ") {
            return Err(format!(
                "set directives are not allowed in templates (found '{rest}'); use CLI flags like --terminal-policy instead"
            ));
        }

        if line == "emit \"\"\"" {
            saw_emit = true;
            break;
        }

        if let Some(rest) = line.strip_prefix("source ") {
            let (name_raw, expr_raw) = rest
                .split_once('=')
                .ok_or_else(|| format!("invalid source declaration: '{line}'"))?;
            let name = name_raw.trim().to_string();
            validate_name(&name)?;

            let segments: Vec<String> = expr_raw
                .split('|')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect();

            if segments.is_empty() {
                return Err(format!("source '{name}' is missing expression"));
            }

            let kind = parse_source_kind(&segments[0])?;
            let ops = segments.into_iter().skip(1).collect();
            sources.push(SourceDecl { name, kind, ops });
            continue;
        }

        return Err(format!("unknown template line '{line}'"));
    }

    if !saw_emit {
        return Err("template missing `emit \"\"\"` block".to_string());
    }

    let mut body_lines = Vec::new();
    while idx < lines.len() {
        let line = lines[idx];
        idx += 1;
        if line.trim() == "\"\"\"" {
            let body = body_lines.join("\n");
            return Ok(TemplateScript { sources, body });
        }
        body_lines.push(line.to_string());
    }

    Err("unterminated emit block; expected closing `\"\"\"`".to_string())
}

fn parse_source_kind(input: &str) -> Result<SourceKind, String> {
    if input == "stdin()" {
        return Ok(SourceKind::Stdin);
    }

    let (fn_name, args) = input
        .split_once('(')
        .ok_or_else(|| format!("invalid source expression '{input}'"))?;
    let args = args
        .strip_suffix(')')
        .ok_or_else(|| format!("invalid source expression '{input}'"))?
        .trim();

    match fn_name.trim() {
        "file" => Ok(SourceKind::File(parse_json_string_arg(args)?)),
        "now" => Ok(SourceKind::Now(parse_json_string_arg(args)?)),
        "literal" => Ok(SourceKind::Literal(parse_json_string_arg(args)?)),
        "command" | "cmd" => {
            let name = parse_json_string_arg(args)?;
            if name.trim().is_empty() {
                return Err("command() requires non-empty command name".to_string());
            }
            Ok(SourceKind::Command(name))
        }
        other => Err(format!("unsupported source function '{other}'")),
    }
}

fn parse_json_string_arg(input: &str) -> Result<String, String> {
    serde_json::from_str::<String>(input)
        .map_err(|_| format!("expected JSON string argument, got '{input}'"))
}

pub fn render_body(body: &str, vars: &HashMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(body.len());
    let mut i = 0usize;

    while i < body.len() {
        let tail = &body[i..];
        if let Some(open_rel) = tail.find("{{") {
            let open = i + open_rel;
            out.push_str(&body[i..open]);

            let after_open = open + 2;
            let Some(close_rel) = body[after_open..].find("}}") else {
                return Err("unclosed '{{' placeholder".to_string());
            };
            let close = after_open + close_rel;
            let key = body[after_open..close].trim();
            validate_name(key)?;

            let value = vars
                .get(key)
                .ok_or_else(|| format!("missing placeholder value for '{key}'"))?;
            out.push_str(value);
            i = close + 2;
        } else {
            out.push_str(tail);
            break;
        }
    }

    Ok(out)
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name cannot be empty".to_string());
    }

    let mut chars = name.chars();
    let first = chars.next().expect("checked above");
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err(format!("invalid name '{name}': must start with [A-Za-z_]"));
    }

    if !chars.all(|c| c == '_' || c.is_ascii_alphanumeric()) {
        return Err(format!("invalid name '{name}': only [A-Za-z0-9_] allowed"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_template() {
        let tpl = r#"
        template v1
        source who = literal("world") | trim:both
        emit """
hello {{who}}
"""
        "#;

        let parsed = parse_template(tpl).expect("template should parse");
        assert_eq!(parsed.sources.len(), 1);
        assert_eq!(parsed.sources[0].ops, vec!["trim:both"]);
        assert_eq!(parsed.body.trim(), "hello {{who}}");
    }

    #[test]
    fn renders_placeholders() {
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "Alice".to_string());
        let out = render_body("hi {{name}}", &vars).expect("should render");
        assert_eq!(out, "hi Alice");
    }

    #[test]
    fn rejects_set_directive() {
        let tpl = r#"
template v1
set terminal_policy = raw
emit """
hello
"""
        "#;
        let err = parse_template(tpl).expect_err("template should fail");
        assert!(err.contains("set directives are not allowed"));
    }

    #[test]
    fn parses_command_source() {
        let tpl = r#"
template v1
source now = command("date_utc")
emit """
{{now}}
"""
        "#;
        let parsed = parse_template(tpl).expect("template should parse");
        assert_eq!(parsed.sources.len(), 1);
        assert!(matches!(
            parsed.sources[0].kind,
            SourceKind::Command(ref name) if name == "date_utc"
        ));
    }
}
