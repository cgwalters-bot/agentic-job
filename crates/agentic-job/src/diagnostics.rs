//! `agentic-job diagnostics`: say why check refused a run's outputs, or
//! why apply's handlers failed them, and publish only bounded refusal
//! evidence, never the requests or the patch.
//!
//! Collector, policy and handler errors can quote the agent's text, so
//! each reason is bounded, kept to one line and has its Markdown and
//! mentions neutralized before it reaches an annotation or a comment.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::exit::Exit;
use crate::files;

/// The reports' bound: check's is far below it.
const MAX_BYTES: u64 = 8 << 20;
const MAX_ERRORS: usize = 100;
const MAX_REASON_CHARS: usize = 1000;
/// What a step output joining the reasons keeps.
const MAX_OUTPUT_CHARS: usize = 4000;

/// The collector's result, then check's verdict, in the check job's
/// `GH_AW_TMP`.
const REPORTS: [&str; 2] = ["agent_output.json", "report.json"];

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Annotate the collector's and check's refusal reasons in DIR
    Refusals(ReasonArgs),
    /// Annotate the errors in gh-aw's safe-output-errors.json at PATH
    HandlerErrors(ReasonArgs),
    /// Copy only the refusal reasons in SOURCE to DESTINATION, for a diagnostics artifact
    Copy(CopyArgs),
}

#[derive(Debug, clap::Args)]
pub struct ReasonArgs {
    /// The directory or file the reasons are read from
    pub path: PathBuf,
    /// The step's $GITHUB_OUTPUT, appended `reason=` with the reasons joined
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct CopyArgs {
    pub source: PathBuf,
    pub destination: PathBuf,
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        match self {
            Self::Refusals(args) => {
                annotate(args, "Refused by check: ", &refusal_reasons(&args.path)?)
            }
            Self::HandlerErrors(args) => {
                annotate(args, "Failed to apply ", &handler_errors(&args.path)?)
            }
            Self::Copy(args) => {
                copy(&args.source, &args.destination)?;
                Ok(Exit::Success)
            }
        }
    }
}

fn annotate(args: &ReasonArgs, prefix: &str, reasons: &[String]) -> Result<Exit> {
    // A neutralized reason holds no line break; `%` is the runner's escape.
    for reason in reasons {
        println!("::error::{prefix}{}", reason.replace('%', "%25"));
    }
    if let Some(output) = &args.output {
        let joined: String = reasons.join("; ").chars().take(MAX_OUTPUT_CHARS).collect();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(output)
            .with_context(|| format!("opening {}", output.display()))?;
        writeln!(file, "reason={joined}")
            .with_context(|| format!("writing {}", output.display()))?;
    }
    Ok(Exit::Success)
}

/// The JSON document at `path`, or None when there is none.
fn read_report(path: &Path) -> Result<Option<Value>> {
    match files::read_regular(path, MAX_BYTES) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("parsing {}", path.display())),
        Err(files::ReadError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => bail!("Diagnostic report {} {err}", path.display()),
    }
}

/// A report's `errors`, which must all be text.
fn errors(report: &Value, name: &str) -> Result<Vec<String>> {
    Vec::<String>::deserialize(&report["errors"])
        .with_context(|| format!("Invalid diagnostic report: {name}"))
}

pub fn refusal_reasons(source: &Path) -> Result<Vec<String>> {
    let mut reasons = Vec::new();
    for name in REPORTS {
        let Some(report) = read_report(&source.join(name))? else {
            continue;
        };
        reasons.extend(errors(&report, name)?.into_iter().take(MAX_ERRORS));
    }
    Ok(reasons
        .iter()
        .take(MAX_ERRORS)
        .map(|reason| neutralize(reason))
        .collect())
}

/// What gh-aw's handler manager records when outputs fail (its
/// safe_output_manifest.cjs, secrets redacted): each failed output's type
/// and its handler's error, or the manager's own message when it failed
/// before any output did. The requests and patch are not in it.
pub fn handler_errors(path: &Path) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct Failure {
        r#type: String,
        #[serde(default)]
        error: Option<String>,
    }
    #[derive(Deserialize)]
    struct Report {
        #[serde(default)]
        failures: Option<Vec<Failure>>,
        #[serde(default)]
        message: Option<String>,
    }
    let Some(report) = read_report(path)? else {
        return Ok(Vec::new());
    };
    let report = Report::deserialize(report).context("Invalid handler error report")?;
    let failures = report.failures.unwrap_or_default();
    let reasons = if failures.is_empty() {
        report
            .message
            .into_iter()
            .filter(|m| !m.is_empty())
            .collect()
    } else {
        failures
            .into_iter()
            .take(MAX_ERRORS)
            .map(|failure| {
                let error = failure.error.filter(|e| !e.is_empty());
                format!(
                    "{}: {}",
                    failure.r#type,
                    error.as_deref().unwrap_or("no error given")
                )
            })
            .collect::<Vec<_>>()
    };
    Ok(reasons.iter().map(|reason| neutralize(reason)).collect())
}

/// One bounded line, with Markdown and mentions made inert.
fn neutralize(reason: &str) -> String {
    let mut shown = String::new();
    for c in reason.chars().take(MAX_REASON_CHARS) {
        match c {
            '\0'..='\x1f' | '\x7f'..='\u{9f}' => shown.push(' '),
            '@' => shown.push_str("@\u{200b}"),
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' => {
                shown.push('\\');
                shown.push(c);
            }
            _ => shown.push(c),
        }
    }
    shown
}

/// The reports in `source` with their errors bounded and everything else,
/// requests and patch included, left out: what audit reads as
/// `check-diagnostics`.
pub fn copy(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)
        .with_context(|| format!("creating {}", destination.display()))?;
    for name in REPORTS {
        let Some(report) = read_report(&source.join(name))? else {
            continue;
        };
        let all = errors(&report, name)?;
        let mut errors: Vec<String> = all
            .iter()
            .take(MAX_ERRORS)
            .map(|error| match error.char_indices().nth(MAX_REASON_CHARS) {
                Some((end, _)) => format!("{} [truncated]", &error[..end]),
                None => error.clone(),
            })
            .collect();
        if all.len() > MAX_ERRORS {
            errors.push("[additional refusal reasons omitted]".to_owned());
        }
        let mut diagnostic = json!({"errors": errors, "items": []});
        if name == "report.json" {
            let Some(ok) = report["ok"].as_bool() else {
                bail!("Invalid diagnostic report: {name}");
            };
            diagnostic["ok"] = ok.into();
        }
        let path = destination.join(name);
        std::fs::write(&path, format!("{diagnostic}\n"))
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, value: &Value) {
        std::fs::write(dir.join(name), value.to_string()).unwrap();
    }

    fn read(path: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn copy_publishes_only_refusal_evidence() {
        for phase in ["collector", "policy"] {
            let dir = tempfile::tempdir().unwrap();
            let collector: &[&str] = if phase == "collector" {
                &["collector refusal"]
            } else {
                &[]
            };
            write(
                dir.path(),
                "agent_output.json",
                &json!({"errors": collector, "items": [{"type": "noop", "message": "must not be published"}]}),
            );
            if phase == "policy" {
                write(
                    dir.path(),
                    "report.json",
                    &json!({"ok": false, "errors": ["policy refusal"], "items": [{"type": "noop"}],
                        "patch": {"file": "rejected.patch"}}),
                );
            }
            let destination = dir.path().join("check-diagnostics");
            copy(dir.path(), &destination).unwrap();
            assert_eq!(
                read(&destination.join("agent_output.json")),
                json!({"errors": collector, "items": []})
            );
            let report = destination.join("report.json");
            if phase == "policy" {
                assert_eq!(
                    read(&report),
                    json!({"ok": false, "errors": ["policy refusal"], "items": []})
                );
            } else {
                assert!(!report.exists());
            }
        }
    }

    #[test]
    fn copy_bounds_input_and_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("agent_output.json");
        let destination = dir.path().join("check-diagnostics");
        write(
            dir.path(),
            "agent_output.json",
            &json!({"errors": vec!["x".repeat(1001); 101], "items": []}),
        );
        copy(dir.path(), &destination).unwrap();
        let errors = read(&destination.join("agent_output.json"))["errors"].clone();
        let errors = errors.as_array().unwrap();
        assert_eq!(errors.len(), 101);
        assert!(errors[0].as_str().unwrap().ends_with("[truncated]"));
        assert!(errors[100].as_str().unwrap().contains("omitted"));
        std::fs::write(&source, " ".repeat((8 << 20) + 1)).unwrap();
        let error = copy(dir.path(), &destination).unwrap_err().to_string();
        assert!(error.contains("over"), "{error}");
        std::fs::remove_file(&source).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &source).unwrap();
        let error = copy(dir.path(), &destination).unwrap_err().to_string();
        assert!(error.contains("not a regular file"), "{error}");
        std::fs::remove_file(&source).unwrap();
        write(dir.path(), "report.json", &json!({"errors": []}));
        assert!(
            copy(dir.path(), &destination).is_err(),
            "a verdict without ok"
        );
    }

    #[test]
    fn refusal_reasons_are_neutralized() {
        for (name, errors, expected) in [
            (
                "agent_output.json",
                vec!["collector refusal"],
                vec!["collector refusal"],
            ),
            (
                "report.json",
                vec!["protected files: CONTRIBUTING.md"],
                vec!["protected files: CONTRIBUTING.md"],
            ),
            ("report.json", vec![], vec![]),
            (
                "report.json",
                vec!["bad\n::error::\r@user [link](x) `code`"],
                vec!["bad ::error:: @\u{200b}user \\[link\\](x) \\`code\\`"],
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            assert!(refusal_reasons(dir.path()).unwrap().is_empty());
            write(
                dir.path(),
                name,
                &json!({"errors": errors, "items": [{"message": "not a reason"}]}),
            );
            assert_eq!(refusal_reasons(dir.path()).unwrap(), expected, "{name}");
            write(dir.path(), name, &json!({"errors": [42]}));
            let error = refusal_reasons(dir.path()).unwrap_err().to_string();
            assert!(error.contains("Invalid diagnostic report"), "{error}");
        }
    }

    #[test]
    fn refusal_reasons_bound_count_and_text() {
        let dir = tempfile::tempdir().unwrap();
        for name in REPORTS {
            write(
                dir.path(),
                name,
                &json!({"errors": vec!["x".repeat(1001); 101]}),
            );
        }
        let reasons = refusal_reasons(dir.path()).unwrap();
        assert_eq!(reasons.len(), MAX_ERRORS);
        assert!(
            reasons
                .iter()
                .all(|reason| reason.chars().count() == MAX_REASON_CHARS)
        );
    }

    // gh-aw's safe-output-errors.json, as its handler manager writes it.
    #[test]
    fn handler_errors_name_each_failed_output() {
        let long = vec![format!("add\\_comment: {}", "x".repeat(987)); 100];
        for (report, expected) in [
            (
                json!({"status": "failure", "message": "1 safe output(s) failed:\n  - add_comment: E008: too many links",
                    "failures": [{"type": "add_comment", "errorCode": "E099",
                        "error": "E008: Comment contains 52 links, maximum is 50."}]}),
                vec!["add\\_comment: E008: Comment contains 52 links, maximum is 50.".to_owned()],
            ),
            (
                json!({"failures": [{"type": "add_comment", "error": "bad\n::error::\r@user [link](x) `code`"},
                    {"type": "create_issue"}]}),
                vec![
                    "add\\_comment: bad ::error:: @\u{200b}user \\[link\\](x) \\`code\\`"
                        .to_owned(),
                    "create\\_issue: no error given".to_owned(),
                ],
            ),
            (
                json!({"message": "Handler manager failed: boom", "failures": []}),
                vec!["Handler manager failed: boom".to_owned()],
            ),
            (
                json!({"failures": vec![json!({"type": "add_comment", "error": "x".repeat(1001)}); 101]}),
                long.clone(),
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("safe-output-errors.json");
            assert!(handler_errors(&file).unwrap().is_empty());
            std::fs::write(&file, report.to_string()).unwrap();
            assert_eq!(handler_errors(&file).unwrap(), expected);
            for invalid in [json!({"failures": [{"type": 42}]}), json!({"message": 1})] {
                std::fs::write(&file, invalid.to_string()).unwrap();
                let error = handler_errors(&file).unwrap_err().to_string();
                assert!(error.contains("Invalid handler error report"), "{error}");
            }
        }
    }

    #[test]
    fn annotations_and_output_stay_on_their_lines() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("output");
        std::fs::write(&output, "").unwrap();
        let args = ReasonArgs {
            path: dir.path().into(),
            output: Some(output.clone()),
        };
        let reasons = vec![neutralize("a%0A::warning::b\nc"); 300];
        annotate(&args, "Refused by check: ", &reasons).unwrap();
        let written = std::fs::read_to_string(&output).unwrap();
        assert_eq!(written.lines().count(), 1);
        assert!(written.starts_with("reason=a%0A::warning::b c; "));
        assert_eq!(
            written.strip_suffix('\n').unwrap().chars().count(),
            "reason=".len() + MAX_OUTPUT_CHARS
        );
    }
}
