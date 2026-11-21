//! `agentic-job publish`: GitHub's native publishing, which is the
//! safe-outputs library's ([`safe_outputs::apply::publish`]), re-exported
//! here. This reads the policy, the requests and the handlers'
//! configuration without following a link, the run's variables and the
//! token from the environment, and writes the library's log lines as
//! workflow commands, escaped.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
pub use safe_outputs::apply::publish::*;
use serde_json::{Value, json};

use crate::exit::Exit;
use crate::files;
use crate::policy::{Load, Policy};

/// The largest requests or configuration file read: check's own bound on
/// the collector's result.
const MAX_INPUT_BYTES: u64 = 4 << 20;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The policy.json check checked against: its `native_handlers` are routed here
    #[arg(long, value_name = "FILE")]
    pub policy: PathBuf,
    /// The requests as apply's guard left them (gh-aw's agent_output.json)
    #[arg(long, value_name = "FILE")]
    pub outputs: PathBuf,
    /// The handlers' configuration apply.yml wrote (handler-config.json)
    #[arg(long, value_name = "FILE")]
    pub handlers: PathBuf,
    /// The check job's upload: its report.json and the patch beside it
    #[arg(long, value_name = "DIR")]
    pub checked: PathBuf,
    /// Where git finds OWNER/NAME.git: the server's address
    #[arg(long, value_name = "URL")]
    pub server: String,
    /// Written with the requests left to gh-aw's handlers, before anything is published
    #[arg(long, value_name = "FILE")]
    pub remainder: PathBuf,
    /// gh-aw's safe-output-items.jsonl, appended what was made
    #[arg(long, value_name = "FILE")]
    pub made: PathBuf,
    /// Written as gh-aw's safe-output-errors.json when a request failed
    #[arg(long, value_name = "FILE")]
    pub errors: PathBuf,
}

pub fn run(args: &Args) -> Result<Exit> {
    match publish_all(args) {
        Ok(true) => Ok(Exit::Success),
        Ok(false) => Ok(Exit::Failure),
        Err(err) => {
            let message = format!("{err:#}");
            println!("::error::{}", crate::run::enter::one_line(&message));
            // Refused before it was written: gh-aw's handlers get nothing.
            if !args.remainder.exists() {
                std::fs::write(&args.remainder, r#"{"items":[],"errors":[]}"#)
                    .with_context(|| format!("writing {}", args.remainder.display()))?;
            }
            // For `diagnostics handler-errors`, as gh-aw's manager reports
            // a failure of its own: a message, and no output's failure.
            let report = json!({"status": "failure", "message": message, "failures": []});
            std::fs::write(&args.errors, format!("{report:#}\n"))
                .with_context(|| format!("writing {}", args.errors.display()))?;
            Ok(Exit::Failure)
        }
    }
}

/// [`run`], which returns whether every request was published.
fn publish_all(args: &Args) -> Result<bool> {
    let policy = Policy::load(&args.policy)?;
    policy.publishable()?;
    ensure!(
        !policy.native_handlers.is_empty(),
        "the policy routes no output type to agentic-job publish"
    );
    let read = |path: &Path| -> Result<Value> {
        let bytes = files::read_regular(path, MAX_INPUT_BYTES)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&bytes).with_context(|| format!("{} is not JSON", path.display()))
    };
    let outputs = read(&args.outputs)?;
    let items = outputs["items"]
        .as_array()
        .with_context(|| format!("{} holds no items", args.outputs.display()))?;
    let handlers = read(&args.handlers)?;
    let handlers = handlers
        .as_object()
        .with_context(|| format!("{} is not an object", args.handlers.display()))?;
    check_server(&args.server)?;
    let checked = Checked {
        items,
        handlers,
        upload: super::upload(&args.checked),
        policy: &policy,
    };
    let run = Run::read(&|name| std::env::var(name).ok())?;
    let github = super::github::from_env(super::github::GH_TOKEN_ENV)?;
    let publisher = publisher(github, &args.server, &checked, &run)?;
    let output = std::env::var_os("GITHUB_OUTPUT").map(PathBuf::from);
    let summary = std::env::var_os("GITHUB_STEP_SUMMARY").map(PathBuf::from);
    let workflow = std::env::var("GITHUB_WORKFLOW").unwrap_or_default();
    let records = Records {
        remainder: &args.remainder,
        made: &args.made,
        errors: &args.errors,
        output: output.as_deref(),
        summary: summary.as_deref(),
        workflow: &workflow,
    };
    let mut log = |line: &Annotation| {
        println!(
            "::{}::{}",
            line.kind,
            crate::run::enter::one_line(&line.text)
        );
    };
    apply(&checked, &run, &publisher, &records, &mut log)
}
