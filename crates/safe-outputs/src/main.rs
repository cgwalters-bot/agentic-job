//! Standalone, credential-free check and separately credentialed apply.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use ring::digest::{SHA256, digest};
use safe_outputs::apply::{Provenance, github::Github, mentions};
use safe_outputs::check::{self, Handback, Publishers, Trusted};
use safe_outputs::contract::{Policy, SafeOutputs};
use safe_outputs::{CONTRACT, Forge, MAX_OUTPUTS_BYTES, collect};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

#[path = "cli_gitlab.rs"]
mod gitlab;

const MAX_CONTEXT_BYTES: u64 = 64 * 1024;
const MAX_RECEIPT_BYTES: u64 = 4096;
const MAX_LINES: usize = 1000;
const TOKEN_ENV: &str = "SAFE_OUTPUTS_TOKEN";

#[derive(Parser)]
#[command(about = "Check bounded safe-output JSONL, then apply in a separate trusted process")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// No credentials or network. Write a receipt only after complete validation.
    Check(Args),
    /// Revalidate, refuse unsupported batches, then read SAFE_OUTPUTS_TOKEN.
    Apply(Args),
}

#[derive(clap::Args)]
struct Args {
    /// Explicit publisher selection; GitHub comments remain the default.
    #[arg(long, value_enum, default_value = "github")]
    forge: CliForge,
    /// Trusted JSON bounds/context, not supplied by the proposals producer.
    #[arg(long)]
    context: PathBuf,
    /// Untrusted gh-aw JSONL; at most 1 MiB and 1000 lines.
    #[arg(long)]
    input: PathBuf,
    /// Check creates this file; apply reads it from the trusted check job.
    #[arg(long)]
    checked: PathBuf,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum CliForge {
    Github,
    Gitlab,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextFile {
    repo: String,
    item: u64,
    #[serde(default)]
    max_outputs: u32,
    #[serde(default)]
    outputs: SafeOutputs,
    #[serde(default = "github_api")]
    api_url: String,
}

fn github_api() -> String {
    "https://api.github.com".into()
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    #[serde(default)]
    forge: Forge,
    context_sha256: String,
    input_sha256: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    files_sha256: std::collections::BTreeMap<String, String>,
}

fn hash(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// O_NONBLOCK prevents a FIFO from blocking before the regular-file check;
// NOFOLLOW rejects a producer replacing the input with a symlink.
fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, open};
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .context("cannot open input as a no-follow file")?;
    let file = File::from(fd);
    ensure!(file.metadata()?.is_file(), "input is not a regular file");
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "file exceeds byte limit {limit}"
    );
    Ok(bytes)
}

struct Native;

impl Publishers for Native {
    fn inline_comment(&self, _: &Map<String, Value>, _: Forge) -> Result<()> {
        bail!("standalone inline comments are unsupported")
    }

    fn native_refusals(&self, _: &[Value], _: &[String]) -> Vec<String> {
        Vec::new()
    }
}

fn validate(context: &ContextFile, bytes: &[u8]) -> Result<Vec<Map<String, Value>>> {
    ensure!(
        safe_outputs::apply::github::is_repo(&context.repo),
        "context repo must be OWNER/REPO"
    );
    ensure!(context.item > 0, "context item must be positive");
    ensure!(context.max_outputs <= 1000, "max_outputs exceeds 1000");
    ensure!(
        bytes.split(|b| *b == b'\n').count() - usize::from(bytes.ends_with(b"\n")) <= MAX_LINES,
        "input exceeds {MAX_LINES} lines"
    );
    // The collector drops unknown fields. Refuse comment semantics this small
    // publisher cannot implement rather than silently turning an edit/reply into
    // a new comment, or dropping a misspelled destination before checking it.
    for line in bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
    {
        let value: Value = serde_json::from_slice(line).context("malformed JSONL")?;
        if value["type"]
            .as_str()
            .is_some_and(|kind| kind.replace('-', "_") == "add_comment")
        {
            let item = value.as_object().context("request must be an object")?;
            ensure!(
                item.keys().all(
                    |key| ["type", "body", "repo", "item_number", "pr", "pr_number"]
                        .contains(&key.as_str())
                ),
                "unsupported standalone comment field"
            );
        }
    }
    let policy: Policy = serde_json::from_value(json!({
        "repo": context.repo, "clone_url": format!("https://github.com/{}", context.repo),
        "base": "main", "kind": "analysis", "max_outputs": context.max_outputs,
        "max_patch_bytes": MAX_OUTPUTS_BYTES, "safe_outputs": context.outputs,
        "contract": CONTRACT
    }))?;
    // Do not echo untrusted request text in errors or privileged job logs.
    policy.validate().context("invalid trusted bounds")?;
    let config = serde_json::to_value(&policy.safe_outputs)?;
    let collected = collect::collect_bytes(
        bytes,
        config.as_object().context("output bounds")?,
        Forge::Github,
        &|host| {
            safe_outputs::link_domains()
                .iter()
                .any(|domain| host == domain || host.ends_with(&format!(".{domain}")))
        },
    )?;
    let checked = check::check(
        &Handback {
            outputs: Some(bytes),
            ..Default::default()
        },
        check::Collected {
            items: collected.items,
            errors: collected.errors,
        },
        &policy,
        Trusted {
            comment: Some((&context.repo, context.item)),
            run_id: None,
        },
        &Native,
        |_| Vec::new(),
    );
    ensure!(
        checked.errors.is_empty(),
        "safe-output validation refused ({} errors)",
        checked.errors.len()
    );
    Ok(checked.items)
}

fn run() -> Result<()> {
    let command = Cli::parse().command;
    let (args, apply) = match &command {
        Command::Check(args) => (args, false),
        Command::Apply(args) => (args, true),
    };
    let context_bytes = read(&args.context, MAX_CONTEXT_BYTES)?;
    let bytes = read(&args.input, MAX_OUTPUTS_BYTES)?;
    let gitlab = match args.forge {
        CliForge::Gitlab => Some(gitlab::Checked::new(&context_bytes, &bytes, &args.input)?),
        CliForge::Github => None,
    };
    let context: Option<ContextFile> = if gitlab.is_none() {
        Some(serde_json::from_slice(&context_bytes).context("invalid context JSON")?)
    } else {
        None
    };
    let items = match &context {
        Some(context) => validate(context, &bytes)?,
        None => Vec::new(),
    };
    let receipt = Receipt {
        version: 1,
        forge: if gitlab.is_some() {
            Forge::Gitlab
        } else {
            Forge::Github
        },
        context_sha256: hash(&context_bytes),
        input_sha256: hash(&bytes),
        files_sha256: gitlab
            .as_ref()
            .map(|checked| checked.digests())
            .unwrap_or_default(),
    };
    if !apply {
        let parent = args
            .checked
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer(&mut file, &receipt)?;
        file.write_all(b"\n")?;
        file.persist_noclobber(&args.checked)
            .context("cannot create check receipt (must not exist)")?;
        println!(
            "checked {} requests",
            gitlab.as_ref().map_or(items.len(), |checked| checked.count)
        );
        return Ok(());
    }
    let accepted: Receipt = serde_json::from_slice(&read(&args.checked, MAX_RECEIPT_BYTES)?)
        .context("invalid check receipt")?;
    ensure!(
        accepted == receipt,
        "checked input or trusted context changed"
    );
    if let Some(checked) = gitlab {
        checked.apply()?;
        return Ok(());
    }
    let context = context.context("missing GitHub context")?;
    // Refuse the ENTIRE batch before acquiring credentials or making any write.
    ensure!(
        items.iter().all(|item| matches!(
            check::item_type(item),
            "add_comment" | "noop" | "missing_tool" | "missing_data"
        )),
        "unsupported standalone native operation; no writes made"
    );
    let bodies: Vec<String> = items
        .iter()
        .filter(|item| check::item_type(item) == "add_comment")
        .map(|item| {
            item.get("body")
                .and_then(Value::as_str)
                .map(|body| mentions::filter(body, "github"))
                .context("comment has no body")
        })
        .collect::<Result<_>>()?;
    if !bodies.is_empty() {
        let token = std::env::var(TOKEN_ENV).context("apply requires SAFE_OUTPUTS_TOKEN")?;
        ensure!(
            !token.trim().is_empty(),
            "apply requires a nonempty SAFE_OUTPUTS_TOKEN"
        );
        let github = Github::new(
            &context.api_url,
            token,
            Provenance {
                name: "safe-outputs",
                status_context: "safe-outputs",
                committer: ("safe-outputs", "noreply@example.com"),
            },
        )?;
        for body in bodies {
            github
                .request(
                    "POST",
                    &format!("/repos/{}/issues/{}/comments", context.repo, context.item),
                    Some(&json!({"body": body})),
                )
                .map_err(|_| anyhow::anyhow!("comment publication failed"))?;
        }
    }
    println!("applied {} requests", items.len());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("safe-outputs: {error:#}");
        std::process::exit(1);
    }
}
