//! Link an implementation to the caller's issue, without closing partial work.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use crate::{exit::Exit, files};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Checked agent_output.json, updated in place
    #[arg(long)]
    pub file: PathBuf,
    /// Repository containing the caller's issue
    #[arg(long)]
    pub item_repo: String,
    /// Repository receiving the pull request
    #[arg(long)]
    pub output_repo: String,
    /// Caller issue number
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub issue: u64,
}

pub fn run(args: &Args) -> Result<Exit> {
    // The collector already bounds this document. Keep reads bounded here too.
    let bytes = files::read_regular(&args.file, 4 << 20)
        .with_context(|| format!("reading {}", args.file.display()))?;
    let mut output: Value = serde_json::from_slice(&bytes).context("parsing checked outputs")?;
    let items = output["items"]
        .as_array_mut()
        .context("outputs have no items array")?;
    let same = args.item_repo.eq_ignore_ascii_case(&args.output_repo);
    let reference = if same {
        format!("Closes #{}", args.issue)
    } else {
        format!("Refs {}#{}", args.item_repo, args.issue)
    };
    for item in items {
        if item["type"] != "create_pull_request" {
            continue;
        }
        ensure!(
            item["body"].is_null() || item["body"].is_string(),
            "pull request body is not text"
        );
        item["body"] = reference_body(
            item["body"].as_str().unwrap_or(""),
            &reference,
            same,
            args.issue,
        )
        .into();
    }
    std::fs::write(&args.file, serde_json::to_vec(&output)?)
        .with_context(|| format!("writing {}", args.file.display()))?;
    Ok(Exit::Success)
}

fn reference_body(body: &str, reference: &str, same: bool, issue: u64) -> String {
    let mut fence: Option<(u8, usize)> = None;
    let mut comment = false;
    let mut found = false;
    for line in body
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
    {
        if comment {
            if line.contains("-->") {
                comment = false;
            }
            continue;
        }
        let indent = line.bytes().take_while(|&b| b == b' ').count();
        let text = &line[indent..];
        if let Some((mark, count)) = fence {
            let closing = text.bytes().take_while(|&b| b == mark).count();
            if indent <= 3 && closing >= count && text[closing..].trim().is_empty() {
                fence = None;
            }
            continue;
        }
        if indent <= 3
            && let Some(mark @ (b'`' | b'~')) = text.bytes().next()
        {
            let count = text.bytes().take_while(|&b| b == mark).count();
            if count >= 3 {
                fence = Some((mark, count));
                continue;
            }
        }
        if let Some((_, after)) = line.split_once("<!--") {
            comment = !after.contains("-->");
            continue;
        }
        let partial = same
            && [format!("Refs #{issue}"), format!("Part of #{issue}")]
                .iter()
                .any(|marker| {
                    line.strip_prefix(marker).is_some_and(|rest| {
                        rest.is_empty() || rest.starts_with(char::is_whitespace)
                    })
                });
        found |= line == reference || partial;
    }
    if found {
        return body.to_owned();
    }
    // Close a truncated example so it cannot swallow the generated reference.
    let close = if let Some((mark, count)) = fence {
        format!("\n{}", char::from(mark).to_string().repeat(count))
    } else if comment {
        "\n-->".to_owned()
    } else {
        String::new()
    };
    format!("{body}{close}\n\n{reference}")
}
