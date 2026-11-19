//! `agentic-job collect`: the safe-outputs collector
//! ([`safe_outputs::collect`]) on a run's hand-back and policy. This reads
//! the policy and the hand-back's `outputs.jsonl`, no-follow and bounded,
//! gives the collector the policy's configuration, and writes the
//! `{items, errors}` that `check --collected` reads.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};

use crate::check::{MAX_OUTPUTS_BYTES, OUTPUTS_FILE};
use crate::exit::Exit;
use crate::files::{self, ReadError};
use crate::policy::{Load, Policy};
pub use safe_outputs::collect::{Collected, collect, field_guide, markdown, sanitize};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The policy.json that `policy` printed for this run
    #[arg(long, value_name = "FILE")]
    pub policy: PathBuf,
    /// The directory holding the handed-back outputs
    #[arg(long, value_name = "DIR")]
    pub outputs: PathBuf,
    /// Where to write what was collected, which `check --collected` reads
    #[arg(long, value_name = "FILE")]
    pub collected: PathBuf,
}

/// The configuration the collector is given for POLICY: its
/// `safe_outputs`, with its secondary pull request's `max` added to
/// `create_pull_request`'s, since the collector counts a pull request of
/// either repository alike; `check` counts each against its own.
pub fn config(policy: &Policy) -> Result<Map<String, Value>> {
    let Value::Object(mut config) = serde_json::to_value(&policy.safe_outputs)? else {
        bail!("the policy's safe_outputs is not an object");
    };
    if let Some(secondary) = &policy.secondary_pull_request
        && let Some(Value::Object(pull)) = config.get_mut("create_pull_request")
    {
        let max = pull.get("max").and_then(Value::as_u64).unwrap_or(0);
        pull.insert("max".into(), (max + u64::from(secondary.max)).into());
    }
    Ok(config)
}

/// What [`collect`] makes of the `outputs.jsonl` in OUTPUTS under
/// POLICY: none at all if there is none, as gh-aw's collector takes a
/// missing file.
pub fn collect_dir(outputs: &Path, policy: &Policy) -> Result<Collected> {
    let path = outputs.join(OUTPUTS_FILE);
    // Read no-follow and bounded here, so the text is collected as it is.
    let text = match files::read_regular(&path, MAX_OUTPUTS_BYTES) {
        Ok(bytes) => {
            String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))?
        }
        Err(ReadError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => bail!("{} {err}", path.display()),
    };
    collect_text(&text, policy)
}

/// What [`collect`] makes of TEXT, an `outputs.jsonl` already read,
/// under POLICY.
pub fn collect_text(text: &str, policy: &Policy) -> Result<Collected> {
    let keeps_link = |host: &str| policy.keeps_link_to(host);
    Ok(collect(text, &config(policy)?, policy.forge, &keeps_link))
}

pub fn run(args: &Args) -> Result<Exit> {
    let policy = Policy::load(&args.policy)?;
    let path = &args.collected;
    let collected = collect_dir(&args.outputs, &policy)?;
    let json = serde_json::to_string(&collected).context("writing what was collected")?;
    std::fs::write(path, json + "\n").with_context(|| format!("writing {}", path.display()))?;
    for error in &collected.errors {
        eprintln!("error: {}", crate::run::enter::one_line(error));
    }
    Ok(if collected.errors.is_empty() {
        Exit::Success
    } else {
        Exit::Failure
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The command reads the hand-back's file and the policy's types, and
    /// fails where the collector refused a line, as check.yml's step after
    /// gh-aw's collector does.
    #[test]
    fn command_writes_the_result() {
        let dir = tempfile::tempdir().unwrap();
        let mut policy = crate::policy::tests::policy();
        policy.safe_outputs.create_pull_request = None;
        policy.safe_outputs.others.clear();
        policy.safe_outputs.others.insert(
            "noop".to_owned(),
            serde_json::from_value(json!({"max": 1})).unwrap(),
        );
        let policy_path = dir.path().join("policy.json");
        std::fs::write(&policy_path, serde_json::to_string(&policy).unwrap()).unwrap();
        let outputs = dir.path().join("outputs");
        std::fs::create_dir(&outputs).unwrap();
        let collected = dir.path().join("collected.json");
        let args = Args {
            policy: policy_path,
            outputs: outputs.clone(),
            collected: collected.clone(),
        };
        let read = || -> Value {
            serde_json::from_str(&std::fs::read_to_string(&collected).unwrap()).unwrap()
        };

        assert_eq!(run(&args).unwrap(), Exit::Success);
        assert_eq!(read(), json!({"items": [], "errors": []}));

        std::fs::write(
            outputs.join(OUTPUTS_FILE),
            "{\"type\":\"noop\",\"message\":\"Done, @someone\"}\n{\"type\":\"add_comment\",\"body\":\"x\"}\n",
        )
        .unwrap();
        assert_eq!(run(&args).unwrap(), Exit::Failure);
        assert_eq!(
            read(),
            json!({
                "items": [{"type": "noop", "message": "Done, `@someone`"}],
                "errors": ["Line 2: Unexpected output type 'add_comment'. Expected one of: noop"],
            })
        );

        // Not through a link the agent's machine planted, nor past the cap.
        std::fs::remove_file(outputs.join(OUTPUTS_FILE)).unwrap();
        std::os::unix::fs::symlink(&args.policy, outputs.join(OUTPUTS_FILE)).unwrap();
        let err = run(&args).unwrap_err().to_string();
        assert!(err.ends_with("is not a regular file"), "{err}");
        std::fs::remove_file(outputs.join(OUTPUTS_FILE)).unwrap();
        let big = usize::try_from(MAX_OUTPUTS_BYTES).unwrap() + 1;
        std::fs::write(outputs.join(OUTPUTS_FILE), "\n".repeat(big)).unwrap();
        let err = run(&args).unwrap_err().to_string();
        assert!(err.contains("over 1048576"), "{err}");
    }

    /// The collector is told of a secondary pull request in its count.
    #[test]
    fn the_policy_as_the_collector_takes_it() {
        let mut policy = crate::policy::tests::policy();
        let max = |config: &Map<String, Value>| config["create_pull_request"]["max"].clone();
        assert_eq!(max(&config(&policy).unwrap()), json!(1));
        policy.secondary_pull_request = Some(crate::policy::Secondary {
            repo: "o/tool".into(),
            clone_url: "https://example.invalid/o/tool".into(),
            base: "main".into(),
            branch_prefix: "agentic-job/".into(),
            max: 1,
            max_patch_bytes: 1 << 20,
            max_patch_files: 3,
            protected_files: Vec::new(),
            protect_top_level_dot_folders: true,
            unprotected_dot_folders: Vec::new(),
            protected_paths: Vec::new(),
        });
        assert_eq!(max(&config(&policy).unwrap()), json!(2));
    }
}
