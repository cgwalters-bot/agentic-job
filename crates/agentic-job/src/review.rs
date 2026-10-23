//! Trusted workflow-side review routing, never run from the reviewed head.
//!
//! Dispatch has no event admission. Validate its request before the workflow
//! reads the forge, then bind the returned PR to the requested repository and
//! base. Only its exact commit may reach the sandbox, not a fork's branch name.

use std::path::PathBuf;
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde_json::{Value, json};

use crate::{exit::Exit, files};

// Only a single PR response, not a list or diff. Refuse an unexpectedly large
// payload rather than let forge-controlled text exhaust the policy job.
const MAX_PULL_BYTES: u64 = 4 << 20;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
static REPO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").expect("valid pattern"));
static SHA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{40}$").expect("valid pattern"));

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Validate the dispatch environment and print the read-only API target
    DispatchTarget,
    /// Bind the API response to that dispatch and print the exact reviewed SHA
    ResolveDispatch {
        #[arg(long, value_name = "FILE")]
        pull_request: PathBuf,
    },
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        let request = Dispatch::from_env()?;
        match self {
            Self::DispatchTarget => {
                let (owner, repo) = request.repo.split_once('/').context("repository owner")?;
                println!(
                    "{}",
                    json!({"owner": owner, "repo": repo, "pull_number": request.item})
                );
            }
            Self::ResolveDispatch { pull_request } => {
                let bytes = files::read_regular(pull_request, MAX_PULL_BYTES)
                    .context("reading dispatched review pull request")?;
                let pull = serde_json::from_slice(&bytes)
                    .context("parsing dispatched review pull request")?;
                println!("{}", request.resolve(&pull)?);
            }
        }
        Ok(Exit::Success)
    }
}

struct Dispatch {
    repo: String,
    base: String,
    item: u64,
}

impl Dispatch {
    fn from_env() -> Result<Self> {
        Self::read(|key| std::env::var(key).unwrap_or_default())
    }

    fn read(env: impl Fn(&str) -> String) -> Result<Self> {
        let repo = env("REPO");
        let item = env("ITEM");
        let number = item
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0 && *n <= MAX_SAFE_INTEGER && n.to_string() == item);
        ensure!(
            env("REVIEW") == "true"
                && env("EVENT") == "false"
                && env("KIND") == "analysis"
                && env("OUTPUTS") == "add_comment,noop"
                && env("MAX_OUTPUTS") == "1"
                && env("NOTIFY") == "none"
                && env("APPLY_PARTIAL") == "false"
                && (env("OUTPUT_REPO").is_empty() || env("OUTPUT_REPO") == repo)
                && env("TARGET") == item
                && number.is_some()
                && REPO.is_match(&repo),
            "Dispatch review requires one verdict or noop on the selected PR, analysis only, no event, notifications or partial apply"
        );
        Ok(Self {
            repo,
            base: env("BASE"),
            item: number.context("dispatch pull request number")?,
        })
    }

    fn resolve<'a>(&self, pull: &'a Value) -> Result<&'a str> {
        let head = pull["head"]["sha"].as_str().unwrap_or_default();
        ensure!(
            pull["number"].as_u64() == Some(self.item)
                && pull["state"] == "open"
                && pull["base"]["ref"] == self.base
                && pull["base"]["repo"]["full_name"] == self.repo
                && SHA.is_match(head),
            "Dispatch review requires an open PR on the configured base with an exact head SHA"
        );
        // A fork (even a deleted one) adds no authority: its repository and
        // author-controlled ref are deliberately not used to select the code.
        Ok(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment() -> Value {
        json!({"REVIEW":"true", "EVENT":"false", "KIND":"analysis",
            "OUTPUTS":"add_comment,noop", "MAX_OUTPUTS":"1", "NOTIFY":"none",
            "APPLY_PARTIAL":"false", "ITEM":"147", "TARGET":"147",
            "REPO":"o/r", "BASE":"main"})
    }

    fn request(env: &Value) -> Result<Dispatch> {
        Dispatch::read(|key| env[key].as_str().unwrap_or_default().to_owned())
    }

    #[test]
    fn dispatch_cannot_add_authority_or_retarget_the_review() {
        let original = environment();
        assert!(request(&original).is_ok());
        let mut same_repo = original.clone();
        same_repo["OUTPUT_REPO"] = json!("o/r");
        assert!(request(&same_repo).is_ok());
        for changes in [
            json!({"TARGET":"*"}),
            json!({"ITEM":"01", "TARGET":"01"}),
            json!({"ITEM":"0", "TARGET":"0"}),
            json!({"ITEM":"9007199254740992", "TARGET":"9007199254740992"}),
            json!({"KIND":"branch"}),
            json!({"OUTPUTS":"all"}),
            json!({"MAX_OUTPUTS":"3"}),
            json!({"EVENT":"true"}),
            json!({"REVIEW":"false"}),
            json!({"OUTPUT_REPO":"other/repo"}),
            json!({"NOTIFY":"comment"}),
            json!({"APPLY_PARTIAL":"true"}),
            json!({"REPO":"o/r/evil"}),
        ] {
            let mut env = original.clone();
            env.as_object_mut()
                .unwrap()
                .extend(changes.as_object().unwrap().clone());
            assert!(request(&env).is_err(), "{changes}");
        }
    }

    #[test]
    fn only_the_requested_open_pr_on_the_configured_base_supplies_a_sha() {
        let request = request(&environment()).unwrap();
        let sha = "a".repeat(40);
        let original = json!({"number":147, "state":"open",
            "base":{"ref":"main", "repo":{"full_name":"o/r"}},
            "head":{"sha":sha}});
        for repo in [
            json!({"full_name":"o/r"}),
            json!({"full_name":"fork/r"}),
            Value::Null,
        ] {
            let mut pull = original.clone();
            pull["head"]["repo"] = repo;
            pull["head"]["ref"] = json!("--upload-pack=evil");
            assert_eq!(request.resolve(&pull).unwrap(), sha);
        }
        for (pointer, replacement) in [
            ("/state", json!("closed")),
            ("/number", json!(148)),
            ("/number", json!("147")),
            ("/head", Value::Null),
            ("/head/sha", json!("--evil")),
            ("/head/sha", json!("A".repeat(40))),
            ("/head/sha", json!("a".repeat(39))),
            ("/base", Value::Null),
            ("/base/ref", json!("other")),
            ("/base/repo/full_name", json!("other/r")),
        ] {
            let mut pull = original.clone();
            *pull.pointer_mut(pointer).unwrap() = replacement;
            assert!(request.resolve(&pull).is_err(), "{pointer}: {pull}");
        }
    }
}
