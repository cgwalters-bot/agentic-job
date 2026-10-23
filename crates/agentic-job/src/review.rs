//! Trusted workflow-side review routing, never run from the reviewed head.
//!
//! Dispatch has no event admission. Validate its request before the workflow
//! reads the forge, then bind the returned PR to the requested repository and
//! base. Only its exact commit may reach the sandbox, not a fork's branch name.
//!
//! An event review is admitted by `event` first; `admit` only narrows that
//! decision, and `task` writes the reviewer's task from the trusted checkout
//! of the default branch, with the owner's merge policy after it.

use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use serde_json::{Value, json};

use crate::{exit::Exit, files};

// Only a single PR response, not a list or diff. Refuse an unexpectedly large
// payload rather than let forge-controlled text exhaust the policy job.
const MAX_PULL_BYTES: u64 = 4 << 20;
// The decision `event` wrote, which holds no event text beyond its fields.
const MAX_DECISION_BYTES: u64 = 1 << 20;
const MAX_TASK_BYTES: u64 = 64 << 10;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
static REPO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").expect("valid pattern"));
static SHA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{40}$").expect("valid pattern"));

// The repository owner's merge policy, read from the same trusted checkout
// of the default branch as the task (policy.yml), never the head. It used to
// live only in prose (the task and operator notes), so reviewers at older
// pins kept arguing whether a person should be required (#556). One line,
// `merge = "agent"` or `merge = "person"`, among blank lines and comments;
// anything else fails the run rather than guess. No file is `person`, which
// `set` tells apart from the owner's choice. Check refuses a patch to this
// file, as to CODEOWNERS (src/check/patch.rs), so no agent can propose its
// own merge authority.
const MERGE_POLICY_FILE: &str = ".github/agentic-job/merge.toml";
const MAX_MERGE_POLICY_BYTES: u64 = 4096;
static MERGE_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^merge = "(agent|person)"\s*$"#).expect("valid pattern"));
static MERGE_BLANK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(#.*)?$").expect("valid pattern"));

// Inline findings next to the verdict (#516), at most this many.
const REVIEW_COMMENT: &str = "create_pull_request_review_comment";
const REVIEW_COMMENTS_MAX: usize = 10;
const REVIEW_AGENTS: [&str; 4] = ["fake", "claude", "opencode", "vibe"];

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Validate the dispatch environment and print the read-only API target
    DispatchTarget,
    /// Bind the API response to that dispatch and print the exact reviewed SHA
    ResolveDispatch {
        #[arg(long, value_name = "FILE")]
        pull_request: PathBuf,
    },
    /// Narrow an event's admission decision to a review of an exact pull request head
    Admit {
        /// The decision `agentic-job event` wrote
        #[arg(long, value_name = "FILE")]
        decision: PathBuf,
        /// The configured base branch
        #[arg(long)]
        base: String,
    },
    /// Check the review request in the environment and print the review task
    /// from the current directory, followed by its merge policy
    Task {
        /// The task file, relative to the current directory
        file: String,
    },
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        match self {
            Self::DispatchTarget => {
                let request = Dispatch::from_env()?;
                let (owner, repo) = request.repo.split_once('/').context("repository owner")?;
                println!(
                    "{}",
                    json!({"owner": owner, "repo": repo, "pull_number": request.item})
                );
            }
            Self::ResolveDispatch { pull_request } => {
                let request = Dispatch::from_env()?;
                let bytes = files::read_regular(pull_request, MAX_PULL_BYTES)
                    .context("reading dispatched review pull request")?;
                let pull = serde_json::from_slice(&bytes)
                    .context("parsing dispatched review pull request")?;
                println!("{}", request.resolve(&pull)?);
            }
            Self::Admit { decision, base } => {
                let bytes = files::read_regular(decision, MAX_DECISION_BYTES)
                    .context("reading the event decision")?;
                let decision =
                    serde_json::from_slice(&bytes).context("parsing the event decision")?;
                println!("{}", admit(decision, base));
            }
            Self::Task { file } => {
                check_request(|key| std::env::var(key).unwrap_or_default())?;
                let root = Path::new(".");
                let mut task = task_file(root, file)?;
                task.push_str(&merge_statement(merge_policy(root)?));
                print!("{task}");
            }
        }
        Ok(Exit::Success)
    }
}

/// The decision, or the same refused: a review needs an admitted pull
/// request event, or a `review` command on one, on `base` at an exact
/// commit. Run only from the reusable workflow's pinned source.
fn admit(mut decision: Value, base: &str) -> Value {
    if decision["admitted"] != true {
        return decision;
    }
    let event = decision["event"].as_str().unwrap_or_default();
    let action = decision["action"].as_str().unwrap_or_default();
    let valid = decision["item"]["kind"] == "pull_request"
        && decision["item"]["number"]
            .as_u64()
            .is_some_and(|n| n > 0 && n <= MAX_SAFE_INTEGER)
        && decision["base"] == base
        && SHA.is_match(decision["head"]["sha"].as_str().unwrap_or_default())
        && ((matches!(event, "pull_request" | "pull_request_target")
            && matches!(
                action,
                "opened" | "synchronize" | "reopened" | "ready_for_review"
            ))
            || (event == "issue_comment"
                && action == "created"
                && decision["command"] == "review"));
    if !valid && let Some(fields) = decision.as_object_mut() {
        fields.insert("admitted".into(), json!(false));
        fields.insert(
            "reason".into(),
            json!(
                "review requires an admitted pull request on the configured base, at an exact commit"
            ),
        );
    }
    decision
}

/// review.yml's request, or the verdict alone, which CI's e2e-review still
/// makes: it reads the bounds and scripted agent from the pull request's
/// base, so it moves to inline comments only once they are on main.
fn check_request(env: impl Fn(&str) -> String) -> Result<()> {
    let request = format!("{}/{}", env("OUTPUTS"), env("MAX_OUTPUTS"));
    let inline = format!(
        "add_comment,noop,{REVIEW_COMMENT}/{}",
        1 + REVIEW_COMMENTS_MAX
    );
    ensure!(
        env("EVENT") == "true"
            && env("KIND") == "analysis"
            && (request == inline || request == "add_comment,noop/1")
            && env("NOTIFY") == "none"
            && env("TARGET").is_empty()
            && env("REPO") == env("GITHUB_REPOSITORY")
            && env("OUTPUT_REPO").is_empty()
            && env("APPLY_ENVIRONMENT").is_empty()
            && env("APPLY_PARTIAL") == "false"
            && REVIEW_AGENTS.contains(&env("AGENT").as_str()),
        "Review requires an analysis event run, one comment or noop and its inline comments on the triggering repository, no notifications, alternate token or partial application, and a supported agent"
    );
    Ok(())
}

/// The regular file `name` under `root`, through directories that are no
/// links: `None` where nothing is there. A link is refused, not followed.
fn read_under(root: &Path, name: &str, max: u64) -> Result<Option<Vec<u8>>> {
    let mut path = root.to_path_buf();
    let mut parts = Path::new(name).components().peekable();
    while let Some(part) = parts.next() {
        let Component::Normal(part) = part else {
            bail!("{name} must be a relative path without . or ..");
        };
        path.push(part);
        if parts.peek().is_some() {
            match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => bail!("{name} must be a regular file without symlinks"),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(err) => return Err(err).with_context(|| format!("reading {name}")),
            }
        }
    }
    match files::read_regular(&path, max) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(files::ReadError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            bail!("{name} must be a regular file without symlinks, at most {max} bytes: {err}")
        }
    }
}

/// The review task, from a regular file of the trusted checkout.
fn task_file(root: &Path, name: &str) -> Result<String> {
    // An empty part is also an empty or absolute name.
    ensure!(
        name.split('/')
            .all(|p| !p.is_empty() && p != "." && p != ".."),
        "Review task must be a relative repository file"
    );
    const UNREADABLE: &str = "Review task must be a regular file without symlinks, at most 64 KiB";
    let bytes = read_under(root, name, MAX_TASK_BYTES)
        .context(UNREADABLE)?
        .context(UNREADABLE)?;
    let task = String::from_utf8(bytes).context("Review task must be UTF-8")?;
    ensure!(!task.trim().is_empty(), "Review task is empty");
    Ok(task)
}

#[derive(Debug, PartialEq)]
struct MergePolicy {
    /// Whether an approving review merges; otherwise a person approves.
    agent: bool,
    /// Whether the owner set it, rather than the default holding.
    set: bool,
}

fn merge_policy(root: &Path) -> Result<MergePolicy> {
    let Some(bytes) = read_under(root, MERGE_POLICY_FILE, MAX_MERGE_POLICY_BYTES)? else {
        return Ok(MergePolicy {
            agent: false,
            set: false,
        });
    };
    let text =
        String::from_utf8(bytes).with_context(|| format!("{MERGE_POLICY_FILE} must be UTF-8"))?;
    let mut values = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if MERGE_BLANK.is_match(line) {
            continue;
        }
        let Some(value) = MERGE_LINE.captures(line) else {
            bail!(r#"{MERGE_POLICY_FILE} may hold only merge = "agent" or merge = "person""#);
        };
        values.push(&value[1] == "agent");
    }
    let [agent] = values[..] else {
        bail!("{MERGE_POLICY_FILE} must set merge exactly once");
    };
    Ok(MergePolicy { agent, set: true })
}

/// What the reviewer is told, as a fact rather than a question for it to
/// weigh. Either way it reviews as hard: an APPROVE is submitted whatever
/// the policy, and only the ruleset decides what that approval merges. Code
/// owners' paths wait for their owner where the ruleset requires it; the
/// verdict names them so the pull request says why it waits, and names any
/// change to who decides, which a person's pull request can still propose.
fn merge_statement(policy: MergePolicy) -> String {
    let source = if policy.set {
        format!("The repository owner set this in {MERGE_POLICY_FILE} on the default branch")
    } else {
        format!("The default branch has no {MERGE_POLICY_FILE}, so the default holds")
    };
    let who = if policy.agent {
        "merge = \"agent\": an approving review from this job merges the pull request by default, \
         so no person approves after you. Do not ask for changes because no person stands behind \
         a change; review it harder instead, naming the worst merged outcome and what stops it."
    } else {
        "merge = \"person\": the repository expects a person to approve every merge after you. \
         Review as hard as if your approval merged."
    };
    format!(
        "\n\n## Merge policy\n\n{source}; it is a fact, not a question for this review: {who}\n\
         Where the ruleset requires code-owner review, paths that the base's CODEOWNERS file \
         (in .github/, the root or docs/, the first GitHub finds) assigns an owner also wait for that \
         owner, whatever your verdict; you cannot see the ruleset, so review those paths as hard as any \
         other. If the pull request changes any, or changes the merge policy file or a CODEOWNERS file, \
         which changes who decides, add a line after the verdict line: \"Needs the owner's review: \" \
         and those paths.\n"
    )
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

    fn merged(original: &Value, changes: &Value) -> Value {
        let mut value = original.clone();
        value
            .as_object_mut()
            .unwrap()
            .extend(changes.as_object().unwrap().clone());
        value
    }

    #[test]
    fn review_admission_narrows_never_overrides_event_authorization() {
        let decision = json!({"admitted":true, "event":"pull_request_target", "action":"opened",
            "item":{"kind":"pull_request", "number":147}, "base":"main",
            "head":{"sha":"a".repeat(40)}});
        let mut admitted = Vec::new();
        for event in ["pull_request", "pull_request_target"] {
            for action in ["opened", "synchronize", "reopened", "ready_for_review"] {
                admitted.push(json!({"event":event, "action":action}));
            }
        }
        admitted.push(json!({"event":"issue_comment", "action":"created", "command":"review"}));
        for changes in admitted {
            let got = admit(merged(&decision, &changes), "main");
            assert_eq!(got["admitted"], true, "{changes}");
        }
        for changes in [
            json!({"admitted":false}),
            json!({"item":{"kind":"issue", "number":147}}),
            json!({"item":{"kind":"pull_request", "number":"147"}}),
            json!({"item":{"kind":"pull_request", "number":0}}),
            json!({"head":null}),
            json!({"head":{"sha":"--upload-pack=evil"}}),
            json!({"base":"other"}),
            json!({"event":"push"}),
            json!({"action":"closed"}),
            json!({"action":"labeled"}),
            json!({"event":"issue_comment", "action":"created", "command":"agent"}),
        ] {
            let got = admit(merged(&decision, &changes), "main");
            assert_eq!(got["admitted"], false, "{changes}");
        }
        // A refusal keeps the event's own reason.
        let refused = json!({"admitted":false, "reason":"not a member"});
        assert_eq!(admit(refused.clone(), "main"), refused);
    }

    #[test]
    fn review_request_has_no_branch_alternate_target_token_or_notification_authority() {
        let original = json!({"EVENT":"true", "KIND":"analysis",
            "OUTPUTS":"add_comment,noop,create_pull_request_review_comment", "MAX_OUTPUTS":"11",
            "NOTIFY":"none", "REPO":"o/r", "GITHUB_REPOSITORY":"o/r", "APPLY_PARTIAL":"false",
            "AGENT":"fake"});
        let check =
            |env: &Value| check_request(|key| env[key].as_str().unwrap_or_default().to_owned());
        // The verdict alone, as CI's e2e-review asks with the base's bounds.
        let mut accepted = vec![
            json!({}),
            json!({"OUTPUTS":"add_comment,noop", "MAX_OUTPUTS":"1"}),
        ];
        accepted.extend(REVIEW_AGENTS.map(|agent| json!({"AGENT":agent})));
        for changes in accepted {
            assert!(check(&merged(&original, &changes)).is_ok(), "{changes}");
        }
        for changes in [
            json!({"AGENT":""}),
            json!({"AGENT":"unknown"}),
            json!({"EVENT":"false"}),
            json!({"KIND":"branch"}),
            json!({"OUTPUTS":"all"}),
            json!({"MAX_OUTPUTS":"max"}),
            json!({"NOTIFY":"comment"}),
            json!({"TARGET":"*"}),
            // Room for more than ten inline comments, or the two requests mixed.
            json!({"MAX_OUTPUTS":"12"}),
            json!({"MAX_OUTPUTS":"1"}),
            json!({"OUTPUTS":"add_comment,noop"}),
            json!({"OUTPUTS":"add_comment,noop", "MAX_OUTPUTS":"11"}),
            json!({"REPO":"other/repo"}),
            json!({"OUTPUT_REPO":"other/repo"}),
            json!({"APPLY_ENVIRONMENT":"write"}),
            json!({"APPLY_PARTIAL":"true"}),
        ] {
            assert!(check(&merged(&original, &changes)).is_err(), "{changes}");
        }
        // review.yml asks for what check_request takes, and its bounds allow it.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let workflow = std::fs::read_to_string(root.join(".github/workflows/review.yml")).unwrap();
        assert!(workflow.contains(&format!(
            "\n      outputs: {}\n      max-outputs: '{}'\n",
            original["OUTPUTS"].as_str().unwrap(),
            original["MAX_OUTPUTS"].as_str().unwrap()
        )));
        for bounds in ["review.toml", "review-command.toml"] {
            let text = std::fs::read_to_string(root.join("workflow").join(bounds)).unwrap();
            assert!(text.contains("\nmax_outputs = 11\n"), "{bounds}");
            assert!(
                text.contains(&format!(
                    "\n{REVIEW_COMMENT} = {{ max = {REVIEW_COMMENTS_MAX} }}\n"
                )),
                "{bounds}"
            );
        }
    }

    #[test]
    fn merge_policy_comes_from_one_strict_base_file_person_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let unset = MergePolicy {
            agent: false,
            set: false,
        };
        assert_eq!(merge_policy(dir.path()).unwrap(), unset);
        let file = dir.path().join(MERGE_POLICY_FILE);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let large = "x".repeat(4097);
        for (text, want) in [
            ("merge = \"agent\"\n", Ok(true)),
            (
                "# The owner's decision.\n\nmerge = \"person\"  \n",
                Ok(false),
            ),
            ("merge = \"agent\"", Ok(true)),
            ("# Windows lines.\r\nmerge = \"agent\"\r\n", Ok(true)),
            ("\u{feff}merge = \"agent\"\n", Err("may hold only")),
            ("", Err("exactly once")),
            ("# nothing\n", Err("exactly once")),
            (
                "merge = \"agent\"\nmerge = \"agent\"\n",
                Err("exactly once"),
            ),
            (
                "merge = \"agent\"\nmerge = \"person\"\n",
                Err("exactly once"),
            ),
            ("merge = \"anyone\"\n", Err("may hold only")),
            ("merge = 'agent'\n", Err("may hold only")),
            ("merge = \"agent\" # inline\n", Err("may hold only")),
            ("merge=\"agent\"\n", Err("may hold only")),
            ("[review]\nmerge = \"agent\"\n", Err("may hold only")),
            (large.as_str(), Err("at most 4096 bytes")),
        ] {
            std::fs::write(&file, text).unwrap();
            match (merge_policy(dir.path()), want) {
                (Ok(got), Ok(agent)) => assert_eq!(got, MergePolicy { agent, set: true }, "{text}"),
                (Err(err), Err(want)) => {
                    assert!(format!("{err:#}").contains(want), "{text}: {err:#}")
                }
                (got, want) => panic!("{text}: {got:?}, want {want:?}"),
            }
        }
        // Neither a link to a valid policy nor a directory is read.
        std::fs::remove_file(&file).unwrap();
        std::fs::write(dir.path().join("other.toml"), "merge = \"agent\"\n").unwrap();
        std::os::unix::fs::symlink("../../other.toml", &file).unwrap();
        assert!(merge_policy(dir.path()).is_err());
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        assert!(merge_policy(dir.path()).is_err());
    }

    #[test]
    fn the_merge_statement_says_whose_policy_it_is() {
        let agent = merge_statement(MergePolicy {
            agent: true,
            set: true,
        });
        let person = merge_statement(MergePolicy {
            agent: false,
            set: true,
        });
        let unset = merge_statement(MergePolicy {
            agent: false,
            set: false,
        });
        assert!(agent.starts_with("\n\n## Merge policy\n\nThe repository owner set this in .github/agentic-job/merge.toml on the default branch"));
        assert!(agent.contains("merge = \"agent\": an approving review from this job merges"));
        assert!(person.contains("The repository owner set this"));
        assert!(person.contains("merge = \"person\": the repository expects a person"));
        assert!(unset.contains(
            "The default branch has no .github/agentic-job/merge.toml, so the default holds"
        ));
        assert!(!unset.contains("owner set this"));
        for statement in [&person, &unset] {
            assert!(statement.contains("Review as hard as if your approval merged."));
        }
        for statement in [&agent, &person, &unset] {
            assert!(statement.contains("it is a fact, not a question for this review"));
            assert!(statement.contains("\"Needs the owner's review: \" and those paths"));
            assert!(statement.contains("review those paths as hard as any other"));
            assert!(statement.contains("changes the merge policy file or a CODEOWNERS file"));
        }
    }

    #[test]
    fn this_repositorys_merge_policy_and_the_documented_example_parse() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert!(merge_policy(&root).unwrap().set);
        // The example the docs show must be one the parser accepts (#558).
        let docs = std::fs::read_to_string(root.join("docs/review.md")).unwrap();
        let section = &docs[docs.find("### Merge policy").unwrap()..];
        let example = section
            .split("```toml\n")
            .skip(1)
            .map(|block| block.split("```").next().unwrap())
            .find(|block| block.contains("merge = "))
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(MERGE_POLICY_FILE);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, example).unwrap();
        let agent = example.contains("merge = \"agent\"");
        assert_eq!(
            merge_policy(dir.path()).unwrap(),
            MergePolicy { agent, set: true }
        );
    }

    #[test]
    fn task_comes_from_a_bounded_regular_base_file_not_a_link_or_escape() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("task.md"), "Trusted base task").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/task.md"), "Nested task").unwrap();
        std::os::unix::fs::symlink("task.md", dir.path().join("link.md")).unwrap();
        std::os::unix::fs::symlink("sub", dir.path().join("dir")).unwrap();
        assert_eq!(
            task_file(dir.path(), "task.md").unwrap(),
            "Trusted base task"
        );
        assert_eq!(task_file(dir.path(), "sub/task.md").unwrap(), "Nested task");
        for name in [
            "",
            "../task.md",
            "/task.md",
            "./task.md",
            "sub//task.md",
            "link.md",
            "dir/task.md",
            "missing.md",
            "sub",
        ] {
            assert!(task_file(dir.path(), name).is_err(), "{name}");
        }
        std::fs::write(dir.path().join("task.md"), " \n").unwrap();
        assert!(task_file(dir.path(), "task.md").is_err());
        std::fs::write(dir.path().join("task.md"), "x".repeat(65537)).unwrap();
        let err = task_file(dir.path(), "task.md").unwrap_err();
        assert!(format!("{err:#}").contains("64 KiB"), "{err:#}");
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
