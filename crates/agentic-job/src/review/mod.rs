//! Trusted workflow-side review routing, never run from the reviewed head.
//!
//! Dispatch has no event admission. Validate its request before the workflow
//! reads the forge, then bind the returned PR to the requested repository and
//! base. Only its exact commit may reach the sandbox, not a fork's branch name.
//! review.yml's own dispatch (`pr`, `head`, `pool`) also names the head the
//! review is for: the PR must not be a draft and must still be at that head,
//! and its pool must have resolved, from the caller's configuration alone,
//! to a supported agent and a model.
//!
//! An event review is admitted by `event` first; `admit` narrows that
//! decision, never widening it, and writes any event decision's outputs for
//! the policy job.
//! `task` writes the reviewer's task from the trusted checkout
//! of the default branch, with the owner's merge policy after it.
//!
//! After the agent, `verdict` and `fold` read check's output (verdict.rs),
//! and `submit` and `status` post the checked verdict (submit.rs). In place
//! of the agent, `carry` may carry the previous head's approval (carry.rs).
//! Before it, `history` may write the earlier reviews it reads (history.rs).
//! With REVIEW_DRAFT_CLASSIFIER, a dispatched review is of a draft, and
//! its verdict carries a checked classifier result (classifier.rs).

mod carry;
mod classifier;
pub mod history;
mod submit;
mod verdict;

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
// The collector's or check's output, as check bounds what it collects.
const MAX_OUTPUT_BYTES: u64 = 4 * crate::check::MAX_OUTPUTS_BYTES;
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
// file, as to CODEOWNERS (crates/safe-outputs/src/check/patch.rs), so no agent can propose its
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
// The verdict alone, `OUTPUTS/MAX_OUTPUTS`, as dispatch.yml's review asks.
const VERDICT_ONLY: &str = "add_comment,noop/1";

/// The verdict and its inline comments, `OUTPUTS/MAX_OUTPUTS`, as review.yml
/// asks.
fn inline_request() -> String {
    format!(
        "add_comment,noop,{REVIEW_COMMENT}/{}",
        1 + REVIEW_COMMENTS_MAX
    )
}

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Validate the dispatch environment and print the read-only API target
    DispatchTarget,
    /// Bind the API response to that dispatch and print the exact reviewed SHA
    ResolveDispatch {
        #[arg(long, value_name = "FILE")]
        pull_request: PathBuf,
    },
    /// Append an event decision's outputs to OUTPUT and print its summary
    /// line, removing the task beside a refused decision; with `--base`,
    /// first narrow the decision, in place, to a review of an exact pull
    /// request head
    Admit {
        /// The decision `agentic-job event` wrote
        #[arg(long, value_name = "FILE")]
        decision: PathBuf,
        /// A review's configured base branch
        #[arg(long)]
        base: Option<String>,
        /// The step's $GITHUB_OUTPUT
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Check the review request in the environment and print the review task
    /// from the current directory, followed by its merge policy, and for a
    /// dispatch with a requested head the pull request it reviews
    Task {
        /// The task file, relative to the current directory
        file: String,
        /// A dispatch's pull request, as `resolve-dispatch` read it
        #[arg(long, value_name = "FILE")]
        pull_request: Option<PathBuf>,
    },
    /// Check the collected output is one verdict comment on the target, or
    /// a noop, and print the verdict: APPROVE, CHANGES or nothing
    Verdict {
        /// The collector's output
        #[arg(long, value_name = "FILE")]
        collected: PathBuf,
        /// The triggering pull request's number
        #[arg(long)]
        target: String,
        /// A draft classifier review's pull request, as `resolve-dispatch`
        /// read it, which its result must name
        #[arg(long, value_name = "FILE")]
        pull_request: Option<PathBuf>,
        /// Where a refusal is written as check's report, `{ok, errors}`
        #[arg(long, value_name = "FILE")]
        report: PathBuf,
    },
    /// Print check's accepted output with the inline findings folded into
    /// the verdict comment, as apply posts it
    Fold {
        #[arg(value_name = "FILE")]
        accepted: PathBuf,
    },
    /// Append `from` and `why` to OUTPUT when the pull request's new head
    /// carries the previous head's approval: a rebase onto the base, or
    /// rustfmt's output, of it; nothing when the review is to run
    Carry {
        /// The step's $GITHUB_OUTPUT
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Write the pull request's earlier verdicts by the review job, their
    /// findings and the replies to them, the commits since each and the
    /// conversation's comments, by the bot and people with write access,
    /// sanitized, as the review agent's review-history.json
    History {
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Submit the checked verdict in the environment, or the approval it
    /// carried, as the pull request's review, and append its URL, or none,
    /// to OUTPUT as `review-url`
    Submit {
        /// Check's accepted output; none for a carried approval
        #[arg(long, value_name = "FILE")]
        accepted: Option<PathBuf>,
        /// The step's $GITHUB_OUTPUT
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Set the commit status `review` on the reviewed head from the jobs'
    /// results in the environment
    Status,
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
                println!("{}", request.resolve(&read_pull(pull_request)?)?);
            }
            Self::Admit {
                decision,
                base,
                output,
            } => println!("{}", admit_event(decision, base.as_deref(), output)?),
            Self::Task { file, pull_request } => {
                // An event review's request, or review.yml's dispatch, which
                // the dispatch step checks again the same way, with the pull
                // request it bound; an event's text follows from `event`.
                let dispatched = if env("EVENT") == "false" {
                    let request = Dispatch::read(env)?;
                    let pull = read_pull(
                        pull_request
                            .as_deref()
                            .context("A dispatched review's task needs --pull-request")?,
                    )?;
                    ensure!(
                        request.head.is_some(),
                        "A dispatched review's task is for a requested head only"
                    );
                    request.resolve(&pull)?;
                    let classifier = request
                        .classifier
                        .then(|| classifier::Bound::of_pull(&pull).map(|b| classifier::task(&b)))
                        .transpose()?;
                    Some((classifier, request.context(&pull)))
                } else {
                    ensure!(
                        pull_request.is_none(),
                        "An event review's pull request comes from its event"
                    );
                    check_request(env)?;
                    None
                };
                let root = Path::new(".");
                let mut task = task_file(root, file)?;
                task.push_str(&merge_statement(merge_policy(root)?));
                if let Some((classifier, context)) = dispatched {
                    task.extend(classifier);
                    task.push('\n');
                    task.push_str(&context);
                }
                print!("{task}");
            }
            Self::Verdict {
                collected,
                target,
                pull_request,
                report,
            } => {
                let bound = match (classifier::enabled(&env)?, pull_request) {
                    (true, Some(pull)) => Some(classifier::Bound::of_pull(&read_pull(pull)?)?),
                    (false, None) => None,
                    _ => bail!(
                        "A draft classifier review's verdict, and only its, needs --pull-request"
                    ),
                };
                let checked = read_output(collected).and_then(|output| {
                    let verdict = verdict::check_outputs(&output, target, bound.is_some())?;
                    if let (Some(bound), Some(_)) = (&bound, verdict) {
                        ensure!(
                            target == &bound.pr.to_string(),
                            "A draft classifier review's target must be its pull request"
                        );
                        let result = classifier::bound_result(&output, bound)?;
                        // Counts and fixed words only, never agent text.
                        let kind = if result.quick() {
                            "may be quick"
                        } else {
                            "is deep"
                        };
                        eprintln!("::notice::The draft classifier result {kind} for the pass");
                    }
                    Ok(verdict)
                });
                match checked {
                    Ok(verdict) => println!("{}", verdict::Verdict::word(verdict)),
                    Err(err) => {
                        let refusal = json!({"ok": false, "errors": [err.to_string()]});
                        std::fs::write(report, refusal.to_string())
                            .with_context(|| format!("writing {}", report.display()))?;
                        eprintln!("::error::{err}");
                        return Ok(Exit::Failure);
                    }
                }
            }
            Self::Fold { accepted } => println!("{}", verdict::fold(read_output(accepted)?)),
            Self::Carry { output } => {
                carry::carry(&env, &submit::Github::from_env(&env)?, output)?;
            }
            Self::History { output } => {
                history::write(&env, &submit::Github::from_env(&env)?, output)?;
            }
            Self::Submit { accepted, output } => {
                let accepted = accepted.as_deref().map(read_output).transpose()?;
                let api = submit::Github::from_env(&env)?;
                let url = submit::submit(&env, accepted.as_ref(), &api)?;
                submit::write_output(output, &url)?;
            }
            Self::Status => submit::report_status(&env, &submit::Github::from_env(&env)?)?,
        }
        Ok(Exit::Success)
    }
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

/// A dispatched review's pull request, as the policy job read it.
fn read_pull(path: &Path) -> Result<Value> {
    let bytes = files::read_regular(path, MAX_PULL_BYTES)
        .context("reading dispatched review pull request")?;
    serde_json::from_slice(&bytes).context("parsing dispatched review pull request")
}

/// The collector's or check's output, `{items, errors}`.
fn read_output(path: &Path) -> Result<Value> {
    let bytes = files::read_regular(path, MAX_OUTPUT_BYTES)
        .with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// The policy job's event step: the decision, narrowed where the run is a
/// review, as the outputs later jobs route by, and its summary line. A
/// refused decision leaves no task behind for a later step to pick up.
fn admit_event(path: &Path, base: Option<&str>, output: &Path) -> Result<String> {
    let bytes =
        files::read_regular(path, MAX_DECISION_BYTES).context("reading the event decision")?;
    let mut decision: Value =
        serde_json::from_slice(&bytes).context("parsing the event decision as JSON")?;
    if let Some(base) = base {
        decision = admit(decision, base);
        std::fs::write(path, serde_json::to_vec_pretty(&decision)?)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    let admitted = decision["admitted"] == true;
    // A line break in a value would start another output.
    let reason = decision["reason"]
        .as_str()
        .unwrap_or_default()
        .replace(char::is_control, " ");
    let item = match decision["item"]["number"].as_u64() {
        Some(number) if admitted => number.to_string(),
        _ => String::new(),
    };
    // `admit` let through only a SHA.
    let head = match decision["head"]["sha"].as_str() {
        Some(sha) if admitted && base.is_some() => sha,
        _ => "",
    };
    let mut lines =
        format!("admitted={admitted}\nreason={reason}\nitem={item}\nreview-head={head}\n");
    if !admitted {
        let task = path
            .parent()
            .context("the event decision's directory")?
            .join(crate::event::TASK_FILE);
        match std::fs::remove_file(&task) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).with_context(|| format!("removing {}", task.display())),
        }
        // What review.yml's refusal job posts: a reason can name event
        // fields, so it is kept inert and on one line.
        if base.is_some() {
            lines.push_str(&format!("refusal={}\n", verdict::refusal_text(&reason)));
        }
    }
    std::fs::OpenOptions::new()
        .append(true)
        .open(output)
        .and_then(|mut file| std::io::Write::write_all(&mut file, lines.as_bytes()))
        .with_context(|| format!("writing {}", output.display()))?;
    let word = if admitted { "admitted" } else { "refused" };
    Ok(format!("agentic-job event: {word}, {reason}"))
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
    ensure!(
        env("EVENT") == "true"
            && env("KIND") == "analysis"
            && (request == inline_request() || request == VERDICT_ONLY)
            && env("NOTIFY") == "none"
            && env("TARGET").is_empty()
            && env("REPO") == env("GITHUB_REPOSITORY")
            && env("OUTPUT_REPO").is_empty()
            && env("APPLY_ENVIRONMENT").is_empty()
            && env("APPLY_PARTIAL") == "false"
            && REVIEW_AGENTS.contains(&env("AGENT").as_str()),
        "Review requires an analysis event run, one comment or noop and its inline comments on the triggering repository, no notifications, alternate token or partial application, and a supported agent"
    );
    ensure!(
        !classifier::enabled(&env)?,
        "A draft classifier review is a dispatch of a requested head, not an event review"
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
    /// The head review.yml's dispatch names, which the PR must still be at;
    /// none for dispatch.yml's review, which reviews whatever head it reads.
    head: Option<String>,
    /// A draft classifier review, which the caller opted into: of a draft
    /// only, where any other review is of a pull request that is not.
    classifier: bool,
}

impl Dispatch {
    fn from_env() -> Result<Self> {
        Self::read(env)
    }

    fn read(env: impl Fn(&str) -> String) -> Result<Self> {
        let repo = env("REPO");
        let item = env("ITEM");
        let number = item
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0 && *n <= MAX_SAFE_INTEGER && n.to_string() == item);
        let head = Some(env("REQUESTED_HEAD")).filter(|head| !head.is_empty());
        let request = format!("{}/{}", env("OUTPUTS"), env("MAX_OUTPUTS"));
        // Inline comments only where review.yml asks, which names a head.
        let outputs = request == VERDICT_ONLY || (head.is_some() && request == inline_request());
        ensure!(
            env("REVIEW") == "true"
                && env("EVENT") == "false"
                && env("KIND") == "analysis"
                && outputs
                && env("NOTIFY") == "none"
                && env("APPLY_PARTIAL") == "false"
                && (env("OUTPUT_REPO").is_empty() || env("OUTPUT_REPO") == repo)
                && env("TARGET") == item
                && number.is_some()
                && REPO.is_match(&repo),
            "Dispatch review requires one verdict or noop (and inline comments, for a requested head) on the selected positive PR number, analysis only, no event, notifications or partial apply"
        );
        if let Some(head) = &head {
            ensure!(
                SHA.is_match(head),
                "Dispatched review head must be a full 40-hex commit SHA"
            );
            // The pool's agent and model, which the workflow looked up in the
            // caller's configuration: empty where it has no such pool. The
            // dispatcher names a pool, never a model or an endpoint.
            ensure!(
                REVIEW_AGENTS.contains(&env("AGENT").as_str()) && !env("MODEL").is_empty(),
                "Dispatched review pool is unknown: the caller's pool configuration (review.yml's REVIEW_POOLS) must map it to a supported agent and a model"
            );
        }
        let classifier = classifier::enabled(&env)?;
        // Its verdict alone: an inline comment would take a finding out of
        // the body the pass reads, so check refuses one.
        ensure!(
            !classifier || (head.is_some() && request == VERDICT_ONLY),
            "A draft classifier review is review.yml's dispatch of a requested head, for one verdict or noop"
        );
        Ok(Self {
            repo,
            base: env("BASE"),
            item: number.context("dispatch pull request number")?,
            head,
            classifier,
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
        if let Some(requested) = &self.head {
            // As an event review, which waits for ready_for_review; a draft
            // classifier review is of a draft, with its title and body.
            if self.classifier {
                classifier::Bound::of_pull(pull)?;
            } else {
                ensure!(
                    pull["draft"] == false,
                    "Dispatched review requires a pull request that is not a draft"
                );
            }
            // A push since the dispatch supersedes it: its verdict would be
            // for a head nobody asked about, and a later dispatch reviews
            // the new one.
            ensure!(
                head == requested,
                "Dispatched review of {requested} refused: the pull request's head is now {head}"
            );
        }
        // A fork (even a deleted one) adds no authority: its repository and
        // author-controlled ref are deliberately not used to select the code.
        Ok(head)
    }

    /// What an event review's task says of its pull request, for one this
    /// request bound: its number and head, then its title and body, fenced
    /// as the forge's text, which ends the task.
    fn context(&self, pull: &Value) -> String {
        let head = self.head.as_deref().unwrap_or_default();
        let mut out = format!(
            "This review was dispatched for pull request #{} of {}. The pull request's head can be fetched from the repository as refs/pull/{}/head, at commit {head}.\n\n",
            self.item, self.repo, self.item
        );
        out.push_str(crate::event::context::UNTRUSTED);
        for (name, key) in [
            ("The pull request's title", "title"),
            ("The pull request's body", "body"),
        ] {
            if let Some(text) = pull[key].as_str() {
                out.push_str(&crate::event::context::fenced(name, text));
            }
        }
        out
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
        // Without a requested head, a draft is reviewed as before.
        let mut draft = original.clone();
        draft["draft"] = json!(true);
        assert_eq!(request.resolve(&draft).unwrap(), sha);
    }

    /// review.yml's dispatch: `pr`, `head` and the pool's agent and model.
    fn requested() -> Value {
        merged(
            &environment(),
            &json!({"OUTPUTS":"add_comment,noop,create_pull_request_review_comment",
                "MAX_OUTPUTS":"11", "REQUESTED_HEAD":"a".repeat(40),
                "AGENT":"opencode", "MODEL":"praxis/gpt-6.1-sol"}),
        )
    }

    #[test]
    fn a_requested_head_needs_an_exact_sha_and_a_known_pool() {
        let original = requested();
        assert_eq!(request(&original).unwrap().head, Some("a".repeat(40)));
        // The verdict alone, too.
        let verdict = merged(
            &original,
            &json!({"OUTPUTS":"add_comment,noop", "MAX_OUTPUTS":"1"}),
        );
        assert!(request(&verdict).is_ok());
        for (changes, want) in [
            (json!({"REQUESTED_HEAD":"a".repeat(39)}), "40-hex"),
            (json!({"REQUESTED_HEAD":"A".repeat(40)}), "40-hex"),
            (json!({"REQUESTED_HEAD":"main"}), "40-hex"),
            (json!({"REQUESTED_HEAD":"--upload-pack=evil"}), "40-hex"),
            (
                json!({"REQUESTED_HEAD":format!("{}\n", "a".repeat(40))}),
                "40-hex",
            ),
            // An unknown pool resolves to nothing; a model alone is no pool.
            (json!({"AGENT":"", "MODEL":""}), "pool is unknown"),
            (json!({"AGENT":"opencode", "MODEL":""}), "pool is unknown"),
            (json!({"AGENT":"unknown"}), "pool is unknown"),
            (json!({"ITEM":"0", "TARGET":"0"}), "positive PR number"),
            (json!({"ITEM":"", "TARGET":""}), "positive PR number"),
            (json!({"ITEM":"-1", "TARGET":"-1"}), "positive PR number"),
            (json!({"ITEM":"1e3", "TARGET":"1e3"}), "positive PR number"),
            (json!({"MAX_OUTPUTS":"12"}), "positive PR number"),
            (json!({"EVENT":"true"}), "positive PR number"),
        ] {
            let err = request(&merged(&original, &changes)).err();
            let err = err.map(|e| e.to_string()).unwrap_or_default();
            assert!(err.contains(want), "{changes}: {err}");
        }
        // Inline comments are review.yml's, which always names a head.
        let mut unrequested = original.clone();
        unrequested["REQUESTED_HEAD"] = json!("");
        assert!(request(&unrequested).is_err());
    }

    #[test]
    fn a_requested_head_binds_an_open_ready_pr_still_at_that_head() {
        let request = request(&requested()).unwrap();
        let sha = "a".repeat(40);
        let original = json!({"number":147, "state":"open", "draft":false,
            "base":{"ref":"main", "repo":{"full_name":"o/r"}},
            "head":{"sha":sha}});
        assert_eq!(request.resolve(&original).unwrap(), sha);
        for (pointer, replacement, want) in [
            ("/draft", json!(true), "not a draft"),
            ("/draft", Value::Null, "not a draft"),
            ("/head/sha", json!("b".repeat(40)), "head is now"),
            ("/state", json!("closed"), "open PR"),
            ("/base/ref", json!("other"), "configured base"),
        ] {
            let mut pull = original.clone();
            *pull.pointer_mut(pointer).unwrap() = replacement;
            let err = request.resolve(&pull).unwrap_err().to_string();
            assert!(err.contains(want), "{pointer}: {err}");
        }
    }

    // Off by default, a draft is refused as above; the caller's opt-in
    // admits a draft, and only a draft, at the requested head, and never
    // an event review or one without a requested head.
    #[test]
    fn only_an_opted_in_dispatch_reviews_a_draft() {
        let opted = merged(
            &requested(),
            &json!({"REVIEW_DRAFT_CLASSIFIER": "true", "OUTPUTS": "add_comment,noop", "MAX_OUTPUTS": "1"}),
        );
        let dispatch = request(&opted).unwrap();
        let pull = classifier::tests::draft("o/r", 147);
        assert_eq!(dispatch.resolve(&pull).unwrap(), classifier::tests::HEAD);
        for (pointer, replacement, want) in [
            ("/draft", json!(false), "open draft"),
            ("/title", Value::Null, "open draft"),
            ("/head/sha", json!("b".repeat(40)), "head is now"),
            ("/state", json!("closed"), "open PR"),
            ("/base/ref", json!("other"), "configured base"),
        ] {
            let mut changed = pull.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            let err = dispatch.resolve(&changed).unwrap_err().to_string();
            assert!(err.contains(want), "{pointer}: {err}");
        }
        for (changes, want) in [
            (json!({"REQUESTED_HEAD": ""}), "requested head"),
            // Inline comments would take findings out of the result's body.
            (
                json!({"OUTPUTS": "add_comment,noop,create_pull_request_review_comment", "MAX_OUTPUTS": "11"}),
                "one verdict or noop",
            ),
            (json!({"REVIEW_DRAFT_CLASSIFIER": "yes"}), "must be true"),
        ] {
            let err = request(&merged(&opted, &changes)).err().unwrap();
            assert!(err.to_string().contains(want), "{changes}: {err}");
        }
        let event = json!({"EVENT":"true", "KIND":"analysis", "OUTPUTS":"add_comment,noop",
            "MAX_OUTPUTS":"1", "NOTIFY":"none", "REPO":"o/r", "GITHUB_REPOSITORY":"o/r",
            "APPLY_PARTIAL":"false", "AGENT":"fake", "REVIEW_DRAFT_CLASSIFIER":"true"});
        let err = check_request(|key| event[key].as_str().unwrap_or_default().to_owned());
        assert!(err.unwrap_err().to_string().contains("not an event review"));
    }
}
