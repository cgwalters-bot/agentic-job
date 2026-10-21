//! Producer-side convenience only: trusted capture and check still enforce policy.

use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};

use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::check::replacement::Replacement;
use crate::check::{self, OUTPUTS_FILE};
use crate::config;
use crate::exit::Exit;
use crate::files::ReadError;
use crate::policy::Policy;
use crate::redact;
use crate::run::brief;
use crate::run::clone::Checkout;
use crate::run::enter::Unconfined;
use crate::run::handback::{
    self as capture, AGENT_OUTCOME, AGENT_OUTPUTS, MAX_OUTCOME_BYTES, REPLACEMENT_PATH,
};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Preserve format-patch mails and test the complete series on its base
    Replace {
        #[arg(long)]
        base: String,
        /// Defaults to BASE..HEAD; include every commit to retain
        range: Option<String>,
    },
    /// Find secret-shaped strings in what the run would hand back: the
    /// change against BASE, and the files in `out/` under your home. Exits
    /// 1 only for a private key or a run token, which the run refuses;
    /// others are warnings
    Scan {
        /// The commit the change is made against: the one the run started from
        #[arg(long, default_value = "HEAD")]
        base: String,
    },
    /// Check what this run would hand back now, as the run checks it after
    /// the session: name each problem and how to fix it
    Check,
    /// Print this run's rules for handing back, in full
    Guide,
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        match self {
            Self::Replace { base, range } => {
                let home = std::env::var_os("HOME").context("HOME is not set")?;
                let output = Path::new(&home).join("out/replacement.json");
                replace(Path::new("."), base, range.as_deref(), &output)?;
                eprintln!("Validated replacement written to {}", output.display());
            }
            Self::Scan { base } => {
                let home = std::env::var_os("HOME").context("HOME is not set")?;
                let found = scan(Path::new("."), base, Path::new(&home))?;
                for finding in &found {
                    println!("{finding}");
                }
                let refused = found.iter().filter(|f| f.is_refused()).count();
                if refused > 0 {
                    eprintln!(
                        "{refused} private key(s) or run token(s): `run` refuses everything \
                         this run hands back while one is there. Remove each, or build it at \
                         run time from parts that do not match, then scan again."
                    );
                    return Ok(Exit::Failure);
                }
                if found.is_empty() {
                    eprintln!("No secret-shaped string in the change or in {}", OUT_DIR);
                } else {
                    eprintln!(
                        "{} secret-shaped string(s), kept and reported by line as warnings: \
                         make sure each is a fixture and no real credential.",
                        found.len()
                    );
                }
            }
            Self::Check => {
                let home = std::env::var_os("HOME").context("HOME is not set")?;
                let home = Path::new(&home);
                let report = validate(home, &RunFile::read(home)?)?;
                for note in &report.notes {
                    println!("note: {note}");
                }
                for problem in &report.problems {
                    println!("{problem}");
                }
                if !report.problems.is_empty() {
                    eprintln!(
                        "{} problem(s): the run refuses this hand-back, or loses part of it. \
                         Fix each, then run `agentic-job handback check` again.",
                        report.problems.len()
                    );
                    return Ok(Exit::Failure);
                }
                eprintln!("No problem found in what this run would hand back now.");
            }
            Self::Guide => {
                let home = std::env::var_os("HOME").context("HOME is not set")?;
                let home = Path::new(&home);
                let run = RunFile::read(home)?;
                print!(
                    "{}",
                    brief::guide(&run.policy, home, &run.checkout, &run.base)
                );
            }
        }
        Ok(Exit::Success)
    }
}

/// Where `run` tells `handback check` and `handback guide`, under the
/// agent's home, what they need of the run.
pub const RUN_FILE: &str = ".config/agentic-job/handback.json";

/// Far bigger than a run file: a policy is a few KiB.
const MAX_RUN_FILE_BYTES: u64 = 1 << 20;

/// What [`RUN_FILE`] holds. The agent may change it, and so mislead only
/// itself: `check` reads the policy the run's policy job printed, never
/// this copy.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunFile {
    policy: Policy,
    checkout: PathBuf,
    /// The commit the change is against.
    base: String,
    run_id: String,
    commit: config::Commit,
}

impl RunFile {
    fn read(home: &Path) -> Result<Self> {
        let path = home.join(RUN_FILE);
        let bytes = crate::files::read_regular(&path, MAX_RUN_FILE_BYTES).map_err(|err| {
            anyhow::anyhow!(
                "{} {err}: `agentic-job run` writes it for its agent, and only there do \
                 `handback check` and `handback guide` work",
                path.display()
            )
        })?;
        serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))
    }
}

/// The content of [`RUN_FILE`] for the run of POLICY that started its
/// agent in CHECKOUT. Its clone URLs are no business of the agent's, and
/// nothing of the check reads them.
pub fn run_file(
    policy: &Policy,
    checkout: &Checkout,
    run_id: &str,
    commit: &config::Commit,
) -> Result<String> {
    let policy = Policy {
        clone_url: String::new(),
        context: Vec::new(),
        ..policy.clone()
    };
    let text = serde_json::to_string(&json!({
        "policy": policy,
        "checkout": checkout.dir,
        "base": checkout.base_commit,
        "run_id": run_id,
        "commit": commit,
    }))?;
    Ok(text + "\n")
}

/// Something in the hand-back the run would refuse or lose.
#[derive(Debug, PartialEq, Eq)]
struct Problem {
    /// The file, line or request it is in.
    at: String,
    what: String,
    fix: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}; {}", self.at, self.what, self.fix)
    }
}

#[derive(Debug, Default)]
struct Report {
    problems: Vec<Problem>,
    /// What is not a problem but changes what is handed back.
    notes: Vec<String>,
}

/// How to fix what `check` refuses, by a phrase of its reason (in
/// `check` and `check::patch`). A reason none of them names is pointed at
/// the guide.
const FIXES: &[(&str, &str)] = &[
    (
        "protected",
        "restore each as it was (`git checkout HEAD -- PATH`, or delete it if you added it), \
         and say in your report what you left out",
    ),
    (
        "files, over",
        "change fewer files: restore those the task does not need",
    ),
    (
        "mode change",
        "restore the file's mode (`chmod`), and add no executable",
    ),
    (
        "special file",
        "make it a regular file that is not executable, or restore it",
    ),
    (
        "private key",
        "remove it, or build it at run time from parts that do not match",
    ),
    (
        "run token",
        "remove it, or build it at run time from parts that do not match",
    ),
    (
        "checkpoint",
        "write at most one checkpoint, exactly as `agentic-job handback guide` shows",
    ),
    (
        "which the policy does not allow",
        "remove that request: only the types the brief lists are allowed",
    ),
    (
        "outputs of type",
        "remove requests of that type to its limit",
    ),
    ("over max_outputs", "make fewer requests in all"),
];
const GUIDE_FIX: &str = "fix what it names: `agentic-job handback guide` gives the rule";

fn fix_for(reason: &str) -> &'static str {
    FIXES
        .iter()
        .find(|(phrase, _)| reason.contains(phrase))
        .map_or(GUIDE_FIX, |(_, fix)| fix)
}

/// What the run would refuse or lose of what the agent of RUN, whose
/// home is HOME, would hand back now. It is the run's own code: `run`'s
/// `collect`, on a copy of the checkout, since it commits there, then
/// `check`'s `check_outputs`, then the scan of the final gate's patterns.
/// gh-aw's collector is not here to validate each request's fields
/// (docs/safe-outputs.md): the requests go to `check` as given, so a
/// field the collector refuses is found only after the session.
fn validate(home: &Path, run: &RunFile) -> Result<Report> {
    let mut report = Report::default();
    let policy = &run.policy;
    let outcome = home.join(AGENT_OUTCOME);
    let outcome_fix = "write one JSON object: `{\"summary\": \"...\", \"tests\": [...], \
                       \"stopped_early\": null}`";
    let outcome_problem = |what: String| Problem {
        at: outcome.display().to_string(),
        what,
        fix: outcome_fix.to_owned(),
    };
    // `collect` takes an unreadable report for none; the pull request is
    // then made from no summary, as partial work.
    match crate::files::read_regular(&outcome, MAX_OUTCOME_BYTES as u64) {
        Err(ReadError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            report
                .problems
                .push(outcome_problem("there is no report".to_owned()));
        }
        Err(err) => report.problems.push(outcome_problem(err.to_string())),
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(Value::Object(object)) => {
                if object
                    .get("summary")
                    .and_then(Value::as_str)
                    .is_none_or(|summary| summary.trim().is_empty())
                {
                    report.problems.push(outcome_problem(
                        "there is no `summary`, so what you hand back is taken for partial work"
                            .to_owned(),
                    ));
                }
            }
            _ => report
                .problems
                .push(outcome_problem("it is not one JSON object".to_owned())),
        },
    }

    let checkout = Checkout {
        dir: run.checkout.clone(),
        base_commit: run.base.clone(),
    };
    if capture::requires_output(policy)
        && let Some(why) = capture::output_missing(&Unconfined, home, &checkout, policy)
    {
        report.problems.push(Problem {
            at: "the hand-back".to_owned(),
            what: why,
            fix: "leave a change or a request, as the brief says".to_owned(),
        });
    }

    let scratch = tempfile::tempdir()?;
    let copy = scratch.path().join("checkout");
    match snapshot(&run.checkout, &copy) {
        Err(err) => report.problems.push(Problem {
            at: run.checkout.display().to_string(),
            what: format!("{err:#}"),
            fix: "fix what it names: the check copies the checkout under $TMPDIR".to_owned(),
        }),
        Ok(nested) => {
            for path in nested {
                report.problems.push(Problem {
                    at: path,
                    what: "a nested repository, which the run stages as a submodule and \
                           `check` refuses with the whole change"
                        .to_owned(),
                    fix: "delete it, or move it out of the checkout".to_owned(),
                });
            }
            let (results, outputs) = (scratch.path().join("run"), scratch.path().join("outputs"));
            std::fs::create_dir(&results)?;
            let change = capture::collect(&capture::Request {
                runner: &Unconfined,
                home,
                checkout: &Checkout {
                    dir: copy,
                    base_commit: run.base.clone(),
                },
                policy,
                commit: &run.commit,
                run_id: &run.run_id,
                harness: None,
                run_dir: &results,
                safe_outputs: &outputs,
            })?;
            if let Some(why) = change.dropped {
                report.problems.push(Problem {
                    at: "the change".to_owned(),
                    what: why,
                    fix: GUIDE_FIX.to_owned(),
                });
            }
            if let Some(why) = change.memory_dropped {
                report.problems.push(Problem {
                    at: format!("~/{}", capture::MEMORY_DIR),
                    what: why,
                    fix: "keep only plain text files there, within the policy's [memory] bounds"
                        .to_owned(),
                });
            }
            if outputs.is_dir() {
                let collected = scratch.path().join("collected.json");
                let text = as_collected(&outputs)?;
                std::fs::write(&collected, &text)?;
                report.notes.extend(redacted_links(&text, policy));
                report.problems.extend(over_handler_limits(&text));
                let verdict = check::check_outputs(&outputs, &collected, policy)?;
                report
                    .problems
                    .extend(verdict.errors.iter().map(|error| Problem {
                        at: "check".to_owned(),
                        what: error.clone(),
                        fix: fix_for(error).to_owned(),
                    }));
                if let Some(checkpoint) = verdict.checkpoint {
                    report.notes.push(format!(
                        "the change is handed back as a draft to be continued, at a checkpoint \
                         ({}): when the work is done, set `complete` to true in {}'s checkpoint, \
                         and leave none in your request",
                        checkpoint.reason,
                        outcome.display()
                    ));
                }
            }
        }
    }

    for finding in scan(&run.checkout, &run.base, home)? {
        if let Some(what) = finding.refused() {
            report.problems.push(Problem {
                at: finding.location,
                what: what.to_owned(),
                fix: fix_for(what).to_owned(),
            });
        } else {
            report.notes.push(format!(
                "{finding}: a secret-shaped string, kept and reported as a warning; make sure \
                 it is a fixture and no real credential"
            ));
        }
    }
    Ok(report)
}

/// A note for each request in COLLECTED (as [`as_collected`] writes it)
/// with links gh-aw's collector will redact under POLICY: the reader sees
/// the host and not the link, so the agent can say what it cites another way.
fn redacted_links(collected: &str, policy: &Policy) -> Vec<String> {
    let Ok(Value::Object(result)) = serde_json::from_str::<Value>(collected) else {
        return Vec::new();
    };
    let items = result.get("items").and_then(Value::as_array);
    items
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(number, item)| {
            let hosts = check::links::redacted_hosts(item, policy);
            (!hosts.is_empty()).then(|| {
                format!(
                    "{AGENT_OUTPUTS}, request {} ({}): its links to {} are posted as \
                     `text (host/redacted)`, without the link: only https links to a public \
                     domain are kept outside code; link with https, or name each such source \
                     in words a reader can find it by",
                    number + 1,
                    item.get("type").and_then(Value::as_str).unwrap_or("?"),
                    hosts.join(", ")
                )
            })
        })
        .collect()
}

/// A problem for each request in COLLECTED (as [`as_collected`] writes it)
/// that gh-aw's handler would refuse at apply, after the session, over a
/// limit of its own ([`check::handler_limits`]), or that would be applied
/// saying nothing ([`unexplained_missing_data`]).
fn over_handler_limits(collected: &str) -> Vec<Problem> {
    let Ok(Value::Object(result)) = serde_json::from_str::<Value>(collected) else {
        return Vec::new();
    };
    let items = result.get("items").and_then(Value::as_array);
    let requests = items.into_iter().flatten().filter_map(Value::as_object);
    requests
        .enumerate()
        .flat_map(|(number, item)| {
            let at = format!(
                "{AGENT_OUTPUTS}, request {} ({})",
                number + 1,
                item.get("type").and_then(Value::as_str).unwrap_or("?")
            );
            let limits = check::handler_limits::refusals(item)
                .into_iter()
                .map(|what| Problem {
                    at: at.clone(),
                    what,
                    fix: "change the request to hold within the limit: apply refuses it whole, \
                          when it can no longer be changed"
                        .to_owned(),
                });
            let unexplained = unexplained_missing_data(item).map(|what| Problem {
                at: at.clone(),
                what,
                fix: format!(
                    "say in `reason` what is missing and why it blocks the task, and name it \
                     in `data_type`; {MISSING_DATA} takes only `data_type`, `reason`, \
                     `context` and `alternatives`"
                ),
            });
            limits.chain(unexplained).collect::<Vec<_>>()
        })
        .collect()
}

const MISSING_DATA: &str = "missing_data";

/// Why ITEM is a `missing_data` that nobody can act on: one with no
/// `reason`. gh-aw's collector takes it, as none of its fields is
/// required, and the status comment then cannot say why ("none given"),
/// so the item stalls until someone reads the session. Such runs wrote
/// `title` and `body`, which are not its fields and are not quoted (#1102).
/// Refused in the session only, where the agent can still say why:
/// `check` would refuse the whole hand-back with it, a change included.
fn unexplained_missing_data(item: &serde_json::Map<String, Value>) -> Option<String> {
    let reason = item.get("reason").and_then(Value::as_str);
    (item.get("type").and_then(Value::as_str) == Some(MISSING_DATA)
        && reason.is_none_or(|reason| reason.trim().is_empty()))
    .then(|| {
        format!(
            "a {MISSING_DATA} with no `reason`, so the status comment cannot say what was \
             missing or why it blocks the task"
        )
    })
}

/// The collector's result for the `outputs.jsonl` in OUTPUTS, as `check`
/// reads it, were the collector to pass every request on as it is: a
/// line that is not a JSON object is the one thing it surely refuses.
fn as_collected(outputs: &Path) -> Result<String> {
    let text = std::fs::read_to_string(outputs.join(OUTPUTS_FILE)).unwrap_or_default();
    let (mut items, mut errors) = (Vec::new(), Vec::new());
    for (number, line) in text.lines().enumerate() {
        match serde_json::from_str::<Value>(line) {
            Ok(Value::Object(item)) => items.push(item),
            _ => errors.push(format!(
                "{AGENT_OUTPUTS}, line {}: not one JSON object",
                number + 1
            )),
        }
    }
    Ok(serde_json::to_string(
        &json!({"items": items, "errors": errors}),
    )?)
}

/// A repository at TO that `collect` can commit in as it does in the
/// checkout REPO, which is left as it is: REPO's HEAD, REPO's index, and
/// a working tree of what `git add --all` would stage in REPO, files that
/// are not in its index as well. Its objects are REPO's, by reference;
/// those `git add` writes are what `run` writes there too. It returns the
/// nested repositories that `git add --all` stages as new submodules,
/// which `check` refuses: the copy holds an empty directory for each, so
/// `collect` there would not see them.
fn snapshot(repo: &Path, to: &Path) -> Result<Vec<String>> {
    let scratch = tempfile::tempdir()?;
    let index = copy_index(repo, &scratch.path().join("index"))?;
    let indexed = git_with_index(repo, &index, &["write-tree"])
        .context("writing the index as a tree: are there unresolved conflicts?")?;
    git_with_index(repo, &index, &["add", "--all"])?;
    let staged = git_with_index(repo, &index, &["write-tree"])?;
    let gitlinks = |tree: &[u8]| -> Result<Vec<String>> {
        let tree = String::from_utf8_lossy(tree).trim().to_owned();
        let list = git(repo, &["ls-tree", "-r", "-z", &tree])?;
        Ok(list
            .split(|&b| b == 0)
            .filter_map(|entry| {
                let (meta, path) = std::str::from_utf8(entry).ok()?.split_once('\t')?;
                meta.starts_with("160000 ").then(|| path.to_owned())
            })
            .collect())
    };
    let known = gitlinks(&indexed)?;
    let nested: Vec<String> = gitlinks(&staged)?
        .into_iter()
        .filter(|path| !known.contains(path))
        .collect();
    let head = git(repo, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let objects = git(repo, &["rev-parse", "--git-path", "objects"])?;
    let objects = repo.join(String::from_utf8(objects)?.trim());
    let objects = objects
        .canonicalize()
        .with_context(|| format!("finding {}", objects.display()))?;

    std::fs::create_dir(to)?;
    git(to, &["init", "--quiet"])?;
    let alternates = format!("{}\n", objects.display());
    std::fs::write(to.join(".git/objects/info/alternates"), alternates)?;
    git(to, &["update-ref", "HEAD", String::from_utf8(head)?.trim()])?;
    let tree = scratch.path().join("tree");
    git_with_index(to, &tree, &["read-tree", String::from_utf8(staged)?.trim()])?;
    git_with_index(to, &tree, &["checkout-index", "--all"])?;
    git(to, &["read-tree", String::from_utf8(indexed)?.trim()])?;
    Ok(nested)
}

/// A copy at TO of the index of the checkout REPO, so that REPO's own
/// stays as it is.
fn copy_index(repo: &Path, to: &Path) -> Result<PathBuf> {
    let own = String::from_utf8(git(repo, &["rev-parse", "--git-path", "index"])?)?;
    match std::fs::copy(repo.join(own.trim()), to) {
        Ok(_) => {}
        // No index yet: `git add` starts an empty one.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("copying the index"),
    }
    Ok(to.to_owned())
}

fn git_with_index(repo: &Path, index: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = git_command(repo)
        .env("GIT_INDEX_FILE", index)
        .args(args)
        .output()?;
    ensure!(
        output.status.success(),
        "git {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

/// Where under the agent's home `run` takes its requests and report from.
const OUT_DIR: &str = "out";

/// Bigger than any file `run` takes from `out/`; one this big is refused
/// there anyway.
const MAX_SCANNED_BYTES: u64 = 64 << 20;

/// A secret-shaped string, by where it is and the pattern it matches;
/// never by the string, which may be real.
#[derive(Debug, PartialEq, Eq)]
struct Finding {
    location: String,
    pattern: &'static str,
    /// On a line the change removes or quotes as context: one the base
    /// commit holds, made before this run's token was.
    from_base: bool,
}

impl Finding {
    /// What `run` refuses, if it is that: a private key cannot be a
    /// harmless fixture. A run token can be one, but the final gate
    /// refuses this session's own by value as a real leak, and the agent
    /// cannot tell its own from another by shape, so a new one is refused
    /// here; one the base holds already cannot be this run's. Any other
    /// shape is a warning (see [`redact`]).
    fn refused(&self) -> Option<&'static str> {
        match self.pattern {
            redact::PRIVATE_KEY => Some("a private key"),
            redact::RUN_TOKEN if !self.from_base => Some("a run token"),
            _ => None,
        }
    }

    fn is_refused(&self) -> bool {
        self.refused().is_some()
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: matches `{}`", self.location, self.pattern)
    }
}

/// The secret-shaped strings in the change of the checkout REPO against
/// BASE and in HOME's `out/`, while the session can still fix them: the
/// private keys and run tokens `run`'s final gate refuses (found only
/// then, a refusal cost runs all their work, #720) and the shapes it
/// reports as warnings. Not the gate itself, which knows the run's own
/// secrets by value, not shape, and scans
/// the patch as it is made; a line at a time, which finds what the gate
/// finds, since no pattern but a private key's spans lines and that one
/// also matches its first line alone.
fn scan(repo: &Path, base: &str, home: &Path) -> Result<Vec<Finding>> {
    let base = String::from_utf8(git(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{base}^{{commit}}"),
        ],
    )?)?;
    let scratch = tempfile::tempdir()?;
    let index = copy_index(repo, &scratch.path().join("index"))?;
    let with_index = |args: &[&str]| git_with_index(repo, &index, args);
    // As `run` stages it; the patch holds the same lines, context included.
    with_index(&["add", "--all"])?;
    let diff = with_index(&[
        "diff",
        "--cached",
        "--no-renames",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        base.trim(),
        "--",
    ])?;
    let mut found = diff_findings(&diff);
    // Whatever `run` reads from there: the requests, the report (a
    // summary can become the commit message) and a replacement series.
    let names = [AGENT_OUTPUTS, AGENT_OUTCOME, REPLACEMENT_PATH];
    for name in names {
        let path = home.join(name);
        let content = match crate::files::read_regular(&path, MAX_SCANNED_BYTES) {
            Ok(content) => content,
            Err(ReadError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => bail!("{} {err}", path.display()),
        };
        for (number, line) in content.split(|&b| b == b'\n').enumerate() {
            let mut patterns = redact::secret_shapes(line);
            // `run` decodes and writes again what it takes from JSON, so
            // an escape (`\u0067hp_`) is a match by then.
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) {
                for pattern in redact::secret_shapes(value.to_string().as_bytes()) {
                    if !patterns.contains(&pattern) {
                        patterns.push(pattern);
                    }
                }
            }
            for pattern in patterns {
                found.push(Finding {
                    location: format!("{}:{}", path.display(), number + 1),
                    pattern,
                    from_base: false,
                });
            }
        }
    }
    Ok(found)
}

/// PATH as a location, unless it is itself what may not be shown.
fn shown(path: &[u8]) -> String {
    if redact::secret_shapes(path).is_empty() {
        String::from_utf8_lossy(path).into_owned()
    } else {
        "a file whose name is secret-shaped".to_owned()
    }
}

/// The secret-shaped strings in DIFF, `git diff` output, each by the file
/// and line it is on: the new file's for an added line and for an
/// unchanged one the patch quotes as context, the old file's for one it
/// removes, since the patch holds all three.
fn diff_findings(diff: &[u8]) -> Vec<Finding> {
    let mut found = Vec::new();
    let (mut old_path, mut new_path) = (String::new(), String::new());
    let (mut old, mut new) = (0_usize, 0_usize);
    let mut in_hunk = false;
    for line in diff.split(|&b| b == b'\n') {
        let location = if line.starts_with(b"diff --git ") {
            in_hunk = false;
            // The names are on the lines after; this one may hold the match.
            "a file name in the diff (`git diff --name-only` lists them)".to_owned()
        } else if let Some(hunk) = line.strip_prefix(b"@@ ") {
            // `@@ -OLD[,COUNT] +NEW[,COUNT] @@ CONTEXT`
            let hunk = String::from_utf8_lossy(hunk);
            let start = |sign: char| {
                hunk.split(' ')
                    .find_map(|part| part.strip_prefix(sign))
                    .and_then(|range| range.split(',').next())
                    .and_then(|start| start.parse::<usize>().ok())
                    .unwrap_or(0)
            };
            (old, new) = (start('-'), start('+'));
            in_hunk = true;
            format!("{new_path} (a hunk header)")
        } else if in_hunk {
            match line.first() {
                Some(b'+') => {
                    new += 1;
                    format!("{new_path}:{}", new - 1)
                }
                Some(b'-') => {
                    old += 1;
                    format!("{old_path}:{} (a line the change removes)", old - 1)
                }
                Some(b' ') => {
                    (old, new) = (old + 1, new + 1);
                    format!(
                        "{new_path}:{} (an unchanged line quoted as context)",
                        new - 1
                    )
                }
                _ => format!("{new_path} (a diff line)"),
            }
        } else {
            if let Some(path) = line.strip_prefix(b"--- ") {
                old_path = shown(path.strip_prefix(b"a/").unwrap_or(path));
            } else if let Some(path) = line.strip_prefix(b"+++ ") {
                new_path = shown(path.strip_prefix(b"b/").unwrap_or(path));
            }
            format!("{new_path} (a diff header)")
        };
        let from_base = in_hunk && matches!(line.first(), Some(b'-' | b' '));
        for pattern in redact::secret_shapes(line) {
            found.push(Finding {
                location: location.clone(),
                pattern,
                from_base,
            });
        }
    }
    found
}

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = git_command(repo).args(args).output()?;
    ensure!(
        output.status.success(),
        "git {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

fn git_command(repo: &Path) -> Process {
    let mut command = Process::new("git");
    // Repository-selection overrides can make `-C scratch` operate on the
    // producer's checkout instead. Never carry Git's ambient overrides into
    // either side of this local validation.
    for (key, _) in std::env::vars_os() {
        if key.as_encoded_bytes().starts_with(b"GIT_") {
            command.env_remove(key);
        }
    }
    command.arg("-C").arg(repo);
    command
}

fn replace(repo: &Path, base: &str, range: Option<&str>, output: &Path) -> Result<()> {
    let base = String::from_utf8(git(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{base}^{{commit}}"),
        ],
    )?)?;
    let base = base.trim();
    let default_range = format!("{base}..HEAD");
    let range = range.unwrap_or(&default_range);
    ensure!(!range.starts_with('-'), "range must not be an option");
    let ids = String::from_utf8(git(
        repo,
        &["rev-list", "--reverse", "--topo-order", range, "--"],
    )?)?;
    let ids: Vec<_> = ids.lines().collect();
    ensure!(
        !ids.is_empty() && ids.len() <= 50,
        "replacement requires 1..=50 commits"
    );
    let scratch = tempfile::tempdir()?;
    git(scratch.path(), &["init", "--quiet"])?;
    // An independent repository avoids worktree registration and leaves the
    // producer's index, HEAD and in-progress operations untouched on failure.
    let source = String::from_utf8(git(repo, &["rev-parse", "--absolute-git-dir"])?)?;
    git(
        scratch.path(),
        &["fetch", "--quiet", "--", source.trim(), base],
    )?;
    git(scratch.path(), &["checkout", "--quiet", "--detach", base])?;
    let mut commits = Vec::new();
    for id in ids {
        let defaults = crate::run::handback::FORMAT_PATCH;
        let mut args = defaults[..defaults.len() - 1].to_vec();
        args.extend([id, "--"]);
        let mail = git(repo, &args)?;
        ensure!(
            !mail.is_empty(),
            "commit {id} has no patch (empty or merge commit)"
        );
        let mut child = git_command(scratch.path())
            .args([
                "-c",
                "user.name=Handback",
                "-c",
                "user.email=handback@localhost",
                "-c",
                "core.hooksPath=/dev/null",
                "am",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        use std::io::Write;
        child
            .stdin
            .take()
            .context("git am stdin")?
            .write_all(&mail)?;
        let applied = child.wait_with_output()?;
        ensure!(
            applied.status.success(),
            "commit {id} does not apply on the replacement base: {}",
            String::from_utf8_lossy(&applied.stderr)
        );
        commits.push(String::from_utf8(mail).context("replacement mail must be UTF-8")?);
    }
    let bytes = serde_json::to_vec(&Replacement {
        base_commit: base.into(),
        commits,
    })?;
    let parent = output.parent().context("output has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    use std::io::Write;
    file.write_all(&bytes)?;
    file.persist(output).context("writing replacement.json")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Kind;

    fn sh(dir: &Path, script: &str) -> String {
        let out = Process::new("sh")
            .args(["-ec", script])
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// An agent's home with its checkout, and the run file `run` leaves.
    fn home(outputs: Value) -> (tempfile::TempDir, RunFile) {
        let dir = tempfile::tempdir().unwrap();
        let checkout = dir.path().join("work/r");
        std::fs::create_dir_all(&checkout).unwrap();
        std::fs::create_dir(dir.path().join("out")).unwrap();
        sh(
            &checkout,
            "git init -q -b main . && echo one > a.txt && git add . && \
             git -c user.name=t -c user.email=t@example.invalid commit -q -m Base",
        );
        let base = sh(&checkout, "git rev-parse HEAD").trim().to_owned();
        let policy = Policy {
            context: Vec::new(),
            repo: "o/r".into(),
            clone_url: "https://example.invalid/o/r".into(),
            base: "main".into(),
            kind: Kind::Branch,
            max_outputs: 3,
            max_patch_bytes: 1 << 20,
            safe_outputs: serde_json::from_value(outputs).unwrap(),
            commit_author: None,
            push_repo: None,
            private: false,
            allowed_domains: crate::policy::link_domains().to_vec(),
            allow_http: Vec::new(),
            memory: None,
            forge: Default::default(),
            contract: crate::policy::CONTRACT,
        };
        let run = RunFile {
            policy,
            checkout,
            base,
            run_id: "7".into(),
            commit: config::Commit::default(),
        };
        (dir, run)
    }

    fn pull_requests() -> Value {
        json!({
            "create_pull_request": {
                "max": 1, "protected_files": ["CODEOWNERS"], "protect_top_level_dot_folders": true,
                "protected_files_policy": "blocked", "draft": true, "max_patch_size": 1024,
                "max_patch_files": 3, "ready_when_complete": true,
            },
            "add_comment": {"max": 1},
            "noop": {"max": 1},
            "missing_data": {"max": 1},
        })
    }

    /// What `check` refuses of what `run` hands back of the agent's work
    /// in HOME: `collect` on the checkout itself, as `run` does after the
    /// session, on a copy, since it commits there.
    fn after_the_session(home: &Path, run: &RunFile) -> Vec<String> {
        let copy = tempfile::tempdir().unwrap();
        sh(
            copy.path(),
            &format!("cp -a {}/. checkout", run.checkout.display()),
        );
        std::fs::create_dir(copy.path().join("run")).unwrap();
        let outputs = copy.path().join("outputs");
        capture::collect(&capture::Request {
            runner: &Unconfined,
            home,
            checkout: &Checkout {
                dir: copy.path().join("checkout"),
                base_commit: run.base.clone(),
            },
            policy: &run.policy,
            commit: &run.commit,
            run_id: &run.run_id,
            harness: None,
            run_dir: &copy.path().join("run"),
            safe_outputs: &outputs,
        })
        .unwrap();
        if !outputs.is_dir() {
            return Vec::new();
        }
        let collected = copy.path().join("collected.json");
        std::fs::write(&collected, as_collected(&outputs).unwrap()).unwrap();
        check::check_outputs(&outputs, &collected, &run.policy)
            .unwrap()
            .errors
    }

    /// Each kind of refusal is reported in the session, as `check` gives
    /// it after the session, with how to fix it; and the checkout is left
    /// as it was, however often it is checked.
    #[test]
    fn the_session_is_told_what_check_would_refuse() {
        let token = format!("gh{}_{}", "p", "a1B2".repeat(10));
        let key = format!("-----BEGIN {}-----", "PRIVATE KEY");
        let pull = |body: &str| {
            json!({"type": "create_pull_request", "title": "Fix it", "body": body}).to_string()
        };
        let done = r#"{"summary": "Fixed it.", "tests": [], "stopped_early": null}"#;
        struct Case<'a> {
            name: &'a str,
            script: String,
            requests: String,
            outcome: Option<&'a str>,
            /// In a problem; none for a hand-back with none.
            want: Option<&'a str>,
            note: bool,
            /// Found before `collect`, which cannot see it in the copy.
            nested: bool,
        }
        let case = |name, script: &str, requests: String| Case {
            name,
            script: script.to_owned(),
            requests,
            outcome: Some(done),
            want: None,
            note: false,
            nested: false,
        };
        let cases = [
            case("clean", "echo two >> a.txt", pull("Why.")),
            Case {
                name: "untracked binary litter is left out",
                ..case(
                    "",
                    "echo two >> a.txt && printf '\\000\\001' > litter.bin",
                    pull("Why."),
                )
            },
            Case {
                want: Some("protected files: .github/x.yml"),
                ..case(
                    "protected path",
                    "mkdir .github && echo x > .github/x.yml",
                    pull("Why."),
                )
            },
            Case {
                want: Some("protected files: sub/CODEOWNERS"),
                ..case(
                    "protected name",
                    "mkdir sub && echo x > sub/CODEOWNERS",
                    pull("Why."),
                )
            },
            Case {
                want: Some("the patch touches 4 files, over 3"),
                ..case(
                    "too many files",
                    "for f in b c d e; do echo $f > $f.txt; done",
                    pull("Why."),
                )
            },
            Case {
                want: Some("a new symlink, submodule, executable or special file"),
                ..case(
                    "an executable",
                    "echo x > run.sh && chmod +x run.sh",
                    pull("Why."),
                )
            },
            Case {
                want: Some("which the policy does not allow"),
                ..case(
                    "a type not allowed",
                    "",
                    json!({"type": "add_labels", "labels": ["x"]}).to_string(),
                )
            },
            Case {
                want: Some("2 outputs of type \"noop\", over 1"),
                ..case(
                    "over a type's count",
                    "",
                    format!("{0}\n{0}", json!({"type": "noop", "message": "m"})),
                )
            },
            Case {
                want: Some("more than one checkpoint"),
                ..case(
                    "two checkpoints",
                    "echo two >> a.txt",
                    pull(&format!(
                        "Why.\n\n{0}\n{1}\n```\n\n{0}\n{1}\n```",
                        crate::check::checkpoint::FENCE,
                        r#"{"reason": "budget", "done": "a", "left": "b", "next": "c"}"#
                    )),
                )
            },
            Case {
                want: Some("line 1: not one JSON object"),
                ..case("a line that is not JSON", "", "noop please".to_owned())
            },
            Case {
                note: true,
                ..case(
                    "a secret-shaped string, a fixture's fake key",
                    &format!("echo 'key = \"{token}\"' > key.txt"),
                    pull("Why."),
                )
            },
            Case {
                want: Some("a private key"),
                ..case(
                    "a private key",
                    &format!("echo '{key}' > key.pem"),
                    pull("Why."),
                )
            },
            Case {
                want: Some("a run token"),
                ..case(
                    "a run token, which the gate refuses when it is this run's",
                    &format!("echo 'praxis-run-{}' > token.txt", "0f".repeat(32)),
                    pull("Why."),
                )
            },
            Case {
                outcome: None,
                want: Some("there is no report"),
                ..case("no report", "echo two >> a.txt", pull("Why."))
            },
            Case {
                outcome: Some(r#"{"tests": []}"#),
                want: Some("there is no `summary`"),
                ..case("no summary", "echo two >> a.txt", pull("Why."))
            },
            Case {
                want: Some("a nested repository"),
                nested: true,
                ..case(
                    "a nested repository",
                    "echo two >> a.txt && git init -q sub && echo x > sub/x && git -C sub add x && \
                     git -C sub -c user.name=t -c user.email=t@example.invalid commit -qm x",
                    pull("Why."),
                )
            },
            Case {
                want: Some("No hand-back was left."),
                ..case("nothing", "", String::new())
            },
            Case {
                outcome: Some(
                    r#"{"summary": "Half.", "checkpoint": {"complete": false, "done": "a",
                        "left": "b", "next": "c"}}"#,
                ),
                note: true,
                ..case("an open checkpoint", "echo two >> a.txt", pull("Why."))
            },
            case(
                "a link gh-aw keeps",
                "echo two >> a.txt",
                pull("Per [the issue](https://github.com/o/r/issues/1)."),
            ),
            case(
                "a link to any public host",
                "echo two >> a.txt",
                pull("Per [the spec](https://src.fedoraproject.org/rpms/x)."),
            ),
            Case {
                note: true,
                ..case(
                    "a link gh-aw redacts, not https",
                    "echo two >> a.txt",
                    pull("Per [the spec](http://src.fedoraproject.org/rpms/x)."),
                )
            },
            // Refused at apply by gh-aw's handler, not by `check`: the
            // comment of tracker's run 38950333437 (#963).
            Case {
                want: Some(
                    "request 1 (add_comment): E008: Comment contains 58 links, maximum is 50.",
                ),
                ..case(
                    "a comment over the handler's limit of links",
                    "",
                    json!({"type": "add_comment", "body": (0..58)
                        .map(|n| format!("- https://example.com/{n}\n"))
                        .collect::<String>()})
                    .to_string(),
                )
            },
            // Within it by the links gh-aw's footer adds.
            case(
                "a comment at the handler's limit of links",
                "",
                json!({"type": "add_comment", "body": "https://example.com/x ".repeat(46)})
                    .to_string(),
            ),
            // Taken by `check`, then quoted as "none given" (#1102): the
            // fields of tracker's run 39008040937.
            Case {
                want: Some("request 1 (missing_data): a missing_data with no `reason`"),
                ..case(
                    "missing data in fields it does not have",
                    "",
                    json!({"type": "missing_data", "title": "Blocked", "body": "On #1012."})
                        .to_string(),
                )
            },
            Case {
                want: Some("request 1 (missing_data): a missing_data with no `reason`"),
                ..case(
                    "missing data with a blank reason",
                    "",
                    json!({"type": "missing_data", "data_type": "log", "reason": " \n"})
                        .to_string(),
                )
            },
            Case {
                want: Some("request 1 (missing_data): a missing_data with no `reason`"),
                ..case(
                    "missing data that names only its type",
                    "",
                    json!({"type": "missing_data", "data_type": "log"}).to_string(),
                )
            },
            case(
                "missing data with a reason",
                "",
                json!({"type": "missing_data", "reason": "The failing log has expired."})
                    .to_string(),
            ),
        ];
        for case in cases {
            let (dir, run) = home(pull_requests());
            let home = dir.path();
            if !case.script.is_empty() {
                sh(&run.checkout, &case.script);
            }
            std::fs::write(home.join(AGENT_OUTPUTS), &case.requests).unwrap();
            if let Some(outcome) = case.outcome {
                std::fs::write(home.join(AGENT_OUTCOME), outcome).unwrap();
            }
            let state = "git status --porcelain=v1 --untracked-files=all && git rev-parse HEAD \
                         && git diff --cached --name-status && git stash list";
            let before = sh(&run.checkout, state);
            let report = validate(home, &run).unwrap();
            let again = validate(home, &run).unwrap();
            assert_eq!(report.problems, again.problems, "{}", case.name);
            assert_eq!(sh(&run.checkout, state), before, "{}", case.name);

            let shown: Vec<String> = report.problems.iter().map(ToString::to_string).collect();
            match case.want {
                None => assert!(shown.is_empty(), "{}: {shown:#?}", case.name),
                Some(want) => assert!(
                    shown
                        .iter()
                        .any(|problem| problem.contains(want) && problem.contains("; ")),
                    "{}: {want} in {shown:#?}",
                    case.name
                ),
            }
            assert_eq!(!report.notes.is_empty(), case.note, "{}", case.name);
            // The same refusals as after the session, in the same words.
            let checked: Vec<&str> = report
                .problems
                .iter()
                .filter(|problem| problem.at == "check")
                .map(|problem| problem.what.as_str())
                .collect();
            let after = after_the_session(home, &run);
            if case.nested {
                assert!(checked.is_empty(), "{}: {checked:?}", case.name);
                assert!(
                    after.iter().any(|error| error.contains("submodule")),
                    "{}: {after:?}",
                    case.name
                );
            } else {
                assert_eq!(checked, after, "{}", case.name);
            }
            assert!(
                shown
                    .iter()
                    .chain(&report.notes)
                    .all(|problem| !problem.contains(&token) && !problem.contains(&key)),
                "{}: {shown:#?}",
                case.name
            );
        }
    }

    /// What `run` leaves its agent names no clone URL, and is what the
    /// validator reads.
    #[test]
    fn the_run_file_is_the_policy_without_its_clone_urls() {
        let (dir, run) = home(pull_requests());
        let checkout = Checkout {
            dir: run.checkout.clone(),
            base_commit: run.base.clone(),
        };
        let text = run_file(&run.policy, &checkout, "7", &run.commit).unwrap();
        std::fs::create_dir_all(dir.path().join(".config/agentic-job")).unwrap();
        std::fs::write(dir.path().join(RUN_FILE), &text).unwrap();
        let read = RunFile::read(dir.path()).unwrap();
        assert!(!text.contains("example.invalid"), "{text}");
        assert_eq!(read.policy.safe_outputs, run.policy.safe_outputs);
        assert_eq!(
            (read.checkout, read.base, read.run_id),
            (run.checkout, run.base, run.run_id)
        );
    }

    #[test]
    fn preserves_mail_and_rejects_a_wrong_base_without_overwriting() {
        let repo = tempfile::tempdir().unwrap();
        let p = repo.path();
        git(p, &["init", "--quiet"]).unwrap();
        git(p, &["config", "user.name", "Test"]).unwrap();
        git(p, &["config", "user.email", "test@example.org"]).unwrap();
        std::fs::write(p.join("file"), "base\n").unwrap();
        git(p, &["add", "."]).unwrap();
        git(p, &["commit", "-qm", "Base"]).unwrap();
        let base = String::from_utf8(git(p, &["rev-parse", "HEAD"]).unwrap()).unwrap();
        std::fs::write(p.join("file"), "changed\n").unwrap();
        git(p, &["commit", "-qam", "Change"]).unwrap();
        let output = p.join("out/replacement.json");
        replace(p, base.trim(), None, &output).unwrap();
        let bytes = std::fs::read(&output).unwrap();
        let series: Replacement = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            series.commits[0].as_bytes(),
            git(
                p,
                &[
                    "format-patch",
                    "--stdout",
                    "--no-signature",
                    "--no-renames",
                    "-1",
                    "HEAD"
                ]
            )
            .unwrap()
        );
        assert!(series.commits[0].ends_with('\n'));
        assert!(replace(p, "HEAD", Some("HEAD~1..HEAD"), &output).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), bytes);
        assert!(replace(p, "HEAD", None, &output).is_err());
    }

    #[test]
    fn a_finding_is_located_by_file_and_line_of_its_side() {
        let token = format!("gh{}_{}", "p", "a1B2".repeat(10));
        let diff = format!(
            "diff --git a/src/k.rs b/src/k.rs\n\
             index 1111111..2222222 100644\n\
             --- a/src/k.rs\n\
             +++ b/src/k.rs\n\
             @@ -10,4 +10,4 @@ fn f() {{\n\
             \x20ctx {token}\n\
             -old {token}\n\
             +new {token}\n\
             \x20clean\n\
             diff --git a/gone b/gone\n\
             deleted file mode 100644\n\
             --- a/gone\n\
             +++ /dev/null\n\
             @@ -1 +0,0 @@\n\
             -{token}\n\
             diff --git a/x b/x\n\
             new file mode 100644\n\
             --- /dev/null\n\
             +++ b/x\n\
             @@ -0,0 +1,2 @@ {token}\n\
             +clean\n\
             +sk-{token}\n"
        );
        let found: Vec<String> = diff_findings(diff.as_bytes())
            .iter()
            .map(|finding| finding.location.clone())
            .collect();
        let want = [
            "src/k.rs:10 (an unchanged line quoted as context)",
            "src/k.rs:11 (a line the change removes)",
            "src/k.rs:11",
            "gone:1 (a line the change removes)",
            "x (a hunk header)",
            "x:2",
            // Also an OpenAI key's shape.
            "x:2",
        ];
        assert_eq!(found, want);
        assert!(found.iter().all(|location| !location.contains(&token)));
    }

    /// A run token the change adds may be this run's, which the final gate
    /// refuses; one the base holds cannot be, and stays a warning.
    #[test]
    fn a_run_token_is_refused_only_where_the_change_adds_it() {
        let token = format!("praxis-run-{}", "0f".repeat(32));
        let diff = format!(
            "diff --git a/t.rs b/t.rs\n\
             --- a/t.rs\n\
             +++ b/t.rs\n\
             @@ -1,3 +1,3 @@\n\
             \x20{token}\n\
             -{token}\n\
             +{token}\n"
        );
        let refused: Vec<bool> = diff_findings(diff.as_bytes())
            .iter()
            .map(Finding::is_refused)
            .collect();
        assert_eq!(refused, [false, false, true]);
        // One hex digit pair short: no run token's shape.
        let short = format!("praxis-run-{}", "0f".repeat(31));
        assert!(diff_findings(format!("+{short}\n").as_bytes()).is_empty());
    }
}
