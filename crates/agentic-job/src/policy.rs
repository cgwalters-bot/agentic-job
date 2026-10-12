//! `agentic-job policy`: check one run's request against the caller's
//! bounds and print `policy.json`. Step 4 of docs/plan.md.
//!
//! The request (which repository, which base, which outputs and how many)
//! comes from whoever started the run. The bounds are a file the caller
//! keeps in its own repository. A request outside them is refused here,
//! on a machine the agent never touches and before the agent's machine
//! starts, and what is within them becomes the run's [`Policy`]: the one
//! thing `run`, gh-aw's collector and `check` all read.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::exit::Exit;

/// The output type that carries a patch for a new pull request.
pub const CREATE_PULL_REQUEST: &str = "create_pull_request";

/// The output type that carries a patch for an open pull request's
/// branch: one commit on top of the head the run started from.
pub const PUSH_TO_PULL_REQUEST_BRANCH: &str = "push_to_pull_request_branch";

/// The output types a bounds file may list. Each is one that gh-aw's
/// collector validates with the configuration written here; another type
/// needs settings of its own, so it is added here with them and not by a
/// caller's file alone.
pub const OUTPUT_TYPES: &[&str] = &[
    CREATE_PULL_REQUEST,
    "add_comment",
    "create_issue",
    "close_issue",
    "add_labels",
    "update_project",
    PUSH_TO_PULL_REQUEST_BRANCH,
    "noop",
    "missing_tool",
    "missing_data",
];

/// The output types the job token cannot apply, whatever the call grants
/// it, and the credential each needs instead. GitHub gives a workflow's
/// token no permission on Projects, and no account to fork into: apply
/// opens a pull request only from a fork of the identity it applies as,
/// and pushes only to such a pull request's branch in that fork, so that
/// the target's CI runs agent-written code as a fork's, with a read-only
/// token. Every other type writes to a repository, which the token can
/// when it is the calling one.
const NOT_FOR_THE_JOB_TOKEN: &[(&str, &str)] = &[
    (
        CREATE_PULL_REQUEST,
        "a user's token that can fork the output repository and push to its fork, as SAFE_OUTPUTS_PAT in an apply environment",
    ),
    (
        PUSH_TO_PULL_REQUEST_BRANCH,
        "the token of the user whose fork the pull request is from, as SAFE_OUTPUTS_PAT in an apply environment",
    ),
    (
        "update_project",
        "a token with project scope as SAFE_OUTPUTS_PAT, in an apply environment",
    ),
];

/// A run hands back one patch, so at most one pull request, or one push.
const MAX_PULL_REQUESTS: u32 = 1;
const MAX_REPLACEMENT_COMMITS: u32 = 50;

/// `--outputs all`: every type the bounds list.
const ALL_OUTPUTS: &str = "all";

/// `--max-outputs max`: as many as the bounds allow.
const MAX_OUTPUTS: &str = "max";

/// gh-aw states a patch's size cap in units of this many bytes.
const KB: u64 = 1024;

/// The one top-level dot-folder bounds may exempt from protection, for
/// repositories they name exactly.
pub const EXEMPTABLE_DOT_FOLDER: &str = ".github";

/// The files a patch may not touch, at any depth: the defaults gh-aw's
/// compiler writes for `create-pull-request` (v0.90.1). A bounds file can
/// take names off this list for the repositories it names, and cannot add
/// to it.
pub const DEFAULT_PROTECTED_FILES: &[&str] = &[
    "package.json",
    "bun.lockb",
    "bunfig.toml",
    "deno.json",
    "deno.jsonc",
    "deno.lock",
    "global.json",
    "NuGet.Config",
    "Directory.Packages.props",
    "mix.exs",
    "mix.lock",
    "go.mod",
    "go.sum",
    "stack.yaml",
    "stack.yaml.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "gradle.properties",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "npm-shrinkwrap.json",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Gemfile",
    "Gemfile.lock",
    "uv.lock",
    "CODEOWNERS",
    "DESIGN.md",
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "CLAUDE.md",
    "AGENTS.md",
];

static REPO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").expect("a valid pattern"));

static BASE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}$").expect("a valid pattern"));

/// A pull request's branch that a push may go to: one that gh-aw's
/// handler pushes by the same name (`normalize_branch_name.cjs` leaves it
/// as it is) and whose patch has a name `check` takes.
static PUSH_BRANCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9]([A-Za-z0-9_./-]{0,98}[A-Za-z0-9_])?$").expect("a valid pattern")
});

static PULL_NUMBER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[1-9][0-9]{0,8}$").expect("a valid pattern"));

static COMMIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{40}$").expect("a valid pattern"));

/// The request's values may start with a dash: they are a stranger's text,
/// and one that does is refused with a reason like any other.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The caller's bounds file
    #[arg(long, value_name = "FILE")]
    pub allow: PathBuf,
    /// Optional organization bounds; both files must admit the request
    #[arg(long, value_name = "FILE")]
    pub org_allow: Option<PathBuf>,
    /// The repository the agent works on, as OWNER/NAME
    #[arg(long, value_name = "REPO", allow_hyphen_values = true)]
    pub repo: String,
    /// Where `run` clones that repository from: https://HOST/OWNER/NAME
    #[arg(long, value_name = "URL", allow_hyphen_values = true)]
    pub clone_url: String,
    /// The branch the agent starts from
    #[arg(long, value_name = "BRANCH", allow_hyphen_values = true)]
    pub base: String,
    /// What the run may hand back: a branch, or an analysis only
    #[arg(long, value_enum)]
    pub kind: Kind,
    /// The output types requested, comma-separated, or "all"
    #[arg(long, value_name = "LIST", allow_hyphen_values = true)]
    pub outputs: String,
    /// The most outputs in all and of any one type, or "max"
    #[arg(long, value_name = "N", allow_hyphen_values = true)]
    pub max_outputs: String,
    /// Apply will hold only the job token: refuse what it cannot apply
    #[arg(long)]
    pub job_token: bool,
    /// The open pull request a push goes to; `--base` is then its branch
    #[arg(
        long,
        value_name = "NUMBER",
        allow_hyphen_values = true,
        requires = "head"
    )]
    pub pull_request: Option<String>,
    /// The commit that branch was at when the run was asked for
    #[arg(
        long,
        value_name = "SHA",
        allow_hyphen_values = true,
        requires = "pull_request"
    )]
    pub head: Option<String>,
    /// Where apply applies the outputs (OWNER/NAME); a push is refused
    /// unless it is `--repo`, where the pull request is
    #[arg(long, value_name = "OWNER/NAME", allow_hyphen_values = true)]
    pub output_repo: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Branch,
    Analysis,
}

/// The caller's bounds file (`--allow`), in TOML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bounds {
    /// The hosts a clone URL may name, exactly (`github.com`).
    pub hosts: Vec<String>,
    /// Globs of OWNER/NAME; see [`glob`].
    pub repos: Vec<String>,
    /// Globs of base branches.
    pub bases: Vec<String>,
    /// The most outputs a run may hand back in all.
    pub max_outputs: u32,
    /// The largest patch, in bytes.
    pub max_patch_bytes: u64,
    /// The most files a patch may touch.
    pub max_patch_files: u32,
    /// The output types a run may ask for, and the ceiling of each.
    pub outputs: BTreeMap<String, OutputLimit>,
    /// Files exempt from protection.
    #[serde(default)]
    pub unprotected_files: Unprotected,
    /// Which events may start a run, and who may start one
    /// (`agentic-job event`). Absent, none may.
    #[serde(default)]
    pub trigger: Option<crate::event::Trigger>,
}

/// Where names come off [`DEFAULT_PROTECTED_FILES`]: only in the
/// repositories named exactly (no globs), only the names listed. So the
/// rest of the list and everything `check` refuses on its own stay protected.
/// The top-level `.github` folder, and no other, can also be exempted there.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unprotected {
    #[serde(default)]
    pub repos: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub dot_folders: Vec<String>,
}

/// How many outputs of one type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputLimit {
    pub max: u32,
    /// Labels an issue may name. Absent preserves the existing unrestricted
    /// behavior; an empty list permits no labels. Enforced by `check`, not
    /// by the handler's silent filtering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<String>>,
    /// Labels an issue may never name, even if also allowed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked: Vec<String>,
    /// Exact GitHub Projects v2 URLs and field names admitted for updates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// Globs of the pull request branches a push may go to. In place of
    /// `bases` for a push: those name what a run starts from to propose
    /// a new pull request, these the branches it may add a commit to.
    /// Unlike `bases`, case counts: a forge's branch names keep it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub branches: Vec<String>,
    /// Zero (the default) forbids replacing history. A positive ceiling
    /// admits that many individually checked, nonempty commit patches.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub replacement_max_commits: u32,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

impl OutputLimit {
    fn validate(&self, output: &str) -> Result<()> {
        ensure!(
            self.replacement_max_commits <= MAX_REPLACEMENT_COMMITS
                && (output == PUSH_TO_PULL_REQUEST_BRANCH || self.replacement_max_commits == 0),
            "outputs.{output}: replacement_max_commits is supported only for a push, at most 50"
        );
        ensure!(
            output == "update_project" || (self.projects.is_empty() && self.fields.is_empty()),
            "outputs.{output}: projects and fields are supported only for update_project"
        );
        if output == "update_project" {
            ensure!(
                !self.projects.is_empty() && !self.fields.is_empty(),
                "outputs.update_project requires explicit nonempty projects and fields lists"
            );
            for project in &self.projects {
                static PROJECT_RE: LazyLock<Regex> = LazyLock::new(|| {
                    Regex::new(
                        r"^https://github\.com/(orgs|users)/[A-Za-z0-9-]+/projects/[1-9][0-9]*$",
                    )
                    .expect("a valid pattern")
                });
                ensure!(
                    PROJECT_RE.is_match(project)
                        && project
                            .rsplit('/')
                            .next()
                            .is_some_and(|n| n.parse::<i32>().is_ok()),
                    "invalid exact project URL {project:?}"
                );
            }
            for field in &self.fields {
                ensure!(
                    !field.is_empty()
                        && field == field.trim()
                        && !field.chars().any(char::is_control),
                    "invalid project field {field:?}"
                );
            }
        }
        ensure!(
            (output == PUSH_TO_PULL_REQUEST_BRANCH) != self.branches.is_empty(),
            "outputs.{output}: `branches` is required for {PUSH_TO_PULL_REQUEST_BRANCH}, and only for it"
        );
        for pattern in &self.branches {
            glob(pattern).with_context(|| format!("outputs.{output}: the glob {pattern:?}"))?;
        }
        ensure!(
            matches!(output, "create_issue" | "add_labels")
                || (self.allowed.is_none() && self.blocked.is_empty()),
            "outputs.{output}: label limits are supported only for create_issue and add_labels"
        );
        ensure!(
            output != "add_labels" || self.allowed.is_some(),
            "outputs.add_labels requires an explicit allowed label list"
        );
        for label in self.allowed.iter().flatten().chain(&self.blocked) {
            ensure!(
                !label.is_empty() && label == label.trim() && !label.chars().any(char::is_control),
                "outputs.{output}: invalid label {label:?}"
            );
        }
        Ok(())
    }
}

/// One run's request, as the command line gives it.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub repo: &'a str,
    pub clone_url: &'a str,
    pub base: &'a str,
    pub kind: Kind,
    pub outputs: &'a str,
    pub max_outputs: &'a str,
    /// Whether apply will hold only the job token.
    pub job_token: bool,
    /// For a push: the pull request's number, and the commit its branch
    /// (`base`) was at when the run was asked for.
    pub pull_request: Option<(&'a str, &'a str)>,
    /// Where apply applies the outputs; a push must name the run's own
    /// repository here.
    pub output_repo: Option<&'a str>,
}

/// What `policy.json` holds: the request, once it is within the bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub repo: String,
    /// What `run` clones.
    pub clone_url: String,
    pub base: String,
    pub kind: Kind,
    /// The most outputs in all.
    pub max_outputs: u32,
    pub max_patch_bytes: u64,
    /// The configuration gh-aw's collector reads (its `config.json`), and
    /// the rules `check` applies to a patch.
    pub safe_outputs: SafeOutputs,
}

/// gh-aw's safe-outputs configuration: a table per output type allowed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeOutputs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_pull_request: Option<PullRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_to_pull_request_branch: Option<Push>,
    #[serde(flatten)]
    pub others: BTreeMap<String, OutputLimit>,
}

/// `create_pull_request`'s configuration, in gh-aw's names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequest {
    pub max: u32,
    /// File names a patch may not touch, at any depth.
    pub protected_files: Vec<String>,
    /// Whether everything under a top-level directory whose name starts
    /// with a dot (`.github/`) is protected as well.
    pub protect_top_level_dot_folders: bool,
    /// Our selective exemptions; apply translates them for gh-aw's handler.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unprotected_dot_folders: Vec<String>,
    pub protected_files_policy: ProtectedFilesPolicy,
    pub draft: bool,
    /// The largest patch, in KB.
    pub max_patch_size: u64,
    pub max_patch_files: u32,
}

/// `push_to_pull_request_branch`'s configuration, in gh-aw's names but
/// for `head`, which its handler does not read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Push {
    /// Always written: gh-aw takes a missing `max` for no limit.
    pub max: u32,
    /// The pull request's number, from the request and never the agent.
    pub target: String,
    /// The commit its branch was at when the run was asked for: what the
    /// run starts from and the patch is against. A plain push of a commit
    /// on it fails if the branch moved since.
    pub head: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub replacement_max_commits: u32,
    /// The target base head resolved by the read-only policy job, not the producer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_base: Option<String>,
    pub protected_files: Vec<String>,
    /// Always true, with no exemption: gh-aw's push handler refuses a
    /// change under `.github/workflows/` without `allow_workflows`, which
    /// apply never sets, so an exempt `.github` would let check pass a
    /// patch that apply then fails. Only a pull request carries one.
    pub protect_top_level_dot_folders: bool,
    pub protected_files_policy: ProtectedFilesPolicy,
    /// The largest patch, in KB.
    pub max_patch_size: u64,
    pub max_patch_files: u32,
}

/// What a patch may touch, whichever output carries it.
#[derive(Debug, Clone, Copy)]
pub struct PatchRules<'a> {
    /// File names a patch may not touch, at any depth.
    pub protected_files: &'a [String],
    /// Whether everything under a top-level dot-folder is protected too.
    pub protect_top_level_dot_folders: bool,
    pub unprotected_dot_folders: &'a [String],
    pub max_patch_files: u32,
}

impl PullRequest {
    pub fn rules(&self) -> PatchRules<'_> {
        PatchRules {
            protected_files: &self.protected_files,
            protect_top_level_dot_folders: self.protect_top_level_dot_folders,
            unprotected_dot_folders: &self.unprotected_dot_folders,
            max_patch_files: self.max_patch_files,
        }
    }
}

impl Push {
    pub fn rules(&self) -> PatchRules<'_> {
        PatchRules {
            protected_files: &self.protected_files,
            protect_top_level_dot_folders: self.protect_top_level_dot_folders,
            unprotected_dot_folders: &[],
            max_patch_files: self.max_patch_files,
        }
    }
}

/// What gh-aw does with a patch that touches a protected file. Only
/// refusing it can be written here, so a policy that says anything else
/// does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtectedFilesPolicy {
    Blocked,
}

impl SafeOutputs {
    /// The ceiling of an output type, if the run may hand it back.
    pub fn max_of(&self, output: &str) -> Option<u32> {
        match output {
            CREATE_PULL_REQUEST => self.create_pull_request.as_ref().map(|pr| pr.max),
            PUSH_TO_PULL_REQUEST_BRANCH => self.push_to_pull_request_branch.as_ref().map(|p| p.max),
            _ => self.others.get(output).map(|limit| limit.max),
        }
    }

    /// The output types the run may hand back.
    pub fn types(&self) -> impl Iterator<Item = &str> {
        self.create_pull_request
            .iter()
            .map(|_| CREATE_PULL_REQUEST)
            .chain(
                self.push_to_pull_request_branch
                    .iter()
                    .map(|_| PUSH_TO_PULL_REQUEST_BRANCH),
            )
            .chain(self.others.keys().map(String::as_str))
    }

    /// The output that carries the run's patch, and the patch's rules: a
    /// policy allows at most one of the two.
    pub fn patch_carrier(&self) -> Option<(&'static str, PatchRules<'_>)> {
        self.create_pull_request
            .as_ref()
            .map(|pr| (CREATE_PULL_REQUEST, pr.rules()))
            .or_else(|| {
                self.push_to_pull_request_branch
                    .as_ref()
                    .map(|push| (PUSH_TO_PULL_REQUEST_BRANCH, push.rules()))
            })
    }
}

impl Policy {
    /// Reads the `policy.json` that `policy` printed.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the policy {}", path.display()))?;
        let policy: Self = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a policy.json", path.display()))?;
        policy
            .validate()
            .with_context(|| format!("{} is not a policy `policy` wrote", path.display()))?;
        Ok(policy)
    }

    /// What the types cannot say: `policy` writes only the output types
    /// that have a configuration here, and only draft pull requests with
    /// the dot-folders protected.
    fn validate(&self) -> Result<()> {
        for output in self.safe_outputs.others.keys() {
            ensure!(
                OUTPUT_TYPES.contains(&output.as_str())
                    && output != CREATE_PULL_REQUEST
                    && output != PUSH_TO_PULL_REQUEST_BRANCH,
                "the output type {output:?} has no configuration here"
            );
        }
        if let Some(pr) = &self.safe_outputs.create_pull_request {
            validate_dot_folders(
                &pr.unprotected_dot_folders,
                "create_pull_request.unprotected_dot_folders",
            )?;
        }
        for (output, limit) in &self.safe_outputs.others {
            limit.validate(output)?;
        }
        if let Some(pr) = &self.safe_outputs.create_pull_request {
            ensure!(pr.draft, "a pull request that is not a draft");
            ensure!(
                pr.protect_top_level_dot_folders,
                "top-level dot-folders are not protected"
            );
            ensure!(pr.max == MAX_PULL_REQUESTS, "more than one pull request");
        }
        if let Some(push) = &self.safe_outputs.push_to_pull_request_branch {
            ensure!(
                self.kind == Kind::Branch && self.safe_outputs.create_pull_request.is_none(),
                "a push in an analysis run, or beside a pull request"
            );
            ensure!(
                push.protect_top_level_dot_folders,
                "top-level dot-folders are not protected"
            );
            ensure!(push.max == MAX_PULL_REQUESTS, "more than one push");
            ensure!(
                push.replacement_max_commits <= MAX_REPLACEMENT_COMMITS,
                "over 50 replacement commits"
            );
            ensure!(
                push.replacement_base
                    .as_ref()
                    .is_none_or(|base| COMMIT_RE.is_match(base)),
                "invalid replacement base commit"
            );
            ensure!(
                PULL_NUMBER_RE.is_match(&push.target) && COMMIT_RE.is_match(&push.head),
                "a push to no single pull request and commit"
            );
            ensure!(
                PUSH_BRANCH_RE.is_match(&self.base) && !push_branch_ambiguous(&self.base),
                "a push to a branch gh-aw would push by another name"
            );
        }
        Ok(())
    }
}

/// A glob as a pattern: `*` is anything within one path segment, `**`
/// anything at all, and every other character itself. Case is ignored, as
/// forges ignore it in names. This is gh-aw's glob syntax
/// (`glob_pattern_helpers.cjs`).
fn glob(pattern: &str) -> Result<Regex, regex::Error> {
    glob_cased(pattern, false)
}

/// [`glob`], or with case counting: a forge keeps it in a branch name, so
/// `dispatch/**` is not to admit `DISPATCH/x` as a branch to push to.
fn glob_cased(pattern: &str, cased: bool) -> Result<Regex, regex::Error> {
    let body = pattern
        .split("**")
        .map(|part| {
            part.split('*')
                .map(regex::escape)
                .collect::<Vec<_>>()
                .join("[^/]*")
        })
        .collect::<Vec<_>>()
        .join(".*");
    let flags = if cased { "" } else { "(?i)" };
    Regex::new(&format!("{flags}^{body}$"))
}

/// Whether gh-aw's handler would push `branch` under another name (it
/// makes one dash of a run of them), or it is no branch name at all.
fn push_branch_ambiguous(branch: &str) -> bool {
    branch.contains("--") || branch.contains("..")
}

fn glob_matches(patterns: &[String], value: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| glob(pattern).is_ok_and(|re| re.is_match(value)))
}

impl Bounds {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the bounds file {}", path.display()))?;
        let bounds: Self = toml::from_str(&text)
            .with_context(|| format!("parsing the bounds file {}", path.display()))?;
        bounds
            .validate()
            .with_context(|| format!("in the bounds file {}", path.display()))?;
        Ok(bounds)
    }

    /// A bounds file that bounds nothing, or asks for what cannot be, is
    /// the caller's mistake and not a request to refuse.
    fn validate(&self) -> Result<()> {
        for (name, list) in [
            ("hosts", &self.hosts),
            ("repos", &self.repos),
            ("bases", &self.bases),
        ] {
            ensure!(!list.is_empty(), "`{name}` is empty, so no run is allowed");
        }
        for pattern in self.repos.iter().chain(&self.bases) {
            glob(pattern).with_context(|| format!("the glob {pattern:?}"))?;
        }
        ensure!(!self.outputs.is_empty(), "`outputs` lists no output type");
        for (output, limit) in &self.outputs {
            limit.validate(output)?;
            ensure!(
                OUTPUT_TYPES.contains(&output.as_str()),
                "the output type {output:?} is not one of {}",
                OUTPUT_TYPES.join(", ")
            );
            ensure!(limit.max >= 1, "`outputs.{output}.max` must be at least 1");
            // A hand-back holds one patch, for one pull request.
            ensure!(
                !matches!(
                    output.as_str(),
                    CREATE_PULL_REQUEST | PUSH_TO_PULL_REQUEST_BRANCH
                ) || limit.max == MAX_PULL_REQUESTS,
                "`outputs.{output}.max` must be {MAX_PULL_REQUESTS}: a run hands back one patch"
            );
        }
        ensure!(self.max_outputs >= 1, "`max_outputs` must be at least 1");
        for repo in &self.unprotected_files.repos {
            ensure!(
                REPO_RE.is_match(repo) && !dotted(repo),
                "unprotected_files.repos requires exact repository names: {repo:?}"
            );
        }
        validate_dot_folders(
            &self.unprotected_files.dot_folders,
            "unprotected_files.dot_folders",
        )?;
        ensure!(
            self.max_patch_files >= 1,
            "`max_patch_files` must be at least 1"
        );
        ensure!(
            self.max_patch_bytes >= KB,
            "`max_patch_bytes` must be at least {KB}"
        );
        Ok(())
    }

    /// The protected file names for a patch to `repo`.
    fn protected_files(&self, repo: &str) -> Vec<String> {
        let unprotected = &self.unprotected_files;
        let exempt = unprotected
            .repos
            .iter()
            .any(|own| own.eq_ignore_ascii_case(repo));
        DEFAULT_PROTECTED_FILES
            .iter()
            .filter(|name| {
                !(exempt && unprotected.files.iter().any(|file| file.as_str() == **name))
            })
            .map(|name| (*name).to_owned())
            .collect()
    }

    fn dot_folders(&self, repo: &str) -> Vec<String> {
        if self
            .unprotected_files
            .repos
            .iter()
            .any(|own| own.eq_ignore_ascii_case(repo))
        {
            self.unprotected_files.dot_folders.clone()
        } else {
            Vec::new()
        }
    }

    /// Why `url` may not be cloned as `repo`, if it may not. The URL must
    /// name that repository on a host of the bounds and nothing more, so
    /// that the bounds on the repository are bounds on what is cloned.
    fn clone_url_problem(&self, url: &str, repo: &str) -> Option<String> {
        let Some((host, path)) = url
            .strip_prefix("https://")
            .and_then(|rest| rest.split_once('/'))
        else {
            return Some(format!("clone URL {url:?} is not https://HOST/OWNER/NAME"));
        };
        if !self
            .hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            return Some(format!(
                "the host of clone URL {url:?} is not within the bounds ({})",
                self.hosts.join(", ")
            ));
        }
        let path = path.strip_suffix(".git").unwrap_or(path);
        (!path.eq_ignore_ascii_case(repo))
            .then(|| format!("clone URL {url:?} does not name the repository {repo:?}"))
    }

    /// The policy of a run, or every reason its request is refused.
    ///
    /// The request's strings are untrusted. Each is matched against a
    /// pattern before it is used, the messages quote them escaped, and
    /// the policy is serialized by serde: a quote or a newline in one can
    /// neither add a key to `policy.json` nor a line to the log.
    pub fn compile(&self, request: &Request<'_>) -> Result<Policy, Vec<String>> {
        let Request {
            repo,
            clone_url,
            base,
            kind,
            outputs,
            max_outputs,
            job_token,
            pull_request,
            output_repo,
        } = *request;
        let mut errors = Vec::new();

        let repo_ok = REPO_RE.is_match(repo) && !dotted(repo);
        if !repo_ok || !glob_matches(&self.repos, repo) {
            errors.push(format!(
                "repo {repo:?} is not within the bounds ({})",
                self.repos.join(", ")
            ));
        }
        // Checked against the repository only if that is a name at all.
        if repo_ok && let Some(problem) = self.clone_url_problem(clone_url, repo) {
            errors.push(problem);
        }
        // An analysis run has no change to propose.
        let no_change = kind == Kind::Analysis;
        // What apply could not do with the credential it will hold: asked
        // for, it is refused here, not after an agent ran for it.
        let needs_token = |output: &str| {
            NOT_FOR_THE_JOB_TOKEN
                .iter()
                .find(|(name, _)| job_token && *name == output)
                .map(|(_, token)| *token)
        };
        // A request names a pull request to push to it, and only then: of
        // the two outputs that carry a patch, `all` means the one it can.
        let other_carrier = if pull_request.is_some() {
            CREATE_PULL_REQUEST
        } else {
            PUSH_TO_PULL_REQUEST_BRANCH
        };
        let mut types: Vec<&str> = Vec::new();
        if outputs.trim() == ALL_OUTPUTS {
            types.extend(
                self.outputs
                    .keys()
                    .map(String::as_str)
                    .filter(|output| {
                        !(no_change
                            && matches!(*output, CREATE_PULL_REQUEST | PUSH_TO_PULL_REQUEST_BRANCH))
                    })
                    .filter(|output| *output != other_carrier)
                    .filter(|output| needs_token(output).is_none()),
            );
        } else {
            for output in outputs.split(',').map(str::trim).filter(|o| !o.is_empty()) {
                if !types.contains(&output) {
                    types.push(output);
                }
            }
        }
        if types.is_empty() {
            errors.push("outputs lists no output type".to_owned());
        }
        let known = || {
            self.outputs
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        };
        errors.extend(
            types
                .iter()
                .filter(|output| !self.outputs.contains_key(**output))
                .map(|output| {
                    format!(
                        "output type {output:?} is not within the bounds ({})",
                        known()
                    )
                }),
        );
        errors.extend(types.iter().filter_map(|output| {
            needs_token(output).map(|token| {
                format!(
                    "output type {output:?} needs {token}: without an apply environment, apply holds the job token, which cannot apply it"
                )
            })
        }));
        for carrier in [CREATE_PULL_REQUEST, PUSH_TO_PULL_REQUEST_BRANCH] {
            if no_change && types.contains(&carrier) {
                errors.push(format!(
                    "an analysis run hands back no change, so it can't {carrier}"
                ));
            }
        }

        // A push goes to the branch the run starts from, which the request
        // names with the pull request and its head: the branch has to be
        // one the bounds let a push go to, and `bases` does not say which.
        let push = types.contains(&PUSH_TO_PULL_REQUEST_BRANCH);
        let push_limit = self.outputs.get(PUSH_TO_PULL_REQUEST_BRANCH);
        let branches = match push_limit {
            Some(limit) if push => &limit.branches[..],
            _ => &self.bases[..],
        };
        let named = BASE_RE.is_match(base) && !base.contains("..");
        let pushable = !push || (PUSH_BRANCH_RE.is_match(base) && !push_branch_ambiguous(base));
        let within = branches
            .iter()
            .any(|pattern| glob_cased(pattern, push).is_ok_and(|re| re.is_match(base)));
        if !named || !pushable || !within {
            errors.push(format!(
                "{} {base:?} is not within the bounds ({})",
                if push { "pull request branch" } else { "base" },
                branches.join(", ")
            ));
        }
        if push {
            // The pull request is in the repository the run works on: its
            // outputs are applied there, and the push goes to the fork
            // apply opened that pull request from (docs/safe-outputs.md).
            if !output_repo.is_some_and(|output_repo| output_repo.eq_ignore_ascii_case(repo)) {
                errors.push(format!(
                    "{PUSH_TO_PULL_REQUEST_BRANCH} goes to {repo:?}, the repository the run works on, not to {}",
                    output_repo.map_or_else(|| "an unnamed one".to_owned(), |o| format!("{o:?}"))
                ));
            }
        }
        match (push, pull_request) {
            (true, Some((number, head))) => {
                if !PULL_NUMBER_RE.is_match(number) {
                    errors.push(format!("pull request {number:?} is not a number"));
                }
                if !COMMIT_RE.is_match(head) {
                    errors.push(format!(
                        "head {head:?} is not a 40-character lowercase commit SHA"
                    ));
                }
                if types.contains(&CREATE_PULL_REQUEST) {
                    errors.push(format!(
                        "a run hands back one patch, so not both {CREATE_PULL_REQUEST} and {PUSH_TO_PULL_REQUEST_BRANCH}"
                    ));
                }
            }
            (true, None) => errors.push(format!(
                "{PUSH_TO_PULL_REQUEST_BRANCH} needs the pull request and its head commit"
            )),
            (false, Some(_)) => errors.push(format!(
                "a pull request and a head are only for {PUSH_TO_PULL_REQUEST_BRANCH}"
            )),
            (false, None) => {}
        }

        let max = match max_outputs {
            MAX_OUTPUTS => Some(self.max_outputs),
            // Digits only: `parse` alone would take a sign.
            n if !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()) => {
                n.parse::<u32>().ok().filter(|n| *n <= self.max_outputs)
            }
            _ => None,
        };
        if max.is_none() {
            errors.push(format!(
                "max_outputs {max_outputs:?} must be a number from 1 to {}",
                self.max_outputs
            ));
        }
        let Some(max) = max.filter(|_| errors.is_empty()) else {
            return Err(errors);
        };

        // The lower of what was asked for and what the bounds allow.
        let limit = |output: &str| OutputLimit {
            max: self
                .outputs
                .get(output)
                .map_or(0, |bound| bound.max)
                .min(max),
            allowed: self
                .outputs
                .get(output)
                .and_then(|bound| bound.allowed.clone()),
            blocked: self
                .outputs
                .get(output)
                .map_or_else(Vec::new, |bound| bound.blocked.clone()),
            projects: self
                .outputs
                .get(output)
                .map_or_else(Vec::new, |bound| bound.projects.clone()),
            fields: self
                .outputs
                .get(output)
                .map_or_else(Vec::new, |bound| bound.fields.clone()),
            branches: Vec::new(),
            replacement_max_commits: 0,
        };
        let safe_outputs = SafeOutputs {
            create_pull_request: types.contains(&CREATE_PULL_REQUEST).then(|| PullRequest {
                max: limit(CREATE_PULL_REQUEST).max,
                protected_files: self.protected_files(repo),
                protect_top_level_dot_folders: true,
                unprotected_dot_folders: self.dot_folders(repo),
                protected_files_policy: ProtectedFilesPolicy::Blocked,
                draft: true,
                max_patch_size: self.max_patch_bytes / KB,
                max_patch_files: self.max_patch_files,
            }),
            push_to_pull_request_branch: pull_request.filter(|_| push).map(|(number, head)| Push {
                max: limit(PUSH_TO_PULL_REQUEST_BRANCH).max,
                target: number.to_owned(),
                head: head.to_owned(),
                replacement_max_commits: self
                    .outputs
                    .get(PUSH_TO_PULL_REQUEST_BRANCH)
                    .map_or(0, |bound| bound.replacement_max_commits),
                replacement_base: None,
                protected_files: self.protected_files(repo),
                protect_top_level_dot_folders: true,
                protected_files_policy: ProtectedFilesPolicy::Blocked,
                max_patch_size: self.max_patch_bytes / KB,
                max_patch_files: self.max_patch_files,
            }),
            others: types
                .iter()
                .filter(|output| {
                    !matches!(**output, CREATE_PULL_REQUEST | PUSH_TO_PULL_REQUEST_BRANCH)
                })
                .map(|output| ((*output).to_owned(), limit(output)))
                .collect(),
        };
        Ok(Policy {
            repo: repo.to_owned(),
            clone_url: clone_url.to_owned(),
            base: base.to_owned(),
            kind,
            max_outputs: max,
            max_patch_bytes: self.max_patch_bytes,
            safe_outputs,
        })
    }
}

/// Whether a component of `name` is dots alone: no directory to clone
/// into, whatever their number, so `run` refuses one (`run::clone::check`).
fn dotted(name: &str) -> bool {
    name.split('/').any(|part| part.bytes().all(|b| b == b'.'))
}

/// Only `.github` may be exempted: check's fixed refusals take the other
/// dot-folders it names (`.husky/`, `.vscode/`, `.circleci/`, `.tekton/`)
/// whatever the policy says, so an exemption for them would grant nothing,
/// and no other folder has been needed.
fn validate_dot_folders(names: &[String], field: &str) -> Result<()> {
    for name in names {
        ensure!(
            name == EXEMPTABLE_DOT_FOLDER,
            "{field} may only name {EXEMPTABLE_DOT_FOLDER:?}, not {name:?}"
        );
    }
    Ok(())
}

pub fn run(args: &Args) -> Result<Exit> {
    let bounds = Bounds::load(&args.allow)?;
    let org_bounds = args.org_allow.as_deref().map(Bounds::load).transpose()?;
    let request = Request {
        repo: &args.repo,
        clone_url: &args.clone_url,
        base: &args.base,
        kind: args.kind,
        outputs: &args.outputs,
        max_outputs: &args.max_outputs,
        job_token: args.job_token,
        pull_request: args.pull_request.as_deref().zip(args.head.as_deref()),
        output_repo: args.output_repo.as_deref(),
    };
    let compiled = bounds
        .compile(&request)
        .and_then(|policy| match &org_bounds {
            Some(org) => org
                .compile(&request)
                .and_then(|other| intersect(policy, other)),
            None => Ok(policy),
        });
    match compiled {
        Ok(policy) => {
            let json = serde_json::to_string_pretty(&policy).context("writing the policy")?;
            println!("{json}");
            Ok(Exit::Success)
        }
        Err(errors) => {
            for error in errors {
                eprintln!("error: {error}");
            }
            Ok(Exit::Failure)
        }
    }
}

/// Intersect compiled policies rather than trying to intersect glob patterns.
/// Each file independently checks the target and any explicitly requested type.
fn intersect(mut policy: Policy, other: Policy) -> Result<Policy, Vec<String>> {
    policy.max_outputs = policy.max_outputs.min(other.max_outputs);
    policy.max_patch_bytes = policy.max_patch_bytes.min(other.max_patch_bytes);
    policy.safe_outputs.others.retain(|name, limit| {
        if let Some(bound) = other.safe_outputs.others.get(name) {
            limit.max = limit.max.min(bound.max);
            limit.allowed = match (&limit.allowed, &bound.allowed) {
                (Some(own), Some(other)) => Some(
                    own.iter()
                        .filter(|label| other.iter().any(|other| other.eq_ignore_ascii_case(label)))
                        .cloned()
                        .collect(),
                ),
                (None, Some(other)) => Some(other.clone()),
                (own, None) => own.clone(),
            };
            limit.blocked.extend(bound.blocked.iter().cloned());
            limit
                .projects
                .retain(|project| bound.projects.contains(project));
            limit.fields.retain(|field| bound.fields.contains(field));
            true
        } else {
            false
        }
    });
    if policy
        .safe_outputs
        .others
        .get("update_project")
        .is_some_and(|limit| limit.projects.is_empty() || limit.fields.is_empty())
    {
        return Err(vec![
            "update_project has no common named projects or fields in both bounds files".to_owned(),
        ]);
    }
    policy.safe_outputs.create_pull_request = match (
        policy.safe_outputs.create_pull_request,
        other.safe_outputs.create_pull_request,
    ) {
        (Some(mut pr), Some(bound)) => {
            pr.unprotected_dot_folders
                .retain(|name| bound.unprotected_dot_folders.contains(name));
            pr.max_patch_size = pr.max_patch_size.min(bound.max_patch_size);
            pr.max_patch_files = pr.max_patch_files.min(bound.max_patch_files);
            for name in bound.protected_files {
                if !pr.protected_files.contains(&name) {
                    pr.protected_files.push(name);
                }
            }
            Some(pr)
        }
        _ => None,
    };
    // Both compiled the one request, so the pull request and head are to
    // agree; a pair that does not pins no single push.
    policy.safe_outputs.push_to_pull_request_branch = match (
        policy.safe_outputs.push_to_pull_request_branch,
        other.safe_outputs.push_to_pull_request_branch,
    ) {
        (Some(push), Some(bound)) if (&push.target, &push.head) != (&bound.target, &bound.head) => {
            return Err(vec![format!(
                "the bounds files pin different pushes: pull request {} at {}, and {} at {}",
                push.target, push.head, bound.target, bound.head
            )]);
        }
        (Some(mut push), Some(bound)) => {
            push.replacement_max_commits = push
                .replacement_max_commits
                .min(bound.replacement_max_commits);
            push.max_patch_size = push.max_patch_size.min(bound.max_patch_size);
            push.max_patch_files = push.max_patch_files.min(bound.max_patch_files);
            for name in bound.protected_files {
                if !push.protected_files.contains(&name) {
                    push.protected_files.push(name);
                }
            }
            Some(push)
        }
        _ => None,
    };
    if policy.safe_outputs.types().next().is_none() {
        return Err(vec!["the bounds files allow no common output type".into()]);
    }
    Ok(policy)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The old tree's allowlist, as a bounds file.
    pub(crate) const BOUNDS: &str = r#"
hosts = ["github.com"]
repos = ["bootc-dev/*", "composefs/*", "cgwalters-bot/*", "cgwalters-forge/*"]
bases = ["main", "master", "bot/**"]
max_outputs = 5
max_patch_bytes = 8388608
max_patch_files = 100

[outputs]
create_pull_request = { max = 1 }
add_comment = { max = 3 }
noop = { max = 1 }
missing_tool = { max = 3 }
missing_data = { max = 3 }

[unprotected_files]
repos = ["cgwalters-bot/homegit", "cgwalters-forge/review"]
files = ["README.md", "AGENTS.md"]
"#;

    const REPO: &str = "bootc-dev/bootc";

    pub(crate) fn bounds() -> Bounds {
        let bounds: Bounds = toml::from_str(BOUNDS).unwrap();
        bounds.validate().unwrap();
        bounds
    }

    fn request() -> Request<'static> {
        Request {
            repo: REPO,
            clone_url: "https://github.com/bootc-dev/bootc",
            base: "main",
            kind: Kind::Branch,
            outputs: "create_pull_request,noop",
            max_outputs: "3",
            job_token: false,
            pull_request: None,
            output_repo: None,
        }
    }

    /// The policy of the request the tests of `check` use.
    pub(crate) fn policy() -> Policy {
        bounds().compile(&request()).unwrap()
    }

    #[test]
    fn dot_folder_bounds_are_exact_and_intersect() {
        for (repos, admitted) in [
            (vec![REPO], true),
            (vec!["BOOTC-DEV/BOOTC"], true),
            (vec!["bootc-dev/other"], false),
        ] {
            let mut bounds = bounds();
            bounds.unprotected_files.repos = repos.into_iter().map(str::to_owned).collect();
            bounds.unprotected_files.dot_folders = vec![".github".into()];
            bounds.validate().unwrap();
            let policy = bounds.compile(&request()).unwrap();
            policy.validate().unwrap();
            let pr = policy.safe_outputs.create_pull_request.as_ref().unwrap();
            assert_eq!(!pr.unprotected_dot_folders.is_empty(), admitted);
            assert!(pr.protect_top_level_dot_folders);
            let loaded: Policy =
                serde_json::from_value(serde_json::to_value(&policy).unwrap()).unwrap();
            assert_eq!(loaded, policy);
            for (left, right, survives) in [
                (policy.clone(), self::policy(), false),
                (self::policy(), policy.clone(), false),
                (policy.clone(), policy, admitted),
            ] {
                assert_eq!(
                    intersect(left, right)
                        .unwrap()
                        .safe_outputs
                        .create_pull_request
                        .unwrap()
                        .unprotected_dot_folders,
                    if survives { vec![".github"] } else { vec![] }
                );
            }
        }
        for name in [
            "*",
            ".github/*",
            ".",
            "..",
            ".git",
            ".gitignore",
            ".github/",
            " .github",
            ".GITHUB",
            ".agents",
            ".husky",
            ".vscode",
            ".circleci",
            ".tekton",
        ] {
            let mut bounds = bounds();
            bounds.unprotected_files.dot_folders = vec![name.into()];
            assert_eq!(
                bounds.validate().unwrap_err().to_string(),
                format!("unprotected_files.dot_folders may only name \".github\", not {name:?}")
            );
            let mut policy = self::policy();
            policy
                .safe_outputs
                .create_pull_request
                .as_mut()
                .unwrap()
                .unprotected_dot_folders = vec![name.into()];
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("policy.json");
            std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
            let error = Policy::load(&path).unwrap_err();
            assert_eq!(
                error.root_cause().to_string(),
                format!(
                    "create_pull_request.unprotected_dot_folders may only name \".github\", not {name:?}"
                )
            );
        }
        let mut bounds = bounds();
        bounds.unprotected_files.repos = vec!["bootc-dev/*".into()];
        assert!(bounds.validate().is_err());
    }

    #[test]
    fn a_push_never_carries_a_folder_exemption() {
        let mut bounds = bounds();
        bounds.outputs.insert(
            PUSH_TO_PULL_REQUEST_BRANCH.into(),
            OutputLimit {
                max: 1,
                branches: vec!["bot/**".into()],
                ..OutputLimit::default()
            },
        );
        bounds.unprotected_files.repos = vec![REPO.into()];
        bounds.unprotected_files.dot_folders = vec![".github".into()];
        let request = Request {
            base: "bot/fix",
            outputs: PUSH_TO_PULL_REQUEST_BRANCH,
            pull_request: Some(("42", "1111111111111111111111111111111111111111")),
            output_repo: Some(REPO),
            ..request()
        };
        let policy = bounds.compile(&request).unwrap();
        let (carrier, rules) = policy.safe_outputs.patch_carrier().unwrap();
        assert_eq!(carrier, PUSH_TO_PULL_REQUEST_BRANCH);
        assert!(rules.protect_top_level_dot_folders);
        assert!(rules.unprotected_dot_folders.is_empty());
        // One written by hand with an exemption does not load.
        let mut value = serde_json::to_value(&policy).unwrap();
        value["safe_outputs"][PUSH_TO_PULL_REQUEST_BRANCH]["unprotected_dot_folders"] =
            serde_json::json!([".github"]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
        assert_eq!(Policy::load(&path).unwrap(), policy);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let error = Policy::load(&path).unwrap_err();
        assert!(
            error
                .root_cause()
                .to_string()
                .contains("unknown field `unprotected_dot_folders`"),
            "{error:#}"
        );
    }

    #[test]
    fn ci_analysis_bounds_admit_topic_bases_without_patch_outputs() {
        // Read at test time, not built in: the release pin's digest does not
        // cover workflow/.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../workflow/analysis.toml");
        let bounds: Bounds = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        bounds.validate().unwrap();
        for (base, outputs, allowed) in [
            ("main", "add_comment", true),
            ("bot/w2-37863744105", "add_comment", true),
            ("topic/nested/branch", "add_comment", true),
            ("bot/../main", "add_comment", false),
            ("bot/w2-37863744105", "create_pull_request", false),
        ] {
            let result = bounds.compile(&Request {
                repo: "cgwalters-forge/agentic-job",
                clone_url: "https://github.com/cgwalters-forge/agentic-job",
                base,
                kind: Kind::Analysis,
                outputs,
                max_outputs: "1",
                job_token: false,
                pull_request: None,
                output_repo: None,
            });
            assert_eq!(result.is_ok(), allowed, "{base}, {outputs}: {result:?}");
        }
    }

    #[test]
    fn project_bounds_intersect_and_round_trip() {
        let first = "https://github.com/orgs/example/projects/1";
        let second = "https://github.com/users/example/projects/2";
        let compile = |projects: &[&str], fields: &[&str]| {
            let mut bounds = bounds();
            bounds.outputs.insert(
                "update_project".to_owned(),
                OutputLimit {
                    max: 2,
                    projects: projects.iter().map(|s| (*s).to_owned()).collect(),
                    fields: fields.iter().map(|s| (*s).to_owned()).collect(),
                    ..OutputLimit::default()
                },
            );
            bounds.validate().unwrap();
            bounds
                .compile(&Request {
                    outputs: "update_project",
                    ..request()
                })
                .unwrap()
        };
        for (projects, fields, accepted) in [
            (vec![second], vec!["Status"], true),
            (
                vec!["https://github.com/orgs/other/projects/1"],
                vec!["Status"],
                false,
            ),
            (vec![second], vec!["Priority"], false),
            (vec![second], vec!["status"], false),
        ] {
            let own = compile(&[first, second], &["Status", "Estimate"]);
            let other = compile(&projects, &fields);
            for (left, right) in [(own.clone(), other.clone()), (other, own)] {
                let result = intersect(left, right);
                assert_eq!(result.is_ok(), accepted, "{projects:?}, {fields:?}");
                if let Ok(policy) = result {
                    let limit = &policy.safe_outputs.others["update_project"];
                    assert_eq!(limit.projects, vec![second]);
                    assert_eq!(limit.fields, vec!["Status"]);
                    let dir = tempfile::tempdir().unwrap();
                    let path = dir.path().join("policy.json");
                    std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
                    assert_eq!(Policy::load(&path).unwrap(), policy);
                }
            }
        }
        for (project, field) in [
            ("http://github.com/orgs/example/projects/1", "Status"),
            ("https://github.com/orgs/example/projects/0", "Status"),
            ("https://github.com/orgs/example/projects/1/", "Status"),
            ("https://github.com/orgs/example/projects/1?x=1", "Status"),
            (first, ""),
            (first, " Status"),
            (first, "Status\n"),
        ] {
            let limit = OutputLimit {
                max: 1,
                projects: vec![project.to_owned()],
                fields: vec![field.to_owned()],
                ..OutputLimit::default()
            };
            assert!(
                limit.validate("update_project").is_err(),
                "{project:?}, {field:?}"
            );
            let mut policy = compile(&[first], &["Status"]);
            policy
                .safe_outputs
                .others
                .insert("update_project".to_owned(), limit);
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("policy.json");
            std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
            let error = Policy::load(&path).unwrap_err();
            let expected = if project != first {
                format!("invalid exact project URL {project:?}")
            } else {
                format!("invalid project field {field:?}")
            };
            assert_eq!(error.root_cause().to_string(), expected);
        }
    }

    #[test]
    fn issue_label_limits_survive_compilation_and_loading() {
        let mut bounds = bounds();
        let limit: OutputLimit =
            toml::from_str("max = 5\nallowed = ['triage', 'blocked']\nblocked = ['blocked']")
                .unwrap();
        bounds
            .outputs
            .insert("create_issue".to_owned(), limit.clone());
        bounds.validate().unwrap();
        let policy = bounds
            .compile(&Request {
                outputs: "create_issue",
                ..request()
            })
            .unwrap();
        let configured = &policy.safe_outputs.others["create_issue"];
        assert_eq!(configured.max, 3);
        assert_eq!(configured.allowed, limit.allowed);
        assert_eq!(configured.blocked, limit.blocked);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
        assert_eq!(Policy::load(&path).unwrap(), policy);
        for output in ["noop", CREATE_PULL_REQUEST, "add_comment"] {
            assert!(limit.validate(output).is_err(), "{output}");
        }
        for label in ["", " ", "triage ", "bad\nlabel"] {
            let limit = OutputLimit {
                max: 1,
                allowed: Some(vec![label.to_owned()]),
                ..OutputLimit::default()
            };
            assert!(limit.validate("create_issue").is_err(), "{label:?}");
        }
    }

    #[test]
    fn issue_actions_compile_with_label_bounds() {
        let mut bounds = bounds();
        for output in ["close_issue", "add_labels"] {
            bounds.outputs.insert(
                output.to_owned(),
                OutputLimit {
                    max: 2,
                    allowed: (output == "add_labels").then(|| vec!["triage".to_owned()]),
                    ..Default::default()
                },
            );
            bounds.validate().unwrap();
            let policy = bounds
                .compile(&Request {
                    outputs: output,
                    ..request()
                })
                .unwrap();
            policy.validate().unwrap();
            assert_eq!(policy.safe_outputs.max_of(output), Some(2));
        }
        bounds.outputs.get_mut("add_labels").unwrap().allowed = None;
        assert!(bounds.validate().is_err());
    }

    #[test]
    fn label_bounds_intersect_without_widening_either_file() {
        for (own, other, expected) in [
            (
                Some(vec!["triage", "docs"]),
                Some(vec!["TRIAGE", "release"]),
                Some(vec!["triage"]),
            ),
            (None, Some(vec!["triage"]), Some(vec!["triage"])),
            (Some(vec!["triage"]), None, Some(vec!["triage"])),
            (Some(vec!["triage"]), Some(vec![]), Some(vec![])),
        ] {
            let configured = |allowed: Option<Vec<&str>>, blocked: &str| {
                let mut bounds = bounds();
                bounds.outputs.insert(
                    "create_issue".to_owned(),
                    OutputLimit {
                        max: 2,
                        allowed: allowed
                            .map(|labels| labels.into_iter().map(str::to_owned).collect()),
                        blocked: vec![blocked.to_owned()],
                        ..OutputLimit::default()
                    },
                );
                bounds
                    .compile(&Request {
                        outputs: "create_issue",
                        ..request()
                    })
                    .unwrap()
            };
            let policy = intersect(
                configured(own, "own-blocked"),
                configured(other, "org-blocked"),
            )
            .unwrap();
            let limit = &policy.safe_outputs.others["create_issue"];
            assert_eq!(
                limit.allowed,
                expected.map(|labels| labels.into_iter().map(str::to_owned).collect())
            );
            assert_eq!(limit.blocked, ["own-blocked", "org-blocked"]);
        }
    }

    #[test]
    fn requests_against_the_bounds() {
        let ok = request();
        let own = |repo: &'static str, clone_url: &'static str| Request {
            repo,
            clone_url,
            ..ok
        };
        // The name, the request, and a part of the refusal if it is refused.
        let cases: &[(&str, Request<'_>, Option<&str>)] = &[
            ("ok", ok, None),
            (
                "another owner",
                own("evil/bootc", "https://github.com/evil/bootc"),
                Some("repo \"evil/bootc\" is not within"),
            ),
            (
                "a repo of another case",
                own("BOOTC-DEV/bootc", "https://github.com/bootc-dev/bootc"),
                None,
            ),
            (
                "a malformed repo",
                Request {
                    repo: "bootc-dev/bootc/x",
                    ..ok
                },
                Some("repo "),
            ),
            (
                "a repo of dots",
                Request {
                    repo: "bootc-dev/..",
                    ..ok
                },
                Some("repo "),
            ),
            (
                "a base not listed",
                Request {
                    base: "release",
                    ..ok
                },
                Some("base \"release\""),
            ),
            (
                "a bot branch",
                Request {
                    base: "bot/agent-run-praxis",
                    ..ok
                },
                None,
            ),
            (
                "a base with ..",
                Request {
                    base: "bot/../main",
                    ..ok
                },
                Some("base "),
            ),
            (
                "a type not listed",
                Request {
                    outputs: "create_pull_request,delete_repo",
                    ..ok
                },
                Some("output type \"delete_repo\""),
            ),
            (
                "no types",
                Request {
                    outputs: " , ",
                    ..ok
                },
                Some("no output type"),
            ),
            (
                "too many outputs",
                Request {
                    max_outputs: "6",
                    ..ok
                },
                Some("max_outputs"),
            ),
            (
                "no number",
                Request {
                    max_outputs: "many",
                    ..ok
                },
                Some("max_outputs"),
            ),
            (
                "zero",
                Request {
                    max_outputs: "0",
                    ..ok
                },
                Some("max_outputs"),
            ),
            (
                "a signed number",
                Request {
                    max_outputs: "+2",
                    ..ok
                },
                Some("max_outputs"),
            ),
            (
                "no number at all",
                Request {
                    max_outputs: "",
                    ..ok
                },
                Some("max_outputs"),
            ),
            (
                "a pull request from an analysis run",
                Request {
                    kind: Kind::Analysis,
                    ..ok
                },
                Some("analysis"),
            ),
            (
                "an analysis run's comments",
                Request {
                    kind: Kind::Analysis,
                    outputs: "noop,add_comment",
                    ..ok
                },
                None,
            ),
            (
                "all types",
                Request {
                    outputs: "all",
                    max_outputs: "max",
                    ..ok
                },
                None,
            ),
            (
                "all types of an analysis run",
                Request {
                    kind: Kind::Analysis,
                    outputs: "all",
                    ..ok
                },
                None,
            ),
            (
                "a clone URL with .git",
                Request {
                    clone_url: "https://github.com/bootc-dev/bootc.git",
                    ..ok
                },
                None,
            ),
            (
                "a clone URL of another host",
                Request {
                    clone_url: "https://evil.example/bootc-dev/bootc",
                    ..ok
                },
                Some("host"),
            ),
            (
                "a clone URL of another repository",
                Request {
                    clone_url: "https://github.com/evil/bootc",
                    ..ok
                },
                Some("does not name"),
            ),
            (
                "a clone URL with a user",
                Request {
                    clone_url: "https://x@github.com/bootc-dev/bootc",
                    ..ok
                },
                Some("host"),
            ),
            (
                "a clone URL with a port",
                Request {
                    clone_url: "https://github.com:444/bootc-dev/bootc",
                    ..ok
                },
                Some("host"),
            ),
            (
                "a clone URL over ssh",
                Request {
                    clone_url: "ssh://github.com/bootc-dev/bootc",
                    ..ok
                },
                Some("is not https://"),
            ),
            (
                "a clone URL with more",
                Request {
                    clone_url: "https://github.com/bootc-dev/bootc/../x",
                    ..ok
                },
                Some("does not name"),
            ),
            (
                "a clone URL with a query",
                Request {
                    clone_url: "https://github.com/bootc-dev/bootc?x=1",
                    ..ok
                },
                Some("does not name"),
            ),
        ];
        let bounds = bounds();
        for (name, request, want) in cases {
            match (bounds.compile(request), want) {
                (Ok(_), None) => {}
                (Err(errors), Some(want)) => {
                    assert!(
                        errors.iter().any(|e| e.contains(want)),
                        "{name}: {errors:?}"
                    );
                }
                (result, _) => panic!("{name}: {result:?}"),
            }
        }
    }

    #[test]
    fn what_the_job_token_cannot_apply_is_refused() {
        let mut bounds = bounds();
        bounds.outputs.insert(
            "update_project".to_owned(),
            OutputLimit {
                max: 1,
                projects: vec!["https://github.com/orgs/example/projects/2".to_owned()],
                fields: vec!["Status".to_owned()],
                ..OutputLimit::default()
            },
        );
        bounds.validate().unwrap();
        // (the outputs, whether apply holds only the job token, the types
        // admitted or a part of the refusal)
        type Expected = Result<&'static [&'static str], &'static str>;
        let cases: &[(&str, bool, Expected)] = &[
            (
                "update_project",
                true,
                Err(
                    "output type \"update_project\" needs a token with project scope as SAFE_OUTPUTS_PAT",
                ),
            ),
            (
                "noop,update_project",
                true,
                Err("without an apply environment, apply holds the job token"),
            ),
            ("update_project", false, Ok(&["update_project"])),
            (
                "create_pull_request",
                true,
                Err(
                    "output type \"create_pull_request\" needs a user's token that can fork the output repository",
                ),
            ),
            (
                "create_pull_request,add_comment,noop,missing_tool,missing_data",
                true,
                Err("without an apply environment, apply holds the job token"),
            ),
            (
                "create_pull_request,add_comment,noop,missing_tool,missing_data",
                false,
                Ok(&[
                    "create_pull_request",
                    "add_comment",
                    "missing_data",
                    "missing_tool",
                    "noop",
                ]),
            ),
            (
                "add_comment,noop,missing_tool,missing_data",
                true,
                Ok(&["add_comment", "missing_data", "missing_tool", "noop"]),
            ),
            (
                "all",
                true,
                Ok(&["add_comment", "missing_data", "missing_tool", "noop"]),
            ),
            (
                "all",
                false,
                Ok(&[
                    "create_pull_request",
                    "add_comment",
                    "missing_data",
                    "missing_tool",
                    "noop",
                    "update_project",
                ]),
            ),
        ];
        for (outputs, job_token, want) in cases {
            let result = bounds.compile(&Request {
                outputs,
                job_token: *job_token,
                ..request()
            });
            match (result, want) {
                (Ok(policy), Ok(types)) => assert_eq!(
                    policy.safe_outputs.types().collect::<Vec<_>>(),
                    *types,
                    "{outputs} {job_token}"
                ),
                (Err(errors), Err(want)) => assert!(
                    errors.iter().any(|e| e.contains(want)),
                    "{outputs} {job_token}: {errors:?}"
                ),
                (result, _) => panic!("{outputs} {job_token}: {result:?}"),
            }
        }
        // The other types write to a repository, which the job token can.
        for output in OUTPUT_TYPES {
            assert_eq!(
                NOT_FOR_THE_JOB_TOKEN.iter().any(|(name, _)| name == output),
                [
                    "create_pull_request",
                    "push_to_pull_request_branch",
                    "update_project"
                ]
                .contains(output),
                "{output}"
            );
        }
    }

    #[test]
    fn every_reason_is_given() {
        let request = Request {
            repo: "evil/x",
            clone_url: "https://github.com/evil/x",
            base: "release",
            kind: Kind::Analysis,
            outputs: "create_pull_request,delete_repo",
            max_outputs: "many",
            job_token: false,
            pull_request: None,
            output_repo: None,
        };
        let errors = bounds().compile(&request).unwrap_err();
        assert_eq!(errors.len(), 5, "{errors:?}");
    }

    pub(crate) const HEAD: &str = "2222222222222222222222222222222222222222";

    /// Bounds that let a run push to branches this system names.
    fn push_bounds() -> Bounds {
        let mut bounds = bounds();
        bounds.outputs.insert(
            PUSH_TO_PULL_REQUEST_BRANCH.to_owned(),
            OutputLimit {
                max: 1,
                branches: vec!["agent-run-*".to_owned(), "dispatch/**".to_owned()],
                ..OutputLimit::default()
            },
        );
        bounds.validate().unwrap();
        bounds
    }

    fn push_request() -> Request<'static> {
        Request {
            base: "agent-run-12",
            outputs: "push_to_pull_request_branch,noop",
            pull_request: Some(("42", HEAD)),
            output_repo: Some(REPO),
            ..request()
        }
    }

    /// The policy of a run that pushes to pull request 42's branch,
    /// `agent-run-12`, at [`HEAD`].
    pub(crate) fn push_policy() -> Policy {
        push_bounds().compile(&push_request()).unwrap()
    }

    #[test]
    fn push_requests_against_the_bounds() {
        let ok = push_request();
        // The name, the request, and a part of the refusal if it is refused.
        let cases: &[(&str, Request<'_>, Option<&str>)] = &[
            ("ok", ok, None),
            (
                "a nested branch",
                Request {
                    base: "dispatch/implement/agent-run-12",
                    ..ok
                },
                None,
            ),
            (
                "a branch the push globs do not name",
                Request { base: "main", ..ok },
                Some(
                    "pull request branch \"main\" is not within the bounds (agent-run-*, dispatch/**)",
                ),
            ),
            (
                "a base the bounds admit for new pull requests only",
                Request {
                    base: "bot/x",
                    ..ok
                },
                Some("pull request branch \"bot/x\" is not within"),
            ),
            (
                "a branch gh-aw would push by another name",
                Request {
                    base: "agent-run--12",
                    ..ok
                },
                Some("is not within"),
            ),
            (
                "a branch ending in a dash",
                Request {
                    base: "agent-run-",
                    ..ok
                },
                Some("is not within"),
            ),
            (
                "no pull request",
                Request {
                    pull_request: None,
                    output_repo: None,
                    ..ok
                },
                Some("needs the pull request and its head commit"),
            ),
            (
                "a pull request that is not a number",
                Request {
                    pull_request: Some(("42 ", HEAD)),
                    ..ok
                },
                Some("pull request \"42 \" is not a number"),
            ),
            (
                "a pull request of a leading zero",
                Request {
                    pull_request: Some(("042", HEAD)),
                    ..ok
                },
                Some("is not a number"),
            ),
            (
                "a short head",
                Request {
                    pull_request: Some(("42", "2222222")),
                    ..ok
                },
                Some("is not a 40-character lowercase commit SHA"),
            ),
            (
                "an upper-case head",
                Request {
                    pull_request: Some(("42", "2222222222222222222222222222222222222ABC")),
                    ..ok
                },
                Some("is not a 40-character lowercase commit SHA"),
            ),
            (
                "a push beside a pull request",
                Request {
                    outputs: "push_to_pull_request_branch,create_pull_request",
                    ..ok
                },
                Some("not both create_pull_request and push_to_pull_request_branch"),
            ),
            (
                "a push in an analysis run",
                Request {
                    kind: Kind::Analysis,
                    ..ok
                },
                Some(
                    "an analysis run hands back no change, so it can't push_to_pull_request_branch",
                ),
            ),
            (
                "the same repository, in another case",
                Request {
                    output_repo: Some("Bootc-Dev/Bootc"),
                    ..ok
                },
                None,
            ),
            // The push goes to the applying identity's fork, as a new
            // pull request's branch does: any repository the bounds let
            // runs work on, and never with the job token, which has none.
            (
                "another repository the bounds allow runs in",
                Request {
                    repo: "bootc-dev/other",
                    clone_url: "https://github.com/bootc-dev/other",
                    output_repo: Some("bootc-dev/other"),
                    ..ok
                },
                None,
            ),
            (
                "apply holding only the job token",
                Request {
                    job_token: true,
                    ..ok
                },
                Some(
                    "output type \"push_to_pull_request_branch\" needs the token of the user whose fork",
                ),
            ),
            (
                "outputs applied in another repository",
                Request {
                    output_repo: Some("cgwalters-bot/bootc"),
                    ..ok
                },
                Some("not to \"cgwalters-bot/bootc\""),
            ),
            (
                "no repository the outputs are applied in",
                Request {
                    output_repo: None,
                    ..ok
                },
                Some("not to an unnamed one"),
            ),
            (
                "a branch the globs name in another case",
                Request {
                    base: "DISPATCH/implement/agent-run-12",
                    ..ok
                },
                Some("is not within"),
            ),
            (
                "a pull request without a push",
                Request {
                    outputs: "noop",
                    ..ok
                },
                Some("a pull request and a head are only for push_to_pull_request_branch"),
            ),
        ];
        let bounds = push_bounds();
        for (name, request, refusal) in cases {
            match (bounds.compile(request), refusal) {
                (Ok(_), None) => {}
                (Err(errors), Some(want)) => assert!(
                    errors.iter().any(|e| e.contains(want)),
                    "{name}: {errors:?}"
                ),
                (result, _) => panic!("{name}: {result:?}"),
            }
        }
        // Bounds that do not list the type admit no push at all.
        let errors = super::tests::bounds().compile(&ok).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("output type \"push_to_pull_request_branch\" is not within")),
            "{errors:?}"
        );
    }

    #[test]
    fn a_push_policy_names_its_pull_request_and_always_a_max() {
        let bounds = push_bounds();
        let policy = bounds.compile(&push_request()).unwrap();
        assert_eq!(policy.base, "agent-run-12");
        assert!(policy.safe_outputs.create_pull_request.is_none());
        let push = policy
            .safe_outputs
            .push_to_pull_request_branch
            .as_ref()
            .unwrap();
        assert_eq!(
            (push.max, push.target.as_str(), push.head.as_str()),
            (1, "42", HEAD)
        );
        assert!(push.protect_top_level_dot_folders);
        assert_eq!(
            policy.safe_outputs.patch_carrier().map(|(name, _)| name),
            Some(PUSH_TO_PULL_REQUEST_BRANCH)
        );
        // gh-aw's handler takes a missing `max` for no limit, and sets
        // `allow_workflows` only when the configuration does.
        let json = serde_json::to_value(&policy.safe_outputs).unwrap();
        let config = &json[PUSH_TO_PULL_REQUEST_BRANCH];
        assert_eq!(config["max"], 1, "{config}");
        assert_eq!(config["target"], "42", "{config}");
        assert!(config.get("allow_workflows").is_none(), "{config}");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
        assert_eq!(Policy::load(&path).unwrap(), policy);

        // `all` with a pull request means the push; without, a new one.
        let all = bounds
            .compile(&Request {
                outputs: "all",
                max_outputs: "max",
                ..push_request()
            })
            .unwrap();
        assert!(all.safe_outputs.push_to_pull_request_branch.is_some());
        assert!(all.safe_outputs.create_pull_request.is_none());
        let all = bounds
            .compile(&Request {
                outputs: "all",
                max_outputs: "max",
                ..request()
            })
            .unwrap();
        assert!(all.safe_outputs.push_to_pull_request_branch.is_none());
        assert!(all.safe_outputs.create_pull_request.is_some());

        // What `policy` never writes does not load.
        type Edit = fn(&mut Policy);
        let edits: &[(&str, Edit)] = &[
            ("an analysis run", |p| p.kind = Kind::Analysis),
            ("two pushes", |p| {
                p.safe_outputs
                    .push_to_pull_request_branch
                    .as_mut()
                    .unwrap()
                    .max = 2;
            }),
            ("no head", |p| {
                p.safe_outputs
                    .push_to_pull_request_branch
                    .as_mut()
                    .unwrap()
                    .head = String::new();
            }),
            ("a target of all", |p| {
                p.safe_outputs
                    .push_to_pull_request_branch
                    .as_mut()
                    .unwrap()
                    .target = "*".into();
            }),
            ("dot-folders open", |p| {
                p.safe_outputs
                    .push_to_pull_request_branch
                    .as_mut()
                    .unwrap()
                    .protect_top_level_dot_folders = false;
            }),
            ("a branch renamed on push", |p| p.base = "agent--run".into()),
            ("beside a pull request", |p| {
                p.safe_outputs.create_pull_request =
                    super::tests::policy().safe_outputs.create_pull_request;
            }),
        ];
        for (name, edit) in edits {
            let mut edited = policy.clone();
            edit(&mut edited);
            assert!(edited.validate().is_err(), "{name}");
        }
        let mut json = serde_json::to_value(&policy).unwrap();
        json["safe_outputs"][PUSH_TO_PULL_REQUEST_BRANCH]["allow_workflows"] = true.into();
        assert!(serde_json::from_value::<Policy>(json).is_err());
    }

    #[test]
    fn push_bounds_must_name_branches_and_one_push() {
        let valid = |output: &str, text: &str| {
            toml::from_str::<OutputLimit>(text).is_ok_and(|limit| limit.validate(output).is_ok())
        };
        for (output, text, ok) in [
            (
                PUSH_TO_PULL_REQUEST_BRANCH,
                "max = 1\nbranches = ['agent-run-*']",
                true,
            ),
            (PUSH_TO_PULL_REQUEST_BRANCH, "max = 1", false),
            (PUSH_TO_PULL_REQUEST_BRANCH, "max = 1\nbranches = []", false),
            // The per-repository list a push to the target's own branches
            // needed (#340) is gone with those pushes, and refused.
            (
                PUSH_TO_PULL_REQUEST_BRANCH,
                "max = 1\nbranches = ['agent-run-*']\nrepos = ['o/r']",
                false,
            ),
            ("add_comment", "max = 1\nbranches = ['x']", false),
        ] {
            assert_eq!(valid(output, text), ok, "{output} {text}");
        }
        let mut bounds = push_bounds();
        bounds
            .outputs
            .get_mut(PUSH_TO_PULL_REQUEST_BRANCH)
            .unwrap()
            .max = 2;
        assert!(bounds.validate().is_err());
    }

    #[test]
    fn push_bounds_intersect() {
        let own = push_bounds().compile(&push_request()).unwrap();
        let mut org_bounds = push_bounds();
        org_bounds.max_patch_files = 7;
        let org = org_bounds.compile(&push_request()).unwrap();
        let both = intersect(own.clone(), org).unwrap();
        let push = both.safe_outputs.push_to_pull_request_branch.unwrap();
        assert_eq!(push.max_patch_files, 7);
        assert_eq!(push.head, HEAD);
        // Two that pin different pushes are refused, not merged.
        for edit in [
            (|p: &mut Push| p.target = "43".into()) as fn(&mut Push),
            |p| p.head = "3".repeat(40),
        ] {
            let mut other = own.clone();
            edit(
                other
                    .safe_outputs
                    .push_to_pull_request_branch
                    .as_mut()
                    .unwrap(),
            );
            let errors = intersect(own.clone(), other).unwrap_err();
            assert!(errors[0].contains("pin different pushes"), "{errors:?}");
        }
        // An organization file that allows no push leaves none.
        let mut no_push = own;
        no_push.safe_outputs.push_to_pull_request_branch = None;
        let mut org = super::tests::policy();
        org.safe_outputs.create_pull_request = None;
        let left = intersect(no_push, org).unwrap();
        assert!(left.safe_outputs.push_to_pull_request_branch.is_none());
    }

    #[test]
    fn replacement_is_explicit_and_only_tightens() {
        for (caller, organization, want) in [(0, 10, 0), (10, 0, 0), (10, 3, 3), (2, 10, 2)] {
            let compile = |count| {
                let mut bounds = push_bounds();
                bounds
                    .outputs
                    .get_mut(PUSH_TO_PULL_REQUEST_BRANCH)
                    .unwrap()
                    .replacement_max_commits = count;
                bounds.validate().unwrap();
                bounds.compile(&push_request()).unwrap()
            };
            let both = intersect(compile(caller), compile(organization)).unwrap();
            assert_eq!(
                both.safe_outputs
                    .push_to_pull_request_branch
                    .unwrap()
                    .replacement_max_commits,
                want
            );
        }
        for (output, count, accepted) in [
            (PUSH_TO_PULL_REQUEST_BRANCH, 50, true),
            (PUSH_TO_PULL_REQUEST_BRANCH, 51, false),
            (CREATE_PULL_REQUEST, 1, false),
            ("noop", 1, false),
        ] {
            let limit = OutputLimit {
                max: 1,
                replacement_max_commits: count,
                branches: if output == PUSH_TO_PULL_REQUEST_BRANCH {
                    vec!["agent-run-*".into()]
                } else {
                    Vec::new()
                },
                ..OutputLimit::default()
            };
            assert_eq!(limit.validate(output).is_ok(), accepted);
        }
    }

    #[test]
    fn ceilings_and_pull_request_settings() {
        let bounds = bounds();
        let compile = |request: Request<'_>| bounds.compile(&request).unwrap();

        let all = compile(Request {
            outputs: "all",
            max_outputs: "max",
            ..request()
        });
        assert_eq!(all.max_outputs, 5);
        assert_eq!(
            all.safe_outputs.types().collect::<Vec<_>>(),
            [
                "create_pull_request",
                "add_comment",
                "missing_data",
                "missing_tool",
                "noop"
            ]
        );
        // The lower of the bound and the request, for each type.
        for (max_outputs, output, want) in [
            ("max", "add_comment", 3),
            ("2", "add_comment", 2),
            ("2", "noop", 1),
            ("2", "create_pull_request", 1),
        ] {
            let policy = compile(Request {
                outputs: "all",
                max_outputs,
                ..request()
            });
            assert_eq!(
                policy.safe_outputs.max_of(output),
                Some(want),
                "{max_outputs} {output}"
            );
        }

        let analysis = compile(Request {
            kind: Kind::Analysis,
            outputs: "all",
            ..request()
        });
        assert_eq!(analysis.safe_outputs.create_pull_request, None);
        assert_eq!(analysis.safe_outputs.max_of("create_pull_request"), None);

        // Asked for twice, allowed once.
        let twice = compile(Request {
            outputs: "noop, noop ,create_pull_request",
            ..request()
        });
        assert_eq!(
            twice.safe_outputs.types().collect::<Vec<_>>(),
            ["create_pull_request", "noop"]
        );

        let pr = policy().safe_outputs.create_pull_request.unwrap();
        assert!(pr.draft);
        assert!(pr.protect_top_level_dot_folders);
        assert_eq!(pr.protected_files_policy, ProtectedFilesPolicy::Blocked);
        assert_eq!((pr.max_patch_size, pr.max_patch_files), (8192, 100));
    }

    #[test]
    fn organization_policy_only_tightens_bounds() {
        let local = bounds();
        let mut org = bounds();
        org.max_outputs = 2;
        org.max_patch_bytes = 4096;
        org.max_patch_files = 3;
        org.outputs.remove("missing_data");
        org.unprotected_files = Unprotected::default();
        let request = Request {
            repo: "cgwalters-bot/homegit",
            clone_url: "https://github.com/cgwalters-bot/homegit",
            outputs: "all",
            max_outputs: "max",
            ..request()
        };
        let a = local.compile(&request).unwrap();
        let b = org.compile(&request).unwrap();
        for (left, right) in [(a.clone(), b.clone()), (b, a)] {
            let policy = intersect(left, right).unwrap();
            assert_eq!(policy.max_outputs, 2);
            assert_eq!(policy.max_patch_bytes, 4096);
            assert_eq!(policy.safe_outputs.max_of("missing_data"), None);
            let pr = policy.safe_outputs.create_pull_request.unwrap();
            assert_eq!(pr.max_patch_files, 3);
            assert!(pr.protected_files.contains(&"README.md".into()));
        }
        assert!(
            org.compile(&Request {
                outputs: "missing_data",
                ..request
            })
            .is_err()
        );
        org.repos = vec!["another/*".into()];
        assert!(org.compile(&request).is_err());
    }

    #[test]
    fn disjoint_output_bounds_refuse_in_both_orders() {
        let mut local = bounds();
        let mut org = bounds();
        local.outputs.retain(|name, _| name == "noop");
        org.outputs.retain(|name, _| name == "missing_data");
        let request = Request {
            outputs: "all",
            ..request()
        };
        let a = local.compile(&request).unwrap();
        let b = org.compile(&request).unwrap();
        for (left, right) in [(a.clone(), b.clone()), (b, a)] {
            assert_eq!(
                intersect(left, right).unwrap_err(),
                vec!["the bounds files allow no common output type"]
            );
        }
    }

    #[test]
    fn docs_are_unprotected_only_where_the_bounds_say() {
        let bounds = bounds();
        let cases = [
            ("cgwalters-bot/homegit", true),
            ("CGWalters-Bot/Homegit", true),
            ("cgwalters-forge/review", true),
            (REPO, false),
            // Named exactly: a glob of the same owner is not enough.
            ("cgwalters-bot/bootc", false),
            ("cgwalters-forge/homegit", false),
        ];
        for (repo, own) in cases {
            let protected = bounds.protected_files(repo);
            let dropped: Vec<&str> = DEFAULT_PROTECTED_FILES
                .iter()
                .copied()
                .filter(|name| !protected.iter().any(|p| p.as_str() == *name))
                .collect();
            let want: &[&str] = if own {
                &["README.md", "AGENTS.md"]
            } else {
                &[]
            };
            assert_eq!(dropped, want, "{repo}");
        }
    }

    #[test]
    fn globs() {
        let cases = [
            ("bootc-dev/*", "bootc-dev/bootc", true),
            ("bootc-dev/*", "BOOTC-DEV/Bootc", true),
            ("bootc-dev/*", "bootc-dev/a/b", false),
            ("bootc-dev/*", "xbootc-dev/a", false),
            ("bot/**", "bot/a/b", true),
            ("bot/**", "bot", false),
            ("main", "main", true),
            ("main", "mainx", false),
            // Everything but the stars is itself.
            ("a.b", "axb", false),
            ("a+b[c]", "a+b[c]", true),
            ("ma(in", "ma(in", true),
        ];
        for (pattern, value, want) in cases {
            assert_eq!(
                glob_matches(&[pattern.to_owned()], value),
                want,
                "{pattern} {value}"
            );
        }
    }

    #[test]
    fn bad_bounds_files() {
        let with = |from: &str, to: &str| BOUNDS.replace(from, to);
        let cases = [
            (
                "an unknown key",
                format!("{BOUNDS}\nextra = 1\n"),
                "unknown field",
            ),
            (
                "an unknown output type",
                with("noop = ", "delete_repo = "),
                "delete_repo",
            ),
            (
                "no repositories",
                with(
                    "repos = [\"bootc-dev/*\", \"composefs/*\", \"cgwalters-bot/*\", \"cgwalters-forge/*\"]",
                    "repos = []",
                ),
                "`repos` is empty",
            ),
            (
                "no hosts",
                with("hosts = [\"github.com\"]", ""),
                "missing field `hosts`",
            ),
            (
                "two pull requests",
                with(
                    "create_pull_request = { max = 1 }",
                    "create_pull_request = { max = 2 }",
                ),
                "a run hands back one patch",
            ),
            (
                "a ceiling of zero",
                with("noop = { max = 1 }", "noop = { max = 0 }"),
                "at least 1",
            ),
            (
                "no room for a patch",
                with("max_patch_bytes = 8388608", "max_patch_bytes = 10"),
                "max_patch_bytes",
            ),
        ];
        for (name, text, want) in cases {
            let err = toml::from_str::<Bounds>(&text)
                .map_err(anyhow::Error::from)
                .and_then(|bounds| bounds.validate())
                .unwrap_err();
            assert!(format!("{err:#}").contains(want), "{name}: {err:#}");
        }
    }

    /// The concern of tracker#281: a request's text must not become
    /// structure. Whatever a field holds, the policy that comes back out
    /// of the JSON is the one that went in, with the same keys.
    #[test]
    fn a_field_cannot_add_a_key() {
        let hostile = [
            "main\",\"max_outputs\":99,\"x\":\"",
            "main\n\"max_outputs\": 99",
            "main\\\",\"safe_outputs\":{}",
            "main\u{0}\u{2028}'</script>",
        ];
        let bounds = bounds();
        let good = policy();
        let keys = |policy: &Policy| {
            let value: serde_json::Value = serde_json::to_value(policy).unwrap();
            value
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        };
        for text in hostile {
            // Refused where a field is the request's ...
            for request in [
                Request {
                    repo: text,
                    ..request()
                },
                Request {
                    clone_url: text,
                    ..request()
                },
                Request {
                    base: text,
                    ..request()
                },
                Request {
                    outputs: text,
                    ..request()
                },
                Request {
                    max_outputs: text,
                    ..request()
                },
            ] {
                assert!(bounds.compile(&request).is_err(), "{text:?}");
            }
            // ... and inert even in a policy that held it.
            let policy = Policy {
                repo: text.to_owned(),
                base: text.to_owned(),
                clone_url: text.to_owned(),
                ..good.clone()
            };
            let json = serde_json::to_string_pretty(&policy).unwrap();
            let back: Policy = serde_json::from_str(&json).unwrap();
            assert_eq!(back, policy, "{text:?}");
            assert_eq!(keys(&back), keys(&good), "{text:?}");
            assert_eq!(back.max_outputs, good.max_outputs);
        }
    }

    /// `run` holds a policy to what it uses its values as before it
    /// clones (`run::clone::check`), minutes after `policy` wrote it.
    /// Nothing `policy` admits may fail there: the edges of what the
    /// patterns here let through are held to that check, and what it
    /// refuses of a name is refused here first.
    #[test]
    fn what_policy_writes_run_can_clone() {
        let all = Bounds {
            repos: vec!["*/*".to_owned()],
            ..bounds()
        };
        for name in [".", "..", "...", "....."] {
            let repo = format!("bootc-dev/{name}");
            let clone_url = format!("https://github.com/{repo}");
            let request = Request {
                repo: &repo,
                clone_url: &clone_url,
                ..request()
            };
            let errors = all.compile(&request).expect_err(&repo);
            assert!(errors[0].starts_with("repo "), "{repo}: {errors:?}");
        }
        let long_base = format!("bot/{}", "x".repeat(196));
        let cases = [
            (REPO, "https://github.com/bootc-dev/bootc", "main"),
            (REPO, "https://GitHub.com/bootc-dev/bootc.git", "master"),
            (
                "cgwalters-bot/a.b_c-d",
                "https://github.com/cgwalters-bot/a.b_c-d",
                "bot/a.b_c-d/e",
            ),
            (
                "composefs/_",
                "https://github.com/composefs/_",
                long_base.as_str(),
            ),
            ("bootc-dev/.x", "https://github.com/bootc-dev/.x", "bot/_/-"),
        ];
        for (repo, clone_url, base) in cases {
            let request = Request {
                repo,
                clone_url,
                base,
                ..request()
            };
            let policy = bounds()
                .compile(&request)
                .unwrap_or_else(|errors| panic!("{repo} {base}: {errors:?}"));
            crate::run::clone::check(&policy)
                .unwrap_or_else(|err| panic!("{repo} {clone_url} {base}: {err:#}"));
        }
    }

    #[test]
    fn a_policy_that_policy_could_not_have_written_is_refused() {
        let good = policy();
        good.validate().unwrap();
        let pr = good.safe_outputs.create_pull_request.clone().unwrap();
        let with_pr = |pr: PullRequest| Policy {
            safe_outputs: SafeOutputs {
                create_pull_request: Some(pr),
                ..good.safe_outputs.clone()
            },
            ..good.clone()
        };
        let mut other_type = good.clone();
        other_type.safe_outputs.others.insert(
            "create_discussion".to_owned(),
            OutputLimit {
                max: 5,
                ..OutputLimit::default()
            },
        );
        let cases = [
            (
                "a type with no configuration here",
                other_type,
                "create_discussion",
            ),
            (
                "a pull request that is not a draft",
                with_pr(PullRequest {
                    draft: false,
                    ..pr.clone()
                }),
                "not a draft",
            ),
            (
                "unprotected dot-folders",
                with_pr(PullRequest {
                    protect_top_level_dot_folders: false,
                    ..pr.clone()
                }),
                "dot-folders",
            ),
            (
                "two pull requests",
                with_pr(PullRequest {
                    max: 2,
                    ..pr.clone()
                }),
                "more than one",
            ),
        ];
        for (name, policy, want) in cases {
            let err = policy.validate().unwrap_err();
            assert!(format!("{err:#}").contains(want), "{name}: {err:#}");
        }
    }

    #[test]
    fn a_policy_that_does_not_refuse_protected_files_is_no_policy() {
        let json = serde_json::to_string(&policy()).unwrap();
        assert!(serde_json::from_str::<Policy>(&json).is_ok());
        for (from, to) in [
            ("\"blocked\"", "\"allowed\""),
            (
                "\"draft\":true",
                "\"draft\":true,\"allowed_files\":[\"**\"]",
            ),
            ("\"kind\":\"branch\"", "\"kind\":\"branch\",\"extra\":1"),
        ] {
            let changed = json.replace(from, to);
            assert_ne!(changed, json, "{from}");
            assert!(serde_json::from_str::<Policy>(&changed).is_err(), "{from}");
        }
    }
}
