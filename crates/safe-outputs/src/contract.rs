//! The effective contract: what `policy.json` holds, one run's request
//! once it is within the bounds ([`Policy`]), and what holds it to the
//! rules it can be written with ([`Policy::validate`]).
//!
//! Compiling a request into a policy, and admitting the event that asked
//! for it, are the caller's (agentic-job's `policy` and `event`); reading
//! the file is the caller's too. Bounds parsing and the intersection of
//! two bounds files' policies are [`crate::bounds`].

use std::collections::BTreeMap;
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde::{Deserialize, Serialize};

pub use crate::advisory::Advisory;
use crate::check::{is_patch_file_name, patch_file_name_in};
use crate::{
    CONTRACT, CREATE_PULL_REQUEST, CREATE_REVIEW_COMMENT, Forge, HIDE_COMMENT, HIDE_REASONS,
    OUTPUT_TYPES, PUSH_TO_PULL_REQUEST_BRANCH, link_domains,
};

/// The output type that sets fields on a Projects v2 board: a destination
/// of its own, outside the output repository.
pub const UPDATE_PROJECT: &str = "update_project";

/// The fields an update may change, of those gh-aw's rules let a request
/// hold; bounds list which in `fields`, and `check` refuses any other key.
/// The handlers cannot be relied on for this: `update_issue` ignores
/// `allow_title` and `allow_status`, and the request's `draft` and
/// `update_branch` override `update_pull_request`'s configuration. Left
/// out: an issue's `labels` (they replace all labels, past `add_labels`'s
/// bounds), `assignees` and `milestone`, which nothing here bounds.
pub const UPDATE_FIELDS: &[(&str, &[&str])] = &[
    ("update_issue", &["title", "body", "status"]),
    (
        "update_pull_request",
        &["title", "body", "draft", "update_branch"],
    ),
];

/// The fields an update type may list, if `output` is one.
pub fn update_fields(output: &str) -> Option<&'static [&'static str]> {
    UPDATE_FIELDS
        .iter()
        .find(|(name, _)| *name == output)
        .map(|(_, fields)| *fields)
}

/// The types apply can publish on GitHub with agentic-job's own handlers
/// (`agentic-job publish`) in place of gh-aw's, where the bounds'
/// `native_handlers` name them; every other type stays gh-aw's.
pub const NATIVE_OUTPUTS: &[&str] = &[
    "add_comment",
    CREATE_PULL_REQUEST,
    "add_labels",
    "remove_labels",
    "close_issue",
    "close_pull_request",
    PUSH_TO_PULL_REQUEST_BRANCH,
    "create_issue",
    CREATE_REVIEW_COMMENT,
];

/// Admission of a bounds file's outputs against the forge profile.
pub(crate) trait ForgeAdmission {
    fn check_outputs<'a>(self, outputs: impl IntoIterator<Item = &'a str>) -> Result<()>;
}

impl ForgeAdmission for Forge {
    /// The first of OUTPUTS the profile does not hold, as a refusal.
    fn check_outputs<'a>(self, outputs: impl IntoIterator<Item = &'a str>) -> Result<()> {
        for output in outputs {
            ensure!(
                self.holds(output),
                "the output type {output:?} is GitHub-only, not for forge {:?}",
                self.name()
            );
        }
        Ok(())
    }
}

/// A run hands back one patch, so at most one pull request, or one push.
pub(crate) const MAX_PULL_REQUESTS: u32 = 1;
const MAX_REPLACEMENT_COMMITS: u32 = 50;
/// The most `replacement_max_files` may be; the patch byte limit still
/// bounds the series.
const MAX_REPLACEMENT_FILES: u32 = 500;

/// How many globs the bounds' `protected` may list, and how long each
/// may be: room for a repository's own source trees, none for a list
/// that makes check compile a pattern per path for long.
pub(crate) const MAX_PROTECTED_GLOBS: usize = 64;
const MAX_PROTECTED_GLOB_CHARS: usize = 256;

/// A clone URL over plain HTTP, admitted only for a host the bounds'
/// `allow_http` names.
pub const PLAIN_HTTP_PREFIX: &str = "http://";

/// The longest check run name bounds may pin: room for a readable name,
/// none for a page of text in the forge's checks list.
const MAX_CHECK_RUN_NAME: usize = 64;

/// The longest discussion category bounds may pin, as for a check run's
/// name: room for a readable name, slug or node ID.
const MAX_DISCUSSION_CATEGORY: usize = 64;

/// gh-aw states a patch's size cap in units of this many bytes.
pub const KB: u64 = 1024;

/// The ceilings of `[github.memory]`: gh-aw's repo-memory defaults, 100 files of
/// 100 KB each (docs/src/content/docs/reference/repo-memory.md in
/// github/gh-aw), and a total that keeps the hand-back small.
pub const MAX_MEMORY_FILES: u32 = 100;
pub const MAX_MEMORY_FILE_BYTES: u64 = 100 * KB;
pub const MAX_MEMORY_BYTES: u64 = 1024 * KB;
/// What a memory file may be named with: text an agent writes notes in,
/// and nothing a later reader would execute (`.sh`) or render as markup
/// that runs (`.html`, `.svg`).
pub const MEMORY_EXTENSIONS: &[&str] = &["md", "txt", "json", "jsonl", "csv"];

/// The ceilings of `[github.test_evidence]`: twice the 5 attempts the
/// external runner contract plans (docs/dispatch.md), and a log no bigger
/// than the largest file a hand-back already holds (its requests).
pub const MAX_TEST_ATTEMPTS: u32 = 10;
pub const MAX_TEST_LOG_BYTES: u64 = 1024 * KB;

/// The one top-level dot-folder bounds may exempt from protection, for
/// repositories they name exactly.
pub const EXEMPTABLE_DOT_FOLDER: &str = ".github";

/// The files a patch may not touch, at any depth: the defaults gh-aw's
/// compiler writes for `create-pull-request` (v0.90.1), less `README.md`.
/// A README steers no build, dependency, owner or agent, and protecting it
/// lost real runs their whole change (a README refresh; a new
/// `tests/coccinelle/README.md`). This list, not gh-aw's, is what both
/// check and apply's handler are given. A bounds file can take names off
/// this list for the repositories it names, and cannot add to it.
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
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "CLAUDE.md",
    "AGENTS.md",
];

/// The output types that name people: `allowed` lists the logins they may
/// name, exactly as written, since the handlers compare them so.
pub const PERSON_OUTPUTS: &[&str] = &["add_reviewer", "assign_to_user"];

/// A GitHub login, at most 39 characters with no leading, trailing or
/// doubled hyphen: what gh-aw's collector and handlers leave unchanged.
static LOGIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9](?:-?[A-Za-z0-9])*$").expect("a valid pattern"));

/// Whether LOGIN is a GitHub login ([`LOGIN_RE`]).
pub fn is_login(login: &str) -> bool {
    login.len() <= 39 && LOGIN_RE.is_match(login)
}

pub static REPO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").expect("a valid pattern"));

pub static BASE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}$").expect("a valid pattern"));

/// A pull request's branch that a push may go to: one that gh-aw's
/// handler pushes by the same name (`normalize_branch_name.cjs` leaves it
/// as it is) and whose patch has a name `check` takes.
pub static PUSH_BRANCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9]([A-Za-z0-9_./-]{0,98}[A-Za-z0-9_])?$").expect("a valid pattern")
});

pub static PULL_NUMBER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[1-9][0-9]{0,8}$").expect("a valid pattern"));

pub static COMMIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{40}$").expect("a valid pattern"));

/// A pinned commit author: ASCII that git keeps as it is (no character
/// its `ident.c` trims from either end of a name) and that `format-patch`
/// writes at most quoted, never encoded, so that `check` knows the one
/// `From:` line to expect. `github-actions[bot]`'s noreply address fits.
/// The name is at most 60 characters, past which `git am` records the
/// address in its place (`mailinfo`'s `get_sane_name`), and does not
/// start with `(`, which it strips with the closing one.
static COMMIT_AUTHOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^[A-Za-z0-9_+\[\]-](?:[A-Za-z0-9 _.+()\[\]-]{0,58}[A-Za-z0-9_+()\[\]-])?",
        r" <[A-Za-z0-9_.+\[\]-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+>$",
    ))
    .expect("a valid pattern")
});

/// Whether `author` may be a bounds file's `commit_author`.
pub fn check_commit_author(author: &str) -> Result<()> {
    ensure!(
        COMMIT_AUTHOR_RE.is_match(author) && !author.contains("  ") && author.len() <= 200,
        "commit_author {author:?} is not `Name <address>` of plain ASCII (letters, digits, spaces and _ . + - ( ) [ ])"
    );
    Ok(())
}

/// The transports a clone may use. `https` is what a caller's bounds
/// admit; `file` reads only what the sandbox user can, and is for tests
/// and a mirror on the machine. Anything else git knows (`ext::`, which
/// runs a command, among them) is refused by git itself with these.
pub const CLONE_TRANSPORTS: &[&str] = &["https", "file"];

/// Whether URL is one a clone may use.
pub fn check_clone_url(url: &str) -> Result<()> {
    check_clone_url_in(url, CLONE_TRANSPORTS)
}

/// Whether URL is one a clone over TRANSPORTS may use.
pub fn check_clone_url_in(url: &str, transports: &[&str]) -> Result<()> {
    let transport = url.split_once("://").map(|(scheme, _)| scheme);
    ensure!(
        transport.is_some_and(|scheme| transports.contains(&scheme))
            && !url.contains(|c: char| c.is_whitespace() || c.is_control()),
        "{url:?} is not an {} URL",
        transports.join(" or ")
    );
    Ok(())
}

/// What the run may hand back: a branch, or an analysis only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Branch,
    Analysis,
}

/// What a bounds file and a policy both hold `native_handlers` to: each
/// one of [`NATIVE_OUTPUTS`] that ALLOWS admits, named once, on GitHub.
pub(crate) fn check_native_handlers(
    types: &[String],
    forge: Forge,
    allows: impl Fn(&str) -> bool,
) -> Result<()> {
    for (at, output) in types.iter().enumerate() {
        ensure!(
            NATIVE_OUTPUTS.contains(&output.as_str()),
            "native_handlers: {output:?} is not one of {}",
            NATIVE_OUTPUTS.join(", ")
        );
        ensure!(
            allows(output),
            "native_handlers names {output:?}, which the outputs do not allow"
        );
        ensure!(
            !types[..at].contains(output),
            "native_handlers names {output:?} twice"
        );
    }
    ensure!(
        types.is_empty() || forge == Forge::Github,
        "native_handlers is only for GitHub"
    );
    Ok(())
}

/// Refuses a `create_issue` LIMIT with `comment_on_duplicate` that NATIVE,
/// the types `native_handlers` routes, leaves to gh-aw's handler: it
/// searches for nothing, and would open every duplicate the setting is
/// there to stop.
pub(crate) fn check_comment_on_duplicate(
    limit: Option<&OutputLimit>,
    native: &[String],
) -> Result<()> {
    ensure!(
        limit.is_none_or(|limit| !limit.comment_on_duplicate)
            || native.iter().any(|output| output == "create_issue"),
        "outputs.create_issue: comment_on_duplicate needs create_issue in native_handlers, as \
         only agentic-job's own handler searches for a duplicate"
    );
    Ok(())
}

/// The smallest `secondary_pull_request` patch budget, as for the primary.
const MIN_SECONDARY_PATCH_BYTES: u64 = KB;
const MIN_SECONDARY_PATCH_FILES: u32 = 1;

/// The longest branch a run's pull request has: `agent-run-` and the
/// largest run ID, which a forge counts in 64 bits.
const LONGEST_RUN_BRANCH: &str = "agent-run-18446744073709551615";

/// What the bounds and a policy both hold the secondary pull request to:
/// one exact repository and base, a prefix that keeps every run's branch
/// one gh-aw pushes by that name, a patch `check` can name, and patch
/// budgets of its own.
pub(crate) fn check_secondary(
    repo: &str,
    base: &str,
    branch_prefix: &str,
    max: u32,
    max_patch_bytes: u64,
    max_patch_files: u32,
) -> Result<()> {
    ensure!(
        REPO_RE.is_match(repo) && repo.split('/').all(|part| !part.starts_with(['.', '-'])),
        "secondary_pull_request.repo requires one exact repository name: {repo:?}"
    );
    // A name gh-aw's handler keeps as it is, of plain components.
    let exact_branch = |branch: &str| {
        PUSH_BRANCH_RE.is_match(branch)
            && !push_branch_ambiguous(branch)
            && branch
                .split('/')
                .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
    };
    ensure!(
        exact_branch(base),
        "secondary_pull_request.base requires one exact branch name: {base:?}"
    );
    ensure!(
        branch_prefix.ends_with('/'),
        "secondary_pull_request.branch_prefix must be nonempty and end with /"
    );
    ensure!(
        exact_branch(&format!("{branch_prefix}{LONGEST_RUN_BRANCH}")),
        "secondary_pull_request.branch_prefix must form an unambiguous branch name: \
         {branch_prefix:?}"
    );
    ensure!(
        is_patch_file_name(&patch_file_name_in(
            repo,
            &format!("{branch_prefix}{LONGEST_RUN_BRANCH}")
        )),
        "secondary_pull_request.repo and branch_prefix are too long to name its patch"
    );
    ensure!(
        max == MAX_PULL_REQUESTS,
        "secondary_pull_request.max must be {MAX_PULL_REQUESTS}"
    );
    ensure!(
        max_patch_bytes >= MIN_SECONDARY_PATCH_BYTES,
        "secondary_pull_request.max_patch_bytes must be at least {MIN_SECONDARY_PATCH_BYTES}"
    );
    ensure!(
        max_patch_files >= MIN_SECONDARY_PATCH_FILES,
        "secondary_pull_request.max_patch_files must be at least {MIN_SECONDARY_PATCH_FILES}"
    );
    Ok(())
}

/// The secondary pull request a run may open, as `policy` compiled it
/// from [`crate::bounds::SecondaryPullRequest`]: in the repository it
/// names and nowhere else, from a clone of its base, with a patch of its
/// own that is held to its own budgets and protected files. Always a draft.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secondary {
    pub repo: String,
    /// What `run` clones for the agent to change: the repository on the
    /// host of the run's own clone URL.
    pub clone_url: String,
    pub base: String,
    pub branch_prefix: String,
    pub max: u32,
    pub max_patch_bytes: u64,
    pub max_patch_files: u32,
    pub protected_files: Vec<String>,
    pub protect_top_level_dot_folders: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unprotected_dot_folders: Vec<String>,
    /// As [`PullRequest::protected_paths`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_paths: Vec<String>,
}

impl Secondary {
    pub fn rules(&self) -> PatchRules<'_> {
        PatchRules {
            protected_files: &self.protected_files,
            protect_top_level_dot_folders: self.protect_top_level_dot_folders,
            unprotected_dot_folders: &self.unprotected_dot_folders,
            protected_paths: &self.protected_paths,
            max_patch_files: self.max_patch_files,
            commit_author: None,
        }
    }

    /// Whether a request's `repo` names this repository. gh-aw's handler
    /// compares it as written, so `run` writes it as the policy does.
    pub fn names(&self, repo: &str) -> bool {
        repo.eq_ignore_ascii_case(&self.repo)
    }

    /// The branch of a run whose own pull request is on BRANCH: under the
    /// prefix, which gh-aw's handler then leaves as it is. So its patch
    /// is never one gh-aw's handler would take for the run's own: neither
    /// by the plain name it falls back to, nor, as `policy` refuses the
    /// prefix that would, by the name it looks for first in the run's or
    /// the output repository.
    pub fn branch(&self, branch: &str) -> String {
        format!("{}{branch}", self.branch_prefix)
    }

    fn validate(&self) -> Result<()> {
        check_secondary(
            &self.repo,
            &self.base,
            &self.branch_prefix,
            self.max,
            self.max_patch_bytes,
            self.max_patch_files,
        )?;
        check_clone_url(&self.clone_url)?;
        ensure!(
            self.protect_top_level_dot_folders,
            "top-level dot-folders are not protected"
        );
        validate_dot_folders(
            &self.unprotected_dot_folders,
            "secondary_pull_request.unprotected_dot_folders",
        )?;
        validate_protected(
            &self.protected_paths,
            "secondary_pull_request.protected_paths",
        )
    }
}

/// `[github.memory]`: how much of the agent's memory directory is handed back,
/// and what its files may be. Each bound has a default and a ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    #[serde(default = "Memory::default_max_files")]
    pub max_files: u32,
    #[serde(default = "Memory::default_max_file_bytes")]
    pub max_file_bytes: u64,
    /// Of all files' contents together.
    #[serde(default = "Memory::default_max_bytes")]
    pub max_bytes: u64,
    /// File name extensions, without the dot, from [`MEMORY_EXTENSIONS`].
    #[serde(default = "Memory::default_extensions")]
    pub extensions: Vec<String>,
}

impl Memory {
    fn default_max_files() -> u32 {
        20
    }

    fn default_max_file_bytes() -> u64 {
        16 * KB
    }

    fn default_max_bytes() -> u64 {
        64 * KB
    }

    fn default_extensions() -> Vec<String> {
        ["md", "txt", "json"].map(str::to_owned).to_vec()
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_MEMORY_FILES).contains(&self.max_files),
            "memory.max_files must be from 1 to {MAX_MEMORY_FILES}"
        );
        ensure!(
            (1..=MAX_MEMORY_FILE_BYTES).contains(&self.max_file_bytes),
            "memory.max_file_bytes must be from 1 to {MAX_MEMORY_FILE_BYTES}"
        );
        ensure!(
            (self.max_file_bytes..=MAX_MEMORY_BYTES).contains(&self.max_bytes),
            "memory.max_bytes must be from max_file_bytes to {MAX_MEMORY_BYTES}"
        );
        ensure!(
            !self.extensions.is_empty(),
            "memory.extensions lists no extension"
        );
        for (i, extension) in self.extensions.iter().enumerate() {
            ensure!(
                MEMORY_EXTENSIONS.contains(&extension.as_str()),
                "memory.extensions may only name {}, not {extension:?}",
                MEMORY_EXTENSIONS.join(", ")
            );
            ensure!(
                !self.extensions[..i].contains(extension),
                "memory.extensions names {extension:?} twice"
            );
        }
        Ok(())
    }
}

/// How many outputs of one type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputLimit {
    pub max: u32,
    /// Labels an issue may name. Absent preserves the existing unrestricted
    /// behavior; an empty list permits no labels. Enforced by `check`, not
    /// by the handler's silent filtering. For [`PERSON_OUTPUTS`], the
    /// logins a request may name instead, required and nonempty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<String>>,
    /// Labels an issue may never name, even if also allowed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked: Vec<String>,
    /// Exact GitHub Projects v2 URLs and field names admitted for updates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<String>,
    /// For `update_issue` and `update_pull_request`, which of
    /// [`UPDATE_FIELDS`] a request may change.
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
    /// The most files a replacement series may touch in all, in place of
    /// `max_patch_files`, which still bounds each of its commits. Zero
    /// (the default) keeps `max_patch_files`. A pull request that grew
    /// over several pushes, each within that limit, can outgrow it, and
    /// a rebase must carry all of it at once (#3017).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub replacement_max_files: u32,
    /// For a GitHub push: the login apply pushes as. A push to a pull request
    /// this account opened is admitted in any repository, not only in
    /// `repos`, as the operator lets the bot always work on its own pull
    /// requests (#3162). Policy and apply each read the author from the
    /// forge, and apply refuses unless it is still this login and the
    /// identity apply holds; `branches` and the replacement limits hold
    /// as for any push. Absent (the default), only `repos` admits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_author: Option<String>,
    /// The one name a check run gets, from the bounds and never the agent:
    /// gh-aw's handler takes it from its configuration. Required for
    /// `create_check_run`, and only for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The one category a discussion is posted in, by name, slug or node
    /// ID. Required for `create_discussion`, and only for it: gh-aw's
    /// handler takes a request's own category over this one, and an
    /// unknown one for Announcements or the first category, so check
    /// refuses another and apply refuses what the pin does not name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// The reasons a comment may be hidden for, from [`HIDE_REASONS`].
    /// Required and nonempty for `hide_comment`, and only for it: gh-aw's
    /// handler takes an empty list for any reason, so the bounds always
    /// pin one, and check refuses a request outside it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_reasons: Vec<String>,
    /// For the two outputs that carry a patch: open complete work ready
    /// for review, and only a checkpoint (`check::checkpoint`) or a run
    /// stopped at a limit as a draft. Off, every pull request is a draft.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ready_when_complete: bool,
    /// For `create_issue`, published by agentic-job's own handler: an
    /// open issue with exactly the title asked for gets the body as a
    /// comment, and no new issue is opened. Without it a run proposing
    /// the follow-up an earlier run filed opens it again; with it a run
    /// refines an existing issue by naming its title. Off by default.
    #[serde(default, skip_serializing_if = "is_false")]
    pub comment_on_duplicate: bool,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl OutputLimit {
    pub fn validate(&self, output: &str) -> Result<()> {
        ensure!(
            self.replacement_max_commits <= MAX_REPLACEMENT_COMMITS
                && (output == PUSH_TO_PULL_REQUEST_BRANCH || self.replacement_max_commits == 0),
            "outputs.{output}: replacement_max_commits is supported only for a push, at most 50"
        );
        ensure!(
            self.replacement_max_files <= MAX_REPLACEMENT_FILES
                && (self.replacement_max_files == 0
                    || (output == PUSH_TO_PULL_REQUEST_BRANCH && self.replacement_max_commits > 0)),
            "outputs.{output}: replacement_max_files is supported only for a push that allows replacement_max_commits, at most {MAX_REPLACEMENT_FILES}"
        );
        ensure!(
            !self.ready_when_complete
                || matches!(output, CREATE_PULL_REQUEST | PUSH_TO_PULL_REQUEST_BRANCH),
            "outputs.{output}: ready_when_complete is supported only for {CREATE_PULL_REQUEST} and {PUSH_TO_PULL_REQUEST_BRANCH}"
        );
        ensure!(
            !self.comment_on_duplicate || output == "create_issue",
            "outputs.{output}: comment_on_duplicate is supported only for create_issue"
        );
        ensure!(
            output == "update_project" || self.projects.is_empty(),
            "outputs.{output}: projects are supported only for update_project"
        );
        ensure!(
            output == "update_project" || update_fields(output).is_some() || self.fields.is_empty(),
            "outputs.{output}: fields are supported only for update_project, update_issue and update_pull_request"
        );
        if let Some(known) = update_fields(output) {
            ensure!(
                !self.fields.is_empty(),
                "outputs.{output} requires an explicit nonempty fields list"
            );
            for field in &self.fields {
                ensure!(
                    known.contains(&field.as_str()),
                    "outputs.{output}: unsupported field {field:?}, not one of {}",
                    known.join(", ")
                );
            }
        }
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
        if let Some(login) = &self.own_author {
            ensure!(
                output == PUSH_TO_PULL_REQUEST_BRANCH && is_login(login),
                "outputs.{output}: own_author is supported only for {PUSH_TO_PULL_REQUEST_BRANCH}, \
                 as one login, not {login:?}"
            );
        }
        // `allowed` and `blocked` are logins for a person output and labels
        // for the rest; the pins below are for one output each, whatever
        // the type, so neither branch returns before them.
        if PERSON_OUTPUTS.contains(&output) {
            // Each named login is notified, and the handlers take an empty
            // or absent list for "anyone": so a nonempty list is required.
            ensure!(
                self.allowed
                    .as_ref()
                    .is_some_and(|logins| !logins.is_empty())
                    && self.blocked.is_empty(),
                "outputs.{output} requires a nonempty allowed list of logins, and no blocked list"
            );
            for login in self.allowed.iter().flatten() {
                ensure!(is_login(login), "outputs.{output}: invalid login {login:?}");
            }
        } else {
            ensure!(
                matches!(output, "create_issue" | "add_labels" | "remove_labels")
                    || (self.allowed.is_none() && self.blocked.is_empty()),
                "outputs.{output}: label limits are supported only for create_issue, add_labels and remove_labels"
            );
            ensure!(
                !matches!(output, "add_labels" | "remove_labels") || self.allowed.is_some(),
                "outputs.{output} requires an explicit allowed label list"
            );
            for label in self.allowed.iter().flatten().chain(&self.blocked) {
                ensure!(
                    !label.is_empty()
                        && label == label.trim()
                        && !label.chars().any(char::is_control),
                    "outputs.{output}: invalid label {label:?}"
                );
            }
        }
        ensure!(
            (output == "create_check_run") == self.name.is_some(),
            "outputs.{output}: `name` is required for create_check_run, and only for it"
        );
        if let Some(name) = &self.name {
            ensure!(
                !name.is_empty()
                    && name.len() <= MAX_CHECK_RUN_NAME
                    && name == name.trim()
                    && !name.chars().any(char::is_control),
                "outputs.{output}: invalid check run name {name:?}"
            );
        }
        ensure!(
            (output == "create_discussion") == self.category.is_some(),
            "outputs.{output}: `category` is required for create_discussion, and only for it"
        );
        if let Some(category) = &self.category {
            ensure!(
                !category.is_empty()
                    && category.len() <= MAX_DISCUSSION_CATEGORY
                    && category == category.trim()
                    && !category.chars().any(char::is_control),
                "outputs.{output}: invalid discussion category {category:?}"
            );
        }
        ensure!(
            (output == HIDE_COMMENT) != self.allowed_reasons.is_empty(),
            "outputs.{output}: `allowed_reasons` is required for {HIDE_COMMENT}, and only for it"
        );
        for reason in &self.allowed_reasons {
            ensure!(
                HIDE_REASONS.contains(&reason.as_str()),
                "outputs.{output}: unsupported reason {reason:?}, not one of {}",
                HIDE_REASONS.join(", ")
            );
        }
        Ok(())
    }
}

/// `[github.test_evidence]`: the repeated-test evidence a run may hand
/// back beside its patch (`test-evidence.json`, docs/dispatch.md), and
/// how much. Absent, `check` refuses any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestEvidence {
    /// The most attempts one manifest may plan, and so hold.
    #[serde(default = "TestEvidence::default_max_attempts")]
    pub max_attempts: u32,
    /// The most each attempt's log may hold.
    #[serde(default = "TestEvidence::default_max_log_bytes")]
    pub max_log_bytes: u64,
}

impl TestEvidence {
    fn default_max_attempts() -> u32 {
        5
    }

    fn default_max_log_bytes() -> u64 {
        256 * KB
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_TEST_ATTEMPTS).contains(&self.max_attempts),
            "test_evidence.max_attempts must be from 1 to {MAX_TEST_ATTEMPTS}"
        );
        ensure!(
            (1..=MAX_TEST_LOG_BYTES).contains(&self.max_log_bytes),
            "test_evidence.max_log_bytes must be from 1 to {MAX_TEST_LOG_BYTES}"
        );
        Ok(())
    }
}

/// What `policy.json` holds: the request, once it is within the bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Trusted, head-bound prose publication; absent for ordinary reviews.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<Advisory>,
    /// Bounds-approved HTTP authorities; empty keeps publishing on HTTPS.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_http: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<ContextRepo>,
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
    /// The bounds' `commit_author`: who `run` commits as, and the only
    /// author `check` lets a patch name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_author: Option<String>,
    /// The bounds' `[forgejo]` `push_repo`, where a pull request or a push is asked
    /// for: the only repository Forgejo's `apply` pushes a branch to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_repo: Option<String>,
    /// A repository that is not public: `run` holds the machine to the
    /// conditions of docs/private-repositories.md before it clones.
    #[serde(default, skip_serializing_if = "is_false")]
    pub private: bool,
    /// What check and apply give gh-aw as `GH_AW_ALLOWED_DOMAINS`:
    /// [`link_domains`], or empty, leaving gh-aw its own
    /// [`crate::GH_AW_LINK_DOMAINS`], in a policy written by hand.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_domains: Vec<String>,
    /// The bounds' `[github.memory]`, where every bounds file has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<Memory>,
    /// The bounds' `[github.test_evidence]`, where every bounds file has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_evidence: Option<TestEvidence>,
    /// The bounds' [`Forge`].
    #[serde(default)]
    pub forge: Forge,
    /// The [`CONTRACT`] `policy` wrote this for. Absent, the policy was
    /// written before there was one, or by hand: the first.
    #[serde(default = "first_contract")]
    pub contract: u32,
    /// The one pull request a run that opens one may also open in another
    /// repository. Not in `safe_outputs`: gh-aw's collector reads that,
    /// and counts a `create_pull_request` of either repository alike.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_pull_request: Option<Secondary>,
    /// The bounds' `native_handlers`, of the types this policy allows:
    /// what apply publishes with `agentic-job publish`, not gh-aw.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_handlers: Vec<String>,
}

/// Match HTTP authorities exactly, including ports, without DNS resolution.
pub fn allows_http(allowed: &[String], authority: &str) -> bool {
    allowed
        .iter()
        .any(|host| host.eq_ignore_ascii_case(authority))
}

/// Not [`CONTRACT`]: once that is raised, a policy without the key is
/// still one of the first contract's, and check refuses it.
fn first_contract() -> u32 {
    1
}

/// The directory under the agent's `work` that the secondary pull
/// request's repository is cloned into, as `OWNER/NAME`.
pub const SECONDARY_DIR: &str = "secondary";

/// Reference context admitted before the agent starts. The workflow resolves
/// refs and confirms visibility; the policy checks names, pins and caller bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRepo {
    pub repo: String,
    pub clone_url: String,
    pub commit: String,
    /// Verified by the read-only policy workflow, never a dispatch input.
    pub public: bool,
}

pub const MAX_CONTEXT_REPOS: usize = 8;

pub fn check_context(context: &[ContextRepo]) -> Result<()> {
    ensure!(
        context.len() <= MAX_CONTEXT_REPOS,
        "at most {MAX_CONTEXT_REPOS} context repositories"
    );
    let mut seen = std::collections::BTreeSet::new();
    for item in context {
        ensure!(
            REPO_RE.is_match(&item.repo)
                && item
                    .repo
                    .split('/')
                    .all(|part| !part.starts_with(['.', '-'])),
            "invalid context repository {:?}",
            item.repo
        );
        ensure!(
            COMMIT_RE.is_match(&item.commit),
            "context commit must be a full lowercase SHA"
        );
        ensure!(
            seen.insert(item.repo.to_ascii_lowercase()),
            "duplicate context repository {:?}",
            item.repo
        );
        check_clone_url(&item.clone_url)?;
    }
    Ok(())
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
    /// The bounds' `protected` globs. Check and apply's own reading of
    /// the patch refuse a path they match; apply takes them out of gh-aw's
    /// handler configuration, which has no such setting.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_paths: Vec<String>,
    pub protected_files_policy: ProtectedFilesPolicy,
    /// What gh-aw's handler is given; apply sets it false only for
    /// complete work under [`OutputLimit::ready_when_complete`].
    pub draft: bool,
    /// The bounds' [`OutputLimit::ready_when_complete`]; apply reads it,
    /// and takes it out of the handler's configuration.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ready_when_complete: bool,
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
    /// [`OutputLimit::replacement_max_files`]; see [`Self::replacement_files`].
    #[serde(default, skip_serializing_if = "is_zero")]
    pub replacement_max_files: u32,
    /// The target base head resolved by the read-only policy job, not the producer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_base: Option<String>,
    /// The bounds' [`OutputLimit::own_author`], where only that admitted
    /// the repository: apply's `push target` refuses the push unless the
    /// pull request is by this login and it is the identity apply holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// As [`PullRequest::ready_when_complete`]: apply marks the pull
    /// request ready after a complete push, a draft after a checkpoint.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ready_when_complete: bool,
    pub protected_files: Vec<String>,
    pub protect_top_level_dot_folders: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unprotected_dot_folders: Vec<String>,
    /// As [`PullRequest::protected_paths`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_paths: Vec<String>,
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
    /// Globs of paths a patch may not touch, from the bounds.
    pub protected_paths: &'a [String],
    pub max_patch_files: u32,
    /// [`Policy::commit_author`], which `check` sets: the outputs' own
    /// configuration does not carry it.
    pub commit_author: Option<&'a str>,
}

impl PullRequest {
    pub fn rules(&self) -> PatchRules<'_> {
        PatchRules {
            protected_files: &self.protected_files,
            protect_top_level_dot_folders: self.protect_top_level_dot_folders,
            unprotected_dot_folders: &self.unprotected_dot_folders,
            protected_paths: &self.protected_paths,
            max_patch_files: self.max_patch_files,
            commit_author: None,
        }
    }
}

impl Push {
    pub fn rules(&self) -> PatchRules<'_> {
        PatchRules {
            protected_files: &self.protected_files,
            protect_top_level_dot_folders: self.protect_top_level_dot_folders,
            unprotected_dot_folders: &self.unprotected_dot_folders,
            protected_paths: &self.protected_paths,
            max_patch_files: self.max_patch_files,
            commit_author: None,
        }
    }

    /// The most files a replacement series may touch in all.
    pub fn replacement_files(&self) -> u32 {
        match self.replacement_max_files {
            0 => self.max_patch_files,
            max => max,
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

    /// Whether the patch's carrier has complete work opened or marked
    /// ready, so that a checkpoint is what keeps it a draft.
    pub fn ready_when_complete(&self) -> bool {
        self.create_pull_request
            .as_ref()
            .is_some_and(|pr| pr.ready_when_complete)
            || self
                .push_to_pull_request_branch
                .as_ref()
                .is_some_and(|push| push.ready_when_complete)
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
    /// Whether gh-aw's sanitizer keeps a link to HOST, as its
    /// `sanitizeUrlDomains` decides: the domain itself or a subdomain.
    pub fn keeps_link_to(&self, host: &str) -> bool {
        crate::keeps_link(&self.allowed_domains, host)
    }

    /// What the types cannot say: `policy` writes only the output types
    /// that have a configuration here, and only draft pull requests with
    /// the dot-folders protected.
    pub fn validate(&self) -> Result<()> {
        check_context(&self.context)?;
        if let Some(advisory) = &self.advisory {
            advisory.validate(self)?;
        }
        check_native_handlers(&self.native_handlers, self.forge, |output| {
            self.safe_outputs.max_of(output).is_some()
        })?;
        check_comment_on_duplicate(
            self.safe_outputs.others.get("create_issue"),
            &self.native_handlers,
        )?;
        if let Some(author) = &self.commit_author {
            check_commit_author(author)?;
        }
        if let Some(push_repo) = &self.push_repo {
            ensure!(
                REPO_RE.is_match(push_repo)
                    && !dotted(push_repo)
                    && !push_repo.ends_with(".git")
                    && !same_owner(push_repo, &self.repo),
                "push_repo {push_repo:?} is not another owner's repository than {:?}",
                self.repo
            );
        }
        ensure!(
            self.allowed_domains.is_empty() || self.allowed_domains == link_domains(),
            "allowed_domains is not the list of top-level domains"
        );
        ensure!(
            self.context.is_empty() || self.repo.rsplit('/').next() != Some("context"),
            "target name conflicts with the context directory"
        );
        if let Some(memory) = &self.memory {
            memory.validate()?;
        }
        ensure!(
            self.contract == CONTRACT,
            "written for safe-output contract {}, not {CONTRACT}",
            self.contract
        );
        self.forge.check_outputs(self.safe_outputs.types())?;
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
            validate_protected(&pr.protected_paths, "create_pull_request.protected_paths")?;
        }
        if let Some(push) = &self.safe_outputs.push_to_pull_request_branch {
            validate_protected(
                &push.protected_paths,
                "push_to_pull_request_branch.protected_paths",
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
            validate_dot_folders(
                &push.unprotected_dot_folders,
                "push_to_pull_request_branch.unprotected_dot_folders",
            )?;
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
                push.replacement_max_files <= MAX_REPLACEMENT_FILES,
                "over {MAX_REPLACEMENT_FILES} replacement files"
            );
            ensure!(
                push.replacement_base
                    .as_ref()
                    .is_none_or(|base| COMMIT_RE.is_match(base)),
                "invalid replacement base commit"
            );
            ensure!(
                push.author.as_deref().is_none_or(is_login),
                "a push's author is not a login"
            );
            // Native publishers do not bind the live PR/MR author to the
            // applying identity. Never let planning drop this constraint.
            ensure!(
                push.author.is_none() || self.forge == Forge::Github,
                "a push's author is supported only on GitHub"
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
        if let Some(secondary) = &self.secondary_pull_request {
            secondary.validate()?;
            // As `policy` compiles it: beside the run's own pull request,
            // from a public repository, and never in the run's own one,
            // whose patch would then be the secondary's to gh-aw.
            ensure!(
                self.kind == Kind::Branch
                    && self.safe_outputs.create_pull_request.is_some()
                    && !self.private
                    && self.forge == Forge::Github,
                "a secondary pull request without the run's own, in a private run, or off GitHub"
            );
            for repo in std::iter::once(&self.repo).chain(&self.push_repo) {
                ensure!(
                    !secondary.names(repo)
                        && !patch_named_as_in(&secondary.repo, &secondary.branch_prefix, repo),
                    "a secondary pull request in, or with a patch named as one of, the run's own \
                     or output repository"
                );
            }
            ensure!(
                self.repo.rsplit('/').next() != Some(SECONDARY_DIR),
                "target name conflicts with the secondary directory"
            );
        }
        Ok(())
    }
}

/// A glob as a pattern: `*` is anything within one path segment, `**`
/// anything at all, and every other character itself. Case is ignored, as
/// forges ignore it in names. This is gh-aw's glob syntax
/// (`glob_pattern_helpers.cjs`).
pub fn glob(pattern: &str) -> Result<Regex, regex::Error> {
    glob_cased(pattern, false)
}

/// [`glob`], or with case counting: a forge keeps it in a branch name, so
/// `dispatch/**` is not to admit `DISPATCH/x` as a branch to push to.
pub fn glob_cased(pattern: &str, cased: bool) -> Result<Regex, regex::Error> {
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
pub fn push_branch_ambiguous(branch: &str) -> bool {
    branch.contains("--") || branch.contains("..")
}

/// The first of the bounds' `protected` globs that `path` matches, as a
/// push's `branches` match a branch: case counts, since git keeps it in a
/// path, and `Raw/x` is a new file beside `raw/`, not a change to it. A
/// glob that does not compile was refused in validation; here it protects
/// everything rather than nothing.
pub fn protecting_glob<'g>(globs: &'g [String], path: &str) -> Option<&'g str> {
    globs
        .iter()
        .find(|pattern| glob_cased(pattern, true).map_or(true, |re| re.is_match(path)))
        .map(String::as_str)
}

/// The bounds' `protected` globs, wherever they are read. A glob that can
/// match no path a patch names is the caller's mistake, and would protect
/// nothing while seeming to: check admits only plain relative paths, so
/// one with an empty, `.` or `..` component (absolute, `./raw/**`, `raw/`)
/// never matches. Nor would `?`, `[...]` or `{a,b}`, which other glob
/// syntaxes give a meaning and this one takes for themselves.
pub(crate) fn validate_protected(globs: &[String], field: &str) -> Result<()> {
    ensure!(
        globs.len() <= MAX_PROTECTED_GLOBS,
        "{field} lists {} globs, over {MAX_PROTECTED_GLOBS}",
        globs.len()
    );
    for pattern in globs {
        ensure!(
            pattern.len() <= MAX_PROTECTED_GLOB_CHARS,
            "{field}: {pattern:?} is over {MAX_PROTECTED_GLOB_CHARS} bytes"
        );
        ensure!(
            pattern
                .split('/')
                .all(|part| !matches!(part, "" | "." | ".."))
                && !pattern.contains(['?', '[', ']', '{', '}'])
                && !pattern.chars().any(char::is_control),
            "{field}: {pattern:?} is not a relative path glob of plain components, \
             with only `*` and `**` special"
        );
        glob_cased(pattern, true).with_context(|| format!("{field}: the glob {pattern:?}"))?;
    }
    Ok(())
}

/// Whether any of PATTERNS, as [`glob`]s, matches VALUE.
pub fn glob_matches(patterns: &[String], value: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| glob(pattern).is_ok_and(|re| re.is_match(value)))
}

/// Whether two OWNER/NAME names have the same owner.
pub fn same_owner(one: &str, other: &str) -> bool {
    let owner = |repo: &str| repo.split('/').next().unwrap_or_default().to_owned();
    owner(one).eq_ignore_ascii_case(&owner(other))
}

/// Whether the patch of a secondary pull request in SECONDARY, on a branch
/// under PREFIX, would have the name gh-aw's handler looks for first for
/// the run's own pull request in REPO (`aw-OWNER-NAME-BRANCH.patch`, of
/// its `target-repo`): `org/tool` under `docs/` is `org/tool-docs`'s.
pub fn patch_named_as_in(secondary: &str, prefix: &str, repo: &str) -> bool {
    patch_file_name_in(secondary, &format!("{prefix}{LONGEST_RUN_BRANCH}"))
        == patch_file_name_in(repo, LONGEST_RUN_BRANCH)
}

/// Whether a component of `name` is dots alone: no directory to clone
/// into, whatever their number, so `run` refuses one (`run::clone::check`).
pub fn dotted(name: &str) -> bool {
    name.split('/').any(|part| part.bytes().all(|b| b == b'.'))
}

/// Only `.github` may be exempted: check's fixed refusals take the other
/// dot-folders it names (`.husky/`, `.vscode/`, `.circleci/`, `.tekton/`)
/// whatever the policy says, so an exemption for them would grant nothing,
/// and no other folder has been needed.
pub(crate) fn validate_dot_folders(names: &[String], field: &str) -> Result<()> {
    for name in names {
        ensure!(
            name == EXEMPTABLE_DOT_FOLDER,
            "{field} may only name {EXEMPTABLE_DOT_FOLDER:?}, not {name:?}"
        );
    }
    Ok(())
}
