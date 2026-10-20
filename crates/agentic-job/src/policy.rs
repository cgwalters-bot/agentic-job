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

/// The output type that sets fields on a Projects v2 board: a destination
/// of its own, outside the output repository.
const UPDATE_PROJECT: &str = "update_project";

/// The output type that takes a pull request out of draft. Off unless a
/// bounds file lists it: apply opens a pull request as a draft unless its
/// work is complete under `ready_when_complete`, and this, like `draft:
/// false` in an update, would take one out of draft on the agent's word.
pub const MARK_READY: &str = "mark_pull_request_as_ready_for_review";

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

/// The output types a bounds file may list. Each is one that gh-aw's
/// collector validates with the configuration written here; another type
/// needs settings of its own, so it is added here with them and not by a
/// caller's file alone.
pub const OUTPUT_TYPES: &[&str] = &[
    CREATE_PULL_REQUEST,
    "add_comment",
    "create_issue",
    "create_discussion",
    HIDE_COMMENT,
    CREATE_REVIEW_COMMENT,
    REPLY_TO_REVIEW_COMMENT,
    RESOLVE_REVIEW_THREAD,
    "close_issue",
    "add_labels",
    "remove_labels",
    "update_issue",
    "update_pull_request",
    MARK_READY,
    "add_reviewer",
    "assign_to_user",
    "close_pull_request",
    "link_sub_issue",
    "create_check_run",
    "update_project",
    PUSH_TO_PULL_REQUEST_BRANCH,
    "noop",
    "missing_tool",
    "missing_data",
];

/// The forge a run's outputs are applied on, from the bounds file: what
/// the caller's repository says, never the request. The wire format is
/// gh-aw's on every forge; this decides which of its types and fields
/// mean the same there (docs/safe-outputs.md#neutral-profile).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Forge {
    #[default]
    Github,
    Forgejo,
    Gitlab,
}

/// The version of the neutral profile [`Forge`] and [`NEUTRAL_OUTPUTS`]
/// describe, written into `policy.json`. It follows the gh-aw commit the
/// type names and fields are read from,
/// 462ed682857c4ab64d40f2c85e3738fa27834839, and is raised when a type or
/// field changes meaning there, so that check refuses a policy written
/// for another profile rather than read its types the new way.
pub const CONTRACT: u32 = 1;

/// The types whose fields mean the same on GitHub, Forgejo and GitLab,
/// and the only ones a run off GitHub may be allowed. A list of what is
/// held, not of what is refused: a type nobody has mapped onto a forge
/// stays GitHub-only, so a publisher never meets a request it would have
/// to guess at.
pub const NEUTRAL_OUTPUTS: &[&str] = &[
    CREATE_PULL_REQUEST,
    PUSH_TO_PULL_REQUEST_BRANCH,
    "add_comment",
    "create_issue",
    "close_issue",
    "close_pull_request",
    "add_labels",
    "remove_labels",
    CREATE_REVIEW_COMMENT,
    "noop",
    "missing_tool",
    "missing_data",
];

/// gh-aw's target field for an issue or a pull request alike. GitLab
/// numbers the two apart (`#5` and `!5` are different items), so there a
/// request names `issue_number` or `pull_request_number`; one naming this
/// could act on the wrong item.
pub const ITEM_NUMBER: &str = "item_number";

impl Forge {
    /// The name a bounds file gives it.
    fn name(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Forgejo => "forgejo",
            Self::Gitlab => "gitlab",
        }
    }

    /// Whether the profile holds OUTPUT on this forge.
    pub fn holds(self, output: &str) -> bool {
        self == Self::Github || NEUTRAL_OUTPUTS.contains(&output)
    }

    /// Whether a request on this forge may not have the field KEY.
    pub fn refuses_field(self, key: &str) -> bool {
        self == Self::Gitlab && key == ITEM_NUMBER
    }

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

/// The output types the job token cannot apply, whatever the call grants
/// it, and the credential each needs instead. GitHub gives a workflow's
/// token no permission on Projects, and no account to fork into: apply
/// opens a pull request only from a fork of the identity it applies as,
/// so that the target's CI runs agent-written code as a fork's, with a
/// read-only token, and pushes to a pull request's branch only as a user
/// it can name and check may push there. Every other type writes to a
/// repository, which the token can when it is the calling one.
const NOT_FOR_THE_JOB_TOKEN: &[(&str, &str)] = &[
    (
        CREATE_PULL_REQUEST,
        "a user's token that can fork the output repository and push to its fork, as SAFE_OUTPUTS_PAT in an apply environment",
    ),
    (
        PUSH_TO_PULL_REQUEST_BRANCH,
        "a user's token that can push to the pull request's branch, as SAFE_OUTPUTS_PAT in an apply environment",
    ),
    (
        "update_project",
        "a token with project scope as SAFE_OUTPUTS_PAT, in an apply environment",
    ),
];

/// A run hands back one patch, so at most one pull request, or one push.
const MAX_PULL_REQUESTS: u32 = 1;
const MAX_REPLACEMENT_COMMITS: u32 = 50;

/// A clone URL over plain HTTP, admitted only for a host the bounds'
/// `allow_http` names.
pub const PLAIN_HTTP_PREFIX: &str = "http://";
/// The domain no bounds file may allow plain HTTP for, nor any host under
/// it: it serves https, so a plain-HTTP URL for it is a downgrade.
const NEVER_PLAIN_HTTP: &str = "github.com";
/// The forge whose private-repository rules a bounds file's `push_repo`
/// leaves as they are (docs/private-repositories.md).
const GITHUB_HOST: &str = "github.com";

/// The longest check run name bounds may pin: room for a readable name,
/// none for a page of text in the forge's checks list.
const MAX_CHECK_RUN_NAME: usize = 64;

/// The longest discussion category bounds may pin, as for a check run's
/// name: room for a readable name, slug or node ID.
const MAX_DISCUSSION_CATEGORY: usize = 64;

/// Hides (minimizes) a comment on the run's triggering item: moderation of
/// what other people wrote there, so it is listed in bounds only by callers
/// who want an agent to do that.
pub const HIDE_COMMENT: &str = "hide_comment";

/// Inline review comments on the run's triggering pull request, without a
/// verdict: a new comment on a line of its diff, a reply to one, and
/// resolving a thread. Check and apply hold each to that pull request, so
/// text an agent read cannot steer it to comment on, or resolve the
/// threads of, another one.
pub const CREATE_REVIEW_COMMENT: &str = "create_pull_request_review_comment";
pub const REPLY_TO_REVIEW_COMMENT: &str = "reply_to_pull_request_review_comment";
pub const RESOLVE_REVIEW_THREAD: &str = "resolve_pull_request_review_thread";
pub const REVIEW_THREAD_OUTPUTS: &[&str] = &[
    CREATE_REVIEW_COMMENT,
    REPLY_TO_REVIEW_COMMENT,
    RESOLVE_REVIEW_THREAD,
];

/// The reasons gh-aw's collector lets a `hide_comment` give (its enum,
/// which it normalizes requests to), and so all `allowed_reasons` may name.
pub const HIDE_REASONS: &[&str] = &[
    "SPAM",
    "ABUSE",
    "OFF_TOPIC",
    "OUTDATED",
    "RESOLVED",
    "LOW_QUALITY",
];

/// `--outputs all`: every type the bounds list.
const ALL_OUTPUTS: &str = "all";

/// `--max-outputs max`: as many as the bounds allow.
const MAX_OUTPUTS: &str = "max";

/// gh-aw states a patch's size cap in units of this many bytes.
const KB: u64 = 1024;

/// The ceilings of `[memory]`: gh-aw's repo-memory defaults, 100 files of
/// 100 KB each (docs/src/content/docs/reference/repo-memory.md in
/// github/gh-aw), and a total that keeps the hand-back small.
pub const MAX_MEMORY_FILES: u32 = 100;
pub const MAX_MEMORY_FILE_BYTES: u64 = 100 * KB;
pub const MAX_MEMORY_BYTES: u64 = 1024 * KB;
/// What a memory file may be named with: text an agent writes notes in,
/// and nothing a later reader would execute (`.sh`) or render as markup
/// that runs (`.html`, `.svg`).
pub const MEMORY_EXTENSIONS: &[&str] = &["md", "txt", "json", "jsonl", "csv"];

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

/// The domains whose links gh-aw's sanitizer keeps when it is given none
/// (`buildAllowedDomains` in `sanitize_content_core.cjs` at the pinned
/// commit). `GH_AW_ALLOWED_DOMAINS` replaces this list, not extends it.
pub const GH_AW_LINK_DOMAINS: &[&str] = &[
    "github.com",
    "github.io",
    "githubusercontent.com",
    "githubassets.com",
    "github.dev",
    "codespaces.new",
];

/// IANA's list of top-level domains (`just refresh-top-level-domains`).
const TOP_LEVEL_DOMAINS: &str = include_str!("top-level-domains.txt");

/// What `policy` gives gh-aw as `GH_AW_ALLOWED_DOMAINS`: every top-level
/// domain, lowercase, so that its sanitizer keeps a link to any public
/// host as written (#918). The pinned sanitizer has no setting that keeps
/// every https link, and no wildcard for every domain; it does keep a
/// listed domain's subdomains. Links to an address, a host of one label
/// or a domain newer than this list are still redacted, as is every
/// non-https URL outside code. The filter stopped no leak (the sandbox
/// holds no credential worth one, and its reads are open to any host) and
/// cost reports their sources.
pub fn link_domains() -> &'static [String] {
    static DOMAINS: LazyLock<Vec<String>> = LazyLock::new(|| {
        TOP_LEVEL_DOMAINS
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    });
    &DOMAINS
}

/// The output types that name people: `allowed` lists the logins they may
/// name, exactly as written, since the handlers compare them so.
pub const PERSON_OUTPUTS: &[&str] = &["add_reviewer", "assign_to_user"];

/// A GitHub login, at most 39 characters with no leading, trailing or
/// doubled hyphen: what gh-aw's collector and handlers leave unchanged.
static LOGIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9](?:-?[A-Za-z0-9])*$").expect("a valid pattern"));

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

/// The request's values may start with a dash: they are a stranger's text,
/// and one that does is refused with a reason like any other.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Resolved context repositories as a JSON array (empty by default)
    #[arg(long, default_value = "[]", allow_hyphen_values = true)]
    pub context: String,
    /// The caller's bounds file
    #[arg(long, value_name = "FILE")]
    pub allow: PathBuf,
    /// Optional organization bounds; both files must admit the request
    #[arg(long, value_name = "FILE")]
    pub org_allow: Option<PathBuf>,
    /// The repository the agent works on, as OWNER/NAME
    #[arg(long, value_name = "REPO", allow_hyphen_values = true)]
    pub repo: String,
    /// Where `run` clones that repository from: https://HOST/OWNER/NAME,
    /// or http:// for a host in the bounds' `allow_http`
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
    /// The repository the run's item (its issue and status comment) is
    /// in, where that is not the output repository; it must be within
    /// `repos`, as `--repo` must
    #[arg(long, value_name = "OWNER/NAME", allow_hyphen_values = true)]
    pub item_repo: Option<String>,
    /// The repository could not be confirmed public: refused unless every
    /// bounds file sets `private = true`
    #[arg(long)]
    pub private: bool,
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
    /// Hosts of `hosts` a clone URL may name over plain `http://`, for a
    /// self-hosted forge on a private network without TLS. Empty by
    /// default: anyone on the path can read and alter a plain-HTTP clone,
    /// so the agent's base, and a private repository's read token, are
    /// only as safe as that network. Never [`NEVER_PLAIN_HTTP`].
    #[serde(default)]
    pub allow_http: Vec<String>,
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
    /// Who the hand-back's commit is by, as `Name <address>`. Without it,
    /// whatever `run` says, which a compromised agent machine chooses:
    /// with it, `check` refuses a patch by anyone else, so the run's
    /// commit cannot be passed off as a maintainer's. A replacement series
    /// keeps its commits' own authors and is not held to it, so bounds
    /// that allow one (`replacement_max_commits`) leave that open.
    /// See [`check_commit_author`].
    #[serde(default)]
    pub commit_author: Option<String>,
    /// The fork (OWNER/NAME) Forgejo's `apply` pushes a pull request's
    /// branch to, never the target repository: the target's CI then runs
    /// the agent's code as a fork's. Only the bounds name it, never a
    /// hand-back; it also lets a private run off GitHub open a pull
    /// request (docs/safe-outputs.md#publishing-to-forgejo).
    #[serde(default)]
    pub push_repo: Option<String>,
    /// Whether a run may work on a repository that is not public. Off,
    /// run evidence is published and only public repositories are run;
    /// on, `policy` keeps such a run's outputs in its own repository and
    /// `run` requires the egress allowlist and a read token
    /// (docs/private-repositories.md).
    #[serde(default)]
    pub private: bool,
    /// No longer used, and accepted so that a bounds file naming it still
    /// reads: links to every public host are kept ([`link_domains`]).
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// The agent's notes across runs (#119): `run` hands back `~/memory/`
    /// as `memory.json` and `check` holds it to these bounds. Absent, no
    /// memory is handed back, and `check` refuses one.
    #[serde(default)]
    pub memory: Option<Memory>,
    /// Where the outputs are applied; GitHub by default. Another forge
    /// may list only [`NEUTRAL_OUTPUTS`].
    #[serde(default)]
    pub forge: Forge,
}

/// `[memory]`: how much of the agent's memory directory is handed back,
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

    fn validate(&self) -> Result<()> {
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
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl OutputLimit {
    fn validate(&self, output: &str) -> Result<()> {
        ensure!(
            self.replacement_max_commits <= MAX_REPLACEMENT_COMMITS
                && (output == PUSH_TO_PULL_REQUEST_BRANCH || self.replacement_max_commits == 0),
            "outputs.{output}: replacement_max_commits is supported only for a push, at most 50"
        );
        ensure!(
            !self.ready_when_complete
                || matches!(output, CREATE_PULL_REQUEST | PUSH_TO_PULL_REQUEST_BRANCH),
            "outputs.{output}: ready_when_complete is supported only for {CREATE_PULL_REQUEST} and {PUSH_TO_PULL_REQUEST_BRANCH}"
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
                ensure!(
                    login.len() <= 39 && LOGIN_RE.is_match(login),
                    "outputs.{output}: invalid login {login:?}"
                );
            }
            return Ok(());
        }
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
                !label.is_empty() && label == label.trim() && !label.chars().any(char::is_control),
                "outputs.{output}: invalid label {label:?}"
            );
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
    /// Where the run's item is, when not in the output repository.
    pub item_repo: Option<&'a str>,
    /// Whether the repository is not public.
    pub private: bool,
}

/// What `policy.json` holds: the request, once it is within the bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
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
    /// The bounds' `push_repo`, where a pull request is asked for: the
    /// only repository Forgejo's `apply` pushes its branch to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_repo: Option<String>,
    /// A repository that is not public: `run` holds the machine to the
    /// conditions of docs/private-repositories.md before it clones.
    #[serde(default, skip_serializing_if = "is_false")]
    pub private: bool,
    /// What check and apply give gh-aw as `GH_AW_ALLOWED_DOMAINS`:
    /// [`link_domains`], or empty, leaving gh-aw its own
    /// [`GH_AW_LINK_DOMAINS`], in a policy written by hand.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_domains: Vec<String>,
    /// The bounds' `[memory]`, where every bounds file has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<Memory>,
    /// The bounds' [`Forge`].
    #[serde(default)]
    pub forge: Forge,
    /// The [`CONTRACT`] `policy` wrote this for. Absent, the policy was
    /// written before there was one, or by hand: the first.
    #[serde(default = "first_contract")]
    pub contract: u32,
}

/// Not [`CONTRACT`]: once that is raised, a policy without the key is
/// still one of the first contract's, and check refuses it.
fn first_contract() -> u32 {
    1
}

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
        crate::run::clone::check_url(&item.clone_url)?;
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
    /// The target base head resolved by the read-only policy job, not the producer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_base: Option<String>,
    /// As [`PullRequest::ready_when_complete`]: apply marks the pull
    /// request ready after a complete push, a draft after a checkpoint.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ready_when_complete: bool,
    pub protected_files: Vec<String>,
    pub protect_top_level_dot_folders: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unprotected_dot_folders: Vec<String>,
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
            max_patch_files: self.max_patch_files,
            commit_author: None,
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
        let host = host.to_ascii_lowercase();
        let kept = |domain: &str| {
            host == domain
                || host
                    .strip_suffix(domain)
                    .is_some_and(|sub| sub.ends_with('.'))
        };
        if self.allowed_domains.is_empty() {
            GH_AW_LINK_DOMAINS.iter().any(|domain| kept(domain))
        } else {
            self.allowed_domains.iter().any(|domain| kept(domain))
        }
    }

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
        check_context(&self.context)?;
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
        for host in &self.allow_http {
            ensure!(
                self.hosts.iter().any(|own| own.eq_ignore_ascii_case(host)),
                "allow_http names {host:?}, which is not in `hosts`"
            );
            // `github.com.` is github.com too.
            let host = host.to_ascii_lowercase();
            let host = host.trim_end_matches('.');
            ensure!(
                host != NEVER_PLAIN_HTTP && !host.ends_with(&format!(".{NEVER_PLAIN_HTTP}")),
                "allow_http may not name {host:?}: {NEVER_PLAIN_HTTP} serves https"
            );
        }
        for pattern in self.repos.iter().chain(&self.bases) {
            glob(pattern).with_context(|| format!("the glob {pattern:?}"))?;
        }
        ensure!(!self.outputs.is_empty(), "`outputs` lists no output type");
        self.forge
            .check_outputs(self.outputs.keys().map(String::as_str))?;
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
        if let Some(author) = &self.commit_author {
            check_commit_author(author)?;
        }
        if let Some(push_repo) = &self.push_repo {
            ensure!(
                REPO_RE.is_match(push_repo) && !dotted(push_repo) && !push_repo.ends_with(".git"),
                "push_repo requires an exact repository name: {push_repo:?}"
            );
        }
        if let Some(memory) = &self.memory {
            memory.validate()?;
        }
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
        let (plain, rest) = match url.strip_prefix("https://") {
            Some(rest) => (false, Some(rest)),
            None => (true, url.strip_prefix(PLAIN_HTTP_PREFIX)),
        };
        let Some((host, path)) = rest.and_then(|rest| rest.split_once('/')) else {
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
        if plain
            && !self
                .allow_http
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            return Some(format!(
                "clone URL {url:?} is plain http://, which the bounds' allow_http does not \
                 name its host for"
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
            item_repo,
            private,
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
        // Its issue's text joins the task and its status comment is posted
        // with the apply credential: a repository the bounds let runs work
        // on, not any one a caller names.
        if let Some(item_repo) = item_repo
            && (!REPO_RE.is_match(item_repo)
                || dotted(item_repo)
                || !glob_matches(&self.repos, item_repo))
        {
            errors.push(format!(
                "item repo {item_repo:?} is not within the bounds ({})",
                self.repos.join(", ")
            ));
        }
        // A private repository's content is only as private as where the
        // run leaves it: outputs applied in, or a status comment on, another
        // repository could publish it, so both stay in the run's own.
        if private {
            if !self.private {
                errors.push(format!(
                    "repo {repo:?} is not public, and the bounds do not set `private = true`"
                ));
            }
            if !output_repo.is_some_and(|output_repo| output_repo.eq_ignore_ascii_case(repo)) {
                errors.push(format!(
                    "a private run applies only to its own repository {repo:?}, not {}",
                    output_repo.map_or("an unnamed one".to_owned(), |name| format!("{name:?}"))
                ));
            }
            if let Some(item_repo) =
                item_repo.filter(|item_repo| !item_repo.eq_ignore_ascii_case(repo))
            {
                errors.push(format!(
                    "a private run's item is in its own repository {repo:?}, not {item_repo:?}"
                ));
            }
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
                    .filter(|output| {
                        !(private && (carries_patch(output) || *output == UPDATE_PROJECT))
                    })
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
        // A project's fields are read by the project's audience, which no
        // check here confines to the private repository's: refused until
        // that destination can be bounded, as patches are below.
        if private && types.contains(&UPDATE_PROJECT) {
            errors.push(format!(
                "a private run can't {UPDATE_PROJECT}: its project can be read outside the \
                 repository"
            ));
        }
        for carrier in [CREATE_PULL_REQUEST, PUSH_TO_PULL_REQUEST_BRANCH] {
            if no_change && types.contains(&carrier) {
                errors.push(format!(
                    "an analysis run hands back no change, so it can't {carrier}"
                ));
            }
            // Apply pushes a patch through a fork of the output repository
            // and checks that fork without a credential, which a private
            // repository's fork does not answer: refused before an agent
            // runs, not after. Off GitHub, a pull request whose fork the
            // bounds name is the exception: Forgejo's apply pushes only
            // there, and only to a private fork for a private run,
            // and the run's evidence stays on the same forge.
            let named_fork =
                carrier == CREATE_PULL_REQUEST && self.push_repo.is_some() && !on_github(clone_url);
            if private && types.contains(&carrier) && !named_fork {
                errors.push(format!(
                    "a private run hands back no patch, so it can't {carrier}: apply's fork is \
                     not supported for private repositories"
                ));
            }
        }

        // The fork is never the target: a branch pushed to the target runs
        // its CI as the repository's own, with its secrets. Nor is it the
        // target's owner's: Forgejo reads a pull request's head of that
        // owner as the target's own branch.
        if let Some(push_repo) = &self.push_repo
            && types.contains(&CREATE_PULL_REQUEST)
            && same_owner(push_repo, repo)
        {
            errors.push(format!(
                "push_repo {push_repo:?} is of the owner of {repo:?}, not another owner's fork"
            ));
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
            // outputs are applied there, and the push goes to that pull
            // request's head repository, which apply checks
            // (docs/safe-outputs.md).
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
            name: self
                .outputs
                .get(output)
                .and_then(|bound| bound.name.clone()),
            category: self
                .outputs
                .get(output)
                .and_then(|bound| bound.category.clone()),
            allowed_reasons: self
                .outputs
                .get(output)
                .map_or_else(Vec::new, |bound| bound.allowed_reasons.clone()),
            ready_when_complete: false,
        };
        let ready = |output: &str| {
            self.outputs
                .get(output)
                .is_some_and(|bound| bound.ready_when_complete)
        };
        let safe_outputs = SafeOutputs {
            create_pull_request: types.contains(&CREATE_PULL_REQUEST).then(|| PullRequest {
                max: limit(CREATE_PULL_REQUEST).max,
                protected_files: self.protected_files(repo),
                protect_top_level_dot_folders: true,
                unprotected_dot_folders: self.dot_folders(repo),
                protected_files_policy: ProtectedFilesPolicy::Blocked,
                draft: true,
                ready_when_complete: ready(CREATE_PULL_REQUEST),
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
                ready_when_complete: ready(PUSH_TO_PULL_REQUEST_BRANCH),
                protected_files: self.protected_files(repo),
                protect_top_level_dot_folders: true,
                unprotected_dot_folders: self.dot_folders(repo),
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
            context: Vec::new(),
            repo: repo.to_owned(),
            clone_url: clone_url.to_owned(),
            base: base.to_owned(),
            kind,
            max_outputs: max,
            max_patch_bytes: self.max_patch_bytes,
            safe_outputs,
            commit_author: self.commit_author.clone(),
            push_repo: self
                .push_repo
                .clone()
                .filter(|_| types.contains(&CREATE_PULL_REQUEST)),
            private,
            allowed_domains: link_domains().to_vec(),
            memory: self.memory.clone(),
            forge: self.forge,
            contract: CONTRACT,
        })
    }
}

/// Whether a clone URL is on GitHub, whose apply is gh-aw's and reads no
/// `push_repo`.
fn on_github(clone_url: &str) -> bool {
    let host = clone_url
        .split_once("://")
        .map_or(clone_url, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    host == GITHUB_HOST || host.ends_with(&format!(".{GITHUB_HOST}"))
}

/// Whether two OWNER/NAME names have the same owner.
fn same_owner(one: &str, other: &str) -> bool {
    let owner = |repo: &str| repo.split('/').next().unwrap_or_default().to_owned();
    owner(one).eq_ignore_ascii_case(&owner(other))
}

/// Whether OUTPUT hands back a patch.
fn carries_patch(output: &str) -> bool {
    matches!(output, CREATE_PULL_REQUEST | PUSH_TO_PULL_REQUEST_BRANCH)
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
    // A dispatcher must not turn context into a way to read outside the caller's
    // authority. Both bounds files admit every URL and repository, independently.
    ensure!(args.context.len() <= 16384, "context input exceeds 16 KiB");
    let context: Vec<ContextRepo> =
        serde_json::from_str(&args.context).context("parsing context")?;
    check_context(&context)?;
    ensure!(
        context.is_empty() || args.repo.rsplit('/').next() != Some("context"),
        "target name conflicts with the context directory"
    );
    for item in &context {
        for bound in std::iter::once(&bounds).chain(org_bounds.iter()) {
            ensure!(
                item.public
                    || bound
                        .repos
                        .iter()
                        .any(|pattern| glob(pattern).is_ok_and(|regex| regex.is_match(&item.repo))),
                "context repository {:?} is outside caller bounds",
                item.repo
            );
            ensure!(
                bound
                    .clone_url_problem(&item.clone_url, &item.repo)
                    .is_none(),
                "context clone URL is outside caller bounds"
            );
        }
    }
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
        item_repo: args.item_repo.as_deref(),
        private: args.private,
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
        Ok(mut policy) => {
            if policy.clone_url.starts_with(PLAIN_HTTP_PREFIX) {
                eprintln!(
                    "warning: {} is cloned over plain HTTP, as the bounds allow for its host",
                    policy.repo
                );
            }
            policy.context = context;
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
    if policy.forge != other.forge {
        return Err(vec![format!(
            "the bounds files name different forges: {:?} and {:?}",
            policy.forge.name(),
            other.forge.name()
        )]);
    }
    policy.commit_author = match (policy.commit_author, other.commit_author) {
        (Some(own), Some(other)) if own != other => {
            return Err(vec![format!(
                "the bounds files pin different commit authors: {own:?} and {other:?}"
            )]);
        }
        (own, other) => own.or(other),
    };
    // A fork to push to only where both files name it: each compile has
    // already allowed a private pull request on its own file's.
    policy.push_repo = match (policy.push_repo, other.push_repo) {
        (Some(own), Some(other)) if !own.eq_ignore_ascii_case(&other) => {
            return Err(vec![format!(
                "the bounds files name different push repositories: {own:?} and {other:?}"
            )]);
        }
        (Some(own), Some(_)) => Some(own),
        _ => None,
    };
    // Memory only where both files allow it, within the tighter of each.
    policy.memory = match (policy.memory, other.memory) {
        (Some(mut own), Some(bound)) => {
            own.max_files = own.max_files.min(bound.max_files);
            own.max_file_bytes = own.max_file_bytes.min(bound.max_file_bytes);
            own.max_bytes = own.max_bytes.min(bound.max_bytes);
            own.extensions
                .retain(|extension| bound.extensions.contains(extension));
            if own.extensions.is_empty() {
                return Err(vec![
                    "memory has no extension allowed by both bounds files".to_owned(),
                ]);
            }
            Some(own)
        }
        _ => None,
    };
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
            if limit.name != bound.name {
                limit.name = None;
            }
            if limit.category != bound.category {
                limit.category = None;
            }
            limit
                .allowed_reasons
                .retain(|reason| bound.allowed_reasons.contains(reason));
            true
        } else {
            false
        }
    });
    if let Some(output) = PERSON_OUTPUTS.iter().find(|output| {
        policy
            .safe_outputs
            .others
            .get(**output)
            .is_some_and(|limit| limit.allowed.as_ref().is_none_or(Vec::is_empty))
    }) {
        return Err(vec![format!(
            "{output} has no login allowed by both bounds files"
        )]);
    }
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
    for (output, _) in UPDATE_FIELDS {
        if policy
            .safe_outputs
            .others
            .get(*output)
            .is_some_and(|limit| limit.fields.is_empty())
        {
            return Err(vec![format!(
                "{output} has no common fields in both bounds files"
            )]);
        }
    }
    if policy
        .safe_outputs
        .others
        .get("create_check_run")
        .is_some_and(|limit| limit.name.is_none())
    {
        return Err(vec![
            "create_check_run has different check run names in the two bounds files".to_owned(),
        ]);
    }
    if policy
        .safe_outputs
        .others
        .get("create_discussion")
        .is_some_and(|limit| limit.category.is_none())
    {
        return Err(vec![
            "create_discussion has different categories in the two bounds files".to_owned(),
        ]);
    }
    if policy
        .safe_outputs
        .others
        .get(HIDE_COMMENT)
        .is_some_and(|limit| limit.allowed_reasons.is_empty())
    {
        return Err(vec![format!(
            "{HIDE_COMMENT} has no reason allowed by both bounds files"
        )]);
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
            pr.ready_when_complete &= bound.ready_when_complete;
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
            push.unprotected_dot_folders
                .retain(|name| bound.unprotected_dot_folders.contains(name));
            push.replacement_max_commits = push
                .replacement_max_commits
                .min(bound.replacement_max_commits);
            push.ready_when_complete &= bound.ready_when_complete;
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
files = ["CONTRIBUTING.md", "AGENTS.md"]
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
            item_repo: None,
            private: false,
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
    fn push_folder_exemptions_are_repository_scoped_and_intersected() {
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
        assert_eq!(rules.unprotected_dot_folders, [".github"]);
        // No other dot-folder can be exempted, even in a hand-written policy.
        let mut value = serde_json::to_value(&policy).unwrap();
        value["safe_outputs"][PUSH_TO_PULL_REQUEST_BRANCH]["unprotected_dot_folders"] =
            serde_json::json!([".husky"]);
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
                .contains("may only name \".github\""),
            "{error:#}"
        );
        for (local, org, admitted) in [
            (true, true, true),
            (true, false, false),
            (false, true, false),
            (false, false, false),
        ] {
            let mut caller = bounds.clone();
            let mut organization = bounds.clone();
            if !local {
                caller.unprotected_files.repos.clear();
            }
            if !org {
                organization.unprotected_files.repos.clear();
            }
            let intersected = intersect(
                caller.compile(&request).unwrap(),
                organization.compile(&request).unwrap(),
            )
            .unwrap();
            assert_eq!(
                !intersected
                    .safe_outputs
                    .patch_carrier()
                    .unwrap()
                    .1
                    .unprotected_dot_folders
                    .is_empty(),
                admitted
            );
        }
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
            ("topic/nested/branch", "add_comment,update_issue", true),
            ("main", MARK_READY, false),
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
                item_repo: None,
                private: false,
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
    fn updates_compile_with_their_fields_and_a_max() {
        for (output, fields) in [
            ("update_issue", vec!["body"]),
            ("update_pull_request", vec!["title", "draft"]),
            (MARK_READY, vec![]),
        ] {
            let mut bounds = bounds();
            bounds.outputs.insert(
                output.to_owned(),
                OutputLimit {
                    max: 2,
                    fields: fields.iter().map(|field| (*field).to_owned()).collect(),
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
            // gh-aw's handlers take a missing max for 10 or more.
            let json = serde_json::to_value(&policy.safe_outputs).unwrap();
            assert_eq!(json[output]["max"], 2, "{json}");
            assert_eq!(policy.safe_outputs.others[output].fields, fields);
            // Organization bounds narrow the fields; none in common is refused.
            if !fields.is_empty() {
                let mut org = bounds.clone();
                org.outputs.get_mut(output).unwrap().fields = vec!["title".to_owned()];
                let other = org
                    .compile(&Request {
                        outputs: output,
                        ..request()
                    })
                    .unwrap();
                let common = intersect(policy.clone(), other);
                assert_eq!(
                    common.is_ok(),
                    fields.contains(&"title"),
                    "{output}: {common:?}"
                );
                if let Ok(common) = common {
                    assert_eq!(common.safe_outputs.others[output].fields, ["title"]);
                }
            }
        }
    }

    #[test]
    fn issue_actions_compile_with_label_bounds() {
        let mut bounds = bounds();
        for output in [
            "close_issue",
            "add_labels",
            "remove_labels",
            "close_pull_request",
            "link_sub_issue",
        ] {
            let labels = output.ends_with("_labels");
            bounds.outputs.insert(
                output.to_owned(),
                OutputLimit {
                    max: 2,
                    allowed: labels.then(|| vec!["triage".to_owned()]),
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
            // gh-aw's handlers take a missing `max` for their own default.
            let json = serde_json::to_value(&policy.safe_outputs).unwrap();
            assert_eq!(json[output]["max"], 2, "{json}");
            if !labels {
                // Label limits are only for the label outputs.
                bounds.outputs.get_mut(output).unwrap().allowed = Some(vec![]);
                assert!(bounds.validate().is_err());
                bounds.outputs.get_mut(output).unwrap().allowed = None;
            }
            if labels {
                bounds.outputs.get_mut(output).unwrap().allowed = None;
                assert!(bounds.validate().is_err());
                bounds.outputs.get_mut(output).unwrap().allowed = Some(vec![]);
                bounds.validate().unwrap();
            }
        }
        bounds.outputs.get_mut("add_labels").unwrap().allowed = None;
        assert!(bounds.validate().is_err());
    }

    #[test]
    fn person_actions_require_allowed_logins() {
        let logins = |logins: &[&str]| Some(logins.iter().map(|l| (*l).to_owned()).collect());
        for output in PERSON_OUTPUTS {
            for (allowed, blocked, ok) in [
                (logins(&["octocat", "hubot-2"]), vec![], true),
                (logins(&["a"]), vec![], true),
                (logins(&[&"a".repeat(39)]), vec![], true),
                (logins(&[&"a".repeat(40)]), vec![], false),
                (None, vec![], false),
                (logins(&[]), vec![], false),
                (logins(&["octocat"]), vec!["hubot".to_owned()], false),
                (logins(&["@octocat"]), vec![], false),
                (logins(&["-octocat"]), vec![], false),
                (logins(&["octocat-"]), vec![], false),
                (logins(&["octo--cat"]), vec![], false),
                (logins(&["octo cat"]), vec![], false),
                (logins(&["octocat[bot]"]), vec![], false),
            ] {
                let mut bounds = bounds();
                bounds.outputs.insert(
                    (*output).to_owned(),
                    OutputLimit {
                        max: 2,
                        allowed: allowed.clone(),
                        blocked,
                        ..Default::default()
                    },
                );
                assert_eq!(bounds.validate().is_ok(), ok, "{output} {allowed:?}");
                if ok {
                    let policy = bounds
                        .compile(&Request {
                            outputs: output,
                            ..request()
                        })
                        .unwrap();
                    policy.validate().unwrap();
                    assert_eq!(policy.safe_outputs.max_of(output), Some(2));
                    assert_eq!(policy.safe_outputs.others[*output].allowed, allowed);
                }
            }
            // A second bounds file narrows the logins; none in common is
            // refused rather than left to the handlers' "anyone".
            let compiled = |allowed: &[&str]| {
                let mut bounds = bounds();
                bounds.outputs.insert(
                    (*output).to_owned(),
                    OutputLimit {
                        max: 1,
                        allowed: logins(allowed),
                        ..Default::default()
                    },
                );
                bounds
                    .compile(&Request {
                        outputs: output,
                        ..request()
                    })
                    .unwrap()
            };
            let policy =
                intersect(compiled(&["octocat", "hubot"]), compiled(&["OCTOCAT"])).unwrap();
            assert_eq!(
                policy.safe_outputs.others[*output].allowed,
                logins(&["octocat"])
            );
            assert!(intersect(compiled(&["octocat"]), compiled(&["hubot"])).is_err());
        }
    }

    #[test]
    fn hidden_comments_name_their_reasons() {
        let accepts = |output: &str, text: &str| {
            toml::from_str::<OutputLimit>(text).is_ok_and(|limit| limit.validate(output).is_ok())
        };
        for (output, text, ok) in [
            (HIDE_COMMENT, "max = 1\nallowed_reasons = ['SPAM']", true),
            (
                HIDE_COMMENT,
                "max = 1\nallowed_reasons = ['OUTDATED', 'RESOLVED']",
                true,
            ),
            (HIDE_COMMENT, "max = 1", false),
            (HIDE_COMMENT, "max = 1\nallowed_reasons = []", false),
            // As the collector normalizes them, and no other.
            (HIDE_COMMENT, "max = 1\nallowed_reasons = ['spam']", false),
            (
                HIDE_COMMENT,
                "max = 1\nallowed_reasons = ['DUPLICATE']",
                false,
            ),
            (
                HIDE_COMMENT,
                "max = 1\nallowed_reasons = ['SPAM']\nallowed = ['x']",
                false,
            ),
            ("add_comment", "max = 1\nallowed_reasons = ['SPAM']", false),
        ] {
            assert_eq!(accepts(output, text), ok, "{output}: {text}");
        }

        let compiled = |reasons: &[&str]| {
            let mut bounds = bounds();
            bounds.outputs.insert(
                HIDE_COMMENT.to_owned(),
                OutputLimit {
                    max: 2,
                    allowed_reasons: reasons.iter().map(|r| (*r).to_owned()).collect(),
                    ..Default::default()
                },
            );
            bounds.validate().unwrap();
            bounds
                .compile(&Request {
                    outputs: HIDE_COMMENT,
                    ..request()
                })
                .unwrap()
        };
        let policy = compiled(&["SPAM", "OUTDATED"]);
        policy.validate().unwrap();
        // The handler reads `allowed_reasons` as it is written here.
        assert_eq!(
            serde_json::to_value(&policy.safe_outputs).unwrap()[HIDE_COMMENT],
            serde_json::json!({"max": 2, "allowed_reasons": ["SPAM", "OUTDATED"]})
        );
        let both = intersect(policy.clone(), compiled(&["OUTDATED", "ABUSE"])).unwrap();
        assert_eq!(
            both.safe_outputs.others[HIDE_COMMENT].allowed_reasons,
            ["OUTDATED"]
        );
        // None in common would be the handler's "any reason".
        assert!(intersect(policy, compiled(&["ABUSE"])).is_err());
    }

    /// The review thread outputs take a `max` and nothing else: gh-aw's
    /// own `target` and `commit_id` would choose the pull request or the
    /// commit, which are the run's, and `side` and `footer` are left at
    /// the handlers' defaults.
    #[test]
    fn review_threads_take_only_a_max() {
        let accepts = |output: &str, text: &str| {
            toml::from_str::<OutputLimit>(text).is_ok_and(|limit| limit.validate(output).is_ok())
        };
        for output in REVIEW_THREAD_OUTPUTS {
            for (text, ok) in [
                ("max = 3", true),
                ("max = 3\ntarget = '*'", false),
                ("max = 3\ntarget = 'triggering'", false),
                ("max = 3\ncommit_id = 'abc'", false),
                ("max = 3\nside = 'LEFT'", false),
                ("max = 3\nfooter = false", false),
                ("max = 3\nallowed = ['x']", false),
                ("max = 3\nallowed_reasons = ['SPAM']", false),
                ("max = 3\nfields = ['body']", false),
            ] {
                assert_eq!(accepts(output, text), ok, "{output}: {text}");
            }
        }

        let mut bounds = bounds();
        for output in REVIEW_THREAD_OUTPUTS {
            bounds.outputs.insert(
                (*output).to_owned(),
                OutputLimit {
                    max: 2,
                    ..Default::default()
                },
            );
        }
        bounds.validate().unwrap();
        let outputs = REVIEW_THREAD_OUTPUTS.join(",");
        let policy = bounds
            .compile(&Request {
                outputs: &outputs,
                ..request()
            })
            .unwrap();
        policy.validate().unwrap();
        for output in REVIEW_THREAD_OUTPUTS {
            assert_eq!(
                serde_json::to_value(&policy.safe_outputs).unwrap()[output],
                serde_json::json!({"max": 2}),
                "{output}"
            );
        }
        // Off unless the bounds list them.
        assert!(
            super::tests::bounds()
                .compile(&Request {
                    outputs: CREATE_REVIEW_COMMENT,
                    ..request()
                })
                .is_err()
        );
    }

    /// gh-aw's per-type `target-repo`, `allowed-repos` and protected-file
    /// policies are not bounds keys: destinations are the caller's, and a
    /// protected file is always refused (docs/safe-outputs.md).
    #[test]
    fn per_type_destinations_and_protection_are_not_offered() {
        for output in [CREATE_PULL_REQUEST, "add_comment", HIDE_COMMENT]
            .into_iter()
            .chain(REVIEW_THREAD_OUTPUTS.iter().copied())
        {
            for key in [
                // The table parses without one of them.
                "",
                "target-repo = 'evil/repo'",
                "target_repo = 'evil/repo'",
                "allowed-repos = ['evil/repo']",
                "allowed_repos = ['evil/repo']",
                "protected-files = 'request-review'",
                "protected_files_policy = 'fallback-to-issue'",
                "protected_files = []",
            ] {
                let text = format!(
                    "{BOUNDS}\n[outputs.{output}]\nmax = 1\nallowed_reasons = ['SPAM']\n{key}\n"
                )
                .replace(&format!("{output} = {{ max = 1 }}\n"), "")
                .replace(&format!("{output} = {{ max = 3 }}\n"), "");
                match toml::from_str::<Bounds>(&text) {
                    Ok(_) => assert!(key.is_empty(), "{output} {key}"),
                    Err(error) => assert!(
                        !key.is_empty() && error.to_string().contains("unknown field"),
                        "{output} {key}: {error}"
                    ),
                }
            }
        }
        // Nor can a policy carry another protected-file policy than refusal.
        let mut policy = serde_json::to_value(policy()).unwrap();
        for value in ["blocked", "request-review", "fallback-to-issue"] {
            policy["safe_outputs"]["create_pull_request"]["protected_files_policy"] =
                serde_json::json!(value);
            assert_eq!(
                serde_json::from_value::<Policy>(policy.clone()).is_ok(),
                value == "blocked",
                "{value}"
            );
        }
    }

    #[test]
    fn pinned_outputs_take_their_pin_from_the_bounds() {
        let accepts = |output: &str, text: &str| {
            toml::from_str::<OutputLimit>(text).is_ok_and(|limit| limit.validate(output).is_ok())
        };
        // The check run's name and the discussion's category: each
        // required for its type, and only for it.
        for (output, key, other) in [
            ("create_check_run", "name", "category"),
            ("create_discussion", "category", "name"),
        ] {
            for (text, ok) in [
                (format!("max = 1\n{key} = 'agent verdict'"), true),
                (format!("max = 1\n{key} = 'agent/verdict (draft)'"), true),
                ("max = 1".to_owned(), false),
                (format!("max = 1\n{key} = ''"), false),
                (format!("max = 1\n{key} = ' agent'"), false),
                (format!("max = 1\n{key} = \"a\\nb\""), false),
                (format!("max = 1\n{key} = '{}'", "a".repeat(64)), true),
                (format!("max = 1\n{key} = '{}'", "a".repeat(65)), false),
                (format!("max = 1\n{key} = 'a'\n{other} = 'b'"), false),
            ] {
                assert_eq!(accepts(output, &text), ok, "{output}: {text}");
            }
            assert!(!accepts("add_comment", &format!("max = 1\n{key} = 'a'")));

            let configured = |pin: &str| {
                let mut bounds = bounds();
                let mut limit = OutputLimit {
                    max: 2,
                    ..OutputLimit::default()
                };
                *if key == "name" {
                    &mut limit.name
                } else {
                    &mut limit.category
                } = Some(pin.to_owned());
                bounds.outputs.insert(output.to_owned(), limit);
                bounds.validate().unwrap();
                bounds
                    .compile(&Request {
                        outputs: output,
                        ..request()
                    })
                    .unwrap()
            };
            let policy = configured("agent verdict");
            policy.validate().unwrap();
            // gh-aw's handlers take a missing `max` for their own default,
            // and a missing pin for the workflow's or any category: both
            // are always written.
            let config = serde_json::to_value(&policy.safe_outputs).unwrap();
            assert_eq!(
                config[output],
                serde_json::json!({"max": 2, key: "agent verdict"})
            );
            assert_eq!(
                intersect(policy.clone(), configured("agent verdict"))
                    .unwrap()
                    .safe_outputs,
                policy.safe_outputs
            );
            assert!(intersect(policy, configured("required-ci")).is_err());
        }
    }

    #[test]
    fn commit_authors_are_plain_and_pinned_by_both_files() {
        let bot = "github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>";
        for (author, ok) in [
            ("A Bot <bot@example.org>", true),
            ("A. Bot (ci) <a.bot+ci@mail.example.org>", true),
            (bot, true),
            ("Bot", false),
            ("<bot@example.org>", false),
            (" Bot <bot@example.org>", false),
            ("Bot. <bot@example.org>", false),
            ("A  Bot <bot@example.org>", false),
            ("\"A Bot\" <bot@example.org>", false),
            ("Bót <bot@example.org>", false),
            ("=?UTF-8?q?x?= <bot@example.org>", false),
            ("A Bot <bot@localhost>", false),
            ("A Bot <bot@example.org> x", false),
            ("A, Bot <bot@example.org>", false),
            ("(bot) <bot@example.org>", false),
            (
                format!("{} <bot@example.org>", "a".repeat(60)).as_str(),
                true,
            ),
            (
                format!("{} <bot@example.org>", "a".repeat(61)).as_str(),
                false,
            ),
            ("A\nBot <bot@example.org>", false),
        ] {
            let text = format!("commit_author = {}\n{BOUNDS}", toml::Value::from(author));
            let bounds = toml::from_str::<Bounds>(&text).unwrap();
            assert_eq!(bounds.validate().is_ok(), ok, "{author:?}");
        }

        let pinned = |author: Option<&str>| {
            let mut bounds = bounds();
            bounds.commit_author = author.map(str::to_owned);
            let policy = bounds.compile(&request()).unwrap();
            policy.validate().unwrap();
            policy
        };
        let policy = pinned(Some(bot));
        assert_eq!(policy.commit_author.as_deref(), Some(bot));
        let loaded: Policy =
            serde_json::from_value(serde_json::to_value(&policy).unwrap()).unwrap();
        assert_eq!(loaded, policy);
        // Unpinned, policy.json is as it was.
        assert!(
            !serde_json::to_string(&pinned(None))
                .unwrap()
                .contains("commit_author")
        );
        // Either file's pin holds; two that differ pin no one.
        for (left, right) in [(Some(bot), None), (None, Some(bot)), (Some(bot), Some(bot))] {
            let both = intersect(pinned(left), pinned(right)).unwrap();
            assert_eq!(both.commit_author.as_deref(), Some(bot));
        }
        assert!(intersect(pinned(Some(bot)), pinned(Some("A Bot <bot@example.org>"))).is_err());
        let mut bad = policy;
        bad.commit_author = Some("Evil".into());
        assert!(bad.validate().is_err());
    }

    #[test]
    fn links_to_every_public_host_are_kept() {
        // A bounds file that still names domains reads, and changes nothing.
        let text = format!("allowed_domains = [\"fedoraproject.org\"]\n{BOUNDS}");
        let named = toml::from_str::<Bounds>(&text).unwrap();
        named.validate().unwrap();
        let policy = named.compile(&request()).unwrap();
        policy.validate().unwrap();
        assert_eq!(policy, bounds().compile(&request()).unwrap());
        assert_eq!(policy.allowed_domains, link_domains());
        let both = intersect(policy.clone(), bounds().compile(&request()).unwrap()).unwrap();
        assert_eq!(both.allowed_domains, link_domains());
        for (host, kept) in [
            ("github.com", true),
            ("src.fedoraproject.org", true),
            ("SRC.FedoraProject.org", true),
            ("docs.rs", true),
            ("an.arbitrary.example.dev", true),
            ("x.xn--p1ai", true),
            // gh-aw redacts these whatever it is given.
            ("localhost", false),
            ("example.invalid", false),
        ] {
            assert_eq!(policy.keeps_link_to(host), kept, "{host}");
        }
        assert!(link_domains().len() > 1000);
        assert!(link_domains().iter().all(|d| {
            !d.is_empty()
                && d.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        }));
        // A policy written by hand may leave gh-aw its own, and none
        // `policy` wrote carries another list.
        let mut own = policy.clone();
        own.allowed_domains.clear();
        own.validate().unwrap();
        assert!(own.keeps_link_to("raw.githubusercontent.com"));
        assert!(!own.keeps_link_to("src.fedoraproject.org"));
        let mut bad = policy;
        bad.allowed_domains.push("a.example,evil.example".into());
        assert!(bad.validate().is_err());
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
            (
                "an item in another repository the bounds allow",
                Request {
                    item_repo: Some("cgwalters-forge/tracker"),
                    ..ok
                },
                None,
            ),
            (
                "an item in a repository the bounds do not allow",
                Request {
                    item_repo: Some("evil/tracker"),
                    ..ok
                },
                Some("item repo \"evil/tracker\" is not within"),
            ),
            (
                "an item in a repository of dots",
                Request {
                    item_repo: Some("cgwalters-forge/.."),
                    ..ok
                },
                Some("item repo "),
            ),
            (
                "an item in a malformed repository",
                Request {
                    item_repo: Some("cgwalters-forge/tracker/x"),
                    ..ok
                },
                Some("item repo "),
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

    /// Plain HTTP only for a host the bounds name in `allow_http`. Bounds
    /// without it refuse it for every host, so organization bounds that do
    /// not opt in refuse the run too: `run` needs both to admit it.
    #[test]
    fn plain_http_only_for_the_hosts_the_bounds_name() {
        let with = |allow_http: &str| {
            let bounds: Bounds = toml::from_str(&BOUNDS.replace(
                "hosts = [\"github.com\"]",
                &format!(
                    "hosts = [\"github.com\", \"forge.internal\", \"other.internal\"]\n\
                     allow_http = [{allow_http}]"
                ),
            ))
            .unwrap();
            bounds.validate().unwrap();
            bounds
        };
        let (opted, default) = (with("\"forge.internal\""), with(""));
        const PLAIN: Option<&str> = Some("plain http://");
        const HOST: Option<&str> = Some("host");
        // The URL, and what bounds with and without the opt-in say of it.
        let cases = [
            ("http://forge.internal/bootc-dev/bootc", None, PLAIN),
            ("https://forge.internal/bootc-dev/bootc", None, None),
            ("http://forge.internal/bootc-dev/bootc.git", None, PLAIN),
            ("http://FORGE.internal/bootc-dev/bootc", None, PLAIN),
            ("http://other.internal/bootc-dev/bootc", PLAIN, PLAIN),
            ("http://github.com/bootc-dev/bootc", PLAIN, PLAIN),
            ("http://forge.internal:8080/bootc-dev/bootc", HOST, HOST),
            ("http://x@forge.internal/bootc-dev/bootc", HOST, HOST),
            (
                "http://forge.internal/evil/bootc",
                Some("does not name"),
                PLAIN,
            ),
            (
                "httpx://forge.internal/bootc-dev/bootc",
                Some("is not"),
                Some("is not"),
            ),
        ];
        for (url, with_opt_in, by_default) in cases {
            let request = Request {
                clone_url: url,
                ..request()
            };
            for (bounds, want) in [(&opted, with_opt_in), (&default, by_default)] {
                match (bounds.compile(&request), want) {
                    (Ok(policy), None) => {
                        assert_eq!(policy.clone_url, url);
                        // And what it admits, `run` can clone.
                        crate::run::clone::check(&policy).unwrap();
                    }
                    (Err(errors), Some(want)) => {
                        assert!(errors.iter().any(|e| e.contains(want)), "{url}: {errors:?}");
                    }
                    (result, _) => panic!("{url} ({want:?}): {result:?}"),
                }
            }
        }
    }

    /// A repository that is not public is admitted only where every bounds
    /// file opts in, and only with its outputs and item in that repository.
    #[test]
    fn private_runs_need_every_bounds_file_and_stay_in_their_repository() {
        let own = Request {
            private: true,
            output_repo: Some(REPO),
            outputs: "add_comment,noop",
            ..request()
        };
        // The name, whether the caller's and the organization's files
        // opt in, the request, and a part of the refusal if it is refused.
        let cases: &[(&str, bool, bool, Request<'_>, Option<&str>)] = &[
            ("public, neither opts in", false, false, request(), None),
            ("private, both opt in", true, true, own, None),
            (
                "private, the caller does not opt in",
                false,
                true,
                own,
                Some("do not set `private = true`"),
            ),
            (
                "private, the organization does not opt in",
                true,
                false,
                own,
                Some("do not set `private = true`"),
            ),
            (
                "private, no output repository",
                true,
                true,
                Request {
                    output_repo: None,
                    ..own
                },
                Some("not an unnamed one"),
            ),
            (
                "private, outputs to another repository",
                true,
                true,
                Request {
                    output_repo: Some("bootc-dev/other"),
                    ..own
                },
                Some("not \"bootc-dev/other\""),
            ),
            (
                "private, the item in another repository",
                true,
                true,
                Request {
                    item_repo: Some("bootc-dev/other"),
                    ..own
                },
                Some("item is in its own repository"),
            ),
            (
                "private, of another case",
                true,
                true,
                Request {
                    output_repo: Some("BOOTC-DEV/BOOTC"),
                    item_repo: Some("Bootc-Dev/Bootc"),
                    ..own
                },
                None,
            ),
            (
                "private, a pull request",
                true,
                true,
                Request {
                    outputs: "create_pull_request,noop",
                    ..own
                },
                Some("can't create_pull_request"),
            ),
            (
                "private, a project",
                true,
                true,
                Request {
                    outputs: "update_project,noop",
                    ..own
                },
                Some("can't update_project"),
            ),
            (
                "private, all outputs but a patch or a project",
                true,
                true,
                Request {
                    outputs: ALL_OUTPUTS,
                    ..own
                },
                None,
            ),
            (
                "public, all outputs with a project",
                false,
                false,
                Request {
                    outputs: ALL_OUTPUTS,
                    ..request()
                },
                None,
            ),
            (
                "private, the item in its own repository",
                true,
                true,
                Request {
                    item_repo: Some(REPO),
                    ..own
                },
                None,
            ),
        ];
        let with = |private: bool| {
            let mut bounds = Bounds {
                private,
                ..bounds()
            };
            bounds.outputs.insert(
                UPDATE_PROJECT.to_owned(),
                OutputLimit {
                    max: 1,
                    projects: vec!["https://github.com/orgs/example/projects/2".to_owned()],
                    fields: vec!["Status".to_owned()],
                    ..OutputLimit::default()
                },
            );
            bounds
        };
        for (name, caller, org, request, want) in cases {
            let compiled = with(*caller).compile(request).and_then(|policy| {
                with(*org)
                    .compile(request)
                    .and_then(|other| intersect(policy, other))
            });
            match (compiled, want) {
                (Ok(policy), None) => {
                    assert_eq!(policy.private, request.private, "{name}");
                    assert!(
                        !request.private || policy.safe_outputs.patch_carrier().is_none(),
                        "{name}"
                    );
                    assert_eq!(
                        policy.safe_outputs.others.contains_key(UPDATE_PROJECT),
                        request.outputs == ALL_OUTPUTS && !request.private,
                        "{name}"
                    );
                    let json = serde_json::to_value(&policy).unwrap();
                    // Absent unless set, so a public run's policy.json is
                    // what it was before the setting.
                    assert_eq!(json.get("private").is_some(), request.private, "{name}");
                    let loaded: Policy = serde_json::from_value(json).unwrap();
                    assert_eq!(loaded, policy, "{name}");
                }
                (Err(errors), Some(want)) => {
                    assert!(
                        errors.iter().any(|e| e.contains(want)),
                        "{name}: {errors:?}"
                    );
                }
                (result, _) => panic!("{name}: {result:?}"),
            }
        }
        let bounds: Bounds = toml::from_str(&format!("private = true\n{BOUNDS}")).unwrap();
        assert!(bounds.private && !self::bounds().private);
    }

    /// Off GitHub, a private run may open a pull request when every bounds
    /// file names the same fork for its branch, which is never the target.
    #[test]
    fn push_repo_bounds_private_pull_requests_off_github() {
        const FORK: &str = "bot/bootc";
        let forge = Request {
            private: true,
            output_repo: Some(REPO),
            clone_url: "https://forge.example/bootc-dev/bootc",
            outputs: "create_pull_request,noop",
            ..request()
        };
        let public = Request {
            private: false,
            ..forge
        };
        // The name, the caller's and the organization's push_repo, the
        // request, and a part of the refusal if it is refused.
        type Case<'a> = (
            &'a str,
            Option<&'a str>,
            Option<&'a str>,
            Request<'a>,
            Option<&'a str>,
        );
        let cases: &[Case<'_>] = &[
            (
                "private, named in both",
                Some(FORK),
                Some(FORK),
                forge,
                None,
            ),
            (
                "private, named in both in another case",
                Some(FORK),
                Some("BOT/Bootc"),
                forge,
                None,
            ),
            (
                "public, named in both",
                Some(FORK),
                Some(FORK),
                public,
                None,
            ),
            ("public, named in neither", None, None, public, None),
            (
                "public, comments only",
                Some(FORK),
                Some(FORK),
                Request {
                    outputs: "add_comment,noop",
                    ..public
                },
                None,
            ),
            (
                "private, named in neither",
                None,
                None,
                forge,
                Some("can't create_pull_request"),
            ),
            (
                "private, named by the caller only",
                Some(FORK),
                None,
                forge,
                Some("can't create_pull_request"),
            ),
            (
                "named differently",
                Some(FORK),
                Some("bot/other"),
                public,
                Some("different push repositories"),
            ),
            (
                "the target itself",
                Some("Bootc-Dev/Bootc"),
                Some("Bootc-Dev/Bootc"),
                public,
                Some("is of the owner of \"bootc-dev/bootc\""),
            ),
            (
                "the target's owner's",
                Some("bootc-dev/fork"),
                Some("bootc-dev/fork"),
                public,
                Some("is of the owner of \"bootc-dev/bootc\""),
            ),
            (
                "private, on GitHub",
                Some(FORK),
                Some(FORK),
                Request {
                    clone_url: "https://github.com/bootc-dev/bootc",
                    ..forge
                },
                Some("can't create_pull_request"),
            ),
        ];
        let with = |push_repo: Option<&str>| {
            let mut bounds = Bounds {
                private: true,
                push_repo: push_repo.map(str::to_owned),
                ..bounds()
            };
            bounds.hosts.push("forge.example".to_owned());
            bounds.validate().unwrap();
            bounds
        };
        for (name, caller, org, request, want) in cases {
            let compiled = with(*caller).compile(request).and_then(|policy| {
                with(*org)
                    .compile(request)
                    .and_then(|other| intersect(policy, other))
            });
            match (compiled, want) {
                (Ok(policy), None) => {
                    let pull_request = policy.safe_outputs.create_pull_request.is_some();
                    let want = caller.filter(|_| pull_request);
                    assert_eq!(policy.push_repo.as_deref(), want, "{name}");
                    assert_eq!(policy.private, request.private, "{name}");
                    let loaded: Policy =
                        serde_json::from_value(serde_json::to_value(&policy).unwrap()).unwrap();
                    assert_eq!(loaded, policy, "{name}");
                }
                (Err(errors), Some(want)) => {
                    assert!(
                        errors.iter().any(|e| e.contains(want)),
                        "{name}: {errors:?}"
                    );
                }
                (result, _) => panic!("{name}: {result:?}"),
            }
        }
        for push_repo in ["bot", "bot/../x", "bot/..", "a b/c", "bot/bootc.git"] {
            let bounds = Bounds {
                push_repo: Some(push_repo.to_owned()),
                ..bounds()
            };
            assert!(bounds.validate().is_err(), "{push_repo}");
        }
        // Nor does a policy.json written by hand name the target.
        for (push_repo, ok) in [
            (FORK, true),
            ("Bootc-Dev/Bootc", false),
            ("bootc-dev/fork", false),
            ("bot/..", false),
            ("bot/bootc.git", false),
        ] {
            let policy = Policy {
                push_repo: Some(push_repo.to_owned()),
                ..policy()
            };
            assert_eq!(policy.validate().is_ok(), ok, "{push_repo}");
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
            item_repo: None,
            private: false,
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
            // The push goes to the pull request's branch wherever apply's
            // user may push to it: any repository the bounds let runs
            // work on, and never with the job token, which names no user.
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
                    "output type \"push_to_pull_request_branch\" needs a user's token that can push to the pull request's branch",
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

    /// Off unless bounds say so, for the patch's carriers alone, and on
    /// only where every bounds file turns it on.
    #[test]
    fn ready_when_complete_is_explicit_and_only_tightens() {
        type Ready = fn(&Policy) -> Option<bool>;
        type Carrier = (
            &'static str,
            fn() -> Bounds,
            fn() -> Request<'static>,
            Ready,
        );
        let carriers: [Carrier; 2] = [
            (CREATE_PULL_REQUEST, bounds, request, |policy| {
                policy
                    .safe_outputs
                    .create_pull_request
                    .as_ref()
                    .map(|pr| pr.ready_when_complete)
            }),
            (
                PUSH_TO_PULL_REQUEST_BRANCH,
                push_bounds,
                push_request,
                |policy| {
                    policy
                        .safe_outputs
                        .push_to_pull_request_branch
                        .as_ref()
                        .map(|push| push.ready_when_complete)
                },
            ),
        ];
        for (output, bounds, request, ready) in carriers {
            let compile = |on| {
                let mut bounds = bounds();
                bounds.outputs.get_mut(output).unwrap().ready_when_complete = on;
                bounds.validate().unwrap();
                bounds.compile(&request()).unwrap()
            };
            for (caller, organization, want) in [
                (false, false, false),
                (true, false, false),
                (false, true, false),
                (true, true, true),
            ] {
                let both = intersect(compile(caller), compile(organization)).unwrap();
                assert_eq!(ready(&both), Some(want), "{output} {caller} {organization}");
                assert_eq!(both.safe_outputs.ready_when_complete(), want);
            }
            // policy.json says nothing of it when off, as before.
            let off = serde_json::to_string(&compile(false)).unwrap();
            assert!(!off.contains("ready_when_complete"), "{off}");
        }
        for (output, accepted) in [
            (CREATE_PULL_REQUEST, true),
            (PUSH_TO_PULL_REQUEST_BRANCH, true),
            ("add_comment", false),
            (MARK_READY, false),
        ] {
            let limit = OutputLimit {
                max: 1,
                ready_when_complete: true,
                branches: if output == PUSH_TO_PULL_REQUEST_BRANCH {
                    vec!["agent-run-*".into()]
                } else {
                    Vec::new()
                },
                ..OutputLimit::default()
            };
            assert_eq!(limit.validate(output).is_ok(), accepted, "{output}");
        }
        let toml = "hosts = []\nrepos = []\nbases = []\nmax_outputs = 1\nmax_patch_bytes = 1\n\
                    max_patch_files = 1\n[outputs]\ncreate_pull_request = { max = 1, ready_when_complete = true }\n";
        let parsed: Bounds = toml::from_str(toml).unwrap();
        assert!(parsed.outputs[CREATE_PULL_REQUEST].ready_when_complete);
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

        // `[memory]` reaches the policy with its defaults, within its
        // ceilings; without it there is none, and no key for it.
        assert_eq!(all.memory, None);
        assert!(!serde_json::to_string(&all).unwrap().contains("memory"));
        let memory = |table: &str| {
            let bounds: Bounds = toml::from_str(&format!("{BOUNDS}\n[memory]\n{table}")).unwrap();
            bounds.validate().unwrap();
            let policy = bounds.compile(&request()).unwrap();
            policy.validate().unwrap();
            policy.memory.unwrap()
        };
        for (table, want) in [
            ("", (20, 16 * KB, 64 * KB, &["md", "txt", "json"][..])),
            (
                "max_files = 100\nmax_file_bytes = 102400\nmax_bytes = 1048576\n\
                 extensions = [\"md\", \"txt\", \"json\", \"jsonl\", \"csv\"]",
                (100, 100 * KB, 1024 * KB, MEMORY_EXTENSIONS),
            ),
            (
                "max_files = 1\nmax_file_bytes = 1\nmax_bytes = 1\nextensions = [\"csv\"]",
                (1, 1, 1, &["csv"]),
            ),
        ] {
            let got = memory(table);
            assert_eq!(
                (got.max_files, got.max_file_bytes, got.max_bytes),
                (want.0, want.1, want.2),
                "{table}"
            );
            assert_eq!(got.extensions, want.3, "{table}");
        }

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
        // Memory only where both files have it, within the tighter bounds.
        let with_memory = |memory: Memory| Policy {
            memory: Some(memory),
            ..b.clone()
        };
        let defaults: Memory = toml::from_str("").unwrap();
        let tight = Memory {
            max_files: 3,
            extensions: vec!["txt".into(), "csv".into()],
            ..defaults.clone()
        };
        let both = Policy {
            memory: Some(defaults.clone()),
            ..a.clone()
        };
        assert_eq!(intersect(both.clone(), b.clone()).unwrap().memory, None);
        assert_eq!(
            intersect(a.clone(), with_memory(defaults.clone()))
                .unwrap()
                .memory,
            None
        );
        let memory = intersect(both.clone(), with_memory(tight.clone()))
            .unwrap()
            .memory
            .unwrap();
        assert_eq!(
            (memory.max_files, memory.extensions),
            (3, vec!["txt".to_owned()])
        );
        let disjoint = Memory {
            extensions: vec!["csv".into()],
            ..tight
        };
        assert!(intersect(both, with_memory(disjoint)).is_err());
        for (left, right) in [(a.clone(), b.clone()), (b, a)] {
            let policy = intersect(left, right).unwrap();
            assert_eq!(policy.max_outputs, 2);
            assert_eq!(policy.max_patch_bytes, 4096);
            assert_eq!(policy.safe_outputs.max_of("missing_data"), None);
            let pr = policy.safe_outputs.create_pull_request.unwrap();
            assert_eq!(pr.max_patch_files, 3);
            assert!(pr.protected_files.contains(&"CONTRIBUTING.md".into()));
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
                &["CONTRIBUTING.md", "AGENTS.md"]
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
                "plain HTTP for a host not in hosts",
                with(
                    "hosts = [\"github.com\"]",
                    "hosts = [\"github.com\"]\nallow_http = [\"forge.internal\"]",
                ),
                "not in `hosts`",
            ),
            (
                "plain HTTP for github.com",
                with(
                    "hosts = [\"github.com\"]",
                    "hosts = [\"GitHub.com\"]\nallow_http = [\"github.COM\"]",
                ),
                "may not name",
            ),
            (
                "plain HTTP for a host under github.com",
                with(
                    "hosts = [\"github.com\"]",
                    "hosts = [\"api.github.com\"]\nallow_http = [\"api.github.com\"]",
                ),
                "may not name",
            ),
            (
                "plain HTTP for github.com spelled with its root",
                with(
                    "hosts = [\"github.com\"]",
                    "hosts = [\"github.com.\"]\nallow_http = [\"github.com.\"]",
                ),
                "may not name",
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
            (
                "an update without fields",
                with("noop = ", "update_issue = { max = 1 }\nnoop = "),
                "explicit nonempty fields",
            ),
            (
                "an issue's labels as an update field",
                with(
                    "noop = ",
                    "update_issue = { max = 1, fields = [\"labels\"] }\nnoop = ",
                ),
                "unsupported field \"labels\"",
            ),
            (
                "a pull request's base as an update field",
                with(
                    "noop = ",
                    "update_pull_request = { max = 1, fields = [\"base\"] }\nnoop = ",
                ),
                "unsupported field \"base\"",
            ),
            (
                "fields for mark-ready",
                with(
                    "noop = ",
                    "mark_pull_request_as_ready_for_review = { max = 1, fields = [\"draft\"] }\nnoop = ",
                ),
                "fields are supported only",
            ),
            (
                "an unknown memory key",
                format!("{BOUNDS}\n[memory]\nbranch = \"x\"\n"),
                "unknown field `branch`",
            ),
            (
                "no memory files",
                format!("{BOUNDS}\n[memory]\nmax_files = 0\n"),
                "memory.max_files must be from 1 to 100",
            ),
            (
                "too many memory files",
                format!("{BOUNDS}\n[memory]\nmax_files = 101\n"),
                "memory.max_files must be from 1 to 100",
            ),
            (
                "empty memory files",
                format!("{BOUNDS}\n[memory]\nmax_file_bytes = 0\n"),
                "memory.max_file_bytes must be from 1 to 102400",
            ),
            (
                "a memory file too big",
                format!("{BOUNDS}\n[memory]\nmax_file_bytes = 102401\nmax_bytes = 200000\n"),
                "memory.max_file_bytes must be from 1 to 102400",
            ),
            (
                "a memory too big",
                format!("{BOUNDS}\n[memory]\nmax_bytes = 1048577\n"),
                "memory.max_bytes must be from max_file_bytes to 1048576",
            ),
            (
                "a memory smaller than one file",
                format!("{BOUNDS}\n[memory]\nmax_file_bytes = 2048\nmax_bytes = 1024\n"),
                "memory.max_bytes must be from max_file_bytes",
            ),
            (
                "no memory extensions",
                format!("{BOUNDS}\n[memory]\nextensions = []\n"),
                "memory.extensions lists no extension",
            ),
            (
                "a script as memory",
                format!("{BOUNDS}\n[memory]\nextensions = [\"md\", \"sh\"]\n"),
                "memory.extensions may only name md, txt, json, jsonl, csv, not \"sh\"",
            ),
            (
                "a dotted memory extension",
                format!("{BOUNDS}\n[memory]\nextensions = [\".md\"]\n"),
                "not \".md\"",
            ),
            (
                "an upper-case memory extension",
                format!("{BOUNDS}\n[memory]\nextensions = [\"MD\"]\n"),
                "not \"MD\"",
            ),
            (
                "a memory extension twice",
                format!("{BOUNDS}\n[memory]\nextensions = [\"md\", \"md\"]\n"),
                "memory.extensions names \"md\" twice",
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
        let memory = |memory: Memory| Policy {
            memory: Some(memory),
            ..good.clone()
        };
        let defaults: Memory = toml::from_str("").unwrap();
        let mut off_github = good.clone();
        off_github.forge = Forge::Forgejo;
        off_github.safe_outputs.others.insert(
            "link_sub_issue".to_owned(),
            OutputLimit {
                max: 1,
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
                "a GitHub-only type off GitHub",
                off_github,
                "\"link_sub_issue\" is GitHub-only, not for forge \"forgejo\"",
            ),
            (
                "another contract",
                Policy {
                    contract: CONTRACT + 1,
                    ..good.clone()
                },
                "safe-output contract",
            ),
            (
                "memory over its ceiling",
                memory(Memory {
                    max_files: 1000,
                    ..defaults.clone()
                }),
                "memory.max_files",
            ),
            (
                "memory of scripts",
                memory(Memory {
                    extensions: vec!["sh".into()],
                    ..defaults
                }),
                "memory.extensions",
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

    /// Bounds on FORGE allowing OUTPUT, with LIMIT as its table.
    fn forge_bounds(forge: &str, output: &str, limit: &str) -> Result<Bounds> {
        let bounds: Bounds = toml::from_str(&format!(
            r#"
forge = "{forge}"
hosts = ["forge.example"]
repos = ["owner/*"]
bases = ["main"]
max_outputs = 3
max_patch_bytes = 65536
max_patch_files = 10

[outputs]
{output} = {limit}
"#
        ))?;
        bounds.validate()?;
        Ok(bounds)
    }

    #[test]
    fn the_neutral_profile_by_forge() {
        const FORGES: [(&str, Forge); 3] = [
            ("github", Forge::Github),
            ("forgejo", Forge::Forgejo),
            ("gitlab", Forge::Gitlab),
        ];
        // Each type with the least table its bounds may have, and whether
        // the profile holds it off GitHub. Every type a bounds file may
        // list is here, so a new one must be placed.
        let cases: &[(&str, &str, bool)] = &[
            (CREATE_PULL_REQUEST, "{ max = 1 }", true),
            (
                PUSH_TO_PULL_REQUEST_BRANCH,
                r#"{ max = 1, branches = ["agent-*"] }"#,
                true,
            ),
            ("add_comment", "{ max = 1 }", true),
            ("create_issue", "{ max = 1 }", true),
            ("close_issue", "{ max = 1 }", true),
            ("close_pull_request", "{ max = 1 }", true),
            ("add_labels", "{ max = 1, allowed = [] }", true),
            ("remove_labels", "{ max = 1, allowed = [] }", true),
            (CREATE_REVIEW_COMMENT, "{ max = 1 }", true),
            ("noop", "{ max = 1 }", true),
            ("missing_tool", "{ max = 1 }", true),
            ("missing_data", "{ max = 1 }", true),
            // GitHub-only: no other forge has the object.
            (
                "create_discussion",
                r#"{ max = 1, category = "General" }"#,
                false,
            ),
            (
                UPDATE_PROJECT,
                r#"{ max = 1, projects = ["https://github.com/orgs/o/projects/1"], fields = ["Status"] }"#,
                false,
            ),
            (
                HIDE_COMMENT,
                r#"{ max = 1, allowed_reasons = ["SPAM"] }"#,
                false,
            ),
            ("link_sub_issue", "{ max = 1 }", false),
            ("create_check_run", r#"{ max = 1, name = "agent" }"#, false),
            // Not mapped onto another forge yet, so held only on GitHub.
            (REPLY_TO_REVIEW_COMMENT, "{ max = 1 }", false),
            (RESOLVE_REVIEW_THREAD, "{ max = 1 }", false),
            ("update_issue", r#"{ max = 1, fields = ["title"] }"#, false),
            (
                "update_pull_request",
                r#"{ max = 1, fields = ["title"] }"#,
                false,
            ),
            (MARK_READY, "{ max = 1 }", false),
            (
                "add_reviewer",
                r#"{ max = 1, allowed = ["someone"] }"#,
                false,
            ),
            (
                "assign_to_user",
                r#"{ max = 1, allowed = ["someone"] }"#,
                false,
            ),
        ];
        let listed: Vec<&str> = cases.iter().map(|(output, ..)| *output).collect();
        assert_eq!(
            listed
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            OUTPUT_TYPES.iter().copied().collect(),
        );
        for (output, limit, neutral) in cases {
            assert_eq!(NEUTRAL_OUTPUTS.contains(output), *neutral, "{output}");
            for (name, forge) in FORGES {
                let held = forge == Forge::Github || *neutral;
                assert_eq!(forge.holds(output), held, "{output} on {name}");
                match forge_bounds(name, output, limit) {
                    Ok(_) => assert!(held, "{output} admitted on {name}"),
                    Err(err) => {
                        assert!(!held, "{output} on {name}: {err:#}");
                        assert!(
                            format!("{err:#}").contains("GitHub-only"),
                            "{output} on {name}: {err:#}"
                        );
                    }
                }
            }
        }

        // What a run off GitHub is admitted to carries its forge and
        // contract into policy.json, and loads again.
        let request = Request {
            repo: "owner/name",
            clone_url: "https://forge.example/owner/name",
            outputs: "add_comment,noop",
            ..request()
        };
        for (name, forge) in FORGES {
            let mut bounds = forge_bounds(name, "add_comment", "{ max = 2 }").unwrap();
            bounds.outputs.insert(
                "noop".into(),
                OutputLimit {
                    max: 1,
                    ..OutputLimit::default()
                },
            );
            let compiled = bounds.compile(&request).unwrap();
            assert_eq!((compiled.forge, compiled.contract), (forge, CONTRACT));
            let json = serde_json::to_value(&compiled).unwrap();
            assert_eq!(json["forge"], name);
            assert_eq!(json["contract"], CONTRACT);
            let loaded: Policy = serde_json::from_value(json).unwrap();
            loaded.validate().unwrap();
        }
        // A policy written before the profile reads as GitHub's.
        let mut json = serde_json::to_value(policy()).unwrap();
        let fields = json.as_object_mut().unwrap();
        fields.remove("forge");
        fields.remove("contract");
        let old: Policy = serde_json::from_value(json).unwrap();
        assert_eq!((old.forge, old.contract), (Forge::Github, 1));

        // Two bounds files agree on the forge or admit nothing.
        let on = |name| forge_bounds(name, "noop", "{ max = 1 }").unwrap();
        let noop = Request {
            outputs: "noop",
            ..request
        };
        let err = intersect(
            on("forgejo").compile(&noop).unwrap(),
            on("gitlab").compile(&noop).unwrap(),
        )
        .unwrap_err();
        assert!(err[0].contains("different forges"), "{err:?}");
    }

    #[test]
    fn target_fields_by_forge() {
        for (forge, field, refused) in [
            (Forge::Github, ITEM_NUMBER, false),
            (Forge::Forgejo, ITEM_NUMBER, false),
            (Forge::Gitlab, ITEM_NUMBER, true),
            (Forge::Gitlab, "issue_number", false),
            (Forge::Gitlab, "pull_request_number", false),
        ] {
            assert_eq!(forge.refuses_field(field), refused, "{field} on {forge:?}");
        }
    }
}
