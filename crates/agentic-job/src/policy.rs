//! `agentic-job policy`: check one run's request against the caller's
//! bounds and print `policy.json`. Step 4 of docs/plan.md.
//!
//! The request (which repository, which base, which outputs and how many)
//! comes from whoever started the run. The bounds are a file the caller
//! keeps in its own repository. A request outside them is refused here,
//! on a machine the agent never touches and before the agent's machine
//! starts, and what is within them becomes the run's [`Policy`]: the one
//! thing `run`, `collect` and `check` all read.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

use crate::exit::Exit;

mod context;
mod dispatch;
use dispatch::admission as dispatch_admission;

// The request vocabulary, the policy's contract, bounds parsing and the
// intersection of two bounds files' policies are the safe-outputs
// library's; reading the files, and admitting and compiling a request
// against bounds, stay here.
use safe_outputs::bounds::{RepoRule, dot_folders, host_name, intersect, protected_files, under};
pub use safe_outputs::bounds::{SecondaryPullRequest, Unprotected};
pub use safe_outputs::contract::*;
pub use safe_outputs::{
    CONTRACT, CREATE_PULL_REQUEST, CREATE_REVIEW_COMMENT, Forge, GH_AW_LINK_DOMAINS, HIDE_COMMENT,
    HIDE_REASONS, ITEM_NUMBER, KIND_TARGETS, MARK_READY, MISSING_DATA, NEUTRAL_OUTPUTS, NOOP,
    OUTPUT_TYPES, PUSH_TO_PULL_REQUEST_BRANCH, REPLY_TO_REVIEW_COMMENT, RESOLVE_REVIEW_THREAD,
    REVIEW_THREAD_OUTPUTS, link_domains,
};

/// The caller's bounds file (`--allow`), with the `[github.trigger]` table
/// that event admission (`agentic-job event`) reads.
pub type Bounds = safe_outputs::bounds::Bounds<crate::event::Trigger>;

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

/// What a run may ask for in a repository the bounds admit only for a
/// push to their `own_author`'s pull request: that push, and the outputs
/// that write nothing to the forge.
const OWN_PULL_REQUEST_OUTPUTS: &[&str] = &[
    PUSH_TO_PULL_REQUEST_BRANCH,
    NOOP,
    "missing_tool",
    MISSING_DATA,
];

/// The forge whose private-repository rules a bounds file's `push_repo`
/// leaves as they are (docs/private-repositories.md).
const GITHUB_HOST: &str = "github.com";

/// `--outputs all`: every type the bounds list.
const ALL_OUTPUTS: &str = "all";

/// `--max-outputs max`: as many as the bounds allow.
const MAX_OUTPUTS: &str = "max";

/// The request's values may start with a dash: they are a stranger's text,
/// and one that does is refused with a reason like any other.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Caller-owned external-fetch receipt; never the external run's policy/config
    #[arg(long, value_name = "FILE")]
    pub external_receipt: Option<PathBuf>,
    /// Trusted admission's advisory target (never producer supplied)
    #[arg(long, requires = "advisory_head")]
    pub advisory_item: Option<u64>,
    /// Exact head resolved by trusted review admission
    #[arg(long, requires = "advisory_item")]
    pub advisory_head: Option<String>,
    /// Resolved context repositories as a JSON array (empty by default)
    #[arg(long, default_value = "[]", allow_hyphen_values = true)]
    pub context: String,
    /// A dispatcher's context request, `[{"repo": "OWNER/REPO", "ref": "REF"}]`
    /// (`ref` optional), resolved through the forge API at `GITHUB_API_URL`
    /// with `GH_TOKEN`; only a public repository is admitted
    #[arg(long, conflicts_with = "context", allow_hyphen_values = true)]
    pub context_request: Option<String>,
    /// The caller's bounds file
    #[arg(long, value_name = "FILE")]
    pub allow: PathBuf,
    /// Optional organization bounds; both files must admit the request
    #[arg(long, value_name = "FILE")]
    pub org_allow: Option<PathBuf>,
    /// The repository the agent works on: OWNER/NAME, or GROUP/SUBGROUP/NAME on GitLab
    #[arg(long, value_name = "REPO", allow_hyphen_values = true)]
    pub repo: String,
    /// Where `run` clones that repository from: https://HOST/REPO,
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
    /// The login that opened that pull request, as the forge says: the
    /// bounds' `own_author` admits it in a repository `repos` does not
    #[arg(
        long,
        value_name = "LOGIN",
        allow_hyphen_values = true,
        requires = "pull_request"
    )]
    pub pull_author: Option<String>,
    /// Where apply applies the outputs (a repository path); a push is refused
    /// unless it is `--repo`, where the pull request is
    #[arg(long, value_name = "REPO", allow_hyphen_values = true)]
    pub output_repo: Option<String>,
    /// The repository the run's item (its issue and status comment) is
    /// in, where that is not the output repository; it must be within
    /// `repos`, as `--repo` must
    #[arg(long, value_name = "REPO", allow_hyphen_values = true)]
    pub item_repo: Option<String>,
    /// The repository could not be confirmed public: refused unless every
    /// bounds file sets `private = true`
    #[arg(long)]
    pub private: bool,
}

/// Reading a policy or bounds file, which the library leaves to its
/// caller: the file is read whole, then parsed and validated.
pub trait Load: Sized {
    fn load(path: &Path) -> Result<Self>;
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
    /// For a push: who opened the pull request, as the forge says.
    pub pull_author: Option<&'a str>,
    /// Where apply applies the outputs; a push must name the run's own
    /// repository here.
    pub output_repo: Option<&'a str>,
    /// Where the run's item is, when not in the output repository.
    pub item_repo: Option<&'a str>,
    /// Whether the repository is not public.
    pub private: bool,
}

impl Load for Policy {
    /// Reads the `policy.json` that `policy` printed.
    fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the policy {}", path.display()))?;
        let policy: Self = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a policy.json", path.display()))?;
        policy
            .validate()
            .with_context(|| format!("{} is not a policy `policy` wrote", path.display()))?;
        Ok(policy)
    }
}

impl Load for Bounds {
    fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the bounds file {}", path.display()))?;
        let bounds: Self = toml::from_str(&text)
            .with_context(|| format!("parsing the bounds file {}", path.display()))?;
        bounds
            .validate()
            .with_context(|| format!("in the bounds file {}", path.display()))?;
        Ok(bounds)
    }
}

/// Compiling one run's request, as the command line gives it, within a
/// bounds file: the request is agentic-job's, so this stays here.
pub trait Compile {
    fn compile(&self, request: &Request<'_>) -> Result<Policy, Vec<String>> {
        self.compile_with(request, &mut context::forge())
    }

    fn compile_with(
        &self,
        request: &Request<'_>,
        read: &mut dyn FnMut(&str) -> Result<serde_json::Value>,
    ) -> Result<Policy, Vec<String>>;
}

impl Compile for Bounds {
    /// The policy of a run, or every reason its request is refused.
    ///
    /// The request's strings are untrusted. Each is matched against a
    /// pattern before it is used, the messages quote them escaped, and
    /// the policy is serialized by serde: a quote or a newline in one can
    /// neither add a key to `policy.json` nor a line to the log.
    fn compile_with(
        &self,
        request: &Request<'_>,
        read: &mut dyn FnMut(&str) -> Result<serde_json::Value>,
    ) -> Result<Policy, Vec<String>> {
        let Request {
            repo,
            clone_url,
            base,
            kind,
            outputs,
            max_outputs,
            job_token,
            pull_request,
            pull_author,
            output_repo,
            item_repo,
            private,
        } = *request;
        let mut errors = Vec::new();
        let limits = self.outputs();
        let push_repo = self.push_repo();

        let repo_ok = self.forge().is_repo(repo) && !dotted(repo);
        if let Some(output_repo) = output_repo
            && (!self.forge().is_repo(output_repo) || dotted(output_repo))
        {
            errors.push(format!("invalid output repository {output_repo:?}"));
        }
        // Whether `repos` admits it is checked below, where the outputs
        // asked for say whether `own_author` may.
        let listed = repo_ok
            && admits_repo(&self.repos, repo, read).unwrap_or_else(|error| {
                errors.push(error.to_string());
                false
            });
        // Checked against the repository only if that is a name at all.
        if repo_ok && let Some(problem) = self.clone_url_problem(clone_url, repo) {
            errors.push(problem);
        }
        // Its issue's text joins the task and its status comment is posted
        // with the apply credential: a repository the bounds let runs work
        // on, not any one a caller names.
        if let Some(item_repo) = item_repo
            && (!self.forge().is_repo(item_repo)
                || dotted(item_repo)
                || !admits_repo(&self.repos, item_repo, read).unwrap_or_else(|error| {
                    errors.push(error.to_string());
                    false
                }))
        {
            errors.push(format!(
                "item repo {item_repo:?} is not within the bounds ({})",
                self.repos
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
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
                limits
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
        // The operator's rule that the bot may always work on a pull
        // request it opened (#3162): a push to one by the login the bounds
        // name is admitted outside `repos`. That admits the push and the
        // outputs that write nothing, and no comment, label or close in a
        // repository the bounds never listed.
        let own_author = limits
            .get(PUSH_TO_PULL_REQUEST_BRANCH)
            .and_then(|limit| limit.own_author.as_deref())
            .filter(|own| {
                types.contains(&PUSH_TO_PULL_REQUEST_BRANCH)
                    && pull_author.is_some_and(|author| author.eq_ignore_ascii_case(own))
            });
        // An opt-in organization policy admits only its live repositories and
        // exact exceptions: author admission must not recover a live refusal.
        let by_author = repo_ok
            && !listed
            && own_author.is_some()
            && !self
                .repos
                .iter()
                .any(|rule| matches!(rule, RepoRule::Organization(_)));
        if !listed && !by_author {
            errors.push(format!(
                "repo {repo:?} is not within the bounds ({})",
                self.repos
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if by_author {
            errors.extend(
                types
                    .iter()
                    .filter(|output| !OWN_PULL_REQUEST_OUTPUTS.contains(output))
                    .map(|output| {
                        format!(
                            "output type {output:?} is not for {repo:?}, which the bounds admit \
                             only for a push to their own_author's pull request"
                        )
                    }),
            );
        }
        let known = || {
            limits
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        };
        errors.extend(
            types
                .iter()
                .filter(|output| !limits.contains_key(**output))
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
            // bounds name is the exception: Forgejo's and GitLab's apply
            // push only there, and only to a private fork for a private run,
            // and the run's evidence stays on the same forge.
            let named_fork =
                carrier == CREATE_PULL_REQUEST && push_repo.is_some() && !on_github(clone_url);
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
        // owner as the target's own branch. GitLab subgroups inherit CI
        // variables from their top-level group, so that group is excluded.
        // A pull request's branch and a
        // push to one both go to that fork.
        let to_fork =
            types.contains(&CREATE_PULL_REQUEST) || types.contains(&PUSH_TO_PULL_REQUEST_BRANCH);
        if let Some(push_repo) = push_repo
            && to_fork
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
        let push_limit = limits.get(PUSH_TO_PULL_REQUEST_BRANCH);
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
        // Only beside the run's own pull request, which already needs a
        // user's token, a public repository and a branch run; and in a
        // repository the run's own patch cannot be mistaken for.
        let secondary = self
            .secondary_pull_request()
            .filter(|_| types.contains(&CREATE_PULL_REQUEST));
        if let Some(secondary) = secondary {
            for (what, name) in [("works on", Some(repo)), ("applies to", output_repo)] {
                if let Some(name) = name.filter(|name| name.eq_ignore_ascii_case(&secondary.repo)) {
                    errors.push(format!(
                        "secondary_pull_request.repo {:?} is the repository the run {what}, \
                         {name:?}: a second pull request there is not a secondary destination",
                        secondary.repo
                    ));
                } else if let Some(name) = name.filter(|name| {
                    patch_named_as_in(&secondary.repo, &secondary.branch_prefix, name)
                }) {
                    errors.push(format!(
                        "secondary_pull_request's patch would have the name of one for the \
                         repository the run {what}, {name:?}: choose another branch_prefix"
                    ));
                }
            }
            if !(repo_ok && clone_url_host(clone_url).is_some()) {
                errors.push(format!(
                    "no host to clone secondary_pull_request.repo {:?} from",
                    secondary.repo
                ));
            }
            if repo.rsplit('/').next() == Some(SECONDARY_DIR) {
                errors.push("target name conflicts with the secondary directory".to_owned());
            }
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
            max: limits.get(output).map_or(0, |bound| bound.max).min(max),
            allowed: limits.get(output).and_then(|bound| bound.allowed.clone()),
            blocked: limits
                .get(output)
                .map_or_else(Vec::new, |bound| bound.blocked.clone()),
            projects: limits
                .get(output)
                .map_or_else(Vec::new, |bound| bound.projects.clone()),
            fields: limits
                .get(output)
                .map_or_else(Vec::new, |bound| bound.fields.clone()),
            branches: Vec::new(),
            replacement_max_commits: 0,
            replacement_max_files: 0,
            own_author: None,
            name: limits.get(output).and_then(|bound| bound.name.clone()),
            category: limits.get(output).and_then(|bound| bound.category.clone()),
            allowed_reasons: limits
                .get(output)
                .map_or_else(Vec::new, |bound| bound.allowed_reasons.clone()),
            ready_when_complete: false,
            comment_on_duplicate: limits
                .get(output)
                .is_some_and(|bound| bound.comment_on_duplicate),
        };
        let ready = |output: &str| {
            limits
                .get(output)
                .is_some_and(|bound| bound.ready_when_complete)
        };
        let safe_outputs = SafeOutputs {
            upstream_pull_request_base: self
                .github
                .as_ref()
                .is_some_and(|github| github.outputs.upstream_pull_request_base),
            own_branch_repos: Some(self.own_branch_repos())
                .filter(|patterns| !patterns.is_empty())
                .map(|patterns| vec![patterns.to_vec()])
                .unwrap_or_default(),
            create_pull_request: types.contains(&CREATE_PULL_REQUEST).then(|| PullRequest {
                max: limit(CREATE_PULL_REQUEST).max,
                protected_files: protected_files(&self.unprotected_files, repo),
                protect_top_level_dot_folders: true,
                unprotected_dot_folders: dot_folders(&self.unprotected_files, repo),
                protected_paths: self.protected.clone(),
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
                replacement_max_commits: limits
                    .get(PUSH_TO_PULL_REQUEST_BRANCH)
                    .map_or(0, |bound| bound.replacement_max_commits),
                replacement_max_files: limits
                    .get(PUSH_TO_PULL_REQUEST_BRANCH)
                    .map_or(0, |bound| bound.replacement_max_files),
                replacement_base: None,
                author: own_author.filter(|_| by_author).map(str::to_owned),
                ready_when_complete: ready(PUSH_TO_PULL_REQUEST_BRANCH),
                protected_files: protected_files(&self.unprotected_files, repo),
                protect_top_level_dot_folders: true,
                unprotected_dot_folders: dot_folders(&self.unprotected_files, repo),
                protected_paths: self.protected.clone(),
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
            external: None,
            advisory: None,
            allow_http: self.allow_http.clone(),
            context: Vec::new(),
            repo: repo.to_owned(),
            clone_url: clone_url.to_owned(),
            base: base.to_owned(),
            kind,
            max_outputs: max,
            max_patch_bytes: self.max_patch_bytes,
            safe_outputs,
            commit_author: self.commit_author.clone(),
            push_repo: push_repo.filter(|_| to_fork).map(str::to_owned),
            private,
            allowed_domains: link_domains().to_vec(),
            memory: self.memory().cloned(),
            test_evidence: self.test_evidence().cloned(),
            forge: self.forge(),
            contract: CONTRACT,
            secondary_pull_request: secondary.and_then(|secondary| {
                clone_url_host(clone_url).map(|host| secondary.compile(host, &self.protected))
            }),
            native_handlers: self
                .native_handlers
                .iter()
                .filter(|output| types.contains(&output.as_str()))
                .cloned()
                .collect(),
        })
    }
}

/// Whether a clone URL is on GitHub, whose apply is gh-aw's and reads no
/// `push_repo`.
fn on_github(clone_url: &str) -> bool {
    let authority = clone_url
        .split_once("://")
        .map_or(clone_url, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or_default();
    under(&host_name(authority), GITHUB_HOST)
}

/// The host of a clone URL `https://HOST/OWNER/NAME`, whose repository
/// `clone_url_problem` has checked is within the bounds.
fn clone_url_host(url: &str) -> Option<&str> {
    url.strip_prefix("https://")
        .and_then(|rest| rest.split_once('/'))
        .map(|(host, _)| host)
}

/// Whether OUTPUT hands back a patch.
fn carries_patch(output: &str) -> bool {
    matches!(output, CREATE_PULL_REQUEST | PUSH_TO_PULL_REQUEST_BRANCH)
}

/// A name prefix alone must not admit a fork, archived repository or transfer.
/// Exact entries are explicit exceptions. Validation forbids mixing org rules
/// with legacy globs, which would otherwise bypass the live restrictions.
fn admits_repo(
    rules: &[RepoRule],
    repo: &str,
    read: &mut dyn FnMut(&str) -> Result<serde_json::Value>,
) -> Result<bool> {
    if rules.iter().any(|rule| {
        matches!(rule, RepoRule::Pattern(pattern)
        if glob(pattern).is_ok_and(|regex| regex.is_match(repo)))
    }) {
        return Ok(true);
    }
    let Some((owner, _)) = repo.split_once('/') else {
        return Ok(false);
    };
    if !rules.iter().any(|rule| {
        matches!(rule, RepoRule::Organization(rule)
        if rule.org.eq_ignore_ascii_case(owner))
    }) {
        return Ok(false);
    }
    let live = read(&format!("repos/{repo}"))
        .with_context(|| format!("cannot confirm organization repository {repo:?}"))?;
    ensure!(
        live["full_name"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(repo))
            && live["owner"]["login"]
                .as_str()
                .is_some_and(|login| login.eq_ignore_ascii_case(owner))
            && live["owner"]["type"] == "Organization"
            && live["archived"] == false,
        "repository {repo:?} requires matching full_name, organization owner and archived = false"
    );
    let mut problems = Vec::new();
    // Read properties at most once, even when several rules name this org.
    let mut properties = None;
    for rule in rules.iter().filter_map(|rule| match rule {
        RepoRule::Organization(rule) if rule.org.eq_ignore_ascii_case(owner) => Some(rule),
        _ => None,
    }) {
        if live["fork"] != rule.forks {
            problems.push(format!("requires fork = {}", rule.forks));
            continue;
        }
        if rule.forks
            && !live["parent"]["full_name"]
                .as_str()
                .is_some_and(|name| safe_outputs::contract::REPO_RE.is_match(name) && !dotted(name))
        {
            problems.push("requires known parent.full_name".to_owned());
            continue;
        }
        let missing_topics: Vec<_> = rule
            .topics
            .iter()
            .filter(|topic| {
                !live["topics"].as_array().is_some_and(|topics| {
                    topics
                        .iter()
                        .any(|value| value.as_str() == Some(topic.as_str()))
                })
            })
            .collect();
        if !missing_topics.is_empty() {
            problems.push(format!("requires topics {missing_topics:?}"));
            continue;
        }
        if !rule.properties.is_empty() && properties.is_none() {
            let values = read(&format!("repos/{repo}/properties/values"))
                .with_context(|| format!("cannot confirm repository {repo:?} custom properties"))?;
            ensure!(
                values.is_array(),
                "repository {repo:?} custom properties response must be an array"
            );
            properties = Some(values);
        }
        let missing_properties: Vec<_> = rule
            .properties
            .iter()
            .filter(|(key, value)| {
                !properties
                    .as_ref()
                    .and_then(|values| values.as_array())
                    .is_some_and(|values| {
                        values.iter().any(|entry| {
                            entry["property_name"].as_str() == Some(key.as_str())
                                && entry["value"].as_str() == Some(value.as_str())
                        })
                    })
            })
            .collect();
        if missing_properties.is_empty() {
            return Ok(true);
        }
        problems.push(format!("requires custom properties {missing_properties:?}"));
    }
    bail!(
        "repository {repo:?} does not match organization rules: {}",
        problems.join("; ")
    )
}

pub fn run(args: &Args) -> Result<Exit> {
    let bounds = Bounds::load(&args.allow)?;
    let org_bounds = args.org_allow.as_deref().map(Bounds::load).transpose()?;
    dispatch_admission(bounds.dedupe || org_bounds.as_ref().is_some_and(|b| b.dedupe))?;
    // A dispatcher must not turn context into a way to read outside the caller's
    // authority. Both bounds files admit every URL and repository, independently.
    let context: Vec<ContextRepo> = match &args.context_request {
        Some(request) => context::resolve(request, &mut context::forge())?,
        None => {
            ensure!(
                args.context.len() <= context::MAX_REQUEST,
                "context input exceeds 16 KiB"
            );
            serde_json::from_str(&args.context).context("parsing context")?
        }
    };
    check_context(&context)?;
    ensure!(
        context.is_empty() || args.repo.rsplit('/').next() != Some("context"),
        "target name conflicts with the context directory"
    );
    for item in &context {
        for bound in std::iter::once(&bounds).chain(org_bounds.iter()) {
            ensure!(
                item.public || admits_repo(&bound.repos, &item.repo, &mut context::forge())?,
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
        pull_author: args.pull_author.as_deref(),
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
            if let Some(path) = &args.external_receipt {
                let receipt = crate::external::Receipt::load(path)?;
                receipt.record.caller_env()?;
                receipt.record.policy(&policy)?;
                ensure!(
                    args.output_repo
                        .as_deref()
                        .is_none_or(|repo| repo == policy.repo),
                    "external output repository must be the trusted target"
                );
                policy.external = Some(ExternalRun {
                    caller_repository: receipt.record.caller_repository,
                    caller_run_id: receipt.record.caller_run_id,
                    caller_attempt: receipt.record.caller_attempt,
                    repository: receipt.record.repository,
                    run_id: receipt.run_id,
                    base_commit: receipt.record.base_commit,
                    raw_digest: receipt.raw.digest,
                });
                // External mode can only narrow the caller's publication policy.
                if let Some(pull) = &mut policy.safe_outputs.create_pull_request {
                    pull.draft = true;
                    pull.ready_when_complete = false;
                }
                policy.validate()?;
            }
            if policy.clone_url.starts_with(PLAIN_HTTP_PREFIX) {
                eprintln!(
                    "warning: {} is cloned over plain HTTP, as the bounds allow for its host",
                    policy.repo
                );
            }
            policy.context = context;
            if let Some(pull) = args.advisory_item {
                ensure!(
                    args.output_repo
                        .as_deref()
                        .is_none_or(|repo| repo == policy.repo)
                        && args.item_repo.is_none(),
                    "advisory cannot reroute its repository"
                );
                policy.native_handlers = vec!["add_comment".into()];
                policy.advisory = Some(Advisory {
                    repo: policy.repo.clone(),
                    pull,
                    base: policy.base.clone(),
                    head: args.advisory_head.clone().context("advisory head")?,
                });
                policy.validate()?;
            }
            let json = serde_json::to_string_pretty(&policy).context("writing the policy")?;
            println!("{json}");
            Ok(Exit::Success)
        }
        Err(errors) => {
            // A refusal quotes the request, a stranger's text: each stays
            // one line of the log that no runner reads as a command.
            for error in errors {
                eprintln!("error: {}", crate::run::enter::one_line(&error));
            }
            Ok(Exit::Failure)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use safe_outputs::bounds::{NeutralBounds, NeutralOutputs};

    /// The old tree's allowlist, as a bounds file.
    pub(crate) const BOUNDS: &str = r#"
hosts = ["github.com"]
repos = ["bootc-dev/*", "composefs/*", "cgwalters-bot/*", "cgwalters-forge/*"]
bases = ["main", "master", "bot/**"]
max_outputs = 5
max_patch_bytes = 8388608
max_patch_files = 100

[unprotected_files]
repos = ["cgwalters-bot/homegit", "cgwalters-forge/review"]
files = ["CONTRIBUTING.md", "AGENTS.md"]

[github.outputs]
create_pull_request = { max = 1 }
add_comment = { max = 3 }
noop = { max = 1 }
missing_tool = { max = 3 }
missing_data = { max = 3 }
"#;

    const REPO: &str = "bootc-dev/bootc";

    pub(crate) fn bounds() -> Bounds {
        let bounds: Bounds = toml::from_str(BOUNDS).unwrap();
        bounds.validate().unwrap();
        bounds
    }

    #[test]
    fn organization_rules_check_live_repositories() {
        use serde_json::json;

        let bounds: Bounds = toml::from_str(&BOUNDS.replace(
            "repos = [\"bootc-dev/*\", \"composefs/*\", \"cgwalters-bot/*\", \"cgwalters-forge/*\"]",
            "repos = [{org = \"bootc-dev\", forks = false}]",
        )).unwrap();
        bounds.validate().unwrap();
        let live = json!({"full_name": REPO, "owner": {"login": "bootc-dev", "type": "Organization"},
            "fork": false, "archived": false});
        let mut push = push_bounds();
        push.repos = bounds.repos.clone();
        push.github
            .as_mut()
            .unwrap()
            .outputs
            .types
            .get_mut(PUSH_TO_PULL_REQUEST_BRANCH)
            .unwrap()
            .own_author = Some("applying-bot".into());
        push.validate().unwrap();
        let push_request = Request {
            pull_author: Some("applying-bot"),
            ..push_request()
        };
        for (pointer, value, allowed) in [
            ("/fork", json!(false), true),
            ("/fork", json!(true), false),
            ("/archived", json!(true), false),
            ("/owner/login", json!("another"), false),
            ("/owner/type", json!("User"), false),
            ("/full_name", json!("another/bootc"), false),
            ("/fork", json!(null), false),
            ("/archived", json!(null), false),
            ("/owner/login", json!(null), false),
            ("/owner/login", json!("BOOTC-DEV"), true),
        ] {
            let mut answer = live.clone();
            *answer.pointer_mut(pointer).unwrap() = value;
            let mut calls = 0;
            let result = bounds.compile_with(&request(), &mut |path| {
                assert_eq!(path, "repos/bootc-dev/bootc");
                calls += 1;
                Ok(answer.clone())
            });
            assert_eq!(result.is_ok(), allowed, "{pointer}: {answer}");
            assert_eq!(calls, 1);
            assert_eq!(
                push.compile_with(&push_request, &mut |_| Ok(answer.clone()))
                    .is_ok(),
                allowed,
                "own_author must not bypass {pointer}: {answer}"
            );
        }
        assert!(
            bounds
                .compile_with(&request(), &mut |_| anyhow::bail!("unavailable"))
                .is_err()
        );
        let other = Request {
            repo: "another/bootc",
            clone_url: "https://github.com/another/bootc",
            ..request()
        };
        assert!(
            bounds
                .compile_with(&other, &mut |_| panic!("not this org"))
                .is_err()
        );
        let item = Request {
            item_repo: Some("bootc-dev/item"),
            ..request()
        };
        assert!(
            bounds
                .compile_with(&item, &mut |path| {
                    let mut answer = live.clone();
                    if path == "repos/bootc-dev/item" {
                        answer["full_name"] = json!("bootc-dev/item");
                        answer["fork"] = json!(true);
                    }
                    Ok(answer)
                })
                .is_err()
        );

        // Exact entries retain their existing authority, including exceptions
        // for forks, archived repositories and other owners, without an API read.
        let mut exact = bounds.clone();
        exact.repos.extend([REPO.into(), "another/bootc".into()]);
        for request in [request(), other] {
            assert!(
                exact
                    .compile_with(&request, &mut |_| panic!("exact entry"))
                    .is_ok()
            );
        }
        // Organization bounds must independently admit the repository.
        assert!(
            bounds
                .compile_with(&request(), &mut |_| Ok(live.clone()))
                .is_ok()
        );
        let mut org = bounds.clone();
        org.repos = vec!["another/repo".into()];
        assert!(
            org.compile_with(&request(), &mut |_| panic!("no rule"))
                .is_err()
        );
    }

    #[test]
    fn organization_forks_require_live_metadata() {
        use serde_json::json;

        let mut bounds = bounds();
        bounds.repos = toml::from_str::<toml::Table>(
            r#"repos = [{org = "example-org", forks = true, properties = { category = "mirror" }, topics = ["managed-fork"]}]"#,
        ).unwrap()["repos"].clone().try_into().unwrap();
        bounds.validate().unwrap();
        let request = Request {
            repo: "example-org/example",
            clone_url: "https://github.com/example-org/example",
            ..request()
        };
        let live = json!({"full_name": request.repo,
            "owner": {"login": "example-org", "type": "Organization"},
            "fork": true, "archived": false, "parent": {"full_name": "upstream/example"},
            "topics": ["managed-fork"]});
        let properties = json!([{"property_name": "category", "value": "mirror"}]);
        for (pointer, value, want) in [
            ("/fork", json!(true), None),
            ("/fork", json!(false), Some("fork = true")),
            ("/topics", json!([]), Some("managed-fork")),
            ("/topics", json!(null), Some("managed-fork")),
            ("/parent", json!(null), Some("parent.full_name")),
            (
                "/parent/full_name",
                json!("invalid"),
                Some("parent.full_name"),
            ),
            ("/archived", json!(true), Some("archived = false")),
            (
                "/owner/login",
                json!("other-org"),
                Some("organization owner"),
            ),
        ] {
            let mut answer = live.clone();
            *answer.pointer_mut(pointer).unwrap() = value;
            let result = bounds.compile_with(&request, &mut |path| match path {
                "repos/example-org/example" => Ok(answer.clone()),
                "repos/example-org/example/properties/values" => Ok(properties.clone()),
                _ => panic!("unexpected read: {path}"),
            });
            match want {
                Some(want) => assert!(result.unwrap_err().join(";").contains(want), "{pointer}"),
                None => {
                    let policy = result.unwrap();
                    let pull = policy.safe_outputs.create_pull_request.unwrap();
                    assert!(pull.draft);
                    assert!(!pull.ready_when_complete);
                    assert_eq!(policy.max_patch_bytes, bounds.max_patch_bytes);
                    assert!(
                        !policy
                            .safe_outputs
                            .others
                            .contains_key("merge_pull_request")
                    );
                }
            }
        }
        for answer in [
            json!([]),
            json!({}),
            json!([{"property_name": "category", "value": "first-party"}]),
        ] {
            let errors = bounds
                .compile_with(&request, &mut |path| {
                    Ok(if path.ends_with("/properties/values") {
                        answer.clone()
                    } else {
                        live.clone()
                    })
                })
                .unwrap_err();
            assert!(errors.join(";").contains("custom properties"));
        }
        for failed_path in [
            "repos/example-org/example",
            "repos/example-org/example/properties/values",
        ] {
            assert!(
                bounds
                    .compile_with(&request, &mut |path| {
                        if path == failed_path {
                            bail!("metadata unavailable");
                        }
                        Ok(live.clone())
                    })
                    .unwrap_err()
                    .join(";")
                    .contains("cannot confirm")
            );
        }
        // Each file admits independently: non-fork bounds do not admit this fork.
        let mut first_party = bounds.clone();
        if let RepoRule::Organization(rule) = &mut first_party.repos[0] {
            rule.forks = false;
        }
        assert!(
            first_party
                .compile_with(&request, &mut |_| Ok(live.clone()))
                .is_err()
        );
    }

    #[test]
    fn organization_rule_validation() {
        for (rule, valid) in [
            ("{org = \"bootc-dev\", forks = false}", true),
            ("{org = \"bootc-dev\", forks = true}", false),
            (
                "{org = \"example-org\", forks = true, properties = { category = \"mirror\" }, topics = [\"managed-fork\"]}",
                true,
            ),
            (
                "{org = \"example-org\", forks = true, topics = [\"managed-fork\"]}",
                false,
            ),
            (
                "{org = \"example-org\", forks = true, properties = { category = \"mirror\" }}",
                false,
            ),
            (
                "{org = \"example-org\", forks = true, properties = { category = \"\" }, topics = [\"managed-fork\"]}",
                false,
            ),
            ("{org = \"bootc-dev\"}", false),
            (
                "{org = \"bootc-dev\", forks = false, archived = true}",
                false,
            ),
            ("{org = \"*\", forks = false}", false),
            ("{org = \"a/b\", forks = false}", false),
            ("{org = \".hidden\", forks = false}", false),
            ("{org = \"\", forks = false}", false),
        ] {
            let text = BOUNDS.replacen(
                "repos = [\"bootc-dev/*\", \"composefs/*\", \"cgwalters-bot/*\", \"cgwalters-forge/*\"]",
                &format!("repos = [{rule}]"), 1,
            );
            let result = toml::from_str::<Bounds>(&text)
                .map_err(anyhow::Error::from)
                .and_then(|bounds| bounds.validate());
            assert_eq!(result.is_ok(), valid, "{rule}: {result:?}");
            if valid {
                for pattern in ["bootc-dev/*", "*/*", "another/*", "bootc-dev/**"] {
                    let mixed = text.replacen(
                        &format!("repos = [{rule}]"),
                        &format!("repos = [{rule}, {pattern:?}]"),
                        1,
                    );
                    assert!(
                        toml::from_str::<Bounds>(&mixed)
                            .unwrap()
                            .validate()
                            .is_err(),
                        "{pattern}"
                    );
                }
                let other_host =
                    text.replace("hosts = [\"github.com\"]", "hosts = [\"example.com\"]");
                assert!(
                    toml::from_str::<Bounds>(&other_host)
                        .unwrap()
                        .validate()
                        .is_err()
                );
            }
        }
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
            pull_author: None,
            output_repo: None,
            item_repo: None,
            private: false,
        }
    }

    #[test]
    fn repository_paths_follow_the_bounds_forge() {
        for forge in [Forge::Github, Forge::Forgejo, Forge::Gitlab] {
            for (repo, fork, shape) in [
                ("example/project", "bot/project", true),
                ("example/team/project", "example/forks/project", false),
                (
                    "example/team/project",
                    "other/forks/project",
                    forge == Forge::Gitlab,
                ),
                ("example/team/project", "EXAMPLE/project", false),
                ("example/team/project", "example/team/deeper/project", false),
                ("example/team/project", "example/team/fork", false),
                ("example//project", "bot/project", false),
                ("example/../project", "bot/project", false),
                ("example/./project", "bot/project", false),
                ("example/project/", "bot/project", false),
                ("example/pro ject", "bot/project", false),
            ] {
                let mut bounds = if forge == Forge::Github {
                    bounds()
                } else {
                    on_forge(bounds(), forge, fork)
                };
                bounds.hosts = vec!["forge.example".into()];
                bounds.repos = vec![RepoRule::Pattern(repo.into())];
                let url = format!("https://forge.example/{repo}");
                let request = Request {
                    repo,
                    clone_url: &url,
                    output_repo: Some(repo),
                    item_repo: Some(repo),
                    ..request()
                };
                let result = bounds
                    .validate()
                    .map_err(|e| vec![e.to_string()])
                    .and_then(|_| bounds.compile(&request));
                assert_eq!(result.is_ok(), shape, "{forge:?} {repo}: {result:?}");
                if let Ok(policy) = result {
                    policy.validate().unwrap();
                }
            }
        }
    }

    /// The policy of the request the tests of `check` use.
    pub(crate) fn policy() -> Policy {
        bounds().compile(&request()).unwrap()
    }

    /// The safe-outputs library's tests check against these policies, as
    /// files: they are what `policy` compiles, less the domain list, and
    /// a push to a fork's is the push policy on Forgejo with its `push_repo`.
    #[test]
    fn library_fixtures_are_what_policy_compiles() {
        let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../safe-outputs/tests/data");
        for (file, push_repo, compiled) in [
            ("policy.json", None, policy()),
            ("push-policy.json", None, push_policy()),
            (
                "push-policy.json",
                Some("bot/bootc"),
                push_policy_to("bot/bootc"),
            ),
        ] {
            let text = std::fs::read_to_string(data.join(file)).unwrap();
            let mut fixture: Policy = serde_json::from_str(&text).unwrap();
            fixture.allowed_domains = link_domains().to_vec();
            fixture.push_repo = push_repo.map(str::to_owned);
            if push_repo.is_some() {
                fixture.forge = Forge::Forgejo;
            }
            assert_eq!(fixture, compiled, "{file} {push_repo:?}");
        }
    }

    const SECONDARY: &str = r#"
[github.secondary_pull_request]
repo = "cgwalters-forge/misctool"
base = "main"
branch_prefix = "agentic-job/"
max = 1
max_patch_bytes = 65536
max_patch_files = 10
"#;

    /// [`BOUNDS`] with [`SECONDARY`], `from` replaced by `to` in the
    /// latter, parsed but not validated.
    fn secondary_bounds(from: &str, to: &str) -> Result<Bounds, toml::de::Error> {
        toml::from_str(&format!("{BOUNDS}{}", SECONDARY.replacen(from, to, 1)))
    }

    /// [`BOUNDS`] with [`SECONDARY`], validated.
    fn configured() -> Bounds {
        let configured = secondary_bounds("", "").unwrap();
        configured.validate().unwrap();
        configured
    }

    #[test]
    fn secondary_pull_request_bounds_are_explicit() {
        assert!(policy().secondary_pull_request.is_none());
        let configured = configured();
        let secondary = configured.secondary_pull_request().unwrap();
        // Nothing inherited from the primary output's exemptions.
        assert!(secondary.unprotected_files.repos.is_empty());
        assert!(secondary.unprotected_files.files.is_empty());
        assert!(secondary.unprotected_files.dot_folders.is_empty());
        // Unreadable: a list of destinations, a missing field (no
        // defaults), an unknown key.
        for (from, to) in [
            (
                "[github.secondary_pull_request]",
                "[[github.secondary_pull_request]]",
            ),
            ("repo = \"cgwalters-forge/misctool\"\n", ""),
            ("base = \"main\"\n", ""),
            ("branch_prefix = \"agentic-job/\"\n", ""),
            ("max = 1\n", ""),
            ("max_patch_bytes = 65536\n", ""),
            ("max_patch_files = 10\n", ""),
            ("max = 1\n", "max = 1\nunknown = true\n"),
        ] {
            assert!(secondary_bounds(from, to).is_err(), "{from:?} -> {to:?}");
        }
        // Readable, and refused or accepted by validation.
        let unprotected = |repo: &str, folder: &str| {
            format!(
                "max_patch_files = 10\n[github.secondary_pull_request.unprotected_files]\n\
                 repos = [{repo:?}]\nfiles = [\"AGENTS.md\"]\ndot_folders = [{folder:?}]\n"
            )
        };
        for (from, to, accepted) in [
            ("main", "release/1.0", true),
            ("agentic-job/", "bot/agentic-job/", true),
            ("max_patch_bytes = 65536", "max_patch_bytes = 1024", true),
            ("max_patch_files = 10", "max_patch_files = 1", true),
            ("cgwalters-forge/misctool", "cgwalters-forge/*", false),
            ("cgwalters-forge/misctool", "cgwalters-forge/**", false),
            ("cgwalters-forge/misctool", "https://github.com/a/b", false),
            ("cgwalters-forge/misctool", "a/../b", false),
            ("cgwalters-forge/misctool", "owner", false),
            ("cgwalters-forge/misctool", "-owner/repo", false),
            ("cgwalters-forge/misctool", "owner/.repo", false),
            ("cgwalters-forge/misctool", "owner/..", false),
            ("main", "", false),
            ("main", "release/*", false),
            ("main", "main:other", false),
            ("main", "main..other", false),
            ("main", "main--other", false),
            ("main", "refs//main", false),
            ("main", "release/.hidden", false),
            ("main", "topic.lock/main", false),
            ("main", "-main", false),
            ("agentic-job/", "", false),
            ("agentic-job/", "agentic-job", false),
            ("agentic-job/", "/", false),
            ("agentic-job/", "../", false),
            ("agentic-job/", "a--b/", false),
            ("agentic-job/", "agentic-job//", false),
            ("agentic-job/", ".agentic-job/", false),
            ("agentic-job/", "agentic.lock/", false),
            ("agentic-job/", "agentic job/", false),
            ("max = 1", "max = 0", false),
            ("max = 1", "max = 2", false),
            ("max_patch_bytes = 65536", "max_patch_bytes = 1023", false),
            ("max_patch_bytes = 65536", "max_patch_bytes = 0", false),
            ("max_patch_files = 10", "max_patch_files = 0", false),
            (
                "max_patch_files = 10\n",
                &unprotected("cgwalters-forge/misctool", ".github"),
                true,
            ),
            (
                "max_patch_files = 10\n",
                &unprotected("CGWALTERS-FORGE/MISCTOOL", ".github"),
                true,
            ),
            // The primary output's repository, or any other.
            (
                "max_patch_files = 10\n",
                &unprotected("bootc-dev/bootc", ".github"),
                false,
            ),
            (
                "max_patch_files = 10\n",
                &unprotected("cgwalters-forge/*", ".github"),
                false,
            ),
            (
                "max_patch_files = 10\n",
                &unprotected("cgwalters-forge/misctool", ".husky"),
                false,
            ),
        ] {
            let configured = secondary_bounds(from, to).unwrap();
            assert_eq!(
                configured.validate().is_ok(),
                accepted,
                "{from:?} -> {to:?}"
            );
        }
    }

    #[test]
    fn a_secondary_pull_request_goes_only_beside_the_runs_own() {
        let configured = configured();
        // (repo, outputs, output repo, compiled with a secondary, or the
        // refusal that names it)
        type Case<'a> = (&'a str, &'a str, Option<&'a str>, Result<bool, &'a str>);
        let cases: &[Case] = &[
            (REPO, "create_pull_request,noop", None, Ok(true)),
            (REPO, "all", None, Ok(true)),
            (REPO, "create_pull_request", Some(REPO), Ok(true)),
            // Without a pull request of its own, a run opens none there.
            (REPO, "add_comment,noop", None, Ok(false)),
            (
                "cgwalters-forge/misctool",
                "create_pull_request",
                None,
                Err("the repository the run works on"),
            ),
            (
                "CGWALTERS-FORGE/MISCTOOL",
                "create_pull_request",
                None,
                Err("the repository the run works on"),
            ),
            (
                REPO,
                "create_pull_request",
                Some("cgwalters-forge/MiscTool"),
                Err("the repository the run applies to"),
            ),
            (
                "cgwalters-forge/secondary",
                "create_pull_request",
                None,
                Err("conflicts with the secondary directory"),
            ),
            // `misctool` under `agentic-job/` would name its patch as one
            // of `misctool-agentic-job` on the run's own branch.
            (
                "cgwalters-forge/misctool-agentic-job",
                "create_pull_request",
                None,
                Err("choose another branch_prefix"),
            ),
            (
                REPO,
                "create_pull_request",
                Some("cgwalters-forge/MiscTool-Agentic-Job"),
                Err("choose another branch_prefix"),
            ),
        ];
        for (repo, outputs, output_repo, want) in cases {
            let clone_url = format!("https://github.com/{repo}");
            let request = Request {
                repo,
                clone_url: &clone_url,
                outputs,
                output_repo: *output_repo,
                ..request()
            };
            match (configured.compile(&request), want) {
                (Ok(policy), Ok(secondary)) => {
                    assert_eq!(
                        policy.secondary_pull_request.is_some(),
                        *secondary,
                        "{repo} {outputs}"
                    );
                    // What `policy` prints is what `run`, check and apply load.
                    let json = serde_json::to_string(&policy).unwrap();
                    let loaded: Policy = serde_json::from_str(&json).unwrap();
                    loaded.validate().unwrap();
                    assert_eq!(loaded, policy);
                }
                (Err(errors), Err(want)) => {
                    assert!(
                        errors.iter().any(|error| error.contains(want)),
                        "{repo} {outputs}: {errors:?}"
                    );
                }
                (got, want) => panic!("{repo} {outputs}: {got:?}, not {want:?}"),
            }
        }
    }

    #[test]
    fn a_secondary_pull_request_keeps_its_own_bounds() {
        // The run's repository is exempt from CONTRIBUTING.md and AGENTS.md
        // in the primary bounds; the secondary inherits none of that.
        let configured = configured();
        let request = Request {
            repo: "cgwalters-bot/homegit",
            clone_url: "https://github.com/cgwalters-bot/homegit",
            ..request()
        };
        let policy = configured.compile(&request).unwrap();
        let own = policy.safe_outputs.create_pull_request.as_ref().unwrap();
        assert!(!own.protected_files.contains(&"AGENTS.md".to_owned()));
        let secondary = policy.secondary_pull_request.as_ref().unwrap();
        assert_eq!(
            secondary.clone_url,
            "https://github.com/cgwalters-forge/misctool"
        );
        assert_eq!((secondary.base.as_str(), secondary.max), ("main", 1));
        assert_eq!(secondary.branch_prefix, "agentic-job/");
        assert_eq!(
            (secondary.max_patch_bytes, secondary.max_patch_files),
            (65536, 10)
        );
        assert_eq!(secondary.protected_files, DEFAULT_PROTECTED_FILES);
        assert!(secondary.protect_top_level_dot_folders);
        assert!(secondary.unprotected_dot_folders.is_empty());

        // Its own exemptions, for itself alone.
        let text = format!(
            "{BOUNDS}{SECONDARY}\n[github.secondary_pull_request.unprotected_files]\n\
             repos = [\"cgwalters-forge/misctool\"]\nfiles = [\"go.mod\"]\n\
             dot_folders = [\".github\"]\n"
        );
        let exempt: Bounds = toml::from_str(&text).unwrap();
        let policy = exempt.compile(&request).unwrap();
        let secondary = policy.secondary_pull_request.as_ref().unwrap();
        assert!(!secondary.protected_files.contains(&"go.mod".to_owned()));
        assert_eq!(secondary.unprotected_dot_folders, [".github"]);
        let own = policy.safe_outputs.create_pull_request.as_ref().unwrap();
        assert!(own.protected_files.contains(&"go.mod".to_owned()));
        assert!(own.unprotected_dot_folders.is_empty());

        // The bounds' protected globs only take away: they hold there too.
        let text = format!("protected = [\"raw/**\"]\n{BOUNDS}{SECONDARY}");
        let globbed: Bounds = toml::from_str(&text).unwrap();
        let policy = globbed.compile(&request).unwrap();
        let secondary = policy.secondary_pull_request.as_ref().unwrap();
        assert_eq!(secondary.rules().protected_paths, ["raw/**"]);
    }

    #[test]
    fn a_policy_holds_its_secondary_pull_request_to_the_bounds_shape() {
        let good = configured().compile(&request()).unwrap();
        good.validate().unwrap();
        type Change = fn(&mut Policy);
        let cases: &[(&str, Change)] = &[
            ("no pull request of its own", |policy| {
                policy.safe_outputs.create_pull_request = None;
            }),
            ("an analysis run", |policy| policy.kind = Kind::Analysis),
            ("a private run", |policy| policy.private = true),
            ("off GitHub", |policy| policy.forge = Forge::Forgejo),
            ("an unreadable protected glob", |policy| {
                policy
                    .secondary_pull_request
                    .as_mut()
                    .unwrap()
                    .protected_paths = vec!["/raw/**".into()];
            }),
            ("the run's own repository", |policy| {
                policy.secondary_pull_request.as_mut().unwrap().repo = REPO.to_uppercase();
                policy.secondary_pull_request.as_mut().unwrap().clone_url =
                    format!("https://github.com/{}", REPO.to_uppercase());
            }),
            (
                "a patch named as one of the run's own repository",
                |policy| {
                    policy.repo = "cgwalters-forge/misctool-agentic-job".into();
                },
            ),
            ("the output repository", |policy| {
                policy.push_repo = Some("cgwalters-forge/MiscTool".into());
            }),
            ("a patch named as one of the output repository", |policy| {
                policy.push_repo = Some("cgwalters-forge/misctool-agentic-job".into());
            }),
            ("a clone URL that is no URL", |policy| {
                policy.secondary_pull_request.as_mut().unwrap().clone_url =
                    "ext::sh -c x/cgwalters-forge/misctool".into();
            }),
            ("unprotected dot-folders", |policy| {
                policy
                    .secondary_pull_request
                    .as_mut()
                    .unwrap()
                    .protect_top_level_dot_folders = false;
            }),
            ("another dot-folder exempted", |policy| {
                policy
                    .secondary_pull_request
                    .as_mut()
                    .unwrap()
                    .unprotected_dot_folders = vec![".husky".into()];
            }),
            ("two pull requests", |policy| {
                policy.secondary_pull_request.as_mut().unwrap().max = 2;
            }),
            ("a glob of repositories", |policy| {
                policy.secondary_pull_request.as_mut().unwrap().repo = "cgwalters-forge/*".into();
            }),
        ];
        for (what, change) in cases {
            let mut policy = good.clone();
            change(&mut policy);
            assert!(policy.validate().is_err(), "{what}");
        }
    }

    #[test]
    fn secondary_pull_requests_intersect_only_where_both_files_agree() {
        let left = configured().compile(&request()).unwrap();
        let tighter = format!(
            "{BOUNDS}{}",
            SECONDARY
                .replace("65536", "4096")
                .replace("max_patch_files = 10", "max_patch_files = 3")
        );
        let tighter: Bounds = toml::from_str(&tighter).unwrap();
        let right = tighter.compile(&request()).unwrap();
        for (left, right) in [(left.clone(), right.clone()), (right, left.clone())] {
            let both = intersect(left, right).unwrap();
            let secondary = both.secondary_pull_request.unwrap();
            assert_eq!(
                (secondary.max_patch_bytes, secondary.max_patch_files),
                (4096, 3)
            );
        }
        // Absent from one file, or another destination: none.
        for other in [
            bounds().compile(&request()).unwrap(),
            toml::from_str::<Bounds>(&format!(
                "{BOUNDS}{}",
                SECONDARY.replace("misctool", "othertool")
            ))
            .unwrap()
            .compile(&request())
            .unwrap(),
            toml::from_str::<Bounds>(&format!(
                "{BOUNDS}{}",
                SECONDARY.replace("agentic-job/", "other/")
            ))
            .unwrap()
            .compile(&request())
            .unwrap(),
        ] {
            for both in [
                intersect(left.clone(), other.clone()),
                intersect(other, left.clone()),
            ] {
                assert!(both.unwrap().secondary_pull_request.is_none());
            }
        }
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
        bounds.outputs_mut().unwrap().insert(
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
                pull_author: None,
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
            bounds.outputs_mut().unwrap().insert(
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
            .outputs_mut()
            .unwrap()
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
            bounds.outputs_mut().unwrap().insert(
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
                org.outputs_mut().unwrap().get_mut(output).unwrap().fields =
                    vec!["title".to_owned()];
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
            bounds.outputs_mut().unwrap().insert(
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
                bounds
                    .outputs_mut()
                    .unwrap()
                    .get_mut(output)
                    .unwrap()
                    .allowed = Some(vec![]);
                assert!(bounds.validate().is_err());
                bounds
                    .outputs_mut()
                    .unwrap()
                    .get_mut(output)
                    .unwrap()
                    .allowed = None;
            }
            if labels {
                bounds
                    .outputs_mut()
                    .unwrap()
                    .get_mut(output)
                    .unwrap()
                    .allowed = None;
                assert!(bounds.validate().is_err());
                bounds
                    .outputs_mut()
                    .unwrap()
                    .get_mut(output)
                    .unwrap()
                    .allowed = Some(vec![]);
                bounds.validate().unwrap();
            }
        }
        bounds
            .outputs_mut()
            .unwrap()
            .get_mut("add_labels")
            .unwrap()
            .allowed = None;
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
                bounds.outputs_mut().unwrap().insert(
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
                bounds.outputs_mut().unwrap().insert(
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
            // A person output's own checks do not stand in for this one.
            (
                "add_reviewer",
                "max = 1\nallowed = ['octocat']\nallowed_reasons = ['SPAM']",
                false,
            ),
            (
                "assign_to_user",
                "max = 1\nallowed = ['octocat']\nallowed_reasons = ['SPAM']",
                false,
            ),
        ] {
            assert_eq!(accepts(output, text), ok, "{output}: {text}");
        }

        let compiled = |reasons: &[&str]| {
            let mut bounds = bounds();
            bounds.outputs_mut().unwrap().insert(
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
            bounds.outputs_mut().unwrap().insert(
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
                    "{BOUNDS}\n[github.outputs.{output}]\nmax = 1\n\
                     allowed_reasons = ['SPAM']\n{key}\n"
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
            // Including an output whose own checks come first.
            for person in PERSON_OUTPUTS {
                let valid = "max = 1\nallowed = ['octocat']";
                assert!(accepts(person, valid), "{person}");
                assert!(
                    !accepts(person, &format!("{valid}\n{key} = 'a'")),
                    "{person} {key}"
                );
            }

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
                bounds
                    .outputs_mut()
                    .unwrap()
                    .insert(output.to_owned(), limit);
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
                bounds.outputs_mut().unwrap().insert(
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
        let https = Request {
            clone_url: "https://forge.internal/bootc-dev/bootc",
            ..request()
        };
        for (own, org, expected) in [
            (&opted, &opted, opted.allow_http.clone()),
            (&opted, &default, vec![]),
            (&default, &opted, vec![]),
        ] {
            assert_eq!(
                intersect(own.compile(&https).unwrap(), org.compile(&https).unwrap())
                    .unwrap()
                    .allow_http,
                expected
            );
        }
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
                        assert_eq!(policy.allow_http, bounds.allow_http);
                        let round_trip: Policy =
                            serde_json::from_slice(&serde_json::to_vec(&policy).unwrap()).unwrap();
                        assert_eq!(round_trip.allow_http, bounds.allow_http);
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
        // A port names its own authority, matched exactly; one on a host
        // that is not GitHub is as acceptable as the host alone.
        let ported: Bounds = toml::from_str(&BOUNDS.replace(
            "hosts = [\"github.com\"]",
            "hosts = [\"forge.internal:3000\"]\nallow_http = [\"forge.internal:3000\"]",
        ))
        .unwrap();
        ported.validate().unwrap();
        let on = |clone_url| Request {
            clone_url,
            ..request()
        };
        assert_eq!(
            ported
                .compile(&on("http://forge.internal:3000/bootc-dev/bootc"))
                .unwrap()
                .allow_http,
            ["forge.internal:3000"]
        );
        assert!(
            ported
                .compile(&on("http://forge.internal:3001/bootc-dev/bootc"))
                .is_err()
        );
    }

    /// A port, a user or a root dot in a clone URL's authority does not
    /// take it off GitHub; another host is not GitHub whatever it names.
    #[test]
    fn github_with_a_port_user_or_root_is_github() {
        for (url, github) in [
            ("https://github.com/bootc-dev/bootc", true),
            ("https://GitHub.com./bootc-dev/bootc", true),
            ("https://github.com:443/bootc-dev/bootc", true),
            ("https://x@github.com:443/bootc-dev/bootc", true),
            ("https://u:p@github.com/bootc-dev/bootc", true),
            ("http://api.github.com.:80/bootc-dev/bootc", true),
            ("http://[::1]:80/bootc-dev/bootc", false),
            ("https://forge.example/bootc-dev/bootc", false),
            ("https://github.com.evil/bootc-dev/bootc", false),
            ("https://xgithub.com/bootc-dev/bootc", false),
            ("https://forge.example/github.com/bootc", false),
            ("https://github.com@forge.example/bootc-dev/bootc", false),
            ("https://forge.example:443/bootc-dev/bootc", false),
        ] {
            assert_eq!(on_github(url), github, "{url}");
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
            bounds.outputs_mut().unwrap().insert(
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
            // The bounds name the ported authority, so only the fork
            // rule can refuse: the port does not take the run off GitHub.
            (
                "private, on GitHub with a port",
                Some(FORK),
                Some(FORK),
                Request {
                    clone_url: "https://github.com:443/bootc-dev/bootc",
                    ..forge
                },
                Some("can't create_pull_request"),
            ),
        ];
        // A fork is named only in `[forgejo]` or `[gitlab]`; bounds that
        // name none are GitHub's.
        for forge in [Forge::Forgejo, Forge::Gitlab] {
            let with = |push_repo: Option<&str>| {
                let private = Bounds {
                    private: true,
                    ..bounds()
                };
                let mut bounds = match push_repo {
                    Some(fork) => on_forge(private, forge, fork),
                    None => private,
                };
                bounds.hosts.push("forge.example".to_owned());
                bounds.hosts.push("github.com:443".to_owned());
                bounds.validate().unwrap();
                bounds
            };
            for (name, caller, org, request, want) in cases {
                let name = format!("{name} on {}", forge.name());
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
                let bounds = on_forge(bounds(), forge, push_repo);
                assert!(bounds.validate().is_err(), "{push_repo}");
            }
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
        bounds.outputs_mut().unwrap().insert(
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
            pull_author: None,
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
        bounds.outputs_mut().unwrap().insert(
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

    /// BOUNDS with its `[github]` outputs moved to the `[forgejo]` or
    /// `[gitlab]` section of FORGE, naming FORK, which `[github]` cannot.
    pub(crate) fn on_forge(mut bounds: Bounds, forge: Forge, fork: &str) -> Bounds {
        let github = bounds.github.take().unwrap();
        let section = Some(NeutralBounds {
            outputs: NeutralOutputs {
                own_branch_repos: Vec::new(),
                types: github.outputs.types,
            },
            push_repo: Some(fork.to_owned()),
        });
        match forge {
            Forge::Gitlab => bounds.gitlab = section,
            _ => bounds.forgejo = section,
        }
        bounds
    }

    /// [`push_policy`] on Forgejo, from the caller's and the
    /// organization's bounds, which both name FORK for the branch.
    pub(crate) fn push_policy_to(fork: &str) -> Policy {
        let bounds = on_forge(push_bounds(), Forge::Forgejo, fork);
        bounds.validate().unwrap();
        let own = bounds.compile(&push_request()).unwrap();
        intersect(own, bounds.compile(&push_request()).unwrap()).unwrap()
    }

    /// A push keeps the bounds' fork, which is never of the target's owner.
    #[test]
    fn push_keeps_the_fork() {
        let policy = push_policy_to("bot/bootc");
        assert_eq!(policy.push_repo.as_deref(), Some("bot/bootc"));
        policy.validate().unwrap();
        let bounds = on_forge(push_bounds(), Forge::Forgejo, "bootc-dev/fork");
        let errors = bounds.compile(&push_request()).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("not another owner's fork")),
            "{errors:?}"
        );
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

    /// A push to the bounds' `own_author`'s pull request, in a repository
    /// `repos` does not list, and what else that admits: nothing.
    #[test]
    fn own_author_admits_only_a_push_to_its_own_pull_request() {
        const BOT: &str = "cgwalters-bot";
        let mut bounds = push_bounds();
        bounds
            .outputs_mut()
            .unwrap()
            .get_mut(PUSH_TO_PULL_REQUEST_BRANCH)
            .unwrap()
            .own_author = Some(BOT.into());
        bounds.validate().unwrap();
        let ok = Request {
            repo: "ostreedev/ostree",
            clone_url: "https://github.com/ostreedev/ostree",
            output_repo: Some("ostreedev/ostree"),
            pull_author: Some(BOT),
            outputs: "push_to_pull_request_branch,noop,missing_tool,missing_data",
            ..push_request()
        };
        // The author apply checks again, or a part of the refusal.
        type Want = Result<Option<&'static str>, &'static str>;
        // The name, the request, and what it gets.
        let cases: &[(&str, Request<'_>, Want)] = &[
            ("the bot's pull request", ok, Ok(Some(BOT))),
            (
                "its login in another case",
                Request {
                    pull_author: Some("CGWalters-Bot"),
                    ..ok
                },
                Ok(Some(BOT)),
            ),
            // `repos` admits as before, and apply checks no author.
            (
                "a listed repository",
                Request {
                    pull_author: Some("carol"),
                    ..push_request()
                },
                Ok(None),
            ),
            (
                "the bot's pull request in a listed repository",
                Request {
                    pull_author: Some(BOT),
                    ..push_request()
                },
                Ok(None),
            ),
            (
                "another's pull request",
                Request {
                    pull_author: Some("carol"),
                    ..ok
                },
                Err("repo \"ostreedev/ostree\" is not within the bounds"),
            ),
            (
                "an app's pull request",
                Request {
                    pull_author: Some(""),
                    ..ok
                },
                Err("is not within the bounds"),
            ),
            (
                "no author",
                Request {
                    pull_author: None,
                    ..ok
                },
                Err("is not within the bounds"),
            ),
            (
                "a comment beside the push",
                Request {
                    outputs: "push_to_pull_request_branch,add_comment",
                    ..ok
                },
                Err(
                    "output type \"add_comment\" is not for \"ostreedev/ostree\", which the bounds admit only for a push",
                ),
            ),
            (
                "every output",
                Request {
                    outputs: "all",
                    max_outputs: "max",
                    ..ok
                },
                Err("is not for \"ostreedev/ostree\""),
            ),
            (
                "no push",
                Request {
                    outputs: "noop",
                    ..ok
                },
                Err("is not within the bounds"),
            ),
            // The branch globs hold as for any push.
            (
                "a branch the push globs do not name",
                Request { base: "main", ..ok },
                Err("pull request branch \"main\" is not within the bounds"),
            ),
            (
                "an item in another unlisted repository",
                Request {
                    item_repo: Some("ostreedev/other"),
                    ..ok
                },
                Err("item repo \"ostreedev/other\" is not within the bounds"),
            ),
            (
                "a repository that is not a name",
                Request {
                    repo: "ostreedev/../x",
                    clone_url: "https://github.com/ostreedev/../x",
                    output_repo: Some("ostreedev/../x"),
                    ..ok
                },
                Err("is not within the bounds"),
            ),
        ];
        for (name, request, want) in cases {
            let author = |policy: &Policy| {
                policy
                    .safe_outputs
                    .push_to_pull_request_branch
                    .as_ref()
                    .unwrap()
                    .author
                    .clone()
            };
            match (bounds.compile(request), want) {
                (Ok(policy), Ok(want)) => {
                    assert_eq!(author(&policy).as_deref(), *want, "{name}");
                    policy.validate().unwrap();
                }
                (Err(errors), Err(want)) => assert!(
                    errors.iter().any(|e| e.contains(want)),
                    "{name}: {errors:?}"
                ),
                (result, _) => panic!("{name}: {result:?}"),
            }
        }
        // Off by default: the same request without the key is refused.
        let errors = push_bounds().compile(&ok).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("is not within the bounds")),
            "{errors:?}"
        );
        // An organization file that lists the repository keeps the check.
        let mut org = push_bounds();
        org.repos.push("ostreedev/*".into());
        let both = intersect(bounds.compile(&ok).unwrap(), org.compile(&ok).unwrap()).unwrap();
        let push = both.safe_outputs.push_to_pull_request_branch.unwrap();
        assert_eq!(push.author.as_deref(), Some(BOT));
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
            (
                PUSH_TO_PULL_REQUEST_BRANCH,
                "max = 1\nbranches = ['agent-run-*']\nown_author = 'cgwalters-bot'",
                true,
            ),
            (
                PUSH_TO_PULL_REQUEST_BRANCH,
                "max = 1\nbranches = ['agent-run-*']\nown_author = 'renovate[bot]'",
                false,
            ),
            (
                PUSH_TO_PULL_REQUEST_BRANCH,
                "max = 1\nbranches = ['agent-run-*']\nown_author = ''",
                false,
            ),
            (
                "add_comment",
                "max = 1\nown_author = 'cgwalters-bot'",
                false,
            ),
        ] {
            assert_eq!(valid(output, text), ok, "{output} {text}");
        }
        let mut bounds = push_bounds();
        bounds
            .outputs_mut()
            .unwrap()
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
                    .outputs_mut()
                    .unwrap()
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

    /// A replacement's file total is each file's own, its
    /// `max_patch_files` where it sets none, and the tighter one wins.
    #[test]
    fn replacement_files_only_tighten() {
        // (caller's max_patch_files, replacement_max_files), the
        // organization's, and the series total both allow.
        for (caller, organization, want) in [
            ((50, 0), (50, 0), (0, 50)),
            ((50, 200), (50, 0), (0, 50)),
            ((50, 200), (50, 100), (100, 100)),
            ((50, 10), (50, 0), (10, 10)),
            ((50, 200), (20, 300), (200, 200)),
            // The caller's total, above the organization's per patch.
            ((50, 0), (20, 300), (50, 50)),
        ] {
            let compile = |(files, total)| {
                let mut bounds = push_bounds();
                bounds.max_patch_files = files;
                let push = bounds
                    .outputs_mut()
                    .unwrap()
                    .get_mut(PUSH_TO_PULL_REQUEST_BRANCH)
                    .unwrap();
                push.replacement_max_commits = 5;
                push.replacement_max_files = total;
                bounds.validate().unwrap();
                bounds.compile(&push_request()).unwrap()
            };
            let both = intersect(compile(caller), compile(organization)).unwrap();
            let push = both.safe_outputs.push_to_pull_request_branch.unwrap();
            assert_eq!(
                (push.replacement_max_files, push.replacement_files()),
                want,
                "{caller:?} {organization:?}"
            );
        }
        // (output, replacement_max_commits, replacement_max_files, valid)
        for (output, commits, total, accepted) in [
            (PUSH_TO_PULL_REQUEST_BRANCH, 5, 500, true),
            (PUSH_TO_PULL_REQUEST_BRANCH, 5, 501, false),
            // Without replacement it would do nothing.
            (PUSH_TO_PULL_REQUEST_BRANCH, 0, 100, false),
            (PUSH_TO_PULL_REQUEST_BRANCH, 0, 0, true),
            (CREATE_PULL_REQUEST, 0, 1, false),
        ] {
            let limit = OutputLimit {
                max: 1,
                replacement_max_commits: commits,
                replacement_max_files: total,
                branches: if output == PUSH_TO_PULL_REQUEST_BRANCH {
                    vec!["agent-run-*".into()]
                } else {
                    Vec::new()
                },
                ..OutputLimit::default()
            };
            assert_eq!(limit.validate(output).is_ok(), accepted, "{output} {total}");
        }
    }

    #[test]
    fn upstream_pull_request_base_is_opt_in_and_intersects() {
        let compile = |enabled| {
            let parsed: Bounds = toml::from_str(&format!(
                "{BOUNDS}\nupstream-pull-request-base = {enabled}\n"
            ))
            .unwrap();
            let policy = parsed.compile(&request()).unwrap();
            let policy: Policy =
                serde_json::from_value(serde_json::to_value(policy).unwrap()).unwrap();
            policy.validate().unwrap();
            policy
        };
        assert!(
            !bounds()
                .compile(&request())
                .unwrap()
                .safe_outputs
                .upstream_pull_request_base
        );
        for first in [false, true] {
            for second in [false, true] {
                let both = intersect(compile(first), compile(second)).unwrap();
                assert_eq!(
                    both.safe_outputs.upstream_pull_request_base,
                    first && second
                );
            }
        }
    }

    #[test]
    fn own_branch_repos_are_caller_bounds_and_intersect() {
        let compile = |patterns: &[&str]| {
            let mut bounds = bounds();
            bounds.github.as_mut().unwrap().outputs.own_branch_repos =
                patterns.iter().map(|s| (*s).to_owned()).collect();
            bounds.compile(&request()).unwrap()
        };
        let parsed: Bounds = toml::from_str(&format!(
            "{BOUNDS}\nown-branch-repos = [\"example-org/*\"]\n"
        ))
        .unwrap();
        let policy = parsed.compile(&request()).unwrap();
        // Check's policy loader and serialized handler configuration retain it.
        let policy: Policy = serde_json::from_value(serde_json::to_value(policy).unwrap()).unwrap();
        policy.validate().unwrap();
        assert!(
            policy
                .safe_outputs
                .accepts_own_branches("Example-Org/repo")
                .unwrap()
        );
        assert!(
            !policy
                .safe_outputs
                .accepts_own_branches("other/repo")
                .unwrap()
        );
        assert!(
            !compile(&[])
                .safe_outputs
                .accepts_own_branches("example-org/repo")
                .unwrap()
        );
        for (other, accepted) in [
            (vec!["*/repo"], true),
            (vec!["other/*"], false),
            (vec![], false),
        ] {
            let both = intersect(policy.clone(), compile(&other)).unwrap();
            assert_eq!(
                both.safe_outputs
                    .accepts_own_branches("example-org/repo")
                    .unwrap(),
                accepted
            );
            assert!(
                !both
                    .safe_outputs
                    .accepts_own_branches("example-org/else")
                    .unwrap()
            );
        }
        for patterns in [
            vec![String::new()],
            vec!["a".repeat(257)],
            vec!["*".into(); 101],
        ] {
            let mut bounds = bounds();
            bounds.github.as_mut().unwrap().outputs.own_branch_repos = patterns.clone();
            assert!(bounds.validate().is_err());
            let mut invalid = policy.clone();
            invalid.safe_outputs.own_branch_repos = vec![patterns];
            assert!(invalid.validate().is_err());
        }
        // GitLab's bounds carry it alike, a merge request needing no fork
        // with it; Forgejo's refuse it.
        for (forge, accepted) in [(Forge::Gitlab, true), (Forge::Forgejo, false)] {
            let mut bounds = on_forge(bounds(), forge, "bot/unused");
            let section = bounds.gitlab.as_mut().or(bounds.forgejo.as_mut()).unwrap();
            section.push_repo = None;
            section.outputs.own_branch_repos = vec!["example-org/*".to_owned()];
            assert_eq!(bounds.validate().is_ok(), accepted, "{forge:?}");
            let mut policy = policy.clone();
            policy.forge = forge;
            assert_eq!(policy.validate().is_ok(), accepted, "{forge:?}");
            if accepted {
                let policy = bounds.compile(&request()).unwrap();
                policy.validate().unwrap();
                assert!(
                    policy
                        .safe_outputs
                        .accepts_own_branches("example-org/repo")
                        .unwrap()
                );
            }
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
                bounds
                    .outputs_mut()
                    .unwrap()
                    .get_mut(output)
                    .unwrap()
                    .ready_when_complete = on;
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
                    max_patch_files = 1\n[github.outputs]\n\
                    create_pull_request = { max = 1, ready_when_complete = true }\n";
        let parsed: Bounds = toml::from_str(toml).unwrap();
        assert!(parsed.outputs()[CREATE_PULL_REQUEST].ready_when_complete);
    }

    /// `native_handlers` routes only what both files name, of the types
    /// the run may hand back, and only on GitHub; off, policy.json says
    /// nothing of it.
    #[test]
    fn native_handlers_are_explicit_and_only_narrow() {
        let compile = |native: &[&str], outputs: &'static str| {
            let mut bounds = bounds();
            bounds.native_handlers = native.iter().map(|output| (*output).to_owned()).collect();
            bounds.validate().unwrap();
            bounds
                .compile(&Request {
                    outputs,
                    ..request()
                })
                .unwrap()
        };
        let both = ["add_comment", CREATE_PULL_REQUEST];
        let all = "create_pull_request,add_comment,noop";
        for (caller, organization, outputs, want) in [
            (&both[..], &both[..], all, &both[..]),
            (&both[..], &[][..], all, &[][..]),
            (&["add_comment"][..], &both[..], all, &["add_comment"][..]),
            (
                &both[..],
                &both[..],
                "create_pull_request,noop",
                &[CREATE_PULL_REQUEST][..],
            ),
        ] {
            let policy =
                intersect(compile(caller, outputs), compile(organization, outputs)).unwrap();
            assert_eq!(
                policy.native_handlers, want,
                "{caller:?} {organization:?} {outputs}"
            );
            policy.validate().unwrap();
        }
        let off = serde_json::to_string(&compile(&[], all)).unwrap();
        assert!(!off.contains("native_handlers"), "{off}");

        let with = |native: &str| format!("native_handlers = {native}\n{BOUNDS}");
        for (bounds, want) in [
            (with(r#"["update_issue"]"#), "is not one of"),
            (with(r#"["add_comment", "add_comment"]"#), "twice"),
            (
                with(r#"["add_comment"]"#).replace("add_comment = { max = 3 }\n", ""),
                "which the outputs do not allow",
            ),
            (
                with(r#"["add_comment"]"#).replace(
                    "[github.outputs]",
                    "[forgejo]\npush_repo = \"bot/bootc\"\n[forgejo.outputs]",
                ),
                "only for GitHub",
            ),
        ] {
            let bounds: Bounds = toml::from_str(&bounds).unwrap();
            let err = format!("{:#}", bounds.validate().unwrap_err());
            assert!(err.contains(want), "{err}");
        }
        let mut policy = compile(&both, all);
        policy.native_handlers.push("close_issue".into());
        assert!(policy.validate().is_err());
    }

    /// `comment_on_duplicate` is for create_issue alone, and only where
    /// agentic-job's handler publishes it, as gh-aw's searches for nothing;
    /// it reaches policy.json only where both files set it.
    #[test]
    fn comment_on_duplicate_needs_the_native_handler() {
        let with = |native: &str, limit: &str| {
            format!("native_handlers = {native}\n{BOUNDS}create_issue = {limit}\n")
        };
        let on = "{ max = 3, comment_on_duplicate = true }";
        for (text, want) in [
            (with(r#"["create_issue"]"#, on), None),
            (with("[]", "{ max = 3 }"), None),
            (
                with("[]", on),
                Some("needs create_issue in native_handlers"),
            ),
            (
                with(r#"["add_comment"]"#, on),
                Some("needs create_issue in native_handlers"),
            ),
            (
                with("[]", "{ max = 3 }").replace(
                    "add_comment = { max = 3 }",
                    "add_comment = { max = 3, comment_on_duplicate = true }",
                ),
                Some("supported only for create_issue"),
            ),
        ] {
            let bounds: Bounds = toml::from_str(&text).unwrap();
            match (bounds.validate(), want) {
                (Ok(()), None) => {}
                (Err(err), Some(want)) => {
                    let err = format!("{err:#}");
                    assert!(err.contains(want), "{err}");
                }
                (got, want) => panic!("{text}: {got:?}, want {want:?}"),
            }
        }

        let compile = |limit: &str| {
            let bounds: Bounds = toml::from_str(&with(r#"["create_issue"]"#, limit)).unwrap();
            bounds.validate().unwrap();
            bounds
                .compile(&Request {
                    outputs: "create_issue,noop",
                    ..request()
                })
                .unwrap()
        };
        for (caller, organization, want) in [
            (on, on, true),
            (on, "{ max = 3 }", false),
            ("{ max = 3 }", on, false),
        ] {
            let policy = intersect(compile(caller), compile(organization)).unwrap();
            assert_eq!(
                policy.safe_outputs.others["create_issue"].comment_on_duplicate, want,
                "{caller} {organization}"
            );
            policy.validate().unwrap();
        }
        let mut policy = compile(on);
        policy.native_handlers.clear();
        assert!(policy.validate().is_err());
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

        // `[github.memory]` reaches the policy with its defaults, within its
        // ceilings; without it there is none, and no key for it.
        assert_eq!(all.memory, None);
        assert!(!serde_json::to_string(&all).unwrap().contains("memory"));
        let memory = |table: &str| {
            let bounds: Bounds =
                toml::from_str(&format!("{BOUNDS}\n[github.memory]\n{table}")).unwrap();
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

        // `[github.test_evidence]` likewise; without it, none.
        assert_eq!(all.test_evidence, None);
        assert!(
            !serde_json::to_string(&all)
                .unwrap()
                .contains("test_evidence")
        );
        for (table, want) in [
            ("", (5, 256 * KB)),
            (
                "max_attempts = 10\nmax_log_bytes = 1048576",
                (10, 1024 * KB),
            ),
            ("max_attempts = 1\nmax_log_bytes = 1", (1, 1)),
        ] {
            let bounds: Bounds =
                toml::from_str(&format!("{BOUNDS}\n[github.test_evidence]\n{table}")).unwrap();
            bounds.validate().unwrap();
            let got = bounds.compile(&request()).unwrap().test_evidence.unwrap();
            assert_eq!((got.max_attempts, got.max_log_bytes), want, "{table}");
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
        org.outputs_mut().unwrap().remove("missing_data");
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
        // Test evidence only where both files have it, within the tighter
        // of each bound.
        let evidence = |max_attempts, max_log_bytes| TestEvidence {
            max_attempts,
            max_log_bytes,
        };
        let tested = |policy: &Policy, rules: TestEvidence| Policy {
            test_evidence: Some(rules),
            ..policy.clone()
        };
        assert_eq!(
            intersect(tested(&a, evidence(5, 10)), b.clone())
                .unwrap()
                .test_evidence,
            None
        );
        assert_eq!(
            intersect(a.clone(), tested(&b, evidence(5, 10)))
                .unwrap()
                .test_evidence,
            None
        );
        assert_eq!(
            intersect(tested(&a, evidence(3, 100)), tested(&b, evidence(5, 10)))
                .unwrap()
                .test_evidence,
            Some(evidence(3, 10))
        );
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
        local
            .outputs_mut()
            .unwrap()
            .retain(|name, _| name == "noop");
        org.outputs_mut()
            .unwrap()
            .retain(|name, _| name == "missing_data");
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
            let protected = protected_files(&bounds.unprotected_files, repo);
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
    fn protected_globs_match_as_branches_do() {
        let globs = ["raw/**".to_owned(), "docs/*.lock".to_owned()];
        for (path, want) in [
            ("raw/a.md", Some("raw/**")),
            ("raw/a/b/c.md", Some("raw/**")),
            ("docs/x.lock", Some("docs/*.lock")),
            // Case counts: a new file beside `raw/`, not a change to it.
            ("Raw/a.md", None),
            ("raw", None),
            ("rawx/a.md", None),
            ("wiki/raw/a.md", None),
            ("docs/a/x.lock", None),
        ] {
            assert_eq!(protecting_glob(&globs, path), want, "{path}");
        }
        // `**/` is at least one directory, as in `branches`: the root's own
        // files need a glob of their own.
        let globs = ["**/*.pem".to_owned()];
        for (path, want) in [
            ("a/key.pem", Some("**/*.pem")),
            ("a/b/key.pem", Some("**/*.pem")),
            ("key.pem", None),
        ] {
            assert_eq!(protecting_glob(&globs, path), want, "{path}");
        }
        assert_eq!(protecting_glob(&[], "raw/a.md"), None);
    }

    #[test]
    fn protected_globs_compile_union_and_load() {
        let mut local = bounds();
        local.protected = vec!["raw/**".into()];
        local.validate().unwrap();
        let mut org = bounds();
        org.protected = vec!["raw/**".into(), "sources/*".into()];
        let own = local.compile(&request()).unwrap();
        let pr = own.safe_outputs.create_pull_request.as_ref().unwrap();
        assert_eq!(pr.protected_paths, ["raw/**"]);
        assert_eq!(pr.rules().protected_paths, ["raw/**"]);
        // Each file only adds protection, in either order; none takes it away.
        for (left, right) in [
            (own.clone(), org.compile(&request()).unwrap()),
            (org.compile(&request()).unwrap(), own.clone()),
        ] {
            let mut got = intersect(left, right)
                .unwrap()
                .safe_outputs
                .create_pull_request
                .unwrap()
                .protected_paths;
            got.sort();
            assert_eq!(got, ["raw/**", "sources/*"]);
        }
        assert_eq!(
            intersect(own.clone(), self::policy())
                .unwrap()
                .safe_outputs
                .create_pull_request
                .unwrap()
                .protected_paths,
            ["raw/**"]
        );
        let mut push = push_bounds();
        push.protected = vec!["raw/**".into()];
        let push = push.compile(&push_request()).unwrap();
        let push = push.safe_outputs.push_to_pull_request_branch.unwrap();
        assert_eq!(push.rules().protected_paths, ["raw/**"]);

        // Off by default, and absent from the policy then.
        let plain = serde_json::to_value(self::policy()).unwrap();
        assert!(plain["safe_outputs"]["create_pull_request"]["protected_paths"].is_null());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, serde_json::to_vec(&own).unwrap()).unwrap();
        assert_eq!(Policy::load(&path).unwrap(), own);
        let mut bad = own;
        bad.safe_outputs
            .create_pull_request
            .as_mut()
            .unwrap()
            .protected_paths = vec!["/raw/**".into()];
        std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(
            format!("{:#}", Policy::load(&path).unwrap_err())
                .contains("create_pull_request.protected_paths: \"/raw/**\" is not a relative")
        );
        // How many globs the two files may protect together is the
        // library's (safe_outputs::bounds::tests).
    }

    #[test]
    fn bad_bounds_files() {
        let with = |from: &str, to: &str| BOUNDS.replace(from, to);
        // [`BOUNDS`] without its `[github]` section.
        let neutral = format!("{}\n", BOUNDS.split("\n[github.").next().unwrap());
        let noop = "noop = { max = 1 }\n";
        let cases = [
            (
                "an unknown key",
                format!("extra = 1\n{BOUNDS}"),
                "unknown field",
            ),
            // One forge section, which selects the forge (#1393).
            ("no forge section", neutral.clone(), "no forge section"),
            (
                "two forge sections",
                format!("{BOUNDS}[gitlab.outputs]\n{noop}"),
                "the sections [github] and [gitlab] are both present",
            ),
            (
                "the old scalar forge",
                format!("forge = \"forgejo\"\n{BOUNDS}"),
                "unknown field `forge`",
            ),
            (
                "the old top-level outputs",
                format!("{neutral}[outputs]\n{noop}"),
                "unknown field `outputs`",
            ),
            (
                "the old top-level push_repo",
                format!("push_repo = \"bot/bootc\"\n{BOUNDS}"),
                "unknown field `push_repo`",
            ),
            (
                "the old top-level trigger",
                format!("{neutral}[trigger]\nevents = [\"issues\"]\n[github.outputs]\n{noop}"),
                "unknown field `trigger`",
            ),
            (
                "the old top-level memory",
                format!("{neutral}[memory]\n[github.outputs]\n{noop}"),
                "unknown field `memory`",
            ),
            (
                "the old top-level secondary_pull_request",
                format!("{BOUNDS}{}", SECONDARY.replace("[github.", "[")),
                "unknown field `secondary_pull_request`",
            ),
            (
                "a trigger in [forgejo]",
                format!(
                    "{neutral}[forgejo.trigger]\nevents = [\"issues\"]\n\
                     [forgejo.outputs]\n{noop}"
                ),
                "unknown field `trigger`",
            ),
            (
                "memory in [gitlab]",
                format!("{neutral}[gitlab.memory]\n[gitlab.outputs]\n{noop}"),
                "unknown field `memory`",
            ),
            (
                "a GitHub-only type in [forgejo]",
                format!(
                    "{neutral}[forgejo.outputs]\n\
                     hide_comment = {{ max = 1, allowed_reasons = [\"SPAM\"] }}\n"
                ),
                "GitHub-only",
            ),
            (
                "a GitHub-only type in [gitlab]",
                format!("{neutral}[gitlab.outputs]\nlink_sub_issue = {{ max = 1 }}\n"),
                "GitHub-only",
            ),
            (
                "a Forgejo pull request without its fork",
                format!("{neutral}[forgejo.outputs]\ncreate_pull_request = {{ max = 1 }}\n"),
                "must name push_repo",
            ),
            (
                "a GitLab merge request without its fork",
                format!("{neutral}[gitlab.outputs]\ncreate_pull_request = {{ max = 1 }}\n"),
                "must name push_repo",
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
                "plain HTTP for github.com with a port",
                with(
                    "hosts = [\"github.com\"]",
                    "hosts = [\"github.com:80\"]\nallow_http = [\"github.com:80\"]",
                ),
                "may not name",
            ),
            (
                "plain HTTP for a host under github.com with a user, root and port",
                with(
                    "hosts = [\"github.com\"]",
                    "hosts = [\"x@API.github.com.:8080\"]\nallow_http = [\"x@API.github.com.:8080\"]",
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
                format!("{BOUNDS}\n[github.memory]\nbranch = \"x\"\n"),
                "unknown field `branch`",
            ),
            (
                "an unknown test evidence key",
                format!("{BOUNDS}\n[github.test_evidence]\nmax_logs = 1\n"),
                "unknown field `max_logs`",
            ),
            (
                "no test attempts",
                format!("{BOUNDS}\n[github.test_evidence]\nmax_attempts = 0\n"),
                "test_evidence.max_attempts must be from 1 to 10",
            ),
            (
                "too many test attempts",
                format!("{BOUNDS}\n[github.test_evidence]\nmax_attempts = 11\n"),
                "test_evidence.max_attempts must be from 1 to 10",
            ),
            (
                "empty test logs",
                format!("{BOUNDS}\n[github.test_evidence]\nmax_log_bytes = 0\n"),
                "test_evidence.max_log_bytes must be from 1 to 1048576",
            ),
            (
                "a test log too big",
                format!("{BOUNDS}\n[github.test_evidence]\nmax_log_bytes = 1048577\n"),
                "test_evidence.max_log_bytes must be from 1 to 1048576",
            ),
            (
                "test evidence in [forgejo]",
                "[forgejo]\npush_repo = \"bot/r\"\n[forgejo.test_evidence]\n[forgejo.outputs]\nnoop = { max = 1 }\n"
                    .to_owned(),
                "unknown field `test_evidence`",
            ),
            (
                "no memory files",
                format!("{BOUNDS}\n[github.memory]\nmax_files = 0\n"),
                "memory.max_files must be from 1 to 100",
            ),
            (
                "too many memory files",
                format!("{BOUNDS}\n[github.memory]\nmax_files = 101\n"),
                "memory.max_files must be from 1 to 100",
            ),
            (
                "empty memory files",
                format!("{BOUNDS}\n[github.memory]\nmax_file_bytes = 0\n"),
                "memory.max_file_bytes must be from 1 to 102400",
            ),
            (
                "a memory file too big",
                format!("{BOUNDS}\n[github.memory]\nmax_file_bytes = 102401\nmax_bytes = 200000\n"),
                "memory.max_file_bytes must be from 1 to 102400",
            ),
            (
                "a memory too big",
                format!("{BOUNDS}\n[github.memory]\nmax_bytes = 1048577\n"),
                "memory.max_bytes must be from max_file_bytes to 1048576",
            ),
            (
                "a memory smaller than one file",
                format!("{BOUNDS}\n[github.memory]\nmax_file_bytes = 2048\nmax_bytes = 1024\n"),
                "memory.max_bytes must be from max_file_bytes",
            ),
            (
                "no memory extensions",
                format!("{BOUNDS}\n[github.memory]\nextensions = []\n"),
                "memory.extensions lists no extension",
            ),
            (
                "a script as memory",
                format!("{BOUNDS}\n[github.memory]\nextensions = [\"md\", \"sh\"]\n"),
                "memory.extensions may only name md, txt, json, jsonl, csv, not \"sh\"",
            ),
            (
                "a dotted memory extension",
                format!("{BOUNDS}\n[github.memory]\nextensions = [\".md\"]\n"),
                "not \".md\"",
            ),
            (
                "an upper-case memory extension",
                format!("{BOUNDS}\n[github.memory]\nextensions = [\"MD\"]\n"),
                "not \"MD\"",
            ),
            (
                "an empty protected glob",
                format!("protected = [\"\"]\n{BOUNDS}"),
                "protected: \"\" is not a relative path glob",
            ),
            (
                "an absolute protected glob",
                format!("protected = [\"/raw/**\"]\n{BOUNDS}"),
                "protected: \"/raw/**\" is not a relative path glob",
            ),
            (
                "a protected glob from the current directory",
                format!("protected = [\"./raw/**\"]\n{BOUNDS}"),
                "\"./raw/**\" is not a relative path glob",
            ),
            (
                "a protected glob through a parent",
                format!("protected = [\"x/../raw/**\"]\n{BOUNDS}"),
                "\"x/../raw/**\" is not a relative path glob",
            ),
            (
                "a protected directory with a trailing slash",
                format!("protected = [\"raw/\"]\n{BOUNDS}"),
                "\"raw/\" is not a relative path glob",
            ),
            (
                "a doubled slash in a protected glob",
                format!("protected = [\"raw//**\"]\n{BOUNDS}"),
                "\"raw//**\" is not a relative path glob",
            ),
            (
                "a brace set, which would be taken for itself",
                format!("protected = [\"*.{{pem,key}}\"]\n{BOUNDS}"),
                "with only `*` and `**` special",
            ),
            (
                "a question mark, which would be taken for itself",
                format!("protected = [\"secret?.txt\"]\n{BOUNDS}"),
                "with only `*` and `**` special",
            ),
            (
                "a character class, which would be taken for itself",
                format!("protected = [\"raw/[ab]/*\"]\n{BOUNDS}"),
                "with only `*` and `**` special",
            ),
            (
                "a protected glob too long",
                format!("protected = [\"{}\"]\n{BOUNDS}", "a".repeat(257)),
                "is over 256 bytes",
            ),
            (
                "too many protected globs",
                format!(
                    "protected = [{}]\n{BOUNDS}",
                    (0..65)
                        .map(|i| format!("\"a{i}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                "protected lists 65 globs, over 64",
            ),
            (
                "a memory extension twice",
                format!("{BOUNDS}\n[github.memory]\nextensions = [\"md\", \"md\"]\n"),
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
            repos: vec!["*/*".into()],
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

    /// Bounds with the section of FORGE allowing OUTPUT, with LIMIT as its
    /// table. Off GitHub the section names the fork its pull requests
    /// come from.
    fn forge_bounds(forge: &str, output: &str, limit: &str) -> Result<Bounds> {
        let fork = if forge == "github" {
            ""
        } else {
            "push_repo = \"bot/name\"\n"
        };
        let bounds: Bounds = toml::from_str(&format!(
            r#"
hosts = ["forge.example"]
repos = ["owner/*"]
bases = ["main"]
max_outputs = 3
max_patch_bytes = 65536
max_patch_files = 10

[{forge}]
{fork}
[{forge}.outputs]
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
            bounds.outputs_mut().unwrap().insert(
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
