//! A caller's bounds file ([`Bounds`]), what it may say
//! ([`Bounds::validate`]), and how two bounds files' policies of one
//! request are made one that both admit ([`intersect`]).
//!
//! Reading the file, compiling a request against it and admitting the
//! event that started the run are the caller's: agentic-job's `policy`
//! and `event`. The `[github.trigger]` table is event admission's, so
//! this carries it as the caller's type, unread.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use crate::contract::{
    DEFAULT_PROTECTED_FILES, ForgeAdmission, KB, MAX_PROTECTED_GLOBS, MAX_PULL_REQUESTS, Memory,
    OutputLimit, PERSON_OUTPUTS, PLAIN_HTTP_PREFIX, Policy, REPO_RE, Secondary, TestEvidence,
    UPDATE_FIELDS, allows_http, check_comment_on_duplicate, check_commit_author,
    check_native_handlers, check_secondary, dotted, glob, validate_dot_folders, validate_protected,
};
use crate::{CREATE_PULL_REQUEST, Forge, HIDE_COMMENT, OUTPUT_TYPES, PUSH_TO_PULL_REQUEST_BRANCH};

/// The domain no bounds file may allow plain HTTP for, nor any host under
/// it: it serves https, so a plain-HTTP URL for it is a downgrade.
const NEVER_PLAIN_HTTP: &str = "github.com";

/// The caller's bounds file (`--allow`), in TOML: the keys every forge
/// shares at the top level, and one forge section. TRIGGER is the
/// `[github.trigger]` table's type, which only the caller reads.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bounds<Trigger = toml::Table> {
    /// Avoid wasted agent setup from overlapping dispatches for one item and kind.
    #[serde(default)]
    pub dedupe: bool,
    /// The hosts a clone URL may name, exactly (`github.com`).
    pub hosts: Vec<String>,
    /// Hosts of `hosts` a clone URL may name over plain `http://`, for a
    /// self-hosted forge on a private network without TLS. Empty by
    /// default: anyone on the path can read and alter a plain-HTTP clone,
    /// so the agent's base, and a private repository's read token, are
    /// only as safe as that network. Never [`NEVER_PLAIN_HTTP`], with
    /// or without a port or user.
    #[serde(default)]
    pub allow_http: Vec<String>,
    /// Globs of OWNER/NAME or opt-in live organization rules.
    pub repos: Vec<RepoRule>,
    /// Globs of base branches.
    pub bases: Vec<String>,
    /// The most outputs a run may hand back in all.
    pub max_outputs: u32,
    /// The largest patch, in bytes.
    pub max_patch_bytes: u64,
    /// The most files a patch may touch.
    pub max_patch_files: u32,
    /// Files exempt from protection.
    #[serde(default)]
    pub unprotected_files: Unprotected,
    /// Globs of paths a patch may never touch, in every repository the
    /// bounds admit, on top of what is protected anyway: files the
    /// repository's owner keeps as they are, such as a wiki's raw sources,
    /// which a run asked to work from them could otherwise rewrite. They
    /// match as `branches` do, case counting; see
    /// [`crate::contract::protecting_glob`].
    #[serde(default)]
    pub protected: Vec<String>,
    /// Who the hand-back's commit is by, as `Name <address>`. Without it,
    /// whatever `run` says, which a compromised agent machine chooses:
    /// with it, `check` refuses a patch by anyone else, so the run's
    /// commit cannot be passed off as a maintainer's. A replacement series
    /// keeps its commits' own authors and is not held to it, so bounds
    /// that allow one (`replacement_max_commits`) leave that open.
    /// See [`check_commit_author`].
    #[serde(default)]
    pub commit_author: Option<String>,
    /// Whether a run may work on a repository that is not public. Off,
    /// run evidence is published and only public repositories are run;
    /// on, `policy` keeps such a run's outputs in its own repository and
    /// `run` requires the egress allowlist and a read token
    /// (docs/private-repositories.md).
    #[serde(default)]
    pub private: bool,
    /// No longer used, and accepted so that a bounds file naming it still
    /// reads: links to every public host are kept ([`crate::link_domains`]).
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// The output types apply publishes with agentic-job's own handlers
    /// rather than gh-aw's, of [`crate::contract::NATIVE_OUTPUTS`] and on
    /// GitHub. Empty by default: gh-aw's handlers publish every type.
    #[serde(default)]
    pub native_handlers: Vec<String>,
    /// Where the outputs are applied, and what only that forge has
    /// (#1393): exactly one of this, `forgejo` and `gitlab` is present,
    /// and [`Bounds::forge`] reads which. The forge comes from the
    /// caller's file, never from a request or a hand-back.
    #[serde(default = "Option::default")]
    pub github: Option<GithubBounds<Trigger>>,
    #[serde(default)]
    pub forgejo: Option<NeutralBounds>,
    #[serde(default)]
    pub gitlab: Option<NeutralBounds>,
}

/// Repository admission, with existing string globs retained for compatibility.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RepoRule {
    Pattern(String),
    Organization(Organization),
}

/// A live GitHub organization rule. Fork admission is deliberately not configurable.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Organization {
    pub org: String,
    pub forks: bool,
}

impl From<String> for RepoRule {
    fn from(pattern: String) -> Self {
        Self::Pattern(pattern)
    }
}

impl From<&str> for RepoRule {
    fn from(pattern: &str) -> Self {
        Self::Pattern(pattern.to_owned())
    }
}

impl std::fmt::Display for RepoRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pattern(pattern) => f.write_str(pattern),
            Self::Organization(rule) => write!(f, "{{org = {:?}, forks = false}}", rule.org),
        }
    }
}

/// `[github]`: every output type, and what only GitHub implements today.
/// `outputs` has no default, here or in the other sections: a section
/// that allows nothing is a caller's mistake.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubBounds<Trigger = toml::Table> {
    /// The output types a run may ask for, and the ceiling of each.
    pub outputs: GithubOutputs,
    /// Which events may start a run, and who may start one
    /// (`agentic-job event`). Absent, none may.
    #[serde(default = "Option::default")]
    pub trigger: Option<Trigger>,
    /// The agent's notes across runs (#119): `run` hands back `~/memory/`
    /// as `memory.json` and `check` holds it to these bounds. Absent, no
    /// memory is handed back, and `check` refuses one.
    #[serde(default)]
    pub memory: Option<Memory>,
    /// Repeated-test evidence beside a pull request's patch: `run` hands
    /// back `test-evidence.json` and its logs, `check` binds them to the
    /// checked patch and apply to the tree it applies. Absent, `check`
    /// refuses any.
    #[serde(default)]
    pub test_evidence: Option<TestEvidence>,
    /// One exact further repository a run may propose a pull request to
    /// (#1075). Kept apart from `repos`, which admits repositories to work
    /// on, so that admitting one is no permission to write to it. `check`
    /// holds it to these bounds, and apply.yml's `secondary-pull-request`
    /// opens it.
    #[serde(default)]
    pub secondary_pull_request: Option<SecondaryPullRequest>,
}

/// GitHub output limits and the caller's acceptance of repository CI execution.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GithubOutputs {
    /// Resolve a fork-side PR's replacement base through a same-author,
    /// same-head PR in its parent. This trusts that parent's history,
    /// including files outside the checked mails, on the fork's branch.
    #[serde(default, rename = "upstream-pull-request-base")]
    pub upstream_pull_request_base: bool,
    #[serde(default, rename = "own-branch-repos")]
    pub own_branch_repos: Vec<String>,
    #[serde(flatten)]
    pub types: BTreeMap<String, OutputLimit>,
}

/// `[forgejo]` or `[gitlab]`: output types of [`crate::NEUTRAL_OUTPUTS`]
/// alone, and the fork a pull request's branch goes to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeutralBounds {
    pub outputs: BTreeMap<String, OutputLimit>,
    /// The fork (OWNER/NAME) `apply` pushes a pull request's branch to,
    /// never the target repository: the target's CI then runs the agent's
    /// code as a fork's. Only the bounds name it, never a hand-back; it
    /// also lets a private run off GitHub open a pull request
    /// (docs/safe-outputs.md#publishing-to-forgejo and
    /// #publishing-to-gitlab).
    #[serde(default)]
    pub push_repo: Option<String>,
}

/// `[github.secondary_pull_request]`: its own repository, base, branches and
/// patch budget, none with a default, and its own exemptions, none
/// inherited from the primary output's: configuring it must not widen
/// what a patch to that repository may touch.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecondaryPullRequest {
    /// One exact OWNER/NAME, no glob.
    pub repo: String,
    /// One exact branch the pull request targets.
    pub base: String,
    /// What the pull request's branch name starts with, ending in `/`.
    pub branch_prefix: String,
    /// [`MAX_PULL_REQUESTS`]: one pull request, from one patch.
    pub max: u32,
    pub max_patch_bytes: u64,
    pub max_patch_files: u32,
    /// Exemptions for `repo` alone; empty by default.
    #[serde(default)]
    pub unprotected_files: Unprotected,
}

impl SecondaryPullRequest {
    fn validate(&self) -> Result<()> {
        check_secondary(
            &self.repo,
            &self.base,
            &self.branch_prefix,
            self.max,
            self.max_patch_bytes,
            self.max_patch_files,
        )?;
        for repo in &self.unprotected_files.repos {
            ensure!(
                repo.eq_ignore_ascii_case(&self.repo),
                "secondary_pull_request.unprotected_files.repos may name only {:?}, not {repo:?}",
                self.repo
            );
        }
        validate_dot_folders(
            &self.unprotected_files.dot_folders,
            "secondary_pull_request.unprotected_files.dot_folders",
        )
    }

    /// Its policy, cloned from HOST: protected files and dot-folders from
    /// its own exemptions alone, never the primary repository's. The
    /// bounds' `protected` globs only take away, so they hold here too.
    pub fn compile(&self, host: &str, protected_paths: &[String]) -> Secondary {
        Secondary {
            repo: self.repo.clone(),
            clone_url: format!("https://{host}/{}", self.repo),
            base: self.base.clone(),
            branch_prefix: self.branch_prefix.clone(),
            max: self.max,
            max_patch_bytes: self.max_patch_bytes,
            max_patch_files: self.max_patch_files,
            protected_files: protected_files(&self.unprotected_files, &self.repo),
            protect_top_level_dot_folders: true,
            unprotected_dot_folders: dot_folders(&self.unprotected_files, &self.repo),
            protected_paths: protected_paths.to_vec(),
        }
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

impl<Trigger> Bounds<Trigger> {
    /// The sections present, by name, in the order the forges are listed.
    fn sections(&self) -> Vec<&'static str> {
        [
            ("github", self.github.is_some()),
            ("forgejo", self.forgejo.is_some()),
            ("gitlab", self.gitlab.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, present)| present.then_some(name))
        .collect()
    }

    /// The forge the section present names. GitHub where there is none,
    /// which [`Self::validate`] refuses, and where [`Self::outputs`] then
    /// allows nothing.
    pub fn forge(&self) -> Forge {
        if self.forgejo.is_some() {
            Forge::Forgejo
        } else if self.gitlab.is_some() {
            Forge::Gitlab
        } else {
            Forge::Github
        }
    }

    /// The `[forgejo]` or `[gitlab]` section.
    fn neutral(&self) -> Option<&NeutralBounds> {
        self.forgejo.as_ref().or(self.gitlab.as_ref())
    }

    /// The section's output types and the ceiling of each, whichever
    /// forge it names; none without a section.
    pub fn outputs(&self) -> &BTreeMap<String, OutputLimit> {
        static NONE: BTreeMap<String, OutputLimit> = BTreeMap::new();
        match (&self.github, self.neutral()) {
            (Some(github), _) => &github.outputs.types,
            (None, Some(neutral)) => &neutral.outputs,
            (None, None) => &NONE,
        }
    }

    /// [`Self::outputs`], to change; `None` without a section.
    pub fn outputs_mut(&mut self) -> Option<&mut BTreeMap<String, OutputLimit>> {
        if let Some(github) = &mut self.github {
            return Some(&mut github.outputs.types);
        }
        let neutral = self.forgejo.as_mut().or(self.gitlab.as_mut());
        neutral.map(|neutral| &mut neutral.outputs)
    }

    /// `[github.trigger]`.
    pub fn trigger(&self) -> Option<&Trigger> {
        self.github.as_ref()?.trigger.as_ref()
    }

    /// `[github.memory]`.
    pub fn memory(&self) -> Option<&Memory> {
        self.github.as_ref()?.memory.as_ref()
    }

    /// `[github.test_evidence]`.
    pub fn test_evidence(&self) -> Option<&TestEvidence> {
        self.github.as_ref()?.test_evidence.as_ref()
    }

    /// `[github.secondary_pull_request]`.
    pub fn secondary_pull_request(&self) -> Option<&SecondaryPullRequest> {
        self.github.as_ref()?.secondary_pull_request.as_ref()
    }

    /// The `push_repo` of `[forgejo]` or `[gitlab]`.
    pub fn push_repo(&self) -> Option<&str> {
        self.neutral()?.push_repo.as_deref()
    }

    /// A bounds file that bounds nothing, or asks for what cannot be, is
    /// the caller's mistake and not a request to refuse.
    pub fn validate(&self) -> Result<()> {
        // The section names the forge, so exactly one: none cannot say
        // where outputs are applied, and two disagree.
        match self.sections()[..] {
            [] => bail!("no forge section: add [github], [forgejo] or [gitlab]"),
            [_] => {}
            [first, second, ..] => bail!(
                "the sections [{first}] and [{second}] are both present: exactly one forge \
                 per bounds file"
            ),
        }
        let forge = self.forge();
        let outputs = self.outputs();
        if let Some(github) = &self.github {
            crate::contract::validate_own_branch_repos(&github.outputs.own_branch_repos)?;
        }
        for (name, list) in [("hosts", &self.hosts), ("bases", &self.bases)] {
            ensure!(!list.is_empty(), "`{name}` is empty, so no run is allowed");
        }
        ensure!(
            !self.repos.is_empty(),
            "`repos` is empty, so no run is allowed"
        );
        for host in &self.allow_http {
            ensure!(
                self.hosts.iter().any(|own| own.eq_ignore_ascii_case(host)),
                "allow_http names {host:?}, which is not in `hosts`"
            );
            ensure!(
                !under(&host_name(host), NEVER_PLAIN_HTTP),
                "allow_http may not name {host:?}: {NEVER_PLAIN_HTTP} serves https"
            );
        }
        let has_org = self
            .repos
            .iter()
            .any(|rule| matches!(rule, RepoRule::Organization(_)));
        for rule in &self.repos {
            match rule {
                RepoRule::Pattern(pattern) => {
                    glob(pattern).with_context(|| format!("the glob {pattern:?}"))?;
                    ensure!(
                        !has_org
                            || (REPO_RE.is_match(pattern)
                                && !pattern.contains('*')
                                && !dotted(pattern)),
                        "organization repos rules may be combined only with exact repository entries, not {pattern:?}"
                    );
                }
                RepoRule::Organization(rule) => {
                    ensure!(
                        forge == Forge::Github
                            && self
                                .hosts
                                .iter()
                                .all(|host| host.eq_ignore_ascii_case("github.com")),
                        "organization repos rules require GitHub and hosts = [\"github.com\"]"
                    );
                    ensure!(
                        !rule.forks,
                        "organization repos rules require forks = false"
                    );
                    ensure!(
                        REPO_RE.is_match(&format!("{}/repo", rule.org))
                            && !rule.org.starts_with(['.', '-']),
                        "invalid repository organization {:?}",
                        rule.org
                    );
                }
            }
        }
        for pattern in &self.bases {
            glob(pattern).with_context(|| format!("the glob {pattern:?}"))?;
        }
        ensure!(!outputs.is_empty(), "`outputs` lists no output type");
        forge.check_outputs(outputs.keys().map(String::as_str))?;
        for (output, limit) in outputs {
            limit.validate(output)?;
            ensure!(
                limit.own_author.is_none() || forge == Forge::Github,
                "outputs.{output}: own_author is supported only on GitHub"
            );
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
        if let Some(push_repo) = self.push_repo() {
            ensure!(
                REPO_RE.is_match(push_repo) && !dotted(push_repo) && !push_repo.ends_with(".git"),
                "push_repo requires an exact repository name: {push_repo:?}"
            );
        }
        // Apply off GitHub opens a pull request only from the fork the
        // bounds name: without one, they would admit a run whose patch
        // apply then refuses.
        ensure!(
            self.neutral().is_none()
                || self.push_repo().is_some()
                || !outputs.contains_key(CREATE_PULL_REQUEST),
            "a [{}] section allowing {CREATE_PULL_REQUEST} must name push_repo: apply \
             pushes a pull request's branch only to the fork it names",
            forge.name()
        );
        if let Some(memory) = self.memory() {
            memory.validate()?;
        }
        if let Some(evidence) = self.test_evidence() {
            evidence.validate()?;
        }
        // Only `[github]` holds one, so it is GitHub's; apply off GitHub
        // pushes to `push_repo` alone.
        if let Some(secondary) = self.secondary_pull_request() {
            secondary.validate()?;
        }
        check_native_handlers(&self.native_handlers, forge, |output| {
            outputs.contains_key(output)
        })?;
        check_comment_on_duplicate(outputs.get("create_issue"), &self.native_handlers)?;
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
        validate_protected(&self.protected, "protected")?;
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

    /// Why `url` may not be cloned as `repo`, if it may not. The URL must
    /// name that repository on a host of the bounds and nothing more, so
    /// that the bounds on the repository are bounds on what is cloned.
    pub fn clone_url_problem(&self, url: &str, repo: &str) -> Option<String> {
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
        if plain && !allows_http(&self.allow_http, host) {
            return Some(format!(
                "clone URL {url:?} is plain http://, which the bounds' allow_http does not \
                 name its host for"
            ));
        }
        let path = path.strip_suffix(".git").unwrap_or(path);
        (!path.eq_ignore_ascii_case(repo))
            .then(|| format!("clone URL {url:?} does not name the repository {repo:?}"))
    }
}

/// The host name of an HTTP authority (`user@HOST:port`, as `hosts`,
/// `allow_http` and a clone URL spell one), in lowercase and without its
/// root dot. The bounds match authorities exactly, port included, but
/// who answers for `github.com` does not change with a port or a user:
/// what refuses GitHub by name compares this, so `github.com:80` cannot be
/// cloned over plain HTTP and `github.com:443` is not off GitHub.
pub fn host_name(authority: &str) -> String {
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    // A bracketed IPv6 literal has colons of its own; cut there, it is no
    // name at all, which is all the comparisons below ask of it.
    let host = host.split_once(':').map_or(host, |(host, _)| host);
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether a lowercase host name is `domain` or a host under it.
pub fn under(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// The protected file names for a patch to `repo`, under UNPROTECTED.
pub fn protected_files(unprotected: &Unprotected, repo: &str) -> Vec<String> {
    let exempt = unprotected
        .repos
        .iter()
        .any(|own| own.eq_ignore_ascii_case(repo));
    DEFAULT_PROTECTED_FILES
        .iter()
        .filter(|name| !(exempt && unprotected.files.iter().any(|file| file.as_str() == **name)))
        .map(|name| (*name).to_owned())
        .collect()
}

/// The dot-folders UNPROTECTED exempts for a patch to `repo`.
pub fn dot_folders(unprotected: &Unprotected, repo: &str) -> Vec<String> {
    if unprotected
        .repos
        .iter()
        .any(|own| own.eq_ignore_ascii_case(repo))
    {
        unprotected.dot_folders.clone()
    } else {
        Vec::new()
    }
}

/// Both files' `protected` globs: each only adds protection. Their union
/// is held to the one file's limit, which `check` holds the policy to.
fn union(mut own: Vec<String>, other: Vec<String>) -> Result<Vec<String>, Vec<String>> {
    for pattern in other {
        if !own.contains(&pattern) {
            own.push(pattern);
        }
    }
    if own.len() > MAX_PROTECTED_GLOBS {
        return Err(vec![format!(
            "the bounds files protect {} globs together, over {MAX_PROTECTED_GLOBS}",
            own.len()
        )]);
    }
    Ok(own)
}

/// Intersect compiled policies rather than trying to intersect glob patterns.
/// Each file independently checks the target and any explicitly requested type.
pub fn intersect(mut policy: Policy, other: Policy) -> Result<Policy, Vec<String>> {
    if policy.advisory != other.advisory {
        return Err(vec![
            "bounds policies disagree on advisory publication".into(),
        ]);
    }
    policy
        .allow_http
        .retain(|host| allows_http(&other.allow_http, host));
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
    // Test evidence likewise.
    policy.test_evidence = match (policy.test_evidence, other.test_evidence) {
        (Some(own), Some(bound)) => Some(TestEvidence {
            max_attempts: own.max_attempts.min(bound.max_attempts),
            max_log_bytes: own.max_log_bytes.min(bound.max_log_bytes),
        }),
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
    policy.safe_outputs.upstream_pull_request_base &= other.safe_outputs.upstream_pull_request_base;
    // Keep each caller's patterns separate: a repository must match both,
    // not their union. No glob-pattern intersection is needed.
    if policy.safe_outputs.own_branch_repos.is_empty()
        || other.safe_outputs.own_branch_repos.is_empty()
    {
        policy.safe_outputs.own_branch_repos.clear();
    } else {
        policy
            .safe_outputs
            .own_branch_repos
            .extend(other.safe_outputs.own_branch_repos);
    }
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
            // Both files must set it, and so both route create_issue to
            // agentic-job's handler, which `validate` requires of each.
            limit.comment_on_duplicate &= bound.comment_on_duplicate;
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
            pr.protected_paths = union(pr.protected_paths, bound.protected_paths)?;
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
        (Some(push), Some(bound))
            if push
                .author
                .as_ref()
                .zip(bound.author.as_ref())
                .is_some_and(|(own, other)| !own.eq_ignore_ascii_case(other)) =>
        {
            return Err(vec![format!(
                "the bounds files admit the push by different authors: {:?} and {:?}",
                push.author, bound.author
            )]);
        }
        (Some(mut push), Some(bound)) => {
            // Where either file admitted the repository only by the pull
            // request's author, apply checks that author again.
            push.author = push.author.or_else(|| bound.author.clone());
            push.unprotected_dot_folders
                .retain(|name| bound.unprotected_dot_folders.contains(name));
            push.replacement_max_commits = push
                .replacement_max_commits
                .min(bound.replacement_max_commits);
            // Each file's own total, its `max_patch_files` where it sets
            // none; zero again where that is all the tighter one is.
            let replacement_files = push.replacement_files().min(bound.replacement_files());
            push.ready_when_complete &= bound.ready_when_complete;
            push.max_patch_size = push.max_patch_size.min(bound.max_patch_size);
            push.max_patch_files = push.max_patch_files.min(bound.max_patch_files);
            push.replacement_max_files = if replacement_files == push.max_patch_files {
                0
            } else {
                replacement_files
            };
            for name in bound.protected_files {
                if !push.protected_files.contains(&name) {
                    push.protected_files.push(name);
                }
            }
            push.protected_paths = union(push.protected_paths, bound.protected_paths)?;
            Some(push)
        }
        _ => None,
    };
    // Only where both files name the one destination alike, within the
    // tighter of each budget and the exemptions both make.
    policy.secondary_pull_request =
        match (policy.secondary_pull_request, other.secondary_pull_request) {
            (Some(mut own), Some(bound))
                if (&own.repo, &own.clone_url, &own.base, &own.branch_prefix)
                    == (
                        &bound.repo,
                        &bound.clone_url,
                        &bound.base,
                        &bound.branch_prefix,
                    ) =>
            {
                own.max = own.max.min(bound.max);
                own.max_patch_bytes = own.max_patch_bytes.min(bound.max_patch_bytes);
                own.max_patch_files = own.max_patch_files.min(bound.max_patch_files);
                own.unprotected_dot_folders
                    .retain(|name| bound.unprotected_dot_folders.contains(name));
                for name in bound.protected_files {
                    if !own.protected_files.contains(&name) {
                        own.protected_files.push(name);
                    }
                }
                own.protected_paths = union(own.protected_paths, bound.protected_paths)?;
                Some(own)
            }
            _ => None,
        }
        .filter(|_| policy.safe_outputs.create_pull_request.is_some());
    // gh-aw's handlers unless both files route a type, and the type is
    // still allowed.
    policy.native_handlers.retain(|output| {
        other.native_handlers.contains(output) && policy.safe_outputs.max_of(output).is_some()
    });
    if policy.safe_outputs.types().next().is_none() {
        return Err(vec!["the bounds files allow no common output type".into()]);
    }
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::fixtures::{policy, push_policy};

    const BOUNDS: &str = r#"
hosts = ["github.com"]
repos = ["bootc-dev/*"]
bases = ["main"]
max_outputs = 5
max_patch_bytes = 8388608
max_patch_files = 100

[github.outputs]
create_pull_request = { max = 1 }
noop = { max = 1 }

[github.trigger]
events = ["issues"]
"#;

    /// [`BOUNDS`]' top-level keys, without its section.
    fn neutral() -> String {
        format!("{}\n", BOUNDS.split("\n[github.").next().unwrap())
    }

    /// Parsed and validated, or the error of either, as text.
    fn validated(text: &str) -> Result<Bounds, String> {
        let bounds: Bounds = toml::from_str(text).map_err(|e| e.to_string())?;
        bounds.validate().map_err(|e| format!("{e:#}"))?;
        Ok(bounds)
    }

    #[test]
    fn bounds_parse_and_carry_the_callers_trigger_unread() {
        let bounds: Bounds = toml::from_str(BOUNDS).unwrap();
        bounds.validate().unwrap();
        let trigger = bounds.trigger().unwrap();
        assert_eq!(trigger["events"][0].as_str(), Some("issues"));
        assert_eq!(
            bounds.clone_url_problem("https://github.com/bootc-dev/bootc.git", "bootc-dev/bootc"),
            None
        );
        assert!(
            bounds
                .clone_url_problem("http://github.com/bootc-dev/bootc", "bootc-dev/bootc")
                .is_some()
        );
        // A refusal for each: what bounds nothing or cannot be.
        for (change, want) in [
            ("hosts = []", "`hosts` is empty"),
            (
                "allow_http = [\"github.com\"]",
                "allow_http may not name \"github.com\"",
            ),
            ("max_patch_bytes = 10", "`max_patch_bytes` must be at least"),
        ] {
            let key = change.split(' ').next().unwrap();
            let text: String = BOUNDS
                .lines()
                .filter(|line| !line.starts_with(&format!("{key} ")))
                .map(|line| format!("{line}\n"))
                .collect::<String>()
                .replacen('\n', &format!("\n{change}\n"), 1);
            let bounds: Bounds = toml::from_str(&text).unwrap();
            let error = format!("{:#}", bounds.validate().unwrap_err());
            assert!(error.contains(want), "{change}: {error}");
        }
        assert!(toml::from_str::<Bounds>(&format!("unknown = 1\n{BOUNDS}")).is_err());
    }

    /// The one section present selects the forge, and holds its outputs
    /// and what only that forge has (#1393).
    #[test]
    fn each_section_selects_its_forge() {
        // The section, the forge, its push_repo, and whether it has a
        // trigger, memory and a secondary pull request.
        for (section, forge, push_repo, github_only) in [
            (
                "[github.outputs]\ncreate_pull_request = { max = 1 }\n\
                 link_sub_issue = { max = 1 }\n\
                 [github.trigger]\nevents = [\"issues\"]\n[github.memory]\n\
                 [github.secondary_pull_request]\nrepo = \"cgwalters-forge/misctool\"\n\
                 base = \"main\"\nbranch_prefix = \"agentic-job/\"\nmax = 1\n\
                 max_patch_bytes = 65536\nmax_patch_files = 10\n",
                Forge::Github,
                None,
                true,
            ),
            (
                "[forgejo]\npush_repo = \"bot/bootc\"\n\
                 [forgejo.outputs]\ncreate_pull_request = { max = 1 }\nnoop = { max = 1 }\n",
                Forge::Forgejo,
                Some("bot/bootc"),
                false,
            ),
            (
                "[forgejo.outputs]\nadd_comment = { max = 1 }\nnoop = { max = 1 }\n",
                Forge::Forgejo,
                None,
                false,
            ),
            (
                "[gitlab.outputs]\nadd_comment = { max = 1 }\nnoop = { max = 1 }\n",
                Forge::Gitlab,
                None,
                false,
            ),
            (
                "[gitlab]\npush_repo = \"bot/bootc\"\n\
                 [gitlab.outputs]\ncreate_pull_request = { max = 1 }\nnoop = { max = 1 }\n",
                Forge::Gitlab,
                Some("bot/bootc"),
                false,
            ),
        ] {
            let bounds = validated(&format!("{}{section}", neutral()))
                .unwrap_or_else(|e| panic!("{section}: {e}"));
            assert_eq!(bounds.forge(), forge, "{section}");
            assert_eq!(bounds.outputs().len(), 2, "{section}");
            assert_eq!(bounds.push_repo(), push_repo, "{section}");
            for present in [
                bounds.trigger().is_some(),
                bounds.memory().is_some(),
                bounds.secondary_pull_request().is_some(),
            ] {
                assert_eq!(present, github_only, "{section}");
            }
        }
    }

    /// What a bounds file may not say about its forge: each refusal, and
    /// a part of its message.
    #[test]
    fn forge_sections_are_refused() {
        let neutral = neutral();
        let noop = "noop = { max = 1 }\n";
        for (name, text, want) in [
            ("no section", neutral.clone(), "no forge section"),
            (
                "two sections",
                format!("{neutral}[github.outputs]\n{noop}[forgejo.outputs]\n{noop}"),
                "the sections [github] and [forgejo] are both present",
            ),
            (
                "three sections",
                format!(
                    "{neutral}[github.outputs]\n{noop}[forgejo.outputs]\n{noop}\
                     [gitlab.outputs]\n{noop}"
                ),
                "exactly one forge per bounds file",
            ),
            (
                "a section without outputs",
                format!("{neutral}[gitlab]\n"),
                "missing field `outputs`",
            ),
            (
                "a section with empty outputs",
                format!("{neutral}[gitlab.outputs]\n"),
                "`outputs` lists no output type",
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
                format!(
                    "{neutral}[secondary_pull_request]\nrepo = \"a/b\"\n[github.outputs]\n{noop}"
                ),
                "unknown field `secondary_pull_request`",
            ),
            (
                "an unknown key in [github]",
                format!("{neutral}[github]\npush_repo = \"bot/bootc\"\n[github.outputs]\n{noop}"),
                "unknown field `push_repo`",
            ),
            (
                "a trigger in [forgejo]",
                format!("{neutral}[forgejo.trigger]\n[forgejo.outputs]\n{noop}"),
                "unknown field `trigger`",
            ),
            (
                "memory in [forgejo]",
                format!("{neutral}[forgejo.memory]\n[forgejo.outputs]\n{noop}"),
                "unknown field `memory`",
            ),
            (
                "a secondary pull request in [gitlab]",
                format!("{neutral}[gitlab.secondary_pull_request]\n[gitlab.outputs]\n{noop}"),
                "unknown field `secondary_pull_request`",
            ),
            (
                "a GitLab merge request without its fork",
                format!("{neutral}[gitlab.outputs]\ncreate_pull_request = {{ max = 1 }}\n"),
                "a [gitlab] section allowing create_pull_request must name push_repo",
            ),
            (
                "a GitHub-only type in [forgejo]",
                format!("{neutral}[forgejo.outputs]\nlink_sub_issue = {{ max = 1 }}\n"),
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
                "a [forgejo] section allowing create_pull_request must name push_repo",
            ),
            (
                "a [github] section without outputs",
                format!("{neutral}[github.trigger]\nevents = [\"issues\"]\n"),
                "missing field `outputs`",
            ),
            (
                "a [forgejo] section without outputs",
                format!("{neutral}[forgejo]\npush_repo = \"bot/bootc\"\n"),
                "missing field `outputs`",
            ),
            (
                "a Forgejo fork that is no exact name",
                format!("{neutral}[forgejo]\npush_repo = \"bot/..\"\n[forgejo.outputs]\n{noop}"),
                "push_repo requires an exact repository name",
            ),
        ] {
            let error = validated(&text).map(|_| ()).unwrap_err();
            assert!(error.contains(want), "{name}: {error}");
        }
    }

    /// Two files' `protected` globs together are held to one file's limit.
    #[test]
    fn protected_globs_union_within_one_files_limit() {
        let half: Vec<String> = (0..MAX_PROTECTED_GLOBS)
            .map(|i| format!("a{i}/**"))
            .collect();
        let other: Vec<String> = (0..MAX_PROTECTED_GLOBS)
            .map(|i| format!("b{i}/**"))
            .collect();
        assert!(union(half.clone(), half.clone()).is_ok());
        assert!(union(half, other).unwrap_err()[0].contains("over 64"));
    }

    /// What an organization's bounds refuse rather than intersect, and
    /// what they tighten.
    #[test]
    fn organization_bounds_intersect_or_refuse() {
        let own = policy();
        let mut tighter = policy();
        tighter.max_outputs = 1;
        tighter
            .safe_outputs
            .create_pull_request
            .as_mut()
            .unwrap()
            .protected_paths = vec!["raw/**".into()];
        let both = intersect(own.clone(), tighter).unwrap();
        assert_eq!(both.max_outputs, 1);
        assert_eq!(
            both.safe_outputs
                .create_pull_request
                .unwrap()
                .protected_paths,
            ["raw/**"]
        );

        let with = |base: Policy, change: &dyn Fn(&mut Policy)| {
            let mut changed = base;
            change(&mut changed);
            changed
        };
        let authored = |author: &str| {
            with(policy(), &|policy| {
                policy.commit_author = Some(author.into())
            })
        };
        let moved = with(push_policy(), &|policy| {
            policy
                .safe_outputs
                .push_to_pull_request_branch
                .as_mut()
                .unwrap()
                .head = "3333333333333333333333333333333333333333".into();
        });
        let pushed_by = |author: &str| {
            with(push_policy(), &|policy| {
                policy
                    .safe_outputs
                    .push_to_pull_request_branch
                    .as_mut()
                    .unwrap()
                    .author = Some(author.into())
            })
        };
        // A file that admitted the push only by its author keeps apply's
        // check of that author, whichever file it is.
        for (own, other) in [
            (pushed_by("bot"), push_policy()),
            (push_policy(), pushed_by("bot")),
            (pushed_by("bot"), pushed_by("Bot")),
        ] {
            let both = intersect(own, other).unwrap();
            let push = both.safe_outputs.push_to_pull_request_branch.unwrap();
            assert!(push.author.unwrap().eq_ignore_ascii_case("bot"));
        }
        // The name, the two policies, and the refusal.
        for (name, own, other, want) in [
            (
                "another forge",
                policy(),
                with(policy(), &|other| other.forge = Forge::Forgejo),
                "the bounds files name different forges",
            ),
            (
                "another commit author",
                authored("Agent <a@example.com>"),
                authored("Other <o@example.com>"),
                "the bounds files pin different commit authors",
            ),
            (
                "another push",
                push_policy(),
                moved,
                "the bounds files pin different pushes",
            ),
            (
                "another push author",
                pushed_by("bot"),
                pushed_by("other"),
                "the bounds files admit the push by different authors",
            ),
            (
                "no common output type",
                policy(),
                with(policy(), &|other| {
                    other.safe_outputs.create_pull_request = None;
                    other.safe_outputs.others.clear();
                }),
                "the bounds files allow no common output type",
            ),
        ] {
            let errors = intersect(own, other).unwrap_err();
            assert!(errors[0].contains(want), "{name}: {errors:?}");
        }
    }
}
