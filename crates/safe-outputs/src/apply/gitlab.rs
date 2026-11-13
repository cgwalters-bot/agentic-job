//! [`Publisher`] for GitLab, through its REST API v4: a note on the
//! caller's issue or merge request, and a merge request from a branch
//! pushed over git to the fork the bounds name, opened on the fork with
//! the repository as its `target_project_id`. Never a branch of the
//! repository itself, for the reason Forgejo's publisher gives, unless the
//! caller's `own-branch-repos` bounds accept the repository's CI running
//! it: then a branch neither its default nor a protected one. Also an
//! issue, labels added to or removed from an issue or a merge request,
//! and one closed with a note saying why; a commit pushed on the branch of
//! the policy's merge request, in that fork, under a lease on the head the
//! run was asked for; and the caller's commit status.
//!
//! GitLab numbers issues and merge requests apart within a project (`#5`
//! and `!5`, each an `iid`), so a note's target kind is the caller's
//! (`--comment-target-kind`), and a label change's or a closing's is its
//! request's target field, never guessed from the number. A project is
//! read by its URL-encoded path, its answer held to that path, and then
//! written to by the ID read, so that a project renamed or moved away is
//! not written to.
//!
//! GitLab creates a label it is given and lacks, so every label is looked
//! for among the project's (its groups' included) by its exact name before
//! any write, and again just before its own; apply creates none. A label
//! is added only where the item lacks it and removed only where it has it,
//! and closing writes nothing to an item closed or merged already, so a
//! re-run changes nothing more.
//!
//! The text is filtered before it gets here ([`super::mentions`]):
//! GitLab's mentions, `@all` and `@here` among them, and its quick
//! actions, a line starting with `/` that GitLab would run with the
//! token's rights.
//!
//! The token goes in one header, `Authorization: Bearer`, never a URL or
//! an argument; git gets it as `oauth2` over Basic through its
//! environment, and every error is scrubbed of it.

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};

use super::forgejo::{self, Api, PUT};
use super::git::{Git, Push};
use super::{
    BranchPush, Close, CommitStatus, Committer, Kind, LabelChange, Made, NewIssue, Op, Publisher,
    PullRequest, State,
};

const GET: &str = "GET";
const POST: &str = "POST";

/// The user git sends a token as: GitLab takes any for an access token,
/// and this one for an OAuth token.
const GIT_USER: &str = "oauth2";

/// Labels asked for a page: GitLab's most.
const LABELS_PER_PAGE: usize = 100;

/// The most pages of a project's labels read: one with more than two
/// thousand is refused rather than read without end.
const MAX_LABEL_PAGES: usize = 20;

/// Protected branch rules asked for a page, and the most pages read.
const PROTECTED_PER_PAGE: usize = 100;
const MAX_PROTECTED_PAGES: usize = 20;

const DIFFS_PER_PAGE: usize = 100;
const MAX_DIFF_PAGES: usize = 20;

/// What separates a scoped label's scope from its value: GitLab keeps one
/// label of a scope on an item, and removes its other when adding one.
const SCOPE: &str = "::";

/// An item's state that GitLab takes no closing for: done already.
const DONE: &[&str] = &["closed", "merged"];

const OPENED: &str = "opened";

/// A commit's latest statuses of the caller's context asked for, one a
/// ref: GitLab's most a page.
const STATUSES_PER_PAGE: usize = 100;

/// Refuse rather than make unbounded reads in the credentialed publisher.
const MAX_STATUS_PAGES: usize = 20;

/// GitLab's commit status state for STATE. It has no `error`, and a run
/// that could not finish did not pass, so that is `failed` too, never
/// `canceled` or `skipped`, which a merge check may let through.
fn status_state(state: State) -> &'static str {
    match state {
        State::Pending => "pending",
        State::Success => "success",
        State::Failure | State::Error => "failed",
    }
}

pub struct Gitlab {
    /// `SERVER/api/v4`.
    api: String,
    /// `SERVER`, under which git finds a project as `PATH.git`.
    git: String,
    /// The project published to: the policy's, which it has checked.
    repo: String,
    token: String,
    /// As Forgejo's: the fork-push role's token for git, else `token`.
    push_token: Option<String>,
    /// In role mode, the numeric actor the caller bound this token to:
    /// a status a rerun takes as already set must be that actor's.
    owner: Option<u64>,
    http: ureq::Agent,
    recover_pushed_commit: Option<String>,
    /// What the caller's comment target is.
    comment_kind: Option<Kind>,
    /// Trusted deployment context, never taken from the checked JSONL.
    status_context: Option<(String, u64)>,
    /// Whether the caller's bounds accept a branch of the project itself.
    own_branches: bool,
}

/// What GitLab says of a project, as far as a push to it needs.
#[derive(Debug, Clone)]
struct Project {
    id: u64,
    path: String,
    /// Readable by its members only.
    private: bool,
    /// Readable by anyone, signed in or not.
    public: bool,
    /// The ID of what it is a fork of.
    forked_from: Option<u64>,
    /// None for a project with no commit yet.
    default_branch: Option<String>,
}

/// Whether GitLab's protected branch RULE, where `*` is any text, `/`
/// included, names BRANCH: a rule too large to read protects everything.
fn protects(rule: &str, branch: &str) -> bool {
    let parts: Vec<String> = rule.split('*').map(regex::escape).collect();
    match regex::Regex::new(&format!("^{}$", parts.join(".*"))) {
        Ok(rule) => rule.is_match(branch),
        Err(_) => true,
    }
}

/// PATH as one path segment: every byte but a letter, digit or `-._~`
/// encoded, `/` included, as GitLab names a project by its path.
fn encoded(path: &str) -> String {
    path.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// The API's name for the items of KIND under a project.
fn collection(kind: Kind) -> &'static str {
    match kind {
        Kind::Issue => "issues",
        Kind::PullRequest => "merge_requests",
    }
}

/// What NUMBER of KIND is called on GitLab.
fn reference(kind: Kind, number: u64) -> String {
    match kind {
        Kind::Issue => format!("#{number}"),
        Kind::PullRequest => format!("!{number}"),
    }
}

/// What GitLab says of an issue or a merge request of the project.
#[derive(Debug)]
struct Item {
    /// The project's ID, which a write goes to.
    project: u64,
    url: String,
    /// `opened`, `closed`, or a merge request's `merged` or `locked`.
    state: String,
    /// Its labels' names.
    labels: Vec<String>,
}

/// LABELS read out of an answer: names, as GitLab gives an item's, or
/// objects with a `name`, as it gives a project's.
fn label_names(labels: &Value) -> Option<Vec<String>> {
    labels
        .as_array()?
        .iter()
        .map(|label| {
            label
                .as_str()
                .or_else(|| label["name"].as_str())
                .map(str::to_owned)
        })
        .collect()
}

/// A scoped label's scope.
fn scope(name: &str) -> Option<&str> {
    name.rsplit_once(SCOPE)
        .map(|(scope, _)| scope)
        .filter(|scope| !scope.is_empty())
}

/// Refuses LABELS when two share a scope: GitLab would keep only one.
fn one_of_each_scope(labels: &[String]) -> Result<()> {
    for (i, label) in labels.iter().enumerate() {
        if let Some(shared) = scope(label)
            && let Some(other) = labels[i + 1..]
                .iter()
                .find(|other| scope(other) == Some(shared))
        {
            bail!("labels {label:?} and {other:?} share the scope {shared:?}");
        }
    }
    Ok(())
}

/// NAMES as GitLab takes a list of labels: separated by commas, which no
/// label of GitLab's has.
fn joined(names: &[String]) -> Result<String> {
    if let Some(name) = names.iter().find(|name| name.contains(',')) {
        bail!("label {name:?} has a comma, which GitLab reads as two labels");
    }
    Ok(names.join(","))
}

impl Gitlab {
    /// Resolve by repository path, then hold the MR to that project's ID.
    /// Issues with a colliding iid are never consulted.
    fn inline_target(
        &self,
        comment: &super::inline::InlineComment,
    ) -> Result<(u64, String, Value)> {
        let target = &comment.target;
        ensure!(
            target.repo.eq_ignore_ascii_case(&self.repo),
            "foreign inline target"
        );
        let project = self.project(&self.repo)?;
        let path = format!("/projects/{}/merge_requests/{}", project.id, target.number);
        let answer = self.request(GET, &path, None)?;
        ensure!(
            answer["iid"].as_u64() == Some(target.number)
                && answer["project_id"].as_u64() == Some(project.id)
                && answer["target_project_id"].as_u64() == Some(project.id),
            "inline target is not a merge request of {}",
            self.repo
        );
        ensure!(answer["state"] == OPENED, "inline target is not open");
        ensure!(answer["sha"] == target.head, "inline target head is stale");
        let refs = &answer["diff_refs"];
        for key in ["base_sha", "start_sha", "head_sha"] {
            ensure!(
                refs[key]
                    .as_str()
                    .is_some_and(|sha| super::COMMIT_RE.is_match(sha)),
                "inline target lacks diff_refs {key}"
            );
        }
        ensure!(refs["head_sha"] == target.head, "inline diff head is stale");
        let url = answer["web_url"]
            .as_str()
            .context("inline target has no web_url")?;
        Ok((project.id, url.to_owned(), refs.clone()))
    }

    fn inline_position(
        &self,
        comment: &super::inline::InlineComment,
    ) -> Result<(u64, String, Value)> {
        let (project, url, refs) = self.inline_target(comment)?;
        let mut found = None;
        let mut complete = false;
        for page in 1..=MAX_DIFF_PAGES {
            let path = format!(
                "/projects/{project}/merge_requests/{}/diffs?page={page}&per_page={DIFFS_PER_PAGE}",
                comment.target.number
            );
            let answer = self.request(GET, &path, None)?;
            let files = answer
                .as_array()
                .context("MR diffs response is not an array")?;
            ensure!(
                files.len() <= DIFFS_PER_PAGE,
                "MR diff page exceeds its limit"
            );
            for file in files {
                let old = file["old_path"].as_str().context("diff has no old_path")?;
                let new = file["new_path"].as_str().context("diff has no new_path")?;
                if new != comment.path {
                    continue;
                }
                ensure!(found.is_none(), "ambiguous file in diff");
                ensure!(
                    file["too_large"] != true && file["collapsed"] != true,
                    "inline file diff is unavailable"
                );
                let patch = file["diff"].as_str().context("inline file has no diff")?;
                let line = super::inline::position(patch, comment)?;
                let mut position = json!({"position_type": "text",
                    "base_sha": refs["base_sha"], "start_sha": refs["start_sha"],
                    "head_sha": refs["head_sha"], "old_path": old, "new_path": new});
                if let Some(old) = line.old {
                    position["old_line"] = old.into();
                }
                if let Some(new) = line.new {
                    position["new_line"] = new.into();
                }
                found = Some(position);
            }
            if files.len() < DIFFS_PER_PAGE {
                complete = true;
                break;
            }
        }
        ensure!(complete, "MR has more diff pages than apply reads");
        let position = found.context("inline comment file is absent from the diff")?;
        let (current_project, _, current_refs) = self.inline_target(comment)?;
        ensure!(
            current_project == project && current_refs == refs,
            "inline diff changed while reading"
        );
        Ok((project, url, position))
    }

    /// SERVER is GitLab's address, `https://gitlab.example` or one under a
    /// path; REPO the policy's project path, which it has checked.
    pub fn new(server: &str, repo: &str, token: String, allow_http: &[String]) -> Result<Self> {
        let server = forgejo::server(server, allow_http)?;
        Ok(Self {
            api: format!("{server}/api/v4"),
            git: server.to_owned(),
            repo: repo.to_owned(),
            token,
            push_token: None,
            owner: None,
            http: forgejo::agent(),
            recover_pushed_commit: None,
            comment_kind: None,
            status_context: None,
            own_branches: false,
        })
    }

    /// Whether the caller's checked bounds accept a branch of the project
    /// itself (`own-branch-repos`): never the hand-back's to say.
    pub fn accepting_own_branches(mut self, accepted: bool) -> Self {
        self.own_branches = accepted;
        self
    }

    /// Only the trusted deployment may supply this, never agent output.
    pub fn recovering(mut self, recover: Option<String>) -> Self {
        self.recover_pushed_commit = recover;
        self
    }

    /// As [`forgejo::Forgejo::pushing_with`].
    pub fn pushing_with(mut self, token: Option<String>) -> Self {
        self.push_token = token;
        self
    }

    /// The caller's numeric actor for this token, in role mode: a status
    /// another account set is not this run's, whatever it says.
    pub fn owned_by(mut self, actor: Option<u64>) -> Self {
        self.owner = actor;
        self
    }

    /// Every form of either token an error could hold: as sent to the API,
    /// URL-encoded, and as git's Basic credential.
    fn secrets(&self) -> Vec<String> {
        let mut secrets = Vec::new();
        for token in [Some(&self.token), self.push_token.as_ref()]
            .into_iter()
            .flatten()
            .filter(|token| !token.is_empty())
        {
            secrets.push(BASE64.encode(format!("{GIT_USER}:{token}")));
            secrets.push(encoded(token));
            secrets.push(token.clone());
        }
        // Longest first, so a token is not cut out of a longer form.
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets
    }

    /// What the caller's `--comment-target` numbers: without it, no note
    /// is posted.
    pub fn commenting_on(mut self, kind: Option<Kind>) -> Self {
        self.comment_kind = kind;
        self
    }

    pub fn status_context(mut self, context: Option<(String, u64)>) -> Self {
        self.status_context = context;
        self
    }

    /// Bind the status to an existing pipeline of this project, SHA and
    /// ref. Commit existence alone also accepts fork-only objects for
    /// which GitLab cannot create a pipeline in the target project.
    fn status_target(&self, status: &CommitStatus) -> Result<(Project, String, &str, u64)> {
        let (reference, pipeline) = self.status_context.as_ref().context(
            "GitLab --status requires trusted --status-ref and --status-pipeline-id; automatic pipeline targeting is ambiguous",
        )?;
        ensure!(
            !reference.is_empty()
                && reference.chars().count() <= 255
                && !reference.chars().any(char::is_control),
            "GitLab status ref must have 1..255 characters and no control characters"
        );
        ensure!(*pipeline > 0, "GitLab status pipeline ID must be positive");
        ensure!(
            super::COMMIT_RE.is_match(&status.sha),
            "GitLab status requires a full commit SHA"
        );
        ensure!(
            status.target_url.chars().count() <= 255,
            "GitLab status run URL exceeds 255 characters"
        );
        let (project, url) = self.commit(&status.sha)?;
        let path = format!("/projects/{}/pipelines/{pipeline}", project.id);
        let answer = self.request(GET, &path, None)?;
        ensure!(
            answer["id"].as_u64() == Some(*pipeline)
                && answer["project_id"].as_u64() == Some(project.id)
                && answer["sha"] == status.sha
                && answer["ref"] == reference.as_str(),
            "GET {path}: status pipeline does not match the trusted project, SHA and ref"
        );
        // GitLab exposed the archive flag in 18.5. Older responses cannot
        // prove eligibility; do not silently accept a possibly archived pipeline.
        let archived = answer["archived"].as_bool().with_context(|| {
            format!("GET {path}: GitLab status requires GitLab 18.5+ with a boolean pipeline archived field")
        })?;
        ensure!(
            !archived && answer.get("yaml_errors") == Some(&Value::Null),
            "GET {path}: status pipeline is archived or has unavailable/invalid CI configuration"
        );
        Ok((project, url, reference, *pipeline))
    }

    /// Read every bounded page, not an arbitrary matching historic job.
    /// IDs define current deterministically; timestamps can tie. Read all
    /// jobs so an older active job belonging to another run is not stolen.
    fn current_status(
        &self,
        project: u64,
        reference: &str,
        pipeline: u64,
        status: &CommitStatus,
    ) -> Result<Option<Value>> {
        let mut latest: Option<Value> = None;
        let mut ids = std::collections::BTreeSet::new();
        let context = &status.context;
        for page in 1..=MAX_STATUS_PAGES {
            let path = format!(
                "/projects/{project}/repository/commits/{}/statuses?name={}&ref={}&pipeline_id={pipeline}&all=true&per_page={STATUSES_PER_PAGE}&page={page}",
                status.sha,
                encoded(context),
                encoded(reference)
            );
            let answer = self.request(GET, &path, None)?;
            let entries = answer
                .as_array()
                .context("GitLab response is not statuses")?;
            ensure!(
                entries.len() <= STATUSES_PER_PAGE,
                "status page exceeds its limit"
            );
            for entry in entries {
                ensure!(
                    entry["name"] == context.as_str()
                        && entry["sha"] == status.sha
                        && entry["ref"] == reference,
                    "GitLab status does not match the requested context, SHA and ref"
                );
                let id = entry["id"].as_u64().context("status has no numeric id")?;
                ensure!(
                    ids.insert(id),
                    "duplicate status id across pages; status listing changed or is ambiguous"
                );
                ensure!(
                    !matches!(entry["status"].as_str(), Some("pending" | "running"))
                        || entry["target_url"] == status.target_url,
                    "another run has an active {context} status in pipeline {pipeline}; refusing to take over its identity"
                );
                if latest
                    .as_ref()
                    .is_none_or(|previous| previous["id"].as_u64() < Some(id))
                {
                    latest = Some(entry.clone());
                }
            }
            if entries.len() < STATUSES_PER_PAGE {
                return Ok(latest);
            }
        }
        bail!(
            "status listing exceeds {MAX_STATUS_PAGES} pages; refusing incomplete current-status selection"
        )
    }

    fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let secrets = self.secrets();
        let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
        Api {
            http: &self.http,
            url: &self.api,
            authorization: &format!("Bearer {}", self.token),
            secrets: &secrets,
        }
        .request(method, path, body)
        .map_err(|err| anyhow::anyhow!(super::git::shown(&secrets, &format!("{err:#}"))))
    }

    /// What git fetches PROJECT from, or pushes to it at.
    fn remote(&self, project: &str) -> String {
        format!("{}/{project}.git", self.git)
    }

    /// PATH, as GitLab answers for it: refused unless the answer is for
    /// that very path, not one it was renamed or moved to, and says what
    /// is needed.
    fn project(&self, path: &str) -> Result<Project> {
        let at = format!("/projects/{}", encoded(path));
        let answer = self.request(GET, &at, None)?;
        let missing = |what: &str| format!("GET {at}: the response has no {what}");
        let id = answer["id"].as_u64().with_context(|| missing("id"))?;
        let named = answer["path_with_namespace"]
            .as_str()
            .with_context(|| missing("path_with_namespace"))?;
        ensure!(
            named.eq_ignore_ascii_case(path),
            "GitLab answers for {path} with {named}: it was renamed or moved"
        );
        let visibility = answer["visibility"]
            .as_str()
            .with_context(|| missing("visibility"))?;
        ensure!(
            ["private", "internal", "public"].contains(&visibility),
            "GET {at}: visibility {visibility:?} is not one GitLab has"
        );
        let forked_from = match &answer["forked_from_project"] {
            Value::Null => None,
            parent => Some(
                parent["id"]
                    .as_u64()
                    .with_context(|| missing("forked_from_project id"))?,
            ),
        };
        Ok(Project {
            id,
            path: named.to_owned(),
            private: visibility == "private",
            public: visibility == "public",
            forked_from,
            default_branch: answer["default_branch"].as_str().map(str::to_owned),
        })
    }

    /// The repository's project and BRANCH's: a fork as
    /// [`Self::check_fork`] holds it, or, where the caller's bounds accept
    /// it, the project itself, with BRANCH neither its default branch nor
    /// one a protected branch rule names.
    fn branch_projects(
        &self,
        push_repo: &str,
        branch: &str,
        private_run: bool,
    ) -> Result<(Project, Project)> {
        if !push_repo.eq_ignore_ascii_case(&self.repo) {
            self.other_owner(push_repo)?;
            return self.check_fork(push_repo, private_run);
        }
        ensure!(
            self.own_branches,
            "a merge request's branch goes to {push_repo} itself only where the caller's \
             own-branch-repos bounds accept it"
        );
        let target = self.project(&self.repo)?;
        ensure!(
            target.default_branch.as_deref() != Some(branch),
            "{branch} is the default branch of {push_repo}, which a push never goes to"
        );
        for page in 1..=MAX_PROTECTED_PAGES {
            let path = format!(
                "/projects/{}/protected_branches?page={page}&per_page={PROTECTED_PER_PAGE}",
                target.id
            );
            let answer = self.request(GET, &path, None)?;
            let rules = answer
                .as_array()
                .with_context(|| format!("GET {path}: the response is not protected branches"))?;
            for rule in rules {
                let name = rule["name"]
                    .as_str()
                    .with_context(|| format!("GET {path}: a protected branch has no name"))?;
                ensure!(
                    !protects(name, branch),
                    "{branch} of {push_repo} is protected ({name}), which a push never goes to"
                );
            }
            if rules.len() < PROTECTED_PER_PAGE {
                return Ok((target.clone(), target));
            }
        }
        bail!(
            "{push_repo} has more protected branch rules than apply reads ({})",
            MAX_PROTECTED_PAGES * PROTECTED_PER_PAGE
        )
    }

    /// The repository's project and the fork's, refused unless the fork
    /// is the repository's, and no more readable than the repository's
    /// audience, as [`forgejo`]'s `check_fork` holds them.
    fn check_fork(&self, push_repo: &str, private_run: bool) -> Result<(Project, Project)> {
        let target = self.project(&self.repo)?;
        let fork = self.project(push_repo)?;
        ensure!(
            fork.forked_from == Some(target.id),
            "{push_repo} is not a fork of {}",
            self.repo
        );
        ensure!(
            fork.private || (target.public && !private_run),
            "{push_repo} is not private, and {} is not public: its branch would publish the repository's code",
            self.repo
        );
        Ok((target, fork))
    }

    /// NUMBER of KIND in the repository's project, refused unless GitLab
    /// answers for it as that item of this project.
    fn item(&self, number: u64, kind: Kind) -> Result<Item> {
        let project = self.project(&self.repo)?;
        let path = format!(
            "/projects/{}/{}/{number}",
            encoded(&self.repo),
            collection(kind)
        );
        let answer = self.request(GET, &path, None)?;
        ensure!(
            answer["iid"].as_u64() == Some(number)
                && answer["project_id"].as_u64() == Some(project.id),
            "{} is not an item of {}",
            reference(kind, number),
            project.path
        );
        let missing = |what: &str| format!("GET {path}: the response has no {what}");
        Ok(Item {
            project: project.id,
            url: answer["web_url"]
                .as_str()
                .map(str::to_owned)
                .with_context(|| missing("web_url"))?,
            state: answer["state"]
                .as_str()
                .map(str::to_owned)
                .with_context(|| missing("state"))?,
            labels: label_names(&answer["labels"]).with_context(|| missing("labels"))?,
        })
    }

    /// The labels of project PROJECT, its groups' included, every page.
    fn project_labels(&self, project: u64) -> Result<Vec<String>> {
        let mut labels = Vec::new();
        for page in 1..=MAX_LABEL_PAGES {
            let path = format!("/projects/{project}/labels?page={page}&per_page={LABELS_PER_PAGE}");
            let answer = self.request(GET, &path, None)?;
            let found = label_names(&answer)
                .with_context(|| format!("GET {path}: the response is not labels"))?;
            if found.is_empty() {
                return Ok(labels);
            }
            labels.extend(found);
        }
        bail!(
            "{} has more labels than apply reads ({})",
            self.repo,
            MAX_LABEL_PAGES * LABELS_PER_PAGE
        )
    }

    /// Refuses NAMES unless project PROJECT has a label of each, by that
    /// exact name: GitLab would create one it lacks, and apply creates
    /// none. Nor two of one scope, of which GitLab would keep one.
    fn resolve(&self, project: u64, names: &[String]) -> Result<()> {
        if names.is_empty() {
            return Ok(());
        }
        joined(names)?;
        one_of_each_scope(names)?;
        let labels = self.project_labels(project)?;
        let missing: Vec<String> = names
            .iter()
            .filter(|name| !labels.contains(name))
            .map(|name| format!("{name:?}"))
            .collect();
        ensure!(
            missing.is_empty(),
            "{} has no label {}; apply creates none",
            self.repo,
            missing.join(", ")
        );
        Ok(())
    }

    /// The item CHANGE is to, and the labels it still adds to it or
    /// removes from it: one the item has, or lacks, is no change.
    fn label_change(&self, change: &LabelChange) -> Result<(Item, Kind, Vec<String>)> {
        let kind = change
            .kind
            .context("a label change on GitLab that does not name its item's kind")?;
        let item = self.item(change.item, kind)?;
        if !change.add {
            let labels = change
                .labels
                .iter()
                .filter(|name| item.labels.contains(name))
                .cloned()
                .collect();
            return Ok((item, kind, labels));
        }
        self.resolve(item.project, &change.labels)?;
        let labels: Vec<String> = change
            .labels
            .iter()
            .filter(|name| !item.labels.contains(name))
            .cloned()
            .collect();
        // No request names the removal GitLab would make for a label of
        // a scope the item has another of.
        for label in &labels {
            if let Some(shared) = scope(label)
                && let Some(replaced) = item.labels.iter().find(|has| scope(has) == Some(shared))
            {
                bail!(
                    "adding {label:?} to {} would remove {replaced:?}, of its scope {shared:?}",
                    reference(kind, change.item)
                );
            }
        }
        Ok((item, kind, labels))
    }

    /// Item NUMBER of KIND to close, and whether it is still open: refused
    /// if neither open nor done already, such as a locked merge request.
    fn to_close(&self, number: u64, kind: Kind) -> Result<(Item, bool)> {
        let item = self.item(number, kind)?;
        let open = item.state == OPENED;
        ensure!(
            open || DONE.contains(&item.state.as_str()),
            "{} is {}, which apply does not close",
            reference(kind, number),
            item.state
        );
        Ok((item, open))
    }

    /// Posts BODY as a note on ITEM, NUMBER of KIND.
    fn note(&self, item: &Item, kind: Kind, number: u64, body: &str) -> Result<Made> {
        let path = format!(
            "/projects/{}/{}/{number}/notes",
            item.project,
            collection(kind)
        );
        let answer = self.request(POST, &path, Some(&json!({"body": body})))?;
        let id = answer["id"]
            .as_u64()
            .with_context(|| format!("POST {path}: the response names no note id"))?;
        Ok(Made {
            url: format!("{}#note_{id}", item.url),
            number: None,
            id: Some(id),
            node_id: None,
        })
    }

    /// The kind of the caller's comment target: refused without one.
    fn comment_kind(&self) -> Result<Kind> {
        self.comment_kind
            .context("a comment on GitLab, and the caller gave no --comment-target-kind for it")
    }

    /// Refuses a push repository of the repository's top-level group,
    /// as Forgejo's publisher refuses one of its owner. Every subgroup
    /// inherits CI variables from that top-level group.
    fn other_owner(&self, push_repo: &str) -> Result<()> {
        ensure!(
            !super::owner(push_repo).eq_ignore_ascii_case(super::owner(&self.repo)),
            "a merge request's branch goes to another owner's fork, not to {push_repo}"
        );
        Ok(())
    }

    /// Git with the token, as GitLab takes it over HTTP, committing as
    /// COMMITTER.
    fn git<'a>(&'a self, committer: &'a Committer) -> Git<'a> {
        let token = self.push_token.as_deref().unwrap_or(&self.token);
        let credential = BASE64.encode(format!("{GIT_USER}:{token}"));
        Git {
            authorization: format!("Basic {credential}"),
            token,
            extra_secrets: self.secrets(),
            committer: (&committer.name, &committer.email),
        }
    }

    /// Pushes the merge request's branch to its fork: see [`Git::push`].
    fn push(&self, pr: &PullRequest) -> Result<String> {
        self.git(&pr.committer).push(
            &Push {
                from: &self.remote(&self.repo),
                base: &pr.base,
                base_commit: &pr.base_commit,
                to: &self.remote(&pr.push_repo),
                branch: &pr.branch,
                patch: &pr.patch,
                files: &pr.files,
                head: None,
                committer: None,
                at_author_date: false,
                max_changed_kb: None,
            },
            self.recover_pushed_commit.as_deref(),
        )
    }

    /// The URL of the merge request PUSH goes to, refused unless GitLab
    /// answers for it as the policy's: that iid among the merge requests
    /// of the repository's project, by the ID read, into that project,
    /// open, from the bounds' fork, by its ID, and the branch the policy
    /// read, at the head the run was asked for; and the fork as
    /// [`Self::branch_projects`] holds it.
    fn push_target(&self, push: &BranchPush) -> Result<String> {
        let (target, fork) = self.branch_projects(&push.push_repo, &push.branch, push.private)?;
        let number = push.number;
        let mr = reference(Kind::PullRequest, number);
        let path = format!("/projects/{}/merge_requests/{number}", target.id);
        let answer = self.request(GET, &path, None)?;
        ensure!(
            answer["iid"].as_u64() == Some(number)
                && answer["project_id"].as_u64() == Some(target.id)
                && answer["target_project_id"].as_u64() == Some(target.id),
            "{mr} is not a merge request of {}",
            target.path
        );
        ensure!(answer["state"] == OPENED, "merge request {mr} is not open");
        let (source, branch) = (
            answer["source_project_id"].as_u64(),
            answer["source_branch"].as_str(),
        );
        ensure!(
            source == Some(fork.id) && branch == Some(push.branch.as_str()),
            "merge request {mr} is from {}:{}, not {} (project {}):{}: a push goes only to the bounds' fork and the branch the policy read",
            source.map_or_else(
                || "a deleted project".to_owned(),
                |id| format!("project {id}")
            ),
            branch.unwrap_or("no branch"),
            fork.path,
            fork.id,
            push.branch
        );
        let head = answer["sha"].as_str();
        ensure!(
            head == Some(push.head.as_str()),
            "merge request {mr}'s branch is at {}, not {}, the head the run was asked for: it moved, and is not pushed over",
            head.unwrap_or("no commit"),
            push.head
        );
        answer["web_url"]
            .as_str()
            .map(str::to_owned)
            .with_context(|| format!("GET {path}: the response has no web_url"))
    }

    /// Commit SHA of the repository's project, as GitLab answers for it,
    /// and its page: a commit it does not have would fail the status
    /// after every other write.
    fn commit(&self, sha: &str) -> Result<(Project, String)> {
        let project = self.project(&self.repo)?;
        let path = format!("/projects/{}/repository/commits/{sha}", project.id);
        let answer = self.request(GET, &path, None)?;
        ensure!(
            answer["id"] == sha,
            "GET {path}: the response is not that commit"
        );
        let url = answer["web_url"]
            .as_str()
            .map(str::to_owned)
            .with_context(|| format!("GET {path}: the response has no web_url"))?;
        Ok((project, url))
    }
}

impl Publisher for Gitlab {
    fn inline_comment(&self, comment: &super::inline::InlineComment) -> Result<String> {
        let (project, url, position) = self.inline_position(comment)?;
        let path = format!(
            "/projects/{project}/merge_requests/{}/discussions",
            comment.target.number
        );
        let answer = self.request(
            POST,
            &path,
            Some(&json!({"body": comment.body, "position": position})),
        )?;
        let id = answer["notes"]
            .as_array()
            .and_then(|notes| notes.first())
            .and_then(|note| note["id"].as_u64())
            .with_context(|| {
                format!(
                    "POST {path}: discussion may have been created, but response has no note id"
                )
            })?;
        Ok(format!("{url}#note_{id}"))
    }

    fn preflight(&self, op: &Op) -> Result<()> {
        match op {
            Op::Inline(comment) => {
                self.inline_position(comment)?;
            }
            Op::Comment { issue, .. } => {
                self.item(*issue, self.comment_kind()?)?;
            }
            // The push makes its own checks, and it is the first write.
            Op::PullRequest(_) => {}
            Op::Issue(issue) => {
                let project = self.project(&self.repo)?;
                self.resolve(project.id, &issue.labels)?;
            }
            Op::Labels(change) => {
                self.label_change(change)?;
            }
            Op::Close(close) => {
                self.to_close(close.number, close.kind)?;
            }
            Op::Push(push) => {
                let pushing = || format!("pushing to {} branch {}", push.push_repo, push.branch);
                self.push_target(push).with_context(pushing)?;
            }
            Op::Status(status) => {
                let (project, _, reference, pipeline) = self.status_target(status)?;
                self.current_status(project.id, reference, pipeline, status)?;
            }
        }
        Ok(())
    }

    /// GitLab's note has no page of its own: it is the item's, at the
    /// note's anchor. The item is read again, as a moment may have passed
    /// since the preflight, and the note goes to the project by the ID
    /// read, which a rename since cannot point elsewhere; every other
    /// write here alike.
    fn comment(&self, issue: u64, body: &str) -> Result<Made> {
        let kind = self.comment_kind()?;
        let item = self.item(issue, kind)?;
        self.note(&item, kind, issue, body)
    }

    fn open_pull_request(&self, pr: &PullRequest) -> Result<Made> {
        // `plan` refuses this too; held here as well, as nothing else
        // stands between the agent's code and the repository's CI.
        let pushing = || format!("pushing {} to {}", pr.branch, pr.push_repo);
        let (target, fork) = self
            .branch_projects(&pr.push_repo, &pr.branch, pr.private)
            .with_context(pushing)?;
        let commit = self.push(pr).with_context(pushing)?;
        // Opened on the fork, the branch's project, for the repository,
        // both by the IDs `branch_projects` read.
        let path = format!("/projects/{}/merge_requests", fork.id);
        let opened = || -> Result<Made> {
            let answer = self.request(
                POST,
                &path,
                Some(&json!({
                    "source_branch": pr.branch,
                    "target_branch": pr.base,
                    "target_project_id": target.id,
                    "title": pr.title,
                    "description": pr.body,
                })),
            )?;
            let url = answer["web_url"]
                .as_str()
                .with_context(|| format!("POST {path}: the response names no web_url"))?;
            Ok(Made {
                url: url.to_owned(),
                number: answer["iid"].as_u64(),
                id: answer["id"].as_u64(),
                node_id: None,
            })
        };
        opened().with_context(|| {
            let text = format!(
                "published {commit} to {} branch {}; merge request creation failed; retry the same checked input with --recover-pushed-commit {commit} (no branch overwrite)",
                pr.push_repo, pr.branch
            );
            self.secrets()
                .iter()
                .fold(text, |text, secret| text.replace(secret, "[token]"))
        })
    }

    /// As Forgejo's: the merge request and fork are read again, then git
    /// holds the branch to the head under a lease.
    fn push_to_branch(&self, push: &BranchPush) -> Result<String> {
        let pushing = || format!("pushing to {} branch {}", push.push_repo, push.branch);
        let url = self.push_target(push).with_context(pushing)?;
        let fork = self.remote(&push.push_repo);
        self.git(&push.committer)
            .push(
                &Push {
                    from: &fork,
                    base: &push.branch,
                    base_commit: &push.head,
                    to: &fork,
                    branch: &push.branch,
                    patch: &push.patch,
                    files: &push.files,
                    head: Some(&push.head),
                    committer: None,
                    at_author_date: false,
                    max_changed_kb: None,
                },
                None,
            )
            .with_context(pushing)?;
        Ok(url)
    }

    /// GitLab leaves out the labels of a token that may not set them and
    /// still creates the issue, so the answer's labels are compared.
    fn create_issue(&self, issue: &NewIssue) -> Result<String> {
        let project = self.project(&self.repo)?;
        self.resolve(project.id, &issue.labels)?;
        let path = format!("/projects/{}/issues", project.id);
        let mut fields = json!({"title": issue.title, "description": issue.body});
        if !issue.labels.is_empty() {
            fields["labels"] = joined(&issue.labels)?.into();
        }
        let answer = self.request(POST, &path, Some(&fields))?;
        let url = answer["web_url"]
            .as_str()
            .with_context(|| format!("POST {path}: the response names no web_url"))?;
        let labelled = label_names(&answer["labels"]).unwrap_or_default();
        ensure!(
            issue.labels.iter().all(|name| labelled.contains(name)),
            "created {url} without all of its labels {}",
            issue.labels.join(", ")
        );
        Ok(url.to_owned())
    }

    /// One update, of the labels still to change, and its answer compared,
    /// as GitLab ignores the labels of a token that may not set them.
    fn change_labels(&self, change: &LabelChange) -> Result<String> {
        let (item, kind, labels) = self.label_change(change)?;
        if labels.is_empty() {
            return Ok(item.url);
        }
        let key = if change.add {
            "add_labels"
        } else {
            "remove_labels"
        };
        let path = format!(
            "/projects/{}/{}/{}",
            item.project,
            collection(kind),
            change.item
        );
        let answer = self.request(PUT, &path, Some(&json!({key: joined(&labels)?})))?;
        let now = label_names(&answer["labels"])
            .with_context(|| format!("PUT {path}: the response has no labels"))?;
        ensure!(
            labels.iter().all(|name| now.contains(name) == change.add),
            "{} did not get its labels {} {}",
            item.url,
            if change.add { "added" } else { "removed" },
            labels.join(", ")
        );
        Ok(item.url)
    }

    /// The note goes first, as on Forgejo: a failure in between leaves the
    /// item open with the reason on it, and a re-run, without a marker to
    /// find it by, notes again. Its quick actions were broken in `plan`.
    fn close(&self, close: &Close) -> Result<String> {
        let (number, kind) = (close.number, close.kind);
        let (item, open) = self.to_close(number, kind)?;
        if !open {
            return Ok(item.url);
        }
        let note = self.note(&item, kind, number, &close.body)?;
        let path = format!("/projects/{}/{}/{number}", item.project, collection(kind));
        let closed = || -> Result<()> {
            let answer = self.request(PUT, &path, Some(&json!({"state_event": "close"})))?;
            ensure!(
                answer["state"] == "closed",
                "PUT {path}: {} is not closed",
                reference(kind, number)
            );
            Ok(())
        };
        closed().with_context(|| format!("after commenting {}", note.url))?;
        Ok(item.url)
    }

    /// At most one POST, never retried on transport/API failure: it may
    /// already have created a job. A subsequent explicit rerun reads back
    /// the current full desired value. GitLab gives a status no own page.
    fn status(&self, status: &CommitStatus) -> Result<String> {
        let (project, url, reference, pipeline) = self.status_target(status)?;
        let state = status_state(status.state);
        let latest = self.current_status(project.id, reference, pipeline, status)?;
        if latest.as_ref().is_some_and(|set| {
            set["status"] == state
                && set["target_url"] == status.target_url.as_str()
                && set["description"] == status.state.description()
                && self
                    .owner
                    .is_none_or(|owner| set["author"]["id"].as_u64() == Some(owner))
        }) {
            return Ok(url);
        }
        let path = format!("/projects/{}/statuses/{}", project.id, status.sha);
        let answer = self.request(
            POST,
            &path,
            Some(&json!({
                "state": state,
                "name": status.context,
                "target_url": status.target_url,
                "description": status.state.description(),
                "ref": reference,
                "pipeline_id": pipeline,
            })),
        )?;
        ensure!(
            answer["status"] == state
                && answer["name"] == status.context
                && answer["sha"] == status.sha
                && answer["ref"] == reference
                && answer["target_url"] == status.target_url
                && answer["description"] == status.state.description(),
            "POST {path}: the response is not a {state} status {}",
            status.context
        );
        Ok(url)
    }

    /// GitLab's authenticated user, `GET /user`: for a project or group
    /// access token, its bot user.
    fn actor_id(&self) -> Result<u64> {
        self.request(GET, "/user", None)?["id"]
            .as_u64()
            .context("GET /user: the response has no numeric id")
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{
        Request, STATUS_CONTEXT, mock, pull_request_branch, repository, serve, sh,
    };
    use super::super::tests::{checked, policy, target, upload};
    use super::super::{Forge, Target, plan};
    use super::*;

    const TOKEN: &str = "test-token-not-secret";

    fn gitlab(server: &str) -> Gitlab {
        Gitlab::new(&format!("{server}/"), "owner/name", TOKEN.to_owned(), &[])
            .unwrap()
            .status_context(Some(("main".into(), 7)))
    }

    fn ok(answer: &Value) -> (u16, String) {
        (200, answer.to_string())
    }

    /// GitLab's answer about a project: its ID, path and visibility, and
    /// the ID of what it is a fork of.
    fn project(id: u64, path: &str, visibility: &str, forked_from: Option<u64>) -> Value {
        json!({
            "id": id, "path_with_namespace": path, "visibility": visibility,
            "forked_from_project": forked_from.map(|id| json!({"id": id})),
        })
    }

    /// The repository, project 1, as GitLab answers for it.
    fn repo() -> Value {
        project(1, "owner/name", "public", None)
    }

    /// Item IID of KIND in project PROJECT, as GitLab answers for it: open
    /// and without labels.
    fn item(kind: Kind, iid: u64, project: u64) -> Value {
        json!({
            "iid": iid, "project_id": project, "state": "opened", "labels": [],
            "web_url": format!("https://gitlab.example/owner/name/-/{}/{iid}", collection(kind)),
        })
    }

    #[test]
    fn nested_forks_exclude_the_targets_top_level_group() {
        let gitlab = Gitlab::new(
            "https://gitlab.example.com",
            "example/team/project",
            TOKEN.into(),
            &[],
        )
        .unwrap();
        for (fork, accepted) in [
            ("example/forks/project", false),
            ("EXAMPLE/project", false),
            ("example/team/deeper/project", false),
            ("other/forks/project", true),
        ] {
            assert_eq!(gitlab.other_owner(fork).is_ok(), accepted, "{fork}");
        }
    }

    #[test]
    fn applies_to_a_nested_namespace() {
        const REPO: &str = "example/team/project";
        let checked = checked(&[json!({"type": "add_comment", "repo": REPO, "body": "Done."})]);
        let mut policy = policy();
        policy.forge = crate::Forge::Gitlab;
        policy.repo = REPO.into();
        policy.push_repo = Some("other/forks/project".into());
        policy.validate().unwrap();
        let target = Target {
            forge: Forge::Gitlab,
            repo: REPO,
            push_repo: Some("other/forks/project"),
            ..target(Some(5))
        };
        let ops = plan(&upload(checked.path()), &policy, &target).unwrap();
        let project = project(1, REPO, "public", None);
        let (server, requests) = mock(vec![
            ok(&project),
            ok(&item(Kind::Issue, 5, 1)),
            ok(&project),
            ok(&item(Kind::Issue, 5, 1)),
            (201, json!({"id": 30, "noteable_iid": 5}).to_string()),
        ]);
        let gitlab = Gitlab::new(&server, REPO, TOKEN.into(), &[])
            .unwrap()
            .commenting_on(Some(Kind::Issue));
        super::super::publish(&ops, &gitlab).unwrap();
        let lines: Vec<_> = requests.iter().map(|request| request.line).collect();
        assert_eq!(
            lines,
            [
                "GET /api/v4/projects/example%2Fteam%2Fproject HTTP/1.1",
                "GET /api/v4/projects/example%2Fteam%2Fproject/issues/5 HTTP/1.1",
                "GET /api/v4/projects/example%2Fteam%2Fproject HTTP/1.1",
                "GET /api/v4/projects/example%2Fteam%2Fproject/issues/5 HTTP/1.1",
                "POST /api/v4/projects/1/issues/5/notes HTTP/1.1",
            ]
        );
    }

    /// A planned note goes to the issue or the merge request the caller
    /// says, by its iid, with its mentions and quick actions broken.
    #[test]
    fn comments_on_an_issue_or_a_merge_request() {
        let checked = checked(&[json!({"type": "add_comment",
            "body": "Done. @all @group/team\n/merge\n  /approve"})]);
        let mut policy = policy();
        policy.repo = "owner/name".into();
        policy.forge = crate::Forge::Gitlab;
        let target = Target {
            forge: Forge::Gitlab,
            repo: "owner/name",
            ..target(Some(5))
        };
        let ops = plan(&upload(checked.path()), &policy, &target).unwrap();
        let [Op::Comment { body, .. }] = &ops[..] else {
            panic!("expected a planned comment: {ops:?}");
        };
        assert_eq!(
            body,
            &format!(
                "Done. @\u{200b}all @\u{200b}group/team\n\u{200b}/merge\n  \u{200b}/approve\n\n> Generated by [example-ci]({})",
                target.run_url
            )
        );
        for (kind, items) in [
            (Kind::Issue, "issues"),
            (Kind::PullRequest, "merge_requests"),
        ] {
            let (server, requests) = mock(vec![
                ok(&repo()),
                ok(&item(kind, 5, 1)),
                ok(&repo()),
                ok(&item(kind, 5, 1)),
                (
                    201,
                    json!({"id": 30, "body": body, "noteable_iid": 5}).to_string(),
                ),
            ]);
            let gitlab = gitlab(&server).commenting_on(Some(kind));
            gitlab.preflight(&ops[0]).unwrap();
            let made = gitlab.comment(5, body).unwrap();
            assert_eq!(
                made.url,
                format!("https://gitlab.example/owner/name/-/{items}/5#note_30")
            );
            assert_eq!(made.id, Some(30));
            let lines: Vec<String> = requests
                .iter()
                .map(|request| {
                    assert_eq!(request.authorization, format!("Bearer {TOKEN}"));
                    if request.line.starts_with("POST") {
                        assert_eq!(request.body, json!({"body": body}));
                    }
                    request.line
                })
                .collect();
            let item = format!("GET /api/v4/projects/owner%2Fname/{items}/5 HTTP/1.1");
            let project = "GET /api/v4/projects/owner%2Fname HTTP/1.1";
            assert_eq!(
                lines,
                [
                    project,
                    &item,
                    project,
                    &item,
                    &format!("POST /api/v4/projects/1/{items}/5/notes HTTP/1.1"),
                ]
            );
        }
    }

    /// No note goes to a target GitLab does not answer for as the
    /// caller's: of no kind the caller named, of another project, or
    /// another number; nor to a project renamed or moved.
    #[test]
    fn comment_target_refusals() {
        let op = Op::Comment {
            issue: 5,
            body: "Done.".into(),
        };
        let cases: Vec<(Option<Kind>, Vec<Value>, &str)> = vec![
            (None, vec![], "no --comment-target-kind"),
            (
                Some(Kind::Issue),
                vec![repo(), item(Kind::Issue, 5, 2)],
                "#5 is not an item of owner/name",
            ),
            (
                Some(Kind::PullRequest),
                vec![repo(), item(Kind::PullRequest, 6, 1)],
                "!5 is not an item of owner/name",
            ),
            (
                Some(Kind::Issue),
                vec![project(1, "other/name", "public", None)],
                "GitLab answers for owner/name with other/name",
            ),
        ];
        for (kind, answers, refusal) in cases {
            let (server, requests) = mock(answers.iter().map(ok).collect());
            let gitlab = gitlab(&server).commenting_on(kind);
            let err = format!("{:#}", gitlab.preflight(&op).unwrap_err());
            assert!(err.contains(refusal), "{err}");
            assert!(
                requests.try_iter().all(|r| r.line.starts_with("GET")),
                "{refusal}: nothing written"
            );
        }
    }

    /// Collection preserves Markdown escapes. Planning must not mistake
    /// escaped backticks for code and leave a live mention for GitLab.
    #[test]
    fn escaped_code_mentions_after_collection() {
        let mut policy = policy();
        policy.forge = crate::Forge::Gitlab;
        let target = Target {
            forge: Forge::Gitlab,
            ..target(Some(5))
        };
        for body in [r"\`@all\`", r"\`@group/team\`", "```\n@here\n```"] {
            let collected = crate::collect::collect(
                &json!({"type": "add_comment", "body": body}).to_string(),
                &super::super::tests::collector_config(&policy),
                policy.forge,
                &|_| true,
            );
            assert!(collected.errors.is_empty(), "{:?}", collected.errors);
            let items: Vec<Value> = collected.items.into_iter().map(Value::Object).collect();
            let dir = checked(&items);
            let ops = plan(&upload(dir.path()), &policy, &target).unwrap();
            let [Op::Comment { body, .. }] = &ops[..] else {
                panic!("expected a comment: {ops:?}");
            };
            assert!(body.contains("@\u{200b}"), "{body:?}");
            for mention in ["@all", "@group/team", "@here"] {
                assert!(!body.contains(mention), "{body:?}");
            }
        }
    }

    /// A label change of no kind is refused before any request.
    #[test]
    fn a_label_change_of_no_kind_is_refused() {
        let op = Op::Labels(LabelChange {
            item: 5,
            kind: None,
            add: true,
            labels: vec!["bug".into()],
        });
        let err = format!(
            "{:#}",
            gitlab("http://127.0.0.1:1").preflight(&op).unwrap_err()
        );
        assert_eq!(
            err,
            "a label change on GitLab that does not name its item's kind"
        );
    }

    const MR: &str = "GET /api/v4/projects/1/merge_requests/9";
    const MR_9_URL: &str = "https://gitlab.example/owner/name/-/merge_requests/9";
    const COMMIT_URL: &str = "https://gitlab.example/owner/name/-/commit/";
    const RUN_URL: &str = "https://gitlab.example/owner/name/-/pipelines/7";
    const STATUSES: &str = "POST /api/v4/projects/1/statuses/";

    /// A loopback forge that remembers every POST, including multiple jobs
    /// for the same context. Unlike a response queue this exercises reruns.
    fn status_server(mut statuses: Vec<Value>) -> (String, std::sync::mpsc::Receiver<Request>) {
        let sha = "4".repeat(40);
        serve(128, move |request| {
            let line = route(request);
            if line == "GET /api/v4/projects/owner%2Fname" {
                return ok(&repo());
            }
            if line == format!("GET /api/v4/projects/1/repository/commits/{sha}") {
                return ok(&json!({"id": sha, "web_url": format!("{COMMIT_URL}{sha}")}));
            }
            if line == "GET /api/v4/projects/1/pipelines/7" {
                return ok(
                    &json!({"id": 7, "project_id": 1, "sha": sha, "ref": "main", "archived": false, "yaml_errors": null}),
                );
            }
            if line.contains("/statuses?") {
                let page: usize = line
                    .split("&page=")
                    .nth(1)
                    .and_then(|s| s.split('&').next())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                let start = (page - 1) * STATUSES_PER_PAGE;
                return ok(&json!(
                    statuses
                        .iter()
                        .skip(start)
                        .take(STATUSES_PER_PAGE)
                        .collect::<Vec<_>>()
                ));
            }
            if line.starts_with(STATUSES) {
                let mut set = request.body.clone();
                set["status"] = set["state"].clone();
                set["id"] = json!(
                    statuses
                        .iter()
                        .filter_map(|s| s["id"].as_u64())
                        .max()
                        .unwrap_or(0)
                        + 1
                );
                set["sha"] = json!(sha);
                set["ref"] = json!("main");
                statuses.push(set.clone());
                return ok(&set);
            }
            (404, "{}".into())
        })
    }

    fn status_entry(id: u64, state: State, link: &str) -> Value {
        json!({"id": id, "name": STATUS_CONTEXT, "sha": "4".repeat(40),
            "ref": "main", "status": status_state(state), "target_url": link,
            "description": state.description()})
    }

    #[test]
    fn stateful_status_reruns() {
        for (initial, states, writes) in [
            // An older match must not hide a newer different result.
            (
                vec![
                    status_entry(1, State::Failure, RUN_URL),
                    status_entry(2, State::Success, RUN_URL),
                ],
                vec![State::Failure],
                1,
            ),
            (vec![], vec![State::Failure, State::Error, State::Error], 2),
            (
                vec![],
                vec![
                    State::Pending,
                    State::Pending,
                    State::Success,
                    State::Success,
                ],
                2,
            ),
        ] {
            let (server, requests) = status_server(initial);
            let publisher = gitlab(&server);
            for state in states {
                publisher
                    .status(&CommitStatus {
                        sha: "4".repeat(40),
                        state,
                        target_url: RUN_URL.into(),
                        context: STATUS_CONTEXT.into(),
                    })
                    .unwrap();
            }
            assert_eq!(
                requests
                    .try_iter()
                    .filter(|r| r.line.starts_with("POST "))
                    .count(),
                writes
            );
        }
    }

    /// In role mode a rerun takes an identical status as set only when
    /// its numeric author is the status role's actor, never by name.
    #[test]
    fn a_rerun_owns_only_its_actors_status() {
        let set = |author: Value| {
            let mut entry = status_entry(1, State::Success, RUN_URL);
            entry["author"] = author;
            entry
        };
        for (author, owner, writes) in [
            (json!({"id": 7, "username": "bot"}), None, 0),
            (json!({"id": 7, "username": "bot"}), Some(7), 0),
            (json!({"id": 8, "username": "bot"}), Some(7), 1),
            (json!({"id": "7", "username": "bot"}), Some(7), 1),
            (Value::Null, Some(7), 1),
        ] {
            let (server, requests) = status_server(vec![set(author.clone())]);
            gitlab(&server)
                .owned_by(owner)
                .status(&CommitStatus {
                    sha: "4".repeat(40),
                    state: State::Success,
                    target_url: RUN_URL.into(),
                    context: STATUS_CONTEXT.into(),
                })
                .unwrap();
            let posts = requests
                .try_iter()
                .filter(|r| r.line.starts_with("POST "))
                .count();
            assert_eq!(posts, writes, "{author} owned by {owner:?}");
        }
    }

    #[test]
    fn status_pagination_and_active_run_conflicts() {
        for (count, other_pending, refusal) in [
            (101, false, None),
            (101, true, Some("another run has an active")),
            (
                MAX_STATUS_PAGES * STATUSES_PER_PAGE,
                false,
                Some("status listing exceeds"),
            ),
        ] {
            // The newest entry is deliberately on the final page and
            // differs from every older (otherwise matching) entry.
            let mut entries: Vec<_> = (1..count)
                .map(|id| status_entry(id as u64, State::Success, RUN_URL))
                .collect();
            entries.push(status_entry(
                count as u64,
                if other_pending {
                    State::Pending
                } else {
                    State::Failure
                },
                "https://gitlab.example/other-run",
            ));
            let (server, requests) = status_server(entries);
            let status = CommitStatus {
                sha: "4".repeat(40),
                state: State::Success,
                target_url: RUN_URL.into(),
                context: STATUS_CONTEXT.into(),
            };
            let result = gitlab(&server).status(&status);
            match refusal {
                Some(refusal) => assert!(format!("{:#}", result.unwrap_err()).contains(refusal)),
                None => {
                    result.unwrap();
                }
            }
            let requests: Vec<_> = requests.try_iter().collect();
            assert_eq!(
                requests
                    .iter()
                    .filter(|r| r.line.starts_with("POST "))
                    .count(),
                usize::from(refusal.is_none())
            );
            assert!(requests.iter().any(|r| r.line.contains("&page=2")));
        }
        // Even a newer same-run result must not hide someone else's
        // unfinished job: GitLab might select that job for the update.
        let (server, requests) = status_server(vec![
            status_entry(1, State::Pending, "https://gitlab.example/other-run"),
            status_entry(2, State::Success, RUN_URL),
        ]);
        let status = CommitStatus {
            sha: "4".repeat(40),
            state: State::Success,
            target_url: RUN_URL.into(),
            context: STATUS_CONTEXT.into(),
        };
        assert!(gitlab(&server).preflight(&Op::Status(status)).is_err());
        assert!(requests.try_iter().all(|r| r.line.starts_with("GET ")));
    }

    #[test]
    fn unsupported_status_context_is_refused_before_other_writes() {
        let sha = "4".repeat(40);
        let pipeline = json!({"id": 7, "project_id": 1, "sha": sha, "ref": "main", "archived": false, "yaml_errors": null});
        let mut cases = vec![(None, pipeline.clone(), "requires trusted")];
        for (key, value) in [
            ("id", json!(8)),
            ("project_id", json!(2)),
            ("sha", json!("5".repeat(40))),
            ("ref", json!("other")),
        ] {
            let mut answer = pipeline.clone();
            answer[key] = value;
            cases.push((
                Some(("main".into(), 7)),
                answer,
                "does not match the trusted",
            ));
        }
        for (key, value) in [
            ("archived", json!(true)),
            ("yaml_errors", json!("invalid CI configuration")),
        ] {
            let mut answer = pipeline.clone();
            answer[key] = value;
            cases.push((
                Some(("main".into(), 7)),
                answer,
                "status pipeline is archived",
            ));
        }
        // GitLab 17.9 through 18.4 expose yaml_errors but not archived in
        // Entities::Ci::Pipeline. Their response must explain the minimum.
        for value in [None, Some(Value::Null), Some(json!("false"))] {
            let mut answer = pipeline.clone();
            let fields = answer.as_object_mut().unwrap();
            fields.remove("archived");
            if let Some(value) = value {
                fields.insert("archived".into(), value);
            }
            cases.push((Some(("main".into(), 7)), answer, "requires GitLab 18.5+"));
        }
        let mut answer = pipeline.clone();
        answer.as_object_mut().unwrap().remove("yaml_errors");
        cases.push((
            Some(("main".into(), 7)),
            answer,
            "status pipeline is archived",
        ));
        for (context, pipeline, refusal) in cases {
            let (server, requests) = mock(if context.is_some() {
                vec![
                    ok(&repo()),
                    ok(&repo()),
                    ok(&json!({"id": sha, "web_url": COMMIT_URL})),
                    ok(&pipeline),
                ]
            } else {
                vec![ok(&repo())]
            });
            let publisher = gitlab(&server).status_context(context);
            // The issue operation would write first, but all preflights
            // finish before any operation can publish.
            let ops = [
                Op::Issue(NewIssue {
                    title: "Issue".into(),
                    body: "Body".into(),
                    labels: vec![],
                }),
                Op::Status(CommitStatus {
                    sha: sha.clone(),
                    state: State::Success,
                    target_url: RUN_URL.into(),
                    context: STATUS_CONTEXT.into(),
                }),
            ];
            let err = super::super::publish(&ops, &publisher).unwrap_err();
            assert!(format!("{err:#}").contains(refusal), "{err:#}");
            assert!(requests.try_iter().all(|r| r.line.starts_with("GET ")));
        }
    }

    #[test]
    fn status_errors_scrub_tokens_and_do_not_retry_posts() {
        for code in [400, 409, 422, 500] {
            let token = "test+status/token";
            let encoded_token = encoded(token);
            let credential = BASE64.encode(format!("{GIT_USER}:{token}"));
            let sha = "4".repeat(40);
            let (server, requests) = mock(vec![
                ok(&repo()),
                ok(&json!({"id": sha, "web_url": COMMIT_URL})),
                ok(
                    &json!({"id": 7, "project_id": 1, "sha": sha, "ref": token, "archived": false, "yaml_errors": null}),
                ),
                ok(&json!([])),
                (
                    code,
                    json!({"message": format!("{token} {encoded_token} {credential}")}).to_string(),
                ),
            ]);
            let publisher = Gitlab::new(&server, "owner/name", token.into(), &[])
                .unwrap()
                .status_context(Some((token.into(), 7)));
            let err = publisher
                .status(&CommitStatus {
                    sha,
                    state: State::Pending,
                    target_url: RUN_URL.into(),
                    context: STATUS_CONTEXT.into(),
                })
                .unwrap_err();
            let err = format!("{err:#}");
            assert!(err.contains(&format!("HTTP {code}")), "{err}");
            for secret in [token, &encoded_token, &credential] {
                assert!(!err.contains(secret), "{err}");
            }
            assert_eq!(
                requests
                    .try_iter()
                    .filter(|r| r.line.starts_with("POST "))
                    .count(),
                1
            );
        }
    }

    #[test]
    fn status_errors_scrub_credentials_crossing_the_truncation_boundary() {
        let token = format!("test+status/{}", "credential".repeat(10));
        for secret in [
            token.to_owned(),
            encoded(&token),
            BASE64.encode(format!("{GIT_USER}:{token}")),
        ] {
            // Leave only a prefix inside the shared API's error budget.
            // Scrubbing later cannot recognize that prefix as a credential.
            let padding = "x".repeat(super::super::git::SHOWN_CHARS - 60);
            let (server, requests) = mock(vec![(500, format!("{padding}{secret}"))]);
            let publisher = Gitlab::new(&server, "owner/name", token.clone(), &[]).unwrap();
            let err = format!(
                "{:#}",
                publisher.request(GET, "/projects/1", None).unwrap_err()
            );
            assert!(err.contains("HTTP 500"), "{err}");
            assert!(!err.contains(&secret[..5]), "{err}");
            assert!(
                err.contains("[token]"),
                "credential must be scrubbed before truncation: {err}"
            );
            assert_eq!(requests.try_iter().count(), 1);
        }
    }

    /// Merge request 9 as GitLab answers for it: open, from project
    /// SOURCE's BRANCH at SHA, into the repository's project, 1.
    fn merge_request(source: u64, branch: &str, sha: &str) -> Value {
        json!({
            "iid": 9, "project_id": 1, "target_project_id": 1, "state": "opened",
            "source_project_id": source, "source_branch": branch, "target_branch": "main",
            "sha": sha, "web_url": MR_9_URL,
        })
    }

    /// The public repository, project 1, its public fork, project 2, and
    /// merge request 9, MR. It knows only the commit KNOWN, whose latest
    /// statuses are SET, takes every write, and fails each route starting
    /// with one of FAILING with the token in its answer.
    fn push_gitlab(
        mr: Value,
        known: String,
        set: Value,
        failing: &'static [&'static str],
    ) -> (String, std::sync::mpsc::Receiver<Request>) {
        serve(64, move |request| {
            let line = route(request);
            if failing.iter().any(|failing| line.starts_with(failing)) {
                let answer = json!({"message": format!("failure {TOKEN}")});
                return (500, answer.to_string());
            }
            let commit = format!("GET /api/v4/projects/1/repository/commits/{known}");
            let answer = match line.as_str() {
                "GET /api/v4/projects/owner%2Fname" => repo(),
                "GET /api/v4/projects/fork%2Fname" => project(2, "fork/name", "public", Some(1)),
                MR => mr.clone(),
                "GET /api/v4/projects/1/pipelines/7" => {
                    json!({"id": 7, "project_id": 1, "sha": known, "ref": "main", "archived": false, "yaml_errors": null})
                }
                line if line == commit => {
                    json!({"id": known, "web_url": format!("{COMMIT_URL}{known}")})
                }
                line if line.starts_with(&format!("{commit}/statuses?")) => set.clone(),
                line if line.starts_with(STATUSES) => {
                    let mut answer = request.body.clone();
                    answer["id"] = json!(1);
                    answer["sha"] = json!(known);
                    answer["status"] = request.body["state"].clone();
                    answer
                }
                _ => return (404, "{}".to_owned()),
            };
            ok(&answer)
        })
    }

    /// A push to the policy's merge request's branch, from another
    /// project, and the caller's status after it: the push, a head that
    /// moved by GitLab's answer or under git's lease, another source
    /// project, branch or target, another iid, paths check did not read,
    /// and failures after a write.
    #[test]
    fn pushes_to_a_merge_request_branch() {
        type Edit = fn(&std::path::Path, &mut Value, &mut BranchPush, &mut String);
        let none: Edit = |_, _, _, _| {};
        let moved = "it moved, and is not pushed over";
        let not_from = "a push goes only to the bounds' fork and the branch the policy read";
        // What, the change to the fixture (the fork's root, merge request
        // 9, the push and the status's commit), the routes that fail, a
        // part of the error, whether the branch got the commit (None: left
        // at the head; Some(false): moved by another), and whether the
        // status was written.
        type Case = (
            &'static str,
            Edit,
            &'static [&'static str],
            Result<(), &'static str>,
            Option<bool>,
            bool,
        );
        let cases: Vec<Case> = vec![
            (
                "the push and its status",
                none,
                &[],
                Ok(()),
                Some(true),
                true,
            ),
            (
                "a head GitLab says moved",
                |_, mr, _, _| mr["sha"] = json!("3".repeat(40)),
                &[],
                Err(moved),
                None,
                false,
            ),
            (
                "a branch that moved after GitLab answered",
                |root, _, _, _| {
                    let work = root.join("work");
                    sh(&work, &["commit", "-q", "--allow-empty", "-m", "Other"]);
                    let fork = root.join("fork/name.git");
                    let fork = fork.to_str().unwrap();
                    sh(
                        &work,
                        &["push", "-q", "-f", fork, "HEAD:refs/heads/agent-run-7"],
                    );
                },
                &[],
                Err("refs/heads/agent-run-7 is no longer at"),
                Some(false),
                false,
            ),
            (
                "another project's merge request into the repository",
                |_, mr, _, _| mr["source_project_id"] = json!(3),
                &[],
                Err("!9 is from project 3:agent-run-7, not fork/name (project 2):agent-run-7"),
                None,
                false,
            ),
            (
                "the repository's own branch",
                |_, mr, _, _| mr["source_project_id"] = json!(1),
                &[],
                Err(not_from),
                None,
                false,
            ),
            (
                "another branch",
                |_, mr, _, _| mr["source_branch"] = json!("main"),
                &[],
                Err("is from project 2:main"),
                None,
                false,
            ),
            (
                "a deleted fork",
                |_, mr, _, _| mr["source_project_id"] = Value::Null,
                &[],
                Err("is from a deleted project:agent-run-7"),
                None,
                false,
            ),
            (
                "a merged merge request",
                |_, mr, _, _| mr["state"] = json!("merged"),
                &[],
                Err("merge request !9 is not open"),
                None,
                false,
            ),
            (
                "another iid",
                |_, mr, _, _| mr["iid"] = json!(10),
                &[],
                Err("!9 is not a merge request of owner/name"),
                None,
                false,
            ),
            (
                "another project's merge request",
                |_, mr, _, _| mr["project_id"] = json!(4),
                &[],
                Err("!9 is not a merge request of owner/name"),
                None,
                false,
            ),
            (
                "a merge request into another project",
                |_, mr, _, _| mr["target_project_id"] = json!(4),
                &[],
                Err("!9 is not a merge request of owner/name"),
                None,
                false,
            ),
            (
                "a public fork of a private run",
                |_, _, push, _| push.private = true,
                &[],
                Err("fork/name is not private"),
                None,
                false,
            ),
            (
                "the repository's owner's",
                |_, _, push, _| push.push_repo = "owner/other".into(),
                &[],
                Err("a merge request's branch goes to another owner's fork, not to owner/other"),
                None,
                false,
            ),
            (
                "paths check did not read",
                |_, _, push, _| push.files = vec!["src/y".into()],
                &[],
                Err("the applied patch changes other paths than check read"),
                None,
                false,
            ),
            (
                "a commit GitLab does not have",
                |_, _, _, sha| *sha = "3".repeat(40),
                &[],
                Err("GET /projects/1/repository/commits/3333"),
                None,
                false,
            ),
            (
                "an answer echoing the token",
                none,
                &[MR],
                Err("GET /projects/1/merge_requests/9: HTTP 500"),
                None,
                false,
            ),
            (
                "a pipeline unavailable in the target project",
                none,
                &["GET /api/v4/projects/1/pipelines/7"],
                Err("GET /projects/1/pipelines/7: HTTP 500"),
                None,
                false,
            ),
            (
                "a status failing after the push",
                none,
                &[STATUSES],
                Err("after publishing https://gitlab.example/owner/name/-/merge_requests/9: POST"),
                Some(true),
                true,
            ),
        ];
        for (what, edit, failing, want, pushed, status_written) in cases {
            let (root, mut push) = pull_request_branch();
            let mut mr = merge_request(2, "agent-run-7", &push.head);
            let mut sha = push.head.clone();
            edit(root.path(), &mut mr, &mut push, &mut sha);
            let (server, requests) = push_gitlab(mr, push.head.clone(), json!([]), failing);
            let mut gitlab = gitlab(&server);
            gitlab.git = root.path().display().to_string();
            let ops = [
                Op::Push(push.clone()),
                Op::Status(CommitStatus {
                    sha,
                    state: State::Success,
                    target_url: RUN_URL.to_owned(),
                    context: STATUS_CONTEXT.to_owned(),
                }),
            ];
            let result = super::super::publish(&ops, &gitlab);
            let requests: Vec<_> = requests.try_iter().collect();
            for request in &requests {
                assert_eq!(request.authorization, format!("Bearer {TOKEN}"), "{what}");
            }
            match (result, want) {
                (Ok(urls), Ok(())) => assert_eq!(
                    urls,
                    [MR_9_URL.to_owned(), format!("{COMMIT_URL}{}", push.head)],
                    "{what}"
                ),
                (Err(err), Err(want)) => {
                    let err = format!("{err:#}");
                    assert!(err.contains(want), "{what}: {err}");
                    assert!(!err.contains(&TOKEN[..4]), "{what}: {err}");
                }
                (result, _) => panic!("{what}: {result:?}"),
            }
            let fork = root.path().join("fork/name.git");
            let branch = sh(&fork, &["rev-parse", "agent-run-7"]);
            match pushed {
                Some(true) => {
                    assert_eq!(sh(&fork, &["rev-parse", "agent-run-7~"]), push.head);
                    assert_eq!(sh(&fork, &["show", "agent-run-7:src/x"]), "x", "{what}");
                }
                Some(false) => assert_ne!(branch, push.head, "{what}"),
                None => assert_eq!(branch, push.head, "{what}"),
            }
            // The fork's branch alone: nothing in the repository itself.
            assert_eq!(
                sh(
                    &root.path().join("owner/name.git"),
                    &["for-each-ref", "--format=%(refname)"]
                ),
                "refs/heads/main",
                "{what}"
            );
            let writes: Vec<String> = requests
                .iter()
                .filter(|request| !request.line.starts_with("GET "))
                .map(route)
                .collect();
            let want_writes = if status_written {
                vec![format!("{STATUSES}{}", push.head)]
            } else {
                vec![]
            };
            assert_eq!(writes, want_writes, "{what}");
        }
    }

    /// Each state the caller may set is GitLab's nearest that fails no
    /// less, with a fixed description, the pinned name and the run's
    /// link; one the commit's latest of that name has, with that link,
    /// is not written again, and GitLab's answer must be that status.
    #[test]
    fn statuses() {
        let sha = "4".repeat(40);
        let latest = |state: State, link: &str| json!([status_entry(1, state, link)]);
        let cases = [
            (
                State::Pending,
                "pending",
                "The run is in progress",
                json!([]),
            ),
            (State::Success, "success", "The run succeeded", json!([])),
            (State::Failure, "failed", "The run failed", json!([])),
            (
                State::Error,
                "failed",
                "The run could not finish",
                json!([]),
            ),
            // Another run's, or another state, is written over.
            (
                State::Success,
                "success",
                "The run succeeded",
                latest(State::Success, "https://gitlab.example/other"),
            ),
            (
                State::Success,
                "success",
                "The run succeeded",
                latest(State::Pending, RUN_URL),
            ),
        ];
        for (state, name, description, set) in cases {
            let (server, requests) = push_gitlab(Value::Null, sha.clone(), set, &[]);
            let url = gitlab(&server)
                .status(&CommitStatus {
                    sha: sha.clone(),
                    state,
                    target_url: RUN_URL.to_owned(),
                    context: STATUS_CONTEXT.to_owned(),
                })
                .unwrap();
            assert_eq!(url, format!("{COMMIT_URL}{sha}"));
            let write = requests
                .try_iter()
                .find(|request| !request.line.starts_with("GET "))
                .unwrap();
            assert_eq!(route(&write), format!("{STATUSES}{sha}"));
            assert_eq!(
                write.body,
                json!({"state": name, "name": STATUS_CONTEXT, "target_url": RUN_URL,
                    "description": description, "ref": "main", "pipeline_id": 7})
            );
        }
        // A re-run finds its own status set, and writes nothing.
        let (server, requests) =
            push_gitlab(Value::Null, sha.clone(), latest(State::Error, RUN_URL), &[]);
        let status = CommitStatus {
            sha: sha.clone(),
            state: State::Error,
            target_url: RUN_URL.to_owned(),
            context: STATUS_CONTEXT.to_owned(),
        };
        assert_eq!(
            gitlab(&server).status(&status).unwrap(),
            format!("{COMMIT_URL}{sha}")
        );
        assert!(requests.try_iter().all(|r| r.line.starts_with("GET ")));
        // An answer that is not the status written is refused.
        let (server, _requests) = mock(vec![
            ok(&repo()),
            ok(&json!({"id": sha, "web_url": "https://gitlab.example/c"})),
            ok(
                &json!({"id": 7, "project_id": 1, "sha": sha, "ref": "main", "archived": false, "yaml_errors": null}),
            ),
            ok(&json!([])),
            ok(&json!({"id": 1, "status": "canceled", "name": STATUS_CONTEXT})),
        ]);
        let err = format!("{:#}", gitlab(&server).status(&status).unwrap_err());
        assert!(
            err.contains("the response is not a failed status example-ci"),
            "{err}"
        );
    }

    /// A project in a subgroup, whose path is one encoded segment.
    const NESTED: &str = "group/sub/name";
    const NESTED_PROJECT: &str = "GET /api/v4/projects/group%2Fsub%2Fname";
    const LABELS: &str = "GET /api/v4/projects/1/labels?page=1&per_page=100";
    const ISSUE_URL: &str = "https://gitlab.example/group/sub/name/-/issues/5";
    const MR_URL: &str = "https://gitlab.example/group/sub/name/-/merge_requests/5";
    const CREATED_URL: &str = "https://gitlab.example/group/sub/name/-/issues/8";
    const PUT_ISSUE: &str = "PUT /api/v4/projects/1/issues/5";
    const PUT_MR: &str = "PUT /api/v4/projects/1/merge_requests/5";
    const NOTE_ISSUE: &str = "POST /api/v4/projects/1/issues/5/notes";
    const NOTE_MR: &str = "POST /api/v4/projects/1/merge_requests/5/notes";
    const CREATE: &str = "POST /api/v4/projects/1/issues";

    fn route(request: &Request) -> String {
        request.line.trim_end_matches(" HTTP/1.1").to_owned()
    }

    /// Issue or merge request 5 of the nested project, in STATE, with
    /// LABELS.
    fn nested(kind: Kind, state: &str, labels: &[&str]) -> Value {
        json!({
            "iid": 5, "project_id": 1, "state": state, "labels": labels,
            "web_url": match kind {
                Kind::Issue => ISSUE_URL,
                Kind::PullRequest => MR_URL,
            },
        })
    }

    /// GitLab with the nested project, whose labels are triage, bug,
    /// priority::1 and priority::2, and whose issue 5 and merge request 5
    /// are ISSUE and MERGE_REQUEST. An update answers with the item as it
    /// leaves it; a new issue is answered without `triage`, as for a token
    /// that may not set it. Every write in FAILING fails, with the token
    /// in its answer.
    fn gitlab_of(
        issue: Value,
        merge_request: Value,
        failing: &'static [&'static str],
    ) -> (String, std::sync::mpsc::Receiver<Request>) {
        serve(64, move |request| {
            let line = route(request);
            if failing.contains(&line.as_str()) {
                let answer = json!({"message": format!("failure {TOKEN}")});
                return (500, answer.to_string());
            }
            let split = |value: &Value| -> Vec<String> {
                value
                    .as_str()
                    .map(|names| names.split(',').map(str::to_owned).collect())
                    .unwrap_or_default()
            };
            let answer = match line.as_str() {
                NESTED_PROJECT => project(1, NESTED, "private", None),
                "GET /api/v4/projects/group%2Fsub%2Fname/issues/5" => issue.clone(),
                "GET /api/v4/projects/group%2Fsub%2Fname/merge_requests/5" => merge_request.clone(),
                LABELS => json!([
                    {"id": 1, "name": "triage"}, {"id": 2, "name": "bug"},
                    {"id": 3, "name": "priority::1"}, {"id": 4, "name": "priority::2"},
                ]),
                "GET /api/v4/projects/1/labels?page=2&per_page=100" => json!([]),
                NOTE_ISSUE | NOTE_MR => json!({"id": 30}),
                CREATE => {
                    let mut labels = split(&request.body["labels"]);
                    labels.retain(|name| name != "triage");
                    json!({"iid": 8, "web_url": CREATED_URL, "labels": labels})
                }
                PUT_ISSUE | PUT_MR => {
                    let mut item = if line == PUT_ISSUE {
                        issue.clone()
                    } else {
                        merge_request.clone()
                    };
                    let mut labels = label_names(&item["labels"]).unwrap();
                    labels.extend(split(&request.body["add_labels"]));
                    let removed = split(&request.body["remove_labels"]);
                    labels.retain(|name| !removed.contains(name));
                    item["labels"] = json!(labels);
                    if request.body["state_event"] == "close" {
                        item["state"] = json!("closed");
                    }
                    item
                }
                _ => return (404, "{}".to_owned()),
            };
            (200, answer.to_string())
        })
    }

    /// Each op as GitLab sees it, and every write it makes, on an issue
    /// and a merge request of the same iid: success, a re-run that finds
    /// it done, refusals before any write, and failures after one.
    #[test]
    fn metadata() {
        let labels = |kind, add: bool, names: &[&str]| {
            Op::Labels(LabelChange {
                item: 5,
                kind: Some(kind),
                add,
                labels: names.iter().map(|name| (*name).to_owned()).collect(),
            })
        };
        let close = |kind| {
            Op::Close(Close {
                number: 5,
                kind,
                body: "Done.".into(),
            })
        };
        let issue = |names: &[&str]| {
            Op::Issue(NewIssue {
                title: "Flaky".into(),
                body: "It fails.".into(),
                labels: names.iter().map(|name| (*name).to_owned()).collect(),
            })
        };
        let open = |kind, labels: &[&str]| nested(kind, "opened", labels);
        let (i, m) = (Kind::Issue, Kind::PullRequest);
        let note = |route| (route, json!({"body": "Done."}));
        let closing = |route| (route, json!({"state_event": "close"}));
        // The ops, issue 5, merge request 5, the writes that fail, the
        // writes made, and the URL or a part of the error.
        type Case = (
            Vec<Op>,
            Value,
            Value,
            &'static [&'static str],
            Vec<(&'static str, Value)>,
            Result<&'static str, &'static str>,
        );
        let cases: Vec<Case> = vec![
            // Of the kind named, whatever the other of its iid has.
            (
                vec![labels(i, true, &["triage", "bug"])],
                open(i, &["bug"]),
                open(m, &[]),
                &[],
                vec![(PUT_ISSUE, json!({"add_labels": "triage"}))],
                Ok(ISSUE_URL),
            ),
            (
                vec![labels(m, true, &["triage"])],
                open(i, &["triage"]),
                open(m, &[]),
                &[],
                vec![(PUT_MR, json!({"add_labels": "triage"}))],
                Ok(MR_URL),
            ),
            (
                vec![labels(m, false, &["bug", "triage"])],
                open(i, &["triage"]),
                open(m, &["bug"]),
                &[],
                vec![(PUT_MR, json!({"remove_labels": "bug"}))],
                Ok(MR_URL),
            ),
            // A re-run: nothing still to change.
            (
                vec![labels(i, true, &["triage"]), labels(i, false, &["bug"])],
                open(i, &["triage"]),
                open(m, &["bug"]),
                &[],
                vec![],
                Ok(ISSUE_URL),
            ),
            // Refused before any write: a label the project lacks, by its
            // exact name, which GitLab would create.
            (
                vec![close(i), labels(i, true, &["triage", "wontfix"])],
                open(i, &[]),
                open(m, &[]),
                &[],
                vec![],
                Err("group/sub/name has no label \"wontfix\"; apply creates none"),
            ),
            (
                vec![labels(m, true, &["BUG"])],
                open(i, &[]),
                open(m, &[]),
                &[],
                vec![],
                Err("has no label \"BUG\""),
            ),
            (
                vec![issue(&["bug", "release"])],
                open(i, &[]),
                open(m, &[]),
                &[],
                vec![],
                Err("group/sub/name has no label \"release\""),
            ),
            (
                vec![issue(&["a,b"])],
                open(i, &[]),
                open(m, &[]),
                &[],
                vec![],
                Err("label \"a,b\" has a comma"),
            ),
            // GitLab would remove a label of the same scope, or keep one
            // of two.
            (
                vec![labels(i, true, &["priority::2"])],
                open(i, &["priority::1"]),
                open(m, &[]),
                &[],
                vec![],
                Err("adding \"priority::2\" to #5 would remove \"priority::1\", of its scope"),
            ),
            (
                vec![issue(&["priority::1", "priority::2"])],
                open(i, &[]),
                open(m, &[]),
                &[],
                vec![],
                Err("labels \"priority::1\" and \"priority::2\" share the scope \"priority\""),
            ),
            // Another project's item, or another iid.
            (
                vec![labels(m, true, &["bug"])],
                open(i, &[]),
                {
                    let mut foreign = open(m, &[]);
                    foreign["project_id"] = json!(2);
                    foreign
                },
                &[],
                vec![],
                Err("!5 is not an item of group/sub/name"),
            ),
            (
                vec![close(i)],
                {
                    let mut other = open(i, &[]);
                    other["iid"] = json!(6);
                    other
                },
                open(m, &[]),
                &[],
                vec![],
                Err("#5 is not an item of group/sub/name"),
            ),
            // Closing the kind named, and not one done already.
            (
                vec![close(i)],
                open(i, &[]),
                nested(m, "merged", &[]),
                &[],
                vec![note(NOTE_ISSUE), closing(PUT_ISSUE)],
                Ok(ISSUE_URL),
            ),
            (
                vec![close(m)],
                nested(i, "closed", &[]),
                open(m, &[]),
                &[],
                vec![note(NOTE_MR), closing(PUT_MR)],
                Ok(MR_URL),
            ),
            (
                vec![close(m)],
                open(i, &[]),
                nested(m, "merged", &[]),
                &[],
                vec![],
                Ok(MR_URL),
            ),
            (
                vec![close(i)],
                nested(i, "closed", &[]),
                open(m, &[]),
                &[],
                vec![],
                Ok(ISSUE_URL),
            ),
            (
                vec![labels(i, true, &["bug"]), close(m)],
                open(i, &[]),
                nested(m, "locked", &[]),
                &[],
                vec![],
                Err("!5 is locked, which apply does not close"),
            ),
            // Failures after a write name it, without the token.
            (
                vec![close(i)],
                open(i, &[]),
                open(m, &[]),
                &[PUT_ISSUE],
                vec![note(NOTE_ISSUE), closing(PUT_ISSUE)],
                Err(
                    "after commenting https://gitlab.example/group/sub/name/-/issues/5#note_30: PUT",
                ),
            ),
            (
                vec![labels(i, true, &["bug"]), close(m)],
                open(i, &[]),
                open(m, &[]),
                &[NOTE_MR],
                vec![(PUT_ISSUE, json!({"add_labels": "bug"})), note(NOTE_MR)],
                Err("after publishing https://gitlab.example/group/sub/name/-/issues/5: POST"),
            ),
            (
                vec![issue(&["bug"])],
                open(i, &[]),
                open(m, &[]),
                &[],
                vec![(
                    CREATE,
                    json!({"title": "Flaky", "description": "It fails.", "labels": "bug"}),
                )],
                Ok(CREATED_URL),
            ),
            (
                vec![issue(&[])],
                open(i, &[]),
                open(m, &[]),
                &[],
                vec![(
                    CREATE,
                    json!({"title": "Flaky", "description": "It fails."}),
                )],
                Ok(CREATED_URL),
            ),
            (
                vec![issue(&["triage", "bug"])],
                open(i, &[]),
                open(m, &[]),
                &[],
                vec![(
                    CREATE,
                    json!({"title": "Flaky", "description": "It fails.", "labels": "triage,bug"}),
                )],
                Err(
                    "created https://gitlab.example/group/sub/name/-/issues/8 without all of its labels triage, bug",
                ),
            ),
        ];
        for (ops, issue, merge_request, failing, writes, want) in cases {
            let (server, requests) = gitlab_of(issue, merge_request, failing);
            let gitlab = Gitlab::new(&format!("{server}/"), NESTED, TOKEN.to_owned(), &[]).unwrap();
            let result = super::super::publish(&ops, &gitlab);
            let made: Vec<(String, Value)> = requests
                .try_iter()
                .filter(|request| !request.line.starts_with("GET "))
                .map(|request| {
                    assert_eq!(request.authorization, format!("Bearer {TOKEN}"));
                    (route(&request), request.body)
                })
                .collect();
            let writes: Vec<(String, Value)> = writes
                .into_iter()
                .map(|(line, body)| (line.to_owned(), body))
                .collect();
            assert_eq!(made, writes, "{ops:?}");
            match (result, want) {
                (Ok(urls), Ok(want)) => assert_eq!(urls.last().map(String::as_str), Some(want)),
                (Err(err), Err(want)) => {
                    let err = format!("{:#}", err);
                    assert!(err.contains(want), "{ops:?}: {err}");
                    assert!(!err.contains(&TOKEN[..4]), "{err}");
                }
                (result, _) => panic!("{ops:?}: {result:?}"),
            }
        }
    }

    /// Requests planned on GitLab reach the item of the kind they name,
    /// with their quick actions and mentions broken.
    #[test]
    fn publishes_planned_metadata() {
        let text = "Done @all\n/merge";
        let dir = checked(&[
            json!({"type": "add_labels", "repo": NESTED, "pull_request_number": 5,
                "labels": ["triage"]}),
            json!({"type": "close_issue", "repo": NESTED, "issue_number": 5, "body": text}),
        ]);
        let mut policy = policy();
        policy.repo = NESTED.into();
        policy.forge = crate::Forge::Gitlab;
        let target = Target {
            forge: Forge::Gitlab,
            repo: NESTED,
            ..target(None)
        };
        let ops = plan(&upload(dir.path()), &policy, &target).unwrap();
        let (server, requests) = gitlab_of(
            nested(Kind::Issue, "opened", &[]),
            nested(Kind::PullRequest, "opened", &[]),
            &[],
        );
        let gitlab = Gitlab::new(&server, NESTED, TOKEN.to_owned(), &[]).unwrap();
        assert_eq!(
            super::super::publish(&ops, &gitlab).unwrap(),
            [MR_URL, ISSUE_URL]
        );
        let writes: Vec<(String, Value)> = requests
            .try_iter()
            .filter(|request| !request.line.starts_with("GET "))
            .map(|request| (route(&request), request.body))
            .collect();
        let body = format!(
            "Done @\u{200b}all\n\u{200b}/merge\n\n> Generated by [example-ci]({})",
            target.run_url
        );
        assert_eq!(
            writes,
            [
                (PUT_MR.to_owned(), json!({"add_labels": "triage"})),
                (NOTE_ISSUE.to_owned(), json!({"body": body})),
                (PUT_ISSUE.to_owned(), json!({"state_event": "close"})),
            ]
        );
    }

    #[test]
    fn opens_a_merge_request_from_a_fork() {
        let (root, pr) = repository();
        let (server, requests) = mock(vec![
            ok(&repo()),
            ok(&project(2, "fork/name", "public", Some(1))),
            (
                201,
                json!({"id": 90, "iid": 9, "project_id": 2, "target_project_id": 1,
                    "web_url": "https://gitlab.example/owner/name/-/merge_requests/9"})
                .to_string(),
            ),
        ]);
        let mut gitlab = gitlab(&server);
        gitlab.git = root.path().display().to_string();
        let made = gitlab.open_pull_request(&pr).unwrap();
        assert_eq!(
            made.url,
            "https://gitlab.example/owner/name/-/merge_requests/9"
        );
        assert_eq!((made.number, made.id), (Some(9), Some(90)));
        for repo in ["owner%2Fname", "fork%2Fname"] {
            let request = requests.recv().unwrap();
            assert_eq!(
                request.line,
                format!("GET /api/v4/projects/{repo} HTTP/1.1")
            );
            assert_eq!(request.authorization, format!("Bearer {TOKEN}"));
        }
        let request = requests.recv().unwrap();
        assert_eq!(
            request.line,
            "POST /api/v4/projects/2/merge_requests HTTP/1.1"
        );
        assert_eq!(
            request.body,
            json!({"source_branch": "agent-run-7", "target_branch": "main",
                "target_project_id": 1, "title": "WIP: Fix it", "description": "Why."})
        );
        // The branch is in the fork, and only there.
        assert_eq!(
            sh(
                &root.path().join("owner/name.git"),
                &["for-each-ref", "--format=%(refname)"]
            ),
            "refs/heads/main"
        );
        let fork = root.path().join("fork/name.git");
        assert_eq!(sh(&fork, &["rev-parse", "agent-run-7~"]), pr.base_commit);
    }

    /// Nested paths retain project identity through preflight, git publication
    /// and MR creation. Own-project publication needs separate caller consent;
    /// that consent never exempts a sibling subgroup from fork isolation.
    #[test]
    fn publishes_nested_merge_requests() {
        const TARGET: &str = "example/team/project";
        for (destination, accepted, parent, refusal) in [
            ("other/forks/project", false, 1, None),
            (TARGET, true, 1, None),
            (TARGET, false, 1, Some("own-branch-repos")),
            (
                "example/forks/project",
                true,
                1,
                Some("another owner's fork"),
            ),
            ("other/forks/project", false, 3, Some("not a fork")),
        ] {
            let (root, mut pr) = repository();
            for (from, to) in [("owner/name", TARGET), ("fork/name", "other/forks/project")] {
                let to = root.path().join(format!("{to}.git"));
                std::fs::create_dir_all(to.parent().unwrap()).unwrap();
                std::fs::rename(root.path().join(format!("{from}.git")), to).unwrap();
            }
            pr.push_repo = destination.into();
            let source_id = if destination == TARGET { 1 } else { 2 };
            let (server, requests) = serve(64, move |request| {
                let answer = match route(request).as_str() {
                    "GET /api/v4/projects/example%2Fteam%2Fproject" => {
                        let mut answer = project(1, TARGET, "public", None);
                        answer["default_branch"] = json!("main");
                        answer
                    }
                    "GET /api/v4/projects/other%2Fforks%2Fproject" => {
                        project(2, "other/forks/project", "public", Some(parent))
                    }
                    line if line.starts_with("GET /api/v4/projects/1/protected_branches?") => {
                        json!([{"name": "main"}])
                    }
                    line if line == format!("POST /api/v4/projects/{source_id}/merge_requests") => {
                        json!({"id": 90, "iid": 9, "web_url": MR_9_URL})
                    }
                    _ => return (404, "{}".into()),
                };
                ok(&answer)
            });
            let mut publisher = Gitlab::new(&server, TARGET, TOKEN.into(), &[])
                .unwrap()
                .accepting_own_branches(accepted);
            publisher.git = root.path().display().to_string();
            let result = super::super::publish(&[Op::PullRequest(pr.clone())], &publisher);
            let requests: Vec<_> = requests.try_iter().collect();
            let target = root.path().join(format!("{TARGET}.git"));
            let fork = root.path().join("other/forks/project.git");
            if let Some(refusal) = refusal {
                let err = result.unwrap_err();
                assert!(
                    format!("{err:#}").contains(refusal),
                    "{destination}: {err:#}"
                );
                assert!(requests.iter().all(|r| r.line.starts_with("GET ")));
                assert_eq!(
                    sh(&target, &["for-each-ref", "--format=%(refname)"]),
                    "refs/heads/main"
                );
                assert_eq!(sh(&fork, &["for-each-ref"]), "");
                continue;
            }
            assert_eq!(result.unwrap(), [MR_9_URL]);
            let posts: Vec<_> = requests
                .iter()
                .filter(|r| r.line.starts_with("POST "))
                .collect();
            assert_eq!(posts.len(), 1);
            assert_eq!(
                posts[0].line,
                format!("POST /api/v4/projects/{source_id}/merge_requests HTTP/1.1")
            );
            assert_eq!(
                posts[0].body,
                json!({"source_branch": pr.branch, "target_branch": pr.base,
                "target_project_id": 1, "title": pr.title, "description": pr.body})
            );
            let pushed = if source_id == 1 { &target } else { &fork };
            assert_eq!(sh(pushed, &["rev-parse", "agent-run-7~"]), pr.base_commit);
            if source_id == 2 {
                assert_eq!(
                    sh(&target, &["for-each-ref", "--format=%(refname)"]),
                    "refs/heads/main"
                );
                assert!(
                    requests
                        .iter()
                        .any(|r| r.line == "GET /api/v4/projects/other%2Fforks%2Fproject HTTP/1.1")
                );
            } else {
                assert_eq!(sh(&fork, &["for-each-ref"]), "");
            }
        }
    }

    /// The repository, whose default branch is DEFAULT and whose protected
    /// branch rules are PROTECTED, its merge request 9, MR, and a merge
    /// request opened in it.
    fn own_gitlab(
        default: &'static str,
        protected: Value,
        mr: Value,
    ) -> (String, std::sync::mpsc::Receiver<Request>) {
        serve(64, move |request| {
            let answer = match route(request).as_str() {
                "GET /api/v4/projects/owner%2Fname" => {
                    let mut answer = repo();
                    answer["default_branch"] = json!(default);
                    answer
                }
                line if line.starts_with("GET /api/v4/projects/1/protected_branches?") => {
                    protected.clone()
                }
                MR => mr.clone(),
                "POST /api/v4/projects/1/merge_requests" => {
                    json!({"id": 90, "iid": 9, "project_id": 1, "target_project_id": 1,
                        "web_url": MR_9_URL})
                }
                _ => return (404, "{}".to_owned()),
            };
            ok(&answer)
        })
    }

    /// Where the caller's bounds accept it, a merge request's branch is
    /// pushed to the repository itself and the merge request opened
    /// there, or a commit pushed on an open one's, under the head's lease;
    /// never without that acceptance, nor to the default branch or one a
    /// protected branch rule names.
    #[test]
    fn own_branches_of_the_repository() {
        let rules = json!([{"name": "main"}, {"name": "release/*"}]);
        // What, whether the bounds accept it, the default branch, the
        // protected branch rules, and a part of the error.
        let cases: &[(&str, bool, &'static str, Value, Option<&str>)] = &[
            ("accepted", true, "main", rules.clone(), None),
            (
                "not accepted",
                false,
                "main",
                rules.clone(),
                Some("only where the caller's own-branch-repos bounds accept it"),
            ),
            (
                "the default branch",
                true,
                "agent-run-7",
                rules.clone(),
                Some("agent-run-7 is the default branch of owner/name"),
            ),
            (
                "a protected branch",
                true,
                "main",
                json!([{"name": "main"}, {"name": "agent-*"}]),
                Some("agent-run-7 of owner/name is protected (agent-*)"),
            ),
        ];
        let refs = |root: &std::path::Path| {
            sh(
                &root.join("owner/name.git"),
                &["for-each-ref", "--format=%(refname)"],
            )
        };
        let publisher = |server: &str, root: &std::path::Path, accepted: bool| {
            let mut publisher = gitlab(server).accepting_own_branches(accepted);
            publisher.git = root.display().to_string();
            publisher
        };
        for (what, accepted, default, protected, want) in cases {
            // A new merge request.
            let (root, mut pr) = repository();
            pr.push_repo = "owner/name".into();
            let (server, requests) = own_gitlab(default, protected.clone(), Value::Null);
            let opened = publisher(&server, root.path(), *accepted).open_pull_request(&pr);
            match (opened, want) {
                (Ok(made), None) => {
                    assert_eq!(made.url, MR_9_URL);
                    let posted = requests
                        .try_iter()
                        .find(|request| request.line.starts_with("POST"))
                        .unwrap();
                    assert_eq!(
                        posted.line,
                        "POST /api/v4/projects/1/merge_requests HTTP/1.1"
                    );
                    assert_eq!(posted.body["target_project_id"], 1, "{what}");
                    let bare = root.path().join("owner/name.git");
                    assert_eq!(sh(&bare, &["rev-parse", "agent-run-7~"]), pr.base_commit);
                }
                (Err(err), Some(want)) => {
                    assert!(format!("{err:#}").contains(want), "{what}: {err:#}");
                    assert_eq!(refs(root.path()), "refs/heads/main", "{what}");
                }
                (result, _) => panic!("{what}: {result:?}"),
            }

            // A push to an open merge request's branch.
            let (root, mut push) = pull_request_branch();
            push.push_repo = "owner/name".into();
            let bare = root.path().join("owner/name.git");
            sh(&bare, &["branch", "agent-run-7", "main"]);
            let mr = merge_request(1, "agent-run-7", &push.head);
            let (server, _) = own_gitlab(default, protected.clone(), mr);
            let pushed = publisher(&server, root.path(), *accepted).push_to_branch(&push);
            match (pushed, want) {
                (Ok(url), None) => {
                    assert_eq!(url, MR_9_URL);
                    assert_eq!(sh(&bare, &["rev-parse", "agent-run-7~"]), push.head);
                }
                (Err(err), Some(want)) => {
                    assert!(format!("{err:#}").contains(want), "{what}: {err:#}");
                    assert_eq!(sh(&bare, &["rev-parse", "agent-run-7"]), push.head);
                }
                (result, _) => panic!("{what}: {result:?}"),
            }
        }

        // A branch moved after GitLab answered is not forced over.
        let (root, mut push) = pull_request_branch();
        push.push_repo = "owner/name".into();
        let bare = root.path().join("owner/name.git");
        let work = root.path().join("work");
        sh(&work, &["commit", "-q", "--allow-empty", "-m", "Other"]);
        sh(
            &work,
            &[
                "push",
                "-q",
                bare.to_str().unwrap(),
                "HEAD:refs/heads/agent-run-7",
            ],
        );
        let moved = sh(&bare, &["rev-parse", "agent-run-7"]);
        let mr = merge_request(1, "agent-run-7", &push.head);
        let (server, _) = own_gitlab("main", rules, mr);
        let err = publisher(&server, root.path(), true)
            .push_to_branch(&push)
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("refs/heads/agent-run-7 is no longer at"),
            "{err:#}"
        );
        assert_eq!(sh(&bare, &["rev-parse", "agent-run-7"]), moved);
    }

    #[test]
    fn protected_branch_rules() {
        for (rule, branch, protected) in [
            ("main", "main", true),
            ("main", "main2", false),
            ("agent-*", "agent-run-7", true),
            ("*", "a/b", true),
            ("release/*", "agent-run-7", false),
            ("a.b", "axb", false),
            ("*-run-*", "agent-run-7", true),
        ] {
            assert_eq!(protects(rule, branch), protected, "{rule} {branch}");
        }
    }

    /// As Forgejo's: publication reads and opens, git pushes with the
    /// fork-push token, and no form of either token is in an error.
    #[test]
    fn two_role_tokens_open_a_merge_request() {
        let publication = ["fake", "publication", "credential"].join("-");
        let push = ["fake", "push", "credential"].join("-");
        let echo: Vec<String> = [&publication, &push]
            .into_iter()
            .flat_map(|token| {
                [
                    token.clone(),
                    encoded(token),
                    BASE64.encode(format!("{GIT_USER}:{token}")),
                ]
            })
            .collect();
        let (root, pr) = repository();
        let (server, requests) = mock(vec![
            ok(&json!({"id": 104, "username": "renamed"})),
            ok(&repo()),
            ok(&project(2, "fork/name", "public", Some(1))),
            (403, format!("{{\"message\": \"{}\"}}", echo.join(" "))),
            (401, echo.join(" ")),
        ]);
        let mut gitlab = Gitlab::new(&server, "owner/name", publication.clone(), &[])
            .unwrap()
            .pushing_with(Some(push.clone()));
        gitlab.git = root.path().display().to_string();
        assert_eq!(gitlab.actor_id().unwrap(), 104);
        let git = gitlab.git(&pr.committer);
        assert_eq!(
            git.authorization,
            format!("Basic {}", BASE64.encode(format!("{GIT_USER}:{push}")))
        );
        let err = format!("{:#}", gitlab.open_pull_request(&pr).unwrap_err());
        assert!(err.contains("--recover-pushed-commit"), "{err}");
        let err2 = format!("{:#}", gitlab.actor_id().unwrap_err());
        for err in [err, err2] {
            for secret in &echo {
                assert!(!err.contains(secret.as_str()), "{err}");
            }
        }
        let lines: Vec<String> = requests
            .try_iter()
            .map(|request| {
                assert_eq!(request.authorization, format!("Bearer {publication}"));
                request.line
            })
            .collect();
        assert_eq!(
            lines,
            [
                "GET /api/v4/user HTTP/1.1",
                "GET /api/v4/projects/owner%2Fname HTTP/1.1",
                "GET /api/v4/projects/fork%2Fname HTTP/1.1",
                "POST /api/v4/projects/2/merge_requests HTTP/1.1",
                "GET /api/v4/user HTTP/1.1",
            ]
        );
        let fork = root.path().join("fork/name.git");
        assert_eq!(sh(&fork, &["rev-parse", "agent-run-7~"]), pr.base_commit);
    }

    /// A push project that is not the repository's fork, or one more can
    /// read than the repository's audience, gets no push.
    #[test]
    fn fork_identity_and_visibility() {
        let not_public = "fork/name is not private, and owner/name is not public";
        let not_fork = "fork/name is not a fork of owner/name";
        // The repository's answer, the fork's, whether the run is private,
        // and a part of the refusal.
        let cases: Vec<(Value, Value, bool, &str)> = vec![
            (
                repo(),
                project(2, "fork/name", "public", Some(3)),
                false,
                not_fork,
            ),
            (
                repo(),
                project(2, "fork/name", "public", None),
                false,
                not_fork,
            ),
            (
                project(1, "owner/name", "internal", None),
                project(2, "fork/name", "internal", Some(1)),
                false,
                not_public,
            ),
            (
                project(1, "owner/name", "private", None),
                project(2, "fork/name", "public", Some(1)),
                false,
                not_public,
            ),
            (
                repo(),
                project(2, "fork/name", "public", Some(1)),
                true,
                not_public,
            ),
            (
                repo(),
                project(2, "fork/name", "secret", Some(1)),
                false,
                "visibility \"secret\"",
            ),
            (
                repo(),
                project(2, "someone/else", "private", Some(1)),
                false,
                "GitLab answers for fork/name with someone/else",
            ),
        ];
        for (target, fork, private, refusal) in cases {
            let (root, mut pr) = repository();
            pr.private = private;
            let (server, requests) = mock(vec![ok(&target), ok(&fork)]);
            let mut gitlab = gitlab(&server);
            gitlab.git = root.path().display().to_string();
            let err = format!("{:#}", gitlab.open_pull_request(&pr).unwrap_err());
            assert!(err.contains(refusal), "{err}");
            assert_eq!(requests.iter().count(), 2, "{refusal}: no merge request");
            assert_eq!(
                sh(&root.path().join("fork/name.git"), &["for-each-ref"]),
                "",
                "{refusal}: no push"
            );
        }
        // A private fork of a private repository is pushed to.
        let (root, pr) = repository();
        let (server, _requests) = mock(vec![
            ok(&project(1, "owner/name", "private", None)),
            ok(&project(2, "fork/name", "private", Some(1))),
            ok(
                &json!({"iid": 9, "web_url": "https://gitlab.example/owner/name/-/merge_requests/9"}),
            ),
        ]);
        let mut gitlab = gitlab(&server);
        gitlab.git = root.path().display().to_string();
        gitlab.open_pull_request(&pr).unwrap();
    }

    /// A server that echoes the token, or does not answer, never puts it
    /// in the error.
    #[test]
    fn the_token_is_not_in_errors() {
        let (server, _requests) = mock(vec![
            (401, format!("{{\"message\": \"bad token {TOKEN}\"}}")),
            (302, String::new()),
        ]);
        let gitlab = gitlab(&server).commenting_on(Some(Kind::Issue));
        for _ in 0..2 {
            let err = format!("{:#}", gitlab.comment(5, "Done.").unwrap_err());
            assert!(!err.contains(&TOKEN[..4]), "{err}");
            assert!(err.starts_with("GET /projects/owner%2Fname"), "{err}");
        }
        let err = format!(
            "{:#}",
            self::gitlab("http://127.0.0.1:1")
                .commenting_on(Some(Kind::Issue))
                .comment(5, "x")
                .unwrap_err()
        );
        assert!(!err.contains(TOKEN), "{err}");
    }

    #[test]
    fn project_paths() {
        for (path, want) in [
            ("owner/name", "owner%2Fname"),
            ("group/sub/name", "group%2Fsub%2Fname"),
            ("a.b-c_d/e~f", "a.b-c_d%2Fe~f"),
            ("o/n?x#y", "o%2Fn%3Fx%23y"),
        ] {
            assert_eq!(encoded(path), want);
        }
    }
}
