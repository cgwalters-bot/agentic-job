//! Where a run's commit goes on GitHub, read from the forge and never from
//! the agent or a pull request's text.
//!
//! [`resolve`] is for the policy job, with its read-only token: the
//! branch, head and current base of the pull request a run pushes to. The
//! caller then checks the branch against its bounds and pins the head the
//! run starts from. The branch may be in the repository itself or in any
//! fork: whose it is and whether apply's account may push there, only
//! apply knows (#553).
//!
//! [`target`] is for apply's fork step, with apply's token, before
//! anything is fetched or pushed: the repository a pull request's branch
//! is pushed to, which gh-aw's handler is then given as the only one it
//! may push to. That is the token's own fork of the output repository,
//! made if missing, with Actions turned off, or for a push the pull
//! request's head repository, whoever opened it. A replacement (RC-023)
//! is pushed with a lease on that head, past the handler, so these checks
//! are the only ones it gets.
//!
//! A push with the user's token starts the head repository's `push` and
//! `pull_request` workflows on the agent's commit, with their secrets:
//! - only the pull request's own branch, and never the head repository's
//!   default branch or a protected one, which take reviewed changes
//!   (gh-aw's handler refuses those too, but goes on where it cannot read);
//! - a repository the user cannot push to is refused here, with that
//!   reason, rather than by the forge mid-apply;
//! - never with `.github` exempted, as a workflow file the agent wrote
//!   would run there with them: only the user's fork has Actions off;
//! - a branch of the output repository itself, or of another's fork of
//!   it, only where the caller's bounds accept it or that repository does
//!   ([`OWNER_BRANCHES`] naming it on its default branch), and of no
//!   other repository: write access is given for people's commits, not as
//!   an acceptance that the fork's own workflows run an agent's with the
//!   fork's secrets. The output repository's CI runs a fork's commit as a
//!   fork's.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::Value;

use super::github::{Github, is_repo, same, segment};
use super::{COMMIT_RE, owner};
use crate::contract::is_login;
use crate::{CREATE_PULL_REQUEST, PUSH_TO_PULL_REQUEST_BRANCH};

/// A repository whose default branch holds this file, naming that
/// repository (`owner/repo`) on a line of its own, accepts branches of its
/// own that an agent's commit is pushed to: a fix's, whether it is the
/// target or another's fork of it, and a new pull request's, in a target
/// the applying account owns and so has no fork of. The name is what a
/// fork does not inherit: one made or synced from a target that accepts
/// holds the target's file, which names the target.
pub const OWNER_BRANCHES: &str = ".github/agentic-job/accept-owner-branches";

/// More than a name or two is not an opt-in file.
const OWNER_BRANCHES_MAX: usize = 4096;

/// The most of config.json and agent_output.json read: what the collector
/// bounds them to.
const MAX_JSON: u64 = 4 << 20;

/// The most digits of a pull request number policy takes.
const PULL_DIGITS: usize = 9;

/// What [`resolve`] is asked, as the policy call names it.
#[derive(Debug)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct ResolveArgs {
    /// The policy call's `event` input: `false` for a push
    #[cfg_attr(feature = "clap", arg(long))]
    pub event: String,
    /// The policy call's `review` input: `false` for a push
    #[cfg_attr(feature = "clap", arg(long))]
    pub review: String,
    /// The run's kind: `branch` for a push
    #[cfg_attr(feature = "clap", arg(long))]
    pub kind: String,
    /// The pull request's number
    #[cfg_attr(feature = "clap", arg(long, allow_hyphen_values = true))]
    pub item: String,
    /// The repository the run works on
    #[cfg_attr(feature = "clap", arg(long))]
    pub repo: String,
    /// Where the run's outputs go: the calling repository where the caller named none
    #[cfg_attr(feature = "clap", arg(long))]
    pub output_repo: String,
}

/// The pull request a run pushes to, as the forge answered.
#[derive(Debug, PartialEq, Eq)]
pub struct Resolved {
    pub branch: String,
    pub head: String,
    /// Its base branch's head now: a pull request's `base.sha` can lag.
    pub base: String,
    /// The login that opened it, which bounds' `own_author` may admit in
    /// any repository.
    pub author: String,
}

pub fn resolve(github: &Github, args: &ResolveArgs, upstream: bool) -> Result<Resolved> {
    ensure!(
        args.event == "false"
            && args.review == "false"
            && args.kind == "branch"
            && args.output_repo.eq_ignore_ascii_case(&args.repo)
            && pull_number(&Value::String(args.item.clone()))
                .is_some_and(|_| args.item.len() <= PULL_DIGITS)
            && is_repo(&args.repo),
        "A push to a pull request needs a branch run of no event or review, on a pull request \
         number, with its outputs in the repository it works on"
    );
    let pull = github.send(
        "GET",
        &format!("/repos/{}/pulls/{}", args.repo, args.item),
        None,
    )?;
    let commit = |value: &Value| value.as_str().is_some_and(|sha| COMMIT_RE.is_match(sha));
    let branch = pull["head"]["ref"]
        .as_str()
        .filter(|branch| !branch.contains(char::is_control));
    let (true, Some(branch)) = (
        pull["number"].as_u64().map(|n| n.to_string()).as_ref() == Some(&args.item)
            && pull["state"] == "open"
            && same(&pull["base"]["repo"]["full_name"], &args.repo)
            && pull["head"]["repo"]["full_name"].is_string()
            && commit(&pull["base"]["sha"])
            && commit(&pull["head"]["sha"]),
        branch,
    ) else {
        bail!(
            "A push needs an open pull request of the repository it works on, from a branch of a \
             repository that still exists"
        );
    };
    // Empty where it is not a login, such as an app's `name[bot]`, which
    // no bounds' `own_author` names.
    let author = pull["user"]["login"]
        .as_str()
        .filter(|login| is_login(login))
        .unwrap_or_default();
    Ok(Resolved {
        branch: branch.to_owned(),
        head: pull["head"]["sha"].as_str().unwrap_or_default().to_owned(),
        base: current_base(github, &args.repo, &pull, upstream)?,
        author: author.to_owned(),
    })
}

/// The head of PULL's base branch now, in REPOSITORY. Only the forge names
/// that branch; no producer-provided ref or commit is used to resolve it.
fn current_base(github: &Github, repository: &str, pull: &Value, upstream: bool) -> Result<String> {
    // Every push resolves its base here, replacement or not: a failed,
    // ambiguous or mismatched association keeps the PR's own target, as
    // before upstream targets were resolved, rather than refusing the push.
    let upstream = if upstream {
        upstream_pull(github, repository, pull).unwrap_or(None)
    } else {
        None
    };
    let (repository, pull) = upstream
        .as_ref()
        .map(|(repo, pull)| (repo.as_str(), pull))
        .unwrap_or((repository, pull));
    let base = &pull["base"];
    let branch = base["ref"].as_str().filter(|branch| !branch.is_empty());
    let (true, Some(branch)) = (same(&base["repo"]["full_name"], repository), branch) else {
        bail!("the pull request's base is not a branch of {repository}");
    };
    let answer = github.send(
        "GET",
        &format!("/repos/{repository}/git/ref/heads/{}", segment(branch)),
        None,
    )?;
    let object = &answer["object"];
    match object["sha"].as_str() {
        Some(sha) if object["type"] == "commit" && COMMIT_RE.is_match(sha) => Ok(sha.to_owned()),
        _ => bail!("the base branch {branch} of {repository} is not at a commit"),
    }
}

/// A fork-side PR can track the same branch as an upstream PR. Only the
/// forge-reported parent and a unique, exact same-head association by the same
/// author may supply its target: issue text, another branch or another user
/// must not choose a replacement root.
/// Only caller bounds enable this: parent history can then reach the fork
/// outside the checked mails. This changes no push destination or authority.
fn upstream_pull(
    github: &Github,
    repository: &str,
    pull: &Value,
) -> Result<Option<(String, Value)>> {
    if !same(&pull["head"]["repo"]["full_name"], repository) {
        return Ok(None);
    }
    let repo = github.send("GET", &format!("/repos/{repository}"), None)?;
    if repo["fork"] != true {
        return Ok(None);
    }
    let parent = repo["parent"]["full_name"]
        .as_str()
        .filter(|name| is_repo(name))
        .context("the fork has no valid parent repository")?;
    let branch = pull["head"]["ref"]
        .as_str()
        .filter(|branch| !branch.is_empty())
        .context("the fork pull request has no head branch")?;
    let head = segment(&format!("{}:{branch}", owner(repository)));
    // Two results suffice to refuse ambiguity; never choose a prefix of a list.
    let answer = github.send(
        "GET",
        &format!("/repos/{parent}/pulls?state=open&head={head}&per_page=2"),
        None,
    )?;
    let pulls = answer
        .as_array()
        .context("upstream pull requests are not a list")?;
    let [upstream] = pulls.as_slice() else {
        return Ok(None);
    };
    // Anyone who can read the fork can open a parent PR from its branch
    // against any parent branch; only the fork PR's own author may choose
    // the target that way.
    let matches = upstream["state"] == "open"
        && pull["user"]["login"]
            .as_str()
            .is_some_and(|login| is_login(login) && same(&upstream["user"]["login"], login))
        && same(&upstream["base"]["repo"]["full_name"], parent)
        && same(&upstream["head"]["repo"]["full_name"], repository)
        && upstream["head"]["ref"] == branch
        && upstream["head"]["sha"] == pull["head"]["sha"]
        && upstream["head"]["sha"]
            .as_str()
            .is_some_and(|sha| COMMIT_RE.is_match(sha));
    Ok(matches.then(|| (parent.to_owned(), upstream.clone())))
}

/// Whether checked caller bounds or NAME's default-branch file accept NAME.
fn accepts_owner_branches(github: &Github, config: &Value, name: &str) -> Result<bool> {
    let acceptance = crate::contract::SafeOutputs {
        own_branch_repos: config
            .get("own_branch_repos")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()
            .context("own-branch-repos: invalid checked configuration")?
            .unwrap_or_default(),
        ..Default::default()
    };
    if acceptance.accepts_own_branches(name)? {
        return Ok(true);
    }
    // Without a ref this reads the default branch.
    let Some(file) = github.get_optional(&format!("/repos/{name}/contents/{OWNER_BRANCHES}"))?
    else {
        return Ok(false);
    };
    let content = file["content"].as_str().filter(|_| {
        file["type"] == "file"
            && file["encoding"] == "base64"
            && file["size"]
                .as_u64()
                .is_some_and(|size| size <= OWNER_BRANCHES_MAX as u64)
    });
    let Some(content) = content else {
        return Ok(false);
    };
    let content: String = content
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let Ok(text) = BASE64.decode(content) else {
        return Ok(false);
    };
    Ok(text.len() <= OWNER_BRANCHES_MAX
        && String::from_utf8_lossy(&text)
            .split('\n')
            .any(|line| line.trim().eq_ignore_ascii_case(name)))
}

/// What [`target`] is asked, by apply's fork step.
#[derive(Debug)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct TargetArgs {
    /// The handlers' configuration check wrote: config.json
    #[cfg_attr(feature = "clap", arg(long, value_name = "FILE"))]
    pub config: PathBuf,
    /// check's accepted outputs: agent_output.json
    #[cfg_attr(feature = "clap", arg(long, value_name = "FILE"))]
    pub outputs: PathBuf,
    /// The repository the outputs go to
    #[cfg_attr(feature = "clap", arg(long))]
    pub output_repo: String,
    /// The repository the run worked on
    #[cfg_attr(feature = "clap", arg(long))]
    pub repo: String,
    /// The calling repository, which holds the run's secrets
    #[cfg_attr(feature = "clap", arg(long))]
    pub calling_repo: String,
    /// The branch of the pull request a push goes to, as the policy read it
    #[cfg_attr(feature = "clap", arg(long))]
    pub base: String,
    /// Where git finds a repository by its name
    #[cfg_attr(feature = "clap", arg(long, value_name = "URL"))]
    pub server: String,
    /// Whether check accepted a replacement series, which is pushed on its base branch's head now
    #[cfg_attr(feature = "clap", arg(long, action = clap::ArgAction::Set))]
    pub replacement: bool,
}

/// What `push target` decides: the repository the handlers push to, if
/// anything is pushed, and a replacement's base.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Target {
    pub repo: Option<String>,
    pub current_base: Option<String>,
}

/// The head repository of the pull request a push goes to, checked.
struct Head {
    repo: String,
    target: u64,
    /// Whether it is the user's own fork, which the fork step checks and
    /// turns Actions off in as for a new pull request.
    own: bool,
    current_base: Option<String>,
}

fn read_json(read: &dyn Fn(&Path, u64) -> Result<Vec<u8>>, path: &Path) -> Result<Value> {
    let bytes = read(path, MAX_JSON).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// A pull request number, as a JSON number or a string of digits.
fn pull_number(value: &Value) -> Option<u64> {
    let text = match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    (text.starts_with(|c: char| ('1'..='9').contains(&c))
        && text.bytes().all(|b| b.is_ascii_digit()))
    .then(|| text.parse().ok())
    .flatten()
}

/// Whether the handler's CONFIG exempts `.github` from protection.
fn exempts_github(config: &Value) -> bool {
    config["unprotected_dot_folders"]
        .as_array()
        .is_some_and(|folders| folders.iter().any(|folder| folder == ".github"))
}

/// Where ARGS' commit is pushed, if anything is. READ gives the content of
/// the regular file at a path, if it is at most the given bytes, never
/// through a link, as [`super::Upload::read`] does.
pub fn target(
    github: &Github,
    args: &TargetArgs,
    read: &dyn Fn(&Path, u64) -> Result<Vec<u8>>,
) -> Result<Target> {
    ensure!(
        is_repo(&args.output_repo) && is_repo(&args.repo),
        "{:?} or {:?} is not a repository name",
        args.output_repo,
        args.repo
    );
    let outputs = read_json(read, &args.outputs)?;
    let items = outputs["items"]
        .as_array()
        .context("the outputs have no items array")?;
    let has = |kind: &str| items.iter().any(|item| item["type"] == kind);
    let push = has(PUSH_TO_PULL_REQUEST_BRANCH);
    if !push && !has(CREATE_PULL_REQUEST) {
        return Ok(Target::default());
    }
    let me = github
        .login()
        .context("a pull request is opened from a fork of the identity apply holds")?;
    let config = read_json(read, &args.config)?;
    let output = &args.output_repo;
    let head = if push {
        let head = head(github, &config, args, &me)?;
        if !head.own {
            return Ok(Target {
                repo: Some(head.repo),
                current_base: head.current_base,
            });
        }
        Some(head)
    } else {
        None
    };
    if owner(output).eq_ignore_ascii_case(&me) {
        let refuse =
            |why: String| anyhow!("{me} owns {output} and has no fork of it to push to: {why}");
        // A push to a branch of the repository itself returned above;
        // what is left is one from `me`'s fork, which an owner has not.
        if push {
            return Err(refuse(
                "a push goes only to a branch of the repository itself or of another's fork".into(),
            ));
        }
        // A workflow file the agent wrote would run on its own branch.
        if exempts_github(&config[CREATE_PULL_REQUEST]) {
            return Err(refuse(
                "its branch is not pushed to the repository itself with .github exempted from \
                 protection"
                    .into(),
            ));
        }
        if !accepts_owner_branches(github, &config, output)? {
            return Err(refuse(format!(
                "apply as an account that does not own it, or, for a new pull request, add \
                 {OWNER_BRANCHES} naming {output} to its default branch, or accept it in the caller's own-branch-repos bounds"
            )));
        }
        return Ok(Target {
            repo: Some(output.clone()),
            current_base: None,
        });
    }
    let name = github.fork(&me, output, &args.repo, &args.server)?;
    ensure!(is_repo(&name), "the forge named the fork {name:?}");
    if let Some(head) = &head {
        ensure!(
            head.repo.eq_ignore_ascii_case(&name),
            "pull request {} of {output} is from {}:{}, not from {name}: a push goes only to the \
             branch of a pull request apply opened from {me}'s fork",
            head.target,
            head.repo,
            args.base
        );
    }
    Ok(Target {
        repo: Some(name),
        current_base: head.and_then(|head| head.current_base),
    })
}

/// The pull request the policy's push goes to, read again with apply's
/// token, and its head repository held to the rules in the module's
/// documentation.
fn head(github: &Github, config: &Value, args: &TargetArgs, me: &str) -> Result<Head> {
    let push = &config[PUSH_TO_PULL_REQUEST_BRANCH];
    let target = pull_number(&push["target"])
        .context("a push is to be applied, and the policy names no pull request for it")?;
    let output = &args.output_repo;
    let base = &args.base;
    let pull = github.send("GET", &format!("/repos/{output}/pulls/{target}"), None)?;
    let what = format!("pull request {target} of {output}");
    let name = pull["head"]["repo"]["full_name"].as_str();
    let branch = pull["head"]["ref"].as_str();
    let Some(name) = name.filter(|_| {
        pull["state"] == "open"
            && branch == Some(base)
            && same(&pull["base"]["repo"]["full_name"], output)
    }) else {
        bail!(
            "{what} is {}, from {}:{}, not open from a branch named {base}: a push goes only to \
             the branch the policy read",
            pull["state"].as_str().unwrap_or("in no state"),
            name.unwrap_or("a deleted repository"),
            branch.unwrap_or("no branch"),
        );
    };
    ensure!(is_repo(name), "{what} names its head repository {name:?}");
    // A repository the bounds admitted only for its author's own pull
    // request: that author is apply's identity, or the bounds did not
    // admit a push here at all.
    if let Some(author) = push.get("author").filter(|author| !author.is_null()) {
        let author = author
            .as_str()
            .context("the policy names a push's author that is not a login")?;
        ensure!(
            same(&pull["user"]["login"], author) && author.eq_ignore_ascii_case(me),
            "{what} is by {}, and apply pushes as {me}: the policy admitted a push to it only as \
             {author}'s own pull request",
            pull["user"]["login"].as_str().unwrap_or("nobody")
        );
    }
    let own =
        pull["head"]["repo"]["fork"] == true && same(&pull["head"]["repo"]["owner"]["login"], me);
    let itself = name.eq_ignore_ascii_case(output);
    ensure!(
        own || !exempts_github(push),
        "{what} is from {name}, not from {me}'s fork with Actions turned off: a workflow file the \
         agent wrote would run there, so it is not pushed to with .github exempted from protection"
    );
    let head = github.send("GET", &format!("/repos/{name}"), None)?;
    // Write access, not a pull request's "maintainers may edit": that lets
    // the target's maintainers push, which `me` is not to be.
    ensure!(
        head["permissions"]["push"] == true,
        "{what} is from {name}, which {me} cannot push to: give that account write access there, \
         or push the fix by hand"
    );
    // Only a fork of the output repository, or that repository itself: not
    // one it was forked from or another in its network, which nothing here
    // asked, nor the caller's, which holds the run's secrets (unless it is
    // the output repository, which then has to accept the push below).
    // `me`'s own fork is whatever the forge forks for it, which the fork
    // step checks.
    ensure!(
        own || itself
            || (head["fork"] == true
                && same(&head["parent"]["full_name"], output)
                && !name.eq_ignore_ascii_case(&args.calling_repo)),
        "{what} is from {name}, which is neither a fork of {output} nor {output} itself, or is \
         the calling repository: a push goes to neither"
    );
    ensure!(
        head["default_branch"] != base.as_str(),
        "{what} is from {name}'s default branch {base}, which a push never goes to"
    );
    // Classic protection is the branch's `protected`; a ruleset only the rules
    // that apply to it say. Any of either is a branch for reviewed changes.
    let branch = github.send(
        "GET",
        &format!("/repos/{name}/branches/{}", segment(base)),
        None,
    )?;
    let rules = github.send(
        "GET",
        &format!("/repos/{name}/rules/branches/{}", segment(base)),
        None,
    )?;
    ensure!(
        branch["protected"] == false && rules.as_array().is_some_and(Vec::is_empty),
        "{what} is from {name}:{base}, a protected branch or one rules apply to, which a push \
         never goes to"
    );
    if !own && !accepts_owner_branches(github, config, name)? {
        let from = if itself {
            format!("a branch of {name} itself")
        } else {
            format!("{name}, not {me}'s fork with Actions turned off")
        };
        bail!(
            "{what} is from {from}, whose CI would run the pushed commit with its secrets: add \
             {OWNER_BRANCHES} naming {name} to its default branch to accept that, or accept it in the caller's own-branch-repos bounds"
        );
    }
    let current_base = if args.replacement {
        let upstream = config
            .get("upstream_pull_request_base")
            .map(|value| serde_json::from_value::<bool>(value.clone()))
            .transpose()
            .context("invalid upstream-pull-request-base configuration")?
            .unwrap_or(false);
        Some(current_base(github, &args.repo, &pull, upstream)?)
    } else {
        None
    };
    Ok(Head {
        repo: name.to_owned(),
        target,
        own,
        current_base,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::super::testing::{TOKEN, forge, repository, sh};
    use super::super::tests::read;
    use super::*;

    const PULL: &str = "GET /repos/o/r/pulls/42";
    const CAROL: &str = "GET /repos/carol/r";
    const BRANCH: &str = "GET /repos/carol/r/branches/fix/x";
    const RULES: &str = "GET /repos/carol/r/rules/branches/fix/x";
    const ACCEPTS: &str = "GET /repos/carol/r/contents/.github/agentic-job/accept-owner-branches";
    const OWN_ACCEPTS: &str = "GET /repos/o/r/contents/.github/agentic-job/accept-owner-branches";
    const FORK: &str = "POST /repos/o/r/forks";
    const ACTIONS: &str = "PUT /repos/bot/r/actions/permissions";

    fn sha(c: char) -> String {
        c.to_string().repeat(40)
    }

    /// The opt-in as the forge answers it, naming NAMES.
    fn naming(names: &[&str]) -> Value {
        let content: String = names.iter().map(|name| format!("{name}\n")).collect();
        json!({"type": "file", "path": OWNER_BRANCHES, "encoding": "base64",
            "size": content.len(), "content": BASE64.encode(content)})
    }

    fn head(name: &str, fork: bool) -> Value {
        json!({"ref": "fix/x", "sha": sha('a'),
            "repo": {"full_name": name, "fork": fork, "owner": {"login": owner(name)}}})
    }

    fn repo(full_name: &str, fork: bool) -> Value {
        json!({"full_name": full_name, "default_branch": "main", "fork": fork,
            "parent": {"full_name": "o/r"}, "permissions": {"push": true}})
    }

    /// The forge as a push to carol's fork `carol/r`, which accepts it,
    /// finds it, for `bot`, whose fork of `o/r` is `bot/r`.
    fn routes() -> BTreeMap<String, (u16, Value)> {
        let mut routes = BTreeMap::new();
        let mut route = |key: &str, value: Value| routes.insert(key.to_owned(), (200, value));
        route("GET /user", json!({"login": "bot"}));
        route(
            PULL,
            json!({"number": 42, "state": "open", "head": head("carol/r", true),
                "user": {"login": "carol"},
                "base": {"ref": "main", "sha": sha('b'), "repo": {"full_name": "o/r"}}}),
        );
        for name in ["carol/r", "bot/r", "bot/other", "o/r"] {
            let path = format!("GET /repos/{name}");
            route(&path, repo(name, name != "o/r"));
            route(
                &format!("{path}/branches/fix/x"),
                json!({"protected": false}),
            );
            route(&format!("{path}/rules/branches/fix/x"), json!([]));
        }
        route(ACCEPTS, naming(&["carol/r"]));
        route(
            "GET /repos/o/r/git/ref/heads/main",
            json!({"object": {"type": "commit", "sha": sha('c')}}),
        );
        route(
            FORK,
            json!({"full_name": "bot/r", "fork": true, "owner": {"login": "bot"},
                "parent": {"full_name": "o/r"}}),
        );
        route(ACTIONS, Value::Null);
        route(
            "GET /repos/bot/r/actions/permissions",
            json!({"enabled": false}),
        );
        routes
    }

    /// One `push target` run: what it hands back, and what it asked.
    struct Case {
        items: Vec<&'static str>,
        config: Value,
        routes: BTreeMap<String, (u16, Value)>,
        repo: &'static str,
        calling_repo: &'static str,
        replacement: bool,
    }

    impl Case {
        fn new() -> Self {
            Self {
                items: vec![PUSH_TO_PULL_REQUEST_BRANCH],
                config: json!({PUSH_TO_PULL_REQUEST_BRANCH: {"target": "42", "head": sha('a')}}),
                routes: routes(),
                repo: "o/r",
                calling_repo: "caller/r",
                replacement: false,
            }
        }

        fn set(&mut self, key: &str, status: u16, value: Value) {
            self.routes.insert(key.to_owned(), (status, value));
        }

        /// Changes KEY of the answer to ASKED.
        fn edit(&mut self, asked: &str, key: &str, value: Value) {
            self.routes.get_mut(asked).unwrap().1[key] = value;
        }

        fn from(&mut self, name: &str, fork: bool) {
            self.edit(PULL, "head", head(name, fork));
        }

        /// A pull request by AUTHOR, whose repository the policy admitted
        /// as ADMITTED's own.
        fn by(&mut self, author: &str, admitted: &str) {
            self.edit(PULL, "user", json!({"login": author}));
            self.config[PUSH_TO_PULL_REQUEST_BRANCH]["author"] = json!(admitted);
        }

        fn me(&mut self, login: &str) {
            self.set("GET /user", 200, json!({"login": login}));
        }

        fn new_pull_request(&mut self) {
            self.items = vec![CREATE_PULL_REQUEST];
            self.config = json!({CREATE_PULL_REQUEST: {"max": 1}});
        }

        fn same_network_fork(&mut self) {
            self.new_pull_request();
            self.edit("GET /repos/o/r", "fork", json!(true));
            self.edit(
                "GET /repos/o/r",
                "source",
                json!({"full_name": "upstream/r"}),
            );
            self.edit(FORK, "parent", json!({"full_name": "another/r"}));
            self.edit(FORK, "source", json!({"full_name": "UPSTREAM/R"}));
        }

        fn run(self) -> (Result<Target>, Vec<String>) {
            // git finds `bot/r` there, as the forge's fork with a branch.
            let (root, _) = repository();
            let fork = root.path().join("bot/r.git");
            std::fs::create_dir_all(&fork).unwrap();
            sh(&fork, &["init", "-q", "--bare"]);
            sh(
                &root.path().join("owner/name.git"),
                &["push", "-q", fork.to_str().unwrap(), "main"],
            );
            let items: Vec<_> = self
                .items
                .iter()
                .map(|kind| json!({"type": kind}))
                .collect();
            std::fs::write(
                root.path().join("agent_output.json"),
                json!({"items": items}).to_string(),
            )
            .unwrap();
            std::fs::write(root.path().join("config.json"), self.config.to_string()).unwrap();
            let args = TargetArgs {
                config: root.path().join("config.json"),
                outputs: root.path().join("agent_output.json"),
                output_repo: "o/r".into(),
                repo: self.repo.into(),
                calling_repo: self.calling_repo.into(),
                base: "fix/x".into(),
                server: format!("file://{}", root.path().display()),
                replacement: self.replacement,
            };
            let (github, requests) = forge(self.routes);
            let target = target(&github, &args, &read);
            let asked = requests
                .try_iter()
                .map(|request| request.line.trim_end_matches(" HTTP/1.1").to_owned())
                .collect();
            (target, asked)
        }
    }

    fn pushed_to(repo: &str, base: Option<String>) -> Target {
        Target {
            repo: Some(repo.into()),
            current_base: base,
        }
    }

    #[test]
    fn caller_own_branch_repos() {
        for new in [false, true] {
            for (patterns, accepted) in [
                (json!([["O/*"]]), true),
                (json!([["other/*"]]), false),
                (json!([["o/*"], ["*/r"]]), true),
                (json!([["o/*"], ["other/*"]]), false),
                (json!([]), false),
            ] {
                let mut case = Case::new();
                if new {
                    case.new_pull_request();
                    case.me("o");
                } else {
                    case.from("o/r", false);
                }
                case.config["own_branch_repos"] = patterns.clone();
                let (result, asked) = case.run();
                assert_eq!(
                    result.is_ok(),
                    accepted,
                    "new={new}, {patterns}: {result:?}"
                );
                if accepted {
                    assert_eq!(result.unwrap(), pushed_to("o/r", None));
                    assert!(!asked.iter().any(|path| path.contains(OWNER_BRANCHES)));
                }
            }
        }
        // The actual head fork, not the upstream target, must match.
        for (pattern, accepted) in [("carol/*", true), ("o/*", false)] {
            let mut case = Case::new();
            case.routes.remove(ACCEPTS);
            case.config["own_branch_repos"] = json!([[pattern]]);
            assert_eq!(case.run().0.is_ok(), accepted);
        }
    }

    #[test]
    fn upstream_target_requires_a_unique_same_head_pull_else_keeps_its_own() {
        const UPSTREAM: &str = "GET /repos/upstream/r/pulls?state=open&head=o%3Afix/x&per_page=2";
        let mut case = Case::new();
        case.from("o/r", true);
        case.edit("GET /repos/o/r", "fork", json!(true));
        case.edit(
            "GET /repos/o/r",
            "parent",
            json!({"full_name": "upstream/r"}),
        );
        let pull = case.routes[PULL].1.clone();
        let mut upstream = pull.clone();
        upstream["base"] = json!({"ref": "release/topic", "repo": {"full_name": "upstream/r"}});
        case.set(
            "GET /repos/upstream/r/git/ref/heads/release/topic",
            200,
            json!({"object": {"type": "commit", "sha": sha('d')}}),
        );
        // Anything but one exact match keeps the PR's own target, 'c'.
        let mut answers = vec![
            (200, json!([]), sha('c')),
            (200, json!([upstream]), sha('d')),
            (200, json!([upstream, upstream]), sha('c')),
            (200, json!({}), sha('c')),
            (404, json!({"message": "Not Found"}), sha('c')),
        ];
        for (pointer, value) in [
            ("/state", json!("closed")),
            ("/user/login", json!("mallory")),
            ("/base/repo/full_name", json!("unrelated/r")),
            ("/head/repo/full_name", json!("another/r")),
            ("/head/ref", json!("another-branch")),
            ("/head/sha", json!(sha('e'))),
        ] {
            let mut mismatched = upstream.clone();
            *mismatched.pointer_mut(pointer).unwrap() = value;
            answers.push((200, json!([mismatched]), sha('c')));
        }
        for (status, answer, expected) in answers {
            for enabled in [false, true] {
                let mut routes = case.routes.clone();
                routes.insert(UPSTREAM.into(), (status, answer.clone()));
                let (github, requests) = forge(routes.clone());
                let args = ResolveArgs {
                    event: "false".into(),
                    review: "false".into(),
                    kind: "branch".into(),
                    item: "42".into(),
                    repo: "o/r".into(),
                    output_repo: "o/r".into(),
                };
                let expected = if enabled { expected.clone() } else { sha('c') };
                assert_eq!(resolve(&github, &args, enabled).unwrap().base, expected);
                assert_eq!(
                    requests
                        .try_iter()
                        .any(|r| r.line.contains("/repos/upstream/")),
                    enabled
                );
                for replacement in [false, true] {
                    let mut apply = Case::new();
                    apply.routes = routes.clone();
                    apply.config["own_branch_repos"] = json!([["o/r"]]);
                    if enabled {
                        apply.config["upstream_pull_request_base"] = json!(true);
                    }
                    apply.replacement = replacement;
                    let (result, asked) = apply.run();
                    assert_eq!(
                        result.unwrap().current_base,
                        replacement.then(|| expected.clone())
                    );
                    assert_eq!(
                        asked.iter().any(|r| r.contains("/repos/upstream/")),
                        enabled && replacement
                    );
                }
            }
        }
    }

    #[test]
    fn targets() {
        type Edit = fn(&mut Case);
        let none: Edit = |_| {};
        // (what, the forge and request, where the commit goes)
        let cases: Vec<(&str, Edit, Target)> = vec![
            (
                "another's fork that accepts it",
                none,
                pushed_to("carol/r", None),
            ),
            (
                "among other names, in any case, with any line ending",
                |c| c.set(ACCEPTS, 200, naming(&["o/r", " Carol/R\r"])),
                pushed_to("carol/r", None),
            ),
            (
                "a replacement, on its base branch's head now",
                |c| c.replacement = true,
                pushed_to("carol/r", Some(sha('c'))),
            ),
            (
                "the identity's own fork, which is forked and turned off as for a new pull request",
                |c| c.from("bot/r", true),
                pushed_to("bot/r", None),
            ),
            (
                "the identity's own fork, with .github exempted",
                |c| {
                    c.from("bot/r", true);
                    c.config[PUSH_TO_PULL_REQUEST_BRANCH]["unprotected_dot_folders"] =
                        json!([".github"]);
                },
                pushed_to("bot/r", None),
            ),
            (
                "the identity's own fork, a replacement",
                |c| {
                    c.from("bot/r", true);
                    c.replacement = true;
                },
                pushed_to("bot/r", Some(sha('c'))),
            ),
            (
                "the identity's own pull request, admitted by its author",
                |c| {
                    c.from("bot/r", true);
                    c.by("Bot", "bot");
                },
                pushed_to("bot/r", None),
            ),
            (
                "a branch of the repository itself, which accepts it",
                |c| {
                    c.from("o/r", false);
                    c.set(OWN_ACCEPTS, 200, naming(&["O/R"]));
                },
                pushed_to("o/r", None),
            ),
            (
                "the same where the output repository calls the run itself",
                |c| {
                    c.from("o/r", false);
                    c.set(OWN_ACCEPTS, 200, naming(&["o/r"]));
                    c.calling_repo = "o/r";
                },
                pushed_to("o/r", None),
            ),
            (
                "a new pull request, from the identity's fork",
                Case::new_pull_request,
                pushed_to("bot/r", None),
            ),
            (
                "the identity's fork with a different parent in the same network",
                Case::same_network_fork,
                pushed_to("bot/r", None),
            ),
            (
                "the identity's fork whose source is the non-fork target",
                |c| {
                    c.same_network_fork();
                    c.edit("GET /repos/o/r", "fork", json!(false));
                    c.edit(FORK, "source", json!({"full_name": "O/R"}));
                },
                pushed_to("bot/r", None),
            ),
            (
                "an owner's new pull request, in its repository, which accepts it",
                |c| {
                    c.new_pull_request();
                    c.me("O");
                    c.set(OWN_ACCEPTS, 200, naming(&["o/r"]));
                },
                pushed_to("o/r", None),
            ),
            (
                "nothing to push",
                |c| c.items = vec!["add_comment"],
                Target::default(),
            ),
        ];
        for (what, edit, want) in cases {
            let mut case = Case::new();
            edit(&mut case);
            let (got, asked) = case.run();
            assert_eq!(
                got.unwrap_or_else(|err| panic!("{what}: {err:#}")),
                want,
                "{what}"
            );
            // Only the identity's own fork is forked, and has Actions turned off.
            let forked = want.repo.as_deref() == Some("bot/r");
            assert_eq!(asked.iter().any(|a| a == FORK), forked, "{what}: {asked:?}");
            assert_eq!(
                asked.iter().any(|a| a == ACTIONS),
                forked,
                "{what}: {asked:?}"
            );
            assert!(
                asked
                    .iter()
                    .all(|a| a.starts_with("GET ") || [FORK, ACTIONS].contains(&a.as_str()))
            );
        }
        let (_, asked) = Case::new().run();
        assert_eq!(
            asked,
            ["GET /user", PULL, CAROL, BRANCH, RULES, ACCEPTS],
            "the head repository, its branch, and its opt-in on its default branch"
        );
    }

    #[test]
    fn refusals() {
        type Edit = fn(&mut Case);
        // (what, the forge and request, the error's words)
        let cases: Vec<(&str, Edit, &str)> = vec![
            (
                "a closed pull request",
                |c| c.edit(PULL, "state", json!("closed")),
                "is closed, from carol/r:fix/x, not open",
            ),
            (
                "another branch than the policy read",
                |c| {
                    c.edit(
                        PULL,
                        "head",
                        json!({"ref": "other",
                "repo": {"full_name": "carol/r", "fork": true}}),
                    )
                },
                "from carol/r:other, not open from a branch named fix/x",
            ),
            (
                "a deleted head repository",
                |c| c.edit(PULL, "head", json!({"ref": "fix/x", "repo": null})),
                "from a deleted repository:fix/x",
            ),
            (
                "a base in another repository",
                |c| {
                    c.edit(
                        PULL,
                        "base",
                        json!({"ref": "main",
                "repo": {"full_name": "x/r"}}),
                    )
                },
                "not open from a branch",
            ),
            (
                "a head repository that is not a name",
                |c| c.from("../r", true),
                "names its head repository",
            ),
            // Admitted only as the identity's own pull request, it is still
            // that identity's, and the identity is the one apply holds.
            (
                "another's pull request, admitted by the identity's authorship",
                |c| {
                    c.from("bot/r", true);
                    c.by("carol", "bot");
                },
                "is by carol, and apply pushes as bot: the policy admitted a push to it only as \
                 bot's own pull request",
            ),
            (
                "a pull request by the author admitted, applied as another identity",
                |c| c.by("carol", "carol"),
                "is by carol, and apply pushes as bot",
            ),
            (
                "an author that is not a string",
                |c| c.config[PUSH_TO_PULL_REQUEST_BRANCH]["author"] = json!(["bot"]),
                "names a push's author that is not a login",
            ),
            (
                "no pull request in the policy",
                |c| c.config = json!({PUSH_TO_PULL_REQUEST_BRANCH: {}}),
                "names no pull request",
            ),
            (
                "a pull request number that is not one",
                |c| c.config[PUSH_TO_PULL_REQUEST_BRANCH]["target"] = json!("042"),
                "names no pull request",
            ),
            (
                "a head repository the identity cannot push to",
                |c| c.edit(CAROL, "permissions", json!({"push": false})),
                "is from carol/r, which bot cannot push to",
            ),
            (
                "an answer without permissions",
                |c| c.edit(CAROL, "permissions", Value::Null),
                "cannot push to",
            ),
            (
                "the head repository's default branch",
                |c| c.edit(CAROL, "default_branch", json!("fix/x")),
                "carol/r's default branch fix/x, which a push never goes to",
            ),
            (
                "the identity's own fork's default branch",
                |c| {
                    c.from("bot/r", true);
                    c.edit("GET /repos/bot/r", "default_branch", json!("fix/x"));
                },
                "default branch",
            ),
            (
                "a protected branch",
                |c| c.set(BRANCH, 200, json!({"protected": true})),
                "carol/r:fix/x, a protected branch",
            ),
            (
                "an answer that does not say",
                |c| c.set(BRANCH, 200, json!({})),
                "a protected branch",
            ),
            (
                "a branch a ruleset applies to",
                |c| c.set(RULES, 200, json!([{"type": "non_fast_forward"}])),
                "one rules apply to",
            ),
            (
                "an answer of rules that is not a list",
                |c| c.set(RULES, 200, json!({})),
                "one rules apply to",
            ),
            // Not a fork: the repository the target was forked from, say.
            (
                "a head repository that is not a fork",
                |c| c.edit(CAROL, "fork", json!(false)),
                "carol/r, which is neither a fork of o/r nor o/r itself",
            ),
            // Another fork in the network, of the target's own parent, say.
            (
                "a fork of another repository",
                |c| c.edit(CAROL, "parent", json!({"full_name": "upstream/r"})),
                "neither a fork of o/r",
            ),
            (
                "an answer without a parent",
                |c| c.edit(CAROL, "parent", Value::Null),
                "neither a fork of o/r",
            ),
            (
                "the caller's repository, which holds the run's secrets",
                |c| c.calling_repo = "Carol/R",
                "or is the calling repository",
            ),
            (
                ".github exempted, outside the fork with Actions off",
                |c| {
                    c.config[PUSH_TO_PULL_REQUEST_BRANCH]["unprotected_dot_folders"] =
                        json!([".github"]);
                },
                "not from bot's fork with Actions turned off: a workflow file",
            ),
            (
                ".github exempted, in the repository itself",
                |c| {
                    c.from("o/r", false);
                    c.set(OWN_ACCEPTS, 200, naming(&["o/r"]));
                    c.config[PUSH_TO_PULL_REQUEST_BRANCH]["unprotected_dot_folders"] =
                        json!([".github"]);
                },
                ".github exempted",
            ),
            (
                "the repository itself, without its opt-in",
                |c| c.from("o/r", false),
                "from a branch of o/r itself, whose CI would run the pushed commit with its secrets: \
                 add .github/agentic-job/accept-owner-branches naming o/r to its default branch",
            ),
            (
                "the repository itself, with its owner's token",
                |c| {
                    c.from("o/r", false);
                    c.me("o");
                },
                "from a branch of o/r itself",
            ),
            (
                "the repository itself, with a directory there",
                |c| {
                    c.from("o/r", false);
                    c.set(OWN_ACCEPTS, 200, json!([naming(&["o/r"])]));
                },
                "naming o/r to its default branch",
            ),
            (
                "the repository itself, with a symbolic link there",
                |c| {
                    c.from("o/r", false);
                    let mut link = naming(&["o/r"]);
                    link["type"] = json!("symlink");
                    c.set(OWN_ACCEPTS, 200, link);
                },
                "naming o/r to its default branch",
            ),
            (
                "the repository itself, with an empty file",
                |c| {
                    c.from("o/r", false);
                    c.set(OWN_ACCEPTS, 200, naming(&[]));
                },
                "naming o/r to its default branch",
            ),
            // Write access is not the fork owner's acceptance that its
            // workflows run an agent's commit with its secrets.
            (
                "another's writable fork, without its opt-in",
                |c| {
                    c.routes.remove(ACCEPTS);
                },
                "is from carol/r, not bot's fork with Actions turned off, whose CI would run the pushed \
                 commit with its secrets: add .github/agentic-job/accept-owner-branches naming carol/r",
            ),
            // A fork made or synced from a target that accepts holds its file.
            (
                "another's fork, with the file it inherited",
                |c| c.set(ACCEPTS, 200, naming(&["o/r"])),
                "naming carol/r",
            ),
            (
                "another's fork, with a name like its own",
                |c| c.set(ACCEPTS, 200, naming(&["carol/r2", "xcarol/r"])),
                "naming carol/r",
            ),
            (
                "another's fork, with a file too large to be one",
                |c| c.edit(ACCEPTS, "size", json!(4097)),
                "naming carol/r",
            ),
            (
                "another's fork, with content the forge did not give",
                |c| c.edit(ACCEPTS, "content", Value::Null),
                "naming carol/r",
            ),
            // A forge that could not answer is not a refusal to report as
            // one, and only a missing opt-in is read as its absence.
            (
                "an opt-in the forge could not read",
                |c| c.set(ACCEPTS, 500, json!({})),
                "HTTP 500",
            ),
            (
                "a head repository the forge could not read",
                |c| {
                    c.routes.remove(CAROL);
                },
                "HTTP 404",
            ),
            (
                "a branch the forge could not read",
                |c| {
                    c.routes.remove(BRANCH);
                },
                "HTTP 404",
            ),
            (
                "rules the forge could not read",
                |c| {
                    c.routes.remove(RULES);
                },
                "HTTP 404",
            ),
            (
                "a replacement base that is not a commit",
                |c| {
                    c.replacement = true;
                    c.set(
                        "GET /repos/o/r/git/ref/heads/main",
                        200,
                        json!({"object": {"type": "tag", "sha": sha('c')}}),
                    );
                },
                "the base branch main of o/r is not at a commit",
            ),
            (
                "a token /user does not name",
                |c| c.set("GET /user", 401, json!({})),
                "a pull request is opened from a fork of the identity apply holds: GET /user: HTTP 401",
            ),
            (
                "a token /user names nobody",
                |c| c.me(""),
                "GET /user names nobody",
            ),
            // A repository of the identity's that is not the fork the forge answers with.
            (
                "a repository of the identity's that is not its fork",
                |c| c.from("bot/other", true),
                "is from bot/other:fix/x, not from bot/r: a push goes only to the branch of a pull \
                 request apply opened from bot's fork",
            ),
            (
                "an owner's push from a fork it cannot have",
                |c| {
                    c.from("o/r2", true);
                    c.me("o");
                    c.set("GET /repos/o/r2", 200, repo("o/r2", true));
                    c.set(
                        "GET /repos/o/r2/branches/fix/x",
                        200,
                        json!({"protected": false}),
                    );
                    c.set("GET /repos/o/r2/rules/branches/fix/x", 200, json!([]));
                },
                "o owns o/r and has no fork of it to push to: a push goes only to a branch",
            ),
            (
                "an owner's new pull request, without the opt-in",
                |c| {
                    c.new_pull_request();
                    c.me("o");
                },
                "o owns o/r and has no fork of it to push to: apply as an account that does not own it, \
                or, for a new pull request, add .github/agentic-job/accept-owner-branches naming o/r",
            ),
            (
                "an owner's new pull request, with a file naming another repository",
                |c| {
                    c.new_pull_request();
                    c.me("o");
                    c.set(OWN_ACCEPTS, 200, naming(&["upstream/r"]));
                },
                "naming o/r to its default branch",
            ),
            // A workflow file the agent wrote would run on its own branch.
            (
                "an owner's new pull request, with .github exempted",
                |c| {
                    c.new_pull_request();
                    c.me("o");
                    c.set(OWN_ACCEPTS, 200, naming(&["o/r"]));
                    c.config[CREATE_PULL_REQUEST]["unprotected_dot_folders"] = json!([".github"]);
                },
                "with .github exempted from protection",
            ),
            (
                "an owner's new pull request, with an opt-in the forge could not read",
                |c| {
                    c.new_pull_request();
                    c.me("o");
                    c.set(OWN_ACCEPTS, 500, json!({}));
                },
                "HTTP 500",
            ),
            // What the forge answers with is the user's repository in the network.
            (
                "a fork in a different network",
                |c| {
                    c.same_network_fork();
                    c.edit(FORK, "source", json!({"full_name": "unrelated/r"}));
                },
                "which is not bot's own fork of it",
            ),
            (
                "a fork without a source when the parent differs",
                |c| {
                    c.same_network_fork();
                    c.edit(FORK, "source", Value::Null);
                },
                "which is not bot's own fork of it",
            ),
            (
                "a fork target without a source when the parent differs",
                |c| {
                    c.same_network_fork();
                    c.edit("GET /repos/o/r", "source", Value::Null);
                },
                "which is not bot's own fork of it",
            ),
            (
                "a fork that is not one",
                |c| {
                    c.same_network_fork();
                    c.edit(FORK, "fork", json!(false));
                },
                "which is not bot's own fork of it",
            ),
            (
                "another user's repository",
                |c| {
                    c.same_network_fork();
                    c.edit(FORK, "owner", json!({"login": "other"}));
                },
                "which is not bot's own fork of it",
            ),
            (
                "the repository the run worked on, a fork the user owns",
                |c| {
                    c.new_pull_request();
                    c.repo = "Bot/R";
                },
                "the run's own repository",
            ),
            // A push with the user's token would run the fork's workflows, with its secrets.
            (
                "a token that may not turn Actions off",
                |c| {
                    c.new_pull_request();
                    c.set(ACTIONS, 403, json!({}));
                },
                "Actions could not be turned off on the fork bot/r",
            ),
            (
                "a fork whose Actions stay on",
                |c| {
                    c.new_pull_request();
                    c.set(
                        "GET /repos/bot/r/actions/permissions",
                        200,
                        json!({"enabled": true}),
                    );
                },
                "Actions could not be turned off",
            ),
            (
                "a fork git never reaches",
                |c| {
                    c.new_pull_request();
                    c.edit(FORK, "full_name", json!("bot/r-1"));
                },
                "the fork bot/r-1 is still not there after",
            ),
        ];
        for (what, edit, want) in cases {
            let mut case = Case::new();
            edit(&mut case);
            let err = match case.run().0 {
                Ok(target) => panic!("{what}: {target:?}"),
                Err(err) => format!("{err:#}"),
            };
            assert!(err.contains(want), "{what}: {err}");
            assert!(!err.contains(TOKEN), "{what}: {err}");
        }
    }

    #[test]
    fn resolves() {
        let args = || ResolveArgs {
            event: "false".into(),
            review: "false".into(),
            kind: "branch".into(),
            item: "42".into(),
            repo: "o/r".into(),
            output_repo: "o/r".into(),
        };
        let resolved = Resolved {
            branch: "fix/x".into(),
            head: sha('a'),
            base: sha('c'),
            author: "carol".into(),
        };
        // An app's pull request resolves, by no author a bound can name.
        let mut app = Case::new();
        app.edit(PULL, "user", json!({"login": "renovate[bot]"}));
        let (github, _requests) = forge(app.routes);
        assert_eq!(resolve(&github, &args(), false).unwrap().author, "");
        type Edit = fn(&mut ResolveArgs, &mut Case);
        // (what, the request and forge, the error's words or none)
        let cases: Vec<(&str, Edit, Option<&str>)> = vec![
            ("a pull request from another's fork", |_, _| {}, None),
            (
                "outputs named in another case",
                |a, _| a.output_repo = "O/R".into(),
                None,
            ),
            (
                "the forge's names in another case",
                |_, c| {
                    c.edit(
                        PULL,
                        "base",
                        json!({"ref": "main",
                "sha": sha('b'), "repo": {"full_name": "O/R"}}),
                    )
                },
                None,
            ),
            // Whose branch it is, and whether apply may push there, apply decides (#553).
            (
                "a branch of the repository itself",
                |_, c| c.from("o/r", false),
                None,
            ),
            (
                "an event's run",
                |a, _| a.event = "true".into(),
                Some("needs a branch run"),
            ),
            (
                "a review",
                |a, _| a.review = "true".into(),
                Some("needs a branch run"),
            ),
            (
                "another kind",
                |a, _| a.kind = "analysis".into(),
                Some("needs a branch run"),
            ),
            (
                "outputs elsewhere",
                |a, _| a.output_repo = "other/r".into(),
                Some("needs a branch run"),
            ),
            (
                "outputs nowhere",
                |a, _| a.output_repo = String::new(),
                Some("needs a branch run"),
            ),
            (
                "a number with a leading zero",
                |a, _| a.item = "042".into(),
                Some("needs a branch run"),
            ),
            (
                "a number with a space",
                |a, _| a.item = "42 ".into(),
                Some("needs a branch run"),
            ),
            (
                "no number",
                |a, _| a.item = String::new(),
                Some("needs a branch run"),
            ),
            (
                "a number too long",
                |a, _| a.item = "9999999999".into(),
                Some("needs a branch run"),
            ),
            (
                "a path for a repository",
                |a, _| {
                    a.repo = "o/r/x".into();
                    a.output_repo = "o/r/x".into();
                },
                Some("needs a branch run"),
            ),
            (
                "a closed pull request",
                |_, c| c.edit(PULL, "state", json!("closed")),
                Some("open pull request"),
            ),
            (
                "another pull request",
                |_, c| c.edit(PULL, "number", json!(43)),
                Some("open pull request"),
            ),
            (
                "no base commit",
                |_, c| c.routes.get_mut(PULL).unwrap().1["base"]["sha"] = Value::Null,
                Some("open pull request"),
            ),
            (
                "a base commit not in lower case",
                |_, c| c.routes.get_mut(PULL).unwrap().1["base"]["sha"] = json!(sha('B')),
                Some("open pull request"),
            ),
            (
                "a base in another repository",
                |_, c| {
                    c.edit(
                        PULL,
                        "base",
                        json!({"ref": "main",
                "sha": sha('b'), "repo": {"full_name": "other/r"}}),
                    )
                },
                Some("open pull request"),
            ),
            (
                "a deleted head repository",
                |_, c| c.routes.get_mut(PULL).unwrap().1["head"]["repo"] = Value::Null,
                Some("open pull request"),
            ),
            (
                "a head repository without a name",
                |_, c| c.routes.get_mut(PULL).unwrap().1["head"]["repo"] = json!({"fork": true}),
                Some("open pull request"),
            ),
            (
                "a head not in lower case",
                |_, c| c.routes.get_mut(PULL).unwrap().1["head"]["sha"] = json!(sha('A')),
                Some("open pull request"),
            ),
            (
                "no branch",
                |_, c| c.routes.get_mut(PULL).unwrap().1["head"]["ref"] = Value::Null,
                Some("open pull request"),
            ),
            (
                "a branch with a newline",
                |_, c| c.routes.get_mut(PULL).unwrap().1["head"]["ref"] = json!("fix\nx=y"),
                Some("open pull request"),
            ),
            // Its base is the forge's branch head now, never the stale sha.
            (
                "a base branch at a tag",
                |_, c| {
                    c.set(
                        "GET /repos/o/r/git/ref/heads/main",
                        200,
                        json!({"object": {"type": "tag", "sha": sha('c')}}),
                    )
                },
                Some("is not at a commit"),
            ),
            (
                "a base branch at no commit",
                |_, c| {
                    c.set(
                        "GET /repos/o/r/git/ref/heads/main",
                        200,
                        json!({"object": {"type": "commit", "sha": "main"}}),
                    )
                },
                Some("is not at a commit"),
            ),
            (
                "a base branch the forge could not read",
                |_, c| {
                    c.routes.remove("GET /repos/o/r/git/ref/heads/main");
                },
                Some("HTTP 404"),
            ),
            (
                "an empty base branch",
                |_, c| c.routes.get_mut(PULL).unwrap().1["base"]["ref"] = json!(""),
                Some("the pull request's base is not a branch of o/r"),
            ),
        ];
        for (what, edit, want) in cases {
            let (mut args, mut case) = (args(), Case::new());
            edit(&mut args, &mut case);
            let (github, _requests) = forge(case.routes);
            match (resolve(&github, &args, false), want) {
                (Ok(got), None) => assert_eq!(got, resolved, "{what}"),
                (Err(err), Some(want)) => {
                    assert!(format!("{err:#}").contains(want), "{what}: {err:#}")
                }
                (got, _) => panic!("{what}: {got:?}"),
            }
        }
    }
}
