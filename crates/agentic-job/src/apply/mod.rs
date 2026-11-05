//! `agentic-job apply`: publish what `check` accepted to a forge that is
//! not GitHub, from a job of its own that holds the write token. GitHub's
//! apply is still gh-aw's handlers in apply.yml, but for the types the
//! bounds route to [`publish`] (comments, new pull requests, labels and
//! closing);
//! this is the first slice of moving publishing behind [`Publisher`]
//! (#1346). On GitHub, [`secondary`] opens the policy's secondary pull
//! request after the handlers.
//!
//! The plan of every write, the Forgejo and GitLab publishers, their push
//! and the filtering of what they post, and GitHub's client and native
//! publishing, are the safe-outputs library's ([`safe_outputs::apply`]),
//! re-exported here at their old paths. This is its adapter: it reads the
//! policy, the check job's upload without following a link, and the token,
//! or the caller's role bindings and their tokens ([`roles::Routed`]),
//! from the environment, and gives the library agentic-job's footer,
//! commit status context and committer ([`PROVENANCE`]).

pub mod applied;
pub mod github;
pub mod issue_reference;
pub mod publish;
pub mod push;
pub mod readiness;
pub mod replacement;
pub mod result;
pub mod secondary;
pub mod status;

use std::path::{Path, PathBuf};

use anyhow::Result;
pub use safe_outputs::apply::*;

use crate::exit::Exit;
use crate::files;
use crate::policy::{Load, Policy};

/// The environment variable holding the forge's token: never an
/// argument, which any user of the machine can read in `/proc`.
pub const TOKEN_ENV: &str = "FORGEJO_TOKEN";

/// GitLab's, as [`TOKEN_ENV`] is Forgejo's.
pub const GITLAB_TOKEN_ENV: &str = "GITLAB_TOKEN";

/// The context of every commit status apply writes: the caller's, never
/// a request's, so that a branch protection rule naming it can trust it.
pub const STATUS_CONTEXT: &str = "agentic-job";

/// How agentic-job names what it publishes: the footer's link text, the
/// commit status context, and the committer of a pushed commit, which
/// names the tool at an address that cannot receive mail (RFC 2606).
pub const PROVENANCE: Provenance<'static> = Provenance {
    name: "agentic-job",
    status_context: STATUS_CONTEXT,
    committer: ("agentic-job", "agentic-job@invalid"),
};

fn token_env(forge: Forge) -> &'static str {
    match forge {
        Forge::Forgejo => TOKEN_ENV,
        Forge::Gitlab => GITLAB_TOKEN_ENV,
    }
}

/// A file of the check job's upload, read without following a link.
pub(crate) fn read_checked(path: &Path, max: u64) -> Result<Vec<u8>> {
    Ok(files::read_regular(path, max)?)
}

/// The check job's upload in DIR, as the library reads it.
pub(crate) fn upload(dir: &Path) -> Upload<'_> {
    Upload {
        dir,
        read: &read_checked,
    }
}

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The forge to publish to
    #[arg(long, value_enum)]
    pub forge: Forge,
    /// The forge's address, without `/api/v1`
    #[arg(long, value_name = "URL")]
    pub server: String,
    /// The repository to publish to: the policy's
    #[arg(long, value_name = "OWNER/NAME")]
    pub repo: String,
    /// The policy.json that `check` checked against
    #[arg(long, value_name = "FILE")]
    pub policy: PathBuf,
    /// The check job's upload: its report.json and the patch it accepted
    #[arg(long, value_name = "DIR")]
    pub checked: PathBuf,
    /// The issue or pull request a comment goes to, from the caller
    #[arg(long, value_name = "NUMBER", value_parser = clap::value_parser!(u64).range(1..))]
    pub comment_target: Option<u64>,
    /// What --comment-target numbers, on GitLab, where an issue and a
    /// merge request may share a number
    #[arg(long, value_enum, requires = "comment_target")]
    pub comment_target_kind: Option<Kind>,
    /// The run's page, linked from the footer of what is posted
    #[arg(long, value_name = "URL")]
    pub run_url: String,
    /// The fork a pull request's branch is pushed to: the policy's `push_repo`
    #[arg(long, value_name = "OWNER/NAME")]
    pub push_repo: Option<String>,
    /// Open the PR for this exact previously pushed commit, without pushing again
    #[arg(long, value_name = "SHA")]
    pub recover_pushed_commit: Option<String>,
    /// After every other write, set this commit status, context `agentic-job`, on --status-sha
    #[arg(long, value_enum, requires = "status_sha")]
    pub status: Option<State>,
    /// The commit the caller's --status is for
    #[arg(long, value_name = "SHA", requires = "status")]
    pub status_sha: Option<String>,
    /// GitLab status's trusted pipeline ref (never read from agent output)
    #[arg(long, value_name = "REF", requires_all = ["status", "status_pipeline_id"])]
    pub status_ref: Option<String>,
    /// GitLab status's trusted project-local pipeline ID
    #[arg(long, value_name = "ID", requires_all = ["status", "status_ref"], value_parser = clap::value_parser!(u64).range(1..))]
    pub status_pipeline_id: Option<u64>,
    /// GitLab: also post the run summary `check --run-summary` accepted as
    /// a note on --comment-target, where GitHub has the job summary
    #[arg(long, requires = "comment_target_kind")]
    pub run_summary: bool,
}

/// GitLab's limit on a note's body, in characters.
const MAX_NOTE_CHARS: usize = 1_000_000;

/// The run summary check accepted, SUMMARY, as a note on the caller's
/// comment target, after the requests and before the commit status in
/// OPS, which says how all of it went. Its mentions and quick actions are
/// broken as an `add_comment`'s are. Without one, or with one too long for
/// a note, the requests are published without it.
fn add_run_summary(ops: &mut Vec<Op>, summary: Option<&str>, target: &Target<'_>) {
    let (Some(issue), Some(summary)) = (target.comment_target, summary) else {
        eprintln!("warning: check accepted no run summary, so none is posted");
        return;
    };
    let body = with_footer(
        &mentions::filter(summary, target.forge.syntax()),
        target.provenance.name,
        target.run_url,
    );
    if body.chars().count() > MAX_NOTE_CHARS {
        eprintln!("warning: the run summary is longer than a note, so it is not posted");
        return;
    }
    let at = ops
        .iter()
        .position(|op| matches!(op, Op::Status(_)))
        .unwrap_or(ops.len());
    ops.insert(at, Op::Comment { issue, body });
}

pub fn run(args: &Args) -> Result<Exit> {
    anyhow::ensure!(
        args.forge == Forge::Gitlab
            || (args.status_ref.is_none() && args.status_pipeline_id.is_none()),
        "--status-ref and --status-pipeline-id are GitLab-only"
    );
    if let Some(commit) = &args.recover_pushed_commit {
        anyhow::ensure!(
            COMMIT_RE.is_match(commit),
            "--recover-pushed-commit requires a full commit SHA"
        );
    }
    anyhow::ensure!(
        args.forge == Forge::Gitlab || args.comment_target_kind.is_none(),
        "--comment-target-kind is GitLab's: Forgejo numbers issues and pull requests together"
    );
    let policy = Policy::load(&args.policy)?;
    // Only the caller's environment binds roles: never a request or the
    // agent's output. With a mapping, the forge token is not read at all.
    let publisher: Box<dyn Publisher> = match roles::read(&|key| std::env::var(key).ok())? {
        None => {
            let token_env = token_env(args.forge);
            let token = std::env::var(token_env).unwrap_or_default();
            anyhow::ensure!(!token.is_empty(), "{token_env} is not set");
            forge_publisher(args, &policy, token, None, None)?
        }
        Some(credentials) => Box::new(roles::Routed::new(&credentials, |_, credential, push| {
            forge_publisher(
                args,
                &policy,
                credential.token.clone(),
                push.map(str::to_owned),
                Some(credential.identity.actor_id),
            )
        })?),
    };
    let target = Target {
        forge: args.forge,
        repo: &args.repo,
        push_repo: args.push_repo.as_deref(),
        comment_target: args.comment_target,
        run_url: &args.run_url,
        status: args.status.zip(args.status_sha.as_deref()),
        provenance: PROVENANCE,
    };
    let mut ops = match plan(&upload(&args.checked), &policy, &target) {
        Ok(ops) => ops,
        Err(errors) => {
            for error in errors {
                eprintln!("error: {}", crate::run::enter::one_line(&error));
            }
            return Ok(Exit::Failure);
        }
    };
    if args.run_summary {
        let report = read_report(&upload(&args.checked))?;
        add_run_summary(&mut ops, report.run_summary.as_deref(), &target);
    }
    for url in publish(&ops, publisher.as_ref())? {
        println!("{url}");
    }
    Ok(Exit::Success)
}

/// The forge's publisher, with TOKEN for its API; PUSH, if given, for git
/// (see [`roles::Routed`]); and OWNER, the numeric actor TOKEN is bound to.
fn forge_publisher(
    args: &Args,
    policy: &Policy,
    token: String,
    push: Option<String>,
    owner: Option<u64>,
) -> Result<Box<dyn Publisher>> {
    Ok(match args.forge {
        Forge::Forgejo => Box::new(
            forgejo::Forgejo::new(&args.server, &policy.repo, token, &policy.allow_http)?
                .recovering(args.recover_pushed_commit.clone())
                .pushing_with(push),
        ),
        Forge::Gitlab => Box::new(
            gitlab::Gitlab::new(&args.server, &policy.repo, token, &policy.allow_http)?
                .recovering(args.recover_pushed_commit.clone())
                .commenting_on(args.comment_target_kind)
                .status_context(args.status_ref.clone().zip(args.status_pipeline_id))
                .pushing_with(push)
                .owned_by(owner),
        ),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::check::BASE_COMMIT_HEADER;

    const HEAD: &str = crate::policy::tests::HEAD;
    const RUN: &str = "https://forge.example/o/r/actions/runs/7";

    /// A push run's upload: pull request 42's branch `agent-run-12` at
    /// `HEAD`, and its patch, which LINK, if set, makes a link to it.
    fn checked_push(link: bool) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let patch = format!(
            "From {HEAD} Mon Sep 17 00:00:00 2001\n\
             {BASE_COMMIT_HEADER}: {HEAD}\n\
             From: agent <agent@localhost>\n\
             Date: Tue, 6 Oct 2026 21:02:35 -0400\n\
             Subject: [PATCH] Change things\n\
             \n\
             ---\n \
             src/x | 1 +\n\
             \n\
             diff --git a/src/x b/src/x\nnew file mode 100644\nindex 0000000..587be6b\n\
             --- /dev/null\n+++ b/src/x\n@@ -0,0 +1 @@\n+x\n"
        );
        let name = "aw-agent-run-12.patch";
        let path = dir.path().join(name);
        if link {
            std::fs::write(dir.path().join("elsewhere"), &patch).unwrap();
            std::os::unix::fs::symlink(dir.path().join("elsewhere"), &path).unwrap();
        } else {
            std::fs::write(&path, &patch).unwrap();
        }
        let report = json!({
            "ok": true, "errors": [],
            "items": [
                {"type": "push_to_pull_request_branch", "message": "m", "branch": "agent-run-12"},
                {"type": "add_comment", "body": "Done."},
            ],
            "patch": {"file": name, "bytes": patch.len(), "base_commit": HEAD, "files": ["src/x"]},
        });
        std::fs::write(dir.path().join(REPORT_FILE), report.to_string()).unwrap();
        dir
    }

    fn policy() -> Policy {
        let mut policy = crate::policy::tests::push_policy_to("bot/bootc");
        policy.safe_outputs.others.insert(
            "add_comment".to_owned(),
            crate::policy::OutputLimit {
                max: 1,
                ..Default::default()
            },
        );
        policy
    }

    fn target() -> Target<'static> {
        Target {
            forge: Forge::Forgejo,
            repo: "bootc-dev/bootc",
            push_repo: Some("bot/bootc"),
            comment_target: Some(64),
            run_url: RUN,
            status: Some((State::Success, HEAD)),
            provenance: PROVENANCE,
        }
    }

    /// What apply has always written as agentic-job, byte for byte: its
    /// footer, its commit status context and its committer.
    #[test]
    fn publishes_as_agentic_job() {
        let dir = checked_push(false);
        let ops = plan(&upload(dir.path()), &policy(), &target()).unwrap();
        let committer = Committer {
            name: "agentic-job".to_owned(),
            email: "agentic-job@invalid".to_owned(),
        };
        let Op::Push(push) = &ops[0] else {
            panic!("{ops:?}")
        };
        assert_eq!(push.committer, committer);
        assert_eq!(
            ops[1],
            Op::Comment {
                issue: 64,
                body: format!("Done.\n\n> Generated by [agentic-job]({RUN})"),
            }
        );
        assert_eq!(
            ops[2],
            Op::Status(CommitStatus {
                sha: HEAD.to_owned(),
                state: State::Success,
                target_url: RUN.to_owned(),
                context: "agentic-job".to_owned(),
            })
        );
    }

    /// GitLab's target: merge request 5 of `owner/name`.
    fn gitlab_target() -> Target<'static> {
        Target {
            forge: Forge::Gitlab,
            repo: "owner/name",
            push_repo: None,
            comment_target: Some(5),
            ..target()
        }
    }

    /// A GitLab run's summary, as check's report holds it, is a note on
    /// the caller's merge request after what the run made and before its
    /// status, posted through the GitLab publisher with mentions and quick
    /// actions broken.
    #[test]
    fn posts_the_run_summary_as_a_gitlab_note() {
        let dir = tempfile::tempdir().unwrap();
        let report = json!({"ok": true, "errors": [], "items": [], "patch": null,
            "run_summary": "## Agent run: @all\n\n/merge"});
        std::fs::write(dir.path().join(REPORT_FILE), report.to_string()).unwrap();
        let summary = read_report(&upload(dir.path())).unwrap().run_summary;
        let status = Op::Status(CommitStatus {
            sha: HEAD.to_owned(),
            state: State::Success,
            target_url: RUN.to_owned(),
            context: STATUS_CONTEXT.to_owned(),
        });
        let comment = Op::Comment {
            issue: 5,
            body: "Done.".to_owned(),
        };
        let mut ops = vec![comment.clone(), status.clone()];
        add_run_summary(&mut ops, summary.as_deref(), &gitlab_target());
        let body = format!(
            "## Agent run: @\u{200b}all\n\n\u{200b}/merge\n\n> Generated by [agentic-job]({RUN})"
        );
        let note = Op::Comment {
            issue: 5,
            body: body.clone(),
        };
        assert_eq!(ops, [comment, note.clone(), status]);

        let project = json!({"id": 1, "path_with_namespace": "owner/name", "visibility": "public"});
        let item = json!({"iid": 5, "project_id": 1, "state": "opened", "labels": [],
            "web_url": "https://gitlab.example/owner/name/-/merge_requests/5"});
        let (server, requests) = testing::mock(
            [&project, &item, &project, &item]
                .map(|answer| (200, answer.to_string()))
                .into_iter()
                .chain([(201, json!({"id": 30}).to_string())])
                .collect(),
        );
        let gitlab = gitlab::Gitlab::new(&format!("{server}/"), "owner/name", "t".to_owned(), &[])
            .unwrap()
            .commenting_on(Some(Kind::PullRequest));
        let made = publish(&[note], &gitlab).unwrap();
        assert_eq!(
            made,
            ["https://gitlab.example/owner/name/-/merge_requests/5#note_30"]
        );
        let post = requests.iter().last().unwrap();
        assert_eq!(
            post.line,
            "POST /api/v4/projects/1/merge_requests/5/notes HTTP/1.1"
        );
        assert_eq!(post.body, json!({ "body": body }));
    }

    /// Without a summary check accepted, or with one that breaking its
    /// mentions makes longer than a note, the requests go without it.
    #[test]
    fn leaves_out_a_run_summary_it_cannot_post() {
        let mentions = "@a ".repeat(MAX_NOTE_CHARS / 3);
        for (name, summary) in [("none", None), ("too long", Some(mentions.as_str()))] {
            let mut ops = Vec::new();
            add_run_summary(&mut ops, summary, &gitlab_target());
            assert!(ops.is_empty(), "{name}");
        }
    }

    /// The upload is read without following a link: a patch that is one
    /// is refused before any write.
    #[test]
    fn refuses_a_linked_patch() {
        let dir = checked_push(true);
        let errors = plan(&upload(dir.path()), &policy(), &target()).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.contains("the patch aw-agent-run-12.patch")
                    && error.contains("is not a regular file")),
            "{errors:?}"
        );
    }
}
