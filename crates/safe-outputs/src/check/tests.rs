//! The check through the library's own entry point, without a run: a
//! hand-back given as bytes, the policy as `policy` writes it
//! ([`super::fixtures`]), and publishers and a lifecycle of the test's
//! own. agentic-job's tests hold the same rules through its `check`
//! command, reading a directory.

use std::cell::RefCell;

use anyhow::anyhow;
use serde_json::json;

use super::fixtures::{policy, push_policy};
use super::*;
use crate::contract::OutputLimit;

const REPO: &str = "bootc-dev/bootc";
const BASE: &str = "1111111111111111111111111111111111111111";
const HEAD: &str = "2222222222222222222222222222222222222222";
const BRANCH: &str = "agent-run-7";
const PATCH: &str = "aw-agent-run-7.patch";
const PUSH_BRANCH: &str = "agent-run-12";
const PUSH_PATCH: &str = "aw-agent-run-12.patch";

/// Publishers that refuse only what a test tells them to.
#[derive(Default)]
struct Fake {
    inline: Option<&'static str>,
    native: Vec<String>,
}

impl Publishers for Fake {
    fn inline_comment(&self, _: &Map<String, Value>, _: Forge) -> Result<()> {
        self.inline.map_or(Ok(()), |error| Err(anyhow!(error)))
    }

    fn native_refusals(&self, _: &[Value], _: &[String]) -> Vec<String> {
        self.native.clone()
    }
}

/// One commit's `git format-patch` mail changing PATH, without the
/// header naming its base.
fn mail(path: &str) -> String {
    format!(
        "From {HEAD} Mon Sep 17 00:00:00 2001\n\
         From: agent <agent@localhost>\n\
         Date: Tue, 6 Oct 2026 21:02:35 -0400\n\
         Subject: [PATCH] Change things\n\
         \n\
         Why it changes.\n\
         ---\n \
         {path} | 2 +-\n \
         1 file changed, 1 insertion(+), 1 deletion(-)\n\
         \n\
         diff --git a/{path} b/{path}\nindex f328e4d..a83147c 100644\n\
         --- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-fn main() {{}}\n+fn main() {{ 1 }}\n"
    )
}

/// The same against BASE_COMMIT, as `run` hands it back.
fn patch(path: &str, base_commit: &str) -> String {
    mail(path).replacen(
        "\nFrom: ",
        &format!("\n{BASE_COMMIT_HEADER}: {base_commit}\nFrom: "),
        1,
    )
}

fn base(repo: &str, r#ref: &str, commit: &str) -> String {
    json!({"repo": repo, "ref": r#ref, "commit": commit}).to_string()
}

fn pull_request() -> Value {
    json!({"type": CREATE_PULL_REQUEST, "title": "t", "body": "b", "branch": BRANCH})
}

fn push() -> Value {
    json!({"type": PUSH_TO_PULL_REQUEST_BRANCH, "message": "m", "branch": PUSH_BRANCH})
}

/// A hand-back's files, owned, and the requests the collector accepted.
#[derive(Clone)]
struct Case {
    items: Vec<Value>,
    outputs: bool,
    base: Option<String>,
    replacement: Option<String>,
    patches: Vec<(String, String)>,
}

impl Case {
    /// A pull request with its patch changing PATH.
    fn pull_request(path: &str) -> Self {
        Self {
            items: vec![pull_request()],
            outputs: true,
            base: Some(base(REPO, "main", BASE)),
            replacement: None,
            patches: vec![(PATCH.into(), patch(path, BASE))],
        }
    }

    /// A push to pull request 42's branch, on the head it was asked at.
    fn push(path: &str) -> Self {
        Self {
            items: vec![push()],
            base: Some(base(REPO, PUSH_BRANCH, HEAD)),
            patches: vec![(PUSH_PATCH.into(), patch(path, HEAD))],
            ..Self::pull_request(path)
        }
    }

    fn check_with(
        &self,
        policy: &Policy,
        publishers: &dyn Publishers,
        lifecycle: impl FnMut(Option<&Map<String, Value>>) -> Vec<String>,
    ) -> Checked {
        let lines: String = self.items.iter().map(|item| format!("{item}\n")).collect();
        let handback = Handback {
            outputs: self.outputs.then_some(lines.as_bytes()),
            base: self.base.as_deref().map(str::as_bytes),
            secondary_base: None,
            replacement: self.replacement.as_deref().map(str::as_bytes),
            patches: self
                .patches
                .iter()
                .map(|(name, text)| (name.as_str(), text.as_bytes()))
                .collect(),
        };
        let collected = Collected {
            items: self
                .items
                .iter()
                .map(|item| item.as_object().unwrap().clone())
                .collect(),
            errors: Vec::new(),
        };
        let trusted = Trusted {
            comment: Some((REPO, 7)),
            run_id: Some("7"),
        };
        check(&handback, collected, policy, trusted, publishers, lifecycle)
    }

    fn check(&self, policy: &Policy) -> Checked {
        self.check_with(policy, &Fake::default(), |_| Vec::new())
    }
}

#[test]
fn a_pull_request_with_its_patch_is_accepted() {
    let checked = Case::pull_request("src/lib.rs").check(&policy());
    assert_eq!(checked.errors, Vec::<String>::new());
    let patch = checked.patch.unwrap();
    assert_eq!(
        (patch.file.as_str(), patch.base_commit.as_str()),
        (PATCH, BASE)
    );
    assert_eq!(patch.files, ["src/lib.rs"]);
    assert_eq!(checked.items.len(), 1);
}

#[test]
fn refusals() {
    let ok = Case::pull_request("src/lib.rs");
    let with = |change: &dyn Fn(&mut Case)| {
        let mut case = ok.clone();
        change(&mut case);
        case
    };
    let mut globbed = policy();
    globbed
        .safe_outputs
        .create_pull_request
        .as_mut()
        .unwrap()
        .protected_paths = vec!["raw/**".into()];
    let mut small = policy();
    small.max_patch_bytes = 64;
    let noop = json!({"type": "noop", "message": "nothing"});
    // The name, the hand-back, the policy, and a part of a refusal.
    let cases: Vec<(&str, Case, Policy, &str)> = vec![
        (
            "a protected file",
            Case::pull_request("package.json"),
            policy(),
            "package.json",
        ),
        (
            "a protected dot-folder",
            Case::pull_request(".github/workflows/ci.yml"),
            policy(),
            ".github/workflows/ci.yml",
        ),
        (
            "a path the bounds protect",
            Case::pull_request("raw/notes.md"),
            globbed,
            "protected by the bounds' glob \"raw/**\"",
        ),
        (
            "a patch over its budget",
            ok.clone(),
            small,
            "bytes, over 64",
        ),
        (
            "a patch against another commit than base.json's",
            with(&|case| case.patches = vec![(PATCH.into(), patch("src/lib.rs", HEAD))]),
            policy(),
            PATCH,
        ),
        (
            "a base in another repository",
            with(&|case| case.base = Some(base("other/repo", "main", BASE))),
            policy(),
            "base.json is not {repo: bootc-dev/bootc, ref: main, commit: SHA}",
        ),
        (
            "a base on another branch",
            with(&|case| case.base = Some(base(REPO, "next", BASE))),
            policy(),
            "base.json is not",
        ),
        (
            "a base that is not a commit",
            with(&|case| case.base = Some(base(REPO, "main", "main"))),
            policy(),
            "base.json is not",
        ),
        (
            "a malformed base",
            with(&|case| case.base = Some("{\"repo\":".into())),
            policy(),
            "base.json is not",
        ),
        (
            "no patch",
            with(&|case| case.patches.clear()),
            policy(),
            "create_pull_request needs exactly one patch, aw-agent-run-7.patch; there is none",
        ),
        (
            "a second patch",
            with(&|case| {
                case.patches
                    .push(("aw-other.patch".into(), patch("src/a.rs", BASE)))
            }),
            policy(),
            "needs exactly one patch",
        ),
        (
            "a patch named as no patch is",
            with(&|case| case.patches.push(("patch.diff".into(), String::new()))),
            policy(),
            "unexpected file \"patch.diff\"",
        ),
        (
            "a pull request to another repository",
            with(&|case| case.items[0]["repo"] = json!("other/repo")),
            policy(),
            "a create_pull_request with repo \"other/repo\", which is not the policy's",
        ),
        (
            "a pull request to another base",
            with(&|case| case.items[0]["base"] = json!("next")),
            policy(),
            "a create_pull_request with base \"next\", which is not the policy's",
        ),
        (
            "a pull request that is not a draft",
            with(&|case| case.items[0]["draft"] = json!(false)),
            policy(),
            "a create_pull_request that is not a draft",
        ),
        (
            "a type the policy does not allow",
            with(&|case| case.items.push(json!({"type": "add_comment", "body": "b"}))),
            policy(),
            "an output of type \"add_comment\", which the policy does not allow",
        ),
        (
            "more of a type than its max",
            with(&|case| case.items.extend([noop.clone(), noop.clone()])),
            policy(),
            "2 outputs of type \"noop\", over 1",
        ),
        (
            "more outputs than max_outputs",
            with(&|case| {
                case.items
                    .extend([noop.clone(), noop.clone(), noop.clone()])
            }),
            policy(),
            "4 outputs, over max_outputs 3",
        ),
        (
            "apply's marker",
            with(&|case| case.items[0]["body"] = json!("x agentic-job-applied y")),
            policy(),
            "a create_pull_request holding agentic-job-applied, which apply writes",
        ),
        (
            "requests without outputs.jsonl",
            with(&|case| case.outputs = false),
            policy(),
            "the collector's result holds outputs, and there is no outputs.jsonl",
        ),
        (
            "a patch without its request",
            with(&|case| case.items = vec![noop.clone()]),
            policy(),
            "a patch without a create_pull_request",
        ),
        (
            "a replacement for a pull request",
            with(&|case| case.replacement = Some("{}".into())),
            policy(),
            "a replacement without a push request",
        ),
    ];
    for (name, case, policy, want) in cases {
        let errors = case.check(&policy).errors;
        assert!(
            errors.iter().any(|error| error.contains(want)),
            "{name}: {errors:?}"
        );
    }
}

#[test]
fn a_push_is_held_to_the_head_it_was_asked_at() {
    let policy = push_policy();
    let checked = Case::push("src/lib.rs").check(&policy);
    assert_eq!(checked.errors, Vec::<String>::new());
    assert_eq!(checked.patch.unwrap().base_commit, HEAD);
    // The branch moved since: another's work, which the push would be
    // on top of.
    let moved = Case {
        base: Some(base(REPO, PUSH_BRANCH, BASE)),
        patches: vec![(PUSH_PATCH.into(), patch("src/lib.rs", BASE))],
        ..Case::push("src/lib.rs")
    };
    assert_eq!(
        moved.check(&policy).errors,
        [format!(
            "base.json is not {{repo: {REPO}, ref: {PUSH_BRANCH}, commit: {HEAD}}}: the pull \
             request's head the run was asked for"
        )]
    );
    let elsewhere = Case {
        items: vec![
            json!({"type": PUSH_TO_PULL_REQUEST_BRANCH, "message": "m", "branch": "main", "pull_request_number": 43}),
        ],
        ..Case::push("src/lib.rs")
    };
    let errors = elsewhere.check(&policy).errors;
    for want in [
        "a push_to_pull_request_branch with branch \"main\", which is not the policy's",
        "a push_to_pull_request_branch with pull_request_number 43, which is not the policy's pull request",
    ] {
        assert!(errors.iter().any(|error| error == want), "{errors:?}");
    }
}

#[test]
fn replacement_series_are_checked_commit_by_commit() {
    let mut policy = push_policy();
    let push = policy
        .safe_outputs
        .push_to_pull_request_branch
        .as_mut()
        .unwrap();
    push.replacement_max_commits = 2;
    push.replacement_base = Some(BASE.into());
    let series = |commits: &[&str]| {
        let commits: Vec<String> = commits.iter().map(|path| mail(path)).collect();
        Case {
            base: None,
            patches: Vec::new(),
            replacement: Some(json!({"base_commit": BASE, "commits": commits}).to_string()),
            ..Case::push("src/lib.rs")
        }
    };
    let checked = series(&["src/a.rs", "src/b.rs"]).check(&policy);
    assert_eq!(checked.errors, Vec::<String>::new());
    let patch = checked.patch.unwrap();
    assert_eq!(patch.file, replacement::REPLACEMENT_FILE);
    assert_eq!(
        patch.commit_files.unwrap(),
        [vec!["src/a.rs".to_owned()], vec!["src/b.rs".to_owned()]]
    );
    let alongside = Case {
        base: Some(base(REPO, PUSH_BRANCH, HEAD)),
        ..series(&["src/a.rs"])
    };
    let malformed = Case {
        replacement: Some("{\"base_commit\":".into()),
        ..series(&["src/a.rs"])
    };
    for (name, case, want) in [
        (
            "a protected file in an earlier commit",
            series(&["package.json", "src/a.rs"]),
            "replacement: replacement mail:",
        ),
        (
            "more commits than the bounds",
            series(&["src/a.rs", "src/b.rs", "src/c.rs"]),
            "replacement: replacement commit count is outside bounds",
        ),
        (
            "beside base.json",
            alongside,
            "a replacement alongside a patch or base.json",
        ),
        ("malformed", malformed, "replacement: "),
    ] {
        let errors = case.check(&policy).errors;
        assert!(
            errors.iter().any(|error| error.starts_with(want)),
            "{name}: {errors:?}"
        );
    }

    // A pull request that grew past `max_patch_files` over several
    // pushes, rebased: refused in all unless `replacement_max_files`
    // allows it, while each commit still keeps to `max_patch_files`.
    let total = |max_patch_files, replacement_max_files| {
        let mut policy = policy.clone();
        let push = policy
            .safe_outputs
            .push_to_pull_request_branch
            .as_mut()
            .unwrap();
        push.max_patch_files = max_patch_files;
        push.replacement_max_files = replacement_max_files;
        series(&["src/a.rs", "src/b.rs"]).check(&policy).errors
    };
    for (max_patch_files, replacement_max_files, want) in [
        (
            1,
            0,
            Some("replacement: replacement exceeds the total file limit"),
        ),
        (
            1,
            1,
            Some("replacement: replacement exceeds the total file limit"),
        ),
        (1, 2, None),
        (2, 0, None),
        (
            2,
            1,
            Some("replacement: replacement exceeds the total file limit"),
        ),
    ] {
        let errors = total(max_patch_files, replacement_max_files);
        assert_eq!(
            errors.first().map(String::as_str),
            want,
            "{max_patch_files} {replacement_max_files}: {errors:?}"
        );
    }
}

#[test]
fn the_caller_decides_what_it_publishes_and_its_lifecycle() {
    let mut policy = policy();
    policy.native_handlers = vec!["noop".into()];
    let mut case = Case::pull_request("src/lib.rs");
    case.base = Some(base("other/repo", "main", BASE));
    let publishers = Fake {
        native: vec!["refused by the caller's handler".into()],
        ..Fake::default()
    };
    let carriers = RefCell::new(Vec::new());
    let checked = case.check_with(&policy, &publishers, |carrier| {
        carriers
            .borrow_mut()
            .push(carrier.map(|item| item_type(item).to_owned()));
        vec!["refused by the caller's lifecycle".into()]
    });
    // Once, with the request that carries the patch, and its refusals
    // where agentic-job's checkpoint and memory always fell: after the
    // requests', before the patch's.
    assert_eq!(*carriers.borrow(), [Some(CREATE_PULL_REQUEST.to_owned())]);
    let at = |want: &str| checked.errors.iter().position(|error| error.contains(want));
    assert!(at("caller's handler") < at("caller's lifecycle"));
    assert!(at("caller's lifecycle") < at("base.json is not"));
    assert!(at("base.json is not").is_some());

    // A neutral inline comment is the caller's publisher's to refuse.
    let mut forgejo = super::fixtures::policy();
    forgejo.forge = Forge::Forgejo;
    forgejo.safe_outputs.others.insert(
        CREATE_REVIEW_COMMENT.into(),
        OutputLimit {
            max: 1,
            ..OutputLimit::default()
        },
    );
    let inline = Case {
        items: vec![
            json!({"type": CREATE_REVIEW_COMMENT, "path": "src/lib.rs", "line": 1, "body": "b"}),
        ],
        base: None,
        patches: Vec::new(),
        ..Case::pull_request("src/lib.rs")
    };
    let publishers = Fake {
        inline: Some("no neutral inline comment here"),
        ..Fake::default()
    };
    let errors = inline
        .check_with(&forgejo, &publishers, |_| Vec::new())
        .errors;
    assert_eq!(errors, ["no neutral inline comment here"]);
}

#[test]
fn comments_go_to_the_trusted_target_only() {
    let policy = policy();
    let comment = |extra: Value| {
        let mut item = json!({"type": "add_comment", "body": "b"});
        item.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        redirections_to(
            item.as_object().unwrap(),
            &policy,
            Some((REPO, 7)),
            &Fake::default(),
        )
    };
    assert!(comment(json!({"item_number": 7})).is_empty());
    assert!(comment(json!({"repo": "Bootc-Dev/Bootc"})).is_empty());
    for (extra, want) in [
        (
            json!({"item_number": 8}),
            "an add_comment with item_number outside the caller's fixed item",
        ),
        (
            json!({"comment_id": 1}),
            "an add_comment with comment_id, outside the caller's fixed destination",
        ),
        (
            json!({"repo": "other/repo"}),
            // As check has always worded it.
            "a add_comment with repo \"other/repo\", which is not the policy's",
        ),
    ] {
        assert_eq!(comment(extra.clone()), [want], "{extra}");
    }
}
