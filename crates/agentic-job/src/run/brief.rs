//! The text `run` puts before the task: where the agent leaves what it
//! hands back, in what format, and how much. In the old tree only the
//! caller's own brief said this, so every caller had to copy it. What
//! the files are is this binary's to know, since this binary reads them;
//! how to work, and what to work on, stays the caller's task.

use std::fmt::Write;
use std::path::Path;

use super::handback::{
    AGENT_OUTCOME, AGENT_OUTPUTS, MAX_LINES, MAX_OUTCOME_BYTES, MAX_OUTPUTS_BYTES,
};
use crate::policy::{
    CREATE_PULL_REQUEST, EXEMPTABLE_DOT_FOLDER, Kind, PUSH_TO_PULL_REQUEST_BRANCH, PatchRules,
    Policy,
};

const KIB: usize = 1 << 10;

/// What `check` refuses by path whatever the policy says
/// (`check::patch`), in words: an agent is not shown the pattern.
const ALWAYS_PROTECTED: &str = "any file or directory whose name starts with `.git`, in any \
                                directory (`.gitignore`, `.gitattributes`, `.gitkeep`, \
                                and the top-level `.github/` unless exempted above), \
                                `CODEOWNERS`, the merge policy \
                                `.github/agentic-job/merge.toml`, and the configuration \
                                of hooks, shells, editors and CI systems (`.husky/`, `lefthook.yml`, `.envrc`, \
                                `.vscode/`, `.pre-commit-config.yaml`, `.travis.yml`)";

/// What `check` refuses of a change's files whatever their names.
const REFUSED_KINDS: &str = "adds an executable, adds, changes or deletes a symbolic link, a \
                             submodule or a binary file, changes a file's mode, or has a path \
                             with a character other than ASCII letters, digits and `_.+@=,-` in \
                             it (no spaces, brackets or parentheses) or a part that starts with \
                             `-`";

/// What a change may not touch and how many files it may, for an agent
/// that would otherwise learn it only from `check` refusing all it did:
/// the first real run lost its whole change to one line added to a
/// README. A task that is nothing but such a change is still made: told
/// only to leave it out, an agent handed back a noop and the run ended
/// well with no result (#537); refused, it fails naming the file.
fn patch_rules(rules: &PatchRules<'_>) -> String {
    let mut text = String::from(
        " A change is refused whole, with everything else in it, if it touches one of these: ",
    );
    if !rules.protected_files.is_empty() {
        let names: Vec<String> = rules
            .protected_files
            .iter()
            .map(|name| format!("`{name}`"))
            .collect();
        let _ = write!(
            text,
            "a file of one of these names, in any directory: {}; ",
            names.join(", ")
        );
    }
    if rules.protect_top_level_dot_folders {
        text.push_str(
            "anything under a top-level directory whose name starts with a dot (`.github/`); ",
        );
        // Validation admits no other exemption.
        if rules
            .unprotected_dot_folders
            .iter()
            .any(|name| name == EXEMPTABLE_DOT_FOLDER)
        {
            let _ = write!(
                text,
                "except `{EXEMPTABLE_DOT_FOLDER}/`, which the caller exempts for this \
                 repository; "
            );
        }
    }
    let _ = write!(
        text,
        "{ALWAYS_PROTECTED}. So is a change to more than {} files, and one that \
         {REFUSED_KINDS}. Where the task asks for a change that would be refused, leave that \
         part out and say so in your report; but if it is all the task asks for, make it \
         anyway, so that the run fails naming the file instead of ending well with nothing \
         handed back.",
        rules.max_patch_files
    );
    text
}

/// The text for a run of POLICY whose agent has the home HOME and works
/// in CHECKOUT. It ends with an empty line.
pub fn hand_back(policy: &Policy, home: &Path, checkout: &Path) -> String {
    let outputs = &policy.safe_outputs;
    let carrier = outputs
        .patch_carrier()
        .filter(|_| policy.kind == Kind::Branch);
    let push = outputs
        .push_to_pull_request_branch
        .as_ref()
        .filter(|_| carrier.is_some_and(|(kind, _)| kind == PUSH_TO_PULL_REQUEST_BRANCH));
    let mut text = String::from(
        "How this run hands back its results. Nothing else leaves this machine, and all of it \
         is published.\n\n",
    );
    let tree = if let Some((_, rules)) = &carrier {
        let proposed = match push {
            Some(push) => format!(
                "pushed as one commit on top of pull request #{}'s branch, `{}`",
                push.target, policy.base
            ),
            None => "proposed as a pull request".to_owned(),
        };
        format!(
            "everything you change, add or delete in it (ignored files excepted) is collected \
             when you finish, as one patch of at most {} KiB against the commit you started \
             from, and {proposed}. Leave your changes uncommitted, and do not push.{}",
            policy.max_patch_bytes / (KIB as u64),
            patch_rules(rules)
        )
    } else {
        "this run proposes no change to the repository, so nothing you change in it is handed \
         back."
            .to_owned()
    };
    let _ = writeln!(text, "- The working tree, `{}`: {tree}", checkout.display());

    let types: Vec<String> = outputs
        .types()
        .filter(|&name| {
            carrier.is_some_and(|(kind, _)| kind == name)
                || ![CREATE_PULL_REQUEST, PUSH_TO_PULL_REQUEST_BRANCH].contains(&name)
        })
        .map(|name| match outputs.max_of(name) {
            Some(max) => format!("`{name}` (at most {max})"),
            None => format!("`{name}`"),
        })
        .collect();
    let requests = home.join(AGENT_OUTPUTS);
    if types.is_empty() {
        let _ = writeln!(
            text,
            "- `{}`: this run may make no requests; leave it unwritten.",
            requests.display()
        );
    } else {
        let _ = writeln!(
            text,
            "- `{}` (optional): your requests, as JSON Lines: one JSON object to a line, each \
             with a `type` and that type's fields as gh-aw's safe outputs define them. At most \
             {} KiB, {MAX_LINES} lines and {} requests in all. This run allows: {}. A request \
             of another type, or one that is malformed, gets all of them refused, the change \
             included.",
            requests.display(),
            MAX_OUTPUTS_BYTES / KIB,
            policy.max_outputs,
            types.join(", "),
        );
    }
    if push.is_some() {
        if let Some(push) = push.filter(|push| push.replacement_max_commits > 0) {
            let _ = writeln!(
                text,
                "  Alternatively, leave `out/replacement.json` under your home as {{\"base_commit\": \"{}\", \"commits\": [\"MAIL\", ...]}}. This replaces the entire branch with at most {} nonempty commits on that fetched base snapshot, or on the current head of the PR's base branch as trusted apply resolves it. A different base is refused at apply; fetch a newer base yourself if needed. Each MAIL is one plain `git format-patch --stdout --no-signature --no-renames -1 COMMIT` output, including its Date header, with no base header or cover letter. Every commit passes the same path rules, and the whole JSON fits the patch byte limit. Include a `push_to_pull_request_branch` request; do not also propose a working-tree patch. A moved branch is refused with an exact lease. Commit messages and existing trailers in these mails are preserved; no trailers are added.",
                push.replacement_base.as_deref().unwrap_or("unresolved"),
                push.replacement_max_commits
            );
        }
        text.push_str(
            "  To word the commit yourself, write `{\"type\": \"push_to_pull_request_branch\", \
             \"message\": \"...\"}`: the message's first line is the commit's subject and the \
             rest its body. Put no line in it that credits a tool or a model (\"Generated with \
             ...\", `Co-Authored-By:`): the run's own configuration adds the commit's trailers. \
             Without one, the message is made from the `summary` below.\n",
        );
    } else if carrier.is_some() {
        text.push_str(
            "  To word the pull request yourself, write `{\"type\": \"create_pull_request\", \
             \"title\": \"...\", \"body\": \"...\"}`: the title and the body are also the \
             message of the commit. Put no line in either that credits a tool or a model \
             (\"Generated with ...\", `Co-Authored-By:`): the run's own configuration adds the \
             commit's trailers. Without one, a pull request is made from the `summary` \
             below.\n",
        );
    }
    let _ = writeln!(
        text,
        "- `{}`: your report, written last, as one JSON object of at most {} KiB: \
         `{{\"summary\": \"...\", \"tests\": [{{\"command\": \"...\", \"exit_code\": 0, \
         \"duration_s\": 12}}], \"stopped_early\": null}}`. `summary` says what you did and \
         why; `tests` lists the commands you ran to check it, with their real exit codes; \
         `stopped_early` is null, or why you stopped before the task was done.",
        home.join(AGENT_OUTCOME).display(),
        MAX_OUTCOME_BYTES / KIB,
    );
    text.push_str(
        "\nContainers in this sandbox. If Podman is installed and the egress proxy is enabled, \
         networked build RUN steps and container commands need the host network and the proxy's \
         public CA bundle. For Alpine or Debian/Ubuntu images use \
         `podman build --network=host -v \
         /etc/egress-proxy/ca-bundle.pem:/etc/ssl/certs/ca-certificates.crt:ro -t local-build .`; \
         use the same network and mount flags with `podman run`. For Fedora/RHEL images change \
         the mount destination to `/etc/pki/tls/certs/ca-bundle.crt`. The image must have the \
         destination available. Podman passes HTTP(S) proxy variables by default; keep \
         `--http-proxy` enabled. Tools that ignore those variables need their own proxy setting. \
         The mount is not baked into the image. Do not disable TLS verification. These are not \
         configured Podman defaults.\n\n",
    );
    text
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::policy::SafeOutputs;

    fn policy(kind: Kind, outputs: serde_json::Value) -> Policy {
        Policy {
            context: Vec::new(),
            repo: "o/r".into(),
            clone_url: "https://example.invalid/o/r".into(),
            base: "main".into(),
            kind,
            max_outputs: 3,
            max_patch_bytes: 1 << 20,
            safe_outputs: serde_json::from_value::<SafeOutputs>(outputs).unwrap(),
        }
    }

    fn text(policy: &Policy) -> String {
        hand_back(
            policy,
            Path::new("/home/agent"),
            Path::new("/home/agent/work/r"),
        )
    }

    #[test]
    fn container_recipe_reaches_branch_and_analysis_agents() {
        for kind in [Kind::Branch, Kind::Analysis] {
            let brief = text(&policy(kind, json!({})));
            for required in [
                "podman build --network=host",
                "/etc/egress-proxy/ca-bundle.pem:/etc/ssl/certs/ca-certificates.crt:ro",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "use the same network and mount flags with `podman run`",
                "keep `--http-proxy` enabled",
                "Do not disable TLS verification",
                "not configured Podman defaults",
            ] {
                assert!(brief.contains(required), "missing {required} for {kind:?}");
            }
        }
    }

    #[test]
    fn the_text_names_both_files_their_formats_and_their_caps() {
        let pull = json!({
            "create_pull_request": {
                "max": 1, "protected_files": [], "protect_top_level_dot_folders": true,
                "protected_files_policy": "blocked", "draft": true, "max_patch_size": 1024,
                "max_patch_files": 100,
            },
            "noop": {"max": 1},
        });
        let branch = text(&policy(Kind::Branch, pull.clone()));
        // (what a branch run with pull requests is told)
        for want in [
            "`/home/agent/work/r`: everything you change",
            "one patch of at most 1024 KiB",
            "Leave your changes uncommitted, and do not push.",
            "`/home/agent/out/safe-outputs.jsonl` (optional)",
            "At most 1024 KiB, 1000 lines and 3 requests in all",
            "This run allows: `create_pull_request` (at most 1), `noop` (at most 1).",
            "{\"type\": \"create_pull_request\", \"title\": \"...\", \"body\": \"...\"}",
            "the message of the commit",
            "`/home/agent/out/outcome.json`: your report",
            "one JSON object of at most 64 KiB",
            "\"stopped_early\": null}`",
        ] {
            assert!(branch.contains(want), "{want}\n{branch}");
        }
        assert!(branch.ends_with(".\n\n"), "{branch:?}");
        assert!(branch.contains("credits a tool or a model"), "{branch}");

        // An analysis run is offered no pull request, whatever the policy
        // file says; a run with no outputs is told to write none.
        let analysis = text(&policy(Kind::Analysis, pull));
        assert!(
            analysis.contains("this run proposes no change"),
            "{analysis}"
        );
        assert!(
            analysis.contains("This run allows: `noop` (at most 1)."),
            "{analysis}"
        );
        assert!(!analysis.contains("create_pull_request"), "{analysis}");
        let nothing = text(&policy(Kind::Branch, json!({})));
        assert!(nothing.contains("this run proposes no change"), "{nothing}");
        assert!(
            nothing.contains("this run may make no requests"),
            "{nothing}"
        );
        assert!(nothing.contains("outcome.json"), "{nothing}");
    }

    #[test]
    fn a_push_run_is_told_where_its_change_goes() {
        let push = crate::policy::tests::push_policy();
        let brief = text(&push);
        for want in [
            "pushed as one commit on top of pull request #42's branch, `agent-run-12`",
            "This run allows: `push_to_pull_request_branch` (at most 1), `noop`",
            "{\"type\": \"push_to_pull_request_branch\", \"message\": \"...\"}",
            "anything under a top-level directory whose name starts with a dot",
        ] {
            assert!(brief.contains(want), "{want}\n{brief}");
        }
        assert!(!brief.contains("create_pull_request"), "{brief}");
        // An analysis run pushes nothing, and is not offered to.
        let analysis = text(&Policy {
            kind: Kind::Analysis,
            ..push
        });
        assert!(
            analysis.contains("this run proposes no change"),
            "{analysis}"
        );
        assert!(
            !analysis.contains(PUSH_TO_PULL_REQUEST_BRANCH),
            "{analysis}"
        );
    }

    #[test]
    fn a_pull_request_run_is_told_what_a_change_may_not_touch() {
        const NAMES: &str =
            "a file of one of these names, in any directory: `DESIGN.md`, `go.mod`; ";
        const DOT_FOLDERS: &str = "a top-level directory whose name starts with a dot";
        struct Case {
            files: &'static [&'static str],
            dot_folders: bool,
            has: &'static [&'static str],
            has_not: &'static [&'static str],
        }
        let rules = |files: &[&str], dot_folders: bool| {
            json!({"create_pull_request": {
                "max": 1, "protected_files": files, "protect_top_level_dot_folders": dot_folders,
                "protected_files_policy": "blocked", "draft": true, "max_patch_size": 1024,
                "max_patch_files": 20,
            }})
        };
        let cases = [
            Case {
                files: &["DESIGN.md", "go.mod"],
                dot_folders: true,
                has: &[NAMES, DOT_FOLDERS],
                has_not: &[],
            },
            Case {
                files: &[],
                dot_folders: true,
                has: &[DOT_FOLDERS],
                has_not: &["of one of these names"],
            },
            Case {
                files: &["DESIGN.md", "go.mod"],
                dot_folders: false,
                has: &[NAMES],
                has_not: &[DOT_FOLDERS],
            },
        ];
        for case in cases {
            let Case {
                files,
                dot_folders,
                has,
                has_not,
            } = case;
            let brief = text(&policy(Kind::Branch, rules(files, dot_folders)));
            let always = [
                "A change is refused whole",
                "name starts with `.git`",
                "`.envrc`",
                "adds an executable, adds, changes or deletes a symbolic link",
                "digits and `_.+@=,-`",
                "`CODEOWNERS`",
                "`.github/agentic-job/merge.toml`",
                "more than 20 files",
                "leave that part out and say so in your",
                "if it is all the task asks for, make it anyway",
            ];
            for want in has.iter().chain(&always) {
                assert!(brief.contains(want), "{want}\n{brief}");
            }
            for unwanted in has_not {
                assert!(!brief.contains(unwanted), "{unwanted}\n{brief}");
            }
        }
        // A run that proposes no change has no such rules to be told.
        let analysis = text(&policy(Kind::Analysis, rules(&["DESIGN.md"], true)));
        assert!(!analysis.contains("refused whole"), "{analysis}");
    }

    #[test]
    fn brief_names_only_effective_folder_exemptions() {
        for folders in [Vec::<String>::new(), vec![".github".into()]] {
            let mut policy = crate::policy::tests::policy();
            policy
                .safe_outputs
                .create_pull_request
                .as_mut()
                .unwrap()
                .unprotected_dot_folders = folders.clone();
            let brief = text(&policy);
            assert_eq!(
                brief.contains("except `.github/`, which the caller exempts"),
                !folders.is_empty()
            );
            // Who merges an exempted change is the repository's merge policy
            // to say, not the brief's (#558).
            assert!(
                !brief.contains("merged only after a human reviews"),
                "{brief}"
            );
        }
    }
}
