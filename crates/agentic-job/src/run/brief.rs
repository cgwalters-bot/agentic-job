//! The text `run` puts before the task: where the agent leaves what it
//! hands back, in what format, and how much. In the old tree only the
//! caller's own brief said this, so every caller had to copy it. What
//! the files are is this binary's to know, since this binary reads them;
//! how to work, and what to work on, stays the caller's task.

use std::fmt::Write;
use std::path::Path;

use super::handback::{
    AGENT_OUTCOME, AGENT_OUTPUTS, MAX_LINES, MAX_OUTCOME_BYTES, MAX_OUTPUTS_BYTES,
    OUTCOME_CHECKPOINT,
};
use crate::check::checkpoint::{FENCE, REASONS};
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
    if !rules.protected_paths.is_empty() {
        let globs: Vec<String> = rules
            .protected_paths
            .iter()
            .map(|glob| format!("`{glob}`"))
            .collect();
        let _ = write!(
            text,
            "a path matching one of these globs (`*` within one directory, `**` across \
             directories): {}; ",
            globs.join(", ")
        );
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

/// What the agent is told of the MCP server SERVER the run gives it: its
/// name and the tools it may call, so that it neither looks for others
/// nor takes the refusal of one for a fault.
pub fn mcp(server: &crate::run::mcp::Server) -> String {
    let tools: Vec<&str> = server.allowed.iter().map(String::as_str).collect();
    format!(
        "This run gives you the MCP server `{}`, through a proxy that holds its credential; \
         you may call only its tools {}.\n\n",
        server.name,
        tools.join(", ")
    )
}

/// Whether the agent of a run of POLICY keeps a checkpoint in its outcome
/// from the start: where its change is proposed and the bounds open
/// complete work ready for review (`ready_when_complete`), so that a
/// draft means "not finished". It is off where that is.
pub fn asks_for_checkpoint(policy: &Policy) -> bool {
    policy.kind == Kind::Branch
        && policy.safe_outputs.patch_carrier().is_some()
        && policy.safe_outputs.ready_when_complete()
}

/// What a run of POLICY is told before its task, as [`guide`] is: where
/// it hands back, its limits, and the validator that names what `check`
/// would refuse while the session can still fix it. The rest of the
/// guide is reference that most runs never need, and was most of the
/// first prompt of every run (#854): `handback guide` prints it, and
/// `handback check` points at the part a problem needs.
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
        "How this run hands back its results. All of it is published; nothing else leaves \
         this machine.\n\n",
    );
    let _ = match (&carrier, push) {
        (Some((_, rules)), _) => writeln!(
            text,
            "- Change: what you change, add or delete in `{}` (ignored files excepted), left \
             uncommitted and unpushed, is {} as one patch against the commit you started \
             from, of at most {} KiB and {} files. A protected path or a refused kind of file \
             gets the whole change refused: leave that part out and say so, unless it is all \
             the task asks for.",
            checkout.display(),
            match push {
                Some(push) => format!("pushed to pull request #{}'s branch", push.target),
                None => "proposed as a pull request".to_owned(),
            },
            policy.max_patch_bytes / (KIB as u64),
            rules.max_patch_files,
        ),
        _ => writeln!(
            text,
            "- Change: none; nothing you change in `{}` is handed back.",
            checkout.display()
        ),
    };
    // #119: brief line comes with restore. Until a run is given its memory
    // back, telling the agent of `~/memory` would promise what is not so.
    let types: Vec<String> = outputs
        .types()
        .filter(|&name| {
            carrier.is_some_and(|(kind, _)| kind == name)
                || ![CREATE_PULL_REQUEST, PUSH_TO_PULL_REQUEST_BRANCH].contains(&name)
        })
        .map(|name| match outputs.max_of(name) {
            Some(max) => format!("`{name}` ({max})"),
            None => format!("`{name}`"),
        })
        .collect();
    let requests = home.join(AGENT_OUTPUTS);
    if types.is_empty() {
        let _ = writeln!(
            text,
            "- Requests: none; leave `{}` unwritten.",
            requests.display()
        );
    } else {
        let wording = match (&carrier, push) {
            (_, Some(_)) => {
                " A `push_to_pull_request_branch` line's `message` is the commit's; credit no tool or model in it."
            }
            (Some(_), None) => {
                " A `create_pull_request` line's `title` and `body` are the pull request's and \
                 its commit's; credit no tool or model in them."
            }
            _ => "",
        };
        let _ = writeln!(
            text,
            "- Requests (optional): `{}`, one gh-aw safe output a line, at most {} in all: {}.{}",
            requests.display(),
            policy.max_outputs,
            types.join(", "),
            wording,
        );
    }
    let _ = write!(
        text,
        "- Report: `{}`, `{{\"summary\": \"...\", \"tests\": [{{\"command\": \"...\", \
         \"exit_code\": 0, \"duration_s\": 12}}], \"stopped_early\": null}}`: what you did and \
         why, the checks you ran with their real exit codes, and null or why you stopped early.",
        home.join(AGENT_OUTCOME).display(),
    );
    // As in the guide: an early checkpoint, kept current, is what brought
    // back the hand-back of an agent whose context was compacted (#813).
    if asks_for_checkpoint(policy) {
        let _ = write!(
            text,
            " Write it as soon as you have read the task, with `\"{OUTCOME_CHECKPOINT}\": \
             {{\"complete\": false, \"done\": \"...\", \"left\": \"...\", \"next\": \
             \"...\"}}`; keep both current, and set `complete` to true last: until then the \
             change is a draft to be continued."
        );
    }
    text.push_str(
        "\n- Never write a private key, a fake one in a test included: build it at run time from \
         parts. Other credential-shaped strings are reported as warnings.\n\n\
         Before you end your turn, run `agentic-job handback check` and fix what it reports \
         until it exits 0. It makes the checks the run makes after your session, on your \
         change, requests, report and checkpoint, and says how to fix each problem; run it as \
         often as you like. `agentic-job handback guide` prints these rules in full: formats, \
         protected paths, checkpoints, replacing a branch's commits, containers.\n\n",
    );
    text
}

/// The whole of what a run of POLICY whose agent has the home HOME and
/// works in CHECKOUT, from the commit BASE, is told of its hand-back,
/// which `handback guide` prints. It ends with an empty line.
pub fn guide(policy: &Policy, home: &Path, checkout: &Path, base: &str) -> String {
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
                "  Alternatively, run `agentic-job handback replace --base {}` in your checkout (optional final argument: a revision range, default BASE..HEAD). Do not construct replacement mails or JSON by hand. The command builds `out/replacement.json` under your home, preserves format-patch bytes and validates the series with git am in a scratch repository before writing it. This replaces the entire branch with at most {} nonempty commits, including all original commits you want to keep. You may fetch and use the current head of the PR's base branch instead; trusted apply refuses any other base. Every commit passes the same path rules, and the whole JSON fits the patch byte limit. Include a `push_to_pull_request_branch` request; do not also propose a working-tree patch. A moved branch is refused with an exact lease. Commit messages and existing trailers are preserved; no trailers are added.",
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
             below. A run for issue N gets `Closes #N` added to the body; if your change \
             does only part of the issue, start a line of the body with `Part of #N` \
             instead, and merging leaves the issue open.\n",
        );
    }
    let checkpoint = asks_for_checkpoint(policy);
    if checkpoint {
        let (what, field) = if push.is_some() {
            ("pull request is marked", "message")
        } else {
            ("pull request opens", "body")
        };
        let _ = writeln!(
            text,
            "  Complete work: the {what} ready for review. If your work is not complete, \
             because you are near a limit or know it is unfinished, end the {field} with a \
             checkpoint, and it is a draft to be continued instead: a line `{FENCE}`, one JSON \
             object `{{\"reason\": \"...\", \"done\": \"...\", \"left\": \"...\", \
             \"next\": \"...\"}}` (`reason` one of {}; the others what is done, what is left \
             and how to continue), and a line of three backticks. A malformed checkpoint, or \
             two, gets all of your requests refused.",
            REASONS.join(", ")
        );
    }
    let _ = writeln!(
        text,
        "- `{}`: your report, {}, as one JSON object of at most {} KiB: \
         `{{\"summary\": \"...\", \"tests\": [{{\"command\": \"...\", \"exit_code\": 0, \
         \"duration_s\": 12}}], \"stopped_early\": null}}`. `summary` says what you did and \
         why; `tests` lists the commands you ran to check it, with their real exit codes; \
         `stopped_early` is null, or why you stopped before the task was done.",
        home.join(AGENT_OUTCOME).display(),
        if checkpoint {
            "written early and kept current"
        } else {
            "written last"
        },
        MAX_OUTCOME_BYTES / KIB,
    );
    // Agents whose context was compacted have lost their hand-back, and
    // ended well with nothing; an early checkpoint, kept current and
    // restated after a compaction, brought one back (#813). That it is
    // there is not that the work is done: it stays open until the agent
    // closes it.
    if checkpoint {
        let _ = writeln!(
            text,
            "  Write it as soon as you have read the task, not only at the end: a `summary` of \
             what you are doing, and `\"{OUTCOME_CHECKPOINT}\": {{\"complete\": false, \
             \"done\": \"...\", \"left\": \"...\", \"next\": \"...\"}}`: what is done, \
             what is left and how to continue. Update both as you work. Finishing means setting \
             `complete` to true, last; until then your change is handed back as a draft to be \
             continued, never as done, whatever else you write."
        );
    }
    // Runs lost all their work to a fake key in a test fixture, found by
    // the final gate only after their sessions had ended (#720); now only
    // a private key is refused, and other shapes are warnings (#918).
    let _ = writeln!(
        text,
        "- Secret-shaped strings: a private key (`-----BEGIN ... PRIVATE KEY-----`) anywhere \
         in the change or in these files gets everything this run hands back refused after \
         your session ends, a fake one in a test included: build one at run time from parts \
         that do not match by themselves. Any other string shaped like a credential (a \
         `ghp_`, `sk-` or `AKIA` token, a JWT) is kept and reported by file and line as a \
         warning; make sure each is a fixture. Run `agentic-job handback scan --base {base}` \
         in your checkout: it lists the file, line and pattern of each such string in your \
         change and in `{}`, and exits 1 while there is a private key; `agentic-job handback \
         check` runs it with the other checks.",
        home.join("out").display(),
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
            commit_author: None,
            push_repo: None,
            private: false,
            allowed_domains: Vec::new(),
            allow_http: Vec::new(),
            memory: None,
            forge: Default::default(),
            contract: crate::policy::CONTRACT,
        }
    }

    fn text(policy: &Policy) -> String {
        guide(
            policy,
            Path::new("/home/agent"),
            Path::new("/home/agent/work/r"),
            "0123abcd",
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
            "start a line of the body with `Part of #N`",
            "`/home/agent/out/outcome.json`: your report",
            "one JSON object of at most 64 KiB",
            "\"stopped_early\": null}`",
            "a private key (`-----BEGIN ... PRIVATE KEY-----`)",
            "is kept and reported by file and line as a warning",
            "`agentic-job handback scan --base 0123abcd`",
            "in `/home/agent/out`",
        ] {
            assert!(branch.contains(want), "{want}\n{branch}");
        }
        assert!(branch.ends_with(".\n\n"), "{branch:?}");
        assert!(branch.contains("credits a tool or a model"), "{branch}");
        // Only a policy that opens complete work ready asks for checkpoints.
        assert!(!branch.contains("checkpoint"), "{branch}");
        let mut ready = pull.clone();
        ready["create_pull_request"]["ready_when_complete"] = json!(true);
        let ready = text(&policy(Kind::Branch, ready));
        for want in [
            "Complete work: the pull request opens ready for review.",
            "end the body with a checkpoint",
            "a line ````checkpoint`",
            "one of budget, runtime, cap, incomplete",
            // The early checkpoint in the outcome (#822).
            "`/home/agent/out/outcome.json`: your report, written early and kept current",
            "Write it as soon as you have read the task",
            "`\"checkpoint\": {\"complete\": false, \"done\": \"...\", \"left\": \"...\", \
             \"next\": \"...\"}`",
            "Finishing means setting `complete` to true, last",
            "never as done",
        ] {
            assert!(ready.contains(want), "{want}\n{ready}");
        }
        assert!(branch.contains("your report, written last"), "{branch}");

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
        // The bounds' globs, only where there are some.
        const GLOBS: &str = "a path matching one of these globs";
        assert!(!text(&policy(Kind::Branch, rules(&[], true))).contains(GLOBS));
        let mut with_globs = rules(&[], true);
        with_globs["create_pull_request"]["protected_paths"] = json!(["raw/**"]);
        let brief = text(&policy(Kind::Branch, with_globs));
        assert!(brief.contains(&format!("{GLOBS} ")), "{brief}");
        assert!(brief.contains("`raw/**`;"), "{brief}");
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

#[cfg(test)]
mod brief_tests {
    use serde_json::json;

    #[test]
    fn the_brief_names_the_mcp_server_and_its_tools() {
        let server = crate::run::mcp::Server {
            name: "tracker".into(),
            url: "https://mcp.example".into(),
            allowed: ["search".to_owned(), "get_issue".to_owned()].into(),
        };
        let text = super::mcp(&server);
        assert!(text.contains("MCP server `tracker`"), "{text}");
        assert!(text.contains("only its tools get_issue, search."), "{text}");
        assert!(!text.contains("mcp.example"), "{text}");
    }

    use super::*;
    use crate::policy::{DEFAULT_PROTECTED_FILES, SafeOutputs};

    /// The most bytes of the brief of an implement run of the dispatch
    /// caller. It was the guide, 5,863 bytes, before it was cut to 1,840 (#854): what
    /// is added to it, every run reads.
    const MAX_BRIEF_BYTES: usize = 2_000;

    /// An implement run of the dispatch caller, whose bounds open
    /// complete work ready.
    fn implement() -> Policy {
        let outputs = json!({
            "create_pull_request": {
                "max": 1, "protected_files": DEFAULT_PROTECTED_FILES,
                "protect_top_level_dot_folders": true, "unprotected_dot_folders": [".github"],
                "protected_files_policy": "blocked", "draft": true, "ready_when_complete": true,
                "max_patch_size": 1024, "max_patch_files": 50,
            },
            "noop": {"max": 1}, "missing_tool": {"max": 1}, "missing_data": {"max": 1},
        });
        Policy {
            context: Vec::new(),
            repo: "o/r".into(),
            clone_url: "https://example.invalid/o/r".into(),
            base: "main".into(),
            kind: Kind::Branch,
            max_outputs: 3,
            max_patch_bytes: 1 << 20,
            safe_outputs: serde_json::from_value::<SafeOutputs>(outputs).unwrap(),
            commit_author: None,
            push_repo: None,
            private: false,
            allowed_domains: Vec::new(),
            allow_http: Vec::new(),
            memory: None,
            forge: Default::default(),
            contract: crate::policy::CONTRACT,
        }
    }

    fn brief(policy: &Policy) -> String {
        hand_back(
            policy,
            Path::new("/home/agent"),
            Path::new("/home/agent/work/r"),
        )
    }

    /// The brief says where the run hands back, its limits and the
    /// validator, and leaves the rest to the guide; and it stays small.
    #[test]
    fn the_brief_is_the_essentials_and_stays_small() {
        let policy = implement();
        let text = brief(&policy);
        for want in [
            "`/home/agent/work/r`",
            "left uncommitted and unpushed",
            "proposed as a pull request",
            "at most 1024 KiB and 50 files",
            "leave that part out and say so, unless it is all the task asks for",
            "`/home/agent/out/safe-outputs.jsonl`",
            "at most 3 in all: `create_pull_request` (1), `missing_data` (1), \
             `missing_tool` (1), `noop` (1).",
            "`title` and `body`",
            "credit no tool or model",
            "`/home/agent/out/outcome.json`",
            "\"exit_code\": 0",
            "\"checkpoint\": {\"complete\": false",
            "set `complete` to true last",
            "Never write a private key, a fake one in a test included",
            "run `agentic-job handback check` and fix what it reports until it exits 0",
            "`agentic-job handback guide` prints these rules in full",
        ] {
            assert!(text.contains(want), "{want}\n{text}");
        }
        assert!(text.ends_with(".\n\n"), "{text:?}");
        let full = guide(
            &policy,
            Path::new("/home/agent"),
            Path::new("/home/agent/work/r"),
            "0",
        );
        assert!(
            text.len() <= MAX_BRIEF_BYTES && text.len() * 10 <= full.len() * 6,
            "the brief is {} bytes, the guide {}: keep reference in the guide\n{text}",
            text.len(),
            full.len()
        );

        let without = Policy {
            safe_outputs: SafeOutputs {
                create_pull_request: policy.safe_outputs.create_pull_request.clone().map(|pr| {
                    crate::policy::PullRequest {
                        ready_when_complete: false,
                        ..pr
                    }
                }),
                ..policy.safe_outputs.clone()
            },
            ..policy.clone()
        };
        assert!(!brief(&without).contains("\"checkpoint\":"));

        let push = brief(&crate::policy::tests::push_policy());
        assert!(
            push.contains("pushed to pull request #42's branch"),
            "{push}"
        );
        assert!(
            push.contains("`push_to_pull_request_branch` line's `message`"),
            "{push}"
        );
        assert!(!push.contains("create_pull_request"), "{push}");

        let analysis = brief(&Policy {
            kind: Kind::Analysis,
            ..policy
        });
        assert!(analysis.contains("- Change: none;"), "{analysis}");
        assert!(!analysis.contains("create_pull_request"), "{analysis}");
        let nothing = brief(&Policy {
            safe_outputs: SafeOutputs::default(),
            ..implement()
        });
        assert!(nothing.contains("- Requests: none;"), "{nothing}");
    }

    /// Measures for the pull request: run with `--ignored --nocapture`.
    #[test]
    #[ignore = "prints the sizes of the brief and the guide"]
    fn sizes() {
        let policy = implement();
        let full = guide(
            &policy,
            Path::new("/home/agent"),
            Path::new("/home/agent/work/r"),
            "0",
        );
        println!("brief {} guide {}", brief(&policy).len(), full.len());
    }
}
