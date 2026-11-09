//! The run action's `failure-class` output and the status comment's
//! word for it are checked against a fixed list in `bash`, where the
//! binary's `FAILURE_KINDS` cannot be imported: the lists must be one.
//! The files are outside the crate, so they are read here, not included.

use agentic_job::run::summary::{CONTROL_UNREACHABLE, FAILURE_KINDS};
use agentic_job::session::provider::Class;

fn read(file: &str) -> String {
    let path = format!("{}/../../{file}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The alternatives of each regular expression that guards the kind in
/// FILE, expanded: `(timeout|...|inference_(rate_limited|...)|...)`.
fn guarded_kinds(file: &str) -> Vec<Vec<String>> {
    let text = read(file);
    let guards: Vec<_> = text
        .lines()
        .filter(|line| line.contains("=~ ^(timeout|"))
        .map(|guard| {
            let start = guard.find("^(").expect("the guard's start") + 2;
            let end = guard[start..].find(")$").expect("the guard's end") + start;
            let (plain, rest) = guard[start..end]
                .split_once("|inference_(")
                .unwrap_or_else(|| panic!("{file}: {guard}"));
            let (inference, after) = rest.split_once(')').unwrap_or((rest, ""));
            plain
                .split('|')
                .map(str::to_owned)
                .chain(inference.split('|').map(|k| format!("inference_{k}")))
                .chain(
                    after
                        .split('|')
                        .filter(|k| !k.is_empty())
                        .map(str::to_owned),
                )
                .collect()
        })
        .collect();
    assert!(
        !guards.is_empty(),
        "{file} has no guard on the failure kind"
    );
    guards
}

#[test]
fn the_action_and_the_status_comment_take_the_summarys_kinds() {
    // The action guards the summary's word where it becomes an output
    // and where the result step reads it back: the summary's kinds and
    // no other, its own `control_unreachable` included, which no summary
    // has. Conclude, which sees both, takes both.
    let found = guarded_kinds("run/action.yml");
    assert_eq!(found.len(), 2, "run/action.yml: {found:?}");
    for kinds in found {
        assert_eq!(kinds, FAILURE_KINDS, "run/action.yml");
    }
    let all: Vec<&str> = FAILURE_KINDS
        .iter()
        .copied()
        .chain([CONTROL_UNREACHABLE])
        .collect();
    let found = guarded_kinds(".github/workflows/apply.yml");
    assert_eq!(found.len(), 1, ".github/workflows/apply.yml: {found:?}");
    assert_eq!(found[0], all, ".github/workflows/apply.yml");
    // The host step writes the action's own word, and only on exit 4
    // (tests/workflows.rs runs the step).
    assert!(
        read("run/action.yml").contains(&format!("\"failure-class={CONTROL_UNREACHABLE}\"")),
        "run/action.yml's host step does not set `{CONTROL_UNREACHABLE}`"
    );
    for class in Class::ALL {
        if let Some(kind) = class.kind() {
            assert!(FAILURE_KINDS.contains(&kind), "{kind}");
        }
    }
    // The documented list, in the same words.
    for file in ["docs/workflow.md", "docs/stable-interfaces.md"] {
        let documented = read(file);
        for kind in &all {
            assert!(
                documented.contains(&format!("`{kind}`")),
                "{file} does not name `{kind}`"
            );
        }
    }
}
