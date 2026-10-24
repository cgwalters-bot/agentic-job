//! The run action's `failure-class` output and the status comment's
//! word for it are checked against a fixed list in `bash`, where the
//! binary's `FAILURE_KINDS` cannot be imported: the lists must be one.
//! The files are outside the crate, so they are read here, not included.

use agentic_job::run::summary::FAILURE_KINDS;
use agentic_job::session::provider::Class;

/// The alternatives of the regular expression that guards the kind in
/// FILE, expanded: `(timeout|...|inference_(rate_limited|...))`.
fn guarded_kinds(file: &str) -> Vec<String> {
    let path = format!("{}/../../{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let guard = text
        .lines()
        .find(|line| line.contains("=~ ^(timeout|"))
        .unwrap_or_else(|| panic!("{file} has no guard on the failure kind"));
    let start = guard.find("^(").expect("the guard's start") + 2;
    let end = guard[start..].find(")$").expect("the guard's end") + start;
    let (plain, inference) = guard[start..end]
        .split_once("|inference_(")
        .unwrap_or_else(|| panic!("{file}: {guard}"));
    let inference = inference.strip_suffix(')').unwrap_or(inference);
    plain
        .split('|')
        .map(str::to_owned)
        .chain(inference.split('|').map(|k| format!("inference_{k}")))
        .collect()
}

#[test]
fn the_action_and_the_status_comment_take_the_summarys_kinds() {
    for file in ["run/action.yml", ".github/workflows/apply.yml"] {
        assert_eq!(guarded_kinds(file), FAILURE_KINDS, "{file}");
    }
    for class in Class::ALL {
        if let Some(kind) = class.kind() {
            assert!(FAILURE_KINDS.contains(&kind), "{kind}");
        }
    }
    // The documented list, in the same words.
    let documented = std::fs::read_to_string(format!(
        "{}/../../docs/workflow.md",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    for kind in FAILURE_KINDS {
        assert!(
            documented.contains(&format!("`{kind}`")),
            "docs/workflow.md does not name `{kind}`"
        );
    }
}
