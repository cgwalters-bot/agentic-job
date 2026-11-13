use std::path::{Path, PathBuf};

use super::*;
use crate::vocabulary::{ITEM_NUMBER, OUTPUT_TYPES};

fn checkout() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Links as `policy` has them kept: to any host under a top-level domain,
/// which is what the fixtures were generated with.
fn keeps_public(host: &str) -> bool {
    crate::link_domains()
        .iter()
        .any(|tld| host == tld || host.ends_with(&format!(".{tld}")))
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

#[test]
fn document_collection_is_opt_in_and_bounded() {
    let item = json!({"type": "document", "title": "Findings", "files": {"findings.md": "Evidence."}, "summary": ["First.", "Second.", "Third."]});
    let config = object(json!({"document": {"max": 1}}));
    let collected = collect(&item.to_string(), &config, Forge::Github, &keeps_public);
    assert!(collected.errors.is_empty(), "{:?}", collected.errors);
    assert_eq!(collected.items.len(), 1);
    for (lines, config, forge) in [
        (item.to_string(), Map::new(), Forge::Github),
        (format!("{item}\n{item}"), config.clone(), Forge::Github),
        (item.to_string(), config.clone(), Forge::Forgejo),
    ] {
        assert!(
            !collect(&lines, &config, forge, &keeps_public)
                .errors
                .is_empty()
        );
    }
}

/// The types and fields are gh-aw's, read at test time from the
/// generated `validation.json`, regenerated from gh-aw's pinned source:
/// a regeneration that changes them fails here. Fields are in the order
/// gh-aw validates them in, which decides the refusal reported.
#[test]
fn types_are_gh_aws() {
    let text = std::fs::read_to_string(checkout().join("safe-outputs/validation.json")).unwrap();
    let validation = object(serde_json::from_str(&text).unwrap());
    for of in TYPES {
        let want = &validation[of.name];
        let names: Vec<&str> = of.fields.iter().map(|field| field.name).collect();
        let order: Vec<&str> = want["fields"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(names, order, "{}", of.name);
        let fields: Map<String, Value> = of
            .fields
            .iter()
            .map(|field| (field.name.to_owned(), Value::Object(field.to_json())))
            .collect();
        let mut got = json!({"defaultMax": of.default_max, "fields": fields});
        if let Some(custom) = &of.custom {
            got["customValidation"] = custom.to_json().into();
        }
        if of.collapse_data {
            got["collapseData"] = true.into();
        }
        assert_eq!(&got, want, "{}", of.name);
    }
    let ours: Vec<&str> = TYPES.iter().map(|of| of.name).collect();
    let theirs: Vec<&str> = validation.keys().map(String::as_str).collect();
    assert_eq!(ours, theirs, "every type of validation.json, in its order");
    // And so every type a policy may allow.
    for name in OUTPUT_TYPES {
        assert!(
            ours.contains(name) || *name == crate::document::TYPE,
            "{name}"
        );
    }
}

/// gh-aw's collector, on each case's `outputs.jsonl` and `config.json`,
/// wrote its `collected.json` (`just collect-fixtures`); this collector
/// must write the same. gh-aw adds an incomplete report to a result with
/// no requests but diagnostics, which `check` drops and this leaves out.
#[test]
fn matches_gh_aws_collector() {
    // Read where agentic-job's tests keep them, rather than copied here.
    let dir = checkout().join("crates/agentic-job/tests/data/collect");
    let mut cases: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    cases.sort();
    assert!(cases.len() >= 3, "no cases in {}", dir.display());
    for case in cases {
        let read = |name: &str| std::fs::read_to_string(case.join(name)).unwrap();
        let config = object(serde_json::from_str(&read("config.json")).unwrap());
        let mut want = object(serde_json::from_str(&read("collected.json")).unwrap());
        let mut items: Vec<Map<String, Value>> =
            serde_json::from_value(want.remove("items").unwrap()).unwrap();
        if items
            .last()
            .is_some_and(|last| last["type"] == "report_incomplete")
        {
            items.pop();
        }
        let errors: Vec<String> = serde_json::from_value(want.remove("errors").unwrap()).unwrap();
        let got = collect(
            &read("outputs.jsonl"),
            &config,
            Forge::Github,
            &keeps_public,
        );
        let name = case.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(got.errors, errors, "{name}: errors");
        assert_eq!(got.items.len(), items.len(), "{name}: how many items");
        for (number, (got, want)) in got.items.iter().zip(&items).enumerate() {
            assert_eq!(got, want, "{name}: item {}", number + 1);
        }
    }
}

/// Where this collector refuses what gh-aw's takes or words a refusal
/// its own way; none of these is in the fixtures.
#[test]
fn refusals_of_its_own() {
    let config = object(json!({"add_comment": {"max": 1}, "dispatch_workflow": {"max": 1}}));
    let known: Vec<&str> = TYPES.iter().map(|of| of.name).collect();
    let unsupported = format!(
        "Line 1: Unsupported output type 'dispatch_workflow': agentic-job collect validates only {}",
        known.join(", ")
    );
    let cases = [
        (r#"{"type":"dispatch_workflow"}"#, unsupported.as_str()),
        (
            r#"{"type":"add_comment","body":"x",}"#,
            "Line 1: Invalid JSON - trailing comma at line 1 column 34",
        ),
        ("[1]", "Line 1: Missing required 'type' field"),
        ("null", "Line 1: Missing required 'type' field"),
        (r#"{"type":null}"#, "Line 1: Missing required 'type' field"),
        (r#"{"type":0}"#, "Line 1: Missing required 'type' field"),
        (
            r#"{"type":7}"#,
            "Line 1: Invalid JSON - 'type' is not a string",
        ),
    ];
    for (line, want) in cases {
        let got = collect(line, &config, Forge::Github, &keeps_public);
        assert_eq!(got.items, Vec::<Map<String, Value>>::new(), "{line}");
        assert_eq!(got.errors, [want], "{line}");
    }
}

/// On GitLab a label request keeps a target of its kind, and a kind-named
/// target its type does not take there is refused, not dropped; GitHub's
/// and Forgejo's collector stays gh-aw's, which drops it.
#[test]
fn kind_named_targets_by_forge() {
    let config = object(json!({
        "add_labels": {"max": 5}, "remove_labels": {"max": 5},
        "add_comment": {"max": 1}, "close_issue": {"max": 1},
    }));
    let labels = r#"{"type":"add_labels","labels":["bug"],"issue_number":5}"#;
    let merge_request = r#"{"type":"remove_labels","labels":["bug"],"pull_request_number":"5"}"#;
    let comment = r#"{"type":"add_comment","body":"x","issue_number":5}"#;
    let close = r#"{"type":"close_issue","body":"x","issue_number":5,"pull_request_number":5}"#;
    // The line, the forge, the item it keeps, or the refusal.
    let cases: &[(&str, Forge, Result<Value, &str>)] = &[
        (
            labels,
            Forge::Gitlab,
            Ok(json!({"type": "add_labels", "labels": ["bug"], "issue_number": 5})),
        ),
        (
            merge_request,
            Forge::Gitlab,
            Ok(json!({"type": "remove_labels", "labels": ["bug"], "pull_request_number": 5})),
        ),
        (
            labels,
            Forge::Github,
            Ok(json!({"type": "add_labels", "labels": ["bug"]})),
        ),
        (
            labels,
            Forge::Forgejo,
            Ok(json!({"type": "add_labels", "labels": ["bug"]})),
        ),
        (
            comment,
            Forge::Github,
            Ok(json!({"type": "add_comment", "body": "x"})),
        ),
        (
            r#"{"type":"add_labels","labels":["bug"],"issue_number":0}"#,
            Forge::Gitlab,
            Err("Line 1: add_labels 'issue_number' must be a valid positive integer"),
        ),
        (
            comment,
            Forge::Gitlab,
            Err(
                "Line 1: add_comment 'issue_number' is not a field of add_comment on GitLab, and would be dropped",
            ),
        ),
        (
            close,
            Forge::Gitlab,
            Err(
                "Line 1: close_issue 'pull_request_number' is not a field of close_issue on GitLab, and would be dropped",
            ),
        ),
    ];
    for (line, forge, want) in cases {
        let got = collect(line, &config, *forge, &keeps_public);
        match want {
            Ok(item) => {
                assert_eq!(got.errors, Vec::<String>::new(), "{line} {forge:?}");
                assert_eq!(got.items, [object(item.clone())], "{line} {forge:?}");
            }
            Err(error) => {
                assert!(got.items.is_empty(), "{line} {forge:?}");
                assert_eq!(got.errors.len(), 1, "{line} {forge:?}");
                assert!(
                    got.errors[0].starts_with(error),
                    "{forge:?}: {:?}",
                    got.errors
                );
            }
        }
    }
    // The guide names what GitLab takes, and not what check refuses there.
    let guide = field_guide("add_labels", Forge::Gitlab).unwrap();
    assert!(guide.contains("`issue_number`") && guide.contains("`pull_request_number`"));
    assert!(!guide.contains("item_number"), "{guide}");
    let guide = field_guide("add_labels", Forge::Github).unwrap();
    assert!(guide.contains("item_number") && !guide.contains("issue_number"));
}

#[test]
fn parse_int_as_javascript() {
    let cases = [
        ("42", Some(42.0)),
        ("  12abc", Some(12.0)),
        ("+5", Some(5.0)),
        ("-3", Some(-3.0)),
        ("5.9", Some(5.0)),
        ("abc", None),
        ("", None),
        ("0x10", Some(0.0)),
    ];
    for (text, want) in cases {
        assert_eq!(js_parse_int(text), want, "{text:?}");
    }
}

/// The bounded entry point, as a caller with no agent run or CI system
/// uses it: a file past the cap or not UTF-8 is refused whole, and each
/// malformed line is refused on its own, the others still collected.
#[test]
fn bounded_input() {
    let config = object(json!({"noop": {"max": 5}}));
    let max = usize::try_from(MAX_OUTPUTS_BYTES).unwrap();
    let noop = r#"{"type":"noop","message":"done"}"#;
    let at_cap = format!("{noop}\n{}", "\n".repeat(max - noop.len() - 1));
    let over_cap = format!("{at_cap}\n");
    // The bytes, and what they are refused with whole.
    let whole: &[(&[u8], Option<&str>)] = &[
        (b"", None),
        (at_cap.as_bytes(), None),
        (
            over_cap.as_bytes(),
            Some("outputs.jsonl is over 1048576 bytes"),
        ),
        (
            b"{\"type\":\"noop\",\"message\":\"\xff\"}",
            Some("outputs.jsonl is not UTF-8"),
        ),
    ];
    for (bytes, want) in whole {
        let got = collect_bytes(bytes, &config, Forge::Github, &keeps_public);
        match want {
            None => assert!(got.unwrap().errors.is_empty(), "{} bytes", bytes.len()),
            Some(want) => assert_eq!(got.unwrap_err().to_string(), *want),
        }
    }
    let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
    // The line after a `noop` that is taken, and how its refusal starts.
    let lines = [
        ("{", "Line 2: Invalid JSON - "),
        (
            r#"{"type":"noop","message":"\ud800"}"#,
            "Line 2: Invalid JSON - ",
        ),
        (
            r#"{"type":"noop","message":"x","n":1e400}"#,
            "Line 2: Invalid JSON - ",
        ),
        (
            deep.as_str(),
            "Line 2: Invalid JSON - recursion limit exceeded",
        ),
        (r#""noop""#, "Line 2: Missing required 'type' field"),
        (
            r#"{"message":"x"}"#,
            "Line 2: Missing required 'type' field",
        ),
        (
            r#"{"type":"noop"}"#,
            "Line 2: noop requires a 'message' field",
        ),
        (
            r#"{"type":"noop","message":7}"#,
            "Line 2: noop requires a 'message' field",
        ),
    ];
    for (line, want) in lines {
        let text = format!("{noop}\n{line}\n");
        let got = collect_bytes(text.as_bytes(), &config, Forge::Github, &keeps_public).unwrap();
        assert_eq!(got.items.len(), 1, "{line}");
        assert_eq!(got.errors.len(), 1, "{line}");
        assert!(got.errors[0].starts_with(want), "{line}: {:?}", got.errors);
    }
}

/// Every forge profile a policy admits: the guide names a type's fields
/// for each type the profile holds, never one the forge refuses, and an
/// inline comment off GitHub keeps only the fields that mean the same
/// there, where GitHub's collector stays gh-aw's.
#[test]
fn every_forge_profile() {
    let config = object(json!({CREATE_REVIEW_COMMENT: {"max": 1}}));
    let single = json!({"type": CREATE_REVIEW_COMMENT, "body": "x", "line": 3, "path": "a.rs"});
    let mut range = single.clone();
    range["start_line"] = json!(2);
    let refused = "Line 1: create_pull_request_review_comment: neutral inline comment field \
        start_line is not representable (multiline ranges are not supported)";
    for forge in [Forge::Github, Forge::Forgejo, Forge::Gitlab] {
        let held: Vec<&str> = OUTPUT_TYPES
            .iter()
            .copied()
            .filter(|name| forge.holds(name))
            .collect();
        assert!(held.contains(&CREATE_REVIEW_COMMENT), "{forge:?}");
        for name in held {
            let guide = field_guide(name, forge).unwrap();
            let named = guide.contains(&format!("`{ITEM_NUMBER}`"));
            assert!(
                !(named && forge.refuses_field(ITEM_NUMBER)),
                "{forge:?} {name}: {guide}"
            );
        }
        let got = collect(&single.to_string(), &config, forge, &keeps_public);
        assert_eq!(got.items, [object(single.clone())], "{forge:?}");
        let got = collect(&range.to_string(), &config, forge, &keeps_public);
        if forge == Forge::Github {
            assert_eq!(got.items, [object(range.clone())], "{forge:?}");
        } else {
            assert!(got.items.is_empty(), "{forge:?}");
            assert_eq!(got.errors, [refused], "{forge:?}");
        }
    }
}
