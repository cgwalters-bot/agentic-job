use std::path::{Path, PathBuf};

use super::*;

fn checkout() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Links as `policy` has them kept: to any host under a top-level domain,
/// which is what the fixtures were generated with.
fn keeps_public(host: &str) -> bool {
    crate::policy::link_domains()
        .iter()
        .any(|tld| host == tld || host.ends_with(&format!(".{tld}")))
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

/// The types and fields are gh-aw's, read at test time from the
/// generated `validation.json` the GitHub path gives gh-aw's collector:
/// a regeneration that changes them fails here.
#[test]
fn types_are_gh_aws() {
    let text = std::fs::read_to_string(checkout().join("safe-outputs/validation.json")).unwrap();
    let validation = object(serde_json::from_str(&text).unwrap());
    for of in TYPES {
        let fields: Map<String, Value> = of
            .fields
            .iter()
            .map(|field| (field.name.to_owned(), field.rule.to_json()))
            .collect();
        let want = &validation[of.name];
        let order: Vec<&String> = want["fields"].as_object().unwrap().keys().collect();
        assert_eq!(fields.keys().collect::<Vec<_>>(), order, "{}", of.name);
        let got = json!({"defaultMax": of.default_max, "fields": fields});
        assert_eq!(&got, want, "{}", of.name);
    }
}

/// gh-aw's collector, on each case's `outputs.jsonl` and `config.json`,
/// wrote its `collected.json` (`just collect-fixtures`); this collector
/// must write the same. gh-aw adds an incomplete report to a result with
/// no requests but diagnostics, which `check` drops and this leaves out.
#[test]
fn matches_gh_aws_collector() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/collect");
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
        let got = collect(&read("outputs.jsonl"), &config, &keeps_public);
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
    let config = object(json!({"add_comment": {"max": 1}, "add_labels": {"max": 1}}));
    let cases = [
        (
            r#"{"type":"add_labels","labels":["bug"]}"#,
            "Line 1: Unsupported output type 'add_labels': agentic-job collect validates only \
             add_comment, create_pull_request, noop, missing_tool, missing_data",
        ),
        (
            r#"{"type":"add_comment","body":"x",}"#,
            "Line 1: Invalid JSON - trailing comma at line 1 column 34",
        ),
        ("[1]", "Line 1: Missing required 'type' field"),
        ("null", "Line 1: Missing required 'type' field"),
        (
            r#"{"type":7}"#,
            "Line 1: Invalid JSON - 'type' is not a string",
        ),
    ];
    for (line, want) in cases {
        let got = collect(line, &config, &keeps_public);
        assert_eq!(got.items, Vec::<Map<String, Value>>::new(), "{line}");
        assert_eq!(got.errors, [want], "{line}");
    }
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

/// The command reads the hand-back's file and the policy's types, and
/// fails where the collector refused a line, as check.yml's step after
/// gh-aw's collector does.
#[test]
fn command_writes_the_result() {
    let dir = tempfile::tempdir().unwrap();
    let mut policy = crate::policy::tests::policy();
    policy.safe_outputs.create_pull_request = None;
    policy.safe_outputs.others.clear();
    policy.safe_outputs.others.insert(
        "noop".to_owned(),
        serde_json::from_value(json!({"max": 1})).unwrap(),
    );
    let policy_path = dir.path().join("policy.json");
    std::fs::write(&policy_path, serde_json::to_string(&policy).unwrap()).unwrap();
    let outputs = dir.path().join("outputs");
    std::fs::create_dir(&outputs).unwrap();
    let args = Args {
        policy: policy_path,
        outputs: outputs.clone(),
        collected: dir.path().join("collected.json"),
    };
    let read = || -> Value {
        serde_json::from_str(&std::fs::read_to_string(&args.collected).unwrap()).unwrap()
    };

    assert_eq!(run(&args).unwrap(), Exit::Success);
    assert_eq!(read(), json!({"items": [], "errors": []}));

    std::fs::write(
        outputs.join(OUTPUTS_FILE),
        "{\"type\":\"noop\",\"message\":\"Done, @someone\"}\n{\"type\":\"add_comment\",\"body\":\"x\"}\n",
    )
    .unwrap();
    assert_eq!(run(&args).unwrap(), Exit::Failure);
    assert_eq!(
        read(),
        json!({
            "items": [{"type": "noop", "message": "Done, `@someone`"}],
            "errors": ["Line 2: Unexpected output type 'add_comment'. Expected one of: noop"],
        })
    );

    // Not through a link the agent's machine planted, nor past the cap.
    std::fs::remove_file(outputs.join(OUTPUTS_FILE)).unwrap();
    std::os::unix::fs::symlink(&args.policy, outputs.join(OUTPUTS_FILE)).unwrap();
    let err = run(&args).unwrap_err().to_string();
    assert!(err.ends_with("is not a regular file"), "{err}");
    std::fs::remove_file(outputs.join(OUTPUTS_FILE)).unwrap();
    let big = usize::try_from(MAX_OUTPUTS_BYTES).unwrap() + 1;
    std::fs::write(outputs.join(OUTPUTS_FILE), "\n".repeat(big)).unwrap();
    let err = run(&args).unwrap_err().to_string();
    assert!(err.contains("over 1048576"), "{err}");
}
