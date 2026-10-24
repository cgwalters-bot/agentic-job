//! The classifier of failed model requests, against the words real runs'
//! transcripts had (`data/provider/errors.json`, redacted): each must
//! land in the class a caller would act on.

use agentic_job::session::provider::{Class, classify};
use serde_json::Value;

#[test]
fn the_audited_runs_words_are_classified() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/provider/errors.json"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let cases: Vec<Value> = serde_json::from_str(&text).unwrap();
    assert!(cases.len() >= 10, "{} cases", cases.len());
    for case in &cases {
        let want: Class = serde_json::from_value(case["class"].clone()).unwrap();
        let text = case["text"].as_str().unwrap();
        assert_eq!(
            classify(text),
            want,
            "{}: {text:?}",
            case["source"].as_str().unwrap_or("?")
        );
    }
    // Every class that is reported has at least one case.
    for class in Class::ALL {
        assert!(
            cases
                .iter()
                .any(|c| c["class"] == Value::String(class.as_str().to_owned())),
            "no case for {class:?}"
        );
    }
}
