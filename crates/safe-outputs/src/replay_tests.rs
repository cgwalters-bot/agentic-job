//! Offline boundary tests for the old-side matcher, independent of Git's fuzz.

use crate::replay::*;

const BASE: &str = "1111111111111111111111111111111111111111";
const ENDPOINT: &str = "inference.example.test:8443";

fn patch(body: &str) -> String {
    format!(
        "X-GH-AW-Base-Commit: {BASE}\ndiff --git a/sample b/sample\n--- a/sample\n+++ b/sample\n{body}"
    )
}

#[test]
fn replay_refuses_ambiguous_and_unbounded_inputs() {
    let literals = [Literal::new(ENDPOINT).unwrap()];
    let original = format!("x={ENDPOINT}\n");
    let body = "@@ -1 +1 @@\n-x=<inference-address>\n+new\n";
    let valid = patch(body);
    let recover_patch =
        |text: &str, evidence: &[Literal]| recover(text, BASE, evidence, |_| Ok(original.clone()));
    assert!(recover_patch(&valid, &literals).is_ok());
    for text in [
        patch(&format!("{body}{body}")),
        patch("@@ -1 +1 @@\n-x=<inference-address> extra\n+new\n"),
        patch("@@ -1 +1 @@\n-x=<agent-inference-token>\n+new\n"),
        patch("@@ -1 +1 @@\n-x=<inference-address>\n+new\n\\ No newline at end of file\n"),
        patch("@@ -999999999999999999999 +1 @@\n-x=<inference-address>\n+new\n"),
        format!("X-GH-AW-Base-Commit: {BASE}\n{valid}"),
        valid.replace("a/sample b/sample", "a/sample b/other"),
        valid.replace("a/sample b/sample", "a//sample b//sample"),
        format!("{valid}{}", "x".repeat(MAX_BYTES)),
    ] {
        assert!(recover_patch(&text, &literals).is_err());
    }
    assert!(
        recover_patch(
            &valid,
            &[Literal {
                bytes: 0,
                sha256: "0".repeat(64)
            }]
        )
        .is_err()
    );
    assert!(recover_patch(&valid, &vec![literals[0].clone(); 9]).is_err());
    assert!(
        recover(&valid, BASE, &literals, |_| Ok(format!(
            "forged {original}"
        )))
        .is_err()
    );
    assert!(recover(&valid, BASE, &literals, |_| Ok("x".repeat(MAX_BYTES + 1))).is_err());
}

#[test]
fn replay_preserves_unaffected_bytes_and_only_recovers_old_side() {
    let literals = [Literal::new(ENDPOINT).unwrap()];
    let text = patch("@@ -1 +1,2 @@\n x=<inference-address>\n+x=<inference-address>\n");
    let recovered = recover(&text, BASE, &literals, |_| Ok(format!("x={ENDPOINT}\n"))).unwrap();
    assert!(recovered.contains(&format!(" x={ENDPOINT}\n+x=<inference-address>\n")));
    let text = patch("@@ -1 +1 @@\n-old\n+new\n");
    assert_eq!(
        recover(&text, BASE, &literals, |_| Ok("old\n".to_owned())).unwrap(),
        text
    );
    // A literal placeholder in the base needs no substitution authority.
    assert_eq!(
        recover(
            &patch("@@ -1 +1 @@\n-x=<inference-address>\n+new\n"),
            BASE,
            &[],
            |_| Ok("x=<inference-address>\n".to_owned())
        )
        .unwrap(),
        patch("@@ -1 +1 @@\n-x=<inference-address>\n+new\n")
    );
}
