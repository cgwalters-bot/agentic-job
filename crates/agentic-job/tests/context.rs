//! Policy-machine context resolution has no credentials or network in tests.

#[test]
fn workflow_context_resolution() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = std::process::Command::new("node")
        .current_dir(root)
        .args(["--test", "workflow/context.test.cjs"])
        .status()
        .expect("Node is required for workflow contract tests");
    assert!(status.success());
}
