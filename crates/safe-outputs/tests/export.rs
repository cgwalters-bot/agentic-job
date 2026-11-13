//! Copied-tree export smoke proof, not verification of a history rewrite.

#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;

/// The same path inventory is consumed by git-filter-repo at transfer time.
const PATHS: &str = include_str!("../export.paths");
const WORKSPACE: &str = include_str!("../export.toml");

fn copy(from: &Path, to: &Path) {
    let metadata = from.symlink_metadata().unwrap();
    assert!(!metadata.file_type().is_symlink(), "{}", from.display());
    if metadata.is_dir() {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            copy(&entry.path(), &to.join(entry.file_name()));
        }
    } else {
        assert!(metadata.is_file(), "{}", from.display());
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(from, to).unwrap();
    }
}

fn cargo(root: &Path, target: &Path, args: &[&str]) {
    let status = Command::new(env!("CARGO"))
        .args(args)
        .current_dir(root)
        .env("CARGO_TARGET_DIR", target)
        .status()
        .unwrap();
    assert!(status.success(), "cargo {args:?}: {status}");
}

#[test]
#[ignore = "builds and tests a temporary export; run just test-safe-outputs-export"]
fn isolated_export() {
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("export");
    for path in PATHS.lines() {
        copy(&checkout.join(path), &root.join(path));
    }
    std::fs::write(root.join("Cargo.toml"), WORKSPACE).unwrap();
    // Keep the existing resolution, allowing Cargo to prune unrelated entries.
    // All verification after this one offline lock operation is locked.
    let target = temp.path().join("target");
    cargo(
        &root,
        &target,
        &["build", "--offline", "-p", "safe-outputs"],
    );
    assert!(!root.join("crates/agentic-job/src").exists());
    assert!(!root.join("crates/agentic-job/Cargo.toml").exists());
    assert!(!root.join("crates/secure-host").exists());
    for args in [
        vec!["build", "--offline", "--locked", "-p", "safe-outputs"],
        vec!["test", "--offline", "--locked", "-p", "safe-outputs"],
        vec![
            "build",
            "--offline",
            "--locked",
            "-p",
            "safe-outputs",
            "--no-default-features",
        ],
        vec![
            "test",
            "--offline",
            "--locked",
            "-p",
            "safe-outputs",
            "--no-default-features",
            "--lib",
        ],
    ] {
        cargo(&root, &target, &args);
    }

    // A distinct downstream crate must not depend on feature unification from
    // agentic-job to use the public adapter test helpers.
    let consumer = temp.path().join("consumer");
    std::fs::create_dir_all(consumer.join("src")).unwrap();
    let library = root.join("crates/safe-outputs");
    std::fs::write(
        consumer.join("Cargo.toml"),
        format!(
            "[package]\nname = \"example-consumer\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[dependencies]\nsafe-outputs = {{ path = {:?}, default-features = false, features = [\"test-support\"] }}\n",
            library
        ),
    ).unwrap();
    std::fs::write(consumer.join("src/lib.rs"), "#[test]\nfn adapter() {\n    use safe_outputs::apply::testing;\n    let _ = testing::committer();\n    let _ = testing::forge(Default::default());\n}\n").unwrap();
    cargo(&consumer, &target, &["generate-lockfile", "--offline"]);
    cargo(&consumer, &target, &["test", "--offline", "--locked"]);
}
