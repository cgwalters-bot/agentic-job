//! secure-host depends on nothing that runs an agent, so that any job
//! can adopt it and a change to agentic-job cannot change what secures
//! the host. `cargo tree -p secure-host` shows the same; this keeps it so
//! from the manifest, which is all a change to the tree has to change.
#![allow(clippy::unwrap_used)]

use std::path::Path;

/// The crates of agentic-job's agent side.
const AGENT_CRATES: &[&str] = &["agentic-job", "agent-client-protocol"];

const TABLES: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];

/// What MANIFEST may not depend on, in any dependency table, target
/// tables included: an agent crate by name, or any crate by `path` or
/// `git`, which is how another of this workspace's crates, and agentic-job
/// through it, would come in. Registry crates stay pinned by Cargo.lock.
fn refused(text: &str) -> Vec<String> {
    let manifest: toml::Table = text.parse().unwrap();
    let mut tables: Vec<&toml::Value> = TABLES.iter().filter_map(|t| manifest.get(*t)).collect();
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            tables.extend(TABLES.iter().filter_map(|t| target.get(*t)));
        }
    }
    let mut found = Vec::new();
    for table in tables.iter().filter_map(|t| t.as_table()) {
        for (name, spec) in table {
            // A renamed dependency names its crate in `package`.
            let package = spec.get("package").and_then(toml::Value::as_str);
            if AGENT_CRATES.contains(&package.unwrap_or(name)) {
                found.push(package.unwrap_or(name).to_owned());
            } else if spec.get("path").is_some() || spec.get("git").is_some() {
                found.push(format!("{name} (not from the registry)"));
            }
        }
    }
    found
}

#[test]
fn no_agent_crate_is_a_dependency() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(refused(&text), Vec::<String>::new());
}

#[test]
fn the_check_finds_agent_crates_wherever_declared() {
    for (manifest, want) in [
        ("[dependencies]\nanyhow = \"1\"\n", &[][..]),
        ("[dependencies]\nanyhow.workspace = true\n", &[]),
        (
            "[dependencies]\nglue = { path = \"../glue\" }\n",
            &["glue (not from the registry)"],
        ),
        (
            "[dependencies]\nglue = { git = \"https://example.com/glue\" }\n",
            &["glue (not from the registry)"],
        ),
        (
            "[dependencies]\nagentic-job = { path = \"../agentic-job\" }\n",
            &["agentic-job"][..],
        ),
        (
            "[dev-dependencies]\nagent-client-protocol = \"2\"\n",
            &["agent-client-protocol"],
        ),
        (
            "[build-dependencies]\nagentic-job = \"0\"\n",
            &["agentic-job"],
        ),
        (
            "[dependencies]\naj = { package = \"agentic-job\", path = \"x\" }\n",
            &["agentic-job"],
        ),
        (
            "[target.'cfg(unix)'.dependencies]\nagent-client-protocol = \"2\"\n",
            &["agent-client-protocol"],
        ),
    ] {
        assert_eq!(refused(manifest), want, "{manifest}");
    }
}
