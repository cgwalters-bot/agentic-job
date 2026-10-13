//! Opt-in evidence that the pinned agents find the skills and subagents
//! `run` installs, where it installs them and with the launcher's
//! switches. Neither makes a model request; no setup or forge access.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;

use agentic_job::run::agent::{self, CLAUDE_QUIET, Kind};
use agentic_job::run::launch::OPENCODE_SWITCHES;
use serde_json::Value;

/// Writes the files of KIND's skills under HOME, as `run` does.
fn install(kind: Kind, home: &Path) {
    for file in agent::skills(kind, true) {
        let path = home.join(file.path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, file.content.unwrap()).unwrap();
    }
}

/// The version policy.yml installs of the package PREFIX names.
fn pinned(prefix: &str) -> String {
    let policy = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/policy.yml");
    let policy = std::fs::read_to_string(policy).unwrap();
    let rest = policy.split(prefix).nth(1).unwrap();
    rest.split('\'').next().unwrap().to_owned()
}

fn json(command: &mut Command) -> Value {
    let out = command.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn pinned_opencode_finds_the_skills() {
    let Ok(opencode) = std::env::var("AGENTIC_JOB_TEST_OPENCODE") else {
        eprintln!("skipped: set AGENTIC_JOB_TEST_OPENCODE to the pinned opencode");
        return;
    };
    // The version the workflows install, not another one's paths.
    let version = Command::new(&opencode).arg("--version").output().unwrap();
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        pinned("'opencode-ai@")
    );
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let work = root.path().join("work");
    install(Kind::Opencode, &home);
    // The target repository's own, which project configuration being
    // off must leave unread.
    let hostile = "---\nname: implement\ndescription: PROJECT_CANARY\n---\nPROJECT_CANARY\n";
    for path in [
        ".opencode/skills/implement/SKILL.md",
        ".opencode/agents/diff-reviewer.md",
    ] {
        let path = work.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, hostile).unwrap();
    }
    let run = |args: &[&str]| {
        let mut command = Command::new(&opencode);
        command
            .args(["debug"])
            .args(args)
            .current_dir(&work)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &home)
            .envs(OPENCODE_SWITCHES.iter().copied());
        json(&mut command)
    };
    let skills = run(&["skill"]);
    for name in ["implement", "review"] {
        let skill = skills
            .as_array()
            .unwrap()
            .iter()
            .find(|skill| skill["name"] == name)
            .unwrap_or_else(|| panic!("no skill {name}: {skills}"));
        let want = home.join(format!(".config/opencode/skills/{name}/SKILL.md"));
        assert_eq!(skill["location"].as_str(), want.to_str());
    }
    assert!(!skills.to_string().contains("PROJECT_CANARY"), "{skills}");
    let reviewer = run(&["agent", "diff-reviewer"]);
    assert_eq!(reviewer["mode"], "subagent");
    assert!(
        reviewer["prompt"]
            .as_str()
            .unwrap()
            .contains("You review a change you did not write."),
        "{reviewer}"
    );
}

/// The SDK the Claude Code ACP adapter at `argv[1]` starts, with the
/// setting sources that adapter passes; it lists what it found before any
/// model request.
const CLAUDE_INIT: &str = r#"
const { createRequire } = await import('node:module');
const { pathToFileURL } = await import('node:url');
const adapter = createRequire(`${process.argv[1]}/package.json`);
const { query } = await import(pathToFileURL(adapter.resolve('@anthropic-ai/claude-agent-sdk')).href);
const q = query({ prompt: 'list', options: { cwd: process.cwd(), settingSources: ['user', 'project', 'local'] } });
for await (const m of q) {
  if (m.type === 'system' && m.subtype === 'init') {
    console.log(JSON.stringify({ skills: m.skills, agents: m.agents }));
    process.exit(0);
  }
}
process.exit(1);
"#;

#[test]
fn pinned_claude_adapter_finds_the_skills() {
    let Ok(adapter) = std::env::var("AGENTIC_JOB_TEST_CLAUDE_ACP") else {
        eprintln!("skipped: set AGENTIC_JOB_TEST_CLAUDE_ACP to the pinned ACP adapter's directory");
        return;
    };
    // The adapter the workflows install, and the setting sources
    // CLAUDE_INIT assumes it passes the SDK.
    let package: Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(&adapter).join("package.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        package["version"],
        pinned("'@agentclientprotocol/claude-agent-acp@")
    );
    let code = std::fs::read_to_string(Path::new(&adapter).join("dist/acp-agent.js")).unwrap();
    assert!(code.contains(r#"settingSources: ["user", "project", "local"]"#));
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let work = root.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    install(Kind::Claude, &home);
    let mut command = Command::new("node");
    command
        .args(["--input-type=module", "-e", CLAUDE_INIT, &adapter])
        .current_dir(&work)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", &home)
        // Nothing listens there: no model is reached.
        .env("ANTHROPIC_BASE_URL", "http://127.0.0.1:9")
        .env("ANTHROPIC_AUTH_TOKEN", "unused")
        .envs(CLAUDE_QUIET.iter().copied());
    let found = json(&mut command);
    let has = |key: &str, name: &str| found[key].as_array().unwrap().iter().any(|n| n == name);
    assert!(
        has("skills", "implement") && has("skills", "review"),
        "{found}"
    );
    assert!(has("agents", "diff-reviewer"), "{found}");
}
