//! `agentic-job launch-agent NAME`: what the session starts as the
//! sandbox user in place of the agent's own program. It gives the agent
//! the environment that selects its provider and nothing else that
//! could, and then becomes the agent.
//!
//! It replaces the old tree's `claude-launch.mjs` and
//! `opencode-launch.mjs`. The run token cannot be on the command line
//! the session builds, which every user can read, so it is in a file of
//! the sandbox user's ([`super::agent`]) that this reads.
//!
//! It runs as the sandbox user, on that user's files: it holds nothing
//! the agent does not, and is not a boundary.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use super::agent::{
    CLAUDE_ENV_FILE, CLAUDE_QUIET, GITHUB_TOKEN_FILE, GITHUB_TOKEN_VAR, Kind, OPENCODE_PROFILE_FILE,
};
use crate::exit::Exit;
use crate::session::agents;
use crate::session::process::is_inherited_setting;

/// The subcommand, as the session's command line names it.
pub const COMMAND: &str = "launch-agent";
/// The one setting of an agent that comes from the session's command
/// line: the model, which the registry passes Claude Code this way.
const KEPT: &[&str] = &["ANTHROPIC_MODEL"];
/// The only variables Claude Code's environment file may set.
const CLAUDE_ENV_PREFIX: &str = "ANTHROPIC_";
/// The variables that move where opencode reads its configuration and
/// keeps its state. The login session's own (`XDG_RUNTIME_DIR`,
/// `XDG_SESSION_*`, from pam_systemd) stay: the agent's commands need
/// them for rootless podman and the user's service manager.
const XDG_BASE_DIRS: &[&str] = &[
    "XDG_CONFIG_HOME",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_HOME",
    "XDG_DATA_DIRS",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
];
/// What keeps opencode to its global configuration: the target
/// repository's `opencode.json` and `.opencode/` could add providers and
/// plugins, and the model list is not fetched from elsewhere.
pub const OPENCODE_SWITCHES: &[(&str, &str)] = &[
    ("OPENCODE_DISABLE_PROJECT_CONFIG", "1"),
    ("OPENCODE_DISABLE_MODELS_FETCH", "1"),
    // External skills have their own project/home discovery, independent
    // of the project-config switch. Also suppress the home Claude prompt
    // fallback and bundled authentication plugins.
    ("OPENCODE_DISABLE_EXTERNAL_SKILLS", "1"),
    ("OPENCODE_DISABLE_CLAUDE_CODE", "1"),
    ("OPENCODE_DISABLE_DEFAULT_PLUGINS", "1"),
    ("OPENCODE_DISABLE_AUTOUPDATE", "1"),
];
/// Selects an opencode configuration merged over the global one.
const OPENCODE_CONFIG_VAR: &str = "OPENCODE_CONFIG";
/// The variables `gh` takes a GitHub token from: only the run's is
/// passed on, as [`GITHUB_TOKEN_VAR`].
const GITHUB_TOKEN_VARS: &[&str] = &[
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
];

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The agent to become: claude or opencode
    pub agent: String,
    /// Arguments passed on to the agent's program
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<OsString>,
}

/// Claude Code's environment file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvFile {
    env: BTreeMap<String, String>,
}

/// The variables of Claude Code's environment file TEXT.
fn claude_env(text: &str) -> Result<BTreeMap<String, String>> {
    let EnvFile { env } = serde_json::from_str(text)?;
    for name in env.keys() {
        let rest = name.strip_prefix(CLAUDE_ENV_PREFIX).unwrap_or_default();
        ensure!(
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
            "it sets {name:?}, and may set only {CLAUDE_ENV_PREFIX}* variables"
        );
    }
    Ok(env)
}

/// The run's read-only GitHub token, from the file under HOME that
/// `agentic-job run` wrote, if it wrote one.
pub fn github_token(
    home: &Path,
    read: impl Fn(&Path) -> std::io::Result<String>,
) -> Result<Option<String>> {
    let file = home.join(GITHUB_TOKEN_FILE);
    match read(&file) {
        Ok(text) => Ok(Some(text.trim_end().to_owned()).filter(|token| !token.is_empty())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("reading {}", file.display())),
    }
}

/// The agent's own program and its first arguments, found on the sandbox
/// user's PATH: the command of its entry in the session's registry,
/// which is the one place that names it.
fn program(kind: Kind) -> Result<Vec<String>> {
    ensure!(
        kind != Kind::Fake,
        "the fake agent is started as it is, without a launcher"
    );
    Ok(agents::builtin(kind.as_str())?.command)
}

/// The agent's environment: INHERITED without anything that selects an
/// agent's provider, credential or configuration, then what the run
/// configured, the run's GitHub token included.
///
/// HOME is the sandbox user's home. Nothing here is resolved against the
/// working directory, which is the target repository.
fn environment(
    kind: Kind,
    inherited: impl Iterator<Item = (OsString, OsString)>,
    home: &Path,
    read: impl Fn(&Path) -> std::io::Result<String>,
) -> Result<BTreeMap<OsString, OsString>> {
    ensure!(home.is_absolute(), "HOME must be an absolute path");
    let dropped = |name: &OsString| {
        let kept = KEPT.iter().any(|kept| name == kept);
        let xdg = kind == Kind::Opencode && XDG_BASE_DIRS.iter().any(|dir| name == dir);
        let github = GITHUB_TOKEN_VARS.iter().any(|var| name == var);
        (is_inherited_setting(name) && !kept) || xdg || github
    };
    let mut env: BTreeMap<OsString, OsString> =
        inherited.filter(|(name, _)| !dropped(name)).collect();
    let mut set = |name: &str, value: &str| env.insert(name.into(), value.into());
    match kind {
        Kind::Claude => {
            // Without it Claude Code would look for a login of its own.
            let file = home.join(CLAUDE_ENV_FILE);
            let run = read(&file)
                .map_err(anyhow::Error::from)
                .and_then(|text| claude_env(&text))
                .with_context(|| format!("reading {}", file.display()))?;
            for (name, value) in &run {
                set(name, value);
            }
            // Also in the managed settings, for the adapter itself.
            for (name, value) in CLAUDE_QUIET {
                set(name, value);
            }
        }
        Kind::Opencode => {
            for (name, value) in OPENCODE_SWITCHES {
                set(name, value);
            }
            // Where there is no profile, opencode's own choice of its
            // global configuration is left alone.
            let profile = home.join(OPENCODE_PROFILE_FILE);
            match read(&profile) {
                Ok(_) => {
                    env.insert(OPENCODE_CONFIG_VAR.into(), profile.into());
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).with_context(|| format!("reading {}", profile.display()));
                }
            }
        }
        Kind::Vibe => {
            env.insert(
                "VIBE_HOME".into(),
                home.join(super::agent::VIBE_HOME).into(),
            );
        }
        Kind::Fake => {}
    }
    if let Some(token) = github_token(home, &read)? {
        env.insert(GITHUB_TOKEN_VAR.into(), token.into());
    }
    Ok(env)
}

/// Becomes the agent. Returns only if that failed.
pub fn run(args: &Args) -> Result<Exit> {
    let kind = Kind::parse(&args.agent)?;
    let program = program(kind)?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let env = environment(kind, std::env::vars_os(), &home, |path| {
        std::fs::read_to_string(path)
    })?;
    let (first, rest) = program.split_first().context("the agent has no program")?;
    let err = Command::new(first)
        .args(rest)
        .args(&args.args)
        .env_clear()
        .envs(env)
        .exec();
    Err(err).with_context(|| format!("starting {first}"))
}

/// The session's command for KIND: this binary as the launcher, by the
/// path EXE, which the sandbox user must be able to run.
pub fn command(exe: &str, kind: Kind) -> Vec<String> {
    [exe, COMMAND, kind.as_str()].map(str::to_owned).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/home/agent";

    fn inherited(vars: &[(&str, &str)]) -> impl Iterator<Item = (OsString, OsString)> {
        vars.iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect::<Vec<_>>()
            .into_iter()
    }

    fn strings(env: &BTreeMap<OsString, OsString>) -> BTreeMap<&str, &str> {
        env.iter()
            .map(|(k, v)| (k.to_str().unwrap(), v.to_str().unwrap()))
            .collect()
    }

    const TOKEN_FILE: &str = "/home/agent/.config/agentic-job/github-token";

    fn missing(_: &Path) -> std::io::Result<String> {
        Err(std::io::ErrorKind::NotFound.into())
    }

    /// The adapter gets only the run's environment and the model.
    #[test]
    fn claude_gets_the_runs_environment_and_the_model() {
        let ambient = [
            ("KEEP_ME", "kept"),
            ("ANTHROPIC_API_KEY", "ambient"),
            ("ANTHROPIC_BASE_URL", "https://elsewhere.example"),
            ("ANTHROPIC_MODEL", "opus"),
            ("CLAUDE_CODE_USE_BEDROCK", "1"),
            ("CLAUDE_CONFIG_DIR", "/tmp/x"),
            ("OPENCODE_CONFIG", "/tmp/y"),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "t"),
            ("XDG_CONFIG_HOME", "/tmp/xdg"),
            ("GH_TOKEN", "ambient"),
            ("GITHUB_TOKEN", "ambient"),
            ("GH_ENTERPRISE_TOKEN", "ambient"),
            ("GITHUB_ENTERPRISE_TOKEN", "ambient"),
        ];
        let read = |path: &Path| {
            if path == Path::new(TOKEN_FILE) {
                return missing(path);
            }
            assert_eq!(
                path,
                Path::new("/home/agent/.config/agentic-job/claude-env.json")
            );
            Ok(r#"{"env": {"ANTHROPIC_BASE_URL": "http://proxy/anthropic", "ANTHROPIC_AUTH_TOKEN": "p",
                "ANTHROPIC_CUSTOM_HEADERS": "x-run-token: t"}}"#
                .to_owned())
        };
        let env = environment(Kind::Claude, inherited(&ambient), Path::new(HOME), read).unwrap();
        assert_eq!(
            strings(&env),
            BTreeMap::from([
                ("KEEP_ME", "kept"),
                ("XDG_CONFIG_HOME", "/tmp/xdg"),
                ("ANTHROPIC_MODEL", "opus"),
                ("ANTHROPIC_BASE_URL", "http://proxy/anthropic"),
                ("ANTHROPIC_AUTH_TOKEN", "p"),
                ("ANTHROPIC_CUSTOM_HEADERS", "x-run-token: t"),
                ("DISABLE_AUTOUPDATER", "1"),
                ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
            ])
        );
    }

    /// It refuses to start without the run's environment, or with one
    /// that sets anything else.
    #[test]
    fn claude_does_not_start_without_its_environment() {
        let with = |text: &'static str| {
            environment(Kind::Claude, inherited(&[]), Path::new(HOME), move |_| {
                Ok(text.to_owned())
            })
        };
        let cases = [
            ("not json", "claude-env.json"),
            ("{}", "missing field `env`"),
            (r#"{"env": []}"#, "invalid type"),
            (r#"{"env": {"ANTHROPIC_BASE_URL": 1}}"#, "invalid type"),
            (r#"{"env": {"PATH": "/evil"}}"#, "may set only ANTHROPIC_*"),
            (
                r#"{"env": {"ANTHROPIC_": "x"}}"#,
                "may set only ANTHROPIC_*",
            ),
            (
                r#"{"env": {"LD_PRELOAD": "x"}}"#,
                "may set only ANTHROPIC_*",
            ),
            (r#"{"env": {}, "other": 1}"#, "unknown field"),
        ];
        for (text, want) in cases {
            let err = format!("{:#}", with(text).unwrap_err());
            assert!(err.contains(want), "{text}: {err}");
        }
        let err = environment(Kind::Claude, inherited(&[]), Path::new(HOME), missing).unwrap_err();
        assert!(format!("{err:#}").contains("reading /home/agent/.config/agentic-job"));
        let err = environment(Kind::Claude, inherited(&[]), Path::new("home"), missing);
        assert!(format!("{:#}", err.unwrap_err()).contains("HOME must be an absolute path"));
    }

    /// opencode loses inherited configuration, keeps the login session,
    /// and takes only the installed profile, by its absolute path.
    #[test]
    fn opencode_reads_only_its_global_configuration() {
        let ambient = [
            ("KEEP_ME", "kept"),
            ("OPENCODE_CONFIG", "evil.json"),
            ("OPENCODE_CONFIG_CONTENT", "{}"),
            ("OPENCODE_DISABLE_PROJECT_CONFIG", "0"),
            ("OPENCODE_DISABLE_EXTERNAL_SKILLS", "0"),
            ("OPENCODE_DISABLE_CLAUDE_CODE", "0"),
            ("OPENCODE_DISABLE_DEFAULT_PLUGINS", "0"),
            ("OPENCODE_DISABLE_AUTOUPDATE", "0"),
            ("ANTHROPIC_API_KEY", "ambient"),
            ("CLAUDE_CONFIG_DIR", "/tmp/x"),
            ("XDG_CONFIG_HOME", "/tmp/xdg"),
            ("XDG_DATA_HOME", "/tmp/data"),
            ("XDG_RUNTIME_DIR", "/run/user/1001"),
            ("XDG_SESSION_ID", "7"),
        ];
        let base = BTreeMap::from([
            ("KEEP_ME", "kept"),
            ("XDG_RUNTIME_DIR", "/run/user/1001"),
            ("XDG_SESSION_ID", "7"),
            ("OPENCODE_DISABLE_PROJECT_CONFIG", "1"),
            ("OPENCODE_DISABLE_MODELS_FETCH", "1"),
            ("OPENCODE_DISABLE_EXTERNAL_SKILLS", "1"),
            ("OPENCODE_DISABLE_CLAUDE_CODE", "1"),
            ("OPENCODE_DISABLE_DEFAULT_PLUGINS", "1"),
            ("OPENCODE_DISABLE_AUTOUPDATE", "1"),
        ]);
        let env = environment(
            Kind::Opencode,
            inherited(&ambient),
            Path::new(HOME),
            missing,
        );
        assert_eq!(strings(&env.unwrap()), base);
        let env = environment(
            Kind::Opencode,
            inherited(&ambient),
            Path::new(HOME),
            |path| {
                if path == Path::new(TOKEN_FILE) {
                    return missing(path);
                }
                assert_eq!(
                    path,
                    Path::new("/home/agent/.config/opencode/opencode-runner.json")
                );
                Ok(String::new())
            },
        )
        .unwrap();
        let mut with_profile = base.clone();
        with_profile.insert(
            "OPENCODE_CONFIG",
            "/home/agent/.config/opencode/opencode-runner.json",
        );
        assert_eq!(strings(&env), with_profile);
        let denied = |_: &Path| Err(std::io::ErrorKind::PermissionDenied.into());
        let err = environment(Kind::Opencode, inherited(&[]), Path::new(HOME), denied);
        assert!(format!("{:#}", err.unwrap_err()).contains("opencode-runner.json"));
    }

    /// Every agent gets the run's GitHub token, and no other.
    #[test]
    fn agents_get_only_the_runs_github_token() {
        let ambient = [
            ("GH_TOKEN", "ambient"),
            ("GITHUB_TOKEN", "ambient"),
            ("GH_ENTERPRISE_TOKEN", "ambient"),
            ("GITHUB_ENTERPRISE_TOKEN", "ambient"),
        ];
        let denied = std::io::ErrorKind::PermissionDenied;
        for kind in [Kind::Claude, Kind::Opencode] {
            for (file, want) in [
                (Err(std::io::ErrorKind::NotFound), Ok(vec![])),
                (Ok(""), Ok(vec![])),
                (Ok("ghs_run\n"), Ok(vec!["GH_TOKEN=ghs_run".to_owned()])),
                (Err(denied), Err(format!("reading {TOKEN_FILE}"))),
            ] {
                let read = |path: &Path| match path.to_str() {
                    Some(TOKEN_FILE) => file.map(str::to_owned).map_err(Into::into),
                    _ if kind == Kind::Claude => Ok(r#"{"env": {}}"#.to_owned()),
                    _ => missing(path),
                };
                let got = environment(kind, inherited(&ambient), Path::new(HOME), read)
                    .map(|env| {
                        strings(&env)
                            .into_iter()
                            .filter(|(name, _)| name.ends_with("_TOKEN"))
                            .map(|(name, value)| format!("{name}={value}"))
                            .collect::<Vec<_>>()
                    })
                    .map_err(|err| format!("{err:#}"));
                match (&got, &want) {
                    (Err(got), Err(want)) => assert!(got.contains(want), "{got}"),
                    _ => assert_eq!(got, want, "{kind:?} {file:?}"),
                }
            }
        }
    }

    #[test]
    fn commands() {
        assert_eq!(
            command("/usr/local/bin/agentic-job", Kind::Claude),
            ["/usr/local/bin/agentic-job", "launch-agent", "claude"]
        );
        assert_eq!(program(Kind::Opencode).unwrap(), ["opencode", "acp"]);
        assert_eq!(program(Kind::Claude).unwrap(), ["claude-agent-acp"]);
        assert!(program(Kind::Fake).is_err());
    }

    #[test]
    fn vibe_ignores_ambient_configuration() {
        let env = environment(
            Kind::Vibe,
            inherited(&[
                ("VIBE_HOME", "/evil"),
                ("VIBE_PROVIDERS", "[]"),
                ("MISTRAL_API_KEY", "ambient"),
                ("VIBE_ACTIVE_MODEL", "evil"),
                ("vibe_providers", "[]"),
                ("KEEP_ME", "kept"),
            ]),
            Path::new(HOME),
            missing,
        )
        .unwrap();
        assert_eq!(
            strings(&env),
            BTreeMap::from([
                ("KEEP_ME", "kept"),
                ("VIBE_HOME", "/home/agent/.config/agentic-job/vibe"),
            ])
        );
        let argv = program(Kind::Vibe).unwrap();
        assert_eq!(
            &argv[..3],
            ["/opt/agentic-job/vibe/bin/python3", "-I", "-c"]
        );
        assert!(argv[3].contains("init_harness_files_manager(\"user\")"));
        assert!(!argv[3].contains("init_harness_files_manager(\"user\", \"project\")"));
    }
}
