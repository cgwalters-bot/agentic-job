//! The agent's configuration: the files that point Claude Code or
//! opencode at the inference proxy with the run's token, and at nothing
//! else.
//!
//! The run token is written to one file in the sandbox user's home, mode
//! 0600 in a directory of mode 0700, and nowhere else: not a command
//! line, not an environment a wrapper would show, not the root-owned
//! settings. That is tidiness and not the boundary. The agent can read
//! its token and run any command; what contains it is the sandbox user
//! and the egress proxy.
//!
//! **Claude Code** gets three files, none taken from anywhere but this
//! binary and the run:
//!
//! - [`CLAUDE_ENV_FILE`], the environment that points it at the proxy,
//!   the token included, which [`super::launch`] applies;
//! - [`MANAGED_SETTINGS_FILE`], root's, with no secret. Claude Code
//!   applies the `env` of settings files over its own environment, the
//!   target repository's `.claude/settings.json` included, and managed
//!   settings over those: so the endpoint and the switches to other
//!   providers are pinned there, and hooks and permission rules are
//!   limited to managed ones, of which there are none, which keeps every
//!   command and edit a permission request the session answers and
//!   records;
//! - [`CLAUDE_INSTRUCTIONS_FILE`], its instructions for an unattended
//!   run.
//!
//! **opencode** gets its global configuration, [`OPENCODE_CONFIG_FILE`],
//! with one provider, the proxy, and the token as that provider's key.
//!
//! Either may take part of this from a public repository the caller
//! names (`[agent] config-repo`): opencode its configuration, which must
//! define exactly one provider (its address and key are replaced), an
//! `AGENTS.md` and an optional profile; Claude Code its instructions.
//! Nothing else in that repository is used: opencode would also merge
//! other configuration files and run plugins, tools and commands found
//! beside its configuration, none of which the provider check covers.
//!
//! An agent is code here, and not an entry of a table a caller writes,
//! on purpose: what keeps its inference at the proxy is different for
//! each one and has to be known, not described. "Adding an agent" in
//! docs/layout.md says what a new one takes.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value, json};

use super::clone::{git_clone, utf8};
use super::enter::Sandbox;
use super::inference::{Endpoint, Token};
use crate::config;

/// In the sandbox user's home.
pub const CLAUDE_ENV_FILE: &str = ".config/agentic-job/claude-env.json";
pub const CLAUDE_INSTRUCTIONS_FILE: &str = ".claude/CLAUDE.md";
pub const OPENCODE_CONFIG_DIR: &str = ".config/opencode";
pub const OPENCODE_CONFIG_FILE: &str = ".config/opencode/opencode.json";
pub const OPENCODE_INSTRUCTIONS_FILE: &str = ".config/opencode/AGENTS.md";
pub const OPENCODE_PROFILE_FILE: &str = ".config/opencode/opencode-runner.json";
pub const VIBE_HOME: &str = ".config/agentic-job/vibe";
pub const VIBE_CONFIG_FILE: &str = ".config/agentic-job/vibe/config.toml";
/// A fixed alias avoids interpreting a caller's model as a Vibe profile or
/// provider selection. It replaces Vibe's sole built-in model, not adds one.
pub const VIBE_MODEL_ALIAS: &str = "mistral-medium-3.5";
/// The run's read-only GitHub token, for `gh` and the GitHub API: the
/// launcher and the fake agent give it to the agent as
/// [`GITHUB_TOKEN_VAR`].
pub const GITHUB_TOKEN_FILE: &str = ".config/agentic-job/github-token";
/// The variable that holds that token, in `agentic-job run`'s
/// environment and in the agent's: the one `gh` reads.
pub const GITHUB_TOKEN_VAR: &str = "GH_TOKEN";
/// Where the agent's configuration repository is cloned, in that home.
const CONFIG_CHECKOUT: &str = ".cache/agentic-job/agent-config";
/// Root's: Claude Code reads its managed settings only from here.
pub const MANAGED_SETTINGS_FILE: &str = "/etc/claude-code/managed-settings.json";
/// The names the files have in a configuration repository.
const SOURCE_CLAUDE_INSTRUCTIONS: &str = "CLAUDE.md";
const SOURCE_OPENCODE_CONFIG: &str = "opencode.json";
const SOURCE_OPENCODE_INSTRUCTIONS: &str = "AGENTS.md";
const SOURCE_OPENCODE_PROFILE: &str = "opencode-runner.json";
/// What the proxy takes as "use your own credential" on its Anthropic
/// routes; it grants nothing without a run token beside it.
pub const PLACEHOLDER_CREDENTIAL: &str = "praxis-substitute:anthropic";
/// Where the proxy reads the run token when `Authorization` holds the
/// placeholder.
pub const RUN_TOKEN_HEADER: &str = "x-run-token";
/// The switches that would send inference to another provider's
/// endpoint, which `ANTHROPIC_BASE_URL` does not govern; pinned empty.
const PROVIDER_SWITCHES: &[&str] = &[
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
];
/// What stops Claude Code calling home for anything but inference.
pub const CLAUDE_QUIET: &[(&str, &str)] = &[
    ("DISABLE_AUTOUPDATER", "1"),
    ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
];
/// Keys of opencode's configuration that choose where inference goes.
const OPENCODE_PROVIDER_KEYS: &[&str] = &["provider", "enabled_providers", "disabled_providers"];
/// The provider of the configuration written when the caller names no
/// repository, and the package that speaks the Responses API for it.
const BUILTIN_PROVIDER: &str = "inference";
const BUILTIN_PROVIDER_PACKAGE: &str = "@ai-sdk/openai";
const OPENCODE_SCHEMA: &str = "https://opencode.ai/config.json";
/// The built-in instructions for Claude Code.
const CLAUDE_INSTRUCTIONS: &str = include_str!("claude-instructions.txt");
/// The largest file taken from a configuration repository.
const MAX_SOURCE_BYTES: usize = 1 << 20;
/// What a failing command may say.
const MAX_COMMAND_OUTPUT: usize = 4096;
/// Prints the file `$1` of the checkout `$2`, and fails with [`ABSENT`]
/// if there is none. With every link resolved, its own included, it
/// must be a regular file still inside the checkout: a repository
/// cannot name a file outside itself, and may link to one of its own,
/// as the old tree allowed (the configuration it runs with every day
/// has its `AGENTS.md` as a link to the one a directory up).
/// The resolved name is itself no link: `$(...)` drops a newline at a
/// name's end, and what is left could be another entry, a link out.
const READ_SCRIPT: &str = r#"[ -e "$1" ] || [ -L "$1" ] || exit 44; r=$(realpath -e -- "$1") && c=$(realpath -e -- "$2") && [ -f "$r" ] && [ ! -L "$r" ] && case "$r" in "$c"/*) exec cat -- "$r" ;; *) exit 1 ;; esac"#;
const ABSENT: i32 = 44;
/// Writes standard input to `$1` under the home, replacing what was
/// there without writing through a link left in its place. The file is
/// private to the user from its first byte: its directory is closed
/// before it exists. Its own mode is set outright as well as by the
/// umask, which alone left it 0664 on one system this was tried on
/// (Ubuntu 26.04; why is not established), where the probes caught it.
const WRITE_SCRIPT: &str = r#"umask 077 && f="$HOME/$1" && d=$(dirname -- "$f") && mkdir -p -- "$d" && chmod 0700 -- "$d" && rm -f -- "$f" && : >"$f" && chmod 0600 -- "$f" && cat >>"$f""#;
const REMOVE_SCRIPT: &str = r#"rm -f -- "$HOME/$1""#;

/// The agents `run` can configure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Claude,
    Opencode,
    Vibe,
    /// The scripted agent, with no model behind it.
    Fake,
}

impl Kind {
    const ALL: &'static [Self] = &[Self::Claude, Self::Opencode, Self::Vibe, Self::Fake];

    /// The agent `[agent] name` names.
    pub fn parse(name: &str) -> Result<Self> {
        let known = || {
            let names: Vec<_> = Self::ALL.iter().map(|kind| kind.as_str()).collect();
            names.join(", ")
        };
        ensure!(
            !name.is_empty(),
            "agent.name is not set: one of {}",
            known()
        );
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == name)
            .with_context(|| format!("agent.name: no agent {name:?} (known: {})", known()))
    }

    /// Its name, which is also its entry in the session's registry.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Opencode => "opencode",
            Self::Vibe => "vibe",
            Self::Fake => "fake",
        }
    }

    pub const fn needs_inference(self) -> bool {
        !matches!(self, Self::Fake)
    }

    /// Where the agent sends its model requests, of the two addresses
    /// ENDPOINT has: none for an agent that makes none.
    pub fn api_url(self, endpoint: &Endpoint) -> Option<&str> {
        match self {
            Self::Claude => Some(&endpoint.anthropic_url),
            Self::Opencode => Some(&endpoint.openai_url),
            Self::Vibe => Some(&endpoint.url),
            Self::Fake => None,
        }
    }

    /// The one file of the agent's that holds the run token, under the
    /// sandbox user's home.
    pub const fn token_file(self) -> Option<&'static str> {
        match self {
            Self::Claude => Some(CLAUDE_ENV_FILE),
            Self::Opencode => Some(OPENCODE_CONFIG_FILE),
            Self::Vibe => Some(VIBE_CONFIG_FILE),
            Self::Fake => None,
        }
    }

    /// The target repository's instructions for agents that the agent
    /// does not load itself, which the task then points it at: opencode
    /// none (the launcher turns its project configuration off, which
    /// would add providers and plugins), Claude Code only `CLAUDE.md`.
    pub const fn unread_instructions(self) -> &'static [&'static str] {
        match self {
            Self::Claude => &["AGENTS.md"],
            Self::Opencode => &["AGENTS.md", "CLAUDE.md"],
            Self::Vibe => &["AGENTS.md", "CLAUDE.md"],
            Self::Fake => &[],
        }
    }
}

/// One file of the sandbox user's, under its home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeFile {
    pub path: &'static str,
    /// What it holds; `None` removes one an earlier run or the machine's
    /// image left.
    pub content: Option<String>,
}

/// What configures an agent for one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Configuration {
    pub files: Vec<HomeFile>,
    /// The root-owned settings: a path and its content.
    pub managed: Option<(&'static str, String)>,
    /// The model the session asks for, where the configuration decides
    /// its full name.
    pub model: Option<String>,
}

/// What a configuration repository gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Source {
    /// Claude Code's instructions, or opencode's configuration.
    pub main: Option<String>,
    pub instructions: Option<String>,
    pub profile: Option<String>,
}

fn pretty(value: &Value) -> String {
    // A `Value` always serializes.
    let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
    text.push('\n');
    text
}

/// Vibe merges built-in providers by name. Replace both defaults so even
/// auxiliary requests cannot use a direct provider or a browser login. The
/// launcher admits only this fresh user configuration, never project files.
pub fn vibe(endpoint: &Endpoint, token: &Token, model: Option<&str>) -> Result<Configuration> {
    let model = model
        .filter(|m| !m.is_empty())
        .context("agent.model is not set: vibe needs a Mistral model name")?;
    let provider = |name: &str| {
        json!({
            "name": name, "api_base": format!("{}/mistral/v1", endpoint.url),
            "api_style": "openai", "backend": "generic", "api_key_env_var": "",
            "browser_auth_base_url": "", "browser_auth_api_base_url": "",
            "extra_headers": {"Authorization": format!("Bearer {}", token.expose())},
        })
    };
    let value = json!({
        "active_model": VIBE_MODEL_ALIAS,
        "providers": [provider("mistral"), provider("llamacpp")],
        // Model definitions deep-merge too. Do not inherit Medium 3.5's
        // image capability or 256k window for an arbitrary broker model.
        "models": [{
            "name": model, "alias": VIBE_MODEL_ALIAS, "provider": "mistral",
            "display_name": model, "temperature": 0.2,
            "thinking": "off", "thinking_levels": ["off"], "supports_images": false,
            "max_context_length": 32768, "auto_compact_threshold": 24576,
            "input_price": 0.0, "output_price": 0.0, "cached_input_price": 0.0,
        }],
        "default_agent": "ask",
        "enable_telemetry": false, "enable_update_checks": false, "enable_auto_update": false,
        "enable_connectors": false, "enable_system_trust_store": true,
        "experiments": {"enable": false},
        "session_logging": {"enabled": false, "generate_titles": false},
        "utility_models": {"title": VIBE_MODEL_ALIAS, "smart_approve": VIBE_MODEL_ALIAS},
    });
    Ok(Configuration {
        files: vec![HomeFile {
            path: VIBE_CONFIG_FILE,
            content: Some(toml::to_string(&value)?),
        }],
        managed: None,
        model: Some(VIBE_MODEL_ALIAS.to_owned()),
    })
}

/// The environment the launcher gives Claude Code: the proxy, and the
/// run token.
///
/// A proxy with the run API takes the token in a header of its own, with
/// a placeholder as the credential it then replaces by its own. A proxy
/// used with a given token takes that token as the credential.
pub fn claude_env(endpoint: &Endpoint, token: &Token) -> BTreeMap<&'static str, String> {
    let mut env = BTreeMap::from([("ANTHROPIC_BASE_URL", endpoint.anthropic_url.clone())]);
    if endpoint.mode.has_run_api() {
        env.insert("ANTHROPIC_AUTH_TOKEN", PLACEHOLDER_CREDENTIAL.to_owned());
        env.insert(
            "ANTHROPIC_CUSTOM_HEADERS",
            format!("{RUN_TOKEN_HEADER}: {}", token.expose()),
        );
    } else {
        env.insert("ANTHROPIC_AUTH_TOKEN", token.expose().to_owned());
    }
    env
}

/// Claude Code's managed settings: they win over the user's and the
/// project's, key by key. Readable by all, so never the token.
pub fn claude_managed_settings(endpoint: &Endpoint) -> Value {
    let mut env = Map::new();
    env.insert("ANTHROPIC_BASE_URL".into(), json!(endpoint.anthropic_url));
    if endpoint.mode.has_run_api() {
        env.insert("ANTHROPIC_AUTH_TOKEN".into(), json!(PLACEHOLDER_CREDENTIAL));
    }
    env.extend(
        PROVIDER_SWITCHES
            .iter()
            .map(|name| ((*name).into(), json!(""))),
    );
    env.extend(
        CLAUDE_QUIET
            .iter()
            .map(|(name, value)| ((*name).into(), json!(value))),
    );
    json!({
        "env": env,
        "allowManagedHooksOnly": true,
        "allowManagedPermissionRulesOnly": true,
        "permissions": {"defaultMode": "default", "disableBypassPermissionsMode": "disable"},
    })
}

/// Claude Code's configuration for the run.
pub fn claude(endpoint: &Endpoint, token: &Token, source: &Source) -> Configuration {
    let instructions = source.main.as_deref().unwrap_or(CLAUDE_INSTRUCTIONS);
    Configuration {
        files: vec![
            HomeFile {
                path: CLAUDE_ENV_FILE,
                content: Some(pretty(&json!({"env": claude_env(endpoint, token)}))),
            },
            HomeFile {
                path: CLAUDE_INSTRUCTIONS_FILE,
                content: Some(instructions.to_owned()),
            },
        ],
        managed: Some((
            MANAGED_SETTINGS_FILE,
            pretty(&claude_managed_settings(endpoint)),
        )),
        model: None,
    }
}

/// TEXT with the comments and trailing commas of JSONC removed, ready
/// for a JSON parser. It knows strings, so a `//` in a URL stays.
pub fn strip_jsonc(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let at = |i: usize| chars.get(i).copied();
    // The index after the comment that starts at I, if one does.
    let comment_end = |i: usize| match (at(i), at(i + 1)) {
        (Some('/'), Some('/')) => Some(
            (i..chars.len())
                .find(|&j| chars[j] == '\n')
                .unwrap_or(chars.len()),
        ),
        (Some('/'), Some('*')) => Some(
            (i + 2..chars.len())
                .find(|&j| chars[j] == '*' && at(j + 1) == Some('/'))
                .map_or(chars.len(), |j| j + 2),
        ),
        _ => None,
    };
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(c) = at(i) {
        if c == '"' {
            let mut j = i + 1;
            while let Some(s) = at(j) {
                if s == '"' {
                    break;
                }
                j += if s == '\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(chars.len());
            out.extend(&chars[i..end]);
            i = end;
        } else if let Some(end) = comment_end(i) {
            // A line comment's newline is kept, at `end`.
            out.push(' ');
            i = end;
        } else if c == ',' {
            // A trailing comma, if what follows it, comments aside,
            // closes the container.
            let mut j = i + 1;
            loop {
                while at(j).is_some_and(char::is_whitespace) {
                    j += 1;
                }
                match comment_end(j) {
                    Some(end) => j = end,
                    None => break,
                }
            }
            if !matches!(at(j), Some('}' | ']')) {
                out.push(c);
            }
            i += 1;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn jsonc_object(name: &str, text: &str) -> Result<Map<String, Value>> {
    let value: Value = serde_json::from_str(&strip_jsonc(text))
        .with_context(|| format!("the configuration repository's {name} is not valid JSONC"))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => bail!("the configuration repository's {name} must be a JSON object"),
    }
}

/// The one provider of an opencode configuration, checked to be the only
/// way inference can go: nothing the repository holds can send the work
/// elsewhere.
fn only_provider(config: &Map<String, Value>) -> Result<String> {
    let defined: Vec<&String> = config
        .get("provider")
        .and_then(Value::as_object)
        .map(|providers| providers.keys().collect())
        .unwrap_or_default();
    let enabled = config.get("enabled_providers");
    match defined.as_slice() {
        [name] if enabled == Some(&json!([name])) && !config.contains_key("disabled_providers") => {
            Ok((*name).clone())
        }
        _ => bail!(
            "the configuration repository's {SOURCE_OPENCODE_CONFIG} must define exactly one \
             provider and enable only it (\"enabled_providers\": [NAME], no \
             \"disabled_providers\"): its address and key become the inference proxy's"
        ),
    }
}

/// An opencode profile is merged over the configuration, so it must
/// leave the providers alone.
fn check_profile(text: &str) -> Result<()> {
    let profile = jsonc_object(SOURCE_OPENCODE_PROFILE, text)?;
    let set: Vec<&str> = OPENCODE_PROVIDER_KEYS
        .iter()
        .copied()
        .filter(|key| profile.contains_key(*key))
        .collect();
    ensure!(
        set.is_empty(),
        "the configuration repository's {SOURCE_OPENCODE_PROFILE} must not set {}: providers \
         come only from {SOURCE_OPENCODE_CONFIG}",
        set.join(", ")
    );
    Ok(())
}

/// The configuration written when the caller names no repository: the
/// proxy as the only provider, with the one model the run names.
fn builtin_opencode(model: Option<&str>) -> Result<(Map<String, Value>, String)> {
    let model = model
        .map(|model| {
            model
                .strip_prefix(BUILTIN_PROVIDER)
                .and_then(|rest| rest.strip_prefix('/'))
                .unwrap_or(model)
        })
        .filter(|model| !model.is_empty())
        .context(
            "agent.model is not set: opencode needs the model's name, or a configuration \
             repository (agent.config-repo) that defines its models",
        )?;
    let full = format!("{BUILTIN_PROVIDER}/{model}");
    let config = json!({
        "$schema": OPENCODE_SCHEMA,
        "enabled_providers": [BUILTIN_PROVIDER],
        "model": full,
        "autoupdate": false,
        "provider": {BUILTIN_PROVIDER: {
            "npm": BUILTIN_PROVIDER_PACKAGE,
            "models": {model: {}},
        }},
    });
    match config {
        Value::Object(map) => Ok((map, full)),
        _ => bail!("the built-in opencode configuration is not an object"),
    }
}

/// opencode's configuration for the run: the caller's or the built-in
/// one, with the proxy's address, the token as its key, and sharing off,
/// whatever the file says.
pub fn opencode(
    endpoint: &Endpoint,
    token: &Token,
    model: Option<&str>,
    source: &Source,
) -> Result<Configuration> {
    let (mut config, model) = match &source.main {
        Some(text) => (
            jsonc_object(SOURCE_OPENCODE_CONFIG, text)?,
            model.map(str::to_owned),
        ),
        None => {
            let (config, model) = builtin_opencode(model)?;
            (config, Some(model))
        }
    };
    let name = only_provider(&config)?;
    if let Some(profile) = &source.profile {
        check_profile(profile)?;
    }
    let options = config
        .get_mut("provider")
        .and_then(|providers| providers.get_mut(&name))
        .and_then(Value::as_object_mut)
        .with_context(|| format!("the provider {name:?} must be a JSON object"))?
        .entry("options")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .with_context(|| format!("the options of the provider {name:?} must be a JSON object"))?;
    options.insert("baseURL".into(), json!(endpoint.openai_url));
    options.insert("apiKey".into(), json!(token.expose()));
    config.insert("share".into(), json!("disabled"));
    let file = |path, content: Option<&String>| HomeFile {
        path,
        content: content.cloned(),
    };
    Ok(Configuration {
        files: vec![
            file(OPENCODE_CONFIG_FILE, Some(&pretty(&Value::Object(config)))),
            file(OPENCODE_INSTRUCTIONS_FILE, source.instructions.as_ref()),
            file(OPENCODE_PROFILE_FILE, source.profile.as_ref()),
        ],
        managed: None,
        model,
    })
}

/// The directory of a configuration repository the files are in, as
/// `[agent] config-path` names it: inside the repository.
fn source_dir(path: Option<&Path>) -> Result<&Path> {
    let path = path.unwrap_or(Path::new(""));
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::Normal(_))),
        "agent.config-path: {} is not a path inside the repository",
        path.display()
    );
    Ok(path)
}

/// What the `[agent]` table says of a configuration repository, checked.
fn source_request(agent: &config::Agent) -> Result<Option<(&str, Option<&str>, &Path)>> {
    let Some(url) = agent.config_repo.as_deref() else {
        ensure!(
            agent.config_ref.is_none() && agent.config_path.is_none(),
            "agent.config-ref and agent.config-path mean nothing without agent.config-repo"
        );
        return Ok(None);
    };
    super::clone::check_url(url).context("agent.config-repo")?;
    let branch = agent.config_ref.as_deref();
    branch
        .map(super::clone::check_ref)
        .transpose()
        .context("agent.config-ref")?;
    Ok(Some((
        url,
        branch,
        source_dir(agent.config_path.as_deref())?,
    )))
}

/// What can be said of the `[agent]` table before anything is fetched or
/// registered.
pub fn check(kind: Kind, agent: &config::Agent) -> Result<()> {
    match (kind, source_request(agent)?) {
        (Kind::Vibe, Some(_)) => bail!("agent.config-repo is not supported for vibe"),
        (Kind::Vibe, None) => {
            ensure!(
                agent.model.as_deref().is_some_and(|m| !m.is_empty()),
                "agent.model is not set: vibe needs a Mistral model name"
            );
            Ok(())
        }
        (Kind::Fake, Some(_)) => {
            bail!("agent.config-repo is set, and the fake agent has no configuration")
        }
        (Kind::Opencode, None) => builtin_opencode(agent.model.as_deref()).map(drop),
        _ => Ok(()),
    }
}

/// Clones the caller's configuration repository as the sandbox user and
/// reads from it the files KIND takes, as that user.
pub fn fetch_source(sandbox: &Sandbox, agent: &config::Agent, kind: Kind) -> Result<Source> {
    let Some((url, branch, path)) = source_request(agent)? else {
        return Ok(Source::default());
    };
    let checkout = sandbox.home.join(CONFIG_CHECKOUT);
    let checkout_text = utf8(&checkout)?;
    sandbox.checked(&["rm", "-rf", "--", checkout_text], b"", MAX_COMMAND_OUTPUT)?;
    git_clone(sandbox, url, branch, "1", checkout_text)?;
    let read = |name: &str| -> Result<Option<String>> {
        let file = checkout.join(path).join(name);
        let out = sandbox.run(
            &["sh", "-c", READ_SCRIPT, "sh", utf8(&file)?, checkout_text],
            b"",
            MAX_SOURCE_BYTES,
        )?;
        if out.status.code() == Some(ABSENT) {
            return Ok(None);
        }
        ensure!(
            out.success(),
            "{name} of the configuration repository is not a regular file inside it ({})",
            out.error()
        );
        String::from_utf8(out.stdout)
            .map(Some)
            .with_context(|| format!("{name} of the configuration repository is not UTF-8"))
    };
    let need = |name: &str| -> Result<Option<String>> {
        read(name)?.map(Some).with_context(|| {
            format!(
                "the configuration repository {url} has no {}",
                path.join(name).display()
            )
        })
    };
    let source = match kind {
        Kind::Claude => Source {
            main: need(SOURCE_CLAUDE_INSTRUCTIONS)?,
            ..Source::default()
        },
        _ => Source {
            main: need(SOURCE_OPENCODE_CONFIG)?,
            instructions: read(SOURCE_OPENCODE_INSTRUCTIONS)?,
            profile: read(SOURCE_OPENCODE_PROFILE)?,
        },
    };
    eprintln!("Agent configuration from {url}");
    Ok(source)
}

/// The run's configuration of KIND.
pub fn generate(
    kind: Kind,
    endpoint: Option<&Endpoint>,
    token: Option<&Token>,
    model: Option<&str>,
    source: &Source,
) -> Result<Configuration> {
    let inference = || {
        endpoint.zip(token).with_context(|| {
            format!(
                "the agent {} needs inference: set [inference] url and register (workflow inputs inference-url and inference-register)",
                kind.as_str()
            )
        })
    };
    Ok(match kind {
        Kind::Claude => {
            let (endpoint, token) = inference()?;
            Configuration {
                model: model.map(str::to_owned),
                ..claude(endpoint, token, source)
            }
        }
        Kind::Opencode => {
            let (endpoint, token) = inference()?;
            opencode(endpoint, token, model, source)?
        }
        Kind::Vibe => {
            ensure!(
                *source == Source::default(),
                "vibe does not accept configuration repositories"
            );
            let (endpoint, token) = inference()?;
            vibe(endpoint, token, model)?
        }
        Kind::Fake => Configuration::default(),
    })
}

/// The file that holds TOKEN, the run's read-only GitHub token, or that
/// removes an earlier run's where this one has none.
///
/// The token is the workflow's to make read-only (docs/workflow.md,
/// "GitHub reads from the agent"); this only keeps it to one line.
pub fn github_token(token: Option<&str>) -> Result<HomeFile> {
    let content = token
        .filter(|token| !token.is_empty())
        .map(|token| {
            // Never the value: it is a credential.
            ensure!(
                token.bytes().all(|b| b.is_ascii_graphic()),
                "{GITHUB_TOKEN_VAR} holds something other than a token"
            );
            Ok(format!("{token}\n"))
        })
        .transpose()?;
    Ok(HomeFile {
        path: GITHUB_TOKEN_FILE,
        content,
    })
}

/// Writes CONFIGURATION's files of the sandbox user's, as that user,
/// with their content on standard input and never on a command line.
/// The managed settings are root's and `sandbox setup` wrote them from
/// the same configuration ([`managed_settings`]): `run` has no root to
/// write with, and only checks that they are what this run expects.
pub fn install(sandbox: &Sandbox, configuration: &Configuration) -> Result<()> {
    for file in &configuration.files {
        let (script, input) = match &file.content {
            Some(content) => (WRITE_SCRIPT, content.as_bytes()),
            None => (REMOVE_SCRIPT, &b""[..]),
        };
        sandbox
            .checked(
                &["sh", "-c", script, "sh", file.path],
                input,
                MAX_COMMAND_OUTPUT,
            )
            .with_context(|| format!("writing {}'s {}", sandbox.user, file.path))?;
    }
    if let Some((path, content)) = &configuration.managed {
        let found = std::fs::read_to_string(path)
            .with_context(|| format!("reading {path}, which `sandbox setup` writes"))?;
        ensure!(
            found == *content,
            "{path} is not what this run's configuration calls for: `sandbox setup` writes it"
        );
    }
    Ok(())
}

/// The managed settings of the agent KIND behind ENDPOINT, if it has
/// any: a root-owned file, readable by all, with no secret in it. Written
/// by `sandbox setup`, as root, from the same configuration `run` reads.
pub fn managed_settings(kind: Kind, endpoint: Option<&Endpoint>) -> Option<(&'static str, String)> {
    match (kind, endpoint) {
        (Kind::Claude, Some(endpoint)) => Some((
            MANAGED_SETTINGS_FILE,
            pretty(&claude_managed_settings(endpoint)),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    use std::io::Write;
    use std::process::Stdio;

    use super::*;
    use crate::run::inference::Mode;

    const TOKEN: &str =
        "praxis-run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PROVIDER: &str = r#"{"name": "p", "options": {"baseURL": "http://local", "apiKey": "unused", "timeout": 5}, "models": {"m": {}}}"#;

    fn endpoint(mode: Mode) -> Endpoint {
        Endpoint {
            url: "http://100.64.0.1:18080".into(),
            mode,
            anthropic_url: "http://100.64.0.1:18080/anthropic".into(),
            openai_url: "http://100.64.0.1:18080/v1".into(),
        }
    }

    fn token() -> Token {
        Token::new(TOKEN).unwrap()
    }

    fn file<'a>(configuration: &'a Configuration, path: &str) -> Option<&'a str> {
        let file = configuration.files.iter().find(|file| file.path == path);
        file.unwrap_or_else(|| panic!("no {path}"))
            .content
            .as_deref()
    }

    fn json_file(configuration: &Configuration, path: &str) -> Value {
        serde_json::from_str(file(configuration, path).unwrap()).unwrap()
    }

    fn opencode_source(extra: &str) -> Source {
        Source {
            main: Some(format!(
                r#"{{"enabled_providers": ["praxis"], "provider": {{"praxis": {PROVIDER}}}{extra}}}"#
            )),
            ..Source::default()
        }
    }

    /// Claude Code starts with the proxy and the run token and no other
    /// provider setting, and the token is in one file.
    #[test]
    fn claude_gets_the_proxy_and_the_token_in_one_file() {
        let got = claude(&endpoint(Mode::Plain), &token(), &Source::default());
        assert_eq!(
            json_file(&got, CLAUDE_ENV_FILE),
            json!({"env": {
                "ANTHROPIC_BASE_URL": "http://100.64.0.1:18080/anthropic",
                "ANTHROPIC_AUTH_TOKEN": "praxis-substitute:anthropic",
                "ANTHROPIC_CUSTOM_HEADERS": format!("x-run-token: {TOKEN}"),
            }})
        );
        assert_eq!(Kind::Claude.token_file(), Some(CLAUDE_ENV_FILE));
        let (path, managed) = got.managed.as_ref().unwrap();
        assert_eq!(*path, "/etc/claude-code/managed-settings.json");
        assert_eq!(
            serde_json::from_str::<Value>(managed).unwrap(),
            json!({
                "env": {
                    "ANTHROPIC_BASE_URL": "http://100.64.0.1:18080/anthropic",
                    "ANTHROPIC_AUTH_TOKEN": "praxis-substitute:anthropic",
                    "CLAUDE_CODE_USE_BEDROCK": "",
                    "CLAUDE_CODE_USE_VERTEX": "",
                    "CLAUDE_CODE_USE_FOUNDRY": "",
                    "DISABLE_AUTOUPDATER": "1",
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                },
                "allowManagedHooksOnly": true,
                "allowManagedPermissionRulesOnly": true,
                "permissions": {"defaultMode": "default", "disableBypassPermissionsMode": "disable"},
            })
        );
        let holders: Vec<_> = got
            .files
            .iter()
            .filter(|file| file.content.as_deref().is_some_and(|c| c.contains(TOKEN)))
            .map(|file| file.path)
            .collect();
        assert_eq!(holders, [CLAUDE_ENV_FILE]);
        assert!(!managed.contains(TOKEN));
        let instructions = file(&got, CLAUDE_INSTRUCTIONS_FILE).unwrap();
        assert!(instructions.contains("unattended run"), "{instructions}");
    }

    /// A given token is the credential itself, and is still never in the
    /// settings every user can read.
    #[test]
    fn claude_with_a_given_token() {
        let mode = Mode::TokenFile {
            path: "/run/token".into(),
        };
        let source = Source {
            main: Some("Be brief.\n".into()),
            ..Source::default()
        };
        let got = claude(&endpoint(mode), &token(), &source);
        assert_eq!(
            json_file(&got, CLAUDE_ENV_FILE),
            json!({"env": {
                "ANTHROPIC_BASE_URL": "http://100.64.0.1:18080/anthropic",
                "ANTHROPIC_AUTH_TOKEN": TOKEN,
            }})
        );
        let managed = &got.managed.as_ref().unwrap().1;
        assert!(!managed.contains(TOKEN) && !managed.contains("ANTHROPIC_AUTH_TOKEN"));
        assert_eq!(file(&got, CLAUDE_INSTRUCTIONS_FILE), Some("Be brief.\n"));
    }

    #[test]
    fn jsonc() {
        let cases = [
            (
                "{\"a\": 1, // note\n \"b\": \"http://x\"}",
                json!({"a": 1, "b": "http://x"}),
            ),
            ("{/* c */ \"a\": [1, 2,],}", json!({"a": [1, 2]})),
            (
                "{\"a\": \"x // not a comment\"}",
                json!({"a": "x // not a comment"}),
            ),
            (
                "{\"a\": \"x,}\", \"b\": [1,\n // c\n ],}",
                json!({"a": "x,}", "b": [1]}),
            ),
            ("{\"a\": \"q\\\"//\", /* é */ \"b\": 2 /* open", json!(null)),
            ("{\"a\": 1, /* x */ // y\n}", json!({"a": 1})),
        ];
        for (text, want) in cases {
            let got = serde_json::from_str::<Value>(&strip_jsonc(text)).unwrap_or(Value::Null);
            assert_eq!(got, want, "{text}");
        }
    }

    /// opencode starts with one provider, the proxy, whatever the
    /// caller's file said its address and key were.
    #[test]
    fn opencode_gets_the_proxy_as_its_only_provider() {
        let source = Source {
            instructions: Some("# Agents\n".into()),
            profile: Some("{ // jsonc\n \"default_agent\": \"build\", }".into()),
            ..opencode_source(r#", "share": "auto", "model": "praxis/m""#)
        };
        let got = opencode(&endpoint(Mode::Plain), &token(), Some("praxis/m"), &source).unwrap();
        assert_eq!(
            json_file(&got, OPENCODE_CONFIG_FILE),
            json!({
                "enabled_providers": ["praxis"],
                "model": "praxis/m",
                "share": "disabled",
                "provider": {"praxis": {
                    "name": "p",
                    "options": {"baseURL": "http://100.64.0.1:18080/v1", "apiKey": TOKEN, "timeout": 5},
                    "models": {"m": {}},
                }},
            })
        );
        assert_eq!(got.model.as_deref(), Some("praxis/m"));
        assert_eq!(got.managed, None);
        assert_eq!(file(&got, OPENCODE_INSTRUCTIONS_FILE), Some("# Agents\n"));
        assert!(
            file(&got, OPENCODE_PROFILE_FILE)
                .unwrap()
                .contains("default_agent")
        );
        assert_eq!(Kind::Opencode.token_file(), Some(OPENCODE_CONFIG_FILE));
        // Files the repository does not have are removed, not left.
        let got = opencode(&endpoint(Mode::Plain), &token(), None, &opencode_source("")).unwrap();
        assert_eq!(file(&got, OPENCODE_INSTRUCTIONS_FILE), None);
        assert_eq!(file(&got, OPENCODE_PROFILE_FILE), None);
        assert_eq!(got.model, None);
    }

    #[test]
    fn opencode_without_a_repository() {
        for model in ["gpt-x", "inference/gpt-x"] {
            let got = opencode(
                &endpoint(Mode::Plain),
                &token(),
                Some(model),
                &Source::default(),
            );
            let got = got.unwrap();
            assert_eq!(
                json_file(&got, OPENCODE_CONFIG_FILE),
                json!({
                    "$schema": "https://opencode.ai/config.json",
                    "enabled_providers": ["inference"],
                    "model": "inference/gpt-x",
                    "autoupdate": false,
                    "share": "disabled",
                    "provider": {"inference": {
                        "npm": "@ai-sdk/openai",
                        "options": {"baseURL": "http://100.64.0.1:18080/v1", "apiKey": TOKEN},
                        "models": {"gpt-x": {}},
                    }},
                })
            );
            assert_eq!(got.model.as_deref(), Some("inference/gpt-x"));
        }
        let err = opencode(&endpoint(Mode::Plain), &token(), None, &Source::default());
        assert!(format!("{:#}", err.unwrap_err()).contains("agent.model is not set"));
    }

    /// Nothing a configuration repository holds may send inference
    /// anywhere but the proxy.
    #[test]
    fn opencode_configurations_that_are_refused() {
        let main = |text: &str| Source {
            main: Some(text.to_owned()),
            ..Source::default()
        };
        let profile = |text: &str| Source {
            profile: Some(text.to_owned()),
            ..opencode_source("")
        };
        let cases = [
            (main("{"), "not valid JSONC"),
            (main("[]"), "must be a JSON object"),
            (
                main(&format!(r#"{{"provider": {{"praxis": {PROVIDER}}}}}"#)),
                "exactly one provider",
            ),
            (
                opencode_source(r#", "enabled_providers": ["praxis", "openai"]"#),
                "exactly one provider",
            ),
            (
                opencode_source(r#", "disabled_providers": []"#),
                "exactly one provider",
            ),
            (
                main(&format!(
                    r#"{{"enabled_providers": ["praxis"], "provider": {{"praxis": {PROVIDER}, "evil": {{}}}}}}"#
                )),
                "exactly one provider",
            ),
            (
                main(r#"{"enabled_providers": ["p"], "provider": {"p": []}}"#),
                "must be a JSON object",
            ),
            (profile("{"), "not valid JSONC"),
            (profile("null"), "must be a JSON object"),
            (
                profile(r#"{"provider": {"other": {}}}"#),
                "must not set provider:",
            ),
            (
                profile(r#"{"enabled_providers": ["praxis", "other"], "disabled_providers": []}"#),
                "must not set enabled_providers, disabled_providers:",
            ),
        ];
        for (source, want) in cases {
            let err = opencode(&endpoint(Mode::Plain), &token(), None, &source).unwrap_err();
            assert!(format!("{err:#}").contains(want), "{source:?}: {err:#}");
        }
    }

    #[test]
    fn agents_and_what_they_need() {
        for (name, kind) in [
            ("claude", Kind::Claude),
            ("opencode", Kind::Opencode),
            ("vibe", Kind::Vibe),
            ("fake", Kind::Fake),
        ] {
            assert_eq!(Kind::parse(name).unwrap(), kind);
            // Every kind is an entry of the session's registry.
            crate::session::agents::builtin(kind.as_str()).unwrap();
        }
        for (name, want) in [
            ("", "agent.name is not set"),
            ("codex", "no agent \"codex\""),
        ] {
            let err = format!("{:#}", Kind::parse(name).unwrap_err());
            assert!(err.contains(want), "{err}");
        }
        // An agent with a model behind it does not start without a proxy.
        for kind in [Kind::Claude, Kind::Opencode, Kind::Vibe] {
            let err = generate(kind, None, None, Some("m"), &Source::default()).unwrap_err();
            assert!(format!("{err:#}").contains("needs inference"), "{err:#}");
        }
        let fake = generate(Kind::Fake, None, None, None, &Source::default()).unwrap();
        assert_eq!(fake, Configuration::default());
        let endpoint = endpoint(Mode::Plain);
        let claude = generate(
            Kind::Claude,
            Some(&endpoint),
            Some(&token()),
            Some("sonnet"),
            &Source::default(),
        );
        assert_eq!(claude.unwrap().model.as_deref(), Some("sonnet"));
    }

    #[test]
    fn vibe_configuration() {
        for mode in [
            Mode::Plain,
            Mode::TokenFile {
                path: "/run/token".into(),
            },
        ] {
            let got = vibe(&endpoint(mode), &token(), Some("devstral-small-latest")).unwrap();
            assert_eq!(got.files.len(), 1);
            assert_eq!(got.files[0].path, Kind::Vibe.token_file().unwrap());
            assert_eq!(got.model.as_deref(), Some(VIBE_MODEL_ALIAS));
            assert!(got.managed.is_none());
            let value: toml::Value =
                toml::from_str(got.files[0].content.as_ref().unwrap()).unwrap();
            for provider in value["providers"].as_array().unwrap() {
                assert_eq!(
                    provider["api_base"].as_str(),
                    Some("http://100.64.0.1:18080/mistral/v1")
                );
                assert_eq!(
                    provider["extra_headers"]["Authorization"].as_str(),
                    Some(format!("Bearer {TOKEN}").as_str())
                );
                assert_eq!(provider["backend"].as_str(), Some("generic"));
                assert_eq!(provider["browser_auth_base_url"].as_str(), Some(""));
            }
            assert_eq!(
                value["models"][0]["name"].as_str(),
                Some("devstral-small-latest")
            );
            assert_eq!(value["experiments"]["enable"].as_bool(), Some(false));
        }
        for model in [None, Some("")] {
            assert!(vibe(&endpoint(Mode::Plain), &token(), model).is_err());
        }
        let agent = config::Agent {
            model: Some("m".into()),
            config_repo: Some("https://github.com/o/r".into()),
            ..Default::default()
        };
        assert!(
            check(Kind::Vibe, &agent)
                .unwrap_err()
                .to_string()
                .contains("not supported")
        );
    }

    #[test]
    fn github_tokens() {
        let file = |content: Option<&str>| HomeFile {
            path: GITHUB_TOKEN_FILE,
            content: content.map(str::to_owned),
        };
        for (token, want) in [
            (None, Some(file(None))),
            (Some(""), Some(file(None))),
            (Some("ghs_abc"), Some(file(Some("ghs_abc\n")))),
            (Some("ghs_abc\nEVIL=1"), None),
            (Some("ghs abc"), None),
            (Some("ghs_ä"), None),
        ] {
            assert_eq!(github_token(token).ok(), want, "{token:?}");
        }
        let err = format!("{:#}", github_token(Some("secret value")).unwrap_err());
        assert!(!err.contains("secret"), "{err}");
    }

    #[test]
    fn configuration_repositories_that_are_refused() {
        let agent = |repo: Option<&str>, branch: Option<&str>, path: Option<&str>| config::Agent {
            config_repo: repo.map(str::to_owned),
            config_ref: branch.map(str::to_owned),
            config_path: path.map(Into::into),
            ..config::Agent::default()
        };
        const URL: &str = "https://github.com/o/dotfiles";
        let good = agent(Some(URL), Some("main"), Some("dotfiles/.config/opencode"));
        assert_eq!(
            source_request(&good).unwrap(),
            Some((URL, Some("main"), Path::new("dotfiles/.config/opencode")))
        );
        assert_eq!(source_request(&agent(None, None, None)).unwrap(), None);
        let cases = [
            (agent(None, Some("main"), None), "nothing without"),
            (agent(None, None, Some("x")), "nothing without"),
            (
                agent(Some("git@github.com:o/r"), None, None),
                "agent.config-repo",
            ),
            (agent(Some("o/r"), None, None), "agent.config-repo"),
            (agent(Some(URL), Some("--x"), None), "agent.config-ref"),
            (agent(Some(URL), None, Some("../x")), "agent.config-path"),
            (agent(Some(URL), None, Some("/etc")), "agent.config-path"),
        ];
        for (agent, want) in cases {
            let err = format!("{:#}", source_request(&agent).unwrap_err());
            assert!(err.contains(want), "{agent:?}: {err}");
        }
    }

    fn sh(script: &str, home: &Path, args: &[&str], input: &[u8]) -> std::process::Output {
        let mut child = Command::new("sh")
            .args(["-c", script, "sh"])
            .args(args)
            .env("HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    /// The scripts that write the sandbox user's files replace what was
    /// there, private to the user, and leave the home's own mode alone.
    #[test]
    fn files_are_written_private_and_replaced() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let secret = root.path().join("secret");
        std::fs::write(&secret, "the runner's").unwrap();
        for round in ["first", "second"] {
            for path in [CLAUDE_ENV_FILE, OPENCODE_CONFIG_FILE, VIBE_CONFIG_FILE] {
                let out = sh(WRITE_SCRIPT, &home, &[path], round.as_bytes());
                assert!(
                    out.status.success(),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                let file = home.join(path);
                assert_eq!(std::fs::read_to_string(&file).unwrap(), round);
                assert_eq!(mode(&file), 0o600);
                assert_eq!(mode(file.parent().unwrap()), 0o700);
            }
            assert_eq!(mode(&home), 0o755);
            // A link left where the file goes is replaced, not written
            // through.
            let file = home.join(CLAUDE_ENV_FILE);
            std::fs::remove_file(&file).unwrap();
            std::os::unix::fs::symlink(&secret, &file).unwrap();
        }
        assert!(
            sh(WRITE_SCRIPT, &home, &[CLAUDE_ENV_FILE], b"third")
                .status
                .success()
        );
        assert_eq!(std::fs::read_to_string(&secret).unwrap(), "the runner's");
        assert!(
            sh(REMOVE_SCRIPT, &home, &[CLAUDE_ENV_FILE], b"")
                .status
                .success()
        );
        assert!(!home.join(CLAUDE_ENV_FILE).exists());
        assert!(
            sh(REMOVE_SCRIPT, &home, &[CLAUDE_ENV_FILE], b"")
                .status
                .success()
        );
    }

    /// Only a regular file of the repository is read, reached by its
    /// name or through links that stay inside it: not a link that leaves
    /// it or leads nowhere, nor a file reached through a linked directory
    /// that leaves it; and a file that is not there is told from one
    /// that is odd.
    #[test]
    fn source_files_are_regular_files_of_the_checkout() {
        let root = tempfile::tempdir().unwrap();
        let checkout = root.path().join("checkout");
        let path = |name: &str| checkout.join(name);
        std::fs::create_dir_all(path("dir/sub")).unwrap();
        std::fs::create_dir(root.path().join("outside")).unwrap();
        std::fs::write(root.path().join("outside/file"), "the runner's").unwrap();
        std::fs::write(path("real"), "content").unwrap();
        std::fs::write(path("dir/sub/deep"), "deep").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", path("link")).unwrap();
        std::os::unix::fs::symlink("nowhere", path("dangling")).unwrap();
        std::os::unix::fs::symlink("../outside", path("way-out")).unwrap();
        std::os::unix::fs::symlink("dir/sub", path("way-in")).unwrap();
        std::os::unix::fs::symlink("../real", path("dir/own")).unwrap();
        std::os::unix::fs::symlink("own", path("dir/own-twice")).unwrap();
        std::os::unix::fs::symlink("../../outside/file", path("dir/others")).unwrap();
        std::os::unix::fs::symlink("sub", path("dir/to-dir")).unwrap();
        // A name that ends in a newline, which the shell drops, beside a
        // link out under the name that is left.
        std::fs::write(path("x\n"), "decoy").unwrap();
        std::os::unix::fs::symlink("../outside/file", path("x")).unwrap();
        std::os::unix::fs::symlink("x\n", path("newline")).unwrap();
        let read = |name: &str| {
            let args = [path(name), checkout.clone()].map(|p| p.to_str().unwrap().to_owned());
            let out = sh(READ_SCRIPT, root.path(), &[&args[0], &args[1]], b"");
            (out.status.code(), String::from_utf8(out.stdout).unwrap())
        };
        assert_eq!(read("real"), (Some(0), "content".into()));
        assert_eq!(read("dir/sub/deep"), (Some(0), "deep".into()));
        // A link between directories of the checkout is the checkout's.
        assert_eq!(read("way-in/deep"), (Some(0), "deep".into()));
        // So is a link to a file of the checkout, however many links on.
        assert_eq!(read("dir/own"), (Some(0), "content".into()));
        assert_eq!(read("dir/own-twice"), (Some(0), "content".into()));
        assert_eq!(read("missing"), (Some(ABSENT), String::new()));
        assert_eq!(read("no-dir/missing"), (Some(ABSENT), String::new()));
        for odd in [
            "link",
            "dangling",
            "dir",
            "way-out/file",
            "dir/others",
            "dir/to-dir",
            "newline",
        ] {
            let (code, text) = read(odd);
            assert!(
                code != Some(0) && code != Some(ABSENT) && text.is_empty(),
                "{odd}: {code:?}"
            );
        }
    }
}
