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
//! **Vibe** gets its user configuration, [`VIBE_CONFIG_FILE`], with both
//! built-in providers as the proxy and the token as their header.
//!
//! Each may take part of this from a public repository the caller
//! names (`[agent] config-repo`): opencode its configuration, which must
//! define exactly one provider (its address and key are replaced), an
//! `AGENTS.md` and an optional profile; Claude Code its instructions;
//! Vibe only the models and the active model of its `config.toml`.
//! With skills enabled, the root `skills/` tree is also installed.
//! Nothing else in that repository is used: opencode would also merge
//! other configuration files and run plugins, tools and commands found
//! beside its configuration, none of which the provider check covers.
//!
//! With `[agent] skills`, either also gets this binary's skills and
//! subagents ([`skills`]), the same text for both, so that a task can say
//! "use the implement skill" rather than spell the procedure out.
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
pub const VIBE_LOG_DIR: &str = ".config/agentic-job/vibe/logs";
/// The run's child agent's Vibe (`[child-agent]`, `acp-drive`): a home of
/// its own, so that its model and logs are not the main agent's.
pub const CHILD_VIBE_HOME: &str = ".config/agentic-job/child-vibe";
pub const CHILD_VIBE_CONFIG_FILE: &str = ".config/agentic-job/child-vibe/config.toml";
pub const CHILD_VIBE_LOG_DIR: &str = ".config/agentic-job/child-vibe/logs";
/// Where the fake agent's `demo` writes a log, as a real agent would.
pub const FAKE_LOG_DIR: &str = ".local/state/fake-agent/log";
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
const SOURCE_VIBE_CONFIG: &str = "config.toml";
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
/// The skills and subagents of `[agent] skills`, in the Agent Skills
/// format (`skills/` at the repository's root). The review skill is the
/// review caller's standing task, so that the two cannot drift apart.
const IMPLEMENT_SKILL: &str = include_str!("../../../../skills/implement/SKILL.md");
const REVIEW_SKILL: &str = concat!(
    "---\nname: review\ndescription: Review a pull request read-only and return one verdict \
     comment. Use when the task says to use the review skill.\n---\n\n",
    include_str!("../../../../workflow/review.md")
);
const DIFF_REVIEWER: &str = include_str!("../../../../skills/agents/diff-reviewer.md");
/// Where each agent reads them in the sandbox user's home, as their
/// sources say: Claude Code its user skills and subagents (the ACP
/// adapter loads the `user` setting source); opencode the `skills/` and
/// `agents/` of its global configuration directory, the only ones left
/// when the launcher turns off project configuration and external
/// skills. A target repository's own `.claude/agents/` would win over
/// Claude Code's user subagents of the same name: the reviewer's name is
/// one a repository is unlikely to use, and the review it makes is the
/// agent's own diligence, not the check after the run.
const CLAUDE_SKILLS: &[(&str, &str)] = &[
    (".claude/skills/implement/SKILL.md", IMPLEMENT_SKILL),
    (".claude/skills/review/SKILL.md", REVIEW_SKILL),
    (".claude/agents/diff-reviewer.md", DIFF_REVIEWER),
];
const OPENCODE_SKILLS: &[(&str, &str)] = &[
    (
        ".config/opencode/skills/implement/SKILL.md",
        IMPLEMENT_SKILL,
    ),
    (".config/opencode/skills/review/SKILL.md", REVIEW_SKILL),
    (".config/opencode/agents/diff-reviewer.md", DIFF_REVIEWER),
];
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

    /// The directory of the agent's own log files, under the sandbox
    /// user's home, which the run adds to the transcript (`agent_log`):
    /// Vibe's (`$VIBE_HOME/logs`, which its launch command turns on),
    /// opencode's default, and Claude Code's debug logs, which it writes
    /// only when debugging is turned on.
    pub const fn log_dir(self) -> &'static str {
        match self {
            Self::Claude => ".claude/debug",
            Self::Opencode => ".local/share/opencode/log",
            Self::Vibe => VIBE_LOG_DIR,
            Self::Fake => FAKE_LOG_DIR,
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
    /// Session config options the session sets after the model, by id.
    pub options: Vec<(&'static str, String)>,
}

/// What a configuration repository gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Source {
    /// Claude Code's instructions, or opencode's or Vibe's configuration.
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

/// The providers Vibe has built in, which it merges with the user's by
/// name: both are replaced by the proxy, so a model may name either.
const VIBE_PROVIDERS: &[&str] = &["mistral", "llamacpp"];
/// The most models taken from a configuration repository's `config.toml`.
const MAX_VIBE_MODELS: usize = 32;
/// The fields of a model in the pinned Vibe (`ModelConfig`), none of which
/// is an address or a key. Any other is refused, so that a later Vibe's
/// field that could be is not passed through unseen.
const VIBE_MODEL_KEYS: &[&str] = &[
    "name",
    "provider",
    "alias",
    "display_name",
    "temperature",
    "top_p",
    "max_output_tokens",
    "input_price",
    "output_price",
    "cached_input_price",
    "thinking",
    "thinking_levels",
    "supports_images",
    "max_context_length",
    "auto_compact_threshold",
];
/// Aliases a model of the file may not have: Vibe deep-merges a model of
/// its built-in's alias, inheriting its window and image support, and
/// renames one of a former built-in's, so neither would be what the file
/// says.
const VIBE_RESERVED_ALIASES: &[&str] = &[VIBE_BUILTIN_ALIAS, VIBE_RENAMED_ALIAS];
/// The alias of Vibe's sole built-in model, which its default and fallback
/// paths select.
const VIBE_BUILTIN_ALIAS: &str = "mistral-medium-3.5";
/// A former built-in's alias, which Vibe renames to the built-in's.
const VIBE_RENAMED_ALIAS: &str = "devstral-2";
/// The output cap per model request of a model that sets no
/// `max_output_tokens`: what Claude Code and opencode ask for by default,
/// or a quarter of the model's declared window if that is less, so that a
/// server that refuses a prompt and reply over the window takes requests
/// up to about compaction's threshold. Uncapped, one GLM response on the
/// broker ran to 249,691 tokens, and the next was cut off at the broker's
/// body limit (#559).
const VIBE_OUTPUT_TOKENS: u64 = 32_000;
/// The most a configuration repository's model may set. At roughly 200
/// bytes of chat-completions stream a token, this keeps one response
/// under the 16 MiB body limit of the broker's Mistral route (#559).
const MAX_VIBE_OUTPUT_TOKENS: u64 = 65_536;
/// The pinned Vibe's legacy ACP loop, which the launcher runs, does not
/// send a model's `max_output_tokens` (only its unified harness does): it
/// sends the session's `max_tokens`, which it takes as this undeclared
/// session config option (`vibe/acp/agent.py`, `set_config_option`).
const VIBE_MAX_TOKENS_OPTION: &str = "max_tokens";

/// The definition of the caller's MODEL under ALIAS.
fn vibe_model(model: &str, alias: &str) -> Value {
    // Model definitions deep-merge, by alias, with a built-in of the same
    // alias. Do not inherit Medium 3.5's image capability or 256k window.
    json!({
        "name": model, "alias": alias, "provider": "mistral",
        "display_name": model, "temperature": 0.2,
        "thinking": "off", "thinking_levels": ["off"], "supports_images": false,
        "max_context_length": 32768, "auto_compact_threshold": 24576,
        "input_price": 0.0, "output_price": 0.0, "cached_input_price": 0.0,
    })
}

/// The alias Vibe selects MODEL by, which defaults to its name.
fn vibe_alias(model: &Value) -> Option<&str> {
    model
        .get("alias")
        .or_else(|| model.get("name"))
        .and_then(Value::as_str)
}

/// The `[[models]]` and `active_model` of a configuration repository's
/// `config.toml`, and nothing else of it: its providers could send
/// inference, with the run token, elsewhere, and its other settings turn
/// on telemetry, connectors and tools. A model reaches a provider only by
/// name, and both names it may use are the proxy's.
fn vibe_source(text: &str) -> Result<(Vec<Value>, Option<String>)> {
    let mut file: Map<String, Value> = toml::from_str(text).with_context(|| {
        format!("the configuration repository's {SOURCE_VIBE_CONFIG} is not valid TOML")
    })?;
    let models = match file.remove("models") {
        None => Vec::new(),
        Some(Value::Array(models)) => models,
        Some(_) => bail!(
            "the configuration repository's {SOURCE_VIBE_CONFIG}: models must be an array of tables"
        ),
    };
    ensure!(
        models.len() <= MAX_VIBE_MODELS,
        "the configuration repository's {SOURCE_VIBE_CONFIG} declares {} models, more than {MAX_VIBE_MODELS}",
        models.len()
    );
    // Vibe keys models by alias, the last of one winning: a duplicate
    // would run another model than the one selected here.
    let mut aliases = std::collections::BTreeSet::new();
    for model in &models {
        let name = model
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let alias = vibe_alias(model).unwrap_or_default();
        ensure!(
            !name.is_empty() && !alias.is_empty(),
            "the configuration repository's {SOURCE_VIBE_CONFIG}: every model needs a name, and \
             an alias that is not empty"
        );
        let unknown: Vec<&str> = model
            .as_object()
            .into_iter()
            .flat_map(Map::keys)
            .map(String::as_str)
            .filter(|key| !VIBE_MODEL_KEYS.contains(key))
            .collect();
        ensure!(
            unknown.is_empty(),
            "the configuration repository's {SOURCE_VIBE_CONFIG}: the model {name:?} sets {}, \
             which this Vibe does not know",
            unknown.join(", ")
        );
        ensure!(
            !VIBE_RESERVED_ALIASES.contains(&alias),
            "the configuration repository's {SOURCE_VIBE_CONFIG}: the alias {alias:?} is Vibe's \
             own; give the model {name:?} another"
        );
        ensure!(
            aliases.insert(alias),
            "the configuration repository's {SOURCE_VIBE_CONFIG} declares the alias {alias:?} twice"
        );
        let provider = model.get("provider").and_then(Value::as_str);
        ensure!(
            provider.is_some_and(|p| VIBE_PROVIDERS.contains(&p)),
            "the configuration repository's {SOURCE_VIBE_CONFIG}: the model {name:?} must use the \
             provider \"mistral\" or \"llamacpp\", which are the inference proxy's"
        );
        if let Some(cap) = model.get("max_output_tokens") {
            ensure!(
                cap.as_u64()
                    .is_some_and(|cap| (1..=MAX_VIBE_OUTPUT_TOKENS).contains(&cap)),
                "the configuration repository's {SOURCE_VIBE_CONFIG}: the model {name:?} sets \
                 max_output_tokens to {cap}, not a number from 1 to {MAX_VIBE_OUTPUT_TOKENS}"
            );
        }
    }
    let active = match file.remove("active_model") {
        None => None,
        Some(Value::String(active)) if active.is_empty() => None,
        Some(Value::String(active)) => {
            ensure!(
                models.iter().any(|m| vibe_alias(m) == Some(&active)),
                "the configuration repository's {SOURCE_VIBE_CONFIG}: active_model {active:?} is \
                 not the alias of one of its models"
            );
            Some(active)
        }
        Some(_) => bail!(
            "the configuration repository's {SOURCE_VIBE_CONFIG}: active_model must be a string"
        ),
    };
    Ok((models, active))
}

/// Vibe merges built-in providers by name. Replace both defaults so even
/// auxiliary requests cannot use a direct provider or a browser login. The
/// launcher admits only this fresh user configuration, never project files.
///
/// The models are the caller's MODEL alone, or those of a configuration
/// repository's SOURCE: there, MODEL selects one of them by alias or name
/// over the file's `active_model`, and is added as without a repository if
/// the file has none of that name.
pub fn vibe(
    endpoint: &Endpoint,
    token: &Token,
    model: Option<&str>,
    source: Option<&str>,
) -> Result<Configuration> {
    let model = model.filter(|m| !m.is_empty());
    let (mut models, active) = source.map(vibe_source).transpose()?.unwrap_or_default();
    let named = model.and_then(|model| {
        models
            .iter()
            .find(|m| vibe_alias(m) == Some(model))
            .or_else(|| {
                models
                    .iter()
                    .find(|m| m.get("name").and_then(Value::as_str) == Some(model))
            })
            .and_then(vibe_alias)
            .map(str::to_owned)
    });
    let active = match (model, named) {
        (_, Some(alias)) => alias,
        (Some(model), None) => {
            ensure!(
                model != VIBE_RENAMED_ALIAS,
                "agent.model {model:?} is a name Vibe renames to its built-in model's"
            );
            // Selected under its own name: Vibe reports the active model's
            // alias over ACP and tells the model it is that, so under the
            // built-in's alias every run reported, and the model claimed to
            // be, Medium 3.5 (#562). It still replaces the built-in, which
            // Vibe's default and fallback paths would otherwise select.
            models.push(vibe_model(model, model));
            if model != VIBE_BUILTIN_ALIAS {
                models.push(vibe_model(model, VIBE_BUILTIN_ALIAS));
            }
            model.to_owned()
        }
        (None, None) => active.with_context(|| match source {
            Some(_) => format!(
                "agent.model is not set, and the configuration repository's {SOURCE_VIBE_CONFIG} \
                 has no active_model"
            ),
            None => "agent.model is not set: vibe needs a Mistral model name".to_owned(),
        })?,
    };
    // Every model gets a cap, a repository's own where it sets one, so the
    // file says what the session asks of the legacy loop for the active one.
    for model in &mut models {
        let window = model.get("max_context_length").and_then(Value::as_u64);
        let cap = window.map_or(VIBE_OUTPUT_TOKENS, |w| (w / 4).clamp(1, VIBE_OUTPUT_TOKENS));
        if let Some(model) = model.as_object_mut() {
            model.entry("max_output_tokens").or_insert(json!(cap));
        }
    }
    let cap = models
        .iter()
        .find(|m| vibe_alias(m) == Some(&active))
        .and_then(|m| m.get("max_output_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(VIBE_OUTPUT_TOKENS);
    let provider = |name: &str| {
        json!({
            "name": name, "api_base": format!("{}/mistral/v1", endpoint.url),
            "api_style": "openai", "backend": "generic", "api_key_env_var": "",
            "browser_auth_base_url": "", "browser_auth_api_base_url": "",
            "extra_headers": {"Authorization": format!("Bearer {}", token.expose())},
        })
    };
    let value = json!({
        "active_model": active,
        "providers": VIBE_PROVIDERS.iter().map(|name| provider(name)).collect::<Vec<_>>(),
        "models": models,
        "default_agent": "ask",
        "enable_telemetry": false, "enable_update_checks": false, "enable_auto_update": false,
        "enable_connectors": false, "enable_system_trust_store": true,
        "experiments": {"enable": false},
        "session_logging": {"enabled": false, "generate_titles": false},
        "utility_models": {"title": active, "smart_approve": active},
    });
    Ok(Configuration {
        files: vec![HomeFile {
            path: VIBE_CONFIG_FILE,
            content: Some(toml::to_string(&value)?),
        }],
        managed: None,
        model: Some(active),
        options: vec![(VIBE_MAX_TOKENS_OPTION, cap.to_string())],
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
        options: Vec::new(),
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
        options: Vec::new(),
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
    // The scripted agent cannot discover or execute skills.
    ensure!(
        !agent.skills || kind != Kind::Fake,
        "agent.skills is not supported for {}",
        kind.as_str()
    );
    match (kind, source_request(agent)?) {
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
    // These directories belong to the runner. Replacing the tree also removes
    // skills deleted at the source or left by an earlier opt-in run.
    if let Some(dir) = skill_dir(kind) {
        sandbox.checked(
            &["rm", "-rf", "--", utf8(&sandbox.home.join(dir))?],
            b"",
            MAX_COMMAND_OUTPUT,
        )?;
    }
    let Some((url, branch, path)) = source_request(agent)? else {
        return Ok(Source::default());
    };
    let checkout = sandbox.home.join(CONFIG_CHECKOUT);
    let checkout_text = utf8(&checkout)?;
    sandbox.checked(&["rm", "-rf", "--", checkout_text], b"", MAX_COMMAND_OUTPUT)?;
    git_clone(sandbox, url, branch, "1", checkout_text)?;
    if agent.skills {
        install_source_skills(sandbox, kind, checkout_text)?;
    }
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
        let content = read(name)?;
        if agent.skills {
            return Ok(content);
        }
        content.map(Some).with_context(|| {
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
        Kind::Vibe => Source {
            main: need(SOURCE_VIBE_CONFIG)?,
            ..Source::default()
        },
        Kind::Opencode | Kind::Fake => Source {
            main: need(SOURCE_OPENCODE_CONFIG)?,
            instructions: read(SOURCE_OPENCODE_INSTRUCTIONS)?,
            profile: read(SOURCE_OPENCODE_PROFILE)?,
        },
    };
    eprintln!("Agent configuration from {url}");
    Ok(source)
}

/// All destinations are runner-owned directories read by the respective
/// harness. Vibe 2.26.1 uses `$VIBE_HOME/skills` (harness_files/_paths.py).
fn skill_dir(kind: Kind) -> Option<&'static str> {
    match kind {
        Kind::Claude => Some(".claude/skills"),
        Kind::Opencode => Some(".config/opencode/skills"),
        Kind::Vibe => Some(".config/agentic-job/vibe/skills"),
        Kind::Fake => None,
    }
}

const MAX_SKILL_FILES: usize = 64;

/// Refuse traversal, links, submodules and executables before mapping repository
/// paths into the harness home. Read blobs, not checkout files, so a checkout
/// symlink cannot redirect a read. Both the listing and total contents are bounded.
fn skill_paths(listing: &[u8]) -> Result<Vec<&str>> {
    let listing = std::str::from_utf8(listing).context("skills tree is not UTF-8")?;
    let mut paths = Vec::new();
    for entry in listing.split('\0').filter(|s| !s.is_empty()) {
        let (metadata, path) = entry
            .split_once('\t')
            .context("invalid skills tree entry")?;
        ensure!(
            metadata.starts_with("100644 blob "),
            "skill must be a non-executable regular file: {path}"
        );
        let relative = path
            .strip_prefix("skills/")
            .context("invalid skill prefix")?;
        ensure!(
            relative.len() <= 256
                && relative.split('/').count() >= 2
                && relative.split('/').all(|part| !part.is_empty()
                    && !part.starts_with('.')
                    && !part.starts_with('-')
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))),
            "invalid skill path: {path}"
        );
        paths.push(path);
        ensure!(
            paths.len() <= MAX_SKILL_FILES,
            "too many skill files (maximum {MAX_SKILL_FILES})"
        );
    }
    Ok(paths)
}

fn install_source_skills(sandbox: &Sandbox, kind: Kind, checkout: &str) -> Result<()> {
    for (path, content) in source_skills(sandbox, kind, checkout)? {
        sandbox.checked(
            &["sh", "-c", WRITE_SCRIPT, "sh", &path],
            &content,
            MAX_COMMAND_OUTPUT,
        )?;
    }
    Ok(())
}

fn source_skills(
    runner: &impl super::enter::Runner,
    kind: Kind,
    checkout: &str,
) -> Result<Vec<(String, Vec<u8>)>> {
    let dir = skill_dir(kind).context("agent has no skills directory")?;
    let listing = runner.run(
        &[
            "git", "-C", checkout, "ls-tree", "-r", "-z", "HEAD", "--", "skills/",
        ],
        b"",
        MAX_SOURCE_BYTES,
    )?;
    ensure!(listing.success(), "listing skills: {}", listing.error());
    let paths = skill_paths(&listing.stdout)?;
    let mut files = Vec::new();
    let mut total = 0;
    for path in paths {
        let output = runner.run(
            &["git", "-C", checkout, "show", &format!("HEAD:{path}")],
            b"",
            MAX_SOURCE_BYTES,
        )?;
        ensure!(output.success(), "reading skill {path}: {}", output.error());
        let content = output.stdout;
        total += content.len();
        ensure!(
            total <= MAX_SOURCE_BYTES,
            "skills exceed {MAX_SOURCE_BYTES} bytes"
        );
        std::str::from_utf8(&content).context("skill file is not UTF-8")?;
        files.push((format!("{dir}/{}", &path["skills/".len()..]), content));
    }
    Ok(files)
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
            let (endpoint, token) = inference()?;
            vibe(endpoint, token, model, source.main.as_deref())?
        }
        Kind::Fake => Configuration::default(),
    })
}

/// The configuration of the run's child agent: Vibe, as the main agent
/// would be configured with MODEL, on the same proxy and run token, in a
/// home of its own. Without one (`None`), it removes the file an earlier
/// run left, so that `acp-drive` finds no child to start.
pub fn child(inference: Option<(&Endpoint, &Token, Option<&str>)>) -> Result<HomeFile> {
    let content = inference
        .map(|(endpoint, token, model)| -> Result<String> {
            let configuration = vibe(endpoint, token, model, None)
                .map_err(|err| anyhow::anyhow!("child-agent: {err:#}"))?;
            let file = configuration.files.into_iter().next();
            file.and_then(|file| file.content)
                .context("child-agent: no configuration")
        })
        .transpose()?;
    Ok(HomeFile {
        path: CHILD_VIBE_CONFIG_FILE,
        content,
    })
}

/// The skills and subagents of KIND, installed when ON and removed when
/// not, so that none an earlier run left is read. Vibe receives only the
/// configuration repository's skills, not these harness-specific procedures.
pub fn skills(kind: Kind, on: bool) -> Vec<HomeFile> {
    let files = match kind {
        Kind::Claude => CLAUDE_SKILLS,
        Kind::Opencode => OPENCODE_SKILLS,
        Kind::Vibe | Kind::Fake => &[],
    };
    files
        .iter()
        .map(|(path, text)| HomeFile {
            path,
            content: on.then(|| (*text).to_owned()),
        })
        .collect()
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
        let source = Source {
            main: Some(VIBE_SOURCE.into()),
            ..Source::default()
        };
        let vibe = generate(Kind::Vibe, Some(&endpoint), Some(&token()), None, &source);
        assert_eq!(vibe.unwrap().model.as_deref(), Some("glm"));
    }

    #[test]
    fn vibe_configuration() {
        for mode in [
            Mode::Plain,
            Mode::TokenFile {
                path: "/run/token".into(),
            },
        ] {
            let got = vibe(
                &endpoint(mode),
                &token(),
                Some("devstral-small-latest"),
                None,
            )
            .unwrap();
            assert_eq!(got.files.len(), 1);
            assert_eq!(got.files[0].path, Kind::Vibe.token_file().unwrap());
            assert_eq!(got.model.as_deref(), Some("devstral-small-latest"));
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
            // Vibe selects, and reports, the model by its alias (#562).
            assert_eq!(
                value["active_model"].as_str(),
                Some("devstral-small-latest")
            );
            for key in ["name", "alias"] {
                assert_eq!(
                    value["models"][0][key].as_str(),
                    Some("devstral-small-latest")
                );
            }
            // A quarter of the declared 32k window.
            assert_eq!(
                value["models"][0]["max_output_tokens"].as_integer(),
                Some(8192)
            );
            assert_eq!(got.options, [("max_tokens", "8192".to_owned())]);
            assert_eq!(value["experiments"]["enable"].as_bool(), Some(false));
        }
        for model in [None, Some(""), Some("devstral-2")] {
            assert!(vibe(&endpoint(Mode::Plain), &token(), model, None).is_err());
        }
        // The built-in's own name needs no second entry.
        let got = vibe(
            &endpoint(Mode::Plain),
            &token(),
            Some("mistral-medium-3.5"),
            None,
        )
        .unwrap();
        let value: toml::Value = toml::from_str(got.files[0].content.as_ref().unwrap()).unwrap();
        assert_eq!(value["models"].as_array().unwrap().len(), 1);
        // A repository may stand in for the model; without one, it is needed.
        for (repo, model, ok) in [
            (None, Some("m"), true),
            (None, None, false),
            (Some("https://github.com/o/r"), None, true),
            (Some("https://github.com/o/r"), Some("m"), true),
        ] {
            let agent = config::Agent {
                model: model.map(str::to_owned),
                config_repo: repo.map(str::to_owned),
                ..Default::default()
            };
            assert_eq!(check(Kind::Vibe, &agent).is_ok(), ok, "{repo:?} {model:?}");
        }
    }

    /// The child gets the main agent's Vibe configuration for its model,
    /// in its own file; a run without one removes an earlier run's.
    #[test]
    fn child_configuration() {
        let endpoint = endpoint(Mode::Plain);
        let got = child(Some((&endpoint, &token(), Some("zai-glm-5-3")))).unwrap();
        assert_eq!(got.path, CHILD_VIBE_CONFIG_FILE);
        let main = vibe(&endpoint, &token(), Some("zai-glm-5-3"), None).unwrap();
        assert_eq!(got.content, main.files[0].content);
        assert!(got.content.unwrap().contains(TOKEN));
        assert_eq!(child(None).unwrap().content, None);
        for model in [None, Some("devstral-2")] {
            let err = child(Some((&endpoint, &token(), model))).unwrap_err();
            assert!(err.to_string().starts_with("child-agent:"), "{err}");
        }
    }

    const VIBE_SOURCE: &str = r#"
active_model = "glm"
enable_telemetry = true
[[providers]]
name = "mistral"
api_base = "https://evil.example/v1"
api_key_env_var = "MISTRAL_API_KEY"
[[models]]
name = "zai-glm-5-3"
alias = "glm"
provider = "mistral"
max_context_length = 131072
max_output_tokens = 16384
[[models]]
name = "devstral-small-latest"
provider = "llamacpp"
"#;

    /// The models and the active model come from the repository, the
    /// providers and every other setting from the job; the caller's model
    /// wins over the file's choice.
    #[test]
    fn vibe_with_a_repository() {
        // The active model's cap is the file's, the default, or the job's
        // own model's.
        let cases = [
            (None, "glm", 2, 16384),
            (Some(""), "glm", 2, 16384),
            (Some("glm"), "glm", 2, 16384),
            (Some("zai-glm-5-3"), "glm", 2, 16384),
            (
                Some("devstral-small-latest"),
                "devstral-small-latest",
                2,
                VIBE_OUTPUT_TOKENS,
            ),
            (
                Some("mistral-large-latest"),
                "mistral-large-latest",
                4,
                8192,
            ),
        ];
        // An alias is matched before a name, as Vibe selects by alias.
        let crossed = "[[models]]\nname = \"a\"\nalias = \"b\"\nprovider = \"mistral\"\n\
                       [[models]]\nname = \"b\"\nalias = \"c\"\nprovider = \"mistral\"\n";
        let got = vibe(&endpoint(Mode::Plain), &token(), Some("b"), Some(crossed)).unwrap();
        assert_eq!(got.model.as_deref(), Some("b"));
        // A model without a cap gets the default, or a quarter of the
        // window it declares if that is less.
        for (extra, cap) in [
            ("", "32000"),
            ("max_context_length = 262144", "32000"),
            ("max_context_length = 16384", "4096"),
            ("max_context_length = 3", "1"),
            (
                "max_context_length = 16384\nmax_output_tokens = 9000",
                "9000",
            ),
        ] {
            let text = format!("[[models]]\nname = \"m\"\nprovider = \"mistral\"\n{extra}");
            let got = vibe(&endpoint(Mode::Plain), &token(), Some("m"), Some(&text)).unwrap();
            assert_eq!(got.options, [("max_tokens", cap.to_owned())], "{extra}");
        }
        for (model, active, count, cap) in cases {
            let got = vibe(&endpoint(Mode::Plain), &token(), model, Some(VIBE_SOURCE)).unwrap();
            assert_eq!(got.model.as_deref(), Some(active), "{model:?}");
            assert_eq!(got.options, [("max_tokens", cap.to_string())]);
            let value: toml::Value =
                toml::from_str(got.files[0].content.as_ref().unwrap()).unwrap();
            assert_eq!(value["active_model"].as_str(), Some(active));
            assert_eq!(value["utility_models"]["title"].as_str(), Some(active));
            let models = value["models"].as_array().unwrap();
            assert_eq!(models.len(), count, "{model:?}");
            assert_eq!(models[0]["max_context_length"].as_integer(), Some(131072));
            // Each model in the file is capped, not just the active one.
            assert_eq!(models[0]["max_output_tokens"].as_integer(), Some(16384));
            assert_eq!(models[1]["max_output_tokens"].as_integer(), Some(32000));
            // The caller's model, under its own name and the built-in's.
            if count == 4 {
                for (m, alias) in [
                    (&models[2], model),
                    (&models[3], Some("mistral-medium-3.5")),
                ] {
                    assert_eq!((m["name"].as_str(), m["alias"].as_str()), (model, alias));
                }
            }
            let providers = value["providers"].as_array().unwrap();
            assert_eq!(providers.len(), 2);
            for provider in providers {
                assert_eq!(
                    provider["api_base"].as_str(),
                    Some("http://100.64.0.1:18080/mistral/v1")
                );
                assert_eq!(provider["api_key_env_var"].as_str(), Some(""));
            }
            assert_eq!(value["enable_telemetry"].as_bool(), Some(false));
        }
    }

    #[test]
    fn vibe_repositories_that_are_refused() {
        let models = |n: usize| "[[models]]\nname = \"m\"\nprovider = \"mistral\"\n".repeat(n);
        let cases = [
            ("active_model = ", None, "not valid TOML"),
            ("models = 1", Some("m"), "array of tables"),
            ("models = [1]", Some("m"), "needs a name"),
            (
                "[[models]]\nprovider = \"mistral\"",
                Some("m"),
                "needs a name",
            ),
            (
                "[[models]]\nname = \"\"\nprovider = \"mistral\"",
                None,
                "needs a name",
            ),
            ("[[models]]\nname = \"m\"", None, "provider"),
            (
                "[[models]]\nname = \"m\"\nalias = \"\"\nprovider = \"mistral\"",
                None,
                "needs a name",
            ),
            (
                "[[models]]\nname = \"m\"\nprovider = \"mistral\"\napi_base = \"http://evil\"",
                Some("m"),
                "sets api_base, which",
            ),
            (
                "[[models]]\nname = \"m\"\nprovider = \"openai\"",
                None,
                "provider",
            ),
            (
                "[[models]]\nname = \"m\"\nprovider = \"mistral\"\nmax_output_tokens = 0",
                Some("m"),
                "max_output_tokens to 0, not",
            ),
            (
                "[[models]]\nname = \"m\"\nprovider = \"mistral\"\nmax_output_tokens = 65537",
                Some("m"),
                "max_output_tokens to 65537, not",
            ),
            (
                "[[models]]\nname = \"m\"\nprovider = \"mistral\"\nmax_output_tokens = -1",
                Some("m"),
                "max_output_tokens to -1, not",
            ),
            (
                "[[models]]\nname = \"m\"\nprovider = \"mistral\"\nmax_output_tokens = \"8192\"",
                Some("m"),
                "max_output_tokens to \"8192\", not",
            ),
            ("active_model = 1", None, "must be a string"),
            ("active_model = \"x\"\n", None, "not the alias"),
            (&models(0), None, "no active_model"),
            (&models(1), None, "no active_model"),
            (&models(MAX_VIBE_MODELS + 1), Some("m"), "more than"),
            (&models(2), Some("m"), "twice"),
            (
                "[[models]]\nname = \"m\"\nalias = \"mistral-medium-3.5\"\nprovider = \"mistral\"",
                Some("x"),
                "is Vibe's own",
            ),
            (
                "[[models]]\nname = \"mistral-medium-3.5\"\nprovider = \"mistral\"",
                None,
                "is Vibe's own",
            ),
            (
                "[[models]]\nname = \"mistral-vibe-cli-latest\"\nalias = \"devstral-2\"\nprovider = \"mistral\"",
                None,
                "is Vibe's own",
            ),
        ];
        for (text, model, want) in cases {
            let err = vibe(&endpoint(Mode::Plain), &token(), model, Some(text)).unwrap_err();
            assert!(format!("{err:#}").contains(want), "{text}: {err:#}");
        }
        let most: String = (0..MAX_VIBE_MODELS)
            .map(|i| format!("[[models]]\nname = \"m{i}\"\nprovider = \"mistral\"\n"))
            .collect();
        assert!(vibe(&endpoint(Mode::Plain), &token(), Some("m0"), Some(&most)).is_ok());
        let largest = format!(
            "[[models]]\nname = \"m\"\nprovider = \"mistral\"\nmax_output_tokens = {MAX_VIBE_OUTPUT_TOKENS}"
        );
        let got = vibe(&endpoint(Mode::Plain), &token(), Some("m"), Some(&largest)).unwrap();
        assert_eq!(got.options, [("max_tokens", "65536".to_owned())]);
    }

    /// The `name` and `description` of the frontmatter TEXT starts with,
    /// which both agents require, as a YAML parser reads them.
    fn frontmatter(text: &str) -> (String, String) {
        let yaml = text
            .strip_prefix("---\n")
            .and_then(|rest| rest.split_once("\n---\n"))
            .unwrap()
            .0;
        let doc = &yaml_rust2::YamlLoader::load_from_str(yaml).unwrap()[0];
        let field = |key: &str| doc[key].as_str().unwrap().to_owned();
        (field("name"), field("description"))
    }

    /// Each agent gets the same skills, each where that agent reads it
    /// and under the name it is called by; a run without them removes
    /// what an earlier one left.
    #[test]
    fn skills_go_where_each_agent_reads_them() {
        let want = [
            "skills/implement/SKILL.md",
            "skills/review/SKILL.md",
            "agents/diff-reviewer.md",
        ];
        for (kind, dir) in [
            (Kind::Claude, ".claude/"),
            (Kind::Opencode, ".config/opencode/"),
        ] {
            let files = skills(kind, true);
            let paths: Vec<_> = files.iter().map(|file| file.path).collect();
            assert_eq!(paths, want.map(|path| format!("{dir}{path}")), "{kind:?}");
            for file in &files {
                let text = file.content.as_deref().unwrap();
                let (name, description) = frontmatter(text);
                // A skill is called by its directory's name, a subagent by
                // its file's.
                let path = Path::new(file.path);
                let called = match path.file_name() {
                    Some(skill) if skill == "SKILL.md" => path.parent().unwrap().file_name(),
                    _ => path.file_stem(),
                };
                assert_eq!(called, Some(std::ffi::OsStr::new(&name)), "{}", file.path);
                assert!(description.contains("Use "), "{}", file.path);
            }
            let removed: Vec<_> = paths
                .iter()
                .map(|path| HomeFile {
                    path,
                    content: None,
                })
                .collect();
            assert_eq!(skills(kind, false), removed);
        }
        // The review skill is the review caller's standing task.
        let standing = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../workflow/review.md"),
        )
        .unwrap();
        assert!(REVIEW_SKILL.ends_with(&standing));
        // opencode makes it a subagent only by its mode; Claude Code
        // ignores the key.
        assert!(DIFF_REVIEWER.contains("\nmode: subagent\n"));
        assert!(IMPLEMENT_SKILL.contains("`diff-reviewer` subagent"));
        for kind in [Kind::Vibe, Kind::Fake] {
            assert_eq!(skills(kind, true), []);
        }
    }

    #[test]
    fn source_skill_paths_are_bounded_regular_files() {
        let entry = |mode: &str, path: &str| format!("{mode} blob abc\t{path}\0");
        assert_eq!(
            skill_paths(entry("100644", "skills/ast-explore/SKILL.md").as_bytes()).unwrap(),
            ["skills/ast-explore/SKILL.md"]
        );
        for (mode, path) in [
            ("120000", "skills/a/SKILL.md"),
            ("100755", "skills/a/script"),
            ("160000", "skills/a/submodule"),
            ("100644", "skills/../config"),
            ("100644", "skills/a/.hidden"),
            ("100644", "skills/a/-option"),
            ("100644", "skills/a/a\nb"),
            ("100644", "skills/a//b"),
            ("100644", "skills/SKILL.md"),
            ("100644", "config/a/SKILL.md"),
        ] {
            assert!(
                skill_paths(entry(mode, path).as_bytes()).is_err(),
                "{mode} {path}"
            );
        }
        for count in [MAX_SKILL_FILES, MAX_SKILL_FILES + 1] {
            let listing = (0..count)
                .map(|i| entry("100644", &format!("skills/a/file{i}")))
                .collect::<String>();
            assert_eq!(
                skill_paths(listing.as_bytes()).is_ok(),
                count == MAX_SKILL_FILES
            );
        }
        assert!(skill_paths(b"\xff").is_err());
        assert!(skill_paths(b"malformed\0").is_err());
    }

    #[test]
    fn source_skills_use_git_blobs_for_every_harness() {
        use super::super::enter::Unconfined;
        use std::process::Command;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .current_dir(root)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        git(&["init", "-q"]);
        std::fs::create_dir_all(root.join("skills/ast-explore")).unwrap();
        let content =
            "---\nname: ast-explore\ndescription: Explore code\n---\nUse the outline first.\n";
        std::fs::write(root.join("skills/ast-explore/SKILL.md"), content).unwrap();
        git(&["add", "."]);
        git(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ]);
        // A checkout mutation cannot redirect reads away from committed blobs.
        std::fs::remove_file(root.join("skills/ast-explore/SKILL.md")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("skills/ast-explore/SKILL.md"))
            .unwrap();
        for (kind, dir) in [
            (Kind::Claude, ".claude/skills"),
            (Kind::Opencode, ".config/opencode/skills"),
            (Kind::Vibe, ".config/agentic-job/vibe/skills"),
        ] {
            let files = source_skills(&Unconfined, kind, root.to_str().unwrap()).unwrap();
            assert_eq!(
                files,
                [(
                    format!("{dir}/ast-explore/SKILL.md"),
                    content.as_bytes().to_vec()
                )]
            );
        }
        // The aggregate, not just each individual read, has a size limit.
        std::fs::remove_file(root.join("skills/ast-explore/SKILL.md")).unwrap();
        std::fs::write(
            root.join("skills/ast-explore/SKILL.md"),
            vec![b'a'; MAX_SOURCE_BYTES],
        )
        .unwrap();
        std::fs::write(root.join("skills/ast-explore/extra.md"), "extra").unwrap();
        git(&["add", "."]);
        git(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "oversize",
        ]);
        assert!(
            source_skills(&Unconfined, Kind::Vibe, root.to_str().unwrap())
                .unwrap_err()
                .to_string()
                .contains("skills exceed")
        );
    }

    #[test]
    fn implement_review_is_bounded_and_delta_only() {
        let skill = IMPLEMENT_SKILL
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for rule in [
            "whole diff against the commit you started from",
            "Save the reviewed state",
            "Stop on no blockers",
            "Only if the first pass found a blocker",
            "only the delta since the first pass",
            "at most two passes",
            "report any remaining blockers",
            "list important findings and nits as follow-ups",
            "review job remains the merge gate",
        ] {
            assert!(skill.contains(rule), "missing review rule: {rule}");
        }
        let reviewer = DIFF_REVIEWER
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(reviewer.contains("Do not expand that delta to the whole diff"));
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
