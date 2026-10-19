//! `agentic-job config`: write a run's `--config` file from a caller's
//! file and from settings given one at a time.
//!
//! It is for a job that gets its settings as strings from someone else,
//! the inputs of a workflow for one. Such a string is only ever a value
//! here: it is never read as TOML, so whatever it holds (a quote, a
//! newline, a table header) it sets the one key it was given for and no
//! other. A job that pasted its inputs into a file could not say that.
//!
//! The result is parsed as `sandbox setup` and `run` will parse it, and
//! held to everything either checks of the file alone
//! ([`super::checked`]): a key that does not exist, a value of the wrong
//! type, a run with no timeout or cap, an agent with no inference proxy,
//! `github-oidc` with no audience. Each stops the job here, before a
//! machine is set up for it. With `--host` it is held only to what
//! `sandbox setup` checks: the file of a job that secures its host and
//! runs no agent names none, and no limits.
//!
//! `setup.repo-packages` in the caller's file is a package list per
//! target repository, `OWNER/NAME = [...]`, with `default` for any other:
//! the entry for `--repo` (or `default`) is added to `setup.packages` and
//! the table left out of what is written. It is the caller's choice of a
//! target's toolchain; nothing is read from the target's own contents.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use toml::{Table, Value};

use super::{Config, Register};
use crate::exit::Exit;
use crate::run::inference::with_address;
use crate::sandbox::network::Direct;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The configuration to start from (TOML); none is an empty one
    #[arg(long, value_name = "FILE")]
    pub from: Option<PathBuf>,
    /// Set a string, as TABLE.KEY=VALUE; an empty VALUE sets nothing
    #[arg(long, value_name = "KEY=VALUE", value_parser = Setting::parse, allow_hyphen_values = true)]
    pub string: Vec<Setting>,
    /// Set a whole number likewise
    #[arg(long, value_name = "KEY=VALUE", value_parser = Setting::parse, allow_hyphen_values = true)]
    pub integer: Vec<Setting>,
    /// Set a list of strings likewise, from words with spaces or newlines between them
    #[arg(long, value_name = "KEY=VALUE", value_parser = Setting::parse, allow_hyphen_values = true)]
    pub list: Vec<Setting>,
    /// Set `true` or `false` likewise
    #[arg(long, value_name = "KEY=VALUE", value_parser = Setting::parse, allow_hyphen_values = true)]
    pub boolean: Vec<Setting>,
    /// Check only what `sandbox setup` reads: for a job that runs no agent
    #[arg(long)]
    pub host: bool,
    /// Leave `setup.script` out: for the secure-host image, which would
    /// run it from the host's root as its second user, where an agent job
    /// with no second user runs it itself
    #[arg(long)]
    pub no_script: bool,
    /// The repository the run works on, OWNER/NAME: chooses its entry of
    /// `setup.repo-packages`
    #[arg(long, value_name = "OWNER/NAME")]
    pub repo: Option<String>,
    /// Replace the host of `inference.url`, a name, with this tailnet
    /// IPv4 address: for an agent job whose step on the tailnet resolved
    /// the name
    #[arg(long, value_name = "ADDRESS")]
    pub inference_address: Option<String>,
}

/// The key of `setup.repo-packages` for a repository that has none.
const DEFAULT_PACKAGES: &str = "default";

/// Whether NAME is `OWNER/NAME` in the characters GitHub allows.
fn is_repo(name: &str) -> bool {
    let part = |part: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    name.split_once('/')
        .is_some_and(|(owner, repo)| part(owner) && part(repo))
}

/// Takes `setup.repo-packages` out of TABLE and adds the list of REPO, or
/// else of `default`, to `setup.packages`. The names are checked with
/// the rest of `setup.packages` when the result is parsed.
fn repo_packages(table: &mut Table, repo: Option<&str>) -> Result<()> {
    if let Some(repo) = repo {
        ensure!(is_repo(repo), "--repo: {repo:?} is not OWNER/NAME");
    }
    let Some(setup) = table.get_mut("setup").and_then(Value::as_table_mut) else {
        return Ok(());
    };
    let Some(sets) = setup.remove("repo-packages") else {
        return Ok(());
    };
    let sets: BTreeMap<String, Vec<String>> = sets
        .try_into()
        .context("setup.repo-packages: expected OWNER/NAME = [package, ...]")?;
    let mut seen = std::collections::BTreeSet::new();
    for key in sets.keys() {
        ensure!(
            key == DEFAULT_PACKAGES || is_repo(key),
            "setup.repo-packages: {key:?} is neither OWNER/NAME nor {DEFAULT_PACKAGES}"
        );
        ensure!(
            seen.insert(key.to_ascii_lowercase()),
            "setup.repo-packages: {key:?} is named twice"
        );
    }
    // GitHub's names, and so the bounds, ignore case.
    let chosen = repo
        .and_then(|repo| {
            sets.iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(repo))
                .map(|(_, list)| list)
        })
        .or_else(|| sets.get(DEFAULT_PACKAGES));
    if let Some(chosen) = chosen {
        setup
            .entry("packages")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .context("setup.packages is not a list")?
            .extend(chosen.iter().cloned().map(Value::String));
    }
    Ok(())
}

/// One `KEY=VALUE` of the command line: the tables down to the key, and
/// the text to set it from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    path: Vec<String>,
    value: String,
}

impl Setting {
    /// Splits at the first `=`: everything after it is the value, more
    /// `=` included. The key is `TABLE.KEY`, of the letters, digits, `-`
    /// and `_` that every key of the configuration is made of.
    fn parse(text: &str) -> Result<Self> {
        let (key, value) = text
            .split_once('=')
            .with_context(|| format!("{text:?} is not KEY=VALUE"))?;
        let path: Vec<String> = key.split('.').map(str::to_owned).collect();
        let plain = |part: &String| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        };
        ensure!(
            path.len() >= 2 && path.iter().all(plain),
            "{key:?} is not TABLE.KEY"
        );
        Ok(Self {
            path,
            value: value.to_owned(),
        })
    }

    fn key(&self) -> String {
        self.path.join(".")
    }
}

/// What a setting's text is turned into.
#[derive(Debug, Clone, Copy)]
enum Kind {
    String,
    Integer,
    List,
    Boolean,
}

impl Kind {
    /// The value TEXT stands for, or none for a text that sets nothing:
    /// an input of a workflow that was left out arrives as an empty
    /// string, and must leave the caller's file as it is.
    fn value(self, setting: &Setting) -> Result<Option<Value>> {
        let text = &setting.value;
        Ok(match self {
            _ if text.trim().is_empty() => None,
            Self::String => Some(Value::String(text.clone())),
            Self::Integer => {
                let number: u32 = text.trim().parse().with_context(|| {
                    format!("{}: {text:?} is not a whole number", setting.key())
                })?;
                Some(Value::Integer(number.into()))
            }
            Self::List => Some(Value::Array(
                text.split_whitespace()
                    .map(|word| Value::String(word.to_owned()))
                    .collect(),
            )),
            // The two words a workflow's boolean input arrives as, and
            // nothing a reader would have to guess at.
            Self::Boolean => Some(Value::Boolean(match text.trim() {
                "true" => true,
                "false" => false,
                _ => bail!("{}: {text:?} is neither true nor false", setting.key()),
            })),
        })
    }
}

/// Puts VALUE at PATH of TABLE, in place of what is there, making the
/// tables on the way.
fn set(table: &mut Table, path: &[String], value: Value) -> Result<()> {
    let Some((key, tables)) = path.split_last() else {
        bail!("a setting with no key");
    };
    let mut at = table;
    for name in tables {
        at = at
            .entry(name)
            .or_insert_with(|| Value::Table(Table::new()))
            .as_table_mut()
            .with_context(|| format!("{name} is not a table"))?;
    }
    at.insert(key.clone(), value);
    Ok(())
}

/// `--inference-address`: the broker's URL with ADDRESS for its name
/// ([`with_address`]). Only under
/// `github-oidc`, the broker that admits a run by the job's identity, not
/// by a token or key that `url` alone would have to be trusted with; and
/// not with `anthropic-url` or `openai-url`, which would keep the name.
fn inference_address(table: &mut Table, address: &str) -> Result<()> {
    let inference = table
        .get_mut("inference")
        .and_then(Value::as_table_mut)
        .context("--inference-address: the configuration has no [inference]")?;
    let get = |key: &str| inference.get(key).and_then(Value::as_str);
    ensure!(
        get("register") == Some(Register::GithubOidc.as_str()),
        "--inference-address needs inference.register = \"github-oidc\", not {:?}",
        get("register").unwrap_or_default()
    );
    for key in ["anthropic-url", "openai-url"] {
        ensure!(
            !inference.contains_key(key),
            "--inference-address: inference.{key} is set, and would not be replaced"
        );
    }
    let url = get("url")
        .context("--inference-address: inference.url is not set")?
        .to_owned();
    inference.insert("url".into(), Value::String(with_address(&url, address)?));
    Ok(())
}

/// The configuration of ARGS as TOML, checked.
fn compose(args: &Args) -> Result<String> {
    let mut table = match &args.from {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?
        }
        None => Table::new(),
    };
    let settings = [
        (Kind::String, &args.string),
        (Kind::Integer, &args.integer),
        (Kind::List, &args.list),
        (Kind::Boolean, &args.boolean),
    ];
    for (kind, list) in settings {
        for setting in list {
            if let Some(value) = kind.value(setting)? {
                set(&mut table, &setting.path, value)
                    .with_context(|| format!("setting {}", setting.key()))?;
            }
        }
    }
    repo_packages(&mut table, args.repo.as_deref())?;
    // Before `egress.direct` is defaulted, which then opens the address.
    if let Some(address) = &args.inference_address {
        inference_address(&mut table, address)?;
    }
    if args.no_script
        && let Some(setup) = table.get_mut("setup").and_then(Value::as_table_mut)
    {
        setup.remove("script");
    }
    // Default only an absent key: an explicit list (even an empty one)
    // is the caller's network policy, not ours to expand.
    let direct_is_set = table
        .get("egress")
        .and_then(Value::as_table)
        .is_some_and(|egress| egress.contains_key("direct"));
    if !direct_is_set {
        let url = table
            .get("inference")
            .and_then(Value::as_table)
            // Under `api-key` only `run` reaches the provider, and under
            // `front` only `run` the broker; the agent reaches `run`'s
            // proxy on loopback.
            .filter(|inference| {
                inference.get("register").and_then(Value::as_str) != Some("api-key")
                    && inference.get("front").and_then(Value::as_bool) != Some(true)
            })
            .and_then(|inference| inference.get("url"))
            .and_then(Value::as_str)
            .filter(|url| Direct::parse(url).is_ok())
            .map(str::to_owned);
        if let Some(url) = url {
            set(
                &mut table,
                &["egress".into(), "direct".into()],
                Value::Array(vec![Value::String(url)]),
            )?;
        }
    }
    let text = toml::to_string(&table).context("writing the configuration")?;
    // As its readers will see it: parsed from the text that is printed.
    let config = Config::parse(&text)?;
    if args.host {
        config.check_host()?;
    } else {
        config.check()?;
    }
    Ok(text)
}

pub fn run(args: &Args) -> Result<Exit> {
    let text = compose(args)?;
    std::io::stdout()
        .write_all(text.as_bytes())
        .context("writing the configuration to standard output")?;
    Ok(Exit::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Register;

    fn settings(list: &[&str]) -> Vec<Setting> {
        list.iter()
            .map(|text| Setting::parse(text).unwrap_or_else(|err| panic!("{text:?}: {err:#}")))
            .collect()
    }

    fn args(from: Option<&str>, string: &[&str], integer: &[&str], list: &[&str]) -> Args {
        Args {
            from: from.map(PathBuf::from),
            string: settings(string),
            integer: settings(integer),
            list: settings(list),
            boolean: Vec::new(),
            host: false,
            no_script: false,
            repo: None,
            inference_address: None,
        }
    }

    /// The file of a job that secures its host and runs no agent.
    fn host_args(boolean: &[&str], list: &[&str]) -> Args {
        Args {
            boolean: settings(boolean),
            host: true,
            ..args(None, &[], &[], list)
        }
    }

    /// The least a run's configuration says: an agent, and limits.
    const RUN: &[&str] = &["agent.name=fake"];
    const LIMITS: &[&str] = &["limits.timeout-minutes=10", "limits.budget=100"];

    fn composed(args: &Args) -> Config {
        let text = compose(args).unwrap_or_else(|err| panic!("{args:?}: {err:#}"));
        Config::parse(&text).unwrap()
    }

    #[test]
    fn settings_fill_their_tables() {
        let config = composed(&args(
            None,
            &[
                "inference.url=http://100.64.0.1:18080",
                "inference.register=github-oidc",
                "inference.audience=proxy",
                "agent.name=fake",
                "sandbox.check.control-url=https://example.com/",
            ],
            &["limits.timeout-minutes= 75 ", "limits.budget=500"],
            &[
                "setup.packages=just  gcc-c++\njq",
                "egress.direct=http://100.64.0.1:18080",
            ],
        ));
        assert_eq!(config.egress.direct, ["http://100.64.0.1:18080"]);
        assert_eq!(config.inference.url, "http://100.64.0.1:18080");
        assert_eq!(config.inference.register, Some(Register::GithubOidc));
        assert_eq!(config.agent.name, "fake");
        assert_eq!(config.sandbox.check.control_url, "https://example.com/");
        assert_eq!(config.limits.timeout_minutes, 75);
        assert_eq!(config.limits.budget, 500);
        assert_eq!(config.setup.packages, ["just", "gcc-c++", "jq"]);
    }

    /// Only an address `egress.direct` takes is implied: the edges of
    /// the tailnet's range, and nothing outside it or by name.
    #[test]
    fn tailnet_inference_defaults_to_direct() {
        for (url, direct) in [
            ("http://100.64.0.0:18080/v1", true),
            ("https://100.127.255.255", true),
            ("https://proxy.example", false),
            ("http://100.63.255.255:18080", false),
            ("http://100.128.0.0:18080", false),
            ("http://127.0.0.1:18080", false),
            ("http://[fd7a:115c:a1e0::1]:18080", false),
        ] {
            let setting = format!("inference.url={url}");
            let config = composed(&args(
                None,
                &[RUN[0], &setting, "inference.register=plain"],
                LIMITS,
                &[],
            ));
            let expected: &[&str] = if direct { &[url] } else { &[] };
            assert_eq!(config.egress.direct, expected, "{url}");
        }
        // Under `api-key` the agent never reaches `url` itself.
        let config = composed(&args(
            None,
            &[
                RUN[0],
                "inference.url=https://100.64.0.1",
                "inference.register=api-key",
                "inference.provider=anthropic",
            ],
            LIMITS,
            &[],
        ));
        assert!(config.egress.direct.is_empty());
    }

    /// The agent job's `--inference-address` gives a named `github-oidc`
    /// broker its address, which `egress.direct` then opens; anything
    /// else is refused.
    #[test]
    fn an_inference_address_for_a_named_broker() {
        const OIDC: &[&str] = &[
            "agent.name=fake",
            "inference.url=http://broker:18080",
            "inference.register=github-oidc",
            "inference.audience=a",
        ];
        let with = |string: &[&str], address: &str| {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            // As the policy job wrote it.
            let policy = compose(&args(None, string, LIMITS, &[])).unwrap();
            file.write_all(policy.as_bytes()).unwrap();
            compose(&Args {
                inference_address: Some(address.to_owned()),
                ..args(file.path().to_str(), &[], &[], &[])
            })
        };
        let config = Config::parse(&with(OIDC, "100.100.1.2").unwrap()).unwrap();
        assert_eq!(config.inference.url, "http://100.100.1.2:18080");
        assert_eq!(config.egress.direct, ["http://100.100.1.2:18080"]);
        // The policy's own file, with no address yet, opens nothing.
        let policy = composed(&args(None, OIDC, LIMITS, &[]));
        assert!(policy.egress.direct.is_empty());

        let with_key = |key: &'static str| [OIDC, &[key]].concat();
        let cases = [
            (
                vec![
                    "agent.name=fake",
                    "inference.url=http://broker:18080",
                    "inference.register=plain",
                ],
                "100.64.0.1",
                "needs inference.register = \"github-oidc\", not \"plain\"",
            ),
            (
                vec![
                    "agent.name=fake",
                    "inference.url=http://100.64.0.1:18080",
                    "inference.register=github-oidc",
                    "inference.audience=a",
                ],
                "100.64.0.2",
                "gives an address, not a name",
            ),
            (OIDC.to_vec(), "192.0.2.1", "not a tailnet IPv4 address"),
            (
                with_key("inference.anthropic-url=http://broker:1"),
                "100.64.0.1",
                "inference.anthropic-url is set",
            ),
            (
                with_key("inference.openai-url=http://broker:1/v1"),
                "100.64.0.1",
                "inference.openai-url is set",
            ),
            (vec!["agent.name=fake"], "100.64.0.1", "has no [inference]"),
        ];
        for (string, address, want) in cases {
            let err = with(&string, address).expect_err(want);
            assert!(format!("{err:#}").contains(want), "{string:?}: {err:#}");
        }
    }

    #[test]
    fn explicit_direct_policy_is_preserved() {
        for policy in ["[]", "[\"http://100.64.0.2:18080\"]"] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            write!(
                file,
                "[egress]\ndirect = {policy}\n[inference]\nurl = \"http://100.64.0.1:18080\"\nregister = \"plain\"\n"
            )
            .unwrap();
            let config = composed(&args(file.path().to_str(), RUN, LIMITS, &[]));
            assert!(!config.egress.direct.contains(&config.inference.url));
            let config = composed(&args(
                file.path().to_str(),
                RUN,
                LIMITS,
                &["egress.direct=http://100.64.0.3:18080"],
            ));
            assert_eq!(config.egress.direct, ["http://100.64.0.3:18080"]);
        }
    }

    #[test]
    fn file_inference_defaults_to_direct() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(
            file,
            "[inference]\nurl = \"http://100.64.0.1:18080\"\nregister = \"plain\"\n"
        )
        .unwrap();
        let config = composed(&args(file.path().to_str(), RUN, LIMITS, &[]));
        assert_eq!(config.egress.direct, ["http://100.64.0.1:18080"]);
        // Under `front` only `run` reaches the broker.
        writeln!(file, "front = true").unwrap();
        let config = composed(&args(file.path().to_str(), RUN, LIMITS, &[]));
        assert!(config.inference.front);
        assert!(config.egress.direct.is_empty());
    }

    #[test]
    fn real_agent_can_reach_default_but_not_override_explicit_policy() {
        let strings = [
            "agent.name=claude",
            "inference.url=http://100.64.0.1:18080",
            "inference.register=plain",
        ];
        let config = composed(&args(None, &strings, LIMITS, &[]));
        assert_eq!(config.egress.direct, ["http://100.64.0.1:18080"]);
        let err = compose(&args(
            None,
            &strings,
            LIMITS,
            &["egress.direct=http://100.64.0.2:18080"],
        ))
        .unwrap_err();
        assert!(format!("{err:#}").contains("add \"http://100.64.0.1:18080\""));
    }

    /// A setting replaces the file's key and leaves the rest; an empty
    /// one leaves the key too.
    #[test]
    fn settings_go_over_the_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(
            file,
            "[sandbox]\nstop-services = [\"docker.service\"]\n[agent]\nname = \"claude\"\n\
             model = \"opus\"\n[limits]\ntimeout-minutes = 30\nbudget = 100\n\
             [setup]\npackages = [\"jq\"]\n"
        )
        .unwrap();
        let from = file.path().to_str().unwrap();
        let config = composed(&args(
            Some(from),
            &["agent.name=fake", "agent.model=", "inference.url= "],
            &["limits.timeout-minutes=5", "limits.budget="],
            &["setup.packages="],
        ));
        assert_eq!(config.sandbox.stop_services, ["docker.service"]);
        assert_eq!(config.agent.name, "fake");
        assert_eq!(config.agent.model.as_deref(), Some("opus"));
        assert_eq!(config.inference.url, "");
        assert_eq!(
            (config.limits.timeout_minutes, config.limits.budget),
            (5, 100)
        );
        assert_eq!(config.setup.packages, ["jq"]);
    }

    /// A target's own list, or else `default`'s, goes after the file's
    /// packages and any setting; the table itself is not written.
    #[test]
    fn repo_packages_follow_the_target() {
        let file_text = "[setup]\npackages = [\"jq\"]\n[setup.repo-packages]\n\
                         default = [\"make\"]\n\"o/rust\" = [\"cargo\", \"gcc\"]\n\"o/none\" = []\n";
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "{file_text}").unwrap();
        let mut bare = tempfile::NamedTempFile::new().unwrap();
        write!(bare, "[setup.repo-packages]\n\"o/rust\" = [\"cargo\"]\n").unwrap();
        let cases: &[(&tempfile::NamedTempFile, Option<&str>, &str, &[&str])] = &[
            (
                &file,
                Some("o/rust"),
                "setup.packages=",
                &["jq", "cargo", "gcc"],
            ),
            (&file, Some("o/none"), "setup.packages=", &["jq"]),
            (&file, Some("o/other"), "setup.packages=", &["jq", "make"]),
            // Names ignore case, as in the bounds.
            (
                &file,
                Some("O/Rust"),
                "setup.packages=",
                &["jq", "cargo", "gcc"],
            ),
            (&file, None, "setup.packages=", &["jq", "make"]),
            (
                &file,
                Some("o/rust"),
                "setup.packages=just",
                &["just", "cargo", "gcc"],
            ),
            (&bare, Some("o/rust"), "setup.packages=", &["cargo"]),
            (&bare, Some("o/other"), "setup.packages=", &[]),
        ];
        for (from, repo, list, packages) in cases {
            let args = Args {
                repo: repo.map(str::to_owned),
                ..args(from.path().to_str(), RUN, LIMITS, &[list])
            };
            let text = compose(&args).unwrap();
            assert!(!text.contains("repo-packages"), "{args:?}: {text}");
            assert_eq!(
                Config::parse(&text).unwrap().setup.packages,
                *packages,
                "{args:?}"
            );
        }
        let refused = [
            (
                "\"o/r\" = [\"--installroot=/\"]",
                "o/r",
                "is not a package name",
            ),
            (
                "\"o/r\" = \"cargo\"",
                "o/r",
                "expected OWNER/NAME = [package, ...]",
            ),
            ("\"o/r/x\" = []", "o/r", "is neither OWNER/NAME nor default"),
            ("\"*\" = []", "o/r", "is neither OWNER/NAME nor default"),
            ("default = []", "o/r --x", "is not OWNER/NAME"),
            ("\"o/r\" = []\n\"O/r\" = []", "o/r", "is named twice"),
        ];
        for (table, repo, names) in refused {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            write!(file, "[setup.repo-packages]\n{table}\n").unwrap();
            let args = Args {
                repo: Some(repo.to_owned()),
                ..args(file.path().to_str(), RUN, LIMITS, &[])
            };
            let err = compose(&args).expect_err("a bad table was taken");
            assert!(format!("{err:#}").contains(names), "{table}: {err:#}");
        }
    }

    /// The shipped runner configuration gives this repository cargo,
    /// which the scripted dispatch review relies on, and others nothing.
    /// It installs no Python for the egress proxy, which is the Rust one.
    #[test]
    fn shipped_hosted_config_gives_this_repository_cargo() {
        let hosted = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.github/agentic-job/hosted.toml"
        );
        for (repo, cargo) in [("cgwalters-forge/agentic-job", true), ("o/other", false)] {
            let args = Args {
                repo: Some(repo.to_owned()),
                ..args(Some(hosted), RUN, LIMITS, &[])
            };
            let config = composed(&args);
            assert!(config.egress.rust_proxy, "{repo}");
            let packages = config.setup.packages;
            assert!(
                !packages.contains(&"python3-venv".to_owned()),
                "{repo}: {packages:?}"
            );
            assert_eq!(
                packages.contains(&"cargo".to_owned()),
                cargo,
                "{repo}: {packages:?}"
            );
            assert!(
                packages.contains(&"nftables".to_owned()),
                "{repo}: {packages:?}"
            );
        }
    }

    /// The shipped runner configuration commits as GitHub's Actions bot,
    /// whose noreply address GitHub attributes to it, for any caller:
    /// an address of an unregistered login is attributed to no one.
    #[test]
    fn shipped_hosted_config_commits_as_an_attributed_author() {
        let hosted = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.github/agentic-job/hosted.toml"
        );
        let config = composed(&args(Some(hosted), RUN, LIMITS, &[]));
        let (name, address) = crate::run::handback::author(&config.commit).unwrap();
        assert_eq!(
            (name.as_str(), address.as_str()),
            (
                "github-actions[bot]",
                "41898282+github-actions[bot]@users.noreply.github.com"
            )
        );
    }

    /// A host's file needs no agent and no limits, which a run's does;
    /// what `sandbox setup` would refuse is refused for it all the same.
    #[test]
    fn a_host_is_configured_without_an_agent() {
        let config = composed(&host_args(
            &[
                "sandbox.lock-runner= false ",
                "egress.proxy=false",
                "sandbox.allow-existing-user=",
                "sandbox.deny-runner-metadata=",
            ],
            &["sandbox.stop-services=docker.socket docker.service"],
        ));
        assert!(!config.sandbox.lock_runner);
        assert!(!config.sandbox.deny_runner_metadata);
        assert!(!config.egress.proxy);
        assert!(!config.sandbox.allow_existing_user);
        assert_eq!(
            config.sandbox.stop_services,
            ["docker.socket", "docker.service"]
        );
        assert_eq!(config.agent.name, "");
        let denied = composed(&host_args(&["sandbox.deny-runner-metadata=true"], &[]));
        assert!(denied.sandbox.lock_runner && denied.sandbox.deny_runner_metadata);
        // For the secure-host image, a run's file without its script and
        // with all else: the agent job runs the script itself.
        let run = args(None, &["setup.script=setup.sh", RUN[0]], LIMITS, &[]);
        assert_eq!(
            composed(&run).setup.script.as_deref(),
            Some(std::path::Path::new("setup.sh"))
        );
        let image = composed(&Args {
            host: true,
            no_script: true,
            ..run
        });
        assert_eq!(image.setup.script, None);
        assert_eq!(image.agent.name, "fake");
        assert_eq!(image.limits.budget, 100);
        // The same file, as a run's: `run` could not use it.
        let run = Args {
            host: false,
            ..host_args(&["egress.proxy=false"], &[])
        };
        assert!(compose(&run).is_err());
        let cases = [
            (
                vec!["sandbox.lock-runner=yes"],
                vec![],
                "sandbox.lock-runner: \"yes\" is neither true nor false",
            ),
            (vec!["sandbox.user=true"], vec![], "invalid type: boolean"),
            (
                vec![
                    "sandbox.lock-runner=false",
                    "sandbox.deny-runner-metadata=true",
                ],
                vec![],
                "sandbox.deny-runner-metadata needs sandbox.lock-runner",
            ),
            (
                vec![
                    "sandbox.lock-runner=false",
                    "sandbox.deny-runner-reads=true",
                ],
                vec![],
                "sandbox.deny-runner-reads needs sandbox.lock-runner",
            ),
            (
                vec![],
                vec!["sandbox.stop-services=docker"],
                "sandbox.stop-services: \"docker\" is not a unit name",
            ),
            (
                vec!["session.listen=true"],
                vec![
                    "session.operators=op@github",
                    "session.origins=https://review.example",
                ],
                "session.listen needs agent.name",
            ),
        ];
        for (boolean, list, names) in cases {
            let args = host_args(&boolean, &list);
            let err = compose(&args).expect_err("a bad setting was taken");
            assert!(format!("{err:#}").contains(names), "{args:?}: {err:#}");
        }
    }

    /// Text that would add keys if it were pasted into a file is the
    /// value of its one key, to the character.
    #[test]
    fn a_value_is_never_read_as_toml() {
        let hostile = [
            "opus\"\n[sandbox]\nuser = \"root",
            "x\"\nallow-existing-user = true\ny = \"",
            "'''\n[limits]\nuncapped = true\n'''",
            "a = b = c",
            "\\\" \\u0000 \u{7f} \t",
        ];
        let plain = composed(&args(None, RUN, LIMITS, &[]));
        for text in hostile {
            let model = format!("agent.model={text}");
            let config = composed(&args(None, &[RUN[0], &model], LIMITS, &[]));
            assert_eq!(config.agent.model.as_deref(), Some(text));
            let mut rest = config;
            rest.agent.model = None;
            assert_eq!(rest, plain, "{text:?} set another key");
        }
    }

    #[test]
    fn what_is_refused() {
        let key = |text: &str| Setting::parse(text).is_err();
        for text in [
            "no-equals",
            "=x",
            "model=x",
            "agent.=x",
            ".model=x",
            "agent.mo del=x",
            "agent.\"model\"=x",
            "agent.model\n[sandbox]=x",
        ] {
            assert!(key(text), "{text:?} was taken as a setting");
        }
        let cases = [
            // (strings, integers, lists, what the error says)
            (vec!["agent.nam=x"], vec![], vec![], "unknown field `nam`"),
            (
                vec!["agents.name=x"],
                vec![],
                vec![],
                "unknown field `agents`",
            ),
            (
                vec!["limits.budget=5"],
                vec![],
                vec![],
                "invalid type: string",
            ),
            (
                vec!["inference.register=oidc"],
                vec![],
                vec![],
                "unknown variant `oidc`",
            ),
            (
                vec!["agent.name=y", "agent.name.first=x"],
                vec![],
                vec![],
                "setting agent.name.first: name is not a table",
            ),
            (
                vec!["sandbox.user=root"],
                vec![],
                vec![],
                "sandbox.user: \"root\"",
            ),
            (
                vec![],
                vec!["limits.budget=-1"],
                vec![],
                "limits.budget: \"-1\" is not a whole number",
            ),
            (
                vec![],
                vec!["limits.budget=1.5"],
                vec![],
                "limits.budget: \"1.5\" is not a whole number",
            ),
            (
                vec![],
                vec!["limits.budget=ten"],
                vec![],
                "limits.budget: \"ten\" is not a whole number",
            ),
            (
                vec![],
                vec![],
                vec!["setup.packages=jq --installroot=/"],
                "setup.packages: \"--installroot=/\" is not a package name",
            ),
            (
                vec![],
                vec![],
                vec!["agent.name=fake"],
                "invalid type: sequence",
            ),
            // What `run` would refuse, minutes later.
            (
                vec!["agent.name=fake"],
                vec![],
                vec![],
                "limits.timeout-minutes is not set",
            ),
            (
                vec!["agent.name=fake"],
                vec!["limits.timeout-minutes=5", "limits.max-requests=50"],
                vec![],
                "limits.max-requests = 50 would not bind",
            ),
            (
                vec!["agent.name=claude"],
                LIMITS.to_vec(),
                vec![],
                "the agent claude needs inference",
            ),
            (
                vec![
                    "agent.name=claude",
                    "inference.url=http://127.0.0.1:18080",
                    "inference.register=github-oidc",
                ],
                LIMITS.to_vec(),
                vec![],
                "needs the audience",
            ),
        ];
        for (string, integer, list, names) in cases {
            let args = args(None, &string, &integer, &list);
            let err = compose(&args).expect_err("a bad setting was taken");
            assert!(format!("{err:#}").contains(names), "{args:?}: {err:#}");
        }
    }
}
