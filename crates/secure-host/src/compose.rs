//! `secure-host config`: write a host's file from a caller's file and
//! from settings given one at a time, checked as setup will read it
//! ([`Host::check`]).
//!
//! It is for a step that gets its settings as strings from someone else,
//! the inputs of an action for one. Such a string is only ever a value
//! here: it is never read as TOML, so whatever it holds (a quote, a
//! newline, a table header) it sets the one key it was given for and no
//! other. A program's tables in the file ([`Host`]) are written back as
//! they came. agentic-job's `config` takes the same settings
//! ([`Setting`], [`Kind`], [`set`]).

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use toml::{Table, Value};

use crate::config::Host;

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
    /// What agentic-job's `config` needs for a host's file; always so here
    #[arg(long, hide = true)]
    pub host: bool,
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
    pub fn parse(text: &str) -> Result<Self> {
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

    pub fn key(&self) -> String {
        self.path.join(".")
    }

    /// Sets this, as KIND, in TABLE; a text that sets nothing leaves it.
    pub fn apply(&self, kind: Kind, table: &mut Table) -> Result<()> {
        if let Some(value) = kind.value(self)? {
            set(table, &self.path, value).with_context(|| format!("setting {}", self.key()))?;
        }
        Ok(())
    }
}

/// What a setting's text is turned into.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
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
pub fn set(table: &mut Table, path: &[String], value: Value) -> Result<()> {
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

/// The file the `--from` of ARGS names, with the settings of ARGS, read
/// in that order of kinds.
pub fn table(from: Option<&std::path::Path>, settings: [(Kind, &[Setting]); 4]) -> Result<Table> {
    let mut table = match from {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?
        }
        None => Table::new(),
    };
    for (kind, list) in settings {
        for setting in list {
            setting.apply(kind, &mut table)?;
        }
    }
    Ok(table)
}

/// The host's file of ARGS as TOML, checked.
fn compose(args: &Args) -> Result<String> {
    let table = table(
        args.from.as_deref(),
        [
            (Kind::String, &args.string),
            (Kind::Integer, &args.integer),
            (Kind::List, &args.list),
            (Kind::Boolean, &args.boolean),
        ],
    )?;
    let text = toml::to_string(&table).context("writing the host configuration")?;
    // As setup will see it: parsed from the text that is printed.
    Host::parse(&text)?.check()?;
    Ok(text)
}

pub fn run(args: &Args) -> Result<()> {
    let text = compose(args)?;
    std::io::stdout()
        .write_all(text.as_bytes())
        .context("writing the host configuration to standard output")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(list: &[&str]) -> Vec<Setting> {
        list.iter()
            .map(|text| Setting::parse(text).unwrap())
            .collect()
    }

    fn args(from: Option<PathBuf>, string: &[&str], boolean: &[&str]) -> Args {
        Args {
            from,
            string: settings(string),
            integer: Vec::new(),
            list: Vec::new(),
            boolean: settings(boolean),
            host: true,
        }
    }

    /// As the pinned action's `config.mjs` calls it, on a job's whole
    /// file: the settings land, and the program's tables come back as
    /// they were.
    #[test]
    fn a_jobs_file_passes_with_the_actions_settings() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("config.toml");
        let job = "[agent]\nname = \"fake\"\n[limits]\nbudget = 100\n\
                   [setup]\nagents = [\"x@1\"]\n[sandbox.prepared]\nserve-port = 7790\n";
        std::fs::write(&from, job).unwrap();
        let text = compose(&args(
            Some(from),
            &["sandbox.runner-user=runner"],
            &["egress.write-policy=false"],
        ))
        .unwrap();
        let got: Table = toml::from_str(&text).unwrap();
        let mut want: Table = toml::from_str(job).unwrap();
        want["sandbox"]
            .as_table_mut()
            .unwrap()
            .insert("runner-user".into(), "runner".into());
        want.insert(
            "egress".into(),
            Value::Table(Table::from_iter([("write-policy".into(), false.into())])),
        );
        assert_eq!(got, want);
        // `--host`, as the action spells it, and the empty text of an
        // input left out.
        let parsed = <crate::cli::Cli as clap::Parser>::try_parse_from([
            "secure-host",
            "config",
            "--host",
            "--from",
            "/in/config.toml",
            "--string",
            "sandbox.runner-user=",
        ]);
        assert!(parsed.is_ok(), "{parsed:?}");
        let empty = compose(&args(None, &["sandbox.runner-user="], &[])).unwrap();
        assert_eq!(empty, "");
    }

    #[test]
    fn what_is_refused() {
        for text in ["no-equals", "=x", "model=x", "agent.=x", "agent.mo del=x"] {
            assert!(Setting::parse(text).is_err(), "{text:?}");
        }
        for (string, boolean, want) in [
            (&["sandbox.usr=x"][..], &[][..], "unknown field `usr`"),
            (&["sandbox.runner-user=root"], &[], "not a user name"),
            (&["sandbox.user=agent"], &[], "was removed"),
            (&["setup.script=/s.sh"], &[], "set nothing here"),
            (&["agent.name=fake"], &[], "agent set nothing here"),
            (&[], &["egress.proxy=yes"], "neither true nor false"),
            (
                &[],
                &[
                    "sandbox.lock-runner=false",
                    "sandbox.deny-runner-reads=true",
                ],
                "needs sandbox.lock-runner",
            ),
        ] {
            let err = compose(&args(None, string, boolean)).unwrap_err();
            assert!(format!("{err:#}").contains(want), "{err:#}");
        }
    }
}
