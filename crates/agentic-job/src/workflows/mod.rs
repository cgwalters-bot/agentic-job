//! `agentic-job workflows check`: the job shape a compiler used to
//! guarantee, required of a repository's ordinary workflow files instead
//! (docs/workflows-check.md). [`rules`] has what a job must be; a file
//! that cannot be is listed, with its reason, in one exemptions file.
//!
//! The files are data: read without following links, capped in size and
//! count, and parsed with [`yaml`]'s bounds. Nothing in them runs.

pub mod rules;
mod yaml;

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args as ClapArgs, Subcommand};
use serde::Deserialize;

use crate::exit::Exit;
use crate::files;

/// Where GitHub reads a repository's workflows, and only at this level.
pub const WORKFLOWS_DIR: &str = ".github/workflows";

/// The exemptions file's place in a repository.
pub const EXEMPTIONS: &str = ".github/agentic-job/workflows.toml";

/// GitHub's own limit on a workflow file is larger; no workflow written by
/// hand comes near this.
const MAX_WORKFLOW_BYTES: u64 = 1 << 20;
const MAX_WORKFLOWS: usize = 500;
const MAX_EXEMPTIONS_BYTES: u64 = 64 << 10;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Refuse workflow files whose jobs could run untrusted steps unsandboxed
    Check(Args),
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        match self {
            Self::Check(args) => check(args),
        }
    }
}

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// The repository whose .github/workflows is checked
    #[arg(long, default_value = ".")]
    pub root: PathBuf,
    /// The exemptions file, from the base branch where the files checked are a proposal's [default: ROOT/.github/agentic-job/workflows.toml]
    #[arg(long)]
    pub exemptions: Option<PathBuf>,
}

/// The exemptions file: each workflow file, by name, that is not held to
/// the rules, and why.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exemptions {
    #[serde(default)]
    exempt: BTreeMap<String, String>,
}

/// Ignoring case, so that no spelling GitHub might load goes unchecked.
fn is_workflow(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.ends_with(".yml") || name.ends_with(".yaml")
}

/// The exemptions at `path`; none when the default file does not exist.
fn read_exemptions(path: &Path, explicit: bool) -> Result<Exemptions> {
    let bytes = match files::read_regular(path, MAX_EXEMPTIONS_BYTES) {
        Err(files::ReadError::Io(err)) if err.kind() == ErrorKind::NotFound && !explicit => {
            return Ok(Exemptions::default());
        }
        read => read.with_context(|| format!("reading {}", path.display()))?,
    };
    let text = String::from_utf8(bytes).context("the exemptions file is not UTF-8")?;
    let exemptions: Exemptions =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    for (name, reason) in &exemptions.exempt {
        ensure!(
            is_workflow(name) && !name.contains('/'),
            "{}: {name:?} is not a workflow file's name",
            path.display()
        );
        ensure!(
            !reason.trim().is_empty(),
            "{}: {name} has no reason",
            path.display()
        );
    }
    Ok(exemptions)
}

/// The names of the workflow files under `root`, sorted.
fn workflow_names(root: &Path) -> Result<Vec<String>> {
    let dir = root.join(WORKFLOWS_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        entries => entries.with_context(|| format!("listing {}", dir.display()))?,
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("listing {}", dir.display()))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            bail!("{}: a name that is not UTF-8", dir.display());
        };
        if is_workflow(&name) {
            names.push(name);
            ensure!(
                names.len() <= MAX_WORKFLOWS,
                "{}: over {MAX_WORKFLOWS} workflow files",
                dir.display()
            );
        }
    }
    names.sort();
    Ok(names)
}

/// The problems of the workflow file `name` under `root`, each a line.
fn check_file(root: &Path, name: &str) -> Vec<String> {
    let file = format!("{WORKFLOWS_DIR}/{name}");
    let parsed = files::read_regular(&root.join(&file), MAX_WORKFLOW_BYTES)
        .map_err(anyhow::Error::new)
        .and_then(|bytes| String::from_utf8(bytes).context("is not UTF-8"))
        .and_then(|text| yaml::parse(&text));
    let workflow = match parsed {
        Ok(workflow) => workflow,
        Err(err) => {
            return vec![format!(
                "{file}: cannot be checked: {err:#}; write it as a regular file of one YAML document, or list it in {EXEMPTIONS} with the reason"
            )];
        }
    };
    rules::check_workflow(&workflow)
        .into_iter()
        .map(|p| {
            let at: Vec<String> = [p.job.map(|j| format!("job {j}")), p.step]
                .into_iter()
                .flatten()
                .collect();
            let at = if at.is_empty() {
                String::new()
            } else {
                format!(" {}", at.join(", "))
            };
            format!("{file}:{at} {}; instead, {}", p.what, p.instead)
        })
        .collect()
}

fn check(args: &Args) -> Result<Exit> {
    let path = args
        .exemptions
        .clone()
        .unwrap_or_else(|| args.root.join(EXEMPTIONS));
    let exemptions = read_exemptions(&path, args.exemptions.is_some())?;
    let names = workflow_names(&args.root)?;
    let mut problems = Vec::new();
    for name in exemptions.exempt.keys() {
        if !names.contains(name) {
            problems.push(format!(
                "{}: exempts {name}, which is not in {WORKFLOWS_DIR}; instead, remove the entry",
                path.display()
            ));
        }
    }
    let mut checked = 0usize;
    for name in &names {
        if let Some(reason) = exemptions.exempt.get(name) {
            eprintln!("{WORKFLOWS_DIR}/{name}: exempt: {reason}");
            continue;
        }
        checked += 1;
        problems.extend(check_file(&args.root, name));
    }
    for problem in &problems {
        println!("{problem}");
    }
    eprintln!(
        "{} problem(s); {checked} workflow file(s) checked, {} exempt",
        problems.len(),
        names.len() - checked
    );
    Ok(if problems.is_empty() {
        Exit::Success
    } else {
        Exit::Failure
    })
}
