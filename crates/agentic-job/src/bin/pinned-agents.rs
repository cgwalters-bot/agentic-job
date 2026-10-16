//! pinned-agents: the agents of `setup.agents` outside a sandbox setup.
//!
//! ```text
//! pinned-agents install DIR SPEC
//! pinned-agents lock SPEC NAME=PATH... < package-lock.json
//! ```
//!
//! `install` puts SPEC in DIR, as setup puts it in /opt/agentic-job/agents,
//! and links its programs in DIR/bin; it prints the agent's directory.
//! `lock` prints SPEC's entry for src/sandbox/setup/agents.toml from npm's
//! resolution, linking each program NAME to PATH (`just agents-lock`).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use agentic_job::sandbox::setup::agents;
use anyhow::{Context, Result, bail};

/// A package-lock.json of an agent is a few hundred kilobytes.
const MAX_INPUT_BYTES: u64 = 16 << 20;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, dir, spec] if command == "install" => {
            let bin = Path::new(dir).join("bin");
            std::fs::create_dir_all(&bin)?;
            let installed = agents::install(spec, Path::new(dir), &bin, &agents::fetch)?;
            println!("{}", installed.display());
        }
        [command, spec, links @ ..] if command == "lock" => {
            let bin = links
                .iter()
                .map(|link| {
                    link.split_once('=')
                        .map(|(name, path)| (name.to_owned(), path.to_owned()))
                        .with_context(|| format!("{link:?} is not NAME=PATH"))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            let mut text = String::new();
            std::io::stdin()
                .take(MAX_INPUT_BYTES)
                .read_to_string(&mut text)?;
            print!("{}", agents::lock_entry(spec, bin, &text)?);
        }
        _ => bail!(
            "usage: pinned-agents install DIR SPEC | pinned-agents lock SPEC NAME=PATH... < package-lock.json"
        ),
    }
    Ok(())
}
