//! `agentic-job sandbox setup`: secure-host's host setup
//! ([`::secure_host::setup`]), with what agentic-job adds to it through
//! [`Program`]: the agents it installs and the agent's managed settings.
//! secure-host's module says what setup closes and in what order; it is
//! re-exported here at the paths callers know.
//!
//! `agentic-job sandbox prepare` does agentic-job's part alone, as root,
//! before the secure-host image, which holds no agent code: the agents,
//! the managed settings, and this binary as the helper, which reads the
//! run's tables. The image's setup then keeps that helper
//! (`[host.prepared]`, which `config --host --prepared` writes).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use rustix::fs::Mode;

pub use ::secure_host::setup::{
    CONFIG_DIR, CRYPTO_POLICIES, DISK_GROUP, OTHER_WRITE, READ_ONLY_GROUPS, ROOT_GROUPS, RootGroup,
    SELF_COPY, SHADOW_GROUP, WORLD_WRITE_LINKS, WORLD_WRITE_PIN, WORLD_WRITE_PROBE_DIR,
    WORLD_WRITE_PROBE_FILE, private_dirs, resolved, runner_sudo_rules, writable_crypto_policies,
};
use ::secure_host::setup::{
    MODE_FILE, Plan, Program, ROOT_UMASK, install_file, install_packages, install_self,
    make_roots_alone, timed,
};

use super::egress;
use super::host;
use crate::config::{self, Config};
use crate::exit::Exit;
use crate::run::agent::{self, Kind};
use crate::run::inference::Endpoint;
use crate::session::bridge;

pub mod agents;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The run's configuration (TOML); copied to /etc/agentic-job/
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
    /// Run the egress proxy from this podman image ID, in root podman:
    /// the secure-host image's entrypoint passes its own.
    #[arg(long, value_name = "ID")]
    pub egress_image: Option<String>,
    /// Hold the file to [`config::HostConfig`]: `secure-host setup`'s.
    #[arg(skip)]
    pub host_only: bool,
}

#[derive(Debug, clap::Args)]
pub struct PrepareArgs {
    /// The run's configuration (TOML), with `[host.prepared]`, as
    /// `agentic-job config --host --prepared` writes it
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
}

/// The proxy of `[egress]`, as the root-owned copy of this binary and
/// the image's (`secure-host/Containerfile`) run it.
pub const EGRESS_PROXY: egress::ProxyBinary = egress::ProxyBinary {
    host: SELF_COPY,
    image: "/agentic-job",
    command: &["sandbox", "egress-proxy"],
};

pub fn run(args: &Args) -> Result<Exit> {
    ::secure_host::setup::run(|| read(args), args.egress_image.as_deref())?;
    Ok(Exit::Success)
}

/// The configuration at PATH, read and checked; HOST_ONLY holds it to
/// [`config::HostConfig`].
fn load(path: &Path, host_only: bool) -> Result<(String, Config, config::checked::Host)> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let config = if host_only {
        config::HostConfig::parse(&text).map(Config::from)
    } else {
        Config::parse(&text)
    }
    .with_context(|| format!("in {}", path.display()))?;
    // It ran as the second user, which setup no longer makes; it is the
    // runner's user's to run after setup, as the agent job does.
    ensure!(
        config.setup.script.is_none(),
        "setup.script: setup runs no script since the sandbox user was removed \
         (agentic-job#2989); the runner's user runs it after setup, so leave it out of the \
         host's file (`agentic-job config --host` does)"
    );
    let host = config.check_host()?;
    Ok((text, config, host))
}

/// The configuration, read and checked as the preflight's first step.
fn read(args: &Args) -> Result<Plan<Job>> {
    let (text, config, host) = load(&args.config, args.host_only)?;
    // Setup would keep a helper no step of this one installed.
    ensure!(
        config.sandbox.prepared.is_none(),
        "host.prepared is for secure-host's setup after `agentic-job sandbox prepare`; \
         `sandbox setup` does both itself: leave it out"
    );
    let config::checked::Host {
        direct,
        refused,
        session,
        install_vibe,
    } = host;
    Ok(Plan {
        text,
        direct,
        refused,
        // A gateway's `session.bind` is reached without serve.
        served_port: session
            .as_ref()
            .is_some_and(bridge::Listen::on_tailnet)
            .then_some(bridge::PORT),
        packages: config.setup.packages.clone(),
        program: Job {
            config,
            install_vibe,
        },
    })
}

/// `agentic-job sandbox prepare`: as root, before secure-host's setup,
/// which it leaves the rest to, what setup's [`Program`] stages would do
/// as root on the open network: apt's bounded waits and the packages,
/// which the agents' installs may need, the agents, the managed settings,
/// and this binary as the helper. The file must say so
/// (`[host.prepared]`), or secure-host's setup would install itself
/// over that helper.
pub fn prepare(args: &PrepareArgs) -> Result<Exit> {
    ensure!(
        host::is_root(),
        "`sandbox prepare` must run as root, before secure-host takes it away"
    );
    // Root's umask is the caller's, and some images build with 000.
    rustix::process::umask(Mode::from_raw_mode(ROOT_UMASK));
    ensure!(
        !Path::new(CONFIG_DIR).exists(),
        "{CONFIG_DIR} already exists: `sandbox prepare` runs before secure-host's setup, on a fresh machine"
    );
    let job = prepared_job(&args.config)?;
    job.preflight()?;
    // Before the first package, as the image does it before setup.
    timed("apt", || {
        ::secure_host::apt::configure(Path::new(::secure_host::apt::APT))
    })?;
    timed("packages", || install_packages(&job.config.setup.packages))?;
    job.install()?;
    timed("configuration", || job.configure())?;
    timed("install-self", install_self)?;
    println!(
        "agentic-job's part of setup is done; {SELF_COPY} is the helper secure-host's setup keeps"
    );
    Ok(Exit::Success)
}

/// `sandbox prepare`'s configuration, at PATH, read and checked.
fn prepared_job(path: &Path) -> Result<Job> {
    let (_, config, host) = load(path, false)?;
    ensure!(
        config.sandbox.prepared.is_some(),
        "host.prepared is not set, so secure-host's setup would install itself as the helper \
         over this one: write the file with `agentic-job config --host --prepared`"
    );
    Ok(Job {
        config,
        install_vibe: host.install_vibe,
    })
}

/// What agentic-job's file asks of setup beyond the host's tables.
struct Job {
    config: Config,
    install_vibe: bool,
}

impl Program for Job {
    type File = Config;

    const PROXY: egress::ProxyBinary = EGRESS_PROXY;

    fn file(&self) -> &Config {
        &self.config
    }

    fn preflight(&self) -> Result<()> {
        if !self.config.setup.agents.is_empty() {
            agents::check_platform()?;
        }
        Ok(())
    }

    fn install(&self) -> Result<()> {
        timed("npm", || install_npm(&self.config.setup.npm))?;
        timed("agents", || {
            for spec in &self.config.setup.agents {
                agents::check_node(spec)?;
                let dir = agents::install(
                    spec,
                    Path::new(agents::ROOT),
                    Path::new(agents::BIN_DIR),
                    &agents::fetch,
                )?;
                // What /usr/local/bin now runs: no one else may replace it.
                make_roots_alone(&dir)?;
            }
            Ok(())
        })?;
        if self.install_vibe {
            timed("vibe", install_vibe)?;
        }
        Ok(())
    }

    fn configure(&self) -> Result<()> {
        write_managed_settings(&self.config)
    }
}

/// The path and content of the agent's managed settings for CONFIG, if
/// it has any. A configuration that names no agent `run` could start is
/// `run`'s to refuse, not setup's.
pub(crate) fn managed_settings(config: &Config) -> Result<Option<(&'static str, String)>> {
    let Ok(kind) = Kind::parse(&config.agent.name) else {
        return Ok(None);
    };
    let endpoint = Endpoint::from_config(&config.inference)?;
    Ok(agent::managed_settings(kind, endpoint.as_ref()))
}

/// The agent's managed settings, root's, from the same configuration
/// `run` will read: `run` has no root to write them with.
fn write_managed_settings(config: &Config) -> Result<()> {
    if let Some((path, content)) = managed_settings(config)? {
        let path = Path::new(path);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        install_file(path, content.as_bytes(), MODE_FILE, None)?;
    }
    Ok(())
}

/// The agent programs. Their versions are exact (the configuration is
/// refused otherwise), so a run is repeatable; their install scripts run
/// as root here, as in the old tree, which is why the list is the
/// caller's and not the task's.
fn install_npm(specs: &[String]) -> Result<()> {
    if specs.is_empty() {
        return Ok(());
    }
    ensure!(
        host::has_program("npm"),
        "setup.npm: no npm on this host; add it to setup.packages"
    );
    let status = Command::new("npm")
        .args(["install", "-g", "--no-audit", "--no-fund", "--"])
        .args(specs)
        .status()
        .context("running npm")?;
    ensure!(
        status.success(),
        "npm install -g {} failed ({status})",
        specs.join(" ")
    );
    Ok(())
}

/// Installed before credentials and network rules, like the npm agents.
/// Neither the checkout nor caller setup code selects the package or path.
fn install_vibe() -> Result<()> {
    const HOME: &str = "/opt/agentic-job/vibe";
    const PACKAGE: &str = "mistral-vibe==2.26.1";
    install_packages(&["python3-venv".to_owned()])?;
    host::run(Command::new("python3").args(["-m", "venv", HOME]))?;
    host::run(Command::new(format!("{HOME}/bin/pip")).args([
        "install",
        "--disable-pip-version-check",
        PACKAGE,
    ]))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The legacy setup path must not ask for Tailscale for a gateway,
    /// just as the prepared-host configuration must not.
    #[test]
    fn only_tailnet_sessions_ask_setup_to_serve() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        for (session, port) in [
            ("", None),
            (
                "[session]\nlisten = true\noperators = [\"op@github\"]\n\
                 origins = [\"https://r.example.ts.net\"]\n",
                Some(bridge::PORT),
            ),
            ("[session]\nlisten = true\nbind = \"0.0.0.0:7790\"\n", None),
        ] {
            use std::io::{Seek, Write};

            file.as_file_mut().set_len(0).unwrap();
            file.rewind().unwrap();
            write!(file, "[agent]\nname = \"fake\"\n{session}").unwrap();
            let plan = read(&Args {
                config: file.path().to_owned(),
                egress_image: None,
                host_only: false,
            })
            .unwrap();
            assert_eq!(plan.served_port, port, "{session}");
        }
    }

    /// The proxy secure-host starts is this binary's `sandbox
    /// egress-proxy`, with every option it may be given.
    #[test]
    fn the_egress_proxy_command_line_parses() {
        let refused = [("fd7a:115c:a1e0::1".to_owned(), 443)];
        for (transparent, refused) in [(false, &[][..]), (true, &[][..]), (false, &refused[..])] {
            for binary in [EGRESS_PROXY.host, EGRESS_PROXY.image] {
                let command = EGRESS_PROXY.command;
                let args = egress::rust_proxy_args(binary, command, true, transparent, refused);
                let parsed = <crate::cli::Cli as clap::Parser>::try_parse_from(&args);
                assert!(parsed.is_ok(), "{parsed:?}");
            }
        }
    }

    /// `prepare` takes only a file that tells secure-host's setup to keep
    /// its helper, and `setup`, which installs its own, only one that
    /// does not; neither takes a table that no longer says what the run's
    /// tables ask of the host.
    #[test]
    fn prepare_and_setup_each_take_their_own_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let session = "[agent]\nname = \"fake\"\n[session]\nlisten = true\n\
                       operators = [\"op@github\"]\norigins = [\"https://r.example.ts.net\"]\n";
        let args = |path: &Path| Args {
            config: path.to_owned(),
            egress_image: None,
            host_only: false,
        };
        for (text, prepare, setup) in [
            (
                "[agent]\nname = \"fake\"\n",
                Err("host.prepared is not set"),
                Ok(()),
            ),
            (
                "[agent]\nname = \"fake\"\n[host.prepared]\n",
                Ok(()),
                Err("`sandbox setup` does both itself"),
            ),
            (
                "[agent]\nname = \"fake\"\n[sandbox.prepared]\n",
                Ok(()),
                Err("`sandbox setup` does both itself"),
            ),
            (
                &format!("{session}[host.prepared]\nserve-port = 7790\n"),
                Ok(()),
                Err("`sandbox setup` does both itself"),
            ),
            (
                &format!("{session}[host.prepared]\n"),
                Err("config --host --prepared"),
                Err("config --host --prepared"),
            ),
        ] {
            fs::write(&path, text).unwrap();
            for (got, want) in [
                (prepared_job(&path).map(drop), prepare),
                (read(&args(&path)).map(drop), setup),
            ] {
                match (got, want) {
                    (Ok(()), Ok(())) => {}
                    (Err(err), Err(want)) => {
                        assert!(format!("{err:#}").contains(want), "{text}: {err:#}")
                    }
                    (got, want) => panic!("{text}: got {got:?}, wanted {want:?}"),
                }
            }
        }
    }
}
