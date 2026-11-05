//! `agentic-job sandbox setup`: secure-host's host setup
//! ([`::secure_host::setup`]), with what agentic-job adds to it through
//! [`Program`]: the agents it installs, the agent's managed settings and
//! a session's bridge. secure-host's module says what setup
//! closes and in what order; it is re-exported here at the paths callers
//! know.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};

pub use ::secure_host::setup::{
    CONFIG_DIR, CRYPTO_POLICIES, DISK_GROUP, OTHER_WRITE, READ_ONLY_GROUPS, ROOT_GROUPS, RootGroup,
    SELF_COPY, SHADOW_GROUP, WORLD_WRITE_LINKS, WORLD_WRITE_PIN, WORLD_WRITE_PROBE_DIR,
    WORLD_WRITE_PROBE_FILE, private_dirs, resolved, runner_sudo_rules, writable_crypto_policies,
};
use ::secure_host::setup::{
    MODE_FILE, Plan, Program, install_file, install_packages, make_roots_alone, timed,
};

use super::egress;
use super::host;
use crate::config::{self, Config};
use crate::exit::Exit;
use crate::run::agent::{self, Kind};
use crate::run::inference::Endpoint;
use crate::session::bridge::{self, Listen};

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

/// The configuration, read and checked as the preflight's first step.
fn read(args: &Args) -> Result<Plan<Job>> {
    let text = fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let config = if args.host_only {
        config::HostConfig::parse(&text).map(Config::from)
    } else {
        Config::parse(&text)
    }
    .with_context(|| format!("in {}", args.config.display()))?;
    // It ran as the second user, which setup no longer makes; it is the
    // runner's user's to run after setup, as the agent job does.
    ensure!(
        config.setup.script.is_none(),
        "setup.script: setup runs no script since the sandbox user was removed \
         (agentic-job#2989); the runner's user runs it after setup, so leave it out of the \
         host's file (`agentic-job config --host` does)"
    );
    let config::checked::Host {
        direct,
        refused,
        session,
        install_vibe,
    } = config.check_host()?;
    Ok(Plan {
        text,
        direct,
        refused,
        served_port: session.is_some().then_some(bridge::PORT),
        packages: config.setup.packages.clone(),
        program: Job {
            config,
            install_vibe,
            session,
        },
    })
}

/// What agentic-job's file asks of setup beyond the host's tables.
struct Job {
    config: Config,
    install_vibe: bool,
    /// A session run's: its bridge is served on the tailnet.
    session: Option<Listen>,
}

impl Program for Job {
    type File = Config;

    const PROXY: egress::ProxyBinary = EGRESS_PROXY;

    fn file(&self) -> &Config {
        &self.config
    }

    fn preflight(&self) -> Result<()> {
        ensure!(
            self.session.is_none() || host::has_program("tailscale"),
            "session.listen needs tailscale: the session's client reaches it over the tailnet"
        );
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

    fn serve(&self) -> Result<()> {
        if self.session.is_some() {
            timed("session-serve", serve_session)?;
        }
        Ok(())
    }

    fn configure(&self) -> Result<()> {
        write_managed_settings(&self.config)
    }
}

/// Publishes the address. The run's trusted guard enables serve only while
/// it holds the bridge listener, and revokes it before releasing that port.
fn serve_session() -> Result<()> {
    let status: serde_json::Value = serde_json::from_str(&host::run(
        Command::new("tailscale").args(["status", "--json"]),
    )?)
    .context("reading tailscale status")?;
    let endpoint = format!("wss://{}/", session_name(&status)?);
    install_file(
        Path::new(bridge::ENDPOINT_FILE),
        format!("{endpoint}\n").as_bytes(),
        MODE_FILE,
        None,
    )?;
    println!("The session's client connects at {endpoint}");
    Ok(())
}

/// This machine's tailnet name, which must have a certificate: without
/// one, `tailscale serve --https` waits for a capability that never comes,
/// so the run would only time out later with no cause.
fn session_name(status: &serde_json::Value) -> Result<&str> {
    let name = status["Self"]["DNSName"]
        .as_str()
        .map(|name| name.trim_end_matches('.'))
        .filter(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        })
        .context("tailscale status names no DNS name for this machine")?;
    let certified = status["CertDomains"]
        .as_array()
        .is_some_and(|domains| domains.iter().any(|domain| domain.as_str() == Some(name)));
    ensure!(certified, "{}", super::session::HTTPS_DISABLED);
    Ok(name)
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

    #[test]
    fn the_session_name_needs_a_dns_name_with_a_certificate() {
        let name = "runner.tail1234.ts.net";
        let status = |dns: &str, certs: serde_json::Value| serde_json::json!({"Self": {"DNSName": dns}, "CertDomains": certs});
        let disabled = Err("HTTPS certificates disabled");
        for (status, wanted) in [
            (
                status("runner.tail1234.ts.net.", serde_json::json!([name])),
                Ok(name),
            ),
            (
                status("runner.tail1234.ts.net.", serde_json::Value::Null),
                disabled,
            ),
            (
                status("runner.tail1234.ts.net.", serde_json::json!(["other"])),
                disabled,
            ),
            (
                status("Runner!.", serde_json::json!(["Runner!"])),
                Err("no DNS name"),
            ),
        ] {
            match (session_name(&status), wanted) {
                (Ok(got), Ok(wanted)) => assert_eq!(got, wanted),
                (Err(error), Err(wanted)) => {
                    assert!(format!("{error:#}").contains(wanted), "{error:#}")
                }
                (got, wanted) => panic!("{status}: got {got:?}, wanted {wanted:?}"),
            }
        }
    }
}
