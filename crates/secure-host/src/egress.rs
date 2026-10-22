//! The egress proxy, installed and started by `sandbox setup`: this
//! crate's own ([`crate::proxy`]), or with `egress.rust-proxy = false`
//! mitmproxy, with the addon and policy of `egress/` at the top of this
//! repository, which applies the same policy and writes the same log.
//!
//! The policy needs the method and path of every request, so the proxy
//! has to end TLS. This module is the old tree's `egress-proxy.mjs
//! start`: the proxy runs as a system user of its own, in a transient
//! service with no capabilities and a read-only system, so the sandbox
//! user can neither signal it, read its certificate authority's key, nor
//! change its policy; and the network rules keep that user off
//! everything private.
//!
//! Setup therefore needs the threat feed's host on the network, and with
//! mitmproxy also Python and a package index. What it takes from them is pinned here: every package by
//! the hashes of `egress/requirements.txt`, and the feed by a commit and
//! a checksum. docs/workflow.md says how each pin is moved.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};

use crate::config::Egress;
use crate::host::{self, User};
use crate::proxy::policy::{ECOSYSTEMS, normalize_host};

/// The addon and what it needs, as they are in `egress/`: the binary
/// carries them, since it is all a runner gets.
const ADDON: &str = include_str!("../../../egress/addon.py");

const POLICY_PY: &str = include_str!("../../../egress/policy.py");

const POLICY_TOML: &str = include_str!("../../../egress/policy.toml");

/// mitmproxy and everything it depends on, each at one version and with
/// the hashes of its files: generated from `egress/requirements.in`.
const REQUIREMENTS: &str = include_str!("../../../egress/requirements.txt");

pub const EGRESS_USER: &str = "egress-proxy";

pub const PROXY_HOST: Ipv4Addr = Ipv4Addr::LOCALHOST;

pub const PROXY_PORT: u16 = 3128;

/// Where, on [`PROXY_HOST`], the network rules redirect the runner's
/// connections under `egress.write-policy` (`network::write_policy_rules`).
pub const TRANSPARENT_PORT: u16 = 3129;

/// Under `egress.write-policy`, the authority goes into the system's
/// trust store, which OpenSSL, GnuTLS, Go and .NET (Runner.Worker
/// itself, which rereads the store when it changes) read: Ubuntu's
/// directory and command, or RHEL's.
const SYSTEM_TRUST: &[(&str, &str)] = &[
    (
        "/usr/local/share/ca-certificates/agentic-job-egress-proxy.crt",
        "update-ca-certificates",
    ),
    (
        "/etc/pki/ca-trust/source/anchors/agentic-job-egress-proxy.pem",
        "update-ca-trust",
    ),
];

/// What a later step needs in its environment to trust the authority
/// where the system's store is not read: Node's bundled roots (every
/// JavaScript action) and Python's requests and pip. Setup cannot set a later
/// step's environment, so the action appends this file to the job's
/// `GITHUB_ENV`; it is root's, and holds only these fixed lines.
pub const RUNNER_ENV: &str = "/etc/egress-proxy/runner.env";

/// Root's: the virtual environment, and a copy of the addon and policy.
const INSTALL_DIR: &str = "/opt/egress-proxy";

const POLICY_DIR: &str = "/opt/egress-proxy/policy";

const DENYLIST: &str = "/opt/egress-proxy/denylist.txt";

const UNIT: &str = "egress-proxy.service";

/// The proxy's own (systemd's StateDirectory and LogsDirectory): its
/// certificate authority's key stays in the first, mode 0700.
const STATE_DIR: &str = "/var/lib/egress-proxy";

/// One JSON line per request: method, host, path and decision, never
/// headers, bodies or query strings.
pub const ACCESS_LOG: &str = "/var/log/egress-proxy/access.jsonl";

/// mitmproxy writes its authority into its configuration directory on
/// first start, and so does the Rust proxy (`proxy::tls::CA_CERT`).
const CA_GENERATED: &str = "/var/lib/egress-proxy/mitmproxy-ca-cert.pem";

const RUST_CA_GENERATED: &str = "/var/lib/egress-proxy/ca-cert.pem";

/// What the sandbox user trusts: the authority alone, and the system
/// bundle plus the authority for everything that replaces the bundle.
const PUBLIC_DIR: &str = "/etc/egress-proxy";

pub const CA_CERT: &str = "/etc/egress-proxy/ca.pem";

pub const CA_BUNDLE: &str = "/etc/egress-proxy/ca-bundle.pem";

const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/certs/ca-certificates.crt",
];

const CERTIFICATE_MARKER: &str = "-----BEGIN CERTIFICATE-----";

/// HaGeZi's Threat Intelligence Feeds, medium: known malware, phishing
/// and command hosts, each with its subdomains. It lists none of the big
/// platforms, so it complements the write rules and does not replace
/// them. A fetch that fails leaves the feed empty, with a warning: it is
/// hardening, not the boundary.
const DENYLIST_REPOSITORY: &str = "https://raw.githubusercontent.com/hagezi/dns-blocklists";

const DENYLIST_FILE: &str = "wildcard/tif.medium-onlydomains.txt";

/// The feed as it was at one commit of its repository, and the SHA-256
/// of the file there: what root fetches before the network rules load is
/// what a pull request here named, not whatever the branch holds that
/// day. A file that is not that one stops the setup.
const DENYLIST_COMMIT: &str = "8f5373998c13aa4699d57762f727ae294c78d8f4";

const DENYLIST_SHA256: &str = "7d2782affed6465d3e3c34bbae68f5ea86ec385b46f95f76eb8ec387670a8db3";

/// Where the feed is fetched to, beside where it goes once it is checked.
const DENYLIST_FETCHED: &str = "/opt/egress-proxy/denylist.txt.fetched";

const FETCH_SECONDS: &str = "60";

const START_TIMEOUT: Duration = Duration::from_secs(60);

const START_POLL: Duration = Duration::from_millis(500);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

const MODE_FILE: u32 = 0o644;

const MODE_DIR: u32 = 0o755;

/// The unit's sandboxing: it needs only its state and log directories.
const UNIT_PROPERTIES: &[&str] = &[
    "User=egress-proxy",
    "Group=egress-proxy",
    "StateDirectory=egress-proxy",
    "StateDirectoryMode=0700",
    "LogsDirectory=egress-proxy",
    "LogsDirectoryMode=0750",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "RestrictSUIDSGID=yes",
    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
    "CapabilityBoundingSet=",
    "LockPersonality=yes",
    "Restart=on-failure",
    "Environment=HOME=/var/lib/egress-proxy",
    "UMask=0077",
];

/// With `sandbox setup --egress-image`, which the secure-host image's
/// entrypoint passes with its own ID, the Rust proxy runs from that image
/// in root podman under the same systemd unit, and not from the host's
/// copy ([`ProxyBinary::host`]): what filters the sandbox user's traffic
/// is then the binary the release attested, from root's image store,
/// which no step after setup can write; and its container and unit are
/// root's, which the runner's user, without root after the lock, can
/// neither stop nor signal. The process inside is still the proxy's
/// user, which the network rules let out.
const PODMAN: &str = "podman";

/// The binary that runs the Rust proxy ([`crate::proxy::run`]), as
/// [`start`] starts it: the program that calls `start` says which.
#[derive(Debug, Clone, Copy)]
pub struct ProxyBinary {
    /// Its copy on the host that only root may change.
    pub host: &'static str,
    /// Its path in the image (`secure-host/Containerfile`).
    pub image: &'static str,
    /// Its arguments before the proxy's own: the command that is the proxy.
    pub command: &'static [&'static str],
}

/// A podman image ID: the SHA-256 of its configuration, in hex.
const IMAGE_ID_LEN: usize = 64;

const LOGS_DIR: &str = "/var/log/egress-proxy";

const STATE_DIR_MODE: u32 = 0o700;

const LOGS_DIR_MODE: u32 = 0o750;

/// The unit around root podman: it cannot drop root or capabilities,
/// which podman needs; the container's options below do that for the
/// proxy.
const CONTAINER_UNIT_PROPERTIES: &[&str] = &["Restart=on-failure"];

/// Fails unless ID is a full podman image ID, which `podman run` takes
/// for that image alone and never for a name it would look up.
pub fn check_image_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == IMAGE_ID_LEN
            && id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{id:?} is not a podman image ID ({IMAGE_ID_LEN} lowercase hex digits)"
    );
    Ok(())
}

/// `podman run` of the proxy from IMAGE as UID:GID: the host's network,
/// since the rules key on the uid; no capabilities, no new privileges and
/// a read-only root; and only its policy (read-only), state and log
/// directories mounted. `Z` gives each mount the container's private
/// SELinux label, without which RHEL's policy denies the proxy its own
/// files; elsewhere podman ignores it. `--pull=never`: the image setup
/// ran from, or nothing. `--events-backend=none`: podman's journald
/// events go through go-systemd, which autobinds an unconnected abstract
/// datagram socket (`@` and five hex digits) for as long as the client,
/// the unit's main process, lives; on the host's network any user could
/// send to it, and `sandbox check` refuses that. The proxy's own log
/// records what it does.
fn container_args(image: &str, uid: u32, gid: u32, binary: &str, proxy: &[String]) -> Vec<String> {
    let mut args: Vec<String> = [
        PODMAN,
        "--events-backend=none",
        "run",
        "--rm",
        "--replace",
        "--name",
        EGRESS_USER,
        "--pull=never",
        "--network=host",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--umask=0077",
        "--env",
        "HOME=/var/lib/egress-proxy",
        "--volume",
        "/opt/egress-proxy:/opt/egress-proxy:ro,Z",
        "--volume",
        "/var/lib/egress-proxy:/var/lib/egress-proxy:Z",
        "--volume",
        "/var/log/egress-proxy:/var/log/egress-proxy:Z",
        "--entrypoint",
        binary,
    ]
    .iter()
    .map(|arg| (*arg).to_owned())
    .collect();
    args.extend([format!("--user={uid}:{gid}"), image.to_owned()]);
    // The image's binary is the entrypoint; the rest are its arguments.
    args.extend(proxy.iter().skip(1).cloned());
    args
}

/// What systemd's StateDirectory and LogsDirectory make for the unit
/// that runs as the proxy's user: its directories, its own.
fn proxy_dirs(user: &User) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for (path, mode) in [(STATE_DIR, STATE_DIR_MODE), (LOGS_DIR, LOGS_DIR_MODE)] {
        fs::create_dir_all(path).with_context(|| format!("creating {path}"))?;
        let meta = fs::symlink_metadata(path).with_context(|| format!("reading {path}"))?;
        ensure!(meta.is_dir(), "{path} is not a directory");
        std::os::unix::fs::lchown(path, Some(user.uid), Some(user.gid))
            .with_context(|| format!("giving {path} to {EGRESS_USER}"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting the mode of {path}"))?;
    }
    Ok(())
}

pub fn proxy_url() -> String {
    format!("http://{PROXY_HOST}:{PROXY_PORT}")
}

/// mitmdump's command line. It connects upstream only for a request the
/// policy allows; and without raw TCP, whatever goes through a tunnel is
/// parsed as HTTP, so other protocols fail and do not pass unseen.
fn mitmdump_args(denylist: bool) -> Vec<String> {
    let set = |option: &str, value: &str| ["--set".to_owned(), format!("{option}={value}")];
    [
        format!("{INSTALL_DIR}/bin/mitmdump"),
        "--mode".to_owned(),
        "regular".to_owned(),
        "--listen-host".to_owned(),
        PROXY_HOST.to_string(),
        "--listen-port".to_owned(),
        PROXY_PORT.to_string(),
    ]
    .into_iter()
    .chain(set("confdir", STATE_DIR))
    .chain(set("connection_strategy", "lazy"))
    .chain(set("rawtcp", "false"))
    .chain(set("flow_detail", "0"))
    .chain(set("termlog_verbosity", "warn"))
    .chain(["-s".to_owned(), format!("{POLICY_DIR}/addon.py")])
    .chain(set("egress_policy", &format!("{POLICY_DIR}/policy.toml")))
    .chain(set("egress_denylist", if denylist { DENYLIST } else { "" }))
    .chain(set("egress_log", ACCESS_LOG))
    .collect()
}

/// The Rust proxy's command line: BINARY, the binary's root-owned copy
/// that setup installs before it starts the proxy or the image's own,
/// and COMMAND, with mitmdump's settings; with TRANSPARENT
/// (`egress.write-policy`) also its listener for the runner's redirected
/// connections; and each host and port of REFUSED, which it refuses the
/// sandbox user whatever the policy says.
pub fn rust_proxy_args(
    binary: &str,
    command: &[&str],
    denylist: bool,
    transparent: bool,
    refused: &[(String, u16)],
) -> Vec<String> {
    let mut args: Vec<String> = std::iter::once(binary)
        .chain(command.iter().copied())
        .map(str::to_owned)
        .collect();
    args.extend([
        "--listen".to_owned(),
        SocketAddr::from((PROXY_HOST, PROXY_PORT)).to_string(),
        "--policy".to_owned(),
        format!("{POLICY_DIR}/policy.toml"),
        "--log".to_owned(),
        ACCESS_LOG.to_owned(),
        "--state-dir".to_owned(),
        STATE_DIR.to_owned(),
    ]);
    if denylist {
        args.extend(["--denylist".to_owned(), DENYLIST.to_owned()]);
    }
    if transparent {
        args.extend([
            "--transparent".to_owned(),
            SocketAddr::from((PROXY_HOST, TRANSPARENT_PORT)).to_string(),
        ]);
    }
    for (host, port) in refused {
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.clone()
        };
        args.extend(["--refuse".to_owned(), format!("{host}:{port}")]);
    }
    args
}

/// The authority's certificate, CA, in the system's trust store and in
/// [`RUNNER_ENV`], for every process of the runner's user after setup.
fn trust_for_runner(ca: &str) -> Result<()> {
    let (path, update) = SYSTEM_TRUST
        .iter()
        .find(|(_, update)| host::has_program(update))
        .with_context(|| {
            format!(
                "egress.write-policy needs the system's trust store, and there is no {}",
                SYSTEM_TRUST
                    .iter()
                    .map(|(_, update)| *update)
                    .collect::<Vec<_>>()
                    .join(" or ")
            )
        })?;
    let dir = Path::new(path)
        .parent()
        .context("a trust store path has a directory")?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    write(path, ca)?;
    host::run(&mut Command::new(update)).with_context(|| format!("running {update}"))?;
    write(RUNNER_ENV, &runner_env())
}

fn runner_env() -> String {
    runner_ca_vars()
        .iter()
        .map(|(name, value)| format!("{name}={value}\n"))
        .collect()
}

/// The variables of [`RUNNER_ENV`]: also what `run --runner-home` gives
/// an agent under `egress.write-policy`, whose environment it clears.
pub const fn runner_ca_vars() -> [(&'static str, &'static str); 2] {
    [
        ("NODE_EXTRA_CA_CERTS", CA_CERT),
        ("REQUESTS_CA_BUNDLE", CA_BUNDLE),
    ]
}

fn write(path: &str, content: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, content).with_context(|| format!("writing {path}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(MODE_FILE))
        .with_context(|| format!("setting the mode of {path}"))
}

fn make_dir(path: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path).with_context(|| format!("creating {path}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(MODE_DIR))
        .with_context(|| format!("setting the mode of {path}"))
}

/// The proxy's user, and root's copy of the policy; for mitmproxy also
/// the virtual environment with it pinned, and the addon. `policy`
/// replaces the write rules that come with the binary, and may not name
/// the hosts of REFUSED ([`check_front_policy`]).
fn install(policy: Option<&Path>, rust: bool, refused: &[(String, u16)]) -> Result<()> {
    if User::lookup(EGRESS_USER)?.is_none() {
        host::run(Command::new("useradd").args([
            "--system",
            "--no-create-home",
            "--home-dir",
            STATE_DIR,
            "--shell",
            "/sbin/nologin",
            EGRESS_USER,
        ]))?;
    }
    make_dir(POLICY_DIR)?;
    let rules = match policy {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("reading egress.policy {}", path.display()))?,
        None => POLICY_TOML.to_owned(),
    };
    check_front_policy(&rules, refused).context("the egress policy under inference.front")?;
    if rust {
        // The binary carries the rest, gh-aw's identifiers included.
        return write(&format!("{POLICY_DIR}/policy.toml"), &rules);
    }
    host::run(Command::new("python3").args(["-m", "venv", INSTALL_DIR])).context(
        "making mitmproxy's Python environment (egress.rust-proxy = false needs python3's venv module, python3-venv in [setup] packages)",
    )?;
    let requirements = format!("{INSTALL_DIR}/requirements.txt");
    write(&requirements, REQUIREMENTS)?;
    // Root runs this on the open network. With hashes required, pip
    // installs no file but the ones the requirements name; and a wheel is
    // unpacked, where a source archive would run its build as root, with
    // build tools that no hash covers.
    host::run(Command::new(format!("{INSTALL_DIR}/bin/pip")).args([
        "install",
        "--quiet",
        "--disable-pip-version-check",
        "--require-hashes",
        "--only-binary",
        ":all:",
        "-r",
        &requirements,
    ]))
    .context("installing mitmproxy by the hashes of egress/requirements.txt")?;
    for (name, content) in [
        ("addon.py", ADDON),
        ("policy.py", POLICY_PY),
        ("ecosystem_domains.json", ECOSYSTEMS),
        ("policy.toml", rules.as_str()),
    ] {
        write(&format!("{POLICY_DIR}/{name}"), content)?;
    }
    Ok(())
}

/// The most of the installed policy file read: 256 allowed domains and
/// the write rules fit many times over.
const MAX_POLICY_BYTES: u64 = 1 << 20;

/// The end of the one path a private run's write rules may name: git's
/// smart HTTP fetch, whose POST holds the commits it wants and has.
const GIT_FETCH_PATH: &str = "/git-upload-pack";

/// What a private run (docs/private-repositories.md) needs of the policy
/// file TEXT, as `egress/policy.py` reads it: every destination limited
/// to its `[egress] allow` list, since under reads-anywhere a GET carries
/// what the agent read to any host; and no write rule but git fetch's
/// POST to `git-upload-pack`, which a forge does not keep. Any other rule
/// is a channel to whatever its endpoint stores: the shipped GraphQL rule
/// passes a mutation that another token posts to a public issue. A file
/// the proxy would not load leaves no proxy running, so this reads only
/// the fields it checks.
pub fn check_private_policy(text: &str) -> Result<()> {
    let table: toml::Table = toml::from_str(text).context("parsing the egress policy")?;
    let mode = table
        .get("egress")
        .and_then(|egress| egress.get("mode"))
        .and_then(toml::Value::as_str);
    ensure!(
        mode == Some("allowlist"),
        "a private run needs the egress policy's domain allowlist ([egress] mode = \"allowlist\" \
         in egress.policy): under reads-anywhere a GET can carry what the agent read anywhere"
    );
    let strings = |rule: &toml::Value, key: &str| -> Option<Vec<String>> {
        rule.get(key)?
            .as_array()?
            .iter()
            .map(|value| value.as_str().map(str::to_owned))
            .collect()
    };
    let rules = match table.get("write") {
        None => &[][..],
        Some(rules) => rules
            .as_array()
            .context("[[write]] is not a list of rules")?,
    };
    for rule in rules {
        let fetch = strings(rule, "methods").is_some_and(|methods| {
            methods
                .iter()
                .all(|method| method.eq_ignore_ascii_case("POST"))
        }) && strings(rule, "paths")
            .is_some_and(|paths| paths.iter().all(|path| path.ends_with(GIT_FETCH_PATH)));
        ensure!(
            fetch,
            "a private run allows no egress write rule but git fetch's POST to *{GIT_FETCH_PATH}; \
             remove [[write]] {:?} from egress.policy",
            rule.get("name")
                .and_then(toml::Value::as_str)
                .unwrap_or("without a name")
        );
    }
    Ok(())
}

/// Checks the policy this machine's proxy enforces, root's copy that
/// `sandbox setup` installed, with [`check_private_policy`].
pub fn check_installed_private() -> Result<()> {
    let path = Path::new(POLICY_DIR).join("policy.toml");
    let bytes = crate::files::read_regular(&path, MAX_POLICY_BYTES)
        .with_context(|| format!("reading {}, which `sandbox setup` installs", path.display()))?;
    check_private_policy(&String::from_utf8(bytes).context("the egress policy is not UTF-8")?)
}

/// What `inference.front` needs of the policy file TEXT: that it names
/// none of the broker's HOSTS, in a `[[write]]` rule's hosts or under a
/// domain of its `[egress] allow` list. The proxy refuses the broker
/// whatever the policy says (`--refuse`); a policy that allows it all the
/// same says the caller expects otherwise, and would let the agent
/// register runs of its own the day that refusal were lost. Addresses
/// are compared as addresses, in any spelling; ecosystem identifiers are
/// gh-aw's public hosts and not looked at.
pub fn check_front_policy(text: &str, hosts: &[(String, u16)]) -> Result<()> {
    if hosts.is_empty() {
        return Ok(());
    }
    let table: toml::Table = toml::from_str(text).context("parsing the egress policy")?;
    let address = |host: &str| {
        host.parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical())
    };
    let broker = |named: &str| {
        let named = normalize_host(named);
        hosts.iter().find(|(host, _)| {
            let host = normalize_host(host);
            host == named || address(&host).is_some_and(|ip| address(&named) == Some(ip))
        })
    };
    let strings = |value: Option<&toml::Value>| -> Vec<String> {
        value
            .and_then(toml::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let rules = table
        .get("write")
        .and_then(toml::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for rule in rules {
        for named in strings(rule.get("hosts")) {
            if let Some((host, _)) = broker(&named) {
                bail!(
                    "[[write]] {:?} allows writes to {host}, the broker inference.front keeps \
                     from the sandbox user: remove it from that rule's hosts",
                    rule.get("name")
                        .and_then(toml::Value::as_str)
                        .unwrap_or("without a name")
                );
            }
        }
    }
    let allowed = strings(table.get("egress").and_then(|egress| egress.get("allow")));
    for domain in allowed.iter().filter(|domain| domain.contains('.')) {
        let domain = normalize_host(domain);
        let under = hosts.iter().find(|(host, _)| {
            let host = normalize_host(host);
            host == domain || host.ends_with(&format!(".{domain}"))
        });
        if let Some((host, _)) = under {
            bail!(
                "[egress] allow names {domain:?}, which covers {host}, the broker \
                 inference.front keeps from the sandbox user: allow narrower domains"
            );
        }
    }
    Ok(())
}

/// Checks the policy this machine's proxy enforces, root's copy that
/// `sandbox setup` installed, with [`check_front_policy`].
pub fn check_installed_front(hosts: &[(String, u16)]) -> Result<()> {
    let path = Path::new(POLICY_DIR).join("policy.toml");
    let bytes = crate::files::read_regular(&path, MAX_POLICY_BYTES)
        .with_context(|| format!("reading {}, which `sandbox setup` installs", path.display()))?;
    check_front_policy(
        &String::from_utf8(bytes).context("the egress policy is not UTF-8")?,
        hosts,
    )
    .with_context(|| format!("in {}", path.display()))
}

/// How many domains a feed's text holds.
fn feed_entries(text: &str) -> usize {
    text.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .count()
}

fn denylist_url() -> String {
    format!("{DENYLIST_REPOSITORY}/{DENYLIST_COMMIT}/{DENYLIST_FILE}")
}

/// Fails unless the file at `path` has the SHA-256 `pinned`.
fn check_sha256(path: &Path, pinned: &str) -> Result<()> {
    let sum = host::run(Command::new("sha256sum").arg("--").arg(path))?;
    let found = sum.split_whitespace().next().unwrap_or_default();
    ensure!(
        found == pinned,
        "{} has the SHA-256 {found}, and the pinned one is {pinned}",
        path.display()
    );
    Ok(())
}

/// Builds a feed fetch with a retry window and a per-attempt timeout.
/// The last attempt can finish after the retry window has elapsed.
fn denylist_fetch_command(url: &str) -> Command {
    let mut command = Command::new("curl");
    command.args([
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        // Retry curl's transient failures, not checksum failures.
        "--retry",
        "3",
        "--retry-max-time",
        FETCH_SECONDS,
        "--max-time",
        FETCH_SECONDS,
        "--output",
        DENYLIST_FETCHED,
        url,
    ]);
    command
}

/// Fetches the threat feed; whether there is one. A fetch that fails
/// leaves none, and a file that is not the pinned one is an error.
fn fetch_denylist() -> Result<bool> {
    let url = denylist_url();
    let fetched = host::run(&mut denylist_fetch_command(&url));
    if let Err(err) = fetched {
        eprintln!(
            "warning: the egress proxy runs without a threat feed: fetching {url} failed ({err:#})"
        );
        return Ok(false);
    }
    check_sha256(Path::new(DENYLIST_FETCHED), DENYLIST_SHA256)
        .with_context(|| format!("the threat feed fetched from {url} is not the pinned one"))?;
    let text = fs::read_to_string(DENYLIST_FETCHED)
        .with_context(|| format!("reading {DENYLIST_FETCHED}"))?;
    fs::remove_file(DENYLIST_FETCHED).with_context(|| format!("removing {DENYLIST_FETCHED}"))?;
    write(DENYLIST, &text)?;
    println!("Threat feed: {} domains from {url}", feed_entries(&text));
    Ok(true)
}

fn listening(port: u16) -> bool {
    let addr = SocketAddr::from((PROXY_HOST, port));
    TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).is_ok()
}

/// Waits until the proxy listens, on its TRANSPARENT port too, and has
/// written its authority to CA.
fn wait_started(ca: &str, transparent: bool) -> Result<()> {
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        if Path::new(ca).exists()
            && listening(PROXY_PORT)
            && (!transparent || listening(TRANSPARENT_PORT))
        {
            return Ok(());
        }
        if !host::succeeds(Command::new("systemctl").args(["is-active", "--quiet", UNIT])) {
            break;
        }
        std::thread::sleep(START_POLL);
    }
    // Why it did not start is in its journal.
    let _ = Command::new("journalctl")
        .args(["-u", UNIT, "--no-pager", "-n", "50"])
        .status();
    bail!("{UNIT} didn't start listening on {}", proxy_url())
}

/// Publishes the authority's certificate, which the proxy wrote to
/// GENERATED, alone and after the system bundle; for the RUNNER's
/// processes too under `egress.write-policy`.
fn publish_ca(generated: &str, runner: bool) -> Result<()> {
    let system = SYSTEM_BUNDLES
        .iter()
        .find(|path| Path::new(path).exists())
        .with_context(|| format!("no system CA bundle ({})", SYSTEM_BUNDLES.join(", ")))?;
    let ca = fs::read_to_string(generated).with_context(|| format!("reading {generated}"))?;
    ensure!(
        ca.contains(CERTIFICATE_MARKER),
        "{generated} holds no certificate"
    );
    let bundle = fs::read_to_string(system).with_context(|| format!("reading {system}"))?;
    make_dir(PUBLIC_DIR)?;
    write(CA_CERT, &ca)?;
    write(CA_BUNDLE, &format!("{}\n{ca}", bundle.trim_end()))?;
    if runner {
        trust_for_runner(&ca)?;
    }
    Ok(())
}

/// Installs and starts the proxy; returns its uid, which the network
/// rules name. The Rust proxy is BINARY's; with IMAGE, which setup's
/// preflight checked, it runs from that image in root podman
/// ([`PODMAN`]). REFUSED, the broker's hosts and ports under
/// `inference.front`, are refused to the sandbox user by the proxy, and
/// its policy may not name them.
pub fn start(
    egress: &Egress,
    binary: ProxyBinary,
    image: Option<&str>,
    refused: &[(String, u16)],
) -> Result<u32> {
    let (rust, transparent) = (egress.rust_proxy, egress.write_policy);
    // The configuration check's, again where it matters: mitmproxy has
    // no transparent listener, and refuses no destination of its own.
    ensure!(
        rust || !transparent,
        "egress.write-policy needs egress.rust-proxy"
    );
    ensure!(
        rust || refused.is_empty(),
        "inference.front needs egress.rust-proxy"
    );
    install(egress.policy.as_deref(), rust, refused)?;
    let user = User::lookup(EGRESS_USER)?.with_context(|| format!("no user {EGRESS_USER}"))?;
    let denylist = fetch_denylist()?;
    let (args, ca, properties) = match (rust, image) {
        (true, Some(image)) => {
            proxy_dirs(&user)?;
            let proxy =
                rust_proxy_args(binary.image, binary.command, denylist, transparent, refused);
            (
                container_args(image, user.uid, user.gid, binary.image, &proxy),
                RUST_CA_GENERATED,
                CONTAINER_UNIT_PROPERTIES,
            )
        }
        (true, None) => (
            rust_proxy_args(binary.host, binary.command, denylist, transparent, refused),
            RUST_CA_GENERATED,
            UNIT_PROPERTIES,
        ),
        (false, _) => (mitmdump_args(denylist), CA_GENERATED, UNIT_PROPERTIES),
    };
    let mut run = Command::new("systemd-run");
    run.arg(format!("--unit={UNIT}"))
        .args(["--service-type=exec", "--collect"])
        .args(
            properties
                .iter()
                .map(|property| format!("--property={property}")),
        )
        .arg("--")
        .args(args);
    host::run(&mut run).context("starting the egress proxy")?;
    wait_started(ca, transparent)?;
    publish_ca(ca, transparent)?;
    println!(
        "Egress proxy ({}) listening on {} as {EGRESS_USER}; its certificate authority is {CA_CERT}",
        match (rust, image) {
            (true, Some(image)) => format!("Rust, root podman from image {image}"),
            (true, None) => "Rust".to_owned(),
            (false, _) => "mitmproxy".to_owned(),
        },
        proxy_url()
    );
    if transparent {
        println!(
            "egress.write-policy: the runner's connections are redirected to {PROXY_HOST}:{TRANSPARENT_PORT}; the authority is in the system's trust store, and {RUNNER_ENV} is what a later step's environment needs"
        );
    }
    Ok(user.uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_runs_need_the_allowlist_and_only_git_fetch_writes() {
        let allow = "[egress]\nmode = \"allowlist\"\nallow = [\"github.com\"]\n";
        let fetch = "[[write]]\nname = \"git fetch\"\nhosts = [\"github.com\"]\n\
                     methods = [\"POST\"]\npaths = [\"/**/git-upload-pack\"]\n";
        let rule = |methods: &str, paths: &str| {
            format!(
                "[[write]]\nname = \"r\"\nhosts = [\"api.github.com\"]\n\
                 methods = {methods}\npaths = {paths}\n"
            )
        };
        // The text, and a part of the refusal if it is refused.
        let cases = [
            (POLICY_TOML.to_owned(), Some("domain allowlist")),
            (String::new(), Some("domain allowlist")),
            (
                "[egress]\nmode = \"reads-anywhere\"\n".to_owned(),
                Some("domain allowlist"),
            ),
            (
                "egress = \"allowlist\"\n".to_owned(),
                Some("domain allowlist"),
            ),
            (
                "[egress]\nmode = [\"allowlist\"]\n".to_owned(),
                Some("domain allowlist"),
            ),
            ("[egress\n".to_owned(), Some("parsing")),
            (allow.to_owned(), None),
            (
                "[egress]\nmode = \"allowlist\"\nallow = []\n".to_owned(),
                None,
            ),
            (format!("{allow}{fetch}"), None),
            (
                format!("{allow}{}", rule("[\"post\"]", "[\"/a/git-upload-pack\"]")),
                None,
            ),
            // The shipped rules but git fetch's.
            (
                POLICY_TOML.replacen(
                    "[[write]]",
                    "[egress]\nmode = \"allowlist\"\n\n[[write]]",
                    1,
                ),
                Some("\"GitHub GraphQL reads\""),
            ),
            (
                format!("{allow}{}", rule("[\"POST\"]", "[\"/graphql\"]")),
                Some("\"r\""),
            ),
            (
                format!(
                    "{allow}{}",
                    rule("[\"WEBSOCKET\"]", "[\"/git-upload-pack\"]")
                ),
                Some("\"r\""),
            ),
            (
                format!(
                    "{allow}{}",
                    rule("[\"POST\", \"PUT\"]", "[\"/git-upload-pack\"]")
                ),
                Some("\"r\""),
            ),
            (
                format!(
                    "{allow}{}",
                    rule("[\"POST\"]", "[\"/git-upload-pack\", \"/**\"]")
                ),
                Some("\"r\""),
            ),
            (
                format!("{allow}{}", rule("[\"POST\"]", "[\"/git-upload-pack-x\"]")),
                Some("\"r\""),
            ),
            (format!("{allow}{}", rule("[]", "\"/x\"")), Some("\"r\"")),
            (format!("write = 1\n{allow}"), Some("not a list")),
        ];
        for (text, want) in cases {
            match (check_private_policy(&text), want) {
                (Ok(()), None) => {}
                (Err(err), Some(want)) => {
                    assert!(format!("{err:#}").contains(want), "{text}: {err:#}");
                }
                (result, _) => panic!("{text}: {result:?}"),
            }
        }
    }

    /// The old tree's command line, argument for argument.
    #[test]
    fn mitmdump_command_line() {
        let want = "/opt/egress-proxy/bin/mitmdump --mode regular --listen-host 127.0.0.1 --listen-port 3128 \
                    --set confdir=/var/lib/egress-proxy --set connection_strategy=lazy --set rawtcp=false \
                    --set flow_detail=0 --set termlog_verbosity=warn -s /opt/egress-proxy/policy/addon.py \
                    --set egress_policy=/opt/egress-proxy/policy/policy.toml \
                    --set egress_denylist=/opt/egress-proxy/denylist.txt \
                    --set egress_log=/var/log/egress-proxy/access.jsonl";
        assert_eq!(mitmdump_args(true).join(" "), want);
        assert!(mitmdump_args(false).contains(&"egress_denylist=".to_owned()));
    }

    /// The Rust proxy takes mitmdump's settings, from the binary's copy
    /// that only root may change, and writes its authority where setup
    /// waits for it.
    #[test]
    fn rust_proxy_command_line() {
        // agentic-job's, whose command line its own test parses.
        const COPY: &str = "/usr/local/libexec/agentic-job";
        const COMMAND: &[&str] = &["sandbox", "egress-proxy"];
        let want = "/usr/local/libexec/agentic-job sandbox egress-proxy --listen 127.0.0.1:3128 \
                    --policy /opt/egress-proxy/policy/policy.toml \
                    --log /var/log/egress-proxy/access.jsonl --state-dir /var/lib/egress-proxy \
                    --denylist /opt/egress-proxy/denylist.txt";
        assert_eq!(
            rust_proxy_args(COPY, COMMAND, true, false, &[]).join(" "),
            want
        );
        let without = rust_proxy_args(COPY, COMMAND, false, false, &[]);
        assert!(!without.contains(&"--denylist".to_owned()));
        assert_eq!(
            rust_proxy_args(COPY, COMMAND, true, true, &[]).join(" "),
            format!("{want} --transparent 127.0.0.1:3129")
        );
        // Under `inference.front`, the broker's hosts, an IPv6 address
        // in brackets.
        let broker = [
            ("broker.example".to_owned(), 18080),
            ("fd7a:115c:a1e0::1".to_owned(), 443),
        ];
        assert_eq!(
            rust_proxy_args(COPY, COMMAND, true, false, &broker).join(" "),
            format!("{want} --refuse broker.example:18080 --refuse [fd7a:115c:a1e0::1]:443")
        );
        assert_eq!(
            Path::new(STATE_DIR).join(crate::proxy::tls::CA_CERT),
            Path::new(RUST_CA_GENERATED)
        );
    }

    /// Under `inference.front` the policy may name none of the broker's
    /// hosts, as a write rule's or under an allowed domain, in any
    /// spelling; other hosts, and any policy without `front`, pass.
    #[test]
    fn a_fronted_brokers_host_is_in_no_policy() {
        let hosts = [
            ("broker.example.com".to_owned(), 18080),
            ("100.64.0.1".to_owned(), 18080),
            ("fd7a:115c:a1e0::1".to_owned(), 443),
        ];
        let rule = |host: &str| {
            format!(
                "[[write]]\nname = \"r\"\nhosts = [\"github.com\", {host:?}]\n\
                 methods = [\"POST\"]\npaths = [\"/**\"]\n"
            )
        };
        let allow =
            |domain: &str| format!("[egress]\nmode = \"allowlist\"\nallow = [{domain:?}]\n");
        let cases = [
            (POLICY_TOML.to_owned(), None),
            (String::new(), None),
            (rule("other.example.com"), None),
            (rule("notbroker.example.com"), None),
            (rule("100.64.0.2"), None),
            (allow("other.example.com"), None),
            (allow("github"), None),
            (rule("broker.example.com"), Some("[[write]] \"r\"")),
            (rule("Broker.Example.COM."), Some("broker.example.com")),
            (rule("broker.example.com:18080"), Some("broker.example.com")),
            (rule("100.64.0.1"), Some("100.64.0.1")),
            (rule("::ffff:100.64.0.1"), Some("100.64.0.1")),
            (rule("[fd7a:115c:a1e0:0::1]"), Some("fd7a:115c:a1e0::1")),
            (allow("broker.example.com"), Some("[egress] allow")),
            (allow("example.com"), Some("covers broker.example.com")),
            (
                format!("{}{}", allow("github.com"), rule("broker.example.com")),
                Some("[[write]]"),
            ),
            ("[egress\n".to_owned(), Some("parsing")),
        ];
        for (text, want) in cases {
            match (check_front_policy(&text, &hosts), want) {
                (Ok(()), None) => {}
                (Err(err), Some(want)) => {
                    assert!(format!("{err:#}").contains(want), "{text}: {err:#}");
                }
                (result, _) => panic!("{text}: {result:?}"),
            }
            // Nothing is refused without `front`.
            if !text.starts_with("[egress\n") {
                check_front_policy(&text, &[]).unwrap();
            }
        }
    }

    /// What a later step appends to its job's environment: the
    /// authority, for Node and Python's requests, and nothing else.
    #[test]
    fn the_runners_environment_names_the_authority() {
        assert_eq!(
            runner_env(),
            "NODE_EXTRA_CA_CERTS=/etc/egress-proxy/ca.pem\nREQUESTS_CA_BUNDLE=/etc/egress-proxy/ca-bundle.pem\n"
        );
        assert_eq!(Path::new(RUNNER_ENV).parent(), Some(Path::new(PUBLIC_DIR)));
    }

    /// From the image only, as the proxy's user on the host's network,
    /// with nothing of the host but its labelled directories.
    #[test]
    fn the_container_runs_the_images_proxy_as_the_proxy_user() {
        let image = "0123456789abcdef".repeat(4);
        const BINARY: &str = "/agentic-job";
        let proxy = rust_proxy_args(BINARY, &["sandbox", "egress-proxy"], true, false, &[]);
        let args = container_args(&image, 991, 992, BINARY, &proxy);
        let want = format!(
            "podman --events-backend=none run --rm --replace --name egress-proxy --pull=never --network=host \
             --cap-drop=all --security-opt=no-new-privileges --read-only --umask=0077 \
             --env HOME=/var/lib/egress-proxy \
             --volume /opt/egress-proxy:/opt/egress-proxy:ro,Z \
             --volume /var/lib/egress-proxy:/var/lib/egress-proxy:Z \
             --volume /var/log/egress-proxy:/var/log/egress-proxy:Z \
             --entrypoint /agentic-job --user=991:992 {image} {}",
            proxy[1..].join(" ")
        );
        assert_eq!(args.join(" "), want);
        // Every path the proxy is given is under a mount.
        for path in [POLICY_DIR, DENYLIST, ACCESS_LOG, RUST_CA_GENERATED] {
            assert!(
                [INSTALL_DIR, STATE_DIR, LOGS_DIR]
                    .iter()
                    .any(|dir| Path::new(path).starts_with(dir)),
                "{path}"
            );
        }
        assert!(
            !CONTAINER_UNIT_PROPERTIES
                .iter()
                .any(|p| p.starts_with("User="))
        );
    }

    #[test]
    fn only_a_full_image_id_names_the_image() {
        let id = "0123456789abcdef".repeat(4);
        assert!(check_image_id(&id).is_ok());
        for bad in [
            String::new(),
            id[1..].to_owned(),
            format!("{id}0"),
            id.to_uppercase(),
            format!("sha256:{}", &id[7..]),
            "registry.example/secure-host:latest".to_owned(),
            format!("--{}", &id[2..]),
        ] {
            assert!(check_image_id(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_unit_runs_as_the_proxy_user_in_its_own_directories() {
        for (property, value) in [
            ("User", EGRESS_USER),
            ("Group", EGRESS_USER),
            ("StateDirectory", EGRESS_USER),
            ("LogsDirectory", EGRESS_USER),
            ("Environment", "HOME=/var/lib/egress-proxy"),
            ("CapabilityBoundingSet", ""),
        ] {
            let want = format!("{property}={value}");
            assert!(UNIT_PROPERTIES.contains(&want.as_str()), "{want}");
        }
        assert!(STATE_DIR.ends_with(EGRESS_USER) && ACCESS_LOG.contains(EGRESS_USER));
        assert!(Path::new(ACCESS_LOG).starts_with(LOGS_DIR));
    }

    #[test]
    fn feed_lines() {
        assert_eq!(feed_entries("# a feed\nevil.example\n\n  \nbad.test\n"), 2);
        assert_eq!(feed_entries(""), 0);
    }

    /// The checksum is of the file's bytes, and anything else is refused.
    #[test]
    fn a_feed_that_is_not_the_pinned_one_is_refused() {
        const FEED: &str = "evil.example\nbad.test\n";
        const FEED_SHA256: &str =
            "8f5c06d1ad3e9913c292e76ab4f4a799a68c85e1ec32dfda4cc87d7890032c9b";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feed.txt");
        for (content, pinned, accepted) in [
            (FEED, FEED_SHA256, true),
            ("evil.example\n", FEED_SHA256, false),
            ("evil.example\nbad.test\ngood.example\n", FEED_SHA256, false),
            ("", FEED_SHA256, false),
            (FEED, DENYLIST_SHA256, false),
        ] {
            fs::write(&path, content).unwrap();
            let checked = check_sha256(&path, pinned);
            assert_eq!(checked.is_ok(), accepted, "{content:?}: {checked:?}");
        }
        assert!(check_sha256(&dir.path().join("absent"), FEED_SHA256).is_err());
    }

    #[test]
    fn the_feed_is_fetched_at_its_pinned_commit() {
        assert_eq!(DENYLIST_COMMIT.len(), 40);
        assert_eq!(DENYLIST_SHA256.len(), 64);
        for pin in [DENYLIST_COMMIT, DENYLIST_SHA256] {
            assert!(pin.bytes().all(|byte| b"0123456789abcdef".contains(&byte)));
        }
        assert_eq!(
            denylist_url(),
            format!(
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/{DENYLIST_COMMIT}/wildcard/tif.medium-onlydomains.txt"
            )
        );
    }

    #[test]
    fn feed_fetch_sets_retry_window_and_per_attempt_timeout() {
        let url = denylist_url();
        let command = denylist_fetch_command(&url);
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        for pair in [
            ["--retry", "3"],
            ["--retry-max-time", FETCH_SECONDS],
            ["--max-time", FETCH_SECONDS],
            ["--output", DENYLIST_FETCHED],
        ] {
            assert!(args.windows(2).any(|args| args == pair), "{pair:?}");
        }
        assert_eq!(args.last(), Some(&url.as_str()));
        assert!(args.contains(&"--fail"));
    }

    fn requirements_are_pinned(text: &str) -> bool {
        let mut lines = text.lines().peekable();
        while let Some(entry) = lines.next() {
            if entry.starts_with(['#', ' ']) || entry.is_empty() {
                continue;
            }
            if !entry.contains("==")
                || !entry.ends_with(" \\")
                || !lines
                    .peek()
                    .is_some_and(|next| next.trim_start().starts_with("--hash=sha256:"))
            {
                return false;
            }
        }
        true
    }

    #[test]
    fn requirements_check_includes_the_last_line() {
        let pinned = "example==1.0 \\\n    --hash=sha256:abc";
        for (text, accepted) in [
            (pinned.to_owned(), true),
            (format!("{pinned}\nunpinned"), false),
            (format!("{pinned}\nexample==2.0 \\"), false),
            ("example==1.0\n    --hash=sha256:abc".to_owned(), false),
            ("example \\\n    --hash=sha256:abc".to_owned(), false),
        ] {
            assert_eq!(requirements_are_pinned(&text), accepted, "{text:?}");
        }
    }

    /// Every requirement is one version with hashes, as `pip
    /// --require-hashes` wants, and mitmproxy is the one requirements.in
    /// names.
    #[test]
    fn every_requirement_is_pinned_with_hashes() {
        const DIRECT: &str = include_str!("../../../egress/requirements.in");
        let is_entry = |line: &&str| !line.starts_with(['#', ' ']) && !line.is_empty();
        let lines: Vec<&str> = REQUIREMENTS.lines().collect();
        let entries: Vec<&str> = lines.iter().copied().filter(is_entry).collect();
        assert!(entries.len() > 1, "{entries:?}");
        assert!(requirements_are_pinned(REQUIREMENTS));
        let direct: Vec<&str> = DIRECT
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .collect();
        assert_eq!(direct.len(), 1, "{direct:?}");
        assert!(entries.contains(&format!("{} \\", direct[0]).as_str()));
    }

    #[test]
    fn the_files_come_with_the_binary() {
        assert!(ADDON.contains("X-Egress-Denied"));
        assert!(POLICY_PY.contains("class Policy"));
        assert!(POLICY_TOML.contains("git-upload-pack"));
        assert!(ECOSYSTEMS.contains("\"ecosystems\""));
    }
}
