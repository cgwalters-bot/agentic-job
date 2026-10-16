//! The egress proxy: mitmproxy, with the addon and policy of `egress/` at
//! the top of this repository, installed and started by `sandbox setup`.
//!
//! It is the one piece that is not Rust. The policy needs the method and
//! path of every request, so the proxy has to end TLS, and a proxy that
//! ends TLS is security-critical code that is not written again here.
//! This module is the old tree's `egress-proxy.mjs start`: the proxy
//! runs as a system user of its own, in a transient service with no
//! capabilities and a read-only system, so the sandbox user can neither
//! signal it, read its certificate authority's key, nor change its
//! policy; and the network rules keep that user off everything private.
//!
//! Setup therefore needs Python, a package index and the threat feed's
//! host on the network. What it takes from them is pinned here: every
//! package by the hashes of `egress/requirements.txt`, and the feed by a
//! commit and a checksum. docs/workflow.md says how each pin is moved.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};

use super::host::{self, User};
use crate::config::Egress;

/// The addon and what it needs, as they are in `egress/`: the binary
/// carries them, since it is all a runner gets.
const ADDON: &str = include_str!("../../../../egress/addon.py");

const POLICY_PY: &str = include_str!("../../../../egress/policy.py");

const POLICY_TOML: &str = include_str!("../../../../egress/policy.toml");

/// mitmproxy and everything it depends on, each at one version and with
/// the hashes of its files: generated from `egress/requirements.in`.
const REQUIREMENTS: &str = include_str!("../../../../egress/requirements.txt");

pub const EGRESS_USER: &str = "egress-proxy";

pub const PROXY_HOST: Ipv4Addr = Ipv4Addr::LOCALHOST;

pub const PROXY_PORT: u16 = 3128;

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
/// first start.
const CA_GENERATED: &str = "/var/lib/egress-proxy/mitmproxy-ca-cert.pem";

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

/// The proxy's user, the virtual environment with the pinned mitmproxy,
/// and root's copy of the addon and the policy. `policy` replaces the
/// write rules that come with the binary.
fn install(policy: Option<&Path>) -> Result<()> {
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
    host::run(Command::new("python3").args(["-m", "venv", INSTALL_DIR])).context(
        "making the egress proxy's Python environment (is python3's venv module installed?)",
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
    make_dir(POLICY_DIR)?;
    let rules = match policy {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("reading egress.policy {}", path.display()))?,
        None => POLICY_TOML.to_owned(),
    };
    for (name, content) in [
        ("addon.py", ADDON),
        ("policy.py", POLICY_PY),
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

fn listening() -> bool {
    let addr = SocketAddr::from((PROXY_HOST, PROXY_PORT));
    TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).is_ok()
}

/// Waits until the proxy listens and has written its authority.
fn wait_started() -> Result<()> {
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        if Path::new(CA_GENERATED).exists() && listening() {
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

/// Publishes the authority's certificate, alone and after the system
/// bundle.
fn publish_ca() -> Result<()> {
    let system = SYSTEM_BUNDLES
        .iter()
        .find(|path| Path::new(path).exists())
        .with_context(|| format!("no system CA bundle ({})", SYSTEM_BUNDLES.join(", ")))?;
    let ca = fs::read_to_string(CA_GENERATED).with_context(|| format!("reading {CA_GENERATED}"))?;
    ensure!(
        ca.contains(CERTIFICATE_MARKER),
        "{CA_GENERATED} holds no certificate"
    );
    let bundle = fs::read_to_string(system).with_context(|| format!("reading {system}"))?;
    make_dir(PUBLIC_DIR)?;
    write(CA_CERT, &ca)?;
    write(CA_BUNDLE, &format!("{}\n{ca}", bundle.trim_end()))
}

/// Installs and starts the proxy; returns its uid, which the network
/// rules name.
pub fn start(egress: &Egress) -> Result<u32> {
    install(egress.policy.as_deref())?;
    let denylist = fetch_denylist()?;
    let mut run = Command::new("systemd-run");
    run.arg(format!("--unit={UNIT}"))
        .args(["--service-type=exec", "--collect"])
        .args(
            UNIT_PROPERTIES
                .iter()
                .map(|property| format!("--property={property}")),
        )
        .arg("--")
        .args(mitmdump_args(denylist));
    host::run(&mut run).context("starting the egress proxy")?;
    wait_started()?;
    publish_ca()?;
    let user = User::lookup(EGRESS_USER)?.with_context(|| format!("no user {EGRESS_USER}"))?;
    println!(
        "Egress proxy listening on {} as {EGRESS_USER}; its certificate authority is {CA_CERT}",
        proxy_url()
    );
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
        const DIRECT: &str = include_str!("../../../../egress/requirements.in");
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
    }
}
