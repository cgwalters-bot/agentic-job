//! `run --runner-gate`: what `run --runner-home` shows of the host before
//! it starts an agent that is the runner's own user, refusing to start
//! it otherwise. Off by default.
//!
//! Such an agent is one more process of the uid of `run`, of the runner
//! and of every step of the job. Clearing its environment does not hide
//! `run`'s `/proc/PID/environ`, and `hidepid` separates uids only. So the
//! gate does not trust what setup says it did: it looks, as that uid, and
//! each check stops one way to a credential the agent may not have:
//!
//! - environment: a credential in `run`'s own environment, which the
//!   agent reads in `run`'s `/proc/PID/environ`; the agent's GitHub token
//!   (`GH_TOKEN`) among them, which no hardened run gives it until a
//!   token can be put in from outside the uid; and an SSH agent's socket,
//!   which signs for whoever connects;
//! - privileges: `sudo` or a group that is root by another name, with
//!   which every other check is moot;
//! - processes: a credential-named environment variable, the value of
//!   one of those, or a string shaped like a
//!   credential, in the environment or command line of any process of the
//!   uid it can read; and any process of the uid's subordinate uids, which
//!   the uid reaches as root of their user namespace;
//! - files: the same, or a credential store, in a fixed list of files of
//!   the runner's home (from passwd and `HOME`), the agent's home, the
//!   workspace's git configuration, the top of `RUNNER_TEMP`, and the
//!   runner's registration (`.credentials`, `.credentials_rsaparams`),
//!   whose directory must be found when a Worker runs;
//! - memory: a process of the uid whose memory a child of `run`, where the
//!   agent will be, can open (`/proc/PID/mem`, as `process_vm_readv` and
//!   ptrace are decided): Yama's, not `hidepid`'s, to refuse;
//! - worker diagnostics: `Runner.Worker`'s .NET diagnostic socket, which
//!   dumps the Worker's memory on request;
//! - egress: a connection of the uid to the metadata service, or around
//!   the egress proxy, that is not refused on the spot; and the installed
//!   ruleset not naming each of the uid's subordinate ranges with it,
//!   which no unprivileged probe can try. An empty set holds no one.
//!
//! The values looked for are those `run` knows. The shapes are a backstop
//! for the rest, not a proof. Each finding names the control that is
//! missing and where, never a value, and a check that cannot tell, such
//! as a candidate file that cannot be read, even for permission denied,
//! counts as missing. Each check that reads has a positive control: a
//! child of `run`'s and a file holding a canary, and the memory probe
//! opening its own child's. Independently, immutable Yama no-attach
//! (scope 3) is required; a scan is not process-memory isolation evidence.
//! Allocated subordinate uids are refused until live probes exist for them.

use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use secure_host::files::{self, ReadError};
use secure_host::host::{self, User};
use secure_host::{network, setup, worker_diagnostics};

use super::agent;
use super::inference::RUN_TOKEN_VAR;
use crate::config::Config;
use crate::redact;

/// A variable whose name, in capitals, ends so holds a credential.
const CREDENTIAL_SUFFIXES: &[&str] = &[
    "_TOKEN",
    "_KEY",
    "_APIKEY",
    "_SECRET",
    "_PASSWORD",
    "_PAT",
    "_CREDENTIALS",
    "_AUTH_CONFIG",
];

/// Or is named so.
const CREDENTIAL_NAMES: &[&str] = &["TOKEN", "PASSWORD", "SECRET"];

/// An SSH agent's socket: no value, but a signature for any process that
/// connects.
const SSH_AGENT_VAR: &str = "SSH_AUTH_SOCK";

/// The runner's programs, whose directory holds its registration.
const RUNNER_COMMS: &[&str] = &[worker_diagnostics::WORKER_COMM, "Runner.Listener"];
/// What a runner's directory has, relative to it.
const RUNNER_MARKER: &str = "bin/Runner.Worker";
/// Where an install of the runner is, under the runner user's home, when
/// its programs cannot be read from /proc.
const RUNNER_INSTALLS: &[&str] = &["actions-runner", "actions-runner/cached", "runner"];
/// A runner's registration, which takes its jobs: credential stores.
const REGISTRATION: &[&str] = &[".credentials", ".credentials_rsaparams"];
/// Where a runner's workspace is: `ROOT/_work/REPO` for one installed by
/// hand.
const RUNNER_WORKSPACE_VAR: &str = "RUNNER_WORKSPACE";

/// Where the egress probes connect, and how long each may take: the
/// metadata service at both addresses, which a rule refuses; and a
/// documentation address (TEST-NET-1, RFC 5737) on a port no proxy
/// takes, which the write policy refuses and nothing else answers.
const METADATA_V4: &str = "169.254.169.254:80";
const METADATA_V6: &str = "[fd00:ec2::254]:80";
const AROUND_PROXY: &str = "192.0.2.1:9";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Shorter values would match ordinary bytes (as `redact`'s literals).
const MIN_VALUE_BYTES: usize = 8;

/// Past this many processes of the uid the gate refuses rather than look
/// at some of them.
const MAX_PROCESSES: usize = 4096;

/// The most read of one `/proc` file or one file of the list.
const MAX_READ_BYTES: u64 = 1 << 20;

/// Past this many entries at the top of `RUNNER_TEMP` the gate refuses.
const MAX_TEMP_ENTRIES: usize = 256;

/// The most findings named; the rest are counted.
const MAX_FINDINGS: usize = 32;

const PROC: &str = "/proc";

/// Files of a home that are credential stores: one that the uid can read
/// and that is not empty is a finding, whatever it holds.
const STORES: &[&str] = &[
    // Refuse the directory itself, including IdentityFile indirection.
    ".ssh",
    ".git-credentials",
    // A cache serves credentials even without any persisted helper config.
    ".cache/git/credential",
    ".git-credential-cache",
    ".netrc",
    ".config/git/credentials",
    ".config/gh/hosts.yml",
    ".config/containers/auth.json",
    // Docker stores base64 username:password pairs, not token shapes.
    ".docker/config.json",
    // These also support opaque passwords or base64 authentication.
    // A shape scan cannot distinguish a safe settings file from a store.
    ".npmrc",
    ".pypirc",
    ".kube/config",
    ".aws/credentials",
    ".aws/config",
    ".aws/sso/cache",
    ".aws/cli/cache",
    ".config/gcloud/application_default_credentials.json",
    ".config/gcloud/credentials.db",
    ".config/gcloud/access_tokens.db",
    ".claude/.credentials.json",
    ".local/share/opencode/auth.json",
    agent::GITHUB_TOKEN_FILE,
];

/// Agent settings can hold opaque credentials, execute credential helpers,
/// or point at a credential-bearing local proxy. Without resolving those
/// mechanisms, a shape scan cannot establish their safety. Refuse nonempty
/// pre-existing settings; run writes its managed settings after this gate.
const OPAQUE_SETTINGS: &[&str] = &[
    ".claude.json",
    agent::CLAUDE_SETTINGS_FILE,
    ".claude/settings.local.json",
    agent::CLAUDE_ENV_FILE,
    agent::OPENCODE_CONFIG_FILE,
    ".config/opencode/opencode.jsonc",
    agent::VIBE_CONFIG_FILE,
    ".vibe/config.toml",
];

/// Git settings get an additional bounded parser check for indirection.
const SETTINGS: &[&str] = &[".gitconfig", ".config/git/config"];

/// Git's `http.extraheader`, lowered: how actions/checkout persists the
/// job token, as base64 no shape matches.
const EXTRAHEADER: &[u8] = b"extraheader";

/// Where the workflow's checkout is, and where the runner keeps files of
/// the job's steps.
const WORKSPACE_VAR: &str = "GITHUB_WORKSPACE";
const RUNNER_TEMP_VAR: &str = "RUNNER_TEMP";

/// The variable the process scan's control holds its canary in.
const CANARY_VAR: &str = "AGENTIC_JOB_GATE_CANARY";
/// How long the control's child may take to become `sleep`.
const CONTROL_TRIES: u32 = 250;
const CONTROL_WAIT: Duration = Duration::from_millis(20);

/// The memory probe: a shell that opens its own memory or exits
/// [`MEMORY_CONTROL_FAILED`], prints [`MEMORY_CONTROL`] if it opens its own
/// child's, which Yama allows below scope 2, and then each pid of its
/// arguments whose memory a subshell of its, no ancestor of any of them,
/// opens. `true`, not `:`, whose failed redirection would end the shell.
const MEMORY_PROBE: &str = "true < /proc/self/mem 2>/dev/null || exit 3
sleep 60 & child=$!
if true < \"/proc/$child/mem\" 2>/dev/null; then echo control; fi
kill \"$child\"
for pid do (true < \"/proc/$pid/mem\") 2>/dev/null && echo \"$pid\"; done
exit 0";
const MEMORY_CONTROL_FAILED: i32 = 3;
const MEMORY_CONTROL: &str = "control";
const PTRACE_SCOPE: &str = "/proc/sys/kernel/yama/ptrace_scope";
const CORE_PATTERN: &str = "/proc/sys/kernel/core_pattern";
/// The Yama scopes under which no process may open its child's memory.
const CLOSED_SCOPES: &[&str] = &["2", "3"];

/// A file the gate reads, with whether it is a credential store.
type ToScan = (PathBuf, bool);

/// The credentials `run` was started with, by variable name, and the
/// values the agent may hold anyway (its own run token).
#[derive(Debug, Default)]
pub struct Known {
    credentials: Vec<(String, Vec<u8>)>,
    allowed: Vec<Vec<u8>>,
}

impl Known {
    /// The non-empty variables of ENV named like a credential, but
    /// ALLOWED_VAR, whose value is the agent's.
    pub fn from_env(
        env: impl IntoIterator<Item = (OsString, OsString)>,
        allowed_var: &str,
    ) -> Self {
        let mut known = Self::default();
        for (name, value) in env {
            let value = value.as_bytes().to_vec();
            let name = name.to_string_lossy().into_owned();
            if value.is_empty() {
                continue;
            }
            if name == allowed_var {
                known.allowed.push(value);
            } else if credential_name(&name) {
                known.credentials.push((name, value));
            }
        }
        known.credentials.sort();
        known
    }

    /// One credential, NAME's VALUE: a positive control's canary.
    fn one(name: &str, value: &str) -> Self {
        Self {
            credentials: vec![(name.to_owned(), value.as_bytes().to_vec())],
            allowed: Vec::new(),
        }
    }

    /// What of a credential BYTES holds, said without its value: a known
    /// value by its variable's name, else the first credential shape in
    /// what is left once the allowed values are taken out.
    fn find(&self, bytes: &[u8]) -> Option<String> {
        let found = self.credentials.iter().find(|(_, value)| {
            value.len() >= MIN_VALUE_BYTES && secure_host::check::contains(bytes, value)
        });
        if let Some((name, _)) = found {
            return Some(match name.as_str() {
                CANARY_VAR => format!("the value of {CANARY_VAR}"),
                agent::GITHUB_TOKEN_VAR => format!("the value of {}", agent::GITHUB_TOKEN_VAR),
                _ => "a known credential value".to_owned(),
            });
        }
        let rest = self
            .allowed
            .iter()
            .filter(|value| value.len() >= MIN_VALUE_BYTES)
            .fold(bytes.to_vec(), |rest, value| without(&rest, value));
        redact::secret_shapes(&rest)
            .first()
            .map(|shape| format!("a string shaped like a credential ({shape})"))
    }

    /// Other processes may hold credentials run was never given. Only the
    /// exact run token run knows is allowed, under its own variable name.
    fn find_environment(&self, bytes: &[u8]) -> Option<String> {
        for entry in bytes.split(|byte| *byte == 0) {
            let Some(at) = entry.iter().position(|byte| *byte == b'=') else {
                continue;
            };
            let (name, value) = (&entry[..at], &entry[at + 1..]);
            if value.is_empty() {
                continue;
            }
            if name == RUN_TOKEN_VAR.as_bytes()
                && self.allowed.iter().any(|allowed| allowed == value)
            {
                continue;
            }
            let name = String::from_utf8_lossy(name);
            if credential_name(&name) || name == SSH_AGENT_VAR {
                return Some("a credential-named variable or SSH agent socket".to_owned());
            }
        }
        self.find(bytes)
    }
}

fn credential_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    CREDENTIAL_NAMES.contains(&upper.as_str())
        || CREDENTIAL_SUFFIXES
            .iter()
            .any(|suffix| upper.ends_with(suffix))
}

/// BYTES with every NEEDLE taken out.
fn without(bytes: &[u8], needle: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if !needle.is_empty() && bytes[at..].starts_with(needle) {
            at += needle.len();
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    out
}

/// Refuses to start the agent as this user unless every check of the
/// module passes, naming each control that is missing.
pub fn check(config: &Config, agent_home: &Path) -> Result<()> {
    let known = Known::from_env(std::env::vars_os(), RUN_TOKEN_VAR);
    let user = User::current()?;
    let proc = Path::new(PROC);
    let mut missing = environment(&known, std::process::id());
    missing.extend(configured_environment(config));
    if std::env::var_os(SSH_AGENT_VAR).is_some_and(|socket| !socket.is_empty()) {
        missing.push(format!(
            "{SSH_AGENT_VAR} is in run's environment: the agent could have that SSH agent sign \
             for it"
        ));
    }
    missing.extend(privileges()?);
    // No file is no subordinate uid.
    let subuid = match std::fs::read_to_string(setup::SUBUID) {
        Err(err) if err.kind() == ErrorKind::NotFound => String::new(),
        read => read.with_context(|| format!("reading {}", setup::SUBUID))?,
    };
    let ranges = setup::subordinate_ranges(&user, &subuid);
    missing.extend(egress(config, read_rules(), &ranges, &user));
    missing.extend(egress_probes());
    if secure_host::check::runner_write_readiness().is_err() {
        missing.push(
            "live HTTP/HTTPS write-policy enforcement was not demonstrated with a successful \
             read control and the proxy's POST refusal (egress.write-policy)"
                .to_owned(),
        );
    }
    missing.extend(subordinate_readiness(&ranges));
    missing.extend(process_control(proc)?);
    let owners = owners(proc)?;
    let pids = of_uid(&owners, user.uid)?;
    missing.extend(subordinate_processes(proc, &owners, &ranges));
    missing.extend(processes(proc, &pids, &known)?);
    missing.extend(memory(proc, &pids)?);
    missing.extend(worker_sockets()?);
    missing.extend(file_control()?);
    let (files, unlocated) = files_to_scan(proc, &owners, &user, agent_home)?;
    missing.extend(unlocated);
    missing.extend(scan_files(&files, &known));
    if missing.is_empty() {
        eprintln!(
            "note: run --runner-gate: {} processes of {} and the files it reads hold no credential \
             run knows of or one shaped like it, and none of their memory opens to a child",
            pids.len(),
            user.name
        );
        return Ok(());
    }
    let more = missing.len().saturating_sub(MAX_FINDINGS);
    missing.truncate(MAX_FINDINGS);
    if more > 0 {
        missing.push(format!("{more} more"));
    }
    bail!(
        "run --runner-gate refuses to start the agent as {}, which would reach what it may not: \
         {}",
        user.name,
        missing.join("; ")
    )
}

/// `Sandbox::own` applies host.env after its fixed environment. Check those
/// effective launch additions too: env_clear is not credential exclusion,
/// and relocation can invalidate the home/configuration inventory above.
fn configured_environment(config: &Config) -> Option<String> {
    config.sandbox.env.iter().any(|(name, value)| {
        let upper = name.to_ascii_uppercase();
        (!value.is_empty() && (credential_name(name) || upper == SSH_AGENT_VAR))
            || upper == "HOME"
            || ["XDG_", "GIT_CONFIG", "CLAUDE_", "OPENCODE_", "VIBE_"]
                .iter()
                .any(|prefix| upper.starts_with(prefix))
    }).then(|| {
        "host.env contains unsupported credential or agent-configuration overrides; the effective \
         launch environment is not covered by the readiness inventory".to_owned()
    })
}

/// One finding for each credential of KNOWN: `run` (PID) holds it in the
/// environment it was started with, which the agent can read.
fn environment(known: &Known, pid: u32) -> Vec<String> {
    known
        .credentials
        .iter()
        .map(|(name, _)| {
            if name == agent::GITHUB_TOKEN_VAR {
                format!(
                    "{name}, the agent's GitHub token, is in run's environment: a hardened run \
                     gives the agent none (the run action's github-token input) until one can be \
                     put in from outside its uid"
                )
            } else {
                format!(
                    "a credential-named variable is in run's environment, which the agent reads at /proc/{pid}/environ: \
                     give it to no step that starts run"
                )
            }
        })
        .collect()
}

/// The installed ruleset, if it is root's alone: otherwise its text says
/// nothing of what was loaded.
fn read_rules() -> Result<String> {
    let path = Path::new(network::RULES_FILE);
    host::roots_alone(path)?;
    let bytes = files::read_regular(path, MAX_READ_BYTES)
        .map_err(|err| anyhow::anyhow!("{} {err}", path.display()))?;
    String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))
}

/// The elements of the set named SET in RULES, as `network` writes them
/// on one line; None for no such set, empty for one that names no uid.
fn set_elements<'a>(rules: &'a str, set: &str) -> Option<Vec<&'a str>> {
    let head = format!("set {set} {{");
    let line = rules
        .lines()
        .find(|line| line.trim_start().starts_with(&head))?;
    let Some((_, elements)) = line.split_once("elements = {") else {
        return Some(Vec::new());
    };
    let elements = elements.split_once('}').map_or("", |(inside, _)| inside);
    Some(
        elements
            .split(',')
            .map(str::trim)
            .filter(|element| !element.is_empty())
            .collect(),
    )
}

/// Root by another name: `sudo`, membership of a group that is, or a
/// container daemon's socket that answers.
fn privileges() -> Result<Vec<String>> {
    const EXTRA_ROOT_GROUPS: &[&str] = &["root", "wheel", "sudo", "admin"];
    let mut missing = Vec::new();
    if host::has_program("sudo") {
        // The exact grant is still root access if the uid can replace the
        // helper or any ancestor. Setup's past check is not readiness now.
        missing.extend(helper_ownership(Path::new(secure_host::helper::SELF_COPY)));
        // A failed `sudo -n true` says nothing about command-specific
        // grants (bash, for example). Require sudo's complete listing to
        // end with setup's deny-all and exact helper-only grant instead.
        let listing = Command::new("sudo")
            .args(["-n", "-l"])
            .env("PATH", host::root_path())
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .context("running sudo -n -l")?;
        if !listing.status.success() || !helper_only_sudo(&listing.stdout) {
            missing.push(
                "sudo authorization is not shown to end with the deny-all and helper-only \
                 policy (sandbox.lock-runner)"
                    .to_owned(),
            );
        }
    }
    let output = Command::new("id")
        .arg("-Gn")
        .env("PATH", host::root_path())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("running id -Gn")?;
    if output.status.success() {
        let groups = String::from_utf8_lossy(&output.stdout);
        for group in groups.split_whitespace().filter(|group| {
            EXTRA_ROOT_GROUPS.contains(group)
                || setup::ROOT_GROUPS.iter().any(|root| root.name == *group)
        }) {
            missing.push(format!(
                "the uid is in the group {group}, which is root by another name"
            ));
        }
    } else {
        missing.push("id -Gn failed, so the uid's groups are not shown".to_owned());
    }
    let sockets: std::collections::BTreeSet<_> = setup::ROOT_GROUPS
        .iter()
        .flat_map(|group| group.sockets.iter().copied())
        .collect();
    for socket in sockets {
        if std::os::unix::net::UnixStream::connect(socket).is_ok() {
            missing.push(format!(
                "{socket} answers the uid, and its daemon grants root-equivalent access"
            ));
        }
    }
    Ok(missing)
}

fn helper_ownership(path: &Path) -> Vec<String> {
    match host::roots_alone(path) {
        Ok(()) => Vec::new(),
        Err(_) => {
            vec!["the sudo helper and its ancestors are not shown to be root's alone".to_owned()]
        }
    }
}

fn subordinate_readiness(ranges: &[String]) -> Vec<String> {
    if ranges.is_empty() {
        Vec::new()
    } else {
        vec![
            "allocated subordinate uids have no live metadata/egress enforcement probe: \
             saved rules are not active enforcement evidence; use a runner without subordinate uids"
                .to_owned(),
        ]
    }
}

/// Read the entire command section, not just lines starting with `(`:
/// otherwise an extra command on a continuation could escape inspection.
/// Unknown or wrapped output is refused, never interpreted as no grant.
fn helper_only_sudo(listing: &[u8]) -> bool {
    let Ok(listing) = std::str::from_utf8(listing) else {
        return false;
    };
    let mut lines = listing.lines().map(str::trim);
    if !lines.any(|line| {
        line.starts_with("User ")
            && line.contains(" may run the following commands on ")
            && line.ends_with(':')
    }) {
        return false;
    }
    let rules: Vec<String> = lines
        .filter(|line| !line.is_empty())
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    rules.iter().all(|rule| rule.starts_with('(')) && rules.ends_with(&setup::runner_sudo_rules())
}

/// The uid's own connections: to the metadata service at both addresses,
/// refused by a rule or with no route; around the egress proxy, refused by
/// the write policy's rule and nothing else. Anything else, a timeout
/// included, shows no rule.
fn egress_probes() -> Vec<String> {
    let ipv6_disabled = secure_host::check::kernel_ipv6_disabled();
    egress_probe_findings(ipv6_disabled, |address| {
        let address = address
            .parse::<std::net::SocketAddr>()
            .map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))?;
        std::net::TcpStream::connect_timeout(&address, CONNECT_TIMEOUT).map(|_| ())
    })
}

fn egress_probe_findings(
    ipv6_disabled: bool,
    mut connect: impl FnMut(&str) -> std::io::Result<()>,
) -> Vec<String> {
    use ErrorKind::{ConnectionRefused, HostUnreachable, NetworkUnreachable};
    let metadata: &[ErrorKind] = &[ConnectionRefused, HostUnreachable, NetworkUnreachable];
    let probes: [(&str, &str, &[ErrorKind]); 3] = [
        (
            METADATA_V4,
            "the cloud metadata service (sandbox.deny-runner-metadata)",
            metadata,
        ),
        (
            METADATA_V6,
            "the cloud metadata service over IPv6 (sandbox.deny-runner-metadata)",
            metadata,
        ),
        (
            AROUND_PROXY,
            "an address around the egress proxy (egress.write-policy)",
            &[ConnectionRefused],
        ),
    ];
    probes
        .into_iter()
        // Only the kernel's boot-disable evidence, never a failed remote
        // connection, makes the IPv6 metadata probe inapplicable.
        .filter(|(address, _, _)| !ipv6_disabled || *address != METADATA_V6)
        .filter_map(|(address, what, refused)| {
            let result = connect(address);
            match result {
                Err(err) if refused.contains(&err.kind()) => None,
                Ok(_) => Some(format!("the uid connects to {what} at {address}")),
                Err(err) => Some(format!(
                    "the uid's connection to {what} at {address} was not refused on the spot \
                     ({})",
                    err.kind()
                )),
            }
        })
        .collect()
}

/// Whether the installed RULES hold USER, and each of its subordinate
/// RANGES, to the egress proxy's write policy and refuse them the metadata
/// service, as setup writes the rules under `egress.write-policy` and
/// `sandbox.deny-runner-metadata`. The file is written before it is
/// loaded: [`egress_probes`] shows the uid's own rules are.
fn egress(config: &Config, rules: Result<String>, ranges: &[String], user: &User) -> Vec<String> {
    let mut missing = Vec::new();
    if !(config.egress.proxy && config.egress.write_policy) {
        missing.push(format!(
            "egress.write-policy is off: the egress proxy's rules hold no process of {}, so the \
             agent's network is open",
            user.name
        ));
    }
    let rules = match rules {
        Ok(rules) => rules,
        Err(err) => {
            missing.push(format!(
                "the installed ruleset cannot show what holds {}: {err:#}",
                user.name
            ));
            return missing;
        }
    };
    let uids: Vec<String> = std::iter::once(user.uid.to_string())
        .chain(ranges.iter().cloned())
        .collect();
    let checks: [(&str, &[&str], &str); 2] = [
        (
            "write_policy_uids",
            &["meta skuid @write_policy_uids counter reject"],
            "held to the egress proxy's write policy (egress.write-policy)",
        ),
        (
            "runner_uids",
            &[
                "meta skuid @runner_uids ip daddr 169.254.169.254 counter reject",
                "meta skuid @runner_uids ip6 daddr fd00:ec2::254 counter reject",
            ],
            "refused the cloud metadata service (sandbox.deny-runner-metadata)",
        ),
    ];
    for (set, set_rules, what) in checks {
        let elements = set_elements(&rules, set).unwrap_or_default();
        let unheld: Vec<&str> = uids
            .iter()
            .map(String::as_str)
            .filter(|uid| !elements.contains(uid))
            .collect();
        let has_rule = set_rules
            .iter()
            .all(|rule| rules.lines().any(|line| line.trim() == *rule));
        // A set without its rule holds none of them.
        let named = match (unheld.is_empty(), has_rule) {
            (true, true) => continue,
            (false, true) => unheld.join(", "),
            (_, false) => uids.join(", "),
        };
        missing.push(format!(
            "the installed ruleset {} leaves uid {named} of {} not {what}",
            network::RULES_FILE,
            user.name
        ));
    }
    missing
}

/// Each process this one sees under PROC, with the owner of its directory.
/// A process that is not dumpable (a setuid program, or one that cleared
/// the flag) shows root's there, though its world-readable command line is
/// still the agent's to read, so a root-owned directory is attributed to
/// the process's real uid instead.
fn owners(proc: &Path) -> Result<Vec<(u32, u32)>> {
    let mut owners = Vec::new();
    for entry in std::fs::read_dir(proc).with_context(|| format!("listing {}", proc.display()))? {
        let entry = entry.with_context(|| format!("listing {}", proc.display()))?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        // Gone since it was listed.
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            Err(err) if gone(&err) => continue,
            Err(_) => bail!("run --runner-gate: cannot determine a process owner"),
        };
        ensure!(
            owners.len() < MAX_PROCESSES,
            "run --runner-gate: too many procfs entries to inspect"
        );
        let owner = if meta.uid() == 0 {
            let status = proc.join(pid.to_string()).join("status");
            match files::read_regular(&status, MAX_READ_BYTES) {
                Ok(bytes) => real_uid(&bytes).with_context(|| {
                    format!("run --runner-gate: process {pid}'s status names no real uid")
                })?,
                Err(ReadError::Io(err)) if gone(&err) => continue,
                Err(err) => {
                    bail!(
                        "run --runner-gate: process {pid}'s status {err}, so its owner is unknown"
                    )
                }
            }
        } else {
            meta.uid()
        };
        owners.push((pid, owner));
    }
    owners.sort_unstable();
    Ok(owners)
}

/// The real uid in a procfs STATUS file's `Uid:` line.
fn real_uid(status: &[u8]) -> Option<u32> {
    // Bytes, not text: the `Name:` line is the process's own choice.
    let line = status
        .split(|&byte| byte == b'\n')
        .find_map(|line| line.strip_prefix(b"Uid:"))?;
    std::str::from_utf8(line)
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// The pids of OWNERS that are UID's.
fn of_uid(owners: &[(u32, u32)], uid: u32) -> Result<Vec<u32>> {
    let pids: Vec<u32> = owners
        .iter()
        .filter(|(_, owner)| *owner == uid)
        .map(|(pid, _)| *pid)
        .collect();
    if pids.len() > MAX_PROCESSES {
        bail!(
            "run --runner-gate: {} processes of uid {uid}, over {MAX_PROCESSES}, are more than it \
             looks through",
            pids.len()
        );
    }
    Ok(pids)
}

/// A finding for each process of OWNERS in one of RANGES (`START-END`),
/// the uid's subordinate uids: as root of their user namespace (`podman
/// unshare`) the uid reads their environment and memory, which neither
/// Yama nor the scans here see.
fn subordinate_processes(_proc: &Path, owners: &[(u32, u32)], ranges: &[String]) -> Vec<String> {
    let bounds: Vec<(u32, u32)> = ranges
        .iter()
        .filter_map(|range| {
            let (start, end) = range.split_once('-')?;
            Some((start.parse().ok()?, end.parse().ok()?))
        })
        .collect();
    owners
        .iter()
        .filter(|(_, uid)| bounds.iter().any(|(start, end)| start <= uid && uid <= end))
        .map(|(pid, uid)| {
            format!(
                "process {pid} runs as subordinate uid {uid}, which the uid reaches as root \
                 of its user namespace: end it before run"
            )
        })
        .collect()
}

/// A process's name, as it set it.
fn raw_comm(proc: &Path, pid: u32) -> String {
    std::fs::read_to_string(proc.join(pid.to_string()).join("comm"))
        .map(|name| name.trim_end().to_owned())
        .unwrap_or_default()
}

/// Whether ERR is a process that has ended.
fn gone(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::NotFound
        || err.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error())
}

/// A finding for each of PIDS whose environment or command line holds a
/// credential of KNOWN or one's shape. One the kernel refuses this uid
/// (the runner-read rule, or a process that is not dumpable) is refused
/// the agent too; one that ended holds nothing.
fn processes(proc: &Path, pids: &[u32], known: &Known) -> Result<Vec<String>> {
    let mut missing = Vec::new();
    for &pid in pids {
        for part in ["environ", "cmdline"] {
            let path = proc.join(pid.to_string()).join(part);
            match files::read_regular(&path, MAX_READ_BYTES) {
                Ok(bytes) => {
                    let found = if part == "environ" {
                        known.find_environment(&bytes)
                    } else {
                        known.find(&bytes)
                    };
                    if let Some(what) = found {
                        missing.push(format!(
                            "process {pid} holds {what} in its {part}, which the agent can read"
                        ));
                    }
                }
                Err(ReadError::Io(err)) if gone(&err) => {}
                Err(ReadError::Io(err)) if err.kind() == ErrorKind::PermissionDenied => {}
                Err(err) => missing.push(format!(
                    "process {pid}'s {part} {err}, so it cannot be shown to hold no credential"
                )),
            }
        }
    }
    Ok(missing)
}

/// The process scan's positive control: a child of this process's with a
/// canary in its environment, which [`processes`] must find there.
fn process_control(proc: &Path) -> Result<Vec<String>> {
    let canary = secure_host::check::canary()?;
    let mut child = Command::new("sleep")
        .arg("60")
        .env_clear()
        .env(CANARY_VAR, &canary)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("starting the process scan's control, sleep")?;
    let pid = child.id();
    let found = became_sleep(proc, pid)
        && processes(proc, &[pid], &Known::one(CANARY_VAR, &canary))?
            .iter()
            .any(|finding| finding.contains(CANARY_VAR));
    // It may have ended already; either way it is waited for.
    let _ = child.kill();
    let _ = child.wait();
    Ok(if found {
        Vec::new()
    } else {
        vec![format!(
            "the process scan's control: a canary in the environment of its own child {pid} was \
             not found, so the scan shows nothing"
        )]
    })
}

/// Whether the child PID has exec'd `sleep`: until then its environment
/// and command line are its parent's.
fn became_sleep(proc: &Path, pid: u32) -> bool {
    (0..CONTROL_TRIES).any(|_| {
        let done = raw_comm(proc, pid) == "sleep";
        if !done {
            std::thread::sleep(CONTROL_WAIT);
        }
        done
    })
}

/// A finding for each of PIDS whose memory a child of this process's can
/// open, from [`MEMORY_PROBE`]'s answer; one if its control failed.
fn memory(proc: &Path, pids: &[u32]) -> Result<Vec<String>> {
    let output = Command::new("sh")
        .args(["-c", MEMORY_PROBE, "sh"])
        .args(pids.iter().map(u32::to_string))
        .env_clear()
        .env("PATH", host::root_path())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("running the memory probe, sh")?;
    let scope = std::fs::read_to_string(PTRACE_SCOPE)
        .map_or_else(|_| "not there".to_owned(), |scope| scope.trim().to_owned());
    let mut missing = memory_findings(proc, output.status.code(), &output.stdout, pids, &scope)?;
    // ptrace restrictions do not stop the uid forcing another process to
    // dump secrets to a readable core file or to systemd-coredump.
    let core = std::fs::read_to_string(CORE_PATTERN).ok();
    if core.as_deref().map(str::trim) != Some("|/bin/false") {
        missing.push(
            "same-uid forced core dumps are not shown discarded (kernel.core_pattern)".to_owned(),
        );
    }
    Ok(missing)
}

/// [`memory`]'s findings from the probe's exit CODE and STDOUT, under
/// Yama's SCOPE.
fn memory_findings(
    _proc: &Path,
    code: Option<i32>,
    stdout: &[u8],
    pids: &[u32],
    scope: &str,
) -> Result<Vec<String>> {
    match code {
        Some(0) => {}
        Some(MEMORY_CONTROL_FAILED) => {
            return Ok(vec![
                "the memory probe's control: it could not open its own memory, so its answer \
                 shows nothing"
                    .to_owned(),
            ]);
        }
        other => {
            return Ok(vec![format!(
                "the memory probe ended with {other:?}, so the memory of the uid's processes \
                 is not shown closed"
            )]);
        }
    }
    let text = String::from_utf8_lossy(stdout);
    let mut missing = Vec::new();
    // A sibling's failed open says nothing about a future PR_SET_PTRACER
    // grant or a child that inherited supervisor secrets. Scope 3 is
    // independent kernel evidence: no attach, immutable until reboot.
    if scope != "3" {
        missing.push(
            "same-uid process-memory isolation is unproven: require kernel.yama.ptrace_scope=3 \
             (immutable no-attach); a credential shape scan or sibling probe is not evidence"
                .to_owned(),
        );
    }
    let mut control = false;
    for line in text.lines() {
        if line == MEMORY_CONTROL {
            control = true;
            continue;
        }
        let pid: u32 = line
            .parse()
            .with_context(|| format!("the memory probe printed {line:?}, not a pid"))?;
        if !pids.contains(&pid) {
            bail!("the memory probe printed pid {pid}, which it was not given");
        }
        missing.push(format!(
            "process {pid}'s memory opens to a child of run, as it would to the agent \
             (kernel.yama.ptrace_scope is {scope})"
        ));
    }
    // Above scope 1 no process opens even its child's memory.
    if !control && !CLOSED_SCOPES.contains(&scope) {
        missing.push(format!(
            "the memory probe's control: it could not open its own child's memory, which \
             kernel.yama.ptrace_scope {scope} allows, so its answer shows nothing"
        ));
    }
    Ok(missing)
}

/// A finding for each diagnostic socket of a `Runner.Worker` that a step
/// can still connect to.
fn worker_sockets() -> Result<Vec<String>> {
    let pids = worker_diagnostics::worker_pids()?;
    Ok(socket_findings(worker_diagnostics::linked_sockets(&pids)))
}

fn socket_findings(sockets: Result<Vec<PathBuf>>) -> Vec<String> {
    // The discovery error may contain a secret-bearing socket pathname.
    let Ok(sockets) = sockets else {
        return vec![
            "Worker diagnostic sockets cannot be inspected; isolation is unproven".to_owned(),
        ];
    };
    sockets
        .into_iter()
        .map(|_| {
            "a linked Runner.Worker .NET diagnostic socket dumps its memory for any \
                 process of its uid (sandbox.unlink-worker-diagnostics)"
                .to_owned()
        })
        .collect()
}

/// The files the gate reads: [`STORES`] and [`SETTINGS`] of USER's home,
/// by passwd and by `HOME`, and of AGENT_HOME; the workspace's git
/// configuration; the files and links at the top of `RUNNER_TEMP`; and
/// the [`REGISTRATION`] of each runner directory [`runner_dirs`] finds
/// among OWNERS. Each with whether it is a store; and a finding if any
/// running runner's directory was not found.
fn files_to_scan(
    proc: &Path,
    owners: &[(u32, u32)],
    user: &User,
    agent_home: &Path,
) -> Result<(Vec<ToScan>, Option<String>)> {
    let mut homes: Vec<PathBuf> = std::iter::once(user.home.clone())
        .chain(std::env::var_os("HOME").map(PathBuf::from))
        .chain(std::iter::once(agent_home.to_owned()))
        .collect();
    homes.dedup();
    let mut paths = Vec::new();
    for home in &homes {
        paths.extend(STORES.iter().map(|file| (home.join(file), true)));
        paths.extend(OPAQUE_SETTINGS.iter().map(|file| (home.join(file), true)));
        paths.extend(SETTINGS.iter().map(|file| (home.join(file), false)));
    }
    let (dirs, unlocated) = runner_dirs(proc, owners, &user.home);
    for dir in &dirs {
        // An install's `cached` copy keeps the registration a level up.
        for dir in std::iter::once(dir.as_path()).chain(dir.parent()) {
            paths.extend(REGISTRATION.iter().map(|file| (dir.join(file), true)));
        }
    }
    if let Some(workspace) = std::env::var_os(WORKSPACE_VAR) {
        // `actions/checkout`'s `path:` puts a checkout, and the token it
        // persists, in a directory of the workspace; deeper ones are not
        // found.
        let workspace = Path::new(&workspace);
        let checkouts = top_entries(workspace, std::fs::FileType::is_dir)?;
        for checkout in std::iter::once(workspace).chain(checkouts.iter().map(PathBuf::as_path)) {
            paths.extend(checkout_configs(checkout)?);
        }
    }
    if let Some(temp) = std::env::var_os(RUNNER_TEMP_VAR) {
        paths.extend(
            top_files(Path::new(&temp))?
                .into_iter()
                .map(|path| (path, false)),
        );
    }
    paths.sort();
    paths.dedup();
    Ok((paths, unlocated))
}

/// The Git configurations to scan of a checkout in DIR, if it has one.
fn checkout_configs(dir: &Path) -> Result<Vec<ToScan>> {
    let git = dir.join(".git");
    // Do not execute Git against untrusted repository configuration.
    // Gitfiles (separate gitdirs and linked worktrees), symlinks and
    // commondir indirection need resolution before they can be scanned;
    // until supported, refuse them rather than mistaking ENOTDIR for
    // an absent config. Also scan per-worktree config in ordinary repos.
    match std::fs::symlink_metadata(&git) {
        Ok(meta) => ensure!(
            meta.is_dir(),
            "run --runner-gate: unsupported Git layout; cannot establish the effective credential configuration"
        ),
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).context("inspecting workspace Git layout"),
    }
    // Each submodule's own configuration, where checkout persists the
    // token too, is not resolved either.
    for indirection in ["commondir", "modules"] {
        match std::fs::symlink_metadata(git.join(indirection)) {
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            _ => bail!(
                "run --runner-gate: unsupported Git layout ({indirection}); cannot establish the \
                 common credential configuration"
            ),
        }
    }
    Ok(vec![
        (git.join("config"), false),
        (git.join("config.worktree"), false),
    ])
}

/// The candidate directories of the runner: those of
/// the programs of OWNERS named in [`RUNNER_COMMS`] where `/proc` shows
/// them, the root of `RUNNER_WORKSPACE`, and [`RUNNER_INSTALLS`] under
/// HOME with [`RUNNER_MARKER`]. Explicitly discovered candidates are kept
/// even without a marker; unknown marker status always refuses. A fallback
/// installation does not identify a running process:
/// refuse each runner whose executable cannot establish its directory,
/// even when another (possibly stale) installation was found.
fn runner_dirs(proc: &Path, owners: &[(u32, u32)], home: &Path) -> (Vec<PathBuf>, Option<String>) {
    let mut unresolved = false;
    let mut dirs = Vec::new();
    for (pid, _) in owners {
        if !RUNNER_COMMS.contains(&raw_comm(proc, *pid).as_str()) {
            continue;
        }
        // `ROOT/bin/Runner.Worker`; refused under the runner-read rule.
        if let Ok(exe) = std::fs::read_link(proc.join(pid.to_string()).join("exe"))
            && let Some(root) = exe.parent().and_then(Path::parent)
        {
            dirs.push(root.to_owned());
        } else {
            unresolved = true;
        }
    }
    if let Some(workspace) = std::env::var_os(RUNNER_WORKSPACE_VAR) {
        let work = Path::new(&workspace).parent();
        if let Some(root) = work
            .filter(|work| work.file_name().is_some_and(|name| name == "_work"))
            .and_then(Path::parent)
        {
            dirs.push(root.to_owned());
        }
    }
    let mut findings = Vec::new();
    for dir in &dirs {
        if let Err(err) = std::fs::symlink_metadata(dir.join(RUNNER_MARKER))
            && err.kind() != ErrorKind::NotFound
        {
            findings.push(format!(
                "runner marker cannot be inspected ({}), so its registration is not shown out of the uid's reach",
                err.kind()
            ));
        }
    }
    for dir in RUNNER_INSTALLS.iter().map(|install| home.join(install)) {
        match std::fs::symlink_metadata(dir.join(RUNNER_MARKER)) {
            Ok(_) => dirs.push(dir),
            Err(err) if matches!(err.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {}
            Err(err) => {
                findings.push(format!(
                    "runner marker cannot be inspected ({}), so its registration is not shown out of the uid's reach",
                    err.kind()
                ));
                dirs.push(dir);
            }
        }
    }
    dirs.sort();
    dirs.dedup();
    if unresolved {
        findings.push(format!(
            "a {} runs, but its directory was not found for that process, so its registration ({}) is not shown \
             out of the uid's reach",
            RUNNER_COMMS.join(" or "),
            REGISTRATION.join(", ")
        ));
    }
    let finding = (!findings.is_empty()).then(|| findings.join("; "));
    (dirs, finding)
}

/// The regular files and links directly in DIR, not followed: the agent
/// can follow a link, and a link is refused by [`scan_files`].
fn top_files(dir: &Path) -> Result<Vec<PathBuf>> {
    top_entries(dir, |kind| kind.is_file() || kind.is_symlink())
}

/// The entries directly in DIR whose type, not followed, is WANTED.
fn top_entries(dir: &Path, wanted: fn(&std::fs::FileType) -> bool) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(paths),
        Err(err) => return Err(err).context("listing readiness candidate directory"),
    };
    for (count, entry) in entries.enumerate() {
        if count >= MAX_TEMP_ENTRIES {
            bail!(
                "run --runner-gate: candidate directory has over {MAX_TEMP_ENTRIES} entries, more than it looks through"
            );
        }
        let entry = entry.context("listing readiness candidate directory")?;
        let kind = entry
            .file_type()
            .context("inspecting readiness candidate type")?;
        if wanted(&kind) {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

/// Use Git only as a parser of the already bounded, no-follow read. It
/// neither loads includes nor opens a repository or runs configured helpers.
/// Include targets are outside the fixed scan, so any indirection refuses.
fn git_indirection(bytes: &[u8]) -> Result<Option<&'static str>> {
    let mut child = Command::new("git")
        .args(["config", "--no-includes", "--file", "-", "--null", "--list"])
        .env_clear()
        .env("PATH", host::root_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("starting Git's configuration parser")?;
    let input = child.stdin.take().context("opening Git's parser input")?;
    // Feed and drain concurrently: a config can produce more than a pipe's
    // capacity of names before Git has consumed all of its input.
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            let mut input = input;
            std::io::Write::write_all(&mut input, bytes)
        });
        let output = child
            .wait_with_output()
            .context("reading Git's parser output")?;
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("Git's parser input writer panicked"))?
            .context("writing Git's parser input")?;
        ensure!(
            output.status.success(),
            "Git could not parse the configuration"
        );
        let entries: Vec<_> = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                let at = entry
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .unwrap_or(entry.len());
                (
                    entry[..at].to_ascii_lowercase(),
                    &entry[at.saturating_add(1).min(entry.len())..],
                )
            })
            .collect();
        let keys: Vec<_> = entries.iter().map(|(key, _)| key.clone()).collect();
        if entries.iter().any(|(key, value)| {
            key == b"core.gitproxy"
                || (key.starts_with(b"http.") && key.ends_with(b".proxy"))
                // Git accepts opaque userinfo in remote URLs and URL
                // rewrite keys. Refuse it after parsing, not by token shape
                // or searching the original possibly quoted/escaped bytes.
                || [key.as_slice(), *value].iter().any(|part| {
                    part.windows(3).position(|part| part == b"://").is_some_and(|at| {
                        part[at + 3..].split(|byte| *byte == b'/').next().is_some_and(|authority| authority.contains(&b'@'))
                    })
                })
        }) {
            return Ok(Some("proxy settings or authenticated URLs"));
        }
        if keys.iter().any(|key| {
            key.starts_with(b"credential.")
                || key.starts_with(b"core.sshcommand")
                || key == b"ssh.variant"
        }) {
            return Ok(Some("credential helpers or SSH commands"));
        }
        Ok(keys
            .iter()
            .any(|key| key == b"include.path" || key.starts_with(b"includeif."))
            .then_some("includes"))
    })
}

/// A finding for each of PATHS that holds a credential of KNOWN or one's
/// shape, or git's extraheader, or is a store that is not empty. One that
/// is not there holds nothing for the agent. Permission denied is not
/// proof of isolation: the uid may own the file or an inaccessible
/// ancestor and chmod it. Refuse rather than infer ownership through a
/// path the gate cannot read.
fn scan_files(paths: &[(PathBuf, bool)], known: &Known) -> Vec<String> {
    let mut missing = Vec::new();
    for (path, store) in paths {
        let bytes = match files::read_regular(path, MAX_READ_BYTES) {
            Ok(bytes) => bytes,
            Err(ReadError::Io(err))
                if matches!(err.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) =>
            {
                continue;
            }
            Err(err) => {
                missing.push(format!(
                    "{} {err}, so it cannot be shown to hold no credential",
                    path_label(path)
                ));
                continue;
            }
        };
        if [
            ".gitconfig",
            ".config/git/config",
            ".git/config",
            ".git/config.worktree",
        ]
        .iter()
        .any(|suffix| path.ends_with(suffix))
        {
            match git_indirection(&bytes) {
                Ok(None) => {}
                Ok(Some(what)) => {
                    missing.push(format!(
                        "{} has unsupported Git {what}, whose credential configuration is not scanned",
                        path_label(path)
                    ));
                    continue;
                }
                Err(err) => {
                    missing.push(format!(
                        "{}: {err:#}, so Git configuration indirection cannot be excluded",
                        path_label(path)
                    ));
                    continue;
                }
            }
        }
        let what = if let Some(what) = known.find(&bytes) {
            what
        } else if secure_host::check::contains(&bytes.to_ascii_lowercase(), EXTRAHEADER) {
            "git's http.extraheader, as actions/checkout persists the job token \
             (check out with persist-credentials: false)"
                .to_owned()
        } else if OPAQUE_SETTINGS.iter().any(|suffix| path.ends_with(suffix))
            && !bytes.iter().all(u8::is_ascii_whitespace)
        {
            "unsupported pre-existing agent settings: opaque credentials, credential helpers and \
             local credential proxies cannot be excluded"
                .to_owned()
        } else if *store && !bytes.iter().all(u8::is_ascii_whitespace) {
            "credentials, as a store of them".to_owned()
        } else {
            continue;
        };
        missing.push(format!(
            "{} holds {what}, and the agent can read it",
            path_label(path)
        ));
    }
    missing
}

/// A filename, like a process name, can itself be the secret. Diagnose
/// only fixed inventory labels; never echo discovered path components.
fn path_label(path: &Path) -> &'static str {
    SETTINGS
        .iter()
        .chain(OPAQUE_SETTINGS)
        .chain(STORES)
        .chain(REGISTRATION)
        .copied()
        .chain([".git/config", ".git/config.worktree"])
        .find(|suffix| path.ends_with(suffix))
        .unwrap_or("candidate file")
}

/// The file scan's positive control: a file of a canary, which
/// [`scan_files`] must find.
fn file_control() -> Result<Vec<String>> {
    let canary = secure_host::check::canary()?;
    let mut file = tempfile::NamedTempFile::new().context("creating the file scan's control")?;
    std::io::Write::write_all(&mut file, canary.as_bytes())
        .context("writing the file scan's control")?;
    let found = scan_files(
        &[(file.path().to_owned(), false)],
        &Known::one(CANARY_VAR, &canary),
    );
    Ok(
        if found.iter().any(|finding| finding.contains(CANARY_VAR)) {
            Vec::new()
        } else {
            vec!["the file scan's control: a canary in a file of its own was not found".to_owned()]
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A credential made at run time, nothing like one in the source.
    fn credential() -> String {
        secure_host::check::canary().unwrap()
    }

    fn runner() -> User {
        User {
            name: "runner".to_owned(),
            uid: 1001,
            gid: 1001,
            home: PathBuf::from("/home/runner"),
        }
    }

    fn known(value: &str) -> Known {
        Known {
            credentials: vec![("GH_TOKEN".to_owned(), value.as_bytes().to_vec())],
            allowed: Vec::new(),
        }
    }

    #[test]
    fn credentials_by_name_and_the_agents_own_allowed() {
        let value = credential();
        let run_token = credential();
        let env = [
            ("GH_TOKEN", value.as_str()),
            ("ACTIONS_RUNTIME_TOKEN", "runtime-value-12345"),
            ("AGENTIC_JOB_INFERENCE_KEY", "key-value-12345"),
            ("DEPLOY_PASSWORD", "password-12345"),
            ("github_token", "lowercase-12345"),
            ("TOKEN", "bare-value-12345"),
            ("DOCKER_AUTH_CONFIG", "docker-auth-12345"),
            (RUN_TOKEN_VAR, run_token.as_str()),
            ("PATH", "/usr/bin:/bin"),
            ("EMPTY_TOKEN", ""),
        ]
        .map(|(name, value)| (OsString::from(name), OsString::from(value)));
        let known = Known::from_env(env, RUN_TOKEN_VAR);
        let names: Vec<&str> = known.credentials.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "ACTIONS_RUNTIME_TOKEN",
                "AGENTIC_JOB_INFERENCE_KEY",
                "DEPLOY_PASSWORD",
                "DOCKER_AUTH_CONFIG",
                "GH_TOKEN",
                "TOKEN",
                "github_token",
            ]
        );
        // The agent's run token is no finding, in a shape or not.
        assert_eq!(known.find(format!("x={run_token}").as_bytes()), None);
        let found = known.find(format!("A=1\0B={value}\0").as_bytes()).unwrap();
        assert_eq!(found, "the value of GH_TOKEN");
        let findings = environment(&known, 42);
        assert_eq!(findings.len(), 7);
        assert!(
            findings[4].contains("the agent's GitHub token"),
            "{findings:?}"
        );
        for finding in &findings {
            assert!(!finding.contains(&value), "{finding}");
        }
    }

    /// The shape scan is a backstop: a credential run does not know of is
    /// found by its shape, and the agent's own run token is not.
    #[test]
    fn shapes_are_the_backstop() {
        let shaped = format!("ghs_{}", "a".repeat(36));
        let mut known = Known::default();
        assert!(known.find(shaped.as_bytes()).unwrap().contains("shaped"));
        known.allowed.push(shaped.clone().into_bytes());
        assert_eq!(known.find(format!("T={shaped}").as_bytes()), None);
        assert_eq!(known.find(b"nothing to see"), None);
    }

    #[test]
    fn process_environment_checks_names_and_only_the_known_run_token_is_allowed() {
        let value = "opaque-value";
        let known = Known::from_env(
            [(OsString::from(RUN_TOKEN_VAR), OsString::from(value))],
            RUN_TOKEN_VAR,
        );
        for (entry, refused) in [
            ("DEPLOY_PASSWORD=opaque", true),
            ("deploy_password=x", true),
            ("DEPLOY_PASSWORD=", false),
            ("SSH_AUTH_SOCK=/tmp/socket", true),
            ("PATH=/usr/bin", false),
            (&format!("{RUN_TOKEN_VAR}={value}"), false),
            (&format!("{RUN_TOKEN_VAR}=someone-elses-token"), true),
            (&format!("DEPLOY_PASSWORD={value}"), true),
        ] {
            assert_eq!(
                known
                    .find_environment(format!("A=B\0{entry}\0").as_bytes())
                    .is_some(),
                refused,
                "{entry}"
            );
        }
    }

    #[test]
    fn sudo_must_show_the_complete_helper_only_policy() {
        let heading = "User runner may run the following commands on host:\n";
        let safe = setup::runner_sudo_rules().join("\n");
        for (rules, allowed) in [
            (safe.clone(), true),
            (format!("(ALL : ALL) ALL\n{safe}"), true),
            ("(root) NOPASSWD: /usr/bin/bash".to_owned(), false),
            (format!("{safe}\n(root) NOPASSWD: /usr/bin/bash"), false),
            (format!("{safe}, /usr/bin/bash"), false),
            (format!("{safe}\n    /usr/bin/bash"), false),
            ("".to_owned(), false),
        ] {
            assert_eq!(
                helper_only_sudo(format!("{heading}{rules}").as_bytes()),
                allowed,
                "{rules}"
            );
        }
        assert!(!helper_only_sudo(safe.as_bytes()));
        assert!(!helper_only_sudo(b"sudo: a password is required"));
    }

    #[test]
    fn sudo_helper_spelling_is_not_ownership_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("agentic-job");
        std::fs::write(&helper, "replaceable helper").unwrap();
        assert!(!helper_ownership(&helper).is_empty());
        assert!(!helper_ownership(&dir.path().join("missing")).is_empty());
    }

    #[test]
    fn diagnostic_socket_inspection_errors_do_not_echo_paths() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let secret = "opaque-socket-password";
        let parent = dir.path().join(secret);
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join(format!("dotnet-diagnostic-{}-1-socket", std::process::id()));
        let _socket = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o0)).unwrap();
        let inspected = worker_diagnostics::linked_sockets(&[std::process::id()]);
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        if !host::is_root() {
            assert!(inspected.is_err());
        }
        let findings = socket_findings(inspected).join("; ");
        assert!(!findings.is_empty());
        assert!(!findings.contains(secret));
        assert!(
            !socket_findings(Err(anyhow::anyhow!("{secret}")))
                .join("; ")
                .contains(secret)
        );
    }

    #[test]
    fn metadata_and_egress_must_be_refused_not_unknown() {
        for (kind, count) in [
            (ErrorKind::ConnectionRefused, 0),
            (ErrorKind::NetworkUnreachable, 1),
            (ErrorKind::TimedOut, 3),
            (ErrorKind::PermissionDenied, 3),
            (ErrorKind::Other, 3),
        ] {
            let found = egress_probe_findings(false, |_| Err(std::io::Error::from(kind)));
            assert_eq!(found.len(), count, "{kind:?}: {found:?}");
        }
        let reachable = egress_probe_findings(false, |_| Ok(()));
        assert_eq!(reachable.len(), 3);
        assert!(reachable[0].contains("metadata"));
        assert!(reachable[1].contains("IPv6"));
        assert!(reachable[2].contains("egress proxy"));
        let ipv4_only = egress_probe_findings(true, |address| {
            assert_ne!(address, METADATA_V6);
            Ok(())
        });
        assert_eq!(ipv4_only.len(), 2);
        assert!(subordinate_readiness(&[]).is_empty());
        assert!(!subordinate_readiness(&["100000-165535".to_owned()]).is_empty());
    }

    #[test]
    fn egress_held_or_refused() {
        let user = runner();
        let subuid = "runner:100000:65536\nother:200000:65536\n";
        let held = vec!["1001".to_owned(), "100000-165535".to_owned()];
        let resolvers = network::resolvers("nameserver 10.0.0.2\n").unwrap();
        let rules = |write: &[String], metadata: &[String]| {
            network::rules_with_resolvers(&[], &[], Some(993), &resolvers, metadata, write)
        };
        let config = |text: &str| Config::parse(text).unwrap();
        let on = config("[egress]\nwrite-policy = true\n");
        let ranges = setup::subordinate_ranges(&user, subuid);
        let missing =
            |config: &Config, rules: Result<String>| egress(config, rules, &ranges, &user);
        assert_eq!(missing(&on, Ok(rules(&held, &held))), Vec::<String>::new());
        let cases: [(&Config, Result<String>, &[&str]); 6] = [
            // An empty set of the sandbox user's: the proxy holds no one.
            (
                &on,
                Ok(rules(&[], &held)),
                &["1001, 100000-165535", "write policy"],
            ),
            // The runner held, but not its subordinate uids.
            (
                &on,
                Ok(rules(&held[..1], &held)),
                &["100000-165535", "write policy"],
            ),
            // Held, but the metadata service open.
            (&on, Ok(rules(&held, &[])), &["metadata"]),
            (
                &on,
                Ok(rules(&held, &held[1..])),
                &["uid 1001 ", "metadata"],
            ),
            (
                &config(""),
                Ok(rules(&held, &held)),
                &["egress.write-policy is off"],
            ),
            (
                &on,
                Err(anyhow::anyhow!("not root's")),
                &["cannot show", "not root's"],
            ),
        ];
        for (config, rules, want) in cases {
            let text = missing(config, rules).join("; ");
            for want in want {
                assert!(text.contains(want), "{want:?} in {text}");
            }
        }
        // A rule without its set, or a set without the rule, is no hold.
        let full = rules(&held, &held);
        let no_reject = full.replace("    meta skuid @write_policy_uids counter reject\n", "");
        assert_eq!(missing(&on, Ok(no_reject)).len(), 1);
        // The metadata service refused over IPv4 alone is not refused.
        let v4_only = full.replace(
            "    meta skuid @runner_uids ip6 daddr fd00:ec2::254 counter reject\n",
            "",
        );
        assert!(missing(&on, Ok(v4_only))[0].contains("metadata"));
    }

    #[test]
    fn subordinate_processes_are_findings() {
        let proc = Path::new(PROC);
        let ranges = ["100000-165535".to_owned()];
        let owners = [(1, 0), (2, 1001), (3, 100000), (4, 165535), (5, 165536)];
        let found = subordinate_processes(proc, &owners, &ranges);
        let text = found.join("\n");
        assert_eq!(found.len(), 2, "{text}");
        assert!(
            text.contains("uid 100000") && text.contains("uid 165535"),
            "{text}"
        );
        assert_eq!(of_uid(&owners, 1001).unwrap(), [2]);
    }

    #[test]
    fn real_uid_of_status() {
        for (status, uid) in [
            (
                &b"Name:\tsudo\nUmask:\t0022\nUid:\t1001\t0\t0\t0\n"[..],
                Some(1001),
            ),
            (b"Name:\t\xff\nUid:\t0\t0\t0\t0\n", Some(0)),
            (b"Name:\tx\nGid:\t5\t5\t5\t5\n", None),
            (b"Uid:\t\n", None),
        ] {
            assert_eq!(real_uid(status), uid, "{status:?}");
        }
        // This process's own status names its own uid.
        let status = std::fs::read("/proc/self/status").unwrap();
        assert_eq!(real_uid(&status), Some(rustix::process::getuid().as_raw()));
    }

    /// A runner's directory is found by its marker, and a runner that runs
    /// where none is found is a finding.
    #[test]
    fn runner_registration() {
        let home = tempfile::tempdir().unwrap();
        let proc = Path::new(PROC);
        assert_eq!(runner_dirs(proc, &[], home.path()), (vec![], None));
        let root = home.path().join("actions-runner");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join(RUNNER_MARKER), "").unwrap();
        let (dirs, unlocated) = runner_dirs(proc, &[], home.path());
        assert_eq!((dirs, unlocated), (vec![root.clone()], None));
        let value = credential();
        std::fs::write(root.join(".credentials_rsaparams"), &value).unwrap();
        let user = User {
            home: home.path().to_owned(),
            ..runner()
        };
        let (files, _) = files_to_scan(proc, &[], &user, home.path()).unwrap();
        let found = scan_files(&files, &Known::default()).join("\n");
        assert!(
            found.contains(".credentials_rsaparams holds credentials"),
            "{found}"
        );
        assert!(!found.contains(&value));
        // A Worker that runs, with its directory nowhere to be found.
        let fake = tempfile::tempdir().unwrap();
        std::fs::create_dir(fake.path().join("77")).unwrap();
        std::fs::write(fake.path().join("77/comm"), "Runner.Worker\n").unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let (dirs, unlocated) = runner_dirs(fake.path(), &[(77, 1001)], elsewhere.path());
        assert!(dirs.is_empty());
        assert!(unlocated.unwrap().contains("not found"));
        // An old installation is no evidence about the running Worker's
        // registration when that process's executable cannot be located.
        let (dirs, unlocated) = runner_dirs(fake.path(), &[(77, 1001)], home.path());
        assert_eq!(dirs, [root]);
        assert!(unlocated.unwrap().contains("not found for that process"));
    }

    #[test]
    fn set_elements_as_network_writes_them() {
        let rules = "  set sandbox_uids { type uid; flags interval; }\n  set write_policy_uids { type uid; flags interval; elements = { 1001, 100000-165535 } }\n";
        assert_eq!(set_elements(rules, "sandbox_uids"), Some(vec![]));
        assert_eq!(
            set_elements(rules, "write_policy_uids"),
            Some(vec!["1001", "100000-165535"])
        );
        assert_eq!(set_elements(rules, "runner_uids"), None);
    }

    /// Positive control: a value made now, put in a child's environment
    /// and command line, is found in each, and never named.
    #[test]
    fn a_process_holding_a_known_value_is_found() {
        let proc = Path::new(PROC);
        let value = credential();
        let mut child = Command::new("sh")
            .args(["-c", "exec sleep 60", "sh", &value])
            .env_clear()
            .env("GH_TOKEN", &value)
            .spawn()
            .unwrap();
        let pid = child.id();
        assert!(became_sleep(proc, pid));
        // During exec, comm may already say sleep before environ is visible.
        // Wait for the fixture's environment rather than racing that window.
        let mut found = Vec::new();
        for _ in 0..CONTROL_TRIES {
            found = processes(proc, &[pid], &known(&value)).unwrap();
            if !found.is_empty() {
                break;
            }
            std::thread::sleep(CONTROL_WAIT);
        }
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("environ"), "{found:?}");
        assert!(!found[0].contains(&value));
        // The control of `check` passes here, as it must on any host.
        assert_eq!(process_control(proc).unwrap(), Vec::<String>::new());
        // A process that has ended holds nothing.
        assert_eq!(
            processes(proc, &[pid], &known(&value)).unwrap(),
            Vec::<String>::new()
        );
        // Keep the canary in argv while waiting on an open stdin. Giving
        // sleep an invalid duration instead races its immediate exit.
        let mut child = Command::new("sh")
            .args(["-c", "read -r line", "sh", &value])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let mut found = Vec::new();
        for _ in 0..CONTROL_TRIES {
            found = processes(proc, &[child.id()], &known(&value)).unwrap();
            if found.iter().any(|f| f.contains("cmdline")) {
                break;
            }
            std::thread::sleep(CONTROL_WAIT);
        }
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(found.iter().any(|f| f.contains("cmdline")), "{found:?}");

        let mut child = Command::new("sleep")
            .arg("60")
            .env_clear()
            .env("DEPLOY_PASSWORD", "opaque-value-not-in-run")
            .spawn()
            .unwrap();
        let pid = child.id();
        assert!(became_sleep(proc, pid));
        let found = processes(proc, &[pid], &Known::default()).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("credential-named variable"), "{found:?}");
        assert!(!found[0].contains("opaque-value-not-in-run"));
    }

    #[test]
    fn files_holding_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let value = credential();
        let write = |name: &str, text: &str| {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            path
        };
        let settings = write(
            ".claude/settings.json",
            &format!("{{\"env\": \"{value}\"}}"),
        );
        let git = write(
            "work/.git/config",
            "[http \"https://github.com/\"]\n\textraHeader = AUTHORIZATION: basic eC1hY2Nlc3M=\n",
        );
        let store = write(".netrc", "machine example.org login x password y\n");
        let docker = write(
            ".docker/config.json",
            r#"{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"}}}"#,
        );
        let empty_store = write(".git-credentials", "\n");
        let clean = write(".gitconfig", "[user]\nname = Example\n");
        let link = dir.path().join(".config/gh/hosts.yml");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&settings, &link).unwrap();
        let paths = [
            (settings, false),
            (git, false),
            (store, true),
            (docker, true),
            (empty_store, true),
            (clean, false),
            (dir.path().join("missing"), true),
            (link, true),
        ];
        let found = scan_files(&paths, &known(&value));
        let text = found.join("\n");
        assert_eq!(found.len(), 5, "{text}");
        for want in [
            "the value of GH_TOKEN",
            "extraheader",
            "as a store",
            "not a regular file",
        ] {
            assert!(text.contains(want), "{want:?} in {text}");
        }
        assert!(!text.contains(&value));
        // Standard authentication fields may contain neither a known
        // literal nor a credential shape. Refuse the whole store, even
        // when it also could be used for credentialless settings.
        for (name, content) in [
            (".npmrc", "//registry.example/:_auth=dXNlcjpwYXNz\n"),
            (".pypirc", "[registry]\npassword = opaque-password\n"),
            (
                ".kube/config",
                "users:\n- user:\n    client-key-data: b3BhcXVl\n",
            ),
        ] {
            assert!(STORES.contains(&name));
            let path = write(name, content);
            let found = scan_files(&[(path, true)], &Known::default());
            assert_eq!(found.len(), 1, "{name}: {found:?}");
            assert!(found[0].contains("as a store"), "{found:?}");
            assert!(!found[0].contains(content), "{found:?}");
        }
        // Each home's lists, and the files at RUNNER_TEMP's top only.
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("git-credentials.config"), "x").unwrap();
        std::fs::create_dir(temp.path().join("sub")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", temp.path().join("link")).unwrap();
        assert_eq!(
            top_files(temp.path()).unwrap(),
            [
                temp.path().join("git-credentials.config"),
                temp.path().join("link")
            ]
        );
        // The control of `check` passes here, as it must on any host.
        assert_eq!(file_control().unwrap(), Vec::<String>::new());
        for _ in 0..MAX_TEMP_ENTRIES {
            let name = credential();
            std::fs::write(temp.path().join(name), "").unwrap();
        }
        assert!(top_files(temp.path()).is_err());
    }

    #[test]
    fn opaque_settings_need_no_known_value_or_token_shape() {
        let dir = tempfile::tempdir().unwrap();
        for name in OPAQUE_SETTINGS {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let paths = [(path.clone(), true)];
            for (content, refused) in [
                ("", false),
                (" \n\t", false),
                // Even innocuous settings are unsupported until their
                // helper and endpoint semantics can be established.
                ("{}", true),
                ("opaque-password", true),
            ] {
                std::fs::write(&path, content).unwrap();
                let findings = scan_files(&paths, &Known::default());
                assert_eq!(!findings.is_empty(), refused, "{name}: {findings:?}");
                if refused {
                    assert!(findings[0].contains("unsupported pre-existing agent settings"));
                }
            }
        }
    }

    #[test]
    fn memory_probe_answers() {
        let proc = Path::new(PROC);
        let me = std::process::id();
        // Its controls pass on any host; whether its parent's memory opens
        // is the host's Yama setting, and either way the answer names only
        // a pid it was given.
        let found = memory(proc, &[me]).unwrap();
        assert!(found.len() <= 3, "{found:?}");
        assert!(
            found.iter().all(|f| f.contains(&me.to_string())
                || f.contains("isolation is unproven")
                || f.contains("core dumps")),
            "{found:?}"
        );
        for (code, stdout, scope, want) in [
            (Some(3), &b""[..], "1", "control"),
            (None, b"control\n", "1", "ended with None"),
            (Some(0), b"control\n7\n", "1", "process 7"),
            // No control where Yama allows one: the answer shows nothing.
            (Some(0), b"", "1", "own child's memory"),
            (Some(0), b"", "not there", "own child's memory"),
        ] {
            let found = memory_findings(proc, code, stdout, &[7], scope).unwrap();
            assert!(
                found.iter().any(|finding| finding.contains(want)),
                "{found:?}"
            );
        }
        assert!(memory_findings(proc, Some(0), b"control\n8\n", &[7], "1").is_err());
        for (stdout, scope) in [(&b"control\n"[..], "1"), (b"", "2"), (b"", "3")] {
            let found = memory_findings(proc, Some(0), stdout, &[7], scope).unwrap();
            assert_eq!(found.is_empty(), scope == "3", "{found:?}");
        }
    }
}
