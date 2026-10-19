//! The probes that need the run token, repeated by `run` once the agent
//! is configured and before it starts: the token is in the agent's one
//! file, private to the sandbox user, and nowhere else that user can
//! write or read.
//!
//! These are the token's part of the old tree's
//! `agent-isolation-check.mjs`. The probes that need no token are
//! `sandbox check`'s (step 5), which the run action calls again unless
//! it passed earlier in the same job. With `[sandbox.check]
//! before-agent`, `run` makes those again too ([`recheck`]), after its
//! own commands as the sandbox user, and adds the old probe that needs
//! the container image `[sandbox.check]` names: that a container's
//! subordinate uid cannot read the token's files.
//!
//! The token goes to every search on standard input, never on a command
//! line.

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, ensure};

use super::clone::utf8;
use super::enter::Sandbox;
use super::inference::Token;
use crate::config::Config;
use crate::sandbox::egress;
use crate::sandbox::network::Direct;

/// Where the sandbox user can write, and so where a token handed to it
/// could have been left, besides its home.
const SHARED_WRITABLE: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];
/// How long the search of those may take, in seconds.
const SEARCH_TIMEOUT_S: &str = "300";
/// What timeout(1) exits with when it ended the command.
const TIMEOUT_EXIT: i32 = 124;
/// Every command line and environment the sandbox user can read.
const PROCESSES_SCRIPT: &str = "cat /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null; true";
/// What those may add up to on a machine with many processes.
const MAX_PROCESSES_BYTES: usize = 256 << 20;
const MAX_OUTPUT: usize = 1 << 20;
/// Any uid but root in a rootless container is a subordinate uid of the
/// sandbox user's, as in `sandbox check`.
const CONTAINER_UID: &str = "1000";
/// Where a token's directory is in the container.
const CONTAINER_DIR: &str = "/token-dir";
/// How long a container may take, image pull included, in seconds.
const CONTAINER_TIMEOUT_S: &str = "600";
/// Reads `$1` and shows nothing of it: a container's output also goes
/// to podman's log driver, which may be the journal.
const READ_SCRIPT: &str = r#"cat -- "$1" >/dev/null"#;
/// A file every uid of the image can read: the control that a
/// subordinate uid's container runs at all.
const WORLD_READABLE: &str = "/etc/os-release";
/// Opens a plain TCP connection to `$1` port `$2`, whatever the service
/// speaks, as `sandbox check`'s `egress-tcp` probe does.
const CONNECT_SCRIPT: &str = r#"exec 3<>"/dev/tcp/$1/$2""#;
/// How long a connection may take to open, here and as the sandbox user.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT_S: &str = "10";
/// Sends `$3` to the proxy at `$1` port `$2` and prints the head of its
/// answer, up to the blank line: the proxy need not close the
/// connection after a refused CONNECT.
const PROXY_REQUEST_SCRIPT: &str = r#"exec 3<>"/dev/tcp/$1/$2" || exit; printf '%s' "$3" >&3; while IFS= read -r line <&3; do printf '%s\n' "$line"; [ "$line" = $'\r' ] && break; done"#;
/// The broker's run API, where a run is registered.
const RUNS_PATH: &str = "/v1/runs";
const PRIVATE_FILE_MODE: &str = "600";
const PRIVATE_DIR_MODE: &str = "700";

/// One probe: what was expected, and whether it held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub what: String,
    pub passed: bool,
}

/// The owner and mode of PATH, as the sandbox user sees them; or why
/// they could not be had, which is no owner and mode a probe expects.
fn owner_and_mode(sandbox: &Sandbox, path: &str) -> Result<String> {
    let out = sandbox.run(&["stat", "-c", "%U %a", "--", path], b"", MAX_OUTPUT)?;
    Ok(if out.success() {
        out.text()
    } else {
        format!("stat failed, {}", out.error())
    })
}

/// A probe that PATH is USER's and of MODE. It says what it found: a
/// failed probe whose text is only what was expected cannot be acted on.
fn private(sandbox: &Sandbox, what: &str, path: &str, mode: &str) -> Result<Probe> {
    let user = &sandbox.user;
    let found = owner_and_mode(sandbox, path)?;
    Ok(Probe {
        what: format!("{what} is {user}'s, mode {mode} (it is: {found})"),
        passed: found == format!("{user} {mode}"),
    })
}

/// Whether a search for the token, which exited with CODE and listed
/// FOUND, shows it to be in FILES and nowhere else. grep's own status says
/// nothing: it is an error for every file it could not read. But a
/// search that timeout(1) cut short found nothing only so far.
fn only_in(code: Option<i32>, found: &[&str], files: &[&str]) -> bool {
    let mut found = found.to_vec();
    let mut files = files.to_vec();
    found.sort_unstable();
    files.sort_unstable();
    code != Some(TIMEOUT_EXIT) && found == files
}

/// Whether HAYSTACK holds NEEDLE.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The command that reads PATH, in a rootless container of IMAGE as UID
/// with the directory DIR at [`CONTAINER_DIR`], and logs nothing of it.
fn read_in_container(image: &str, uid: &str, dir: &str, path: &str) -> Vec<String> {
    [
        "timeout",
        "--kill-after=10",
        CONTAINER_TIMEOUT_S,
        "podman",
        "run",
        "--rm",
        "--network=none",
        "--log-driver=none",
        "--security-opt",
        "label=disable",
        "--user",
        uid,
        "-v",
        &format!("{dir}:{CONTAINER_DIR}:ro"),
        image,
        "sh",
        "-c",
        READ_SCRIPT,
        "sh",
        path,
    ]
    .map(str::to_owned)
    .to_vec()
}

/// Probes that a rootless container's subordinate uid cannot read FILE
/// in DIR, with the controls that the container's root, the sandbox
/// user, can, and that the subordinate uid reads what everyone may.
/// Without podman there is no container to read it from.
fn from_container(sandbox: &Sandbox, image: &str, dir: &str, file: &str) -> Result<Vec<Probe>> {
    let user = &sandbox.user;
    if !sandbox
        .run(&["sh", "-c", "command -v podman"], b"", MAX_OUTPUT)?
        .success()
    {
        eprintln!("note: {user} has no podman, so no container to read {file} from");
        return Ok(Vec::new());
    }
    let reads = |uid, path: &str| -> Result<bool> {
        let argv = read_in_container(image, uid, dir, path);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        Ok(sandbox.run(&argv, b"", MAX_OUTPUT)?.success())
    };
    let inside = format!("{CONTAINER_DIR}/{file}");
    Ok(vec![
        Probe {
            what: format!("a container of {user}'s, as its root, reads {file} (control)"),
            passed: reads("0", &inside)?,
        },
        Probe {
            what: format!(
                "a container of {user}'s, as uid {CONTAINER_UID}, reads {WORLD_READABLE} (control)"
            ),
            passed: reads(CONTAINER_UID, WORLD_READABLE)?,
        },
        Probe {
            what: format!("a container of {user}'s, as uid {CONTAINER_UID}, cannot read {file}"),
            passed: !reads(CONTAINER_UID, &inside)?,
        },
    ])
}

/// Probes where the run token is. TOKEN_FILES are the files that should
/// hold it, under the sandbox user's home: the agent's, and its child
/// agent's if the run has one; GIVEN is the runner's own file the token
/// came from, if it came from one. With IMAGE, each file is also read
/// from a container of it.
pub fn token(
    sandbox: &Sandbox,
    token: &Token,
    token_files: &[&str],
    given: Option<&Path>,
    image: Option<&str>,
) -> Result<Vec<Probe>> {
    let needle = format!("{}\n", token.expose());
    let user = &sandbox.user;
    let mut probes = Vec::new();
    let mut files = Vec::new();
    for token_file in token_files {
        let file = sandbox.home.join(token_file);
        let dir = file.parent().context("the token's file has no directory")?;
        let (file, dir) = (utf8(&file)?.to_owned(), utf8(dir)?.to_owned());

        // The control: a search that cannot find the token where it is
        // proves nothing by not finding it elsewhere.
        let found = sandbox.run(
            &["grep", "-qsF", "-f", "-", "--", &file],
            needle.as_bytes(),
            MAX_OUTPUT,
        )?;
        probes.push(Probe {
            what: format!("{user}'s {file} holds the run token (control)"),
            passed: found.success(),
        });
        for (what, path, mode) in [
            (file.as_str(), file.as_str(), PRIVATE_FILE_MODE),
            ("its directory", dir.as_str(), PRIVATE_DIR_MODE),
        ] {
            probes.push(private(sandbox, what, path, mode)?);
        }
        if let Some(image) = image {
            let name = Path::new(token_file)
                .file_name()
                .and_then(|name| name.to_str())
                .context("the token's file has no name")?;
            probes.extend(from_container(sandbox, image, &dir, name)?);
        }
        files.push(file);
    }
    let files: Vec<&str> = files.iter().map(String::as_str).collect();
    probes.extend(elsewhere(sandbox, "the token", token.expose(), &files)?);
    let mut probe = |what: String, passed: bool| probes.push(Probe { what, passed });

    if let Some(given) = given {
        let given = utf8(given)?;
        let read = sandbox.run(&["cat", "--", given], b"", MAX_OUTPUT)?;
        probe(format!("{user} cannot read {given}"), !read.success());
    }
    Ok(probes)
}

/// Probes that SECRET is in no file under the sandbox user's home and the
/// directories it shares but FILES, and in no environment or command line
/// it can read. WHAT names the secret. The search of files runs as the
/// sandbox user and is given SECRET: only for one that user holds anyway.
fn elsewhere(sandbox: &Sandbox, what: &str, secret: &str, files: &[&str]) -> Result<Vec<Probe>> {
    let user = &sandbox.user;
    let needle = format!("{secret}\n");
    let home = utf8(&sandbox.home)?;
    let search = [
        &[
            "timeout",
            SEARCH_TIMEOUT_S,
            "grep",
            "-rlsF",
            "-f",
            "-",
            "--",
            home,
        ],
        SHARED_WRITABLE,
    ]
    .concat();
    let search = sandbox.run(&search, needle.as_bytes(), MAX_OUTPUT)?;
    let code = search.status.code();
    let timed_out = code == Some(TIMEOUT_EXIT);
    let found = search.text();
    let found: Vec<&str> = found.lines().collect();
    Ok(vec![
        Probe {
            what: format!(
                "{user} finds {what} in no other file it can write ({})",
                if timed_out {
                    format!("the search took more than {SEARCH_TIMEOUT_S}s")
                } else if found.is_empty() {
                    "nowhere".to_owned()
                } else {
                    found.join(", ")
                }
            ),
            passed: only_in(code, &found, files),
        },
        in_no_process(sandbox, what, secret)?,
    ])
}

/// Probes that no environment or command line the sandbox user can read
/// holds SECRET. What it reads comes back here to be searched: SECRET
/// itself goes to none of its processes.
fn in_no_process(sandbox: &Sandbox, what: &str, secret: &str) -> Result<Probe> {
    let processes = sandbox.run(&["sh", "-c", PROCESSES_SCRIPT], b"", MAX_PROCESSES_BYTES)?;
    Ok(Probe {
        what: format!(
            "no process {} can read has {what} in its environment or command line",
            sandbox.user
        ),
        passed: !holds(&processes.stdout, secret.as_bytes()),
    })
}

/// Probes that SECRET, which only `run` holds (the provider's key under
/// `api-key`, the broker's run token under `inference.front`), is in no
/// process the sandbox user can read, prints what was found, and fails
/// unless it held. WHAT names it. Its files are not searched for it,
/// since that search would hand it to a process of the sandbox user's:
/// nothing writes it there, and the probes of the agent's token show that
/// what `run` writes for the agent is where it belongs.
pub fn require_absent(sandbox: &Sandbox, what: &str, secret: &str) -> Result<()> {
    let probe = in_no_process(sandbox, what, secret.trim())?;
    ensure!(
        report(&[probe]),
        "{what} is where the sandbox user can read it: see the failed probes above"
    );
    Ok(())
}

/// The broker under `inference.front`, as its probes see it.
pub struct Broker<'a> {
    /// Its hosts and ports, as the configuration names them.
    pub hosts: &'a [(String, u16)],
    /// What `run` resolved those to when it fronted the run, and alone
    /// connects to ([`super::api_key::Pinned`]).
    pub addresses: &'a [SocketAddr],
    /// Where the sandbox user connects around the egress proxy.
    pub direct: &'a [Direct],
}

/// The egress proxy `sandbox setup` serves the sandbox user.
pub fn egress_proxy() -> SocketAddr {
    SocketAddr::from((egress::PROXY_HOST, egress::PROXY_PORT))
}

/// Probes that the sandbox user cannot reach the BROKER under
/// `inference.front`, prints what was found, and fails unless it held.
/// Were it to, the agent could register runs of its own there, each with
/// a fresh cap, past the proxy `run` serves it at PROXY. There are two
/// ways it could:
///
/// - Around the egress proxy, where the network rules let it: loopback,
///   and `egress.direct`. Every address of the broker's is held to that
///   by what it is, whether it answers now or not, since one that is
///   down now may answer later; and each that `run` reaches (the control
///   that it is up, so that a refused connection shows the network
///   rules) is tried as the sandbox user too. The addresses are `run`'s,
///   since the sandbox user may resolve nothing.
/// - Through the egress proxy at EGRESS, which must refuse the broker
///   itself (`--refuse`) whatever its policy says: a GET and a POST of
///   `/v1/runs` and a CONNECT to each of the broker's names and
///   addresses, as the sandbox user and, with IMAGE and podman, a GET and
///   a POST from a container of that image as a subordinate uid. Only
///   the egress proxy's 403 for that destination passes: the broker's
///   own answer, a 502 or no answer at all would not show the refusal.
///
/// The sandbox user's own control is that it reaches PROXY: a command
/// that cannot connect at all shows nothing.
pub fn require_unreachable(
    sandbox: &Sandbox,
    broker: &Broker<'_>,
    proxy: SocketAddr,
    egress: &SocketAddr,
    image: Option<&str>,
) -> Result<()> {
    let mut probes = unreachable(sandbox, broker, proxy)?;
    let forms = forms(broker);
    probes.extend(through_egress(sandbox, &forms, egress)?);
    if let Some(image) = image {
        probes.extend(through_egress_from_container(
            sandbox, image, &forms, egress,
        )?);
    }
    ensure!(
        report(&probes),
        "the sandbox user can reach the broker, or nothing showed it cannot: see the failed \
         probes above; keep the broker out of egress.direct and off loopback, and its host out \
         of egress.policy"
    );
    Ok(())
}

/// Whether the sandbox user's uids reach ADDRESS around the egress
/// proxy (`sandbox::network`): anything on loopback, `0.0.0.0` and `::`
/// included, which reach this machine, and what DIRECT opens. In any
/// spelling: an IPv4-mapped IPv6 address is the IPv4 one.
fn around_the_proxy(address: SocketAddr, direct: &[Direct]) -> bool {
    let ip = address.ip().to_canonical();
    ip.is_loopback()
        || ip.is_unspecified()
        || match ip {
            std::net::IpAddr::V4(v4) => direct
                .iter()
                .any(|open| open.host == v4 && open.port == address.port()),
            std::net::IpAddr::V6(_) => false,
        }
}

/// The broker's names and addresses, each as a request's authority
/// would name it, with its port: what the egress proxy must refuse.
fn forms(broker: &Broker<'_>) -> Vec<String> {
    let mut forms: Vec<String> = broker
        .hosts
        .iter()
        .map(|(host, port)| match host.parse::<std::net::IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, *port).to_string(),
            Err(_) => format!("{host}:{port}"),
        })
        .chain(broker.addresses.iter().map(SocketAddr::to_string))
        .collect();
    forms.sort_unstable();
    forms.dedup();
    forms
}

/// Whether the sandbox user opens a TCP connection to ADDRESS.
fn connects(sandbox: &Sandbox, address: &SocketAddr) -> Result<bool> {
    let (ip, port) = (address.ip().to_string(), address.port().to_string());
    let argv = [
        "timeout",
        CONNECT_TIMEOUT_S,
        "bash",
        "-c",
        CONNECT_SCRIPT,
        "probe",
        &ip,
        &port,
    ];
    Ok(sandbox.run(&argv, b"", MAX_OUTPUT)?.success())
}

/// The probes of [`require_unreachable`] around the egress proxy.
fn unreachable(sandbox: &Sandbox, broker: &Broker<'_>, proxy: SocketAddr) -> Result<Vec<Probe>> {
    let user = &sandbox.user;
    let mut probes = vec![
        Probe {
            what: format!("{user} reaches the run's inference proxy at {proxy} (control)"),
            passed: connects(sandbox, &proxy)?,
        },
        Probe {
            what: "run resolved the broker to an address (control)".to_owned(),
            passed: !broker.addresses.is_empty(),
        },
    ];
    for address in broker.addresses {
        probes.push(Probe {
            what: format!(
                "the broker's {address} is neither on loopback nor in egress.direct, \
                 where {user} connects around the egress proxy"
            ),
            passed: !around_the_proxy(*address, broker.direct),
        });
    }
    let reached: Vec<&SocketAddr> = broker
        .addresses
        .iter()
        .filter(|address| TcpStream::connect_timeout(address, CONNECT_TIMEOUT).is_ok())
        .collect();
    probes.push(Probe {
        what: "run reaches the broker at one of its addresses (control)".to_owned(),
        passed: !reached.is_empty(),
    });
    for address in reached {
        probes.push(Probe {
            what: format!("{user} cannot open a TCP connection to the broker at {address}"),
            passed: !connects(sandbox, address)?,
        });
    }
    Ok(probes)
}

/// The request for `/v1/runs` that METHOD makes of the broker at
/// AUTHORITY through a proxy: in absolute form, or a CONNECT's.
fn proxy_request(method: &str, authority: &str) -> String {
    match method {
        "CONNECT" => format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"),
        "POST" => format!(
            "POST http://{authority}{RUNS_PATH} HTTP/1.1\r\nHost: {authority}\r\n\
             Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
        _ => format!(
            "{method} http://{authority}{RUNS_PATH} HTTP/1.1\r\nHost: {authority}\r\n\
             Connection: close\r\n\r\n"
        ),
    }
}

/// Whether HEAD, a response's status line and headers, is the egress
/// proxy's refusal of a `--refuse` destination: its 403, with its reason
/// in its own header, which neither the broker nor any other refusal of
/// the proxy's gives.
fn refused_as_broker(head: &str) -> bool {
    let mut lines = head.lines();
    let forbidden = lines.next().is_some_and(|status| {
        let mut words = status.split_whitespace();
        words
            .next()
            .is_some_and(|version| version.starts_with("HTTP/"))
            && words.next() == Some("403")
    });
    forbidden
        && lines.any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case(crate::sandbox::proxy::DENIED_HEADER)
                    && value.trim() == crate::sandbox::proxy::REFUSED_DESTINATION
            })
        })
}

/// The sandbox user's GET, POST and CONNECT to the broker at each of
/// FORMS through the egress proxy at EGRESS: each must be refused there.
fn through_egress(sandbox: &Sandbox, forms: &[String], egress: &SocketAddr) -> Result<Vec<Probe>> {
    let user = &sandbox.user;
    let (ip, port) = (egress.ip().to_string(), egress.port().to_string());
    let mut probes = Vec::new();
    for authority in forms {
        for method in ["GET", "POST", "CONNECT"] {
            let request = proxy_request(method, authority);
            let argv = [
                "timeout",
                CONNECT_TIMEOUT_S,
                "bash",
                "-c",
                PROXY_REQUEST_SCRIPT,
                "probe",
                &ip,
                &port,
                &request,
            ];
            let head = sandbox.run(&argv, b"", MAX_OUTPUT)?.text();
            let what = match method {
                "CONNECT" => format!("CONNECT {authority}"),
                _ => format!("{method} http://{authority}{RUNS_PATH}"),
            };
            probes.push(Probe {
                what: format!("the egress proxy refuses {user} {what}"),
                passed: refused_as_broker(&head),
            });
        }
    }
    Ok(probes)
}

/// [`through_egress`]'s GET and POST, from a container of IMAGE as a
/// subordinate uid on the host's network, with curl. Without podman
/// there is no container to try from.
fn through_egress_from_container(
    sandbox: &Sandbox,
    image: &str,
    forms: &[String],
    egress: &SocketAddr,
) -> Result<Vec<Probe>> {
    let user = &sandbox.user;
    if !sandbox
        .run(&["sh", "-c", "command -v podman"], b"", MAX_OUTPUT)?
        .success()
    {
        eprintln!("note: {user} has no podman, so no container to try the broker from");
        return Ok(Vec::new());
    }
    let proxy = format!("http://{egress}");
    let mut probes = Vec::new();
    for authority in forms {
        let url = format!("http://{authority}{RUNS_PATH}");
        for post in [false, true] {
            let mut argv = vec![
                "timeout",
                "--kill-after=10",
                CONTAINER_TIMEOUT_S,
                "podman",
                "run",
                "--rm",
                "--network=host",
                "--log-driver=none",
                "--user",
                CONTAINER_UID,
                image,
                "curl",
                "-sS",
                "-g",
                "-m",
                CONNECT_TIMEOUT_S,
                "-o",
                "/dev/null",
                "-D",
                "-",
                "--proxy",
                &proxy,
            ];
            if post {
                argv.extend([
                    "-X",
                    "POST",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    "{}",
                ]);
            }
            argv.push(&url);
            let head = sandbox.run(&argv, b"", MAX_OUTPUT)?.text();
            probes.push(Probe {
                what: format!(
                    "the egress proxy refuses a container of {user}'s, as uid {CONTAINER_UID}, \
                     {} {url}",
                    if post { "POST" } else { "GET" }
                ),
                passed: refused_as_broker(&head),
            });
        }
    }
    Ok(probes)
}

/// Probes, before the agent starts, that the MCP server's CREDENTIAL,
/// which only `run` holds, is in no process the sandbox user can read
/// (not searched for in files, as the provider's key is not), and that
/// the MCP proxy's TOKEN, which the agent gets in `session/new` and in no
/// file, is in no file or process of that user's yet. Prints what was
/// found, and fails unless all held.
pub fn require_mcp(sandbox: &Sandbox, credential: Option<&str>, token: &Token) -> Result<()> {
    let mut probes = Vec::new();
    if let Some(credential) = credential {
        probes.push(in_no_process(
            sandbox,
            "the MCP server's credential",
            credential.trim(),
        )?);
    }
    probes.extend(elsewhere(
        sandbox,
        "the MCP proxy's token",
        token.expose(),
        &[],
    )?);
    ensure!(
        report(&probes),
        "the MCP server's credential or its proxy's token is where the sandbox user can read \
         it: see the failed probes above"
    );
    Ok(())
}

/// Probes where TOKEN is, prints what was found, and fails unless every
/// probe passed: what `run` does before it starts an agent that holds
/// the token.
pub fn require(
    sandbox: &Sandbox,
    token: &Token,
    token_files: &[&str],
    given: Option<&Path>,
    image: Option<&str>,
) -> Result<()> {
    let probes = self::token(sandbox, token, token_files, given, image)?;
    ensure!(
        report(&probes),
        "the run token is not only where it belongs: see the failed probes above"
    );
    Ok(())
}

/// `sandbox check`'s probes of the sandbox CONFIG describes, again, and
/// an error unless all passed: what `[sandbox.check] before-agent` asks
/// of `run` once it has cloned the target. Between the run action's check
/// and here `run` has run commands as the sandbox user, and a check
/// probes what such a user left behind (a process, a unit, a listener).
pub fn recheck(config: &Config) -> Result<()> {
    eprintln!("Probing the sandbox again before the agent starts (sandbox.check.before-agent)");
    let report = crate::sandbox::check::probes(config, None)?;
    let failures: Vec<&str> = report.failures().into_iter().collect();
    ensure!(
        failures.is_empty(),
        "{} sandbox check(s) failed before the agent started: {}",
        failures.len(),
        failures.join(", ")
    );
    Ok(())
}

/// Prints PROBES as the old check did, and says whether all passed.
pub fn report(probes: &[Probe]) -> bool {
    for probe in probes {
        let mark = if probe.passed { "ok  " } else { "FAIL" };
        eprintln!("{mark} {}", super::enter::one_line(&probe.what));
    }
    probes.iter().all(|probe| probe.passed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_found_in_bytes() {
        let dump = b"PATH=/usr/bin\0TOKEN=praxis-run-abc\0\xff\xfe";
        assert!(holds(dump, b"praxis-run-abc"));
        assert!(!holds(dump, b"praxis-run-abd"));
        assert!(!holds(b"", b"praxis-run-abc"));
    }

    /// The token has to be found in its file, and the search has to have
    /// finished, for it to show the token is nowhere else.
    #[test]
    fn a_search_shows_the_token_only_where_it_finished() {
        const FILE: &str = "/home/agent/.config/x.json";
        const CHILD: &str = "/home/agent/.config/child.toml";
        // (the search's exit status, what it listed, the verdict)
        let cases: [(Option<i32>, &[&str], bool); 7] = [
            (Some(0), &[FILE], true),
            // grep could not read some file: still a whole search.
            (Some(2), &[FILE], true),
            (Some(TIMEOUT_EXIT), &[FILE], false),
            (Some(TIMEOUT_EXIT), &[], false),
            (Some(1), &[], false),
            (Some(0), &[FILE, "/tmp/copy"], false),
            (Some(0), &["/tmp/copy"], false),
        ];
        for (code, found, want) in cases {
            assert_eq!(only_in(code, found, &[FILE]), want, "{code:?} {found:?}");
        }
        // With a child agent, both of its files and no other.
        let cases: [(&[&str], bool); 5] = [
            (&[CHILD, FILE], true),
            (&[FILE, CHILD], true),
            (&[FILE], false),
            (&[CHILD], false),
            (&[FILE, CHILD, "/tmp/copy"], false),
        ];
        for (found, want) in cases {
            assert_eq!(only_in(Some(0), found, &[FILE, CHILD]), want, "{found:?}");
        }
    }

    /// The probe that the agent cannot reach the broker fails where
    /// nothing blocks it: here the agent is this process's own user, which
    /// reaches a listener on loopback as the broker's runner does. A broker
    /// that is not there, or a sandbox user that connects nowhere, the run's
    /// own proxy included, fails a control instead of passing the probe.
    #[test]
    fn a_broker_the_agent_reaches_fails_its_probe() {
        let home = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::own(&Config::default(), &home.path().join("agent")).unwrap();
        let listen = || std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (broker, proxy) = (listen(), listen());
        let address = broker.local_addr().unwrap();
        let hosts = [("127.0.0.1".to_owned(), address.port())];
        let addresses = [address];
        let at = |addresses| Broker {
            hosts: &hosts,
            addresses,
            direct: &[],
        };
        let verdicts = |proxy, addresses| -> Vec<bool> {
            unreachable(&sandbox, &at(addresses), proxy)
                .unwrap()
                .iter()
                .map(|probe| probe.passed)
                .collect()
        };
        // (the proxy's control, the resolution's control, the address
        // judged by what it is, the broker's control, the probe)
        let proxy_at = proxy.local_addr().unwrap();
        assert_eq!(
            verdicts(proxy_at, &addresses),
            [true, true, false, true, false]
        );
        let closed = SocketAddr::from(([127, 0, 0, 1], 1));
        assert!(require_unreachable(&sandbox, &at(&addresses), proxy_at, &closed, None).is_err());
        drop(proxy);
        assert_eq!(
            verdicts(proxy_at, &addresses),
            [false, true, false, true, false]
        );
        // An address that does not answer is still judged.
        drop(broker);
        assert_eq!(verdicts(proxy_at, &addresses), [false, true, false, false]);
        assert_eq!(verdicts(proxy_at, &[]), [false, false, false]);
    }

    /// Where the sandbox user connects around the egress proxy: loopback
    /// and what `egress.direct` opens, in any spelling of the address,
    /// whether or not anything listens there.
    #[test]
    fn the_brokers_addresses_are_judged_by_what_they_are() {
        let direct = [Direct::parse("http://100.64.0.1:18080").unwrap()];
        let cases = [
            ("127.0.0.1:18080", true),
            ("127.1.2.3:1", true),
            ("[::1]:443", true),
            ("0.0.0.0:80", true),
            ("[::]:80", true),
            ("[::ffff:127.0.0.1]:80", true),
            ("100.64.0.1:18080", true),
            ("[::ffff:100.64.0.1]:18080", true),
            ("100.64.0.1:18081", false),
            ("100.64.0.2:18080", false),
            ("203.0.113.5:443", false),
            ("[2001:db8::1]:443", false),
            ("[fd7a:115c:a1e0::1]:443", false),
        ];
        for (address, want) in cases {
            assert_eq!(
                around_the_proxy(address.parse().unwrap(), &direct),
                want,
                "{address}"
            );
        }
        let broker = Broker {
            hosts: &[
                ("broker.example".to_owned(), 18080),
                ("fd7a:115c:a1e0::1".to_owned(), 443),
            ],
            addresses: &[
                "100.64.0.1:18080".parse().unwrap(),
                "[fd7a:115c:a1e0::1]:443".parse().unwrap(),
            ],
            direct: &direct,
        };
        assert_eq!(
            forms(&broker),
            [
                "100.64.0.1:18080",
                "[fd7a:115c:a1e0::1]:443",
                "broker.example:18080"
            ]
        );
    }

    /// The probes through the egress proxy, against the Rust proxy itself
    /// on loopback in front of a broker that answers everything, with a
    /// policy that admits every read and write to it: they pass when the
    /// proxy is given the broker to refuse, by its name, its addresses
    /// and their spellings, and each fails when that refusal is removed,
    /// the negative control. A proxy that is not there fails them too.
    #[test]
    fn the_broker_through_the_egress_proxy() {
        const OPEN: &str = "[[write]]\nname = \"all\"\nhosts = [\"localhost\", \"127.0.0.1\", \"::1\"]\n\
                            methods = [\"POST\"]\npaths = [\"/**\"]\n";
        let home = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::own(&Config::default(), &home.path().join("agent")).unwrap();
        let broker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = broker.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in broker.incoming() {
                let Ok(mut stream) = stream else { continue };
                std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let mut buffer = [0; 4096];
                    let _ = stream.read(&mut buffer);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    );
                });
            }
        });
        let hosts = [("localhost".to_owned(), port)];
        let addresses = super::super::api_key::Pinned::lookup(&hosts)
            .unwrap()
            .addresses();
        let forms = forms(&Broker {
            hosts: &hosts,
            addresses: &addresses,
            direct: &[],
        });
        assert!(forms.contains(&format!("127.0.0.1:{port}")), "{forms:?}");
        let verdicts = |egress: SocketAddr| -> Vec<bool> {
            through_egress(&sandbox, &forms, &egress)
                .unwrap()
                .iter()
                .map(|probe| probe.passed)
                .collect()
        };
        let refusing = crate::sandbox::proxy::serve_for_tests(OPEN, &[format!("localhost:{port}")]);
        let got = verdicts(refusing);
        assert_eq!(got.len(), forms.len() * 3);
        assert!(got.iter().all(|passed| *passed), "{got:?}");
        let open = crate::sandbox::proxy::serve_for_tests(OPEN, &[]);
        let got = verdicts(open);
        assert!(got.iter().all(|passed| !passed), "{got:?}");
        assert!(
            verdicts(SocketAddr::from(([127, 0, 0, 1], 1)))
                .iter()
                .all(|passed| !passed)
        );
    }

    /// Only the egress proxy's 403 for a refused destination shows the
    /// refusal.
    #[test]
    fn a_refusal_is_the_proxys_for_the_broker() {
        let reason = crate::sandbox::proxy::REFUSED_DESTINATION;
        let cases = [
            (format!("HTTP/1.1 403 Forbidden\r\nX-Egress-Denied: {reason}\r\n"), true),
            (format!("HTTP/1.1 403 Forbidden\nx-egress-denied:  {reason}"), true),
            ("HTTP/1.1 403 Forbidden\r\nX-Egress-Denied: host is not in the domain allowlist\r\n".to_owned(), false),
            ("HTTP/1.1 403 Forbidden\r\n".to_owned(), false),
            (format!("HTTP/1.1 200 OK\r\nX-Egress-Denied: {reason}\r\n"), false),
            ("HTTP/1.1 502 Bad Gateway\r\n".to_owned(), false),
            (String::new(), false),
        ];
        for (head, want) in cases {
            assert_eq!(refused_as_broker(&head), want, "{head}");
        }
        assert_eq!(
            proxy_request("POST", "[::1]:8080"),
            "POST http://[::1]:8080/v1/runs HTTP/1.1\r\nHost: [::1]:8080\r\n\
             Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
        );
    }

    #[test]
    fn a_failed_probe_fails_the_report() {
        let probe = |passed| Probe {
            what: "a probe".into(),
            passed,
        };
        assert!(report(&[probe(true), probe(true)]));
        assert!(!report(&[probe(true), probe(false)]));
        assert!(report(&[]));
    }
}
