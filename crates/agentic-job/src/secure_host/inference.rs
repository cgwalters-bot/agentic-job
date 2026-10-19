//! `agentic-job secure-host inference CONFIG`: a TCP connection to the
//! configuration's inference proxy as the runner's user, before setup, so
//! that a runner off the proxy's network fails here and says so rather
//! than in a probe of setup's rules. It sends nothing: no HTTP request,
//! identity token or model credential. A configuration without a proxy,
//! a deterministic job's, and the scripted agent are not checked.

use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use hyper::Uri;

use crate::config::{Config, Register};

/// For each address the proxy's name resolves to.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The agent that needs no model, and so no proxy.
const SCRIPTED_AGENT: &str = "fake";

/// Where a connection goes: the host of `url` and its port, the scheme's
/// when it names none. `None` for a configuration that needs no proxy.
pub fn address(config: &Config) -> Result<Option<(String, u16)>> {
    let url = &config.inference.url;
    if url.is_empty() || config.agent.name == SCRIPTED_AGENT {
        return Ok(None);
    }
    let refusal = || format!("inference.url must be an HTTP(S) URL, not {url:?}");
    let uri: Uri = url.parse().with_context(refusal)?;
    let default = match uri.scheme_str() {
        Some("http") => 80,
        Some("https") => 443,
        _ => bail!(refusal()),
    };
    let (Some(authority), Some(host)) = (uri.authority(), uri.host()) else {
        bail!(refusal());
    };
    // `Uri` takes a port that is not a number, and then has none.
    let port = match uri.port_u16() {
        Some(port) => port,
        None => {
            let named = authority.as_str().rsplit('@').next().unwrap_or_default();
            ensure!(named == host, refusal());
            default
        }
    };
    // An IPv6 literal keeps its brackets in the URI, not in the address.
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    ensure!(!host.is_empty(), refusal());
    Ok(Some((host.to_owned(), port)))
}

/// Opens one connection to any of the addresses HOST resolves to, and
/// closes it.
pub fn connect(host: &str, port: u16) -> Result<()> {
    let mut last = None;
    for address in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(_) => return Ok(()),
            Err(err) => last = Some(err),
        }
    }
    Err(last.map_or_else(|| anyhow::anyhow!("{host} has no address"), Into::into))
}

pub fn check(config: &Config, connect: impl FnOnce(&str, u16) -> Result<()>) -> Result<()> {
    let Some((host, port)) = address(config)? else {
        return Ok(());
    };
    // A broker's tailnet name, which a runner that joined without the
    // tailnet's DNS cannot resolve, is given its address by the job.
    let oidc = config.inference.register == Some(Register::GithubOidc);
    let named = if oidc && host.parse::<IpAddr>().is_err() {
        format!(
            "; for {host}, a name this runner may not resolve, pass prepare its address as \
             inference-address"
        )
    } else {
        String::new()
    };
    connect(&host, port).with_context(|| {
        format!(
            "control failed: the runner cannot reach the inference proxy at {}: join its \
             network in a step before secure-host, or use a runner on it{named}",
            config.inference.url
        )
    })
}

pub fn run(path: &Path) -> Result<()> {
    check(&Config::load(path)?, connect)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::net::TcpListener;

    use super::*;

    fn config(agent: &str, url: &str) -> Config {
        let mut config = Config::default();
        config.agent.name = agent.to_owned();
        config.inference.url = url.to_owned();
        config
    }

    /// An agent, its proxy's URL, and where a check connects, if at all.
    type Case = (&'static str, &'static str, Option<(&'static str, u16)>);

    /// Where each configuration connects, if it does at all.
    #[test]
    fn addresses() {
        let cases: &[Case] = &[
            (
                "claude",
                "http://100.64.0.1:8080/path",
                Some(("100.64.0.1", 8080)),
            ),
            (
                "claude",
                "https://proxy.example",
                Some(("proxy.example", 443)),
            ),
            ("opencode", "http://[::1]", Some(("::1", 80))),
            (
                "codex",
                "http://proxy.invalid:8080",
                Some(("proxy.invalid", 8080)),
            ),
            // Even with an unreachable proxy, the scripted agent connects nowhere.
            ("fake", "http://proxy.invalid:8080", None),
            ("claude", "", None),
        ];
        for &(agent, url, want) in cases {
            let got = address(&config(agent, url)).unwrap();
            assert_eq!(
                got,
                want.map(|(host, port)| (host.to_owned(), port)),
                "{url}"
            );
        }
    }

    #[test]
    fn refusals() {
        for url in [
            "file:///etc/passwd",
            "http://",
            "http://proxy:invalid",
            "proxy:8080",
            "/path",
        ] {
            let err = address(&config("claude", url)).unwrap_err();
            assert!(
                format!("{err:#}").contains("must be an HTTP(S) URL"),
                "{url}: {err:#}"
            );
        }
    }

    /// A failed connection names the proxy and what to do; a skipped
    /// configuration never calls `connect`.
    #[test]
    fn the_check() {
        let calls = RefCell::new(Vec::new());
        let failing = |host: &str, port| {
            calls.borrow_mut().push((host.to_owned(), port));
            bail!("connection refused")
        };
        let err = check(&config("claude", "http://127.0.0.1:8080"), failing).unwrap_err();
        assert!(
            format!("{err:#}").contains(
                "control failed: the runner cannot reach the inference proxy at \
                 http://127.0.0.1:8080: join its network in a step before secure-host"
            ),
            "{err:#}"
        );
        assert!(!format!("{err:#}").contains("inference-address"), "{err:#}");
        assert_eq!(*calls.borrow(), [("127.0.0.1".to_owned(), 8080)]);
        // A broker's name the runner could not reach is named, with the
        // way out; a provider's name has none.
        let mut broker = config("claude", "http://broker:8080");
        broker.inference.register = Some(Register::GithubOidc);
        let err = check(&broker, failing).unwrap_err();
        assert!(
            format!("{err:#}").contains(
                "for broker, a name this runner may not resolve, pass prepare its address as \
                 inference-address"
            ),
            "{err:#}"
        );
        broker.inference.register = Some(Register::ApiKey);
        let err = check(&broker, failing).unwrap_err();
        assert!(!format!("{err:#}").contains("inference-address"), "{err:#}");
        check(&config("fake", "http://127.0.0.1:8080"), |_: &str, _| {
            panic!("connected")
        })
        .unwrap();
        check(&Config::default(), |_: &str, _| panic!("connected")).unwrap();
    }

    #[test]
    fn real_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        check(
            &config("claude", &format!("http://127.0.0.1:{port}")),
            connect,
        )
        .unwrap();
        drop(listener);
        assert!(
            check(
                &config("claude", &format!("http://127.0.0.1:{port}")),
                connect
            )
            .is_err()
        );
    }

    /// The file `agentic-job config` writes, with and without a proxy.
    #[test]
    fn from_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[sandbox]\nuser = \"agent\"\n").unwrap();
        run(&path).unwrap();
        std::fs::write(
            &path,
            "[agent]\nname = \"claude\"\n\n[inference]\nurl = \"ftp://proxy\"\n",
        )
        .unwrap();
        assert!(run(&path).is_err());
        assert!(run(&dir.path().join("absent.toml")).is_err());
    }
}
