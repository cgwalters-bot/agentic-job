//! The egress policy, as `egress/policy.py` has it, line for line: the
//! two must decide every request alike while both proxies ship, and the
//! tests below are `egress/test_policy.py`'s cases.
//!
//! Reads default to open: GET, HEAD and OPTIONS without a body go to any
//! host not on the threat feed. The optional `[egress]` allowlist gates
//! all destinations; its entries are domains, or gh-aw's ecosystem
//! identifiers for groups of them. Anything else (POST, PUT, PATCH,
//! DELETE, a WebSocket, a read with a body) is a write, allowed only to
//! the endpoints of a `[[write]]` rule. The host is the one the
//! connection really goes to; a Host header or TLS server name naming
//! another host (domain fronting) is refused.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;

pub const READ_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

/// What a WebSocket upgrade is matched as in a write rule: once
/// upgraded, frames go both ways, so it is a write.
pub const WEBSOCKET: &str = "WEBSOCKET";

const WRITE_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE", WEBSOCKET];

pub const MAX_ALLOWED_DOMAINS: usize = 256;

/// The longest DNS name.
const MAX_DOMAIN: usize = 253;

/// gh-aw's ecosystem identifiers and their hosts, derived by
/// `egress/ecosystems.py`.
pub const ECOSYSTEMS: &str = include_str!("../../../../../egress/ecosystem_domains.json");

/// The most of a threat feed read: the pinned one is a few MiB.
const MAX_DENYLIST_BYTES: u64 = 64 << 20;

/// The most of a policy file read, as `sandbox::egress` checks it.
const MAX_POLICY_BYTES: u64 = 1 << 20;

pub const READ: &str = "read";
pub const TUNNEL: &str = "tunnel";
pub const ON_FEED: &str = "host is on the threat feed";
pub const NOT_ALLOWED: &str = "host is not in the domain allowlist";
pub const OTHER_HOST: &str = "the Host header names another host";
pub const OTHER_SNI: &str = "the TLS server name names another host";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    /// Why: "read", a write rule's name, or the refusal.
    pub reason: String,
}

impl Decision {
    fn allow(reason: &str) -> Self {
        Self {
            allowed: true,
            reason: reason.to_owned(),
        }
    }

    pub fn deny(reason: &str) -> Self {
        Self {
            allowed: false,
            reason: reason.to_owned(),
        }
    }
}

/// HOST lowercased, without brackets, port or trailing dots.
pub fn normalize_host(host: &str) -> String {
    let host = host.trim().to_lowercase();
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(inside, _)| inside)
    } else if host.matches(':').count() == 1 {
        host.split_once(':').map_or(host.as_str(), |(name, _)| name)
    } else {
        &host
    };
    host.trim_end_matches('.').to_owned()
}

/// A path glob as a regex: '*' is any run of characters but '/', '**'
/// any run at all; everything else is literal.
fn glob_regex(glob: &str) -> Result<Regex> {
    let mut body = String::from("^");
    let mut rest = glob;
    while let Some(star) = rest.find('*') {
        body.push_str(&regex::escape(&rest[..star]));
        if rest[star..].starts_with("**") {
            body.push_str(".*");
            rest = &rest[star + 2..];
        } else {
            body.push_str("[^/]*");
            rest = &rest[star + 1..];
        }
    }
    body.push_str(&regex::escape(rest));
    body.push_str(r"\z");
    Regex::new(&body).with_context(|| format!("path glob {glob:?}"))
}

/// The runner's own writes, which `egress.write-policy` sends through the
/// proxy with every other process of the runner's uid: the Actions
/// service (job and step status, logs, the results service behind
/// artifacts, caches and summaries, live logs over a WebSocket), and
/// the Azure storage it hands out signed upload URLs for. Each covers a
/// domain and every name under it, which a policy file cannot say: the
/// service's hosts (`run-actions-N-azure-REGION`, `pipelinesghubeusN`)
/// and its storage accounts (`productionresultssaN`) are not published,
/// so exact names cannot be known before the job. Only the transparent
/// listener's connections get them, never the sandbox user's.
///
/// Both are write channels to anyone with a token for them: the Actions
/// service takes another repository's runtime token, and the storage
/// domain is every Azure account's, an attacker's too, with a signed URL
/// of its own. They stop nothing there; they keep the job working.
const RUNNER_WRITES: &[(&str, &str, &[&str])] = &[
    (
        "GitHub Actions service (runner)",
        "actions.githubusercontent.com",
        WRITE_METHODS,
    ),
    // Azure's block, append and put-blob uploads are all PUTs.
    (
        "GitHub Actions results storage (runner)",
        "blob.core.windows.net",
        &["PUT"],
    ),
];

#[derive(Debug, Clone)]
struct WriteRule {
    name: String,
    hosts: HashSet<String>,
    /// Domains whose names, each and all under it, the rule covers: only
    /// [`RUNNER_WRITES`] has any, a policy file never.
    domains: Vec<String>,
    methods: HashSet<String>,
    paths: Vec<Regex>,
}

impl WriteRule {
    fn matches(&self, method: &str, host: &str, path: &str) -> bool {
        let under = |domain: &String| {
            host.strip_suffix(domain.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
        };
        self.methods.contains(method)
            && (self.hosts.contains(host) || self.domains.iter().any(under))
            && self.paths.iter().any(|glob| glob.is_match(path))
    }

    fn runner(name: &str, domain: &str, methods: &[&str]) -> Result<Self> {
        Ok(Self {
            name: name.to_owned(),
            hosts: HashSet::new(),
            domains: vec![domain.to_owned()],
            methods: methods.iter().map(|method| (*method).to_owned()).collect(),
            paths: vec![glob_regex("/**")?],
        })
    }

    fn parse(entry: &toml::Value) -> Result<Self> {
        let table = entry
            .as_table()
            .with_context(|| format!("a [[write]] rule is a table: {entry}"))?;
        let name = table
            .get("name")
            .and_then(toml::Value::as_str)
            .filter(|name| !name.is_empty())
            .with_context(|| format!("a [[write]] rule needs a name: {entry}"))?;
        let mut lists = BTreeMap::new();
        for key in ["hosts", "methods", "paths"] {
            let values: Option<Vec<&str>> = table
                .get(key)
                .and_then(toml::Value::as_array)
                .filter(|values| !values.is_empty())
                .and_then(|values| {
                    values
                        .iter()
                        .map(|value| value.as_str().filter(|value| !value.is_empty()))
                        .collect()
                });
            let values = values
                .with_context(|| format!("[[write]] {name}: {key} must be a list of strings"))?;
            lists.insert(key, values);
        }
        let unknown: Vec<&str> = table
            .keys()
            .map(String::as_str)
            .filter(|key| !["name", "hosts", "methods", "paths", "why"].contains(key))
            .collect();
        ensure!(
            unknown.is_empty(),
            "[[write]] {name}: unknown keys {unknown:?}"
        );
        let methods: HashSet<String> = lists["methods"]
            .iter()
            .map(|method| method.to_uppercase())
            .collect();
        ensure!(
            methods
                .iter()
                .all(|method| WRITE_METHODS.contains(&method.as_str())),
            "[[write]] {name}: methods must be among {WRITE_METHODS:?}"
        );
        for path in &lists["paths"] {
            ensure!(
                path.starts_with('/'),
                "[[write]] {name}: path '{path}' must start with /"
            );
        }
        Ok(Self {
            name: name.to_owned(),
            hosts: lists["hosts"]
                .iter()
                .map(|host| normalize_host(host))
                .collect(),
            domains: Vec::new(),
            methods,
            paths: lists["paths"]
                .iter()
                .map(|path| glob_regex(path))
                .collect::<Result<_>>()?,
        })
    }
}

/// The hosts gh-aw's ecosystem identifier NAME stands for in ECOSYSTEMS,
/// each checked afterwards like an entry written out. gh-aw writes some
/// as '*.x', for the subdomains of x; an entry here already covers x and
/// all of its subdomains, so '*.x' becomes x, which adds only x itself,
/// a name of the same owner. Any other '*' is left alone, and refuses
/// the policy.
fn ecosystem_hosts(ecosystems: &str, name: &str) -> Result<Vec<String>> {
    let data: serde_json::Value =
        serde_json::from_str(ecosystems).context("reading gh-aw's ecosystem identifiers")?;
    let hosts: Option<Vec<String>> = data
        .get("ecosystems")
        .and_then(|ecosystems| ecosystems.get(name))
        .and_then(serde_json::Value::as_array)
        .and_then(|hosts| {
            hosts
                .iter()
                .map(|host| {
                    host.as_str()
                        .map(|host| host.strip_prefix("*.").unwrap_or(host).to_owned())
                })
                .collect()
        });
    hosts.with_context(|| {
        format!("[egress] allow: {name:?} is neither a domain nor a known ecosystem identifier")
    })
}

fn is_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let alnum = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    (1..=63).contains(&bytes.len())
        && bytes.first().is_some_and(alnum)
        && bytes.last().is_some_and(alnum)
        && bytes.iter().all(|byte| alnum(byte) || *byte == b'-')
}

/// The `[egress]` table: None for reads-anywhere, else the allowed
/// domains. An explicit mode avoids silently ignoring a caller's
/// intended restriction.
fn parse_allowlist(data: &toml::Value, ecosystems: &str) -> Result<Option<HashSet<String>>> {
    let table = data
        .as_table()
        .filter(|table| table.keys().all(|key| key == "mode" || key == "allow"))
        .context("[egress] accepts only mode and allow")?;
    match table.get("mode").map(toml::Value::as_str) {
        None | Some(Some("reads-anywhere")) => {
            ensure!(
                !table.contains_key("allow"),
                "[egress] allow requires mode = allowlist"
            );
            return Ok(None);
        }
        Some(Some("allowlist")) => {}
        Some(_) => bail!("[egress] mode must be reads-anywhere or allowlist"),
    }
    let entries = match table.get("allow") {
        None => &[][..],
        Some(entries) => entries
            .as_array()
            .filter(|entries| entries.len() <= MAX_ALLOWED_DOMAINS)
            .with_context(|| {
                format!("[egress] allow must be a list of at most {MAX_ALLOWED_DOMAINS} domains")
            })?,
    };
    let mut domains = Vec::new();
    for entry in entries {
        let entry = entry
            .as_str()
            .filter(|entry| entry.chars().count() <= MAX_DOMAIN)
            .context("[egress] allow entries must be DNS domain names")?;
        // A domain has two labels at least: an entry without a dot can
        // only be an ecosystem identifier.
        if entry.contains('.') {
            domains.push(entry.to_owned());
        } else {
            domains.extend(ecosystem_hosts(ecosystems, entry)?);
        }
    }
    // What identifiers expand to counts too, so naming a few cannot make
    // the list longer than one written out could be.
    ensure!(
        domains.len() <= MAX_ALLOWED_DOMAINS,
        "[egress] allow names {} domains with its ecosystems, more than {MAX_ALLOWED_DOMAINS}",
        domains.len()
    );
    let mut result = HashSet::new();
    for domain in domains {
        ensure!(
            domain.chars().count() <= MAX_DOMAIN,
            "[egress] allow entries must be DNS domain names"
        );
        // One terminal dot names the root; refuse more rather than guess
        // what a malformed entry meant.
        let lower = domain.to_lowercase();
        let domain = lower.strip_suffix('.').unwrap_or(&lower);
        let labels: Vec<&str> = domain.split('.').collect();
        ensure!(
            labels.len() >= 2 && labels.iter().all(|label| is_label(label)),
            "[egress] allow entries must be DNS domain names, not URLs or wildcards"
        );
        ensure!(
            domain.parse::<IpAddr>().is_err(),
            "[egress] allow does not accept IP literals"
        );
        result.insert(domain.to_owned());
    }
    Ok(Some(result))
}

/// A domain list, one per line ('#' comments), as HaGeZi's wildcard
/// feeds are: each entry covers its subdomains too.
fn read_denylist(path: &Path) -> Result<HashSet<String>> {
    let bytes = crate::files::read_regular(path, MAX_DENYLIST_BYTES)
        .with_context(|| format!("reading the threat feed {}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes)
        .lines()
        .map(|line| normalize_host(line.split('#').next().unwrap_or_default()))
        .filter(|domain| !domain.is_empty())
        .collect())
}

#[derive(Debug, Default, Clone)]
pub struct Policy {
    writes: Vec<WriteRule>,
    denylist: HashSet<String>,
    allowlist: Option<HashSet<String>>,
}

impl Policy {
    /// The policy file at POLICY, and the threat feed at DENYLIST if any.
    pub fn load(policy: &Path, denylist: Option<&Path>) -> Result<Self> {
        let bytes = crate::files::read_regular(policy, MAX_POLICY_BYTES)
            .with_context(|| format!("reading {}", policy.display()))?;
        let text = String::from_utf8(bytes)
            .with_context(|| format!("{} is not UTF-8", policy.display()))?;
        let mut loaded = Self::parse(&text, ECOSYSTEMS)
            .with_context(|| format!("loading {}", policy.display()))?;
        if let Some(path) = denylist {
            loaded.denylist = read_denylist(path)?;
        }
        Ok(loaded)
    }

    /// This policy with [`RUNNER_WRITES`] after its own rules: what the
    /// runner's processes are held to under `egress.write-policy`.
    pub fn with_runner_writes(&self) -> Result<Self> {
        let mut policy = self.clone();
        for (name, domain, methods) in RUNNER_WRITES {
            policy
                .writes
                .push(WriteRule::runner(name, domain, methods)?);
        }
        Ok(policy)
    }

    /// A policy file's TEXT, its ecosystem identifiers from ECOSYSTEMS.
    pub fn parse(text: &str, ecosystems: &str) -> Result<Self> {
        let data: toml::Table = toml::from_str(text).context("parsing the policy")?;
        let unknown: Vec<&str> = data
            .keys()
            .map(String::as_str)
            .filter(|key| *key != "write" && *key != "egress")
            .collect();
        ensure!(unknown.is_empty(), "unknown tables {unknown:?}");
        let writes = match data.get("write") {
            None => Vec::new(),
            Some(rules) => rules
                .as_array()
                .context("[[write]] is not a list of rules")?
                .iter()
                .map(WriteRule::parse)
                .collect::<Result<_>>()?,
        };
        let allowlist = match data.get("egress") {
            None => None,
            Some(egress) => parse_allowlist(egress, ecosystems)?,
        };
        Ok(Self {
            writes,
            denylist: HashSet::new(),
            allowlist,
        })
    }

    fn domain_allowed(&self, host: &str) -> bool {
        let Some(allowlist) = &self.allowlist else {
            return true;
        };
        let host = normalize_host(host);
        if host.parse::<IpAddr>().is_ok() {
            return false;
        }
        // Label boundaries prevent notexample.com from matching
        // example.com. Applied to writes too: otherwise a write rule
        // bypasses CONNECT's gate.
        allowlist.iter().any(|domain| {
            host == *domain
                || host
                    .strip_suffix(domain.as_str())
                    .is_some_and(|rest| rest.ends_with('.'))
        })
    }

    /// Whether HOST or a domain it is under is on the threat feed.
    fn denylisted(&self, host: &str) -> bool {
        let host = normalize_host(host);
        let labels: Vec<&str> = host.split('.').collect();
        (0..labels.len()).any(|i| self.denylist.contains(&labels[i..].join(".")))
    }

    /// A CONNECT to HOST: what goes through the tunnel is checked again,
    /// request by request.
    pub fn connect(&self, host: &str) -> Decision {
        if self.denylisted(host) {
            return Decision::deny(ON_FEED);
        }
        if !self.domain_allowed(host) {
            return Decision::deny(NOT_ALLOWED);
        }
        Decision::allow(TUNNEL)
    }

    /// A request to HOST (where the connection goes).
    pub fn request(&self, request: &Request) -> Decision {
        let host = normalize_host(request.host);
        let method = if request.websocket {
            WEBSOCKET.to_owned()
        } else {
            request.method.to_uppercase()
        };
        if self.denylisted(&host) {
            return Decision::deny(ON_FEED);
        }
        if !self.domain_allowed(&host) {
            return Decision::deny(NOT_ALLOWED);
        }
        let other = |name: Option<&str>| {
            name.is_some_and(|name| !name.is_empty() && normalize_host(name) != host)
        };
        if other(request.host_header) {
            return Decision::deny(OTHER_HOST);
        }
        if other(request.sni) {
            return Decision::deny(OTHER_SNI);
        }
        let read = READ_METHODS.contains(&method.as_str());
        if read && !request.has_body {
            return Decision::allow(READ);
        }
        let path = request.path.split('?').next().unwrap_or_default();
        let path = path.split('#').next().unwrap_or_default();
        let path = if path.is_empty() { "/" } else { path };
        if let Some(rule) = self
            .writes
            .iter()
            .find(|rule| rule.matches(&method, &host, path))
        {
            return Decision::allow(&rule.name);
        }
        let what = if read { "a read with a body" } else { &method };
        Decision::deny(&format!("{what} to an endpoint not in the write allowlist"))
    }
}

/// What [`Policy::request`] decides on.
#[derive(Debug, Default, Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub host_header: Option<&'a str>,
    pub sni: Option<&'a str>,
    pub has_body: bool,
    pub websocket: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY_TOML: &str = include_str!("../../../../../egress/policy.toml");

    fn shipped() -> Policy {
        let mut policy = Policy::parse(POLICY_TOML, ECOSYSTEMS).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let feed = dir.path().join("feed.txt");
        std::fs::write(
            &feed,
            "# a feed\nevil.example\nbad.test # trailing comment\n\n",
        )
        .unwrap();
        policy.denylist = read_denylist(&feed).unwrap();
        policy
    }

    fn allowlist(allow: &str) -> Result<Policy> {
        Policy::parse(
            &format!("[egress]\nmode = \"allowlist\"\nallow = {allow}\n"),
            ECOSYSTEMS,
        )
    }

    fn get<'a>(host: &'a str) -> Request<'a> {
        Request {
            method: "GET",
            host,
            path: "/",
            ..Request::default()
        }
    }

    /// `test_policy.py`'s `test_requests`, case for case.
    #[test]
    fn requests() {
        let policy = shipped();
        let with = |method, host, path| Request {
            method,
            host,
            path,
            ..Request::default()
        };
        let cases = [
            (with("GET", "index.crates.io", "/se/rd/serde"), true),
            (
                with("HEAD", "static.crates.io", "/crates/x/x-1.0.0.crate"),
                true,
            ),
            (with("OPTIONS", "example.com", "/"), true),
            (with("GET", "anything.example.org", "/?q=1"), true),
            (with("GET", "GitHub.com.", "/"), true),
            // writes only where policy.toml lists them
            (
                with("POST", "github.com", "/bootc-dev/bootc/git-upload-pack"),
                true,
            ),
            (
                with("POST", "github.com", "/bootc-dev/bootc.git/git-upload-pack"),
                true,
            ),
            (
                with(
                    "POST",
                    "github.com",
                    "/bootc-dev/bootc.git/git-upload-pack?x=1",
                ),
                true,
            ),
            (
                with(
                    "POST",
                    "github.com",
                    "/bootc-dev/bootc.git/git-receive-pack",
                ),
                false,
            ),
            (
                with("POST", "evil.github.com", "/a/b/git-upload-pack"),
                false,
            ),
            (with("POST", "example.com", "/a/b/git-upload-pack"), false),
            (with("PUT", "github.com", "/a/b/git-upload-pack"), false),
            (
                with(
                    "POST",
                    "registry.npmjs.org",
                    "/-/npm/v1/security/advisories/bulk",
                ),
                true,
            ),
            (
                with(
                    "POST",
                    "registry.npmjs.org",
                    "/-/npm/v1/security/advisories/bulk/x",
                ),
                false,
            ),
            (with("PUT", "registry.npmjs.org", "/some-package"), false),
            // gh's reads; the read-only token is what refuses a mutation
            (
                with(
                    "GET",
                    "api.github.com",
                    "/repos/a/b/pulls/1/comments?per_page=100",
                ),
                true,
            ),
            (
                with("GET", "api.github.com", "/repos/a/b/pulls/1/reviews"),
                true,
            ),
            (with("POST", "api.github.com", "/graphql"), true),
            (with("post", "api.github.com", "/graphql"), true),
            (with("POST", "api.github.com", "/graphql/x"), false),
            (with("POST", "github.com", "/graphql"), false),
            (
                with("POST", "api.github.com", "/repos/a/b/issues/1/comments"),
                false,
            ),
            (
                with("POST", "api.github.com", "/repos/a/b/pulls/1/comments"),
                false,
            ),
            (
                with("PATCH", "api.github.com", "/repos/a/b/issues/1"),
                false,
            ),
            (with("PUT", "api.github.com", "/graphql"), false),
            (with("DELETE", "example.com", "/"), false),
            (with("PATCH", "example.com", "/"), false),
            // reads that carry data are writes
            (
                Request {
                    has_body: true,
                    ..get("example.com")
                },
                false,
            ),
            (
                Request {
                    websocket: true,
                    ..get("github.com")
                },
                false,
            ),
            // the threat feed covers subdomains, for reads too
            (get("evil.example"), false),
            (get("a.b.Evil.Example"), false),
            (get("bad.test"), false),
            (get("notevil.example"), true),
            // domain fronting
            (
                Request {
                    host_header: Some("github.com:443"),
                    ..get("github.com")
                },
                true,
            ),
            (
                Request {
                    host_header: Some("evil.example.org"),
                    ..get("github.com")
                },
                false,
            ),
            (
                Request {
                    host_header: Some(""),
                    ..get("github.com")
                },
                true,
            ),
            (
                Request {
                    sni: Some("github.com"),
                    ..get("github.com")
                },
                true,
            ),
            (
                Request {
                    sni: Some("other.example.org"),
                    ..get("github.com")
                },
                false,
            ),
            (
                Request {
                    host_header: Some("[::1]:8080"),
                    ..get("::1")
                },
                true,
            ),
        ];
        for (request, allowed) in cases {
            let decision = policy.request(&request);
            assert_eq!(
                decision.allowed, allowed,
                "{request:?}: {}",
                decision.reason
            );
        }
        assert!(policy.connect("github.com").allowed);
        assert!(!policy.connect("x.evil.example").allowed);
    }

    #[test]
    fn allowlist_gates_every_destination() {
        let mut policy = allowlist("[\"Example.COM.\"]").unwrap();
        policy.denylist = HashSet::from(["evil.example.com".to_owned()]);
        policy.writes = shipped().writes;
        for (host, allowed) in [
            ("example.com", true),
            ("A.Example.COM.:443", true),
            ("notexample.com", false),
            ("example.com.attacker.test", false),
            ("other.test", false),
            ("evil.example.com", false),
            ("sub.evil.example.com", false),
            ("192.0.2.1", false),
            ("[2001:db8::1]:443", false),
            ("::1", false),
        ] {
            assert_eq!(policy.connect(host).allowed, allowed, "{host}");
            for method in READ_METHODS {
                let request = Request {
                    method,
                    ..get(host)
                };
                assert_eq!(policy.request(&request).allowed, allowed, "{method} {host}");
            }
        }
        for request in [
            Request {
                host_header: Some("other.test"),
                ..get("example.com")
            },
            Request {
                sni: Some("other.test"),
                ..get("example.com")
            },
            Request {
                has_body: true,
                ..get("example.com")
            },
        ] {
            assert!(!policy.request(&request).allowed, "{request:?}");
        }
        let graphql = |method| Request {
            method,
            host: "api.github.com",
            path: "/graphql",
            ..Request::default()
        };
        assert!(!policy.request(&graphql("POST")).allowed);
        policy.allowlist = Some(HashSet::from(["api.github.com".to_owned()]));
        assert!(policy.request(&graphql("POST")).allowed);
        assert!(!policy.request(&graphql("DELETE")).allowed);
    }

    #[test]
    fn allowlist_config() {
        for text in ["", "[egress]\nmode = \"reads-anywhere\""] {
            let policy = Policy::parse(text, ECOSYSTEMS).unwrap();
            assert!(policy.connect("other.test").allowed, "{text}");
        }
        let empty = Policy::parse("[egress]\nmode = \"allowlist\"", ECOSYSTEMS).unwrap();
        assert!(!empty.connect("example.com").allowed);
        let too_many = format!(
            "[{}]",
            vec!["\"a.example\""; MAX_ALLOWED_DOMAINS + 1].join(", ")
        );
        for value in [
            "\"example.com\"",
            "[\"*.example.com\"]",
            "[\"https://example.com\"]",
            "[\"example.com:443\"]",
            "[\"192.0.2.1\"]",
            "[\"::1\"]",
            "[1]",
            "[\"localhost\"]",
            "[\"-bad.example\"]",
            "[\"a..example\"]",
            "[\"example.com..\"]",
            "[\"example.com...\"]",
            "[\".\"]",
            &too_many,
        ] {
            assert!(allowlist(value).is_err(), "{value}");
        }
        for text in [
            "[egress]\nmode = \"typo\"",
            "[egress]\nallow = []",
            "[egress]\nmode = \"allowlist\"\nextra = true",
            "egress = []",
            "[egress]\nmode = 1",
            "[other]",
            "write = 1",
        ] {
            assert!(Policy::parse(text, ECOSYSTEMS).is_err(), "{text}");
        }
    }

    #[test]
    fn ecosystems() {
        let padded = |n: usize, extra: &str| {
            let mut entries = vec!["\"a.example\"".to_owned(); n];
            entries.push(extra.to_owned());
            format!("[{}]", entries.join(", "))
        };
        // (allow, hosts allowed, hosts refused), against gh-aw's groups as
        // ecosystem_domains.json has them
        let cases = [
            (
                "[\"github\"]".to_owned(),
                &[
                    "github.com",
                    "api.github.com",
                    "raw.githubusercontent.com",
                    "githubusercontent.com",
                ][..],
                &["example.com", "pypi.org", "github.com.attacker.test"][..],
            ),
            (
                "[\"python\"]".to_owned(),
                &["pypi.org", "files.pythonhosted.org", "pythonhosted.org"],
                &["github.com"],
            ),
            (
                "[\"node\"]".to_owned(),
                &["registry.npmjs.org"],
                &["pypi.org"],
            ),
            (
                "[\"containers\"]".to_owned(),
                &["ghcr.io", "registry-1.docker.io", "auth.docker.io"],
                &["docker.example"],
            ),
            (
                "[\"github\", \"example.com\"]".to_owned(),
                &["github.com", "a.example.com"],
                &["pypi.org"],
            ),
            // the bound counts what identifiers expand to
            (
                padded(MAX_ALLOWED_DOMAINS - 13, "\"github\""),
                &["github.com"],
                &[],
            ),
        ];
        for (allow, allowed, refused) in cases {
            let policy = allowlist(&allow).unwrap();
            for host in allowed {
                assert!(policy.connect(host).allowed, "{host}");
            }
            for host in refused {
                assert!(!policy.connect(host).allowed, "{host}");
            }
        }
        for allow in [
            "[\"nosuch\"]".to_owned(),
            "[\"GitHub\"]".to_owned(),
            "[\"\"]".to_owned(),
            "[\"localhost\"]".to_owned(),
            // gh-aw's loopback names and IP literals fail as written-out
            // entries would
            "[\"local\"]".to_owned(),
            padded(MAX_ALLOWED_DOMAINS - 12, "\"github\""),
            format!("[{}]", ["\"java\""; 8].join(", ")),
        ] {
            assert!(allowlist(&allow).is_err(), "{allow}");
        }
    }

    /// Only a leading '*.' is gh-aw's subdomain wildcard; anything else
    /// with '*' refuses the policy.
    #[test]
    fn ecosystem_wildcards() {
        for (host, want) in [
            ("*.example.com", Some("example.com")),
            ("example.com", Some("example.com")),
            ("*.*.example.com", None),
            ("a.*.example.com", None),
            ("*", None),
            ("*example.com", None),
            ("example.*", None),
            ("https://example.com", None),
        ] {
            let ecosystems = serde_json::json!({"ecosystems": {"test": [host]}}).to_string();
            let policy = Policy::parse(
                "[egress]\nmode = \"allowlist\"\nallow = [\"test\"]",
                &ecosystems,
            );
            match want {
                None => assert!(policy.is_err(), "{host}"),
                Some(want) => assert_eq!(
                    policy.unwrap().allowlist,
                    Some(HashSet::from([want.to_owned()])),
                    "{host}"
                ),
            }
        }
    }

    /// The runner's built-in writes reach the Actions service's names and
    /// the storage domain's, with PUT alone there, and nothing that only
    /// ends in the same letters; the shipped policy has none of them.
    #[test]
    fn runner_writes() {
        let policy = shipped();
        let runner = policy.with_runner_writes().unwrap();
        let write = |method, host| Request {
            method,
            host,
            path: "/twirp/x/CreateArtifact",
            has_body: true,
            ..Request::default()
        };
        let cases = [
            (
                "POST",
                "results-receiver.actions.githubusercontent.com",
                true,
            ),
            (
                "PATCH",
                "run-actions-3-azure-eastus.actions.githubusercontent.com",
                true,
            ),
            ("POST", "Actions.GitHubUserContent.com.", true),
            ("PUT", "productionresultssa7.blob.core.windows.net", true),
            ("POST", "productionresultssa7.blob.core.windows.net", false),
            (
                "DELETE",
                "productionresultssa7.blob.core.windows.net",
                false,
            ),
            ("POST", "evilactions.githubusercontent.com", false),
            ("PUT", "blob.core.windows.net.example", false),
            ("POST", "raw.githubusercontent.com", false),
            ("POST", "example.com", false),
        ];
        for (method, host, want) in cases {
            assert_eq!(
                runner.request(&write(method, host)).allowed,
                want,
                "{method} {host}"
            );
            assert!(
                !policy.request(&write(method, host)).allowed,
                "{method} {host}"
            );
        }
        let socket = Request {
            websocket: true,
            ..write("GET", "results-receiver.actions.githubusercontent.com")
        };
        assert!(runner.request(&socket).allowed);
    }

    #[test]
    fn reasons() {
        let policy = shipped();
        assert_eq!(policy.request(&get("a.org")).reason, READ);
        let post = |host, path| Request {
            method: "POST",
            host,
            path,
            ..Request::default()
        };
        assert_eq!(
            policy
                .request(&post("github.com", "/a/b/git-upload-pack"))
                .reason,
            "git fetch (smart HTTP)"
        );
        assert_eq!(
            policy.request(&post("a.org", "/")).reason,
            "POST to an endpoint not in the write allowlist"
        );
        assert_eq!(
            policy
                .request(&Request {
                    has_body: true,
                    ..get("a.org")
                })
                .reason,
            "a read with a body to an endpoint not in the write allowlist"
        );
        assert_eq!(policy.connect("github.com").reason, TUNNEL);
    }

    #[test]
    fn globs() {
        for (glob, path, want) in [
            ("/*/x", "/a/x", true),
            ("/*/x", "/a/b/x", false),
            ("/**/x", "/a/b/x", true),
            ("/a.b", "/a.b", true),
            ("/a.b", "/aXb", false),
            ("/x", "/x/", false),
            ("/x", "/y/x", false),
        ] {
            assert_eq!(
                glob_regex(glob).unwrap().is_match(path),
                want,
                "{glob} {path}"
            );
        }
    }

    #[test]
    fn hosts_are_normalized() {
        for (host, want) in [
            ("Example.COM.", "example.com"),
            ("example.com:443", "example.com"),
            ("[::1]:80", "::1"),
            ("::1", "::1"),
            (" a.org ", "a.org"),
            ("a.org..", "a.org"),
        ] {
            assert_eq!(normalize_host(host), want, "{host}");
        }
    }

    #[test]
    fn bad_rules() {
        let good = "name = \"x\"\nhosts = [\"a.org\"]\nmethods = [\"POST\"]\npaths = [\"/x\"]\n";
        let rule =
            |text: &str| WriteRule::parse(&toml::Value::Table(toml::from_str(text).unwrap()));
        rule(good).unwrap();
        for (key, value) in [
            ("name", "\"\""),
            ("hosts", "[]"),
            ("methods", "[\"GET\"]"),
            ("paths", "[\"x\"]"),
            ("paths", "\"/x\""),
            ("hosts", "[\"\"]"),
        ] {
            let text: String = good
                .lines()
                .map(|line| {
                    if line.starts_with(&format!("{key} =")) {
                        format!("{key} = {value}\n")
                    } else {
                        format!("{line}\n")
                    }
                })
                .collect();
            assert!(rule(&text).is_err(), "{text}");
        }
        assert!(rule(&format!("{good}extra = 1\n")).is_err());
        assert!(WriteRule::parse(&toml::Value::Integer(1)).is_err());
    }
}
