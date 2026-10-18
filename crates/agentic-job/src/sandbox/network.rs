//! The network rules: nftables, keyed on the sandbox user's uid and on
//! its subordinate uids, so that containers it starts are covered.
//!
//! The ruleset follows the old tree's (`setup-runner-sandbox.mjs`), except
//! proxy DNS is restricted to configured resolvers. The sandbox user's
//! uids reach no cloud metadata service and, with direct endpoints
//! configured, nothing on the tailnet but those. With the egress proxy
//! they reach nothing else at all but loopback, where the proxy listens,
//! and not loopback's DNS: the proxy resolves names. The proxy's own uid
//! opens connections only to DNS and to public addresses, so the proxy
//! cannot be used to reach what the sandbox user may not.
//!
//! With `sandbox.deny-runner-metadata`, the runner's user and its
//! subordinate uids are refused the metadata service too, at its IPv4
//! and its IPv6 address, and only that:
//! every step of the job then shares that one refusal. The sandbox's
//! uids are then refused the IPv6 address as well, so that the runner,
//! which may still enter the sandbox user, has no way around it.
//!
//! The tailnet rules are defence in depth under the tailnet's own access
//! rules for the runner, which are the real control there.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};

use super::egress;
use super::host;
use crate::config::Egress;

pub const TABLE: &str = "runner_sandbox";

/// The ruleset `sandbox setup` loaded, kept for whoever wants to read it.
pub const RULES_FILE: &str = "/etc/agentic-job/rules.nft";

const METADATA_ADDRESS: &str = "169.254.169.254";

/// The metadata service's IPv6 address, where a cloud serves one (EC2's
/// Nitro instances, when enabled).
const METADATA_V6_ADDRESS: &str = "fd00:ec2::254";

/// Tailscale's address ranges and its interface. The filter matches
/// both: the interface because with accepted subnet routes other
/// addresses go there too, and the ranges because the node's own tailnet
/// address is reached over loopback.
const TAILNET_V4: &str = "100.64.0.0/10";

const TAILNET_V6: &str = "fd7a:115c:a1e0::/48";

const TAILSCALE_IF: &str = "tailscale0";

/// The first three groups of [`TAILNET_V6`].
const TAILNET_V6_PREFIX: [u16; 3] = [0xfd7a, 0x115c, 0xa1e0];

/// The first octet of [`TAILNET_V4`], and the range of its second.
const TAILNET_FIRST_OCTET: u8 = 100;

const TAILNET_SECOND_OCTET: std::ops::RangeInclusive<u8> = 64..=127;

pub const DNS_PORT: u16 = 53;

/// Azure's WireServer, which serves the VM's configuration.
const WIRESERVER: &str = "168.63.129.16";

/// Where the egress proxy may not connect, whatever a name resolves to:
/// loopback, private, link-local (the metadata service), shared (the
/// tailnet), multicast and reserved addresses, and the WireServer. DNS
/// is allowed before these, so the proxy can use the host's resolver.
const PROXY_DENIED_V4: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    TAILNET_V4,
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/3",
    WIRESERVER,
];

const PROXY_DENIED_V6: &[&str] = &[
    "::1/128",
    "::ffff:0:0/96",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

/// An endpoint the sandbox user reaches directly, never through the
/// egress proxy: the inference proxy, so that the run token does not
/// cross the egress proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Direct {
    pub host: Ipv4Addr,
    pub port: u16,
}

impl Direct {
    /// From a URL such as `http://100.101.102.103:18080/v1`. Only IPv4
    /// literals on the tailnet: nftables matches addresses, and a name
    /// could resolve elsewhere later.
    pub fn parse(url: &str) -> Result<Self> {
        let (default_port, rest) = if let Some(rest) = url.strip_prefix("http://") {
            (80, rest)
        } else if let Some(rest) = url.strip_prefix("https://") {
            (443, rest)
        } else {
            bail!("egress.direct: '{url}' is not an http or https URL");
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        ensure!(
            !authority.contains('@'),
            "egress.direct: '{url}' has credentials in it"
        );
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse::<u16>()
                    .ok()
                    .filter(|&port| port != 0)
                    .with_context(|| format!("egress.direct: '{url}' has a bad port"))?,
            ),
            None => (authority, default_port),
        };
        let address = host
            .parse::<Ipv4Addr>()
            .ok()
            .filter(|address| {
                let [first, second, ..] = address.octets();
                first == TAILNET_FIRST_OCTET && TAILNET_SECOND_OCTET.contains(&second)
            })
            .with_context(|| {
                format!("egress.direct: '{host}' is not a tailnet IPv4 address ({TAILNET_V4})")
            })?;
        Ok(Self {
            host: address,
            port,
        })
    }

    /// The `ADDRESS . PORT` element of the nftables set.
    fn element(&self) -> String {
        format!("{} . {}", self.host, self.port)
    }
}

/// Whether `address`, a name server of resolv.conf, is on the tailnet.
fn on_tailnet(address: &str) -> bool {
    match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let [first, second, ..] = v4.octets();
            first == TAILNET_FIRST_OCTET && TAILNET_SECOND_OCTET.contains(&second)
        }
        Ok(std::net::IpAddr::V6(v6)) => v6.segments()[..3] == TAILNET_V6_PREFIX,
        Err(_) => false,
    }
}

/// The name servers of `resolv_conf` that are on the tailnet. The egress
/// proxy is kept off the tailnet, its DNS included, which answers for
/// every node; so with such a resolver the proxy resolves nothing.
pub fn tailnet_resolvers(resolv_conf: &str) -> Vec<&str> {
    resolv_conf
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver")).then(|| words.next())?
        })
        .filter(|address| on_tailnet(address))
        .collect()
}

/// Parse only literal resolver addresses, never interpolate resolver-file
/// text into nft syntax. Malformed nameserver directives fail closed.
pub fn resolvers(resolv_conf: &str) -> Result<Vec<IpAddr>> {
    let mut addresses = Vec::new();
    for line in resolv_conf.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let address = words.next().context("nameserver without an address")?;
        let address = address
            .parse::<IpAddr>()
            .with_context(|| format!("invalid nameserver address {address:?}"))?;
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    Ok(addresses)
}

/// The direct endpoints of the configuration.
pub fn direct(egress: &Egress) -> Result<Vec<Direct>> {
    egress.direct.iter().map(|url| Direct::parse(url)).collect()
}

/// The ruleset for the sandbox user's `uids` (its own, and its
/// subordinate ranges as `START-END`). Rejected rather than dropped, so
/// a blocked connection fails at once.
pub fn rules(uids: &[String], direct: &[Direct], proxy_uid: Option<u32>) -> String {
    rules_with_resolvers(uids, direct, proxy_uid, &[], &[], None, &[])
}

/// The ports whose connections `egress.write-policy` redirects to the
/// proxy's transparent listener: HTTP and HTTPS.
const REDIRECTED_PORTS: &str = "80, 443";

/// `egress.write-policy`'s part, for `write_uids` (the runner's user and
/// its subordinate ranges): the set, the NAT chain and the filter rules.
///
/// Runner.Worker reads proxy settings only when it starts, before any
/// step, so a later process is not asked to use the proxy: its new
/// connections to a public address on port 80 or 443 are redirected to
/// the proxy's transparent listener ([`egress::TRANSPARENT_PORT`]),
/// which decides each request as it does the sandbox user's, with the
/// runner's own writes added. The addresses the proxy may not connect to
/// are not redirected, so they meet the filter, where everything of
/// those uids but loopback, DNS to the configured resolvers and
/// connections open before setup (the Worker's, made before any
/// untrusted step) is refused: another port, UDP (QUIC), IPv6, the
/// tailnet and private addresses, and the metadata service.
///
/// NAT runs before the filter at the output hook, so the filter sees a
/// redirected connection to loopback, never its first address.
fn write_policy_rules(write_uids: &[String], resolvers: &[IpAddr]) -> (String, String, String) {
    if write_uids.is_empty() {
        return (String::new(), String::new(), String::new());
    }
    let set = format!(
        "\n  set write_policy_uids {{ type uid; flags interval; elements = {{ {} }} }}",
        write_uids.join(", ")
    );
    let chain = format!(
        "
  chain write_policy {{
    type nat hook output priority -100; policy accept;
    meta skuid @write_policy_uids ip daddr != {{ {} }} tcp dport {{ {REDIRECTED_PORTS} }} redirect to :{}
  }}",
        PROXY_DENIED_V4.join(", "),
        egress::TRANSPARENT_PORT
    );
    let dns = dns_accepts("@write_policy_uids", resolvers);
    let filter = format!(
        "
    meta skuid @sandbox_uids oifname \"lo\" tcp dport {} counter reject
    meta skuid @write_policy_uids ct state established,related accept
    meta skuid @write_policy_uids ip daddr 127.0.0.0/8 accept
    meta skuid @write_policy_uids ip6 daddr ::1 accept{dns}
    meta skuid @write_policy_uids counter reject",
        egress::TRANSPARENT_PORT
    );
    (set, chain, filter)
}

/// SUBJECT's DNS to each of RESOLVERS, accepted.
fn dns_accepts(subject: &str, resolvers: &[IpAddr]) -> String {
    resolvers
        .iter()
        .map(|address| {
            let family = if address.is_ipv4() { "ip" } else { "ip6" };
            format!("\n    meta skuid {subject} {family} daddr {address} meta l4proto {{ tcp, udp }} th dport {DNS_PORT} accept")
        })
        .collect()
}

/// DNS exceptions apply only to these resolver addresses. All other DNS
/// destinations are rejected, including otherwise public addresses.
///
/// `runner_uids` (`sandbox.deny-runner-metadata`: the runner's user and
/// its subordinate ranges) are refused the metadata service and nothing
/// else; none leaves the ruleset as it was. With them the sandbox's uids
/// are refused its IPv6 address too, which the runner could otherwise
/// reach as the sandbox user when there is no egress proxy.
///
/// `session_port` (a session run's bridge, `session::bridge`) is refused
/// to the sandbox's uids on loopback, and so is the node's own tailnet
/// address, where `tailscale serve` passes it on: the bridge lets in
/// whoever `Tailscale-User-Login` names, and a connection of the agent's
/// own could otherwise name the operator itself, or come through serve
/// as the node's owner, and prompt the session it runs in.
///
/// `write_uids` (`egress.write-policy`, which needs the proxy) are held
/// to the proxy's write rules: [`write_policy_rules`].
pub fn rules_with_resolvers(
    uids: &[String],
    direct: &[Direct],
    proxy_uid: Option<u32>,
    resolvers: &[IpAddr],
    runner_uids: &[String],
    session_port: Option<u16>,
    write_uids: &[String],
) -> String {
    let (write_set, write_chain, write_rules) = if proxy_uid.is_some() {
        write_policy_rules(write_uids, resolvers)
    } else {
        Default::default()
    };
    let session_rules = session_port.map_or_else(String::new, |port| {
        format!(
            "
    meta skuid @sandbox_uids oifname \"lo\" tcp dport {port} counter reject
    meta skuid @sandbox_uids oifname \"lo\" ip daddr {TAILNET_V4} counter reject
    meta skuid @sandbox_uids oifname \"lo\" ip6 daddr {TAILNET_V6} counter reject"
        )
    });
    let (runner_set, runner_rules) = if runner_uids.is_empty() {
        (String::new(), String::new())
    } else {
        (
            format!(
                "\n  set runner_uids {{ type uid; flags interval; elements = {{ {} }} }}",
                runner_uids.join(", ")
            ),
            format!(
                "
    meta skuid @sandbox_uids ip6 daddr {METADATA_V6_ADDRESS} counter reject
    meta skuid @runner_uids ip daddr {METADATA_ADDRESS} counter reject
    meta skuid @runner_uids ip6 daddr {METADATA_V6_ADDRESS} counter reject"
            ),
        )
    };
    let allowed: Vec<String> = direct.iter().map(Direct::element).collect();
    let (tailnet_set, tailnet_rules) = if allowed.is_empty() {
        (String::new(), String::new())
    } else {
        (
            format!(
                "\n  set tailnet_allowed {{ type ipv4_addr . inet_service; elements = {{ {} }} }}",
                allowed.join(", ")
            ),
            format!(
                "
    meta skuid @sandbox_uids ip daddr . tcp dport @tailnet_allowed accept
    meta skuid @sandbox_uids oifname \"{TAILSCALE_IF}\" counter reject
    meta skuid @sandbox_uids ip daddr {TAILNET_V4} counter reject
    meta skuid @sandbox_uids ip6 daddr {TAILNET_V6} counter reject"
            ),
        )
    };
    let egress_rules = proxy_uid.map_or_else(String::new, |proxy| {
        let dns = dns_accepts(&proxy.to_string(), resolvers);
        format!(
            "
    meta skuid @sandbox_uids oifname \"lo\" meta l4proto {{ tcp, udp }} th dport {DNS_PORT} counter reject
    meta skuid @sandbox_uids oifname \"lo\" ip daddr 127.0.0.0/8 accept
    meta skuid @sandbox_uids oifname \"lo\" ip6 daddr ::1 accept
    meta skuid @sandbox_uids counter reject
    meta skuid {proxy} ct state established,related accept
    meta skuid {proxy} oifname \"{TAILSCALE_IF}\" counter reject
    meta skuid {proxy} ip daddr {TAILNET_V4} counter reject
    meta skuid {proxy} ip6 daddr {TAILNET_V6} counter reject{dns}
    meta skuid {proxy} meta l4proto {{ tcp, udp }} th dport {DNS_PORT} counter reject
    meta skuid {proxy} ip daddr {{ {} }} counter reject
    meta skuid {proxy} ip6 daddr {{ {} }} counter reject",
            PROXY_DENIED_V4.join(", "),
            PROXY_DENIED_V6.join(", ")
        )
    });
    format!(
        "table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
  set sandbox_uids {{ type uid; flags interval; elements = {{ {} }} }}{runner_set}{tailnet_set}{write_set}{write_chain}
  chain output {{
    type filter hook output priority 0; policy accept;
    meta skuid @sandbox_uids ip daddr {METADATA_ADDRESS} counter reject{runner_rules}{write_rules}{session_rules}{tailnet_rules}{egress_rules}
  }}
}}
",
        uids.join(", ")
    )
}

/// Loads `ruleset`, and leaves it in [`RULES_FILE`].
pub fn apply(ruleset: &str) -> Result<()> {
    std::fs::write(RULES_FILE, ruleset).with_context(|| format!("writing {RULES_FILE}"))?;
    ensure!(
        host::has_program("nft"),
        "nft not found: the network rules need nftables"
    );
    host::run(Command::new("nft").arg("-f").arg(Path::new(RULES_FILE)))
        .context("loading the network rules")?;
    Ok(())
}

/// What every command of the sandbox user gets so that it uses the
/// egress proxy: the proxy, but not for loopback and the direct hosts,
/// and its certificate authority in the forms the usual tools read.
/// `SSL_CERT_FILE` and the like replace the system bundle, so they get
/// the bundle with the authority added.
pub fn proxy_environment(direct: &[Direct]) -> BTreeMap<String, String> {
    let no_proxy = ["localhost", "127.0.0.1", "::1"]
        .into_iter()
        .map(str::to_owned)
        .chain(direct.iter().map(|direct| direct.host.to_string()))
        .collect::<Vec<_>>()
        .join(",");
    let proxy = egress::proxy_url();
    let proxied = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
        .into_iter()
        .map(|name| (name, proxy.clone()));
    let unproxied = ["NO_PROXY", "no_proxy"]
        .into_iter()
        .map(|name| (name, no_proxy.clone()));
    let bundle = [
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "CARGO_HTTP_CAINFO",
        "GIT_SSL_CAINFO",
        "REQUESTS_CA_BUNDLE",
        "PIP_CERT",
    ]
    .into_iter()
    .map(|name| (name, egress::CA_BUNDLE.to_owned()));
    // Node's own fetch uses the proxy variables only with the first.
    let node = [
        ("NODE_USE_ENV_PROXY", "1".to_owned()),
        ("NODE_EXTRA_CA_CERTS", egress::CA_CERT.to_owned()),
    ];
    proxied
        .chain(unproxied)
        .chain(bundle)
        .chain(node)
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_of(url: &str) -> Direct {
        Direct::parse(url).unwrap()
    }

    #[test]
    fn direct_endpoints() {
        let cases = [
            ("http://100.101.102.103:18080/v1", "100.101.102.103 . 18080"),
            ("http://100.64.0.1", "100.64.0.1 . 80"),
            ("https://100.127.255.254/x?y#z", "100.127.255.254 . 443"),
        ];
        for (url, element) in cases {
            assert_eq!(direct_of(url).element(), element, "{url}");
        }
        let bad = [
            "100.101.102.103:18080",
            "ftp://100.101.102.103",
            "http://proxy.example:18080",
            "http://10.0.0.1:18080",
            "http://100.63.0.1",
            "http://100.128.0.1",
            "http://100.101.102.103:0",
            "http://100.101.102.103:port",
            "http://user@100.101.102.103",
            "http://[fd7a:115c:a1e0::1]:80",
        ];
        for url in bad {
            assert!(Direct::parse(url).is_err(), "{url} parsed");
        }
    }

    /// The whole text for one case; the corpus test in CI compares every
    /// shape with the old tree's own function.
    #[test]
    fn ruleset_with_everything() {
        let uids = ["1002".to_owned(), "165536-231071".to_owned()];
        let direct = [direct_of("http://100.101.102.103:18080")];
        let want = r#"table inet runner_sandbox
delete table inet runner_sandbox
table inet runner_sandbox {
  set sandbox_uids { type uid; flags interval; elements = { 1002, 165536-231071 } }
  set tailnet_allowed { type ipv4_addr . inet_service; elements = { 100.101.102.103 . 18080 } }
  chain output {
    type filter hook output priority 0; policy accept;
    meta skuid @sandbox_uids ip daddr 169.254.169.254 counter reject
    meta skuid @sandbox_uids ip daddr . tcp dport @tailnet_allowed accept
    meta skuid @sandbox_uids oifname "tailscale0" counter reject
    meta skuid @sandbox_uids ip daddr 100.64.0.0/10 counter reject
    meta skuid @sandbox_uids ip6 daddr fd7a:115c:a1e0::/48 counter reject
    meta skuid @sandbox_uids oifname "lo" meta l4proto { tcp, udp } th dport 53 counter reject
    meta skuid @sandbox_uids oifname "lo" ip daddr 127.0.0.0/8 accept
    meta skuid @sandbox_uids oifname "lo" ip6 daddr ::1 accept
    meta skuid @sandbox_uids counter reject
    meta skuid 993 ct state established,related accept
    meta skuid 993 oifname "tailscale0" counter reject
    meta skuid 993 ip daddr 100.64.0.0/10 counter reject
    meta skuid 993 ip6 daddr fd7a:115c:a1e0::/48 counter reject
    meta skuid 993 meta l4proto { tcp, udp } th dport 53 counter reject
    meta skuid 993 ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3, 168.63.129.16 } counter reject
    meta skuid 993 ip6 daddr { ::1/128, ::ffff:0:0/96, fc00::/7, fe80::/10, ff00::/8 } counter reject
  }
}
"#;
        assert_eq!(rules(&uids, &direct, Some(993)), want);
    }

    #[test]
    fn ruleset_without_the_proxy_or_direct_endpoints() {
        let want = r#"table inet runner_sandbox
delete table inet runner_sandbox
table inet runner_sandbox {
  set sandbox_uids { type uid; flags interval; elements = { 1002 } }
  chain output {
    type filter hook output priority 0; policy accept;
    meta skuid @sandbox_uids ip daddr 169.254.169.254 counter reject
  }
}
"#;
        assert_eq!(rules(&["1002".to_owned()], &[], None), want);
    }

    /// The runner's uids get the metadata refusal and nothing more: the
    /// rest of the ruleset is the sandbox user's alone, but for its IPv6
    /// metadata refusal, which the runner could reach through `sandbox
    /// exec` without it.
    #[test]
    fn ruleset_refusing_the_runner_the_metadata_service() {
        let runner = ["1001".to_owned(), "100000-165535".to_owned()];
        let want = r#"table inet runner_sandbox
delete table inet runner_sandbox
table inet runner_sandbox {
  set sandbox_uids { type uid; flags interval; elements = { 1002 } }
  set runner_uids { type uid; flags interval; elements = { 1001, 100000-165535 } }
  chain output {
    type filter hook output priority 0; policy accept;
    meta skuid @sandbox_uids ip daddr 169.254.169.254 counter reject
    meta skuid @sandbox_uids ip6 daddr fd00:ec2::254 counter reject
    meta skuid @runner_uids ip daddr 169.254.169.254 counter reject
    meta skuid @runner_uids ip6 daddr fd00:ec2::254 counter reject
  }
}
"#;
        assert_eq!(
            rules_with_resolvers(&["1002".to_owned()], &[], None, &[], &runner, None, &[]),
            want
        );
        let proxied = rules_with_resolvers(
            &["1002".to_owned()],
            &[],
            Some(993),
            &[],
            &runner,
            None,
            &[],
        );
        assert_eq!(proxied.matches("@runner_uids").count(), 2);
        assert_eq!(
            proxied.replace(
                "\n  set runner_uids { type uid; flags interval; elements = { 1001, 100000-165535 } }",
                ""
            )
            .replace(
                "\n    meta skuid @sandbox_uids ip6 daddr fd00:ec2::254 counter reject\n    meta skuid @runner_uids ip daddr 169.254.169.254 counter reject\n    meta skuid @runner_uids ip6 daddr fd00:ec2::254 counter reject",
                ""
            ),
            rules(&["1002".to_owned()], &[], Some(993))
        );
    }

    /// `egress.write-policy`: the runner's new HTTP and HTTPS connections
    /// to public addresses go to the transparent listener, and nothing
    /// else of its uids leaves the host but DNS to the resolvers; the
    /// sandbox user cannot reach that listener, whose policy is wider
    /// than its own. Without the proxy there is nothing to redirect to,
    /// and the rules are as they were.
    #[test]
    fn ruleset_holding_the_runner_to_the_write_policy() {
        let sandbox = ["1002".to_owned()];
        let runner = ["1001".to_owned(), "100000-165535".to_owned()];
        let resolvers = resolvers("nameserver 10.0.0.2\n").unwrap();
        let ruleset =
            rules_with_resolvers(&sandbox, &[], Some(993), &resolvers, &[], None, &runner);
        let want = r#"table inet runner_sandbox
delete table inet runner_sandbox
table inet runner_sandbox {
  set sandbox_uids { type uid; flags interval; elements = { 1002 } }
  set write_policy_uids { type uid; flags interval; elements = { 1001, 100000-165535 } }
  chain write_policy {
    type nat hook output priority -100; policy accept;
    meta skuid @write_policy_uids ip daddr != { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3, 168.63.129.16 } tcp dport { 80, 443 } redirect to :3129
  }
  chain output {
    type filter hook output priority 0; policy accept;
    meta skuid @sandbox_uids ip daddr 169.254.169.254 counter reject
    meta skuid @sandbox_uids oifname "lo" tcp dport 3129 counter reject
    meta skuid @write_policy_uids ct state established,related accept
    meta skuid @write_policy_uids ip daddr 127.0.0.0/8 accept
    meta skuid @write_policy_uids ip6 daddr ::1 accept
    meta skuid @write_policy_uids ip daddr 10.0.0.2 meta l4proto { tcp, udp } th dport 53 accept
    meta skuid @write_policy_uids counter reject
"#;
        assert!(ruleset.starts_with(want), "{ruleset}");
        // Without those uids, the same ruleset less what they added.
        let between =
            |from: &str, to: &str| &want[want.find(from).unwrap()..want.find(to).unwrap()];
        let set_and_chain = between("\n  set write_policy_uids", "\n  chain output");
        let filter = between(
            "\n    meta skuid @sandbox_uids oifname",
            "\n    meta skuid @write_policy_uids counter",
        );
        let without = ruleset
            .replace(set_and_chain, "")
            .replace(filter, "")
            .replace("\n    meta skuid @write_policy_uids counter reject", "");
        assert_eq!(
            without,
            rules_with_resolvers(&sandbox, &[], Some(993), &resolvers, &[], None, &[])
        );
        // The sandbox's refusal comes before its loopback accept.
        let refusal = ruleset.find("tcp dport 3129 counter reject").unwrap();
        let accept = ruleset
            .find("@sandbox_uids oifname \"lo\" ip daddr")
            .unwrap();
        assert!(refusal < accept);
        assert_eq!(
            rules_with_resolvers(&sandbox, &[], None, &resolvers, &[], None, &runner),
            rules(&sandbox, &[], None)
        );
    }

    /// With the runner refused, no uid set the ruleset names keeps a path
    /// to either metadata address in either family, with or without the
    /// proxy and direct endpoints: each set's refusal comes before its
    /// first accept. The sandbox's uids matter without the proxy, since
    /// the runner may run anything as the sandbox user.
    #[test]
    fn no_uid_set_reaches_the_metadata_service_when_the_runner_is_refused() {
        let sandbox = ["1002".to_owned(), "165536-231071".to_owned()];
        let runner = ["1001".to_owned(), "100000-165535".to_owned()];
        let direct = [direct_of("http://100.101.102.103:18080")];
        for proxy in [None, Some(993)] {
            for direct in [&direct[..], &[]] {
                let ruleset =
                    rules_with_resolvers(&sandbox, direct, proxy, &[], &runner, None, &[]);
                for set in ["@sandbox_uids", "@runner_uids"] {
                    let accept = ruleset
                        .lines()
                        .position(|line| line.contains(set) && line.ends_with("accept"))
                        .unwrap_or(usize::MAX);
                    for (family, address) in
                        [("ip", METADATA_ADDRESS), ("ip6", METADATA_V6_ADDRESS)]
                    {
                        let rule =
                            format!("    meta skuid {set} {family} daddr {address} counter reject");
                        let at = ruleset.lines().position(|line| line == rule);
                        assert!(
                            at.is_some_and(|at| at < accept),
                            "{set} {family} with {proxy:?}, {} direct:\n{ruleset}",
                            direct.len()
                        );
                    }
                }
                if let Some(proxy) = proxy {
                    assert!(ruleset.contains(&format!(
                        "meta skuid {proxy} ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,"
                    )));
                    assert!(ruleset.contains(&format!(
                        "meta skuid {proxy} ip6 daddr {{ ::1/128, ::ffff:0:0/96, fc00::/7,"
                    )));
                }
            }
        }
    }

    /// A session's bridge is refused to the sandbox's uids before any of
    /// their accepts, with or without the proxy and direct endpoints, and
    /// a task run's ruleset is as it was.
    #[test]
    fn the_sandbox_cannot_reach_a_sessions_bridge() {
        let sandbox = ["1002".to_owned()];
        let direct = [direct_of("http://100.101.102.103:18080")];
        let refusals = [
            "    meta skuid @sandbox_uids oifname \"lo\" tcp dport 7790 counter reject",
            "    meta skuid @sandbox_uids oifname \"lo\" ip daddr 100.64.0.0/10 counter reject",
            "    meta skuid @sandbox_uids oifname \"lo\" ip6 daddr fd7a:115c:a1e0::/48 counter reject",
        ];
        for proxy in [None, Some(993)] {
            for direct in [&direct[..], &[]] {
                let task = rules_with_resolvers(&sandbox, direct, proxy, &[], &[], None, &[]);
                let session =
                    rules_with_resolvers(&sandbox, direct, proxy, &[], &[], Some(7790), &[]);
                let first_accept = session
                    .lines()
                    .position(|line| line.contains("@sandbox_uids") && line.ends_with("accept"))
                    .unwrap_or(usize::MAX);
                for rule in refusals {
                    let at = session.lines().position(|line| line == rule);
                    assert!(at.is_some_and(|at| at < first_accept), "{rule}:\n{session}");
                }
                assert_eq!(
                    session.replace(&format!("\n{}", refusals.join("\n")), ""),
                    task
                );
            }
        }
    }

    #[test]
    fn resolvers_on_the_tailnet() {
        let conf = "# made by tailscale\nnameserver 100.100.100.100\nnameserver fd7a:115c:a1e0::53\nnameserver 168.63.129.16\nnameserver 127.0.0.53\nsearch example.ts.net\n";
        assert_eq!(
            tailnet_resolvers(conf),
            ["100.100.100.100", "fd7a:115c:a1e0::53"]
        );
        assert!(tailnet_resolvers("nameserver 10.0.0.2\noptions edns0\n").is_empty());
    }

    #[test]
    fn resolver_file_addresses() {
        for (text, expected) in [
            ("# comment\nsearch example.org\n", vec![]),
            (
                "nameserver 10.0.0.2 # local\nnameserver 10.0.0.2\nnameserver ::1\n",
                vec!["10.0.0.2", "::1"],
            ),
        ] {
            let got = resolvers(text).unwrap();
            assert_eq!(
                got.iter().map(ToString::to_string).collect::<Vec<_>>(),
                expected
            );
        }
        for text in [
            "nameserver",
            "nameserver example.org",
            "nameserver 10.0.0.2;accept",
            "nameserver fe80::1%eth0",
        ] {
            assert!(resolvers(text).is_err(), "{text}");
        }
    }

    #[test]
    fn dns_exceptions_are_scoped_and_below_tailnet_denial() {
        let addresses = resolvers("nameserver 10.0.0.2\nnameserver 2001:db8::53\n").unwrap();
        let rules =
            rules_with_resolvers(&["1002".into()], &[], Some(993), &addresses, &[], None, &[]);
        let tailnet = rules
            .find("ip6 daddr fd7a:115c:a1e0::/48 counter reject")
            .unwrap();
        let reject = rules
            .find("meta skuid 993 meta l4proto { tcp, udp } th dport 53 counter reject")
            .unwrap();
        let private = rules.find("meta skuid 993 ip daddr { 0.0.0.0/8").unwrap();
        for (family, address) in [("ip", "10.0.0.2"), ("ip6", "2001:db8::53")] {
            let accept = rules.find(&format!("meta skuid 993 {family} daddr {address} meta l4proto {{ tcp, udp }} th dport 53 accept")).unwrap();
            assert!(tailnet < accept && accept < reject && reject < private);
        }
        assert!(!rules.contains("th dport 53 accept\n    meta skuid 993 ip daddr {"));
        assert!(
            !rules_with_resolvers(&["1002".into()], &[], None, &addresses, &[], None, &[])
                .contains("dport 53")
        );
    }

    #[test]
    fn proxy_variables() {
        let env = proxy_environment(&[direct_of("http://100.101.102.103:18080")]);
        let get = |name: &str| env.get(name).map(String::as_str);
        assert_eq!(get("HTTPS_PROXY"), Some("http://127.0.0.1:3128"));
        assert_eq!(get("http_proxy"), Some("http://127.0.0.1:3128"));
        assert_eq!(
            get("NO_PROXY"),
            Some("localhost,127.0.0.1,::1,100.101.102.103")
        );
        assert_eq!(get("no_proxy"), get("NO_PROXY"));
        assert_eq!(get("NODE_EXTRA_CA_CERTS"), Some("/etc/egress-proxy/ca.pem"));
        assert_eq!(
            get("GIT_SSL_CAINFO"),
            Some("/etc/egress-proxy/ca-bundle.pem")
        );
        assert_eq!(env.len(), 14);
    }
}
