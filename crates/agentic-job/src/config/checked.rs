//! The one check of a configuration, for every command that reads one.
//!
//! `sandbox setup` and `run` each refuse a configuration they cannot
//! use, and `agentic-job config`, which writes the file both read, has
//! to refuse it first: `run` starts minutes after the machine was set
//! up, which is late to learn of a missing key. So that the three cannot
//! drift, none of them checks a table itself. [`Config::check_host`] is
//! what `sandbox setup` needs to hold, and what every entry into the
//! sandbox holds again (`sandbox::enter`); [`Config::check`] is that
//! and what `run` needs. Each takes its checked values from here.
//!
//! Only what the file alone decides is checked here. What depends on the
//! machine (that the sandbox user exists, that a path of the file is
//! there) or on the run (the task, `--meta`, the policy) stays with the
//! command that meets it.

use anyhow::{Context, Result, bail, ensure};

use super::{Config, Limits as LimitsTable};
use crate::run::agent::{self, Kind};
use crate::run::handback;
use crate::run::inference::Endpoint;
use crate::sandbox::network::{self, Direct};
use crate::session::Limits;
use crate::session::bridge::Listen;

/// What `sandbox setup` takes from a configuration it may act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// Install the pinned Vibe runtime once, for either or both agents.
    pub install_vibe: bool,
    /// Where the sandbox user connects without the egress proxy.
    pub direct: Vec<Direct>,
    /// `None` for a task run, which no client attaches to; otherwise
    /// setup serves the bridge's port on the tailnet and keeps the
    /// sandbox user from it.
    pub session: Option<Listen>,
}

/// What `run` takes from a configuration it may act on.
#[derive(Debug, Clone, PartialEq)]
pub struct Checked {
    pub host: Host,
    pub kind: Kind,
    /// `None` for a run with no inference proxy.
    pub endpoint: Option<Endpoint>,
    pub limits: Limits,
    /// The model of the run's child agent, Vibe, if it has one.
    pub child: Option<String>,
}

/// The limits, with the proxy's part in them checked: a cap on model
/// requests binds only where the proxy counts them.
fn limits(table: &LimitsTable, endpoint: Option<&Endpoint>) -> Result<Limits> {
    let limits = Limits::from_config(table)?;
    let uncounted = match endpoint {
        None => Some("the run has no inference proxy"),
        Some(endpoint) if !endpoint.mode.has_run_api() => {
            Some("register = \"token-file\" has no run API")
        }
        Some(_) => None,
    };
    if let (Some(cap), Some(why)) = (limits.max_requests, uncounted) {
        bail!(
            "limits.max-requests = {cap} would not bind: nothing counts this run's model \
             requests ({why}). Remove it and cap the run with limits.budget, or say \
             limits.uncapped = true; from the reusable workflow, whose max-requests input \
             defaults to 150, pass max-requests: \"0\" with budget instead"
        );
    }
    Ok(limits)
}

impl Config {
    /// Whether the agent KIND can reach the inference proxy at ENDPOINT.
    /// Behind the egress proxy the sandbox user reaches the tailnet only
    /// where `egress.direct` lists it, and the egress proxy itself not at
    /// all, so an address there that is not listed fails at the agent's
    /// first request, the run already paid for. Only the address the
    /// agent itself uses is held to this: `run` registers from outside
    /// the sandbox. A name cannot be judged here, since only what it
    /// resolves to on the machine is on the tailnet or not.
    fn check_reachable(&self, kind: Kind, endpoint: &Endpoint, direct: &[Direct]) -> Result<()> {
        let Some(url) = kind.api_url(endpoint).filter(|_| self.egress.proxy) else {
            return Ok(());
        };
        let unlisted = Direct::parse(url)
            .ok()
            .filter(|address| !direct.contains(address));
        if let Some(Direct { host, port }) = unlisted {
            let scheme = url.split_once("://").map_or("http", |(scheme, _)| scheme);
            bail!(
                "the inference proxy at {url} is on the tailnet, which the sandbox user \
                 reaches only where egress.direct lists it: add \"{scheme}://{host}:{port}\" to \
                 egress.direct"
            );
        }
        Ok(())
    }

    /// The run's child agent, if `[child-agent]` names one: Vibe, with a
    /// model, behind the run's proxy, which it can reach, and under a cap
    /// on model requests. The cap is the bound: the session's budget reads
    /// only the cost the main agent reports, while the proxy counts every
    /// request made with the run's token, the child's too, so a run
    /// capped only by its budget could spend without bound through the
    /// child.
    fn check_child(
        &self,
        endpoint: Option<&Endpoint>,
        direct: &[Direct],
        limits: &Limits,
    ) -> Result<Option<String>> {
        let child = &self.child_agent;
        let model = child.model.as_deref().filter(|m| !m.is_empty());
        if child.name.is_empty() {
            ensure!(
                model.is_none(),
                "child-agent.model means nothing without child-agent.name"
            );
            return Ok(None);
        }
        let model =
            model.context("child-agent.model is not set: vibe needs a Mistral model name")?;
        let endpoint = endpoint.context(
            "child-agent needs inference: set [inference] url and register (workflow inputs \
             inference-url and inference-register)",
        )?;
        self.check_reachable(Kind::Vibe, endpoint, direct)?;
        ensure!(
            limits.max_requests.is_some(),
            "child-agent needs limits.max-requests: the budget reads only the cost the main agent \
             reports, and the proxy's count of requests is what covers the child's"
        );
        Ok(Some(model.to_owned()))
    }

    /// The tables that say how the machine is set up, checked.
    pub fn check_host(&self) -> Result<Host> {
        self.sandbox.validate()?;
        self.setup.validate()?;
        // Keep setup's closed installer set and run's child set together:
        // accepting a child whose runtime is absent fails only after setup.
        ensure!(
            self.child_agent.name.is_empty() || self.child_agent.name == Kind::Vibe.as_str(),
            "child-agent.name: {:?} cannot be a child agent, only \"vibe\" has a pinned installer",
            self.child_agent.name
        );
        // Setup would serve the bridge's port on the tailnet, with the
        // operator's login on what it passes on, for any later step that
        // listens there: only a run's bridge checks it.
        ensure!(
            !self.session.listen || !self.agent.name.is_empty(),
            "session.listen needs agent.name: only `run` holds the port setup serves"
        );
        Ok(Host {
            install_vibe: self.agent.name == Kind::Vibe.as_str()
                || self.child_agent.name == Kind::Vibe.as_str(),
            direct: network::direct(&self.egress)?,
            session: Listen::from_config(&self.session)?,
        })
    }

    /// The whole configuration, checked: [`Config::check_host`], and
    /// that it names an agent `run` can configure, an inference proxy if
    /// that agent has a model behind it, limits that bind, and a commit
    /// git will take.
    pub fn check(&self) -> Result<Checked> {
        let host = self.check_host()?;
        let kind = Kind::parse(&self.agent.name)?;
        agent::check(kind, &self.agent)?;
        let endpoint = Endpoint::from_config(&self.inference)?;
        ensure!(
            endpoint.is_some() || !kind.needs_inference(),
            "the agent {} needs inference: set [inference] url and register (workflow inputs inference-url and inference-register)",
            kind.as_str()
        );
        if let Some(endpoint) = &endpoint {
            self.check_reachable(kind, endpoint, &host.direct)?;
        }
        let limits = limits(&self.limits, endpoint.as_ref())?;
        // Vibe cannot price an arbitrary broker model. A caller's budget
        // alone would appear capped but never bind, so require counted requests.
        if kind == Kind::Vibe {
            ensure!(
                limits.max_requests.is_some(),
                "vibe needs limits.max-requests: its model has no authoritative local price"
            );
        }
        let child = self.check_child(endpoint.as_ref(), &host.direct, &limits)?;
        handback::author(&self.commit)?;
        handback::check_trailers(&self.commit.trailers)?;
        Ok(Checked {
            host,
            kind,
            endpoint,
            limits,
            child,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::inference::Mode;

    const FAKE: &str = "[agent]\nname = \"fake\"\n";
    const CLAUDE: &str = "[agent]\nname = \"claude\"\n";
    const CAPPED: &str = "[limits]\ntimeout-minutes = 10\nbudget = 100\n";
    const PROXY: &str = "[inference]\nurl = \"http://100.64.0.1:18080\"\n";
    const OIDC: &str = "register = \"github-oidc\"\naudience = \"proxy\"\n";
    const DIRECT: &str = "[egress]\ndirect = [\"http://100.64.0.1:18080\"]\n";
    const CHILD: &str = "[child-agent]\nname = \"vibe\"\nmodel = \"glm\"\n";
    const REQUESTS: &str = "[limits]\ntimeout-minutes = 10\nmax-requests = 50\n";

    fn direct(url: &str) -> String {
        format!("[egress]\ndirect = [{url:?}]\n")
    }

    fn checked(text: &str) -> Result<Checked> {
        Config::parse(text)?.check()
    }

    #[test]
    fn setup_installs_vibe_for_either_agent() {
        for (main, child, install) in [
            ("fake", "", false),
            ("fake", CHILD, true),
            ("claude", CHILD, true),
            ("opencode", CHILD, true),
            ("vibe", "", true),
            ("vibe", CHILD, true),
        ] {
            let config = Config::parse(&format!("[agent]\nname = {main:?}\n{child}")).unwrap();
            assert_eq!(
                config.check_host().unwrap().install_vibe,
                install,
                "{main}/{child}"
            );
        }
        let run = checked(&format!("{FAKE}{PROXY}{OIDC}{REQUESTS}{DIRECT}{CHILD}")).unwrap();
        assert!(run.host.install_vibe);
        assert_eq!(run.child.as_deref(), Some("glm"));
        for child in ["claude", "opencode", "fake", "unknown"] {
            let config = Config::parse(&format!(
                "{FAKE}[child-agent]\nname = {child:?}\nmodel = \"glm\"\n"
            ))
            .unwrap();
            assert!(
                config
                    .check_host()
                    .unwrap_err()
                    .to_string()
                    .contains("pinned installer")
            );
            assert!(config.check().is_err());
        }
    }

    #[test]
    fn what_a_run_can_use() {
        let fake = checked(&format!("{FAKE}{CAPPED}")).unwrap();
        assert_eq!((fake.kind, fake.endpoint), (Kind::Fake, None));
        assert_eq!(
            (fake.limits.timeout_s, fake.limits.budget_aic),
            (600, Some(100.0))
        );
        assert_eq!(fake.host.session, None);
        let session = checked(&format!(
            "{FAKE}{CAPPED}[session]\nlisten = true\noperators = [\"op@github\"]\n\
             origins = [\"https://review.example.ts.net\"]\n"
        ))
        .unwrap();
        assert_eq!(
            session.host.session.map(|listen| listen.operators),
            Some(vec!["op@github".to_owned()])
        );

        let text = format!(
            "{CLAUDE}skills = true\n{PROXY}{OIDC}[limits]\ntimeout-minutes = 10\nmax-requests = 150\n\
             {DIRECT}[commit]\nauthor = \"A Bot <bot@example.org>\"\ntrailers = [\"Generated-by: AI\"]\n"
        );
        let claude = checked(&text).unwrap();
        assert_eq!(claude.kind, Kind::Claude);
        assert_eq!(claude.limits.max_requests, Some(150));
        assert_eq!(claude.host.direct.len(), 1);
        let endpoint = claude.endpoint.unwrap();
        assert_eq!(
            endpoint.mode,
            Mode::GithubOidc {
                audience: "proxy".into()
            }
        );

        let text = format!(
            "[agent]\nname = \"opencode\"\nmodel = \"m\"\nskills = true\n{PROXY}{OIDC}{CAPPED}{DIRECT}"
        );
        let opencode = checked(&text).unwrap();
        assert_eq!((opencode.kind, opencode.child), (Kind::Opencode, None));

        let text = format!(
            "[agent]\nname = \"opencode\"\nmodel = \"m\"\n{CHILD}{PROXY}{OIDC}{REQUESTS}{DIRECT}"
        );
        assert_eq!(checked(&text).unwrap().child.as_deref(), Some("glm"));
    }

    /// One row for each table a command used to check by itself: the
    /// agent's and the inference proxy's, the limits, what crosses two of
    /// them, the commit, and the machine's.
    #[test]
    fn what_is_refused() {
        let token_file = "register = \"token-file\"\ntoken-file = \"/run/token\"\n";
        let cases = [
            (CAPPED.to_owned(), "agent.name is not set"),
            (
                format!("[agent]\nname = \"gemini\"\n{CAPPED}"),
                "no agent \"gemini\"",
            ),
            (
                format!("{FAKE}config-repo = \"https://example.org/x\"\n{CAPPED}"),
                "the fake agent has no configuration",
            ),
            (
                format!("{FAKE}skills = true\n{CAPPED}"),
                "agent.skills is not supported for fake",
            ),
            (
                format!("{FAKE}config-ref = \"main\"\n{CAPPED}"),
                "mean nothing without agent.config-repo",
            ),
            (
                format!("{CLAUDE}config-repo = \"ssh://example.org/x\"\n{PROXY}{OIDC}{CAPPED}"),
                "agent.config-repo: \"ssh://example.org/x\" is not an https or file URL",
            ),
            (
                format!("[agent]\nname = \"opencode\"\n{PROXY}{OIDC}{CAPPED}"),
                "agent.model is not set",
            ),
            (
                format!("{CLAUDE}{CAPPED}"),
                "the agent claude needs inference: set [inference] url and register (workflow inputs inference-url and inference-register)",
            ),
            (
                format!("{CLAUDE}{PROXY}{CAPPED}"),
                "inference.register is not set",
            ),
            (
                format!("{CLAUDE}{PROXY}register = \"github-oidc\"\n{CAPPED}"),
                "needs the audience",
            ),
            (
                format!("{CLAUDE}{PROXY}register = \"plain\"\naudience = \"x\"\n{CAPPED}"),
                "inference.audience is set",
            ),
            (
                format!("{CLAUDE}{PROXY}register = \"token-file\"\n{CAPPED}"),
                "needs the absolute path",
            ),
            (
                format!("{FAKE}[inference]\nregister = \"plain\"\n{CAPPED}"),
                "inference.url is not set",
            ),
            (
                format!("{FAKE}[inference]\nurl = \"proxy:18080\"\nregister = \"plain\"\n{CAPPED}"),
                "is not an http or https URL",
            ),
            (FAKE.to_owned(), "limits.timeout-minutes is not set"),
            (
                format!("{FAKE}{CAPPED}[session]\nlisten = true\noperators = [\"op@github\"]\n"),
                "session.origins needs 1 to",
            ),
            (
                format!("{FAKE}{CAPPED}[session]\nrelay = \"relay:7000\"\n"),
                "unknown field `relay`",
            ),
            (
                format!("{FAKE}[limits]\nbudget = 100\n"),
                "limits.timeout-minutes is not set",
            ),
            (
                format!("{FAKE}[limits]\ntimeout-minutes = 10\n"),
                "neither max-requests nor budget",
            ),
            (
                format!("{FAKE}{CAPPED}uncapped = true\n"),
                "limits.uncapped is set together",
            ),
            (
                format!("{FAKE}[limits]\ntimeout-minutes = 10\nmax-requests = 50\n"),
                "would not bind: nothing counts this run's model requests (the run has no \
                 inference proxy)",
            ),
            (
                format!(
                    "{CLAUDE}{PROXY}{token_file}[limits]\ntimeout-minutes = 10\n\
                     max-requests = 50\n{DIRECT}"
                ),
                "register = \"token-file\" has no run API",
            ),
            (
                format!("{CLAUDE}{PROXY}{OIDC}{CAPPED}"),
                "add \"http://100.64.0.1:18080\" to egress.direct",
            ),
            (
                format!(
                    "{CLAUDE}{PROXY}{OIDC}{CAPPED}{}",
                    direct("http://100.64.0.1:18081")
                ),
                "is on the tailnet",
            ),
            (
                format!(
                    "[agent]
name = \"opencode\"
model = \"m\"
{PROXY}{OIDC}\
                     openai-url = \"https://100.64.0.2/v1\"
{CAPPED}{DIRECT}"
                ),
                "add \"https://100.64.0.2:443\" to egress.direct",
            ),
            (
                format!("{FAKE}{CAPPED}[child-agent]\nmodel = \"glm\"\n"),
                "child-agent.model means nothing without child-agent.name",
            ),
            (
                format!(
                    "{CLAUDE}{PROXY}{OIDC}{REQUESTS}{DIRECT}[child-agent]\nname = \"opencode\"\nmodel = \"m\"\n"
                ),
                "cannot be a child agent, only \"vibe\"",
            ),
            (
                format!("{CLAUDE}{PROXY}{OIDC}{REQUESTS}{DIRECT}[child-agent]\nname = \"vibe\"\n"),
                "child-agent.model is not set",
            ),
            (
                format!("{FAKE}{CAPPED}{CHILD}"),
                "child-agent needs inference",
            ),
            (
                format!("{CLAUDE}{PROXY}{OIDC}{CAPPED}{DIRECT}{CHILD}"),
                "child-agent needs limits.max-requests",
            ),
            (
                format!(
                    "{CLAUDE}{PROXY}{OIDC}[limits]\ntimeout-minutes = 10\nuncapped = true\n\
                     {DIRECT}{CHILD}"
                ),
                "child-agent needs limits.max-requests",
            ),
            (
                format!("{FAKE}{CAPPED}[commit]\nauthor = \"nobody\"\n"),
                "commit.author: \"nobody\" is not `Name <address>`",
            ),
            (
                format!("{FAKE}{CAPPED}[commit]\ntrailers = [\"no colon\"]\n"),
                "commit.trailers: \"no colon\" is not one line",
            ),
            (
                format!("{FAKE}{CAPPED}[sandbox]\nuser = \"root\"\n"),
                "sandbox.user: \"root\" is not a user name",
            ),
            (
                format!("{FAKE}{CAPPED}[setup]\nnpm = [\"opencode-ai\"]\n"),
                "setup.npm: \"opencode-ai\" is not NAME@VERSION",
            ),
            (
                format!("{FAKE}{CAPPED}[egress]\ndirect = [\"http://proxy.example:18080\"]\n"),
                "egress.direct: 'proxy.example' is not a tailnet IPv4 address",
            ),
        ];
        for (text, names) in cases {
            let err = checked(&text).expect_err(&text);
            assert!(format!("{err:#}").contains(names), "{text}: {err:#}");
        }
    }

    /// The agent's own address is held to `egress.direct`, and only
    /// where that is what decides whether it is reached.
    #[test]
    fn an_inference_proxy_the_agent_can_reach() {
        let opencode = "[agent]\nname = \"opencode\"\nmodel = \"m\"\n";
        let at = |url: &str| format!("[inference]\nurl = {url:?}\n{OIDC}");
        let cases = [
            // Listed, by another spelling of the same address and port.
            format!(
                "{CLAUDE}{PROXY}{OIDC}{CAPPED}{}",
                direct("http://100.64.0.1:18080/v1")
            ),
            format!(
                "{CLAUDE}{}{CAPPED}{}",
                at("https://100.64.0.1"),
                direct("https://100.64.0.1:443")
            ),
            // No egress proxy: the tailnet is open unless something is listed.
            format!("{CLAUDE}{PROXY}{OIDC}{CAPPED}[egress]\nproxy = false\n"),
            // Not on the tailnet, or not known to be.
            format!("{CLAUDE}{}{CAPPED}", at("http://127.0.0.1:18080")),
            format!("{CLAUDE}{}{CAPPED}", at("https://proxy.example")),
            format!(
                "{CLAUDE}{}{CAPPED}",
                at("http://proxy.tailnet.ts.net:18080")
            ),
            format!("{CLAUDE}{}{CAPPED}", at("http://192.0.2.1:18080")),
            // The address the agent does not use, and an agent that uses none.
            format!(
                "{CLAUDE}{PROXY}{OIDC}openai-url = \"http://100.64.0.2:1/v1\"\n{CAPPED}{DIRECT}"
            ),
            format!(
                "{opencode}{PROXY}{OIDC}anthropic-url = \"http://100.64.0.2:1\"\n{CAPPED}{DIRECT}"
            ),
            format!("{FAKE}{PROXY}register = \"plain\"\n{CAPPED}"),
        ];
        for text in cases {
            checked(&text).unwrap_or_else(|err| panic!("{text}: {err:#}"));
        }
    }

    /// `sandbox setup` holds a file to the machine's tables alone: it is
    /// also run by itself, on a file that describes no run.
    #[test]
    fn the_host_check_is_the_machines_part() {
        let host_only = "[sandbox]\nstop-services = [\"docker.service\"]\n";
        let config = Config::parse(host_only).unwrap();
        assert_eq!(
            config.check_host().unwrap(),
            Host {
                install_vibe: false,
                direct: vec![],
                session: None
            }
        );
        assert!(config.check().is_err());
        for bad in [
            "[sandbox]\nuser = \"root\"\n",
            "[setup]\npackages = [\"--installroot=/\"]\n",
            "[egress]\ndirect = [\"http://proxy.example:18080\"]\n",
        ] {
            let config = Config::parse(bad).unwrap();
            assert!(config.check_host().is_err(), "{bad}");
            assert!(config.check().is_err(), "{bad}");
        }
    }

    /// A cap on model requests is kept where the proxy counts them, and
    /// is never dropped where nothing does: such a configuration is
    /// refused, so that a run is uncapped only by saying so.
    #[test]
    fn a_request_cap_nothing_counts_is_refused() {
        let endpoint = |mode| Endpoint {
            url: "http://proxy".into(),
            mode,
            anthropic_url: "http://proxy/anthropic".into(),
            openai_url: "http://proxy/v1".into(),
        };
        let table = |text: &str| {
            Config::parse(&format!("[limits]\ntimeout-minutes = 10\n{text}"))
                .unwrap()
                .limits
        };
        let given = endpoint(Mode::TokenFile {
            path: "/run/token".into(),
        });
        let counted = endpoint(Mode::Plain);
        // (limits, endpoint, the cap kept or the refusal)
        type Case<'a> = (&'a str, Option<&'a Endpoint>, Result<Option<u64>, &'a str>);
        let cases: [Case; 9] = [
            ("max-requests = 150", Some(&counted), Ok(Some(150))),
            (
                "max-requests = 150\nbudget = 500",
                Some(&counted),
                Ok(Some(150)),
            ),
            ("max-requests = 150", Some(&given), Err("would not bind")),
            (
                "max-requests = 150\nbudget = 500",
                Some(&given),
                Err("register = \"token-file\" has no run API"),
            ),
            ("max-requests = 150", None, Err("no inference proxy")),
            (
                "max-requests = 150",
                None,
                Err("max-requests input \
                 defaults to 150, pass max-requests: \"0\" with budget"),
            ),
            ("budget = 500", Some(&given), Ok(None)),
            ("uncapped = true", Some(&given), Ok(None)),
            ("", Some(&given), Err("neither max-requests nor budget")),
        ];
        for (text, endpoint, want) in cases {
            match (limits(&table(text), endpoint), want) {
                (Ok(limits), Ok(cap)) => assert_eq!(limits.max_requests, cap, "{text}"),
                (Err(err), Err(want)) => {
                    assert!(format!("{err:#}").contains(want), "{text}: {err:#}");
                }
                (got, want) => panic!("{text}: got {got:?}, wanted {want:?}"),
            }
        }
    }

    #[test]
    fn vibe_requires_a_counted_request_cap() {
        let agent = "[agent]\nname = \"vibe\"\nmodel = \"devstral-small-latest\"\n";
        for (limits, error) in [
            ("max-requests = 100", None),
            ("budget = 500", Some("vibe needs limits.max-requests")),
            ("uncapped = true", Some("vibe needs limits.max-requests")),
        ] {
            let text =
                format!("{agent}{PROXY}{OIDC}[limits]\ntimeout-minutes = 10\n{limits}\n{DIRECT}");
            match (checked(&text), error) {
                (Ok(_), None) => {}
                (Err(err), Some(want)) => assert!(format!("{err:#}").contains(want), "{err:#}"),
                (got, want) => panic!("{text}: got {got:?}, wanted {want:?}"),
            }
        }
    }
}
