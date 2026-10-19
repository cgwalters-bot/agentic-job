//! The run token's life against a mock inference proxy that speaks the
//! broker's run API (`support`): registering with an identity token and
//! without proof, the retries, the count of model requests, and the end
//! of the run. What the old tree's `praxis.test.mjs` covered, and the
//! one case it had the other way round: a proxy with no run API.

// clippy.toml lets test functions unwrap, but not the helpers they share,
// which here are most of the file.
#![allow(clippy::unwrap_used)]

mod support;

use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agentic_job::config::Register;
use agentic_job::run::inference::{
    Ended, Endpoint, Identity, Mode, NEVER, OIDC_TOKEN_VAR, OIDC_URL_VAR, OidcRequest,
    RECORD_SCHEMA, Retry, Run, Token,
};
use agentic_job::run::register::{DEBUG_VAR, FORGEJO_VAR, STEP_DEBUG_VAR};
use support::{AUDIENCE, FORGEJO_OIDC, Fault, Proxy, REQUEST_BEARER};

const TIMEOUT_S: u64 = 600;
const QUICK: Retry = Retry {
    attempts: 4,
    delay: Duration::from_millis(10),
};
const NAME: &str = "37558571698-1";

fn endpoint(proxy: &Proxy, mode: Mode) -> Endpoint {
    Endpoint {
        url: proxy.url.clone(),
        mode,
        anthropic_url: format!("{}/anthropic", proxy.url),
        openai_url: format!("{}/v1", proxy.url),
        front: false,
    }
}

fn oidc_mode() -> Mode {
    Mode::GithubOidc {
        audience: AUDIENCE.to_owned(),
        identity_proxy: None,
    }
}

fn job(proxy: &Proxy) -> Identity {
    Identity {
        oidc: Some(OidcRequest {
            url: proxy.oidc_url(),
            bearer: REQUEST_BEARER.to_owned(),
        }),
        name: Some(NAME.to_owned()),
        ..Identity::default()
    }
}

fn register(proxy: &Proxy, mode: Mode) -> anyhow::Result<Run> {
    Run::register(&endpoint(proxy, mode), &job(proxy), QUICK, TIMEOUT_S, NEVER)
}

fn error(result: anyhow::Result<Run>) -> String {
    match result {
        Ok(_) => panic!("the run registered"),
        Err(err) => format!("{err:#}"),
    }
}

/// `github-oidc`: the job asks the CI system for an identity token for
/// the proxy's audience and sends only that; the proxy's count is read
/// with the run token; ending the run kills the token.
#[test]
fn a_run_registers_with_the_jobs_identity_token() {
    let proxy = Proxy::start();
    let run = register(&proxy, oidc_mode()).unwrap();
    assert_eq!(run.register_mode(), Register::GithubOidc);
    assert_eq!(proxy.seen(), ["GET /oidc", "POST /v1/runs"]);
    let requests = proxy.requests();
    assert_eq!(
        requests[0].path,
        format!("/oidc?api-version=2&audience={AUDIENCE}")
    );
    assert_eq!(
        requests[0].header("authorization"),
        Some(format!("Bearer {REQUEST_BEARER}").as_str())
    );
    let sent = requests[1].header("authorization").unwrap();
    assert!(
        sent.starts_with(&format!("Bearer jwt.{AUDIENCE}.")),
        "{sent}"
    );
    // No name beside the proof, and no body.
    assert_eq!(requests[1].header("x-run-id"), None);
    let body = ["content-length", "transfer-encoding"].map(|name| requests[1].header(name));
    assert!(matches!(body, [None | Some("0"), None]), "{body:?}");
    assert_eq!(proxy.live_tokens(), [run.token().expose()]);
    let record = run.registered().unwrap();
    assert_eq!(record.as_json()["schema"], RECORD_SCHEMA);
    assert_eq!(record.as_json()["proof"], "github-oidc");

    assert_eq!(run.usage().unwrap().model_requests(), Some(0));
    proxy.serve_requests(3);
    assert_eq!(run.usage().unwrap().model_requests(), Some(3));

    let Ended::Ended(Some(last)) = run.end(QUICK).unwrap() else {
        panic!("no final record");
    };
    assert_eq!((last.state(), last.model_requests()), ("finished", Some(3)));
    assert!(proxy.live_tokens().is_empty());
    assert_eq!(proxy.run_states(), ["finished"]);
    // Ending it again is harmless and gives the same record.
    assert_eq!(run.end(QUICK).unwrap(), Ended::Ended(Some(last)));
}

/// `github-oidc` registered by an earlier job (`agentic-job register`):
/// the agent's job has no identity token, only the run token, and takes
/// the run over once the proxy says it is active. It is counted and ended
/// as its own; a token whose run has ended, or that the proxy does not
/// know, starts nothing.
#[test]
fn a_run_an_earlier_job_registered_is_taken_over() {
    let proxy = Proxy::start();
    let earlier = register(&proxy, oidc_mode()).unwrap();
    let given = Identity {
        run_token: Some(earlier.token().clone()),
        ..Identity::default()
    };
    let take_over = || {
        Run::register(
            &endpoint(&proxy, oidc_mode()),
            &given,
            QUICK,
            TIMEOUT_S,
            NEVER,
        )
    };
    let run = take_over().unwrap();
    assert_eq!(run.token(), earlier.token());
    assert_eq!(run.register_mode(), Register::GithubOidc);
    assert_eq!(
        proxy.seen(),
        ["GET /oidc", "POST /v1/runs", "GET /v1/runs/self"]
    );
    assert_eq!(proxy.run_states(), ["active"]);
    assert_eq!(run.counted_at_registration(), Some(0));
    proxy.serve_requests(2);
    assert_eq!(run.usage().unwrap().model_requests(), Some(2));
    assert!(matches!(run.end(QUICK).unwrap(), Ended::Ended(Some(_))));
    assert!(proxy.live_tokens().is_empty());

    // A re-run of the agent's job alone gets the ended run's token.
    let err = error(take_over());
    assert!(err.contains("\"finished\", not active"), "{err}");
    proxy.restart();
    let err = error(take_over());
    assert!(err.contains("does not know the run token"), "{err}");
    // Neither asked for an identity token or registered anew.
    assert_eq!(
        proxy
            .seen()
            .iter()
            .filter(|r| r.starts_with("POST") || r.contains("oidc"))
            .count(),
        2
    );
}

/// `agentic-job register`, as the workflow's register job runs it: the
/// run token goes to the output file alone, never to its stdout or
/// stderr; another mode registers nothing and writes nothing; and without
/// the job's identity token it fails rather than write an empty token.
/// With step debug logging, where the runner would log the output's
/// value, it refuses before it registers. On Forgejo it masks the token.
#[test]
fn the_register_command_writes_the_token_to_its_output_alone() {
    let proxy = Proxy::start();
    let dir = tempfile::tempdir().unwrap();
    let (config, output) = (dir.path().join("config.toml"), dir.path().join("output"));
    let command = |register: &str, oidc: bool, env: &[(&str, &str)]| {
        std::fs::write(
            &config,
            format!(
                "[agent]\nname = \"claude\"\n[limits]\ntimeout-minutes = 10\nuncapped = true\n\
                 [inference]\nurl = \"{}\"\n{register}\n",
                proxy.url
            ),
        )
        .unwrap();
        std::fs::write(&output, "earlier=1\n").unwrap();
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_agentic-job"));
        command
            .args(["register", "--config"])
            .arg(&config)
            .arg("--output")
            .arg(&output)
            .env_remove(OIDC_URL_VAR)
            .env_remove(OIDC_TOKEN_VAR)
            .env_remove(DEBUG_VAR)
            .env_remove(STEP_DEBUG_VAR)
            .env_remove(FORGEJO_VAR);
        if oidc {
            command
                .env(OIDC_URL_VAR, proxy.oidc_url())
                .env(OIDC_TOKEN_VAR, REQUEST_BEARER);
        }
        command.envs(env.iter().copied());
        let got = command.output().unwrap();
        let printed =
            String::from_utf8(got.stdout).unwrap() + &String::from_utf8(got.stderr).unwrap();
        (
            got.status.success(),
            printed,
            std::fs::read_to_string(&output).unwrap(),
        )
    };
    let oidc = format!("register = \"github-oidc\"\naudience = \"{AUDIENCE}\"");
    let (passed, printed, written) = command(&oidc, true, &[]);
    assert!(passed, "{printed}");
    let token = proxy.live_tokens().pop().unwrap();
    assert_eq!(written, format!("earlier=1\nrun-token={token}\n"));
    assert!(!printed.contains(&token), "{printed}");
    assert!(!printed.contains(REQUEST_BEARER), "{printed}");

    let (passed, printed, written) = command(&oidc, false, &[]);
    assert!(!passed && printed.contains("id-token: write"), "{printed}");
    assert_eq!(written, "earlier=1\n");
    // GitHub's runner sets RUNNER_DEBUG; Forgejo's debug switch is the
    // ACTIONS_STEP_DEBUG secret, which a workflow may pass on. Either
    // refuses on either forge.
    for debug in [
        (DEBUG_VAR, "1"),
        (DEBUG_VAR, "true"),
        (STEP_DEBUG_VAR, "true"),
    ] {
        for forge in [None, Some((FORGEJO_VAR, "true"))] {
            let env: Vec<_> = [Some(debug), forge].into_iter().flatten().collect();
            let (passed, printed, written) = command(&oidc, true, &env);
            assert!(!passed && printed.contains("debug logging"), "{printed}");
            assert!(printed.contains(debug.0), "{printed}");
            assert_eq!(written, "earlier=1\n");
        }
    }
    let (passed, printed, written) = command("register = \"plain\"", true, &[]);
    assert!(
        passed && printed.contains("Nothing to register"),
        "{printed}"
    );
    assert_eq!(written, "earlier=1\n");
    assert_eq!(proxy.run_states(), ["active"]);

    // On Forgejo, which keeps a masked job output, the token is masked
    // before it is written: printed in the mask command alone. Not for
    // another value, as a runner that drops a masked output may have.
    let mut seen = vec![token];
    for (value, masked) in [("true", true), ("1", false)] {
        let (passed, printed, written) = command(&oidc, true, &[(FORGEJO_VAR, value)]);
        assert!(passed, "{printed}");
        let new = proxy
            .live_tokens()
            .into_iter()
            .find(|live| !seen.contains(live))
            .unwrap();
        assert_eq!(written, format!("earlier=1\nrun-token={new}\n"));
        let mask = format!("::add-mask::{new}\n");
        assert_eq!(printed.starts_with(&mask), masked, "{printed}");
        assert_eq!(
            printed.matches(&new).count(),
            usize::from(masked),
            "{printed}"
        );
        assert!(!seen.iter().any(|old| printed.contains(old)), "{printed}");
        seen.push(new);
    }
}

/// A proxy that is restarting is tried again, with the same identity
/// token, which the proxy answers with the same run: a lost reply costs
/// nothing and leaves no second run.
#[test]
fn registration_is_retried_with_the_same_identity_token() {
    let proxy = Proxy::start();
    proxy.fail_registrations([
        Fault::Status(503, "OIDC keys unavailable\n"),
        Fault::LostReply,
        Fault::Status(429, "too many registrations\n"),
    ]);
    let run = register(&proxy, oidc_mode()).unwrap();
    let posts: Vec<_> = proxy
        .requests()
        .into_iter()
        .filter(|r| r.method == "POST")
        .map(|r| r.header("authorization").unwrap().to_owned())
        .collect();
    assert_eq!(posts.len(), 4);
    assert!(posts.iter().all(|sent| *sent == posts[0]), "{posts:?}");
    // One identity token was asked for, one run exists, and only the
    // last token it was given works.
    assert_eq!(proxy.seen().iter().filter(|r| *r == "GET /oidc").count(), 1);
    assert_eq!(proxy.run_states(), ["active"]);
    assert_eq!(proxy.live_tokens(), [run.token().expose()]);
}

/// `plain`: the run's name and no proof, where the proxy's policy admits
/// that. A name registers once, so a try after a lost reply asks under a
/// new one.
#[test]
fn a_run_registers_without_proof_by_name() {
    let proxy = Proxy::start();
    proxy.admit_unproven();
    let run = register(&proxy, Mode::Plain).unwrap();
    assert_eq!(run.register_mode(), Register::Plain);
    assert_eq!(proxy.seen(), ["POST /v1/runs"]);
    let request = &proxy.requests()[0];
    assert_eq!(request.header("x-run-id"), Some(NAME));
    assert_eq!(request.header("authorization"), None);
    assert_eq!(run.registered().unwrap().as_json()["run"], NAME);
    assert_eq!(run.end(QUICK).unwrap(), Ended::Ended(run.usage()));

    // The name is taken now, by a run that has ended.
    let err = error(register(&proxy, Mode::Plain));
    assert!(
        err.contains("HTTP 409") && err.contains("registered already"),
        "{err}"
    );

    let proxy = Proxy::start();
    proxy
        .admit_unproven()
        .fail_registrations([Fault::Closed, Fault::LostReply]);
    let run = register(&proxy, Mode::Plain).unwrap();
    let names: Vec<_> = proxy
        .requests()
        .iter()
        .map(|r| r.header("x-run-id").unwrap().to_owned())
        .collect();
    assert_eq!(
        names,
        [
            NAME.to_owned(),
            format!("{NAME}.retry1"),
            format!("{NAME}.retry2")
        ]
    );
    // The orphan of the lost reply expires at the proxy by itself.
    assert_eq!(proxy.run_states(), ["active", "active"]);
    assert!(
        proxy
            .live_tokens()
            .contains(&run.token().expose().to_owned())
    );
}

/// A run that cannot announce itself does not start. None of these is
/// ever an agent running uncapped, which is what the old tree made of a
/// proxy without the run API.
#[test]
fn a_run_that_cannot_announce_itself_does_not_start() {
    let refusal = |status, text| vec![Fault::Status(status, text)];
    // (whether the proxy has the run API, what it answers registrations
    // with, the mode, the error, the registrations tried)
    let cases: [(bool, Vec<Fault>, Mode, &str, usize); 10] = [
        (false, vec![], oidc_mode(), "has no run API (HTTP 404", 1),
        (false, vec![], Mode::Plain, "does not start", 1),
        // A proxy whose policy does not admit unproven runs.
        (
            true,
            vec![],
            Mode::Plain,
            "does not register runs without proof (HTTP 401",
            1,
        ),
        (
            true,
            refusal(403, "workflow may not register runs\n"),
            oidc_mode(),
            "refused to register runs of this workflow (HTTP 403: workflow may not register runs)",
            1,
        ),
        (
            true,
            refusal(401, "invalid OIDC token\n"),
            oidc_mode(),
            "rejected the job's identity token (HTTP 401: invalid OIDC token): its audience is \"mock-proxy\"",
            1,
        ),
        // No policy at all is not a restart: it is not tried again.
        (
            true,
            refusal(503, "run registration is not configured\n"),
            oidc_mode(),
            "has no policy for registering runs",
            1,
        ),
        (
            true,
            vec![Fault::Status(503, "too many runs\n"); 4],
            oidc_mode(),
            "HTTP 503: too many runs",
            4,
        ),
        (
            true,
            vec![Fault::Closed; 4],
            oidc_mode(),
            "cannot reach the inference proxy",
            4,
        ),
        (
            true,
            refusal(201, "{\"usage\": {}}"),
            oidc_mode(),
            "returned no token",
            1,
        ),
        // Not followed: the identity token would go wherever it points.
        (
            true,
            vec![Fault::Redirect("/v1/runs")],
            oidc_mode(),
            "failed (HTTP 307",
            1,
        ),
    ];
    for (run_api, faults, mode, want, tries) in cases {
        let proxy = Proxy::start();
        if !run_api {
            proxy.without_run_api();
        }
        proxy.fail_registrations(faults);
        let err = error(register(&proxy, mode));
        assert!(err.contains(want), "{want}: {err}");
        let posts = proxy
            .seen()
            .iter()
            .filter(|r| *r == "POST /v1/runs")
            .count();
        assert_eq!(posts, tries, "{want}");
        assert!(proxy.live_tokens().is_empty(), "{want}");
    }
}

/// `identity-proxy`: the identity-token request, and it alone, goes
/// through the proxy the configuration names, as a CONNECT tunnel to an
/// https URL; one that is not https is refused before anything is sent.
#[test]
fn an_identity_proxy_carries_only_a_tunnel_to_the_ci_system() {
    let proxy = Proxy::start();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let identity_proxy = format!("http://{}", listener.local_addr().unwrap());
    let (seen, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let _ = seen.send(line.trim_end().to_owned());
            let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n");
        }
    });
    let mode = Mode::GithubOidc {
        audience: AUDIENCE.to_owned(),
        identity_proxy: Some(identity_proxy),
    };
    let ci = |url: &str| Identity {
        oidc: Some(OidcRequest {
            url: url.to_owned(),
            bearer: REQUEST_BEARER.to_owned(),
        }),
        ..Identity::default()
    };
    let register = |identity: &Identity| {
        error(Run::register(
            &endpoint(&proxy, mode.clone()),
            identity,
            QUICK,
            TIMEOUT_S,
            NEVER,
        ))
    };

    let err = register(&ci("https://ci.invalid:8443/oidc?api-version=2"));
    assert!(err.contains("asking for the identity token"), "{err}");
    let lines: Vec<String> = received.try_iter().collect();
    assert!(!lines.is_empty(), "the proxy was not asked");
    assert!(
        lines
            .iter()
            .all(|line| line == "CONNECT ci.invalid:8443 HTTP/1.1"),
        "{lines:?}"
    );

    let err = register(&ci(&proxy.oidc_url()));
    assert!(err.contains("not https"), "{err}");
    assert_eq!(received.try_iter().count(), 0);
    // Nothing reached the inference proxy, nor the CI system's stand-in.
    assert_eq!(proxy.seen(), [""; 0]);
}

/// What is missing on the job's side is said before anything is sent.
#[test]
fn a_run_needs_what_its_mode_sends() {
    let proxy = Proxy::start();
    proxy.admit_unproven();
    let nobody = Identity::default();
    let cases = [
        (oidc_mode(), "needs ACTIONS_ID_TOKEN_REQUEST_URL"),
        (Mode::Plain, "--meta has no \"run_id\""),
    ];
    for (mode, want) in cases {
        let err = error(Run::register(
            &endpoint(&proxy, mode),
            &nobody,
            QUICK,
            TIMEOUT_S,
            NEVER,
        ));
        assert!(err.contains(want), "{err}");
    }
    let wrong = Identity {
        oidc: Some(OidcRequest {
            url: proxy.oidc_url(),
            bearer: "not-the-jobs".to_owned(),
        }),
        name: Some("a name".to_owned()),
        ..Identity::default()
    };
    let err = error(Run::register(
        &endpoint(&proxy, oidc_mode()),
        &wrong,
        QUICK,
        TIMEOUT_S,
        NEVER,
    ));
    assert!(
        err.contains("asking for the identity token: HTTP 401"),
        "{err}"
    );
    let err = error(Run::register(
        &endpoint(&proxy, Mode::Plain),
        &wrong,
        QUICK,
        TIMEOUT_S,
        NEVER,
    ));
    assert!(err.contains("cannot name it at the proxy"), "{err}");
    assert!(
        proxy.seen().iter().all(|r| r == "GET /oidc"),
        "{:?}",
        proxy.seen()
    );

    let unreachable = Endpoint {
        url: "http://127.0.0.1:1".to_owned(),
        ..endpoint(&proxy, Mode::Plain)
    };
    let err = error(Run::register(
        &unreachable,
        &job(&proxy),
        QUICK,
        TIMEOUT_S,
        NEVER,
    ));
    assert!(
        err.contains("cannot reach the inference proxy at http://127.0.0.1:1"),
        "{err}"
    );
}

/// A request that gets no answer says which one it was: the CI system's
/// ID token endpoint, named by its host alone, or the inference proxy.
#[test]
fn an_unanswered_request_says_which_it_was() {
    let proxy = Proxy::start();
    let once = Retry {
        attempts: 1,
        ..QUICK
    };
    let ci = |url: &str| Identity {
        oidc: Some(OidcRequest {
            url: url.to_owned(),
            bearer: REQUEST_BEARER.to_owned(),
        }),
        ..Identity::default()
    };
    // A name that does not resolve (RFC 6761), and a refused connection.
    let endpoints = [
        (
            "http://root-url.invalid:3000/_apis/token?not-for-logs=1",
            "root-url.invalid",
        ),
        ("http://127.0.0.1:1/oidc?not-for-logs=1", "127.0.0.1"),
    ];
    for (url, host) in endpoints {
        let err = error(Run::register(
            &endpoint(&proxy, oidc_mode()),
            &ci(url),
            once,
            TIMEOUT_S,
            NEVER,
        ));
        assert!(
            err.contains(&format!(
                "the CI system's ID token endpoint (ACTIONS_ID_TOKEN_REQUEST_URL, host {host}) \
                 got no answer"
            )),
            "{err}"
        );
        for absent in [
            "not-for-logs",
            REQUEST_BEARER,
            "cannot reach the inference proxy",
        ] {
            assert!(!err.contains(absent), "{absent}: {err}");
        }
    }
    assert_eq!(proxy.seen(), [""; 0]);

    let unreachable = Endpoint {
        url: "http://127.0.0.1:1".to_owned(),
        ..endpoint(&proxy, oidc_mode())
    };
    let err = error(Run::register(
        &unreachable,
        &job(&proxy),
        once,
        TIMEOUT_S,
        NEVER,
    ));
    assert!(
        err.contains("cannot reach the inference proxy at http://127.0.0.1:1"),
        "{err}"
    );
    assert!(!err.contains("ID token endpoint"), "{err}");
    assert_eq!(proxy.seen(), ["GET /oidc"]);
}

/// Forgejo's request URL, its ROOT_URL with a path and `?placeholder=true`:
/// the audience is added as one more parameter, and when the ROOT_URL's
/// host gets no answer, the error names that host alone.
#[test]
fn a_forgejo_request_url_takes_the_audience_and_names_its_host() {
    let proxy = Proxy::start();
    let forgejo = |root_url: &str| Identity {
        oidc: Some(OidcRequest {
            url: format!("{root_url}{FORGEJO_OIDC}?placeholder=true"),
            bearer: REQUEST_BEARER.to_owned(),
        }),
        ..Identity::default()
    };
    Run::register(
        &endpoint(&proxy, oidc_mode()),
        &forgejo(&proxy.url),
        QUICK,
        TIMEOUT_S,
        NEVER,
    )
    .unwrap();
    assert_eq!(
        proxy.requests()[0].path,
        format!("{FORGEJO_OIDC}?placeholder=true&audience={AUDIENCE}")
    );

    let once = Retry {
        attempts: 1,
        ..QUICK
    };
    let err = error(Run::register(
        &endpoint(&proxy, oidc_mode()),
        &forgejo("https://forgejo.invalid/sub"),
        once,
        TIMEOUT_S,
        NEVER,
    ));
    assert!(
        err.contains(
            "the CI system's ID token endpoint (ACTIONS_ID_TOKEN_REQUEST_URL, host \
             forgejo.invalid) got no answer"
        ),
        "{err}"
    );
    for absent in ["placeholder", "/sub", "cannot reach the inference proxy"] {
        assert!(!err.contains(absent), "{absent}: {err}");
    }
}

/// `token-file`: the token is given, there is no run API, and so nothing
/// is counted and nothing is ended. The proxy is never asked.
#[test]
fn a_given_token_has_no_run() {
    let proxy = Proxy::start();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    let mode = || Mode::TokenFile { path: path.clone() };
    let err = error(register(&proxy, mode()));
    assert!(err.contains("reading the token file"), "{err}");
    std::fs::write(&path, "one with spaces\n").unwrap();
    let err = error(register(&proxy, mode()));
    assert!(
        err.contains("not a token") && !err.contains("not a token\n"),
        "{err}"
    );

    std::fs::write(&path, "sk-a-given-token-0123456789\n").unwrap();
    let run = Arc::new(register(&proxy, mode()).unwrap());
    assert_eq!(
        run.token(),
        &Token::new("sk-a-given-token-0123456789").unwrap()
    );
    assert_eq!(run.register_mode(), Register::TokenFile);
    assert!(!run.has_run_api() && run.registered().is_none() && run.usage().is_none());
    assert!(run.count(Duration::from_millis(10)).is_none());
    assert_eq!(run.end(QUICK).unwrap(), Ended::NoRunApi);
    assert!(proxy.seen().is_empty(), "{:?}", proxy.seen());
}

/// The session's cap on model requests reads this channel: it follows
/// the proxy's count while the run is counted, keeps the last count when
/// the proxy briefly cannot be asked, invalidates a stale count, and stops
/// when the counter is dropped.
#[test]
fn the_request_count_follows_the_proxy() {
    let proxy = Proxy::start();
    let run = Arc::new(register(&proxy, oidc_mode()).unwrap());
    let (count, counter) = run.count(Duration::from_millis(20)).unwrap();
    let wait_for = |want: Option<u64>| {
        let deadline = Instant::now() + Duration::from_secs(10);
        while *count.borrow() != want {
            assert!(
                Instant::now() < deadline,
                "the count stayed {:?}",
                *count.borrow()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    };
    wait_for(Some(0));
    proxy.serve_requests(2);
    wait_for(Some(2));
    proxy.serve_requests(40);
    wait_for(Some(42));
    // A proxy that forgot the run must not leave a trusted count forever.
    proxy.restart();
    wait_for(None);
    drop(counter);
    std::thread::sleep(Duration::from_millis(100));
    let polls = proxy.seen().len();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(proxy.seen().len(), polls, "the counting went on");
}

/// Ending a run either leaves its token dead or says it may be live.
#[test]
fn the_end_of_a_run() {
    const LIVE: &str = "its token may still be live";
    // A proxy that is briefly down is asked again.
    let proxy = Proxy::start();
    let run = register(&proxy, oidc_mode()).unwrap();
    proxy.fail_endings([502, 503].map(|status| Fault::Status(status, "upstream error\n")));
    assert!(matches!(run.end(QUICK).unwrap(), Ended::Ended(Some(_))));
    assert_eq!(
        proxy
            .seen()
            .iter()
            .filter(|r| *r == "DELETE /v1/runs/self")
            .count(),
        3
    );
    assert!(proxy.live_tokens().is_empty());

    // One that stays down, or refuses, leaves the token possibly live.
    for (statuses, tries) in [(vec![500; 4], 4), (vec![400], 1)] {
        let proxy = Proxy::start();
        let run = register(&proxy, oidc_mode()).unwrap();
        proxy.fail_endings(
            statuses
                .into_iter()
                .map(|status| Fault::Status(status, "upstream error\n")),
        );
        let err = format!("{:#}", run.end(QUICK).unwrap_err());
        assert!(err.contains(LIVE), "{err}");
        assert_eq!(
            proxy
                .seen()
                .iter()
                .filter(|r| *r == "DELETE /v1/runs/self")
                .count(),
            tries
        );
        assert_eq!(proxy.live_tokens().len(), 1);
    }

    // A proxy that answers and still has the run active did not end it.
    let proxy = Proxy::start();
    let run = register(&proxy, oidc_mode()).unwrap();
    proxy.keep_runs_active();
    let err = format!("{:#}", run.end(QUICK).unwrap_err());
    assert!(
        err.contains("still has the run active") && err.contains(LIVE),
        "{err}"
    );

    // A proxy that restarted knows no token: this one admits nothing,
    // and there is no record of the run.
    let proxy = Proxy::start();
    let run = register(&proxy, oidc_mode()).unwrap();
    proxy.restart();
    assert_eq!(run.end(QUICK).unwrap(), Ended::Ended(None));
}

/// A proxy that registers a run and gives no count of its requests the
/// client can read still registers it; what was counted at registration
/// is then nothing, which is what `run` refuses a request cap for.
#[test]
fn a_run_without_a_readable_count() {
    let proxy = Proxy::start();
    proxy.odd_records();
    let run = Arc::new(register(&proxy, oidc_mode()).unwrap());
    assert!(run.registered().is_none() && run.usage().is_none());
    assert_eq!(run.counted_at_registration(), None);
    let (count, _counter) = run.count(Duration::from_millis(10)).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(*count.borrow(), None);

    let proxy = Proxy::start();
    let run = Arc::new(register(&proxy, oidc_mode()).unwrap());
    assert_eq!(run.counted_at_registration(), Some(0));
    // The channel has the count from the start, before the first poll.
    let (count, _counter) = run.count(Duration::from_secs(3600)).unwrap();
    assert_eq!(*count.borrow(), Some(0));
}

/// Told to stop, a registration that is being retried gives up: it does
/// not go on for minutes and leave a run nobody ends.
#[test]
fn a_stopped_registration_is_not_retried() {
    let proxy = Proxy::start();
    proxy.fail_registrations(vec![Fault::Status(503, "too many runs\n"); 4]);
    let posts = || {
        proxy
            .seen()
            .iter()
            .filter(|r| *r == "POST /v1/runs")
            .count()
    };
    let stopped = || posts() > 0;
    let err = error(Run::register(
        &endpoint(&proxy, oidc_mode()),
        &job(&proxy),
        QUICK,
        TIMEOUT_S,
        &stopped,
    ));
    assert!(
        err.contains("stopped; the last try said") && err.contains("HTTP 503"),
        "{err}"
    );
    assert_eq!(posts(), 1);
}

/// A run the proxy lets live for less than the agent's timeout still
/// registers; the warning is the job log's.
#[test]
fn a_short_lived_run_still_registers() {
    let proxy = Proxy::start();
    proxy.run_secs(60);
    let run = register(&proxy, oidc_mode()).unwrap();
    let expires = run.registered().unwrap().expires_at_unix().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(expires < now + TIMEOUT_S);
}

/// A run registered without proof, fronted by `run`'s own proxy capped at
/// CAP model requests.
fn fronted(proxy: &Proxy, cap: Option<u64>) -> (Run, Endpoint) {
    proxy.admit_unproven();
    let endpoint = Endpoint {
        front: true,
        ..endpoint(proxy, Mode::Plain)
    };
    let run = Run::register(&endpoint, &job(proxy), QUICK, TIMEOUT_S, NEVER)
        .and_then(|run| run.front(&endpoint, cap, None))
        .unwrap();
    let agent = run.agent_endpoint(&endpoint);
    (run, agent)
}

/// A request to `run`'s proxy as the agent makes it: the status, the
/// content type and transfer encoding, and the text.
fn ask(url: &str, headers: &[(&str, &str)], body: &str) -> (u16, String, String, String) {
    let http: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .proxy(None)
        .build()
        .into();
    let request = headers
        .iter()
        .fold(http.post(url), |request, (name, value)| {
            request.header(*name, *value)
        });
    let mut response = request.send(body).unwrap();
    let header = |name| {
        response
            .headers()
            .get(name)
            .map(|value| value.to_str().unwrap().to_owned())
            .unwrap_or_default()
    };
    let (kind, encoding) = (header("content-type"), header("transfer-encoding"));
    let status = response.status().as_u16();
    (
        status,
        kind,
        encoding,
        response.body_mut().read_to_string().unwrap(),
    )
}

const MESSAGE: &str = r#"{"model":"m","max_tokens":1,"messages":[]}"#;

/// Under `inference.front` the agent is given `run`'s proxy and a token
/// of its own; each agent's route reaches the broker's with the run token
/// in place of that one, and the answer streams back. The run token
/// admits nothing at `run`'s proxy, and the broker's run API is not
/// forwarded, so the agent cannot register a run of its own through it.
#[test]
fn a_fronted_broker_gets_the_run_token_and_the_agent_never_does() {
    let proxy = Proxy::start();
    let (run, agent) = fronted(&proxy, None);
    assert!(run.fronted());
    let (local, broker) = (run.agent_token().expose(), run.token().expose());
    assert_ne!(local, broker);
    assert!(agent.url.starts_with("http://127.0.0.1:"), "{agent:?}");
    assert_ne!(agent.url, proxy.url);
    // Where the broker resolved when the run was fronted, and only there.
    let at: std::net::SocketAddr = proxy.url.strip_prefix("http://").unwrap().parse().unwrap();
    assert_eq!(run.broker_addresses(), [at]);
    assert_eq!(agent.anthropic_url, format!("{}/anthropic", agent.url));
    assert_eq!(agent.openai_url, format!("{}/openai", agent.url));

    // As Claude Code, opencode and Vibe send them.
    let placeholder = "Bearer praxis-substitute:anthropic";
    let bearer = format!("Bearer {local}");
    let routes = [
        (
            format!("{}/v1/messages?beta=true", agent.anthropic_url),
            vec![("authorization", placeholder), ("x-run-token", local)],
            "/anthropic/v1/messages?beta=true",
        ),
        (
            format!("{}/responses", agent.openai_url),
            vec![("authorization", bearer.as_str())],
            "/v1/responses",
        ),
        (
            format!("{}/mistral/v1/chat/completions", agent.url),
            vec![("authorization", bearer.as_str())],
            "/mistral/v1/chat/completions",
        ),
    ];
    for (url, headers, path) in routes {
        let (status, kind, encoding, text) = ask(&url, &headers, MESSAGE);
        assert_eq!(
            (status, kind.as_str(), encoding.as_str(), text.as_str()),
            (200, "text/event-stream", "chunked", support::ANSWER),
            "{url}"
        );
        let seen = proxy.requests().pop().unwrap();
        assert_eq!(seen.path, path);
        let sent = format!("{:?}", seen.headers);
        assert!(sent.contains(broker), "{sent}");
        assert!(!sent.contains(local), "{sent}");
    }

    // The run token is not the proxy's, and the run API is not forwarded.
    let registrations = || {
        proxy
            .seen()
            .iter()
            .filter(|r| *r == "POST /v1/runs")
            .count()
    };
    assert_eq!(registrations(), 1);
    let stolen = format!("Bearer {broker}");
    let (status, ..) = ask(
        &format!("{}/responses", agent.openai_url),
        &[("authorization", &stolen)],
        MESSAGE,
    );
    assert_eq!(status, 401);
    for path in ["/v1/runs", "/openai/../v1/runs", "/anthropic/../v1/runs"] {
        let (status, ..) = ask(
            &format!("{}{path}", agent.url),
            &[("authorization", &bearer), ("x-run-id", "agents-own")],
            "",
        );
        assert_eq!(status, 403, "{path}");
    }
    assert_eq!(registrations(), 1);
}

/// What the broker is sent through `run`'s proxy is held to its checks:
/// a tool the provider runs is refused before it reaches the broker.
#[test]
fn a_fronted_broker_gets_only_what_the_filter_admits() {
    let proxy = Proxy::start();
    let (run, agent) = fronted(&proxy, None);
    let before = proxy.seen().len();
    let bearer = format!("Bearer {}", run.agent_token().expose());
    for body in [
        r#"{"model":"m","tools":[{"type":"web_search"}]}"#,
        r#"{"model":"m","input":[{"role":"user","content":[{"type":"input_image","image_url":"https://x.invalid/leak"}]}]}"#,
        r#"{"model":"gpt-4o-search-preview"}"#,
    ] {
        let (status, _, _, text) = ask(
            &format!("{}/responses", agent.openai_url),
            &[("authorization", &bearer)],
            body,
        );
        assert_eq!(status, 403, "{body}: {text}");
    }
    assert_eq!(proxy.seen().len(), before);
}

/// `run`'s proxy refuses requests past the cap itself, counted when they
/// are admitted; the session's count is the higher of its count and the
/// broker's; and ending the run closes the port before the broker ends it.
#[test]
fn a_fronted_run_is_capped_counted_and_closed() {
    let proxy = Proxy::start();
    let (run, agent) = fronted(&proxy, Some(2));
    let run = Arc::new(run);
    let (count, _counter) = run.count(Duration::from_millis(10)).unwrap();
    let wait_for = |want: u64| {
        let deadline = Instant::now() + Duration::from_secs(10);
        while *count.borrow() != Some(want) {
            assert!(
                Instant::now() < deadline,
                "the count stayed {:?}",
                *count.borrow()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    };
    let bearer = format!("Bearer {}", run.agent_token().expose());
    let url = format!("{}/responses", agent.openai_url);
    let models = || {
        proxy
            .seen()
            .iter()
            .filter(|r| *r == "POST /v1/responses")
            .count()
    };
    for want in [200, 200, 403, 403] {
        let (status, ..) = ask(&url, &[("authorization", &bearer)], MESSAGE);
        assert_eq!(status, want);
    }
    assert_eq!(models(), 2);
    // The mock broker counted none of them: the proxy's count is higher.
    wait_for(2);
    // Then the broker's, which may see requests the proxy did not.
    proxy.serve_requests(5);
    wait_for(5);

    assert!(matches!(run.end(QUICK).unwrap(), Ended::Ended(Some(_))));
    assert_eq!(proxy.run_states(), ["finished"]);
    let address = agent.url.strip_prefix("http://").unwrap().to_owned();
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::net::TcpStream::connect(&address).is_ok() {
        assert!(Instant::now() < deadline, "{address} is still open");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(models(), 2);
}

/// `front` is for a broker: a run without one is left as it is.
#[test]
fn only_a_fronted_endpoint_is_fronted() {
    let proxy = Proxy::start();
    let endpoint = endpoint(&proxy, oidc_mode());
    let run = register(&proxy, oidc_mode())
        .and_then(|run| run.front(&endpoint, Some(1), None))
        .unwrap();
    assert!(!run.fronted());
    assert_eq!(run.agent_token(), run.token());
    assert_eq!(run.agent_endpoint(&endpoint), endpoint);
}
