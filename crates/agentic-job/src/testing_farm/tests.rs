use super::*;
use std::io::BufRead;
use std::sync::mpsc;

const TOKEN: &str = "fixture-api-token";
const ID: &str = "01234567-89ab-cdef-0123-456789abcdef";
const ARTIFACTS: &str = "https://artifacts.example.com";

fn request() -> Request {
    Request {
        api: "https://api.example.com".into(),
        url: "https://git.example.com/example-org/plans".into(),
        reference: "c".repeat(40),
        plan: "/plans/agent".into(),
        compose: "Fedora-Rawhide".into(),
        arch: "x86_64".into(),
        timeout: 60,
        variables: BTreeMap::from([("AGENT_ITEM".into(), "7".into())]),
        artifacts: ARTIFACTS.into(),
        handback: "work/handback.zip".into(),
    }
}

fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, content) in files {
        zip.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

/// A status response, its artifacts in the request's own directory under ROOT.
fn status_at(root: &str, state: &str, overall: &str) -> Value {
    json!({
        "id": ID,
        "state": state,
        "result": {"overall": overall},
        "run": {"artifacts": format!("{root}/{ID}")},
    })
}

fn state(state: &str, overall: &str) -> Value {
    status_at(ARTIFACTS, state, overall)
}

/// Testing Farm offline: each status call returns the next of STATES, the
/// last repeating, and each wait advances the clock by the poll interval.
/// Every status read checks that the request's ID is recorded.
struct Fixture {
    dir: tempfile::TempDir,
    start: Instant,
    now: Instant,
    states: Vec<Value>,
    /// When set, every status read from then on sees the request passed,
    /// however the reads are spaced.
    passes_at: Option<Instant>,
    status_delay: Duration,
    cancel_fails: bool,
    bytes: Vec<u8>,
    submitted: Vec<Value>,
    cancelled: Vec<String>,
    downloaded: Vec<String>,
}

impl Fixture {
    fn new(states: Vec<Value>, bytes: Vec<u8>) -> Self {
        let start = Instant::now();
        Self {
            dir: tempfile::tempdir().unwrap(),
            start,
            now: start,
            states,
            passes_at: None,
            status_delay: Duration::ZERO,
            cancel_fails: false,
            bytes,
            submitted: Vec::new(),
            cancelled: Vec::new(),
            downloaded: Vec::new(),
        }
    }

    fn passing() -> Self {
        Self::new(
            vec![
                state("queued", "unknown"),
                state("running", "unknown"),
                state("complete", "passed"),
            ],
            archive(&[("outputs.jsonl", b"{}\n"), ("aw-agent-run-7.patch", b"")]),
        )
    }

    fn id_file(&self) -> PathBuf {
        self.dir.path().join("request-id")
    }

    fn args(&self) -> Args {
        Args {
            request: self.dir.path().join("request.json"),
            output: self.dir.path().join("output"),
            id: self.id_file(),
        }
    }

    fn deadline(&self, request: &Request) -> Instant {
        self.start + Duration::from_secs(request.timeout * 60)
    }

    fn launch(&mut self, request: &Request) -> Result<BTreeMap<String, Vec<u8>>> {
        let (deadline, id_file) = (self.deadline(request), self.id_file());
        launch(self, request, TOKEN, deadline, &id_file)
    }

    fn run(&mut self, request: &Request) -> Result<Exit> {
        let (deadline, args) = (self.deadline(request), self.args());
        if !args.output.exists() {
            std::fs::create_dir(&args.output).unwrap();
        }
        run_with(&args, request, self, TOKEN, deadline)
    }
}

impl Farm for Fixture {
    fn now(&self) -> Instant {
        self.now
    }

    fn submit(&mut self, body: &Value) -> Result<Value> {
        self.submitted.push(body.clone());
        Ok(json!({"id": ID}))
    }

    fn status(&mut self, id: &str) -> Result<Value> {
        assert_eq!(id, ID);
        assert_eq!(
            std::fs::read_to_string(self.id_file()).unwrap(),
            format!("{ID}\n")
        );
        let started = self.now;
        self.now += self.status_delay;
        if self.passes_at.is_some_and(|at| started >= at) {
            return Ok(state("complete", "passed"));
        }
        if self.states.len() > 1 {
            Ok(self.states.remove(0))
        } else {
            Ok(self.states[0].clone())
        }
    }

    fn cancel(&mut self, id: &str) -> Result<()> {
        self.cancelled.push(id.to_owned());
        ensure!(!self.cancel_fails, "DELETE failed with HTTP 500");
        Ok(())
    }

    fn download(&mut self, url: &str) -> Result<Vec<u8>> {
        self.downloaded.push(url.to_owned());
        Ok(self.bytes.clone())
    }

    fn wait(&mut self, until: Instant) {
        self.now += POLL.min(until.saturating_duration_since(self.now));
    }
}

#[test]
fn passing_request_returns_its_handback() {
    let request = request();
    let mut farm = Fixture::passing();
    let files = farm.launch(&request).unwrap();
    assert_eq!(files["outputs.jsonl"], b"{}\n");
    assert_eq!(
        farm.downloaded,
        [format!("{ARTIFACTS}/{ID}/work/handback.zip")]
    );
    assert!(farm.cancelled.is_empty());
    assert_eq!(farm.submitted.len(), 1);
    // The request ended, so a cleanup step has nothing to cancel.
    assert!(!farm.id_file().exists());
}

/// The body is the caller's fields alone: no token, no secrets, no reservation.
#[test]
fn request_body_carries_no_token_and_no_reservation() {
    let request = request();
    let mut farm = Fixture::passing();
    farm.launch(&request).unwrap();
    let body = &farm.submitted[0];
    let text = body.to_string();
    for absent in [TOKEN, "secrets", RESERVATION, "reserve", "tmt", "webhook"] {
        assert!(!text.contains(absent), "{absent} in {text}");
    }
    assert_eq!(
        *body,
        json!({
            "test": {"fmf": {
                "url": "https://git.example.com/example-org/plans",
                "ref": "c".repeat(40),
                "name": "^/plans/agent$",
            }},
            "environments": [{
                "arch": "x86_64",
                "os": {"compose": "Fedora-Rawhide"},
                "variables": {"AGENT_ITEM": "7"},
            }],
            "settings": {"pipeline": {"timeout": 60}},
        })
    );
}

#[test]
fn token_in_a_variable_is_refused_before_submitting() {
    let mut request = request();
    request
        .variables
        .insert("LEAK".into(), format!("x{TOKEN}x"));
    let mut farm = Fixture::passing();
    let error = farm.launch(&request).unwrap_err();
    assert!(format!("{error:#}").contains("token"), "{error:#}");
    assert!(farm.submitted.is_empty());
}

#[test]
fn request_settings_are_bounded() {
    type Change = fn(&mut Request);
    let cases: &[(&str, Change)] = &[
        ("reservation", |r| {
            r.variables
                .insert("TF_RESERVATION_DURATION".into(), "60".into());
        }),
        ("reservation", |r| {
            r.variables
                .insert("tf_reservation_authorized_keys_base64".into(), "x".into());
        }),
        ("variable", |r| {
            r.variables.insert("1X".into(), "x".into());
        }),
        ("variable", |r| {
            r.variables.insert("A-B".into(), "x".into());
        }),
        ("variable", |r| {
            r.variables.insert("BIG".into(), "x".repeat(MAX_VALUE + 1));
        }),
        ("more than", |r| {
            r.variables = (0..=MAX_VARIABLES)
                .map(|i| (format!("V{i}"), String::new()))
                .collect();
        }),
        ("full lowercase commit", |r| r.reference = "main".into()),
        ("full lowercase commit", |r| r.reference = "C".repeat(40)),
        ("HTTPS", |r| r.api = "http://api.example.com".into()),
        ("HTTPS", |r| r.url = "http://git.example.com/plans".into()),
        ("HTTPS", |r| {
            r.artifacts = "https://artifacts.example.com/".into()
        }),
        ("HTTPS", |r| r.artifacts = "file:///tmp".into()),
        ("plan", |r| r.plan = "plans/agent".into()),
        ("compose", |r| r.compose = "Fedora Rawhide".into()),
        ("timeout", |r| r.timeout = 0),
        ("timeout", |r| r.timeout = MAX_MINUTES + 1),
        ("hand-back", |r| r.handback = "../other/handback.zip".into()),
        ("hand-back", |r| r.handback = "/handback.zip".into()),
        ("hand-back", |r| r.handback = "work//handback.zip".into()),
        ("hand-back", |r| r.handback = "work/handback.zip?x".into()),
    ];
    request().validate().unwrap();
    for (expected, change) in cases {
        let mut request = request();
        change(&mut request);
        let error = format!("{:#}", request.validate().unwrap_err());
        assert!(error.contains(expected), "{expected}: {error}");
    }
}

#[test]
fn unknown_fields_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("request.json");
    let mut value = json!({
        "api": "https://api.example.com",
        "url": "https://git.example.com/example-org/plans",
        "ref": "c".repeat(40),
        "plan": "/plans/agent",
        "compose": "Fedora-Rawhide",
        "arch": "x86_64",
        "timeout": 60,
        "artifacts": ARTIFACTS,
        "handback": "handback.zip",
    });
    std::fs::write(&path, value.to_string()).unwrap();
    Request::load(&path).unwrap();
    value["secrets"] = json!({"TOKEN": "x"});
    std::fs::write(&path, value.to_string()).unwrap();
    assert!(Request::load(&path).is_err());
}

#[test]
fn timeout_cancels_the_request() {
    let request = request();
    let mut farm = Fixture::new(vec![state("running", "unknown")], Vec::new());
    let error = farm.launch(&request).unwrap_err();
    assert!(
        format!("{error:#}").contains("did not finish within 60 minutes"),
        "{error:#}"
    );
    assert_eq!(farm.cancelled, [ID]);
    assert!(farm.downloaded.is_empty());
    assert!(!farm.id_file().exists());
}

/// A request whose cancellation failed keeps its ID for the cleanup step.
#[test]
fn failed_cancel_keeps_the_id() {
    let request = request();
    let mut farm = Fixture::new(vec![state("running", "unknown")], Vec::new());
    farm.cancel_fails = true;
    let error = farm.launch(&request).unwrap_err();
    assert!(format!("{error:#}").contains("failed too"), "{error:#}");
    assert_eq!(
        std::fs::read_to_string(farm.id_file()).unwrap(),
        format!("{ID}\n")
    );
    let id_file = farm.id_file();
    let error = cancel_with(&mut farm, &id_file).unwrap_err();
    assert!(format!("{error:#}").contains("HTTP 500"), "{error:#}");
    assert!(id_file.exists());
    farm.cancel_fails = false;
    cancel_with(&mut farm, &id_file).unwrap();
    assert_eq!(farm.cancelled, [ID; 3]);
    assert!(!farm.id_file().exists());
}

/// The cleanup step cancels only a recorded, well-formed ID.
#[test]
fn cleanup_cancels_only_a_recorded_request() {
    let mut farm = Fixture::new(vec![state("running", "unknown")], Vec::new());
    let id_file = farm.id_file();
    cancel_with(&mut farm, &id_file).unwrap();
    for text in ["", ID, "../../v0.1/requests\n", &format!("{ID}\nx\n")] {
        std::fs::write(&id_file, text).unwrap();
        let error = cancel_with(&mut farm, &id_file).unwrap_err();
        assert!(
            format!("{error:#}").contains("no Testing Farm request ID"),
            "{text:?}: {error:#}"
        );
    }
    assert!(farm.cancelled.is_empty());
}

/// A request that passes between the last poll before the deadline and the
/// deadline itself is fetched, not cancelled.
#[test]
fn passing_inside_the_last_poll_interval_is_fetched() {
    let request = request();
    let mut farm = Fixture::new(vec![state("running", "unknown")], Fixture::passing().bytes);
    let deadline = farm.deadline(&request);
    farm.passes_at = Some(deadline - Duration::from_secs(15));
    let files = farm.launch(&request).unwrap();
    assert_eq!(files["outputs.jsonl"], b"{}\n");
    assert!(farm.cancelled.is_empty());
    assert_eq!(farm.now, deadline);
}

#[test]
fn passing_during_a_status_read_that_spans_the_deadline_is_fetched() {
    let request = request();
    let mut farm = Fixture::new(vec![state("running", "unknown")], Fixture::passing().bytes);
    let deadline = farm.deadline(&request);
    farm.now = deadline - Duration::from_secs(1);
    farm.passes_at = Some(deadline);
    farm.status_delay = Duration::from_secs(2);
    farm.launch(&request).unwrap();
    assert!(farm.cancelled.is_empty());
    assert_eq!(farm.downloaded.len(), 1);
    assert_eq!(farm.now, deadline + Duration::from_secs(3));
}

/// tmt matches the plan name as a regular expression; the request's name
/// selects the caller's plan alone.
#[test]
fn plan_name_selects_only_that_plan() {
    let cases = [
        ("/plans/agent", "/plans/agent-reserve"),
        ("/plans/agent", "/plans/prefix/plans/agent"),
        ("/plans/agent.v1", "/plans/agentXv1"),
    ];
    for (plan, other) in cases {
        let mut request = request();
        request.plan = plan.into();
        request.validate().unwrap();
        let pattern = request.body()["test"]["fmf"]["name"]
            .as_str()
            .unwrap()
            .to_owned();
        let re = regex::Regex::new(&pattern).unwrap();
        assert!(re.is_match(plan), "{pattern} misses {plan}");
        assert!(!re.is_match(other), "{pattern} selects {other}");
    }
}

#[test]
fn unknown_state_cancels_the_request() {
    let request = request();
    let mut farm = Fixture::new(vec![state("paused", "unknown")], Vec::new());
    farm.launch(&request).unwrap_err();
    assert_eq!(farm.cancelled, [ID]);
}

/// Each refused remote result leaves the output directory empty.
#[test]
fn refused_results_write_nothing() {
    let passed = || vec![state("complete", "passed")];
    let cases: Vec<(&str, Vec<Value>, Vec<u8>)> = vec![
        (
            "did not pass: failed",
            vec![state("complete", "failed")],
            Vec::new(),
        ),
        (
            "did not pass: error",
            vec![state("complete", "error")],
            Vec::new(),
        ),
        (
            "did not pass: absent",
            vec![json!({"id": ID, "state": "complete"})],
            Vec::new(),
        ),
        ("ended error", vec![state("error", "unknown")], Vec::new()),
        (
            "ended canceled",
            vec![state("canceled", "unknown")],
            Vec::new(),
        ),
        (
            "is being cancelled",
            vec![state("cancel-requested", "unknown")],
            Vec::new(),
        ),
        (
            "another request",
            vec![json!({"id": "x", "state": "complete"})],
            Vec::new(),
        ),
        (
            "reported artifacts at nothing",
            vec![json!({"id": ID, "state": "complete", "result": {"overall": "passed"}})],
            Vec::new(),
        ),
        (
            "reported artifacts at https://elsewhere.example.com",
            vec![status_at(
                "https://elsewhere.example.com",
                "complete",
                "passed",
            )],
            Vec::new(),
        ),
        ("exceeds", passed(), vec![0; MAX_ARCHIVE as usize + 1]),
        ("hand-back", passed(), b"not a zip".to_vec()),
        ("hand-back is empty", passed(), archive(&[])),
        (
            "hand-back",
            passed(),
            archive(&[("../outputs.jsonl", b"{}\n")]),
        ),
        ("hand-back", passed(), archive(&[("run.sh", b"exit 0\n")])),
    ];
    let request = request();
    for (expected, states, bytes) in cases {
        let mut farm = Fixture::new(states, bytes);
        let error = farm.run(&request).unwrap_err();
        assert!(
            format!("{error:#}").contains(expected),
            "{expected}: {error:#}"
        );
        assert_eq!(std::fs::read_dir(farm.args().output).unwrap().count(), 0);
        // A request Testing Farm reported ended is not cancelled again.
        let live = matches!(expected, "another request" | "is being cancelled");
        assert_eq!(farm.cancelled.len(), usize::from(live), "{expected}");
        assert!(!farm.id_file().exists(), "{expected}");
    }
}

#[test]
fn nonempty_output_directory_is_refused_before_submitting() {
    let request = request();
    let mut farm = Fixture::passing();
    farm.run(&request).unwrap();
    farm.submitted.clear();
    farm.run(&request).unwrap_err();
    assert!(
        farm.submitted.is_empty(),
        "submitted with a nonempty output directory"
    );
}

/// An existing ID file is refused before anything is submitted.
#[test]
fn existing_id_file_is_refused_before_submitting() {
    let request = request();
    let mut farm = Fixture::passing();
    std::fs::write(farm.id_file(), "other\n").unwrap();
    let error = farm.run(&request).unwrap_err();
    assert!(format!("{error:#}").contains("must not exist"), "{error:#}");
    assert!(farm.submitted.is_empty());
    assert_eq!(std::fs::read_to_string(farm.id_file()).unwrap(), "other\n");
}

#[test]
fn request_ids_are_uuids() {
    assert!(is_request_id(ID));
    for id in [
        "",
        "../../v0.1/requests",
        &"a".repeat(36),
        &ID.to_uppercase(),
        "01234567-89ab-cdef-0123-456789abcde/",
    ] {
        assert!(!is_request_id(id), "{id}");
    }
}

/// One request as it arrived on the wire.
#[derive(Debug)]
struct Wire {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

/// A response: status, extra headers and body.
type Reply = (u16, Vec<(&'static str, String)>, Vec<u8>);

/// A loopback HTTPS server whose certificate only the test's own roots
/// trust. Each reply answers one connection; each request is sent to the
/// channel before its reply, so it is there once the client has the reply.
struct Server {
    root: String,
    listener: std::net::TcpListener,
    config: std::sync::Arc<tokio_rustls::rustls::ServerConfig>,
    roots: ureq::tls::RootCerts,
}

impl Server {
    fn bind() -> Self {
        use tokio_rustls::rustls::{self, pki_types};
        let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
        let roots = ureq::tls::RootCerts::new_with_certs(&[ureq::tls::Certificate::from_der(
            key.cert.der(),
        )
        .to_owned()]);
        let private = pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![key.cert.der().clone()], private.into())
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let root = format!(
            "https://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        );
        Self {
            root,
            listener,
            config: std::sync::Arc::new(config),
            roots,
        }
    }

    /// An API client of this server only: its roots, no proxy.
    fn api(&self, request: &Request, deadline: Instant) -> Api {
        Api {
            roots: self.roots.clone(),
            proxy: None,
            ..Api::new(request, TOKEN.into(), deadline)
        }
    }

    fn answer(self, replies: Vec<Reply>) -> mpsc::Receiver<Wire> {
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            for (status, headers, body) in replies {
                let (tcp, _) = self.listener.accept().unwrap();
                let connection =
                    tokio_rustls::rustls::ServerConnection::new(self.config.clone()).unwrap();
                let mut stream = std::io::BufReader::new(tokio_rustls::rustls::StreamOwned::new(
                    connection, tcp,
                ));
                sender.send(read_request(&mut stream)).unwrap();
                let mut head = format!(
                    "HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n",
                    body.len()
                );
                for (name, value) in headers {
                    head.push_str(&format!("{name}: {value}\r\n"));
                }
                head.push_str("\r\n");
                let stream = stream.get_mut();
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
                stream.conn.send_close_notify();
                stream.flush().unwrap();
            }
        });
        receiver
    }
}

fn read_request(stream: &mut impl BufRead) -> Wire {
    let mut line = String::new();
    stream.read_line(&mut line).unwrap();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap().to_owned();
    let path = parts.next().unwrap().to_owned();
    let (mut authorization, mut length) = (None, 0);
    loop {
        let mut header = String::new();
        stream.read_line(&mut header).unwrap();
        let Some((name, value)) = header.trim_end().split_once(": ") else {
            break;
        };
        match name.to_ascii_lowercase().as_str() {
            "authorization" => authorization = Some(value.to_owned()),
            "content-length" => length = value.parse().unwrap(),
            _ => {}
        }
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    Wire {
        method,
        path,
        authorization,
        body,
    }
}

fn ok(body: &Value) -> Reply {
    (200, Vec::new(), body.to_string().into_bytes())
}

/// Over HTTPS: the POST body is the caller's request, the token goes to
/// the API alone, and storage's redirect is refused, not followed.
#[test]
fn transport_sends_the_token_to_the_api_alone() {
    let server = Server::bind();
    let mut request = request();
    request.api = server.root.clone();
    request.artifacts = server.root.clone();
    let farm = Fixture::passing();
    let args = farm.args();
    std::fs::create_dir(&args.output).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut api = server.api(&request, deadline);
    let root = request.artifacts.clone();
    let wires = server.answer(vec![
        ok(&json!({"id": ID})),
        ok(&status_at(&root, "complete", "passed")),
        (
            302,
            vec![("Location", format!("{root}/elsewhere.zip"))],
            Vec::new(),
        ),
        // Served only if the redirect were followed.
        (200, Vec::new(), farm.bytes.clone()),
    ]);
    let error = run_with(&args, &request, &mut api, TOKEN, deadline).unwrap_err();
    assert!(format!("{error:#}").contains("HTTP 302"), "{error:#}");
    let wires: Vec<Wire> = wires.try_iter().collect();
    let bearer = Some(format!("Bearer {TOKEN}"));
    let seen: Vec<_> = wires
        .iter()
        .map(|wire| {
            (
                wire.method.as_str(),
                wire.path.as_str(),
                &wire.authorization,
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("POST", "/v0.1/requests", &bearer),
            ("GET", &*format!("/v0.1/requests/{ID}"), &bearer),
            ("GET", &*format!("/{ID}/work/handback.zip"), &None),
        ]
    );
    let body: Value = serde_json::from_slice(&wires[0].body).unwrap();
    assert_eq!(body, request.body());
    assert_eq!(std::fs::read_dir(&args.output).unwrap().count(), 0);
    assert!(!args.id.exists());
}

/// The cleanup step's DELETE on the wire, once, and nothing without an ID.
#[test]
fn transport_cancels_from_the_id_file() {
    let server = Server::bind();
    let mut request = request();
    request.api = server.root.clone();
    let dir = tempfile::tempdir().unwrap();
    let id_file = dir.path().join("request-id");
    std::fs::write(&id_file, format!("{ID}\n")).unwrap();
    let mut api = server.api(&request, Instant::now());
    let wires = server.answer(vec![(204, Vec::new(), Vec::new())]);
    cancel_with(&mut api, &id_file).unwrap();
    assert!(!id_file.exists());
    cancel_with(&mut api, &id_file).unwrap();
    let wires: Vec<Wire> = wires.try_iter().collect();
    assert_eq!(wires.len(), 1, "{wires:?}");
    assert_eq!(wires[0].method, "DELETE");
    assert_eq!(wires[0].path, format!("/v0.1/requests/{ID}"));
    assert_eq!(wires[0].authorization, Some(format!("Bearer {TOKEN}")));
}

fn documented_job() -> yaml_rust2::Yaml {
    // Read at run time: docs are outside what the build's digest covers.
    let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/interface.md");
    let docs = std::fs::read_to_string(docs).unwrap();
    let yaml = docs
        .split("```yaml\n")
        .skip(1)
        .filter_map(|block| block.split_once("```").map(|(yaml, _)| yaml))
        .find(|yaml| yaml.contains("testing-farm-cancel"))
        .expect("docs/interface.md shows the Testing Farm job");
    yaml_rust2::YamlLoader::load_from_str(yaml).unwrap()[0]["agent_job"].clone()
}

/// The documented job separates the cleanup ID from the workspace. The
/// filesystem and effective variable guarantees are runner prerequisites.
#[test]
fn documented_job_keeps_the_id_outside_the_workspace() {
    let job = documented_job();
    let variables = &job["variables"];
    assert_eq!(variables["GIT_STRATEGY"].as_str(), Some("empty"));
    assert!(job["dependencies"].as_vec().is_some_and(Vec::is_empty));
    assert!(job["needs"].is_badvalue() && job["cache"].is_badvalue());
    assert_eq!(job["inherit"]["default"].as_bool(), Some(false));
    assert!(job["before_script"].is_badvalue());
    assert!(job["environment"]["name"].as_str().is_some());
    let id_path = "/tmp/agentic-job-testing-farm/request-id";
    assert_eq!(
        job["script"][0].as_str(),
        Some("mkdir -m 700 /tmp/agentic-job-testing-farm")
    );
    for command in [&job["script"][1], &job["after_script"][0]] {
        assert!(
            command
                .as_str()
                .unwrap()
                .contains(&format!("--id {id_path}"))
        );
    }
    // Go's time.ParseDuration; GitLab Runner ignores a value it cannot parse.
    let duration = regex::Regex::new(r"^(\d+h)?(\d+m)?(\d+s)?$").unwrap();
    for key in ["RUNNER_SCRIPT_TIMEOUT", "RUNNER_AFTER_SCRIPT_TIMEOUT"] {
        let value = variables[key].as_str().unwrap_or_default();
        assert!(
            !value.is_empty() && duration.is_match(value),
            "{key}: {value:?}"
        );
    }
}

/// Model Runner's root glob and feed its re-archived files to the same
/// checked reader `external-fetch-gitlab` uses for the job ZIP.
#[test]
fn documented_job_publishes_a_flat_handback_the_consumer_can_read() {
    let job = documented_job();
    let artifacts = &job["artifacts"];
    assert_eq!(artifacts["when"].as_str(), Some("on_success"));
    let paths = artifacts["paths"].as_vec().unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].as_str(), Some("*"));
    assert!(job["script"][1].as_str().unwrap().ends_with(" --output ."));

    let mut farm = Fixture::passing();
    farm.run(&request()).unwrap();
    let included: Vec<_> = std::fs::read_dir(farm.args().output)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            (
                entry.file_name().into_string().unwrap(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect();
    let files: Vec<_> = included
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    let job_zip = archive(&files);
    assert_eq!(
        members(&job_zip).unwrap(),
        BTreeMap::from([
            ("aw-agent-run-7.patch".into(), Vec::new()),
            ("outputs.jsonl".into(), b"{}\n".to_vec()),
        ])
    );
    assert!(members(&archive(&[("handback.zip", &farm.bytes)])).is_err());
}
