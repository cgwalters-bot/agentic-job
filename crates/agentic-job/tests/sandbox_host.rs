//! Each probe of `sandbox check` fails when its protection is removed.
//!
//! This changes the host it runs on, as root, and puts each thing back:
//! it is for a machine that is thrown away, after `sandbox setup` has run
//! there. Setup ends by taking root away from the runner's user, this
//! test's own, so root is had through a service CI starts before setup
//! ([`ROOT_SOCKET`]: a shell behind a Unix socket only the runner's group
//! may connect to), and through sudo where that service is not there.
//! CI's `sandbox` job runs it:
//!
//! ```text
//! cargo test --test sandbox_host -- --ignored --nocapture
//! ```
//!
//! Every case runs every probe, which takes most of a minute, so CI
//! shares the cases out over several machines: with
//! `AGENTIC_JOB_TEST_SHARD=I/N` this runs every Nth case, starting at
//! the Ith (counted from 0). Each machine still checks that all probes
//! pass before anything is removed and after everything is put back.
//!
//! The run-token probes want the job's identity-token request variables
//! in the environment (any values: the probes only look for them where
//! they must not be).

// Helpers outside a #[test] function are still test code.
#![allow(clippy::unwrap_used)]

use std::any::Any;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{SocketAddr as UnixAddr, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use agentic_job::config::{self, Config};
use agentic_job::sandbox::check::{self, RunToken};
use agentic_job::sandbox::enter::Entry;
use agentic_job::sandbox::host::User;
use agentic_job::sandbox::{egress, network, setup};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

/// Where CI's root service listens: a shell that runs what it is sent,
/// as root, for this test alone (see the top of the file).
const ROOT_SOCKET: &str = "/run/agentic-job-test-root.sock";

/// What the shell prints after each command, with its status.
const STATUS_MARKER: &str = "__agentic_job_test_status=";

/// Sorts after the deny rules: a grant for the runner's user there wins.
const SUDOERS_RUNNER_GRANT: &str = "/etc/sudoers.d/zzz-test-runner-grant";

/// A polkit rule for the runner's user alone, read before the deny rule.
const POLKIT_RUNNER_GRANT: &str = "/etc/polkit-1/rules.d/00-aaa-test-runner-grant.rules";

/// polkitd watches its rules directory; give it a moment to reload.
const POLKIT_SETTLE: Duration = Duration::from_secs(3);

const POLKIT_DENY: &str = "/etc/polkit-1/rules.d/00-agentic-job-sandbox.rules";

const POLKIT_ASIDE: &str = "/etc/polkit-1/agentic-job-sandbox.rules.aside";

/// Sorts before the deny rule, so the first rule to answer is this one.
const POLKIT_GRANT: &str = "/etc/polkit-1/rules.d/00-aaa-test-grant.rules";

/// Sorts after the deny rule: the last matching sudoers rule wins.
const SUDOERS_GRANT: &str = "/etc/sudoers.d/zzz-test-grant";

const TAILSCALE_DIR: &str = "/var/run/tailscale";

const TAILSCALE_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

const HCA_DIR: &str = "/opt/hca";

const SUDOERS_EARLY_GRANT: &str = "/etc/sudoers.d/aa-test-grant";

/// A group both runner images have, and that reads the host's logs.
const FORBIDDEN_GROUP: &str = "adm";

const READABLE_TOKEN: &str = "/etc/agentic-job-test-token";

/// The variable whose value the job must keep from the sandbox user.
const REQUEST_TOKEN_VAR: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

/// Which of the cases this machine runs: `I/N`, see the top of the file.
const SHARD_VAR: &str = "AGENTIC_JOB_TEST_SHARD";

fn scheduler_failures(id: &str, view_masks_cron: bool) -> &'static [&'static str] {
    match (id, view_masks_cron) {
        ("cron", true) => &[],
        ("cron", false) => &["cron"],
        ("at", false) => &["at"],
        _ => panic!("unsupported scheduler case: {id}, masked={view_masks_cron}"),
    }
}

/// Under the view, the sandbox user's write meets a read-only mount
/// before the world-write policy: only the runner's probe is left to fail.
fn world_write_failures(view: bool) -> &'static [&'static str] {
    if view {
        &["runner-world-write"]
    } else {
        &["runner-world-write", "world-write"]
    }
}

/// The cases a layer can mask, which the host without the view runs too.
fn baseline_case(name: &str) -> bool {
    matches!(name, "cron" | "at" | "the world-write policy")
}

fn removal_case_enabled(name: &str, view: bool) -> bool {
    view || baseline_case(name)
}

#[test]
fn layered_removal_cases_are_observable() {
    for (id, masked, expected) in [
        ("cron", false, vec!["cron"]),
        ("cron", true, vec![]),
        ("at", false, vec!["at"]),
    ] {
        assert_eq!(scheduler_failures(id, masked), expected);
        assert!(baseline_case(id));
    }
    assert_eq!(world_write_failures(true), ["runner-world-write"]);
    assert_eq!(
        world_write_failures(false),
        ["runner-world-write", "world-write"]
    );
    for (name, without_view, with_view) in [
        ("cron", true, true),
        ("at", true, true),
        ("the world-write policy", true, true),
        ("the runner's home open", false, true),
        ("the user manager's filesystem view", false, true),
    ] {
        assert_eq!(baseline_case(name), without_view);
        for (view, expected) in [(false, without_view), (true, with_view)] {
            assert_eq!(removal_case_enabled(name, view), expected, "{name}");
        }
    }
}

/// The policy's map value, as secure-host/world-write.mjs writes it: the
/// root filesystem's kernel dev_t (major << 20 | minor), then whether it
/// is enabled, each a native-endian u32, in hex bytes for bpftool.
fn world_write_config(enabled: bool) -> Vec<String> {
    let dev = std::fs::metadata("/").unwrap().dev();
    let device = (rustix::fs::major(dev) << 20) | rustix::fs::minor(dev);
    device
        .to_ne_bytes()
        .into_iter()
        .chain(u32::from(enabled).to_ne_bytes())
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `bpftool` setting the policy's one map entry to `value`.
fn world_write_update(value: &[String]) -> Vec<String> {
    let map = format!("{}/maps/root_fs", setup::WORLD_WRITE_PIN);
    let head = ["bpftool", "map", "update", "pinned", &map];
    let key = ["key", "hex", "00", "00", "00", "00", "value", "hex"];
    strings(&head)
        .into_iter()
        .chain(strings(&key))
        .chain(value.iter().cloned())
        .collect()
}

/// The shard `AGENTIC_JOB_TEST_SHARD` names, as (index, count); every
/// case when it is not set. A value that is not `I/N` with I below N is
/// a mistake in the job, and running nothing for it would pass.
fn shard() -> (usize, usize) {
    let Ok(text) = std::env::var(SHARD_VAR) else {
        return (0, 1);
    };
    let parsed = text
        .split_once('/')
        .and_then(|(index, count)| Some((index.parse().ok()?, count.parse().ok()?)))
        .filter(|(index, count)| index < count);
    parsed.unwrap_or_else(|| panic!("{SHARD_VAR}={text:?} is not I/N with I below N"))
}

/// The working directory changed to one outside the runner's home; put
/// back when dropped.
struct WorkDir {
    before: PathBuf,
    dir: PathBuf,
}

impl WorkDir {
    fn enter(dir: &str) -> Self {
        let before = std::env::current_dir().unwrap();
        std::fs::create_dir(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_current_dir(dir).unwrap();
        Self {
            before,
            dir: PathBuf::from(dir),
        }
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.before);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// A process of the sandbox user's that runs `script` (sh, with `arg` as
/// `$1`) until the returned value is dropped. The script must sleep.
fn sandbox_process(entry: &Entry, uid: u32, script: &'static str, arg: String) -> Removed {
    let entry = entry.clone();
    let holder = std::thread::spawn(move || {
        let _ = entry.run(&["sh", "-c", script, "sh", &arg], b"");
    });
    std::thread::sleep(Duration::from_secs(3));
    let stop = strings(&["pkill", "-KILL", "-u", &uid.to_string(), "sleep"]);
    Removed::new(vec![stop], vec![Box::new(holder)])
}

/// A stand-in the length and shape of a real run token.
const TOKEN: &str = "test-run-0123456789abcdef0123456789abcdef0123456789abcdef";

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|&item| item.to_owned()).collect()
}

/// What a command run as root left: its status, and all it wrote.
struct RootOutput {
    success: bool,
    /// The exit status, or -1 for a command ended by a signal.
    status: i32,
    output: String,
}

/// `text` as one word for sh.
fn sh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// Runs `argv` as root with `input` on its standard input, through the
/// root service when it is there and through sudo otherwise. The
/// service's shell gets the command as one script, with the input
/// encoded into it and a status line after it, and sends back everything
/// the command printed.
fn root_run(argv: &[String], input: &str) -> RootOutput {
    let command = argv
        .iter()
        .map(|arg| sh_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    if let Ok(mut socket) = UnixStream::connect(ROOT_SOCKET) {
        let encoded = base64_encode(input.as_bytes());
        let script = format!(
            "printf %s {encoded} | base64 -d | {command} 2>&1\nprintf '\\n{STATUS_MARKER}%s\\n' \"$?\"\nexit\n",
        );
        socket.write_all(script.as_bytes()).unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        let mut output = String::new();
        socket.read_to_string(&mut output).unwrap();
        let (printed, status) = output
            .rsplit_once(STATUS_MARKER)
            .unwrap_or_else(|| panic!("the root service sent no status for {argv:?}: {output}"));
        let status: i32 = status.trim().parse().unwrap_or(-1);
        return RootOutput {
            success: status == 0,
            status,
            output: printed.trim_end().to_owned(),
        };
    }
    let mut child = Command::new("sudo")
        .arg("-n")
        .arg("--")
        .args(argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    RootOutput {
        success: out.status.success(),
        status: out.status.code().unwrap_or(-1),
        output: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

/// Standard base64, for the input of a root command: only text that sh
/// takes as one word crosses the socket.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut word = 0u32;
        for (i, byte) in chunk.iter().enumerate() {
            word |= u32::from(*byte) << (16 - 8 * i);
        }
        for i in 0..4 {
            if i <= chunk.len() {
                let index = usize::try_from((word >> (18 - 6 * i)) & 0x3f).unwrap();
                out.push(char::from(ALPHABET[index]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Runs `argv` as root; whether it succeeded.
fn root_ok(argv: &[String]) -> bool {
    root_run(argv, "").success
}

fn root(argv: &[&str]) {
    assert!(root_ok(&strings(argv)), "as root, {argv:?} failed");
}

/// Runs `argv` as root with `input` on its standard input.
fn root_input(argv: &[&str], input: &str) {
    assert!(
        root_run(&strings(argv), input).success,
        "as root, {argv:?} failed"
    );
}

/// Writes `content` to `path` as root, with `mode`.
fn root_write(path: &str, content: &str, mode: &str) {
    root_input(&["tee", "--", path], content);
    root(&["chmod", mode, path]);
}

/// What must fail with no network rules at all, on CI's hosted runner:
/// Azure, whose metadata service the runner reaches, with a local
/// resolver on loopback. Its WireServer does not answer HTTP there even
/// for the runner, so those two probes have nothing to lose; its DNS
/// port answers every user.
const NO_RULES: &[&str] = &[
    "metadata",
    "container-metadata",
    "egress-direct",
    "egress-tcp",
    "egress-resolve",
    "egress-dns",
    "egress-wireserver-dns",
    "egress-proxy-metadata",
    "egress-container-direct",
    "egress-container-own-network",
    "local-tcp",
];

const NO_EGRESS_RULES: &[&str] = &[
    "egress-direct",
    "egress-tcp",
    "egress-resolve",
    "egress-dns",
    "egress-wireserver-dns",
    "egress-proxy-metadata",
    "egress-container-direct",
    "egress-container-own-network",
    "local-tcp",
];

const PROXY_UNRESTRICTED: &[&str] = &["egress-proxy-metadata"];

/// The expected failures of a network case: `default`, or the
/// comma-separated list in `AGENTIC_JOB_TEST_<NAME>` for a host whose
/// network differs (no local resolver, a tailnet with direct endpoints).
fn network_case(name: &str, default: &'static [&'static str]) -> Vec<&'static str> {
    match std::env::var(format!("AGENTIC_JOB_TEST_{name}")) {
        // Leaked: a handful of names, for the life of one test run.
        Ok(list) => list
            .split(',')
            .map(|id| &*Box::leak(id.to_owned().into_boxed_str()))
            .collect(),
        Err(_) => default.to_vec(),
    }
}

/// A protection that has been removed. Dropping it puts the host back.
struct Removed {
    restore: Vec<Vec<String>>,
    settle: Duration,
    held: Vec<Box<dyn Any>>,
}

impl Removed {
    /// `restore` is run as root on drop, after `held` is let go.
    fn new(restore: Vec<Vec<String>>, held: Vec<Box<dyn Any>>) -> Self {
        Self {
            restore,
            settle: Duration::ZERO,
            held,
        }
    }

    /// Removed by running `apply` as root, put back by `restore`.
    fn by(apply: &[&[&str]], restore: &[&[&str]]) -> Self {
        apply.iter().for_each(|argv| root(argv));
        Self::new(
            restore.iter().map(|argv| strings(argv)).collect(),
            Vec::new(),
        )
    }

    /// Waits now, and again once it is put back.
    fn settling(mut self, settle: Duration) -> Self {
        std::thread::sleep(settle);
        self.settle = settle;
        self
    }
}

impl Drop for Removed {
    fn drop(&mut self) {
        self.held.clear();
        for argv in &self.restore {
            if !root_ok(argv) {
                eprintln!("warning: could not put back: sudo {argv:?}");
            }
        }
        std::thread::sleep(self.settle);
    }
}

/// Whether the probes get a run token, and whose copy of it.
enum Token {
    None,
    /// The fixture's: the runner's file in its closed home.
    InPlace,
    /// The runner's copy somewhere else.
    RunnerFile(PathBuf),
}

struct Case {
    name: &'static str,
    /// The ids that must fail, and no others.
    expect: Vec<String>,
    token: Token,
    remove: Box<dyn FnOnce() -> Removed>,
}

impl Case {
    fn new(
        name: &'static str,
        expect: &[&str],
        remove: impl FnOnce() -> Removed + 'static,
    ) -> Self {
        Self {
            name,
            expect: strings(expect),
            token: Token::None,
            remove: Box::new(remove),
        }
    }

    fn with_token(self) -> Self {
        Self {
            token: Token::InPlace,
            ..self
        }
    }

    fn with_runner_file(self, path: &str) -> Self {
        Self {
            token: Token::RunnerFile(PathBuf::from(path)),
            ..self
        }
    }
}

/// The run token where `run` would put it: the runner's own file, and the
/// agent's configuration in the sandbox user's home.
struct TokenFixture {
    runner_file: PathBuf,
    agent_dir: PathBuf,
    agent_config: PathBuf,
}

impl TokenFixture {
    fn create(runner: &User, entry: &Entry) -> Self {
        let runner_file = runner.home.join(".agentic-job-test-token");
        std::fs::write(&runner_file, format!("{TOKEN}\n")).unwrap();
        std::fs::set_permissions(&runner_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let agent_dir = entry.home().join("agent-config");
        let agent_config = agent_dir.join("settings.json");
        // The modes are set outright, as `run` must: what a umask gives
        // is the host's business.
        let script = "mkdir -p \"$1\" && chmod 700 \"$1\" && cat > \"$2\" && chmod 600 \"$2\"";
        let written = entry
            .run(
                &[
                    "sh",
                    "-c",
                    script,
                    "sh",
                    &agent_dir.display().to_string(),
                    &agent_config.display().to_string(),
                ],
                format!("{{\"token\": \"{TOKEN}\"}}\n").as_bytes(),
            )
            .unwrap();
        assert!(
            written.success(),
            "{}",
            String::from_utf8_lossy(&written.stderr)
        );
        Self {
            runner_file,
            agent_dir,
            agent_config,
        }
    }

    fn token(&self) -> RunToken<'_> {
        RunToken {
            runner_file: &self.runner_file,
            agent_config: &self.agent_config,
        }
    }
}

/// Runs `script` (sh) as the sandbox user; it must succeed.
fn in_sandbox(entry: &Entry, script: &str) {
    let output = entry.run(&["sh", "-c", script], b"").unwrap();
    assert!(
        output.success(),
        "{script}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn cases(config: &Config, runner: &User, entry: &Entry, fixture: &TokenFixture) -> Vec<Case> {
    let user = config.sandbox.user.clone();
    let uid = entry.user().uid;
    let home = runner.home.display().to_string();
    let mut cases = Vec::new();

    {
        let user = user.clone();
        cases.push(Case::new(
            "a sudoers rule for the sandbox user",
            &["sudo"],
            move || {
                root_write(
                    SUDOERS_GRANT,
                    &format!("{user} ALL=(ALL:ALL) NOPASSWD: ALL\n"),
                    "0440",
                );
                Removed::by(&[], &[&["rm", "-f", SUDOERS_GRANT]])
            },
        ));
    }
    {
        // The deny rule is read last, so a grant read before it loses.
        let user = user.clone();
        cases.push(Case::new(
            "nothing: a sudoers rule that sorts before the deny rule",
            &[],
            move || {
                let grant = format!("{user} ALL=(ALL:ALL) NOPASSWD: ALL\n");
                root_write(SUDOERS_EARLY_GRANT, &grant, "0440");
                Removed::by(&[], &[&["rm", "-f", SUDOERS_EARLY_GRANT]])
            },
        ));
    }
    if config.sandbox.lock_runner {
        let runner_name = runner.name.clone();
        cases.push(Case::new(
            "a sudoers rule for the runner's user",
            &["runner-sudo", "runner-sudo-list", "runner-sudo-rules"],
            move || {
                root_write(
                    SUDOERS_RUNNER_GRANT,
                    &format!("{runner_name} ALL=(ALL:ALL) NOPASSWD: ALL\n"),
                    "0440",
                );
                Removed::by(&[], &[&["rm", "-f", SUDOERS_RUNNER_GRANT]])
            },
        ));
        // With the deny rule aside and a grant for the runner's user, it
        // gets pkexec and run0; the sandbox user, with no grant, only
        // what polkit opens to everyone.
        let runner_name = runner.name.clone();
        cases.push(Case::new(
            "the polkit deny rule, with a rule that grants the runner's user",
            &["linger", "runner-pkexec", "runner-run0"],
            move || {
                let grant = format!(
                    "polkit.addRule(function(action, subject) {{\n  if (subject.user == \"{runner_name}\") return polkit.Result.YES;\n}});\n"
                );
                root_write(POLKIT_RUNNER_GRANT, &grant, "0644");
                Removed::by(
                    &[&["mv", POLKIT_DENY, POLKIT_ASIDE]],
                    &[
                        &["rm", "-f", POLKIT_RUNNER_GRANT],
                        &["mv", POLKIT_ASIDE, POLKIT_DENY],
                    ],
                )
                .settling(POLKIT_SETTLE)
            },
        ));
    }
    {
        let user = user.clone();
        cases.push(Case::new(
            "a group that reads the host's logs",
            &["groups"],
            move || {
                Removed::by(
                    &[&["usermod", "-aG", FORBIDDEN_GROUP, &user]],
                    &[&["gpasswd", "-d", &user, FORBIDDEN_GROUP]],
                )
            },
        ));
    }
    // Enabling one's own lingering is open to every user by default, so
    // the deny rule alone is what stops it; pkexec needs a grant as well.
    cases.push(Case::new("the polkit deny rule", &["linger"], || {
        Removed::by(
            &[&["mv", POLKIT_DENY, POLKIT_ASIDE]],
            &[&["mv", POLKIT_ASIDE, POLKIT_DENY]],
        )
        .settling(POLKIT_SETTLE)
    }));
    {
        let user = user.clone();
        cases.push(Case::new(
            "the polkit deny rule, with a rule that grants",
            &["polkit", "linger"],
            move || {
                let grant = format!(
                    "polkit.addRule(function(action, subject) {{\n  if (subject.user == \"{user}\") return polkit.Result.YES;\n}});\n"
                );
                root_write(POLKIT_GRANT, &grant, "0644");
                Removed::by(
                    &[&["mv", POLKIT_DENY, POLKIT_ASIDE]],
                    &[&["rm", "-f", POLKIT_GRANT], &["mv", POLKIT_ASIDE, POLKIT_DENY]],
                )
                .settling(POLKIT_SETTLE)
            },
        ));
    }
    {
        let home = home.clone();
        cases.push(Case::new(
            "the runner's home open",
            &[&format!("private-dir:{home}")],
            move || Removed::by(&[&["chmod", "0755", &home]], &[&["chmod", "0700", &home]]),
        ));
    }
    {
        // Its names are hidden and every file in it can still be opened.
        let home = home.clone();
        cases.push(Case::new(
            "the runner's home searchable",
            &[&format!("private-dir:{home}")],
            move || Removed::by(&[&["chmod", "0711", &home]], &[&["chmod", "0700", &home]]),
        ));
    }
    {
        let work = format!("/var/tmp/agentic-job-test-work-{}", std::process::id());
        let expect = format!("private-dir:{work}");
        cases.push(Case::new(
            "the job's work directory outside the runner's home",
            &[&expect],
            move || Removed::new(Vec::new(), vec![Box::new(WorkDir::enter(&work))]),
        ));
    }
    {
        // The value of the variable that asks for the job's identity
        // token, in the environment of a process of the sandbox user's.
        let entry = entry.clone();
        let value = std::env::var(REQUEST_TOKEN_VAR)
            .expect("the identity-token request variables must be set for this test");
        cases.push(Case::new(
            "the identity-token request token in a sandbox process",
            &[&format!("oidc-value:{REQUEST_TOKEN_VAR}")],
            move || sandbox_process(&entry, uid, "export LEAK=\"$1\"; sleep 600; true", value),
        ));
    }
    {
        // What the system manager has in its environment, every service
        // it starts gets, the sandbox user's sessions among them.
        let user = user.clone();
        cases.push(Case::new(
            "a job variable in the system manager's environment",
            &["env-job-variables", "environ-job-variables"],
            move || {
                Removed::by(
                    &[&["systemctl", "set-environment", "ACTIONS_LEAK_TEST=1"]],
                    &[
                        &["systemctl", "unset-environment", "ACTIONS_LEAK_TEST"],
                        // Its user manager started with the variable.
                        &["loginctl", "terminate-user", &user],
                    ],
                )
            },
        ));
    }
    for (name, id, file) in [
        ("cron", "cron", "/etc/cron.deny"),
        ("at", "at", "/etc/at.deny"),
    ] {
        let user = user.clone();
        let entry = entry.clone();
        let view_masks_cron = config.sandbox.filesystem_view && id == "cron";
        cases.push(Case::new(
            name,
            scheduler_failures(id, view_masks_cron),
            move || {
                let delete = format!("/^{user}$/d");
                let append = format!("echo {user} >> {file}");
                let removed =
                    Removed::by(&[&["sed", "-i", &delete, file]], &[&["sh", "-c", &append]]);
                if view_masks_cron {
                    // With the deny entry gone, prove the first layer still holds,
                    // not merely that crontab failed for an unrelated reason.
                    let output = entry
                        .run(&["crontab", "-"], b"# view layer control\n")
                        .unwrap();
                    assert!(!output.success());
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    assert!(stderr.contains("Read-only file system"), "{stderr}");
                }
                removed
            },
        ));
    }
    // Switched off in its map, as it was before the loader enabled it;
    // its links stay attached.
    cases.push(Case::new(
        "the world-write policy",
        world_write_failures(config.sandbox.filesystem_view),
        || {
            assert!(root_ok(&world_write_update(&world_write_config(false))));
            Removed::new(
                vec![world_write_update(&world_write_config(true))],
                Vec::new(),
            )
        },
    ));
    if config.sandbox.filesystem_view {
        let uid = entry.user().uid;
        cases.push(Case::new(
            "the user manager's filesystem view",
            &["filesystem-view-manager", "filesystem-view-socket"],
            move || {
                let unit = format!("user@{uid}.service");
                let drop_in = format!("/etc/systemd/system/{unit}.d/agentic-job-view.conf");
                let aside = format!("{drop_in}.aside");
                Removed::by(
                    &[
                        &["mv", &drop_in, &aside],
                        &["systemctl", "daemon-reload"],
                        &["systemctl", "stop", &unit],
                    ],
                    &[
                        &["mv", &aside, &drop_in],
                        &["systemctl", "daemon-reload"],
                        &["systemctl", "stop", &unit],
                    ],
                )
            },
        ));
    }
    for (name, hidepid) in [("proc hidepid=0", "0"), ("proc hidepid=1", "1")] {
        cases.push(Case::new(name, &["proc-other-users"], move || {
            Removed::by(
                &[&[
                    "mount",
                    "-o",
                    &format!("remount,hidepid={hidepid},gid=0"),
                    "/proc",
                ]],
                &[&["mount", "-o", "remount,hidepid=invisible,gid=0", "/proc"]],
            )
        }));
    }
    cases.push(Case::new(
        "ptrace of any process of one's uid",
        &["ptrace-scope"],
        || {
            Removed::by(
                &[&["sysctl", "-q", "-w", "kernel.yama.ptrace_scope=0"]],
                &[&["sysctl", "-q", "-w", "kernel.yama.ptrace_scope=1"]],
            )
        },
    ));
    // The first stopped unit the host has, as before the lock. A unit
    // of a daemon that a group of the runner's user leads to (docker's
    // socket on the hosted image) is not alone: the runner's probe
    // connects to it, which starts the service and what that requires,
    // so the case expects those too and stops them all afterwards.
    let unit = config
        .sandbox
        .stop_services
        .iter()
        .find(|unit| root_ok(&strings(&["systemctl", "cat", "--", unit])))
        .expect("the configuration must stop a unit this host has, for the test to start again")
        .clone();
    let runner_groups: Vec<String> = Command::new("id")
        .args(["-Gn", "--", &runner.name])
        .output()
        .ok()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let group = setup::ROOT_GROUPS.iter().find(|group| {
        config.sandbox.lock_runner
            && group.units.contains(&unit.as_str())
            && runner_groups.iter().any(|name| name == group.name)
    });
    let woken: Vec<String> = group
        .map(|group| {
            group
                .units
                .iter()
                .filter(|other| {
                    **other != unit
                        && config.sandbox.stop_services.iter().any(|s| s == *other)
                        && root_ok(&strings(&["systemctl", "cat", "--", other]))
                })
                .map(|other| (*other).to_owned())
                .collect()
        })
        .unwrap_or_default();
    let mut expect = vec![format!("service:{unit}")];
    if let Some(group) = group {
        expect.push(format!("runner-group:{}", group.name));
        expect.extend(woken.iter().map(|other| format!("service:{other}")));
    }
    let expect: Vec<&str> = expect.iter().map(String::as_str).collect();
    cases.push(Case::new("a stopped service started", &expect, move || {
        // Setup masked them all, so the woken units too: what wakes them
        // is the runner's probe, not this.
        for u in std::iter::once(&unit).chain(&woken) {
            root(&["systemctl", "unmask", "--runtime", "--", u]);
        }
        root(&["systemctl", "start", &unit]);
        Removed::new(
            std::iter::once(&unit)
                .chain(&woken)
                .flat_map(|u| {
                    [
                        strings(&["systemctl", "stop", "--", u]),
                        strings(&["systemctl", "mask", "--runtime", "--", u]),
                    ]
                })
                .collect(),
            Vec::new(),
        )
    }));
    if config.sandbox.close_resolved && setup::resolved::startable().unwrap() {
        // The bus policy aside, and the Varlink socket open again: the
        // socket is one more that any user connects to.
        let aside = format!("{}.off", setup::resolved::BUS_POLICY);
        cases.push(Case::new(
            "systemd-resolved open to every user",
            &["resolved-bus", "resolved-varlink", "local-sockets"],
            move || {
                let reload: &[&str] = &[
                    "busctl",
                    "call",
                    "org.freedesktop.DBus",
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus",
                    "ReloadConfig",
                ];
                let socket = setup::resolved::VARLINK_SOCKET;
                let policy = setup::resolved::BUS_POLICY;
                Removed::by(
                    &[
                        &["mv", "--", policy, &aside],
                        reload,
                        &["chmod", "o+rw", "--", socket],
                    ],
                    &[
                        &["mv", "--", &aside, policy],
                        reload,
                        &["chmod", "o-rwx", "--", socket],
                    ],
                )
            },
        ));
        // Closed where it is not running yet, which the bus and its
        // sockets would start; the runner's control starts it again.
        let unit = setup::resolved::UNIT;
        cases.push(Case::new("systemd-resolved stopped", &[], move || {
            Removed::by(
                &[&["systemctl", "stop", "--", unit]],
                &[&["systemctl", "start", "--", unit]],
            )
        }));
        // Its sockets made again, as a restart after setup (a package's)
        // makes them: the drop-ins keep them closed.
        let triggers = Command::new("systemctl")
            .args(["show", "--property=TriggeredBy", "--value", "--", unit])
            .output()
            .unwrap();
        let mut units: Vec<String> = String::from_utf8_lossy(&triggers.stdout)
            .split_whitespace()
            .filter(|u| u.ends_with(".socket"))
            .map(str::to_owned)
            .collect();
        units.push(unit.to_owned());
        cases.push(Case::new(
            "systemd-resolved and its sockets restarted",
            &[],
            move || {
                let units: Vec<&str> = units.iter().map(String::as_str).collect();
                let stop = [&["systemctl", "stop", "--"][..], &units].concat();
                let start = [&["systemctl", "start", "--"][..], &units].concat();
                Removed::by(&[&stop, &start], &[&start])
            },
        ));
    }
    cases.push(Case::new(
        "listeners any user can connect to",
        &["local-sockets", "local-tcp"],
        || {
            let name = format!("agentic-job-test-listener-{}", std::process::id());
            let unix =
                UnixListener::bind_addr(&UnixAddr::from_abstract_name(name).unwrap()).unwrap();
            let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            Removed::new(Vec::new(), vec![Box::new(unix), Box::new(tcp)])
        },
    ));
    if Path::new(HCA_DIR).is_dir() {
        cases.push(Case::new(
            "the hosted compute agent's directory open",
            &[&format!("private-dir:{HCA_DIR}")],
            || {
                Removed::by(
                    &[&["chmod", "0755", HCA_DIR]],
                    &[&["chmod", "0700", HCA_DIR]],
                )
            },
        ));
    }
    if root_ok(&strings(&["test", "-S", TAILSCALE_SOCKET])) {
        cases.push(Case::new(
            "tailscaled's socket directory open",
            &[
                &format!("private-dir:{TAILSCALE_DIR}"),
                "local-sockets",
                "tailscale-status",
                "tailscale-localapi",
                // Dialing through tailscaled is only tried for a host
                // with direct endpoints.
                if config.egress.direct.is_empty() {
                    "tailscale-status"
                } else {
                    "tailnet-nc"
                },
            ],
            || {
                Removed::by(
                    &[&["chmod", "0755", TAILSCALE_DIR]],
                    &[&["chmod", "0700", TAILSCALE_DIR]],
                )
            },
        ));
    }

    // The network rules. Each case loads other rules in their place and
    // puts back the ones setup left.
    let rules_back: &[&[&str]] = &[&["nft", "-f", network::RULES_FILE]];
    let uids: Vec<String> = std::iter::once(uid.to_string())
        .chain(
            setup::subuid_ranges(
                entry.user(),
                &std::fs::read_to_string("/etc/subuid").unwrap(),
            )
            .unwrap(),
        )
        .collect();
    if config.egress.proxy {
        let direct = network::direct(&config.egress).unwrap();
        let proxy_uid = User::lookup(egress::EGRESS_USER).unwrap().unwrap().uid;
        cases.push(Case::new(
            "the network rules",
            &network_case("NO_RULES", NO_RULES),
            move || {
                Removed::by(
                    &[&["nft", "delete", "table", "inet", network::TABLE]],
                    rules_back,
                )
            },
        ));
        {
            // The rules of a host without the proxy: the metadata service
            // stays closed and every way around the proxy opens.
            let (uids, direct) = (uids.clone(), direct.clone());
            cases.push(Case::new(
                "the rules that send everything through the proxy",
                &network_case("NO_EGRESS_RULES", NO_EGRESS_RULES),
                move || {
                    root_input(&["nft", "-f", "-"], &network::rules(&uids, &direct, None));
                    Removed::by(&[], rules_back)
                },
            ));
        }
        {
            // Rules that name another uid as the proxy's: the proxy
            // itself is then free to go where the sandbox may not.
            cases.push(Case::new(
                "the rules on the proxy's own user",
                &network_case("PROXY_UNRESTRICTED", PROXY_UNRESTRICTED),
                move || {
                    let other = Some(proxy_uid + 1);
                    root_input(&["nft", "-f", "-"], &network::rules(&uids, &direct, other));
                    Removed::by(&[], rules_back)
                },
            ));
        }
    }

    // The run token.
    let dir = fixture.agent_dir.display().to_string();
    let file = fixture.agent_config.display().to_string();
    cases.push(
        Case::new("the run token in place", &[], || {
            Removed::new(Vec::new(), Vec::new())
        })
        .with_token(),
    );
    {
        let (entry, file) = (entry.clone(), file.clone());
        cases.push(
            Case::new(
                "the agent's configuration readable by all",
                &["token-config-mode"],
                move || {
                    in_sandbox(&entry, &format!("chmod 644 {file}"));
                    Removed::by(&[], &[&["chmod", "600", &file]])
                },
            )
            .with_token(),
        );
    }
    {
        // Now a subordinate uid, any container's user, reads the token.
        let (entry, dir, file) = (entry.clone(), dir.clone(), file.clone());
        cases.push(
            Case::new(
                "the agent's configuration and its directory readable by all",
                &[
                    "token-config-mode",
                    "token-config-dir-mode",
                    "token-container-subuid",
                ],
                move || {
                    in_sandbox(&entry, &format!("chmod 755 {dir} && chmod 644 {file}"));
                    Removed::by(&[], &[&["chmod", "700", &dir], &["chmod", "600", &file]])
                },
            )
            .with_token(),
        );
    }
    {
        let entry = entry.clone();
        let copy = format!("/tmp/agentic-job-test-token-copy-{uid}");
        let source = file.clone();
        cases.push(
            Case::new("a copy of the token in /tmp", &["token-files"], move || {
                in_sandbox(&entry, &format!("cp {source} {copy}"));
                Removed::by(&[], &[&["rm", "-f", &copy]])
            })
            .with_token(),
        );
    }
    {
        // A process of the sandbox user's with the token as an argument,
        // alive while the probes run.
        let entry = entry.clone();
        cases.push(
            Case::new(
                "the token on a command line",
                &["token-processes"],
                move || sandbox_process(&entry, uid, "sleep 600; true", TOKEN.to_owned()),
            )
            .with_token(),
        );
    }
    cases.push(
        Case::new(
            "the runner's copy of the token where anyone reads it",
            &["token-runner-file"],
            || {
                root_write(READABLE_TOKEN, &format!("{TOKEN}\n"), "0644");
                Removed::by(&[], &[&["rm", "-f", READABLE_TOKEN]])
            },
        )
        .with_runner_file(READABLE_TOKEN),
    );
    cases
}

fn failed(config: &Config, token: Option<RunToken<'_>>) -> BTreeSet<String> {
    let report = check::probes(config, token).expect("the probes could not run");
    for id in [
        "runner-world-write-control",
        "runner-world-write",
        "world-write-control",
        "world-write",
    ] {
        assert!(
            report.outcomes().iter().any(|outcome| outcome.id == id),
            "the world-write policy's probe did not run: {id}"
        );
    }
    for id in ["filesystem-view", "filesystem-view-manager"] {
        assert_eq!(
            report.outcomes().iter().any(|outcome| outcome.id == id),
            config.sandbox.filesystem_view,
            "unexpected view probe selection: {id}"
        );
    }
    report.failures().into_iter().map(str::to_owned).collect()
}

/// Use the actual session wrapper, not just a separate run0 command. The
/// scripted agent's tool process must inherit the same view as the agent.
fn session_view(config: &Config, entry: &Entry) {
    use agentic_job::session::{self, Clients, Launch, Limits, Options, Policy};

    let sandbox = agentic_job::run::enter::Sandbox::new(config).unwrap();
    let work = entry.home().join("view-session");
    assert!(
        entry
            .succeeds(&["mkdir", "-p", &work.display().to_string()])
            .unwrap()
    );
    let fake = "/tmp/agentic-job-view-fake-agent";
    root(&[
        "install",
        "-m",
        "0755",
        env!("CARGO_BIN_EXE_fake-agent"),
        fake,
    ]);
    let script = work.join("script.json").display().to_string();
    let command = format!(
        "echo home-control > control; if touch {}/session; then echo escaped > verdict; else echo held > verdict; fi",
        setup::VIEW_PROBE_DIR
    );
    root_write(
        &script,
        &serde_json::json!([{"execute": {"title": "Bash", "command": command}}]).to_string(),
        "0644",
    );
    let _cleanup = Removed::by(
        &[],
        &[
            &["rm", "-rf", &work.display().to_string(), fake],
            &["rm", "-f", &format!("{}/session", setup::VIEW_PROBE_DIR)],
        ],
    );
    let out = tempfile::tempdir().unwrap();
    let registry = format!(
        "[fake]\ncommand = {}\n",
        serde_json::json!([fake, "script", script])
    );
    let options = Options {
        name: "fake".into(),
        agent: session::agents::parse(&registry, "fake").unwrap(),
        model: None,
        config_options: Vec::new(),
        cwd: work.clone(),
        prompt: "Probe the filesystem view".into(),
        out: out.path().join("out"),
        permissions: Policy::allow_all(),
        limits: Limits {
            timeout_s: 60,
            ..Limits::default()
        },
        requests: None,
        launch: Launch::Sandbox {
            user: sandbox.user.clone(),
            wrapper: sandbox.wrapper(&work).unwrap(),
        },
        clients: Clients::none(),
        bridge: None,
        log: Box::new(std::io::sink()),
        output: None,
        restate: None,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let returned = runtime.block_on(session::run(options)).unwrap();
    assert_eq!(returned.result.exit().code(), 0);
    let result = entry
        .run(
            &[
                "cat",
                &work.join("verdict").display().to_string(),
                &work.join("control").display().to_string(),
            ],
            b"",
        )
        .unwrap();
    assert!(result.success());
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        "held\nhome-control\n"
    );
}

#[test]
#[ignore = "changes the host as root; CI's sandbox job runs it after `sandbox setup`"]
fn each_probe_fails_when_its_protection_is_removed() {
    let config =
        Config::load(Path::new(config::ROOT_COPY)).expect("`sandbox setup` has not run here");
    let runner = User::current().unwrap();
    let entry = Entry::new(&config).unwrap();
    let none = BTreeSet::new();

    assert_eq!(failed(&config, None), none, "before anything is removed");
    if config.sandbox.filesystem_view {
        for path in [
            entry.home().join("exec-view-control"),
            PathBuf::from(format!("{}/exec-view", setup::VIEW_PROBE_DIR)),
        ] {
            let output = Command::new(BIN)
                .args([
                    "sandbox",
                    "exec",
                    "--",
                    "sh",
                    "-c",
                    "f=$1; : > \"$f\" && rm -f -- \"$f\"",
                    "sh",
                    &path.display().to_string(),
                ])
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                path.starts_with(entry.home()),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        session_view(&config, &entry);
    }
    // Kill only a sacrificial run0 PAM handler, never the manager's. Killing
    // it need not terminate its parent on systemd 257; no surviving command
    // may acquire the handler's unrestricted mount view.
    if config.sandbox.filesystem_view {
        let killed = entry.run(&["python3", "-I", "-c", r#"
import os, pathlib, subprocess, time
# The handler is this command's child, which hidepid hides from /proc even
# as a zombie: found as a child and waited for instead.
helpers = [int(child) for task in pathlib.Path('/proc/self/task').iterdir() for child in (task / 'children').read_text().split()]
assert len(helpers) == 1, helpers
subprocess.run(['kill', '-TERM', str(helpers[0])], check=True)
for _ in range(50):
    if os.waitpid(helpers[0], os.WNOHANG)[0]:
        break
    time.sleep(0.1)
else:
    raise AssertionError('PAM handler survived SIGTERM')
try:
    fd = os.open('/etc/agentic-job/write-probe/after-pam-kill', os.O_WRONLY | os.O_CREAT, 0o600)
except PermissionError:
    pass
except OSError as error:
    import errno
    assert error.errno == errno.EROFS, error
else:
    os.close(fd)
    raise AssertionError('PAM handler death opened host filesystem')
"#], b"").unwrap();
        assert!(
            killed.success(),
            "{}",
            String::from_utf8_lossy(&killed.stderr)
        );
    }

    // A machine is set up once: a second job must not inherit the first's
    // sandbox user.
    let again = root_run(
        &strings(&[BIN, "sandbox", "setup", "--config", config::ROOT_COPY]),
        "",
    );
    assert_eq!(again.status, 2, "{}", again.output);
    assert!(
        again.output.contains("ran on this machine before"),
        "{}",
        again.output
    );

    let fixture = TokenFixture::create(&runner, &entry);
    let (index, count) = shard();
    let mine = cases(&config, &runner, &entry, &fixture)
        .into_iter()
        // The baseline proves the layers masked by the view, without repeating
        // all four shards on a fifth host. at -l and private-dir probes are
        // reads/traversals, so read-only mounts do not mask their removal.
        .filter(|case| removal_case_enabled(case.name, config.sandbox.filesystem_view))
        .skip(index)
        .step_by(count);
    let mut wrong = Vec::new();
    for case in mine {
        println!("\n=== removed: {} ===", case.name);
        let token = match &case.token {
            Token::None => None,
            Token::InPlace => Some(fixture.token()),
            Token::RunnerFile(path) => Some(RunToken {
                runner_file: path,
                agent_config: &fixture.agent_config,
            }),
        };
        let removed = (case.remove)();
        let got = failed(&config, token);
        drop(removed);
        let want: BTreeSet<String> = case.expect.into_iter().collect();
        if got != want {
            wrong.push(format!("{}: failed {got:?}, expected {want:?}", case.name));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));

    println!("\n=== everything put back ===");
    assert_eq!(
        failed(&config, Some(fixture.token())),
        none,
        "after everything was put back"
    );
}
