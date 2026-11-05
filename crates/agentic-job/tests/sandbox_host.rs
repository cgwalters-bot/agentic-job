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
//! The probes are the runner's user's, the only agent user since the
//! sandbox user was removed (agentic-job#2989).

// Helpers outside a #[test] function are still test code.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use agentic_job::config::{self, Config};
use agentic_job::sandbox::check;
use agentic_job::sandbox::host::User;
use agentic_job::sandbox::{network, setup};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

/// Where CI's root service listens: a shell that runs what it is sent,
/// as root, for this test alone (see the top of the file).
const ROOT_SOCKET: &str = "/run/agentic-job-test-root.sock";

/// What the shell prints after each command, with its status.
const STATUS_MARKER: &str = "__agentic_job_test_status=";

/// Sorts after the deny rules: a grant for the runner's user there wins.
const SUDOERS_RUNNER_GRANT: &str = "/etc/sudoers.d/zzz-test-runner-grant";

/// Sorts before the deny rule, which polkit would otherwise take first.
const POLKIT_RUNNER_GRANT: &str = "/etc/polkit-1/rules.d/00-aaa-test-runner-grant.rules";

/// How long polkit takes to see a rule file change.
const POLKIT_SETTLE: Duration = Duration::from_secs(3);

const POLKIT_DENY: &str = "/etc/polkit-1/rules.d/00-agentic-job-sandbox.rules";

/// Outside the rules directory, so that polkit does not read it.
const POLKIT_ASIDE: &str = "/etc/polkit-1/agentic-job-sandbox.rules.aside";

/// The policy's map value, as `secure-host world-write` writes it: the
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

/// Writes `content` to `path` as root, with `mode`.
fn root_write(path: &str, content: &str, mode: &str) {
    assert!(
        root_run(&strings(&["tee", "--", path]), content).success,
        "as root, writing {path} failed"
    );
    root(&["chmod", mode, path]);
}

/// The expected failures of the network case: `default`, or the
/// comma-separated list in `AGENTIC_JOB_TEST_<NAME>` for a host whose
/// network differs (one where the runner reaches the metadata service at
/// its IPv6 address too, say).
fn network_case(name: &str, default: &[&str]) -> Vec<String> {
    match std::env::var(format!("AGENTIC_JOB_TEST_{name}")) {
        Ok(list) => list.split(',').map(str::to_owned).collect(),
        Err(_) => strings(default),
    }
}

/// A protection that has been removed. Dropping it puts the host back.
struct Removed {
    restore: Vec<Vec<String>>,
    settle: Duration,
}

impl Removed {
    /// Removed by running `apply` as root, put back by `restore`.
    fn by(apply: &[&[&str]], restore: &[&[&str]]) -> Self {
        apply.iter().for_each(|argv| root(argv));
        Self {
            restore: restore.iter().map(|argv| strings(argv)).collect(),
            settle: Duration::ZERO,
        }
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
        for argv in &self.restore {
            if !root_ok(argv) {
                eprintln!("warning: could not put back: sudo {argv:?}");
            }
        }
        std::thread::sleep(self.settle);
    }
}

struct Case {
    name: &'static str,
    /// The ids that must fail, and no others.
    expect: Vec<String>,
    remove: Box<dyn FnOnce() -> Removed>,
}

impl Case {
    fn new(
        name: &'static str,
        expect: Vec<String>,
        remove: impl FnOnce() -> Removed + 'static,
    ) -> Self {
        Self {
            name,
            expect,
            remove: Box::new(remove),
        }
    }
}

fn cases(config: &Config, runner: &User) -> Vec<Case> {
    let mut cases = Vec::new();
    if config.sandbox.lock_runner {
        let runner_name = runner.name.clone();
        cases.push(Case::new(
            "a sudoers rule for the runner's user",
            strings(&["runner-sudo", "runner-sudo-list", "runner-sudo-rules"]),
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
        // gets pkexec and run0.
        let runner_name = runner.name.clone();
        cases.push(Case::new(
            "the polkit deny rule, with a rule that grants the runner's user",
            strings(&["runner-pkexec", "runner-run0"]),
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
    // Switched off in its map, as it was before the loader enabled it;
    // its links stay attached.
    cases.push(Case::new(
        "the world-write policy",
        strings(&["runner-world-write"]),
        || {
            assert!(root_ok(&world_write_update(&world_write_config(false))));
            Removed {
                restore: vec![world_write_update(&world_write_config(true))],
                settle: Duration::ZERO,
            }
        },
    ));
    cases.push(Case::new(
        "ptrace of any process of one's uid",
        strings(&["ptrace-scope"]),
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
    cases.push(Case::new("a stopped service started", expect, move || {
        // Setup masked them all, so the woken units too: what wakes them
        // is the runner's probe, not this.
        for u in std::iter::once(&unit).chain(&woken) {
            root(&["systemctl", "unmask", "--runtime", "--", u]);
        }
        root(&["systemctl", "start", &unit]);
        Removed {
            restore: std::iter::once(&unit)
                .chain(&woken)
                .flat_map(|u| {
                    [
                        strings(&["systemctl", "stop", "--", u]),
                        strings(&["systemctl", "mask", "--runtime", "--", u]),
                    ]
                })
                .collect(),
            settle: Duration::ZERO,
        }
    }));
    // sandbox.deny-runner-metadata's rule is in the table setup loaded:
    // without it the runner reaches the metadata service again (IPv4
    // only on CI's hosted runner).
    if config.sandbox.deny_runner_metadata() {
        cases.push(Case::new(
            "the network rules",
            network_case("NO_RULES", &["runner-metadata"]),
            || {
                Removed::by(
                    &[&["nft", "delete", "table", "inet", network::TABLE]],
                    &[&["nft", "-f", network::RULES_FILE]],
                )
            },
        ));
    }
    cases
}

/// The ids of `sandbox check`'s probes that failed.
fn failed(config: &Config) -> BTreeSet<String> {
    let report = check::probes(config).expect("the probes could not run");
    for id in ["runner-world-write-control", "runner-world-write"] {
        assert!(
            report.outcomes().iter().any(|outcome| outcome.id == id),
            "the world-write policy's probe did not run: {id}"
        );
    }
    report.failures().into_iter().map(str::to_owned).collect()
}

#[test]
#[ignore = "changes the host as root; CI's sandbox job runs it after `sandbox setup`"]
fn each_probe_fails_when_its_protection_is_removed() {
    let config =
        Config::load(Path::new(config::ROOT_COPY)).expect("`sandbox setup` has not run here");
    let runner = User::current().unwrap();
    let none = BTreeSet::new();

    assert_eq!(failed(&config), none, "before anything is removed");
    // No second user, under the name the removed one had.
    assert!(
        User::lookup(config::Sandbox::REMOVED_USER)
            .unwrap()
            .is_none(),
        "setup made a second user"
    );

    // A machine is set up once.
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

    let mut wrong = Vec::new();
    for case in cases(&config, &runner) {
        println!("\n=== removed: {} ===", case.name);
        let removed = (case.remove)();
        let got = failed(&config);
        drop(removed);
        let want: BTreeSet<String> = case.expect.into_iter().collect();
        if got != want {
            wrong.push(format!("{}: failed {got:?}, expected {want:?}", case.name));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));

    println!("\n=== everything put back ===");
    assert_eq!(failed(&config), none, "after everything was put back");
}
