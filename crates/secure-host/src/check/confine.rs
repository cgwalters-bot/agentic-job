//! `secure-host probe` (`agentic-job sandbox probe`): what a step of a job secured by
//! secure-host tries, as the runner's own user: the routes to root (sudo,
//! the container daemon, a root-owned world-writable file), to the cloud
//! metadata service, to the environment of a process an earlier step left
//! running, and to Runner.Worker's .NET diagnostic sockets
//! (`sandbox.unlink-worker-diagnostics`), through which a step could have
//! the Worker dump its memory. CI's `confined` job runs it once before
//! secure-host as the positive control, where each must work, and after it
//! from a `run:` step and from .github/actions/confine-probe, a JavaScript
//! action whose main and post steps run it as their child, where each must
//! fail (cgwalters-forge/actions's secure-host/docs/evidence.md). Its
//! `sandbox-user` and `no-user` modes probe, after the lock, the sandbox
//! user setup makes by default, and a host that opted out of it
//! (`sandbox.create-user = false`).
//!
//! It writes what it found to `$RUNNER_TEMP/confine/LABEL.json` for the
//! job's artifact, and to its log: booleans and group names, never a
//! variable's value. The post step's record is only in its log: the
//! upload is a main step, so it runs before any post step. Where they are
//! the same, the probes are `sandbox check`'s.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use rustix::io::Errno;
use rustix::process::{Pid, test_kill_process};
use serde_json::json;

use super::{metadata_request, runner_reaches, runner_stdout, sudo_rules};
use crate::config::{HostFile, ROOT_COPY};
use crate::enter::Entry;
use crate::helper::SELF_COPY;
use crate::host::{self, User};
use crate::root::Root;
use crate::setup::runner_sudo_rules;
use crate::worker_diagnostics::{WORKER_COMM, listed_sockets};

/// Root's, mode 0666, made before the control in a shared temporary
/// directory on the root filesystem, which setup's walk and the check's
/// search leave alone: only the access-time policy refuses a write to it.
const FIXTURE: &str = "/var/tmp/agentic-job-confine-root-file";

/// The pid of `sleep`, which a step before the control started and left
/// running, so that every probe is a later step than it. Its environment
/// is the earlier step's; only whether it can be read is recorded.
const ORPHAN: &str = "confine-orphan.pid";

/// The pid of the Worker, which the control finds among its ancestors and
/// records here: after the lock, the runner-read rule and hidepid take
/// every ancestor out of a step's /proc.
const WORKER: &str = "confine-worker.pid";

/// Under `$RUNNER_TEMP`: the records, which the job uploads.
const RECORDS: &str = "confine";

/// This process is the Worker's grandchild, a child of a `run:` step's
/// shell or of an action's node; far more than that, and then no Worker.
const MAX_ANCESTORS: usize = 32;

/// What the runner hands a step, which no lock takes away: recorded as
/// whether each is set.
const TOKENS: &[&str] = &["ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"];

#[derive(Debug, clap::Args)]
pub struct Args {
    mode: Mode,
    /// The record's name: lowercase letters, digits and dashes
    label: String,
    /// The host configuration for the user modes; normally setup's root-owned copy
    #[arg(long, hide = true, default_value = ROOT_COPY)]
    config: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    /// Before the lock: the job's user has each route.
    Control,
    /// After it: none, and its own world-writable file still takes a
    /// write, so the refusal of the root-owned one is the policy's, not
    /// every write's.
    Confined,
    /// After it, the sandbox user setup made by default, entered the one
    /// way there is (`helper enter`, whose success is the control): no
    /// sudo, no metadata service.
    SandboxUser,
    /// After it with `sandbox.create-user = false`: no such user, and the
    /// runner's sudo is the helper's rule and nothing else.
    NoUser,
}

impl Mode {
    /// The probes of this mode, in the order they are logged.
    fn names(self) -> &'static [&'static str] {
        match self {
            Self::Control => &[
                "sudo",
                "docker",
                "world-write",
                "metadata",
                "environ",
                "worker-diagnostics",
            ],
            Self::Confined => &[
                "sudo",
                "docker",
                "world-write",
                "metadata",
                "environ",
                "worker-diagnostics",
                "owner-write",
            ],
            Self::SandboxUser => &["user", "user-enter", "user-sudo", "user-metadata"],
            Self::NoUser => &["user", "sudo", "sudo-true-listed", "sudo-rules", "helper"],
        }
    }

    /// Whether the probe `name` must succeed: everything in the control,
    /// and only these otherwise.
    fn wanted(self, name: &str) -> bool {
        match self {
            Self::Control => true,
            Self::Confined => name == "owner-write",
            Self::SandboxUser => ["user", "user-enter"].contains(&name),
            Self::NoUser => ["sudo-rules", "helper"].contains(&name),
        }
    }
}

type Results = BTreeMap<&'static str, bool>;

/// The probes of `mode` whose result is not what it must be, as messages.
fn failures(mode: Mode, results: &Results) -> Vec<String> {
    let verb = |must: bool| if must { "succeed" } else { "fail" };
    mode.names()
        .iter()
        .filter(|name| results.get(*name) != Some(&mode.wanted(name)))
        .map(|name| {
            let got = match results.get(name) {
                None => "not probed",
                Some(true) => "succeeded",
                Some(false) => "failed",
            };
            format!("{name}: {got}, must {}", verb(mode.wanted(name)))
        })
        .collect()
}

/// Whether sudo's `rules` end with the lock's deny rule and the helper's
/// grant, which win over any before them: `sandbox check`'s
/// `runner-sudo-rules`.
fn locked(rules: &[String]) -> bool {
    rules.ends_with(&runner_sudo_rules())
}

/// Whether `label` can name a record: lowercase letters, digits and dashes.
fn valid_label(label: &str) -> bool {
    let allowed = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
    !label.is_empty() && label.bytes().all(allowed)
}

/// Why the fixture, if `found` as (regular file, owner, mode), would make
/// its refusal prove nothing, or None.
fn fixture_problem(found: Option<(bool, u32, u32)>) -> Option<String> {
    let Some((regular, uid, mode)) = found else {
        return Some("missing".to_owned());
    };
    let mode = mode & 0o7777;
    if !regular {
        Some("not a regular file".to_owned())
    } else if uid != 0 {
        Some(format!("owned by uid {uid}, not root"))
    } else if mode != 0o666 {
        Some(format!("mode {mode:o}, not 666"))
    } else {
        None
    }
}

/// Why a refused read of the orphan's environment, or connection to the
/// Worker, would prove nothing, or None, by the error of `kill(pid, 0)`
/// (None when it succeeded): it must be running and this user's. A signal
/// needs no ptrace access, so this holds where setup's hidepid and the
/// runner-read rule hide it from /proc.
fn orphan_problem(error: Option<Errno>) -> Option<String> {
    match error? {
        Errno::SRCH => Some("not running".to_owned()),
        Errno::PERM => Some("not this user's".to_owned()),
        other => Some(format!("kill(0) failed with {other}")),
    }
}

/// The name and parent's pid in a `/proc/PID/stat` line. The name is
/// between the first `(` and the last `)`, and may hold either.
fn parse_stat(stat: &str) -> Option<(&str, u32)> {
    let (open, close) = (stat.find('(')?, stat.rfind(')')?);
    let comm = stat.get(open + 1..close)?;
    let ppid = stat.get(close + 1..)?.split_whitespace().nth(1)?;
    Some((comm, ppid.parse().ok()?))
}

/// The Worker that runs this step: the nearest ancestor of that name.
fn ancestor_worker() -> Result<u32> {
    let mut pid = std::process::id();
    for _ in 0..MAX_ANCESTORS {
        if pid <= 1 {
            break;
        }
        let path = format!("/proc/{pid}/stat");
        let stat = fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
        let (comm, ppid) = parse_stat(&stat).context("no name or parent")?;
        if comm == WORKER_COMM {
            return Ok(pid);
        }
        pid = ppid;
    }
    bail!("no {WORKER_COMM} among this step's ancestors")
}

/// The pid recorded in `name` under `temp`, refused unless that process
/// is running and this user's.
fn recorded_pid(temp: &Path, name: &str) -> Result<u32> {
    let path = temp.join(name);
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let pid: u32 = match text.trim().parse() {
        Ok(pid) => pid,
        Err(_) => bail!("{name}: not a pid"),
    };
    let Some(process) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
        bail!("{name}: not a pid");
    };
    if let Some(problem) = orphan_problem(test_kill_process(process).err()) {
        bail!("process {pid} of {name}: {problem}, so probing it proves nothing");
    }
    Ok(pid)
}

/// Whether this user reads the orphan's environment; the orphan must be
/// running before and after. With hidepid=invisible a process the rule
/// refuses is not in /proc at all for this one: not found, while the
/// signal says it is running.
fn reads_orphan(temp: &Path) -> Result<bool> {
    let pid = recorded_pid(temp, ORPHAN)?;
    let refused = [ErrorKind::PermissionDenied, ErrorKind::NotFound];
    let read = match fs::read(format!("/proc/{pid}/environ")) {
        Ok(_) => true,
        Err(err) if refused.contains(&err.kind()) => false,
        Err(err) => return Err(err).context("reading the orphan's environment"),
    };
    recorded_pid(temp, ORPHAN)?;
    Ok(read)
}

/// Whether this process opens `path` for writing.
fn opens_for_write(path: &Path) -> Result<bool> {
    let what = || format!("opening {}", path.display());
    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == ErrorKind::PermissionDenied => Ok(false),
        Err(err) => Err(err).with_context(what),
    }
}

/// The root-owned fixture, refused unless it is as the job made it.
fn fixture() -> Result<&'static Path> {
    let path = Path::new(FIXTURE);
    let found = match fs::symlink_metadata(path) {
        Ok(meta) => Some((meta.file_type().is_file(), meta.uid(), meta.mode())),
        Err(err) if err.kind() == ErrorKind::NotFound => None,
        Err(err) => return Err(err).context(FIXTURE),
    };
    if let Some(problem) = fixture_problem(found) {
        bail!("{FIXTURE}: {problem}, so writing it proves nothing");
    }
    Ok(path)
}

/// This user's own world-writable file, the control of the fixture's.
fn owner_file(temp: &Path, label: &str) -> Result<PathBuf> {
    let path = temp.join(format!("confine-owner-{label}"));
    fs::write(&path, "").with_context(|| format!("writing {}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
        .with_context(|| format!("making {} world-writable", path.display()))?;
    Ok(path)
}

/// Whether this step connects to any diagnostic socket of its Worker,
/// found and recorded by the control, read back once confined. The
/// listing keeps a path after it is unlinked, so the control proves the
/// Worker had one to find.
fn reaches_worker(mode: Mode, temp: &Path) -> Result<bool> {
    let pid = if mode == Mode::Control {
        let pid = ancestor_worker()?;
        let path = temp.join(WORKER);
        fs::write(&path, format!("{pid}\n"))
            .with_context(|| format!("writing {}", path.display()))?;
        pid
    } else {
        recorded_pid(temp, WORKER)?
    };
    let sockets = listed_sockets(&[pid])?;
    Ok(sockets.iter().any(|s| UnixStream::connect(s).is_ok()))
}

/// What the sandbox user does, or that there is none, as the runner's user.
fn user_results<F: HostFile>(mode: Mode, path: &Path) -> Result<Results> {
    let config = F::load(path)?;
    let user = User::lookup(&config.sandbox().user)?;
    let mut results = Results::from([("user", user.is_some())]);
    if mode == Mode::NoUser {
        let truth = host::find_program("true").context("no true on this host")?;
        let truth = truth.to_string_lossy();
        let listing = runner_stdout(&["sudo", "-n", "-l"]);
        results.extend([
            ("sudo", runner_reaches(&["sudo", "-n", "true"])),
            // sudo's own answer for an ordinary command, which the lock refuses.
            (
                "sudo-true-listed",
                runner_reaches(&["sudo", "-n", "-l", &truth]),
            ),
            ("sudo-rules", locked(&sudo_rules(&listing))),
            ("helper", Root::Helper.ping()),
        ]);
    } else if user.is_some() {
        ensure!(
            Path::new(SELF_COPY).is_file(),
            "{SELF_COPY} is missing: the sandbox user is entered through the helper"
        );
        let entry = Entry::new(&config)?;
        results.extend([
            ("user-enter", entry.succeeds(&["true"])?),
            ("user-sudo", entry.succeeds(&["sudo", "-n", "true"])?),
            // Around the egress proxy its environment names, whose refusal
            // would otherwise stand in for the rule on its uid.
            ("user-metadata", entry.succeeds(&metadata_request())?),
        ]);
    }
    Ok(results)
}

/// The routes of the runner's user, before or after the lock.
fn runner_results(mode: Mode, temp: &Path, label: &str) -> Result<Results> {
    // Refuse invalid controls before starting commands or contacting services.
    let environ = reads_orphan(temp)?;
    let fixture = fixture()?;
    let mut results = Results::from([
        ("sudo", runner_reaches(&["sudo", "-n", "true"])),
        ("docker", runner_reaches(&["docker", "info"])),
        ("world-write", opens_for_write(fixture)?),
        ("metadata", runner_reaches(&metadata_request())),
        ("environ", environ),
        ("worker-diagnostics", reaches_worker(mode, temp)?),
    ]);
    if mode == Mode::Confined {
        let own = owner_file(temp, label)?;
        results.insert("owner-write", opens_for_write(&own)?);
    }
    Ok(results)
}

/// The groups this process carries: a running process keeps the groups
/// it started with, so the runner's steps still carry docker's after the
/// lock, with its daemon stopped.
fn groups() -> Vec<String> {
    runner_stdout(&["id", "-Gn"])
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// Whether the variable `name` is set to something.
fn is_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

pub fn run<F: HostFile>(args: &Args) -> Result<bool> {
    let Args {
        mode,
        label,
        config,
    } = args;
    let mode = *mode;
    ensure!(
        valid_label(label),
        "label {label:?}: only lowercase letters, digits and dashes"
    );
    let Some(temp) = std::env::var_os("RUNNER_TEMP") else {
        bail!("RUNNER_TEMP is not set");
    };
    let temp = PathBuf::from(temp);
    let out = temp.join(RECORDS);
    fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
    let results = match mode {
        Mode::Control | Mode::Confined => runner_results(mode, &temp, label)?,
        Mode::SandboxUser | Mode::NoUser => user_results::<F>(mode, config)?,
    };
    let problems = failures(mode, &results);
    let tokens: Results = TOKENS.iter().map(|&var| (var, is_set(var))).collect();
    let record = json!({
        "label": label,
        "mode": mode,
        "results": results,
        "groups": groups(),
        "tokens": tokens,
        "problems": problems,
    });
    let path = out.join(format!("{label}.json"));
    let text = format!("{}\n", serde_json::to_string_pretty(&record)?);
    fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    for &name in mode.names() {
        let got = results.get(name).copied();
        let ok = got == Some(mode.wanted(name));
        let verdict = if ok { "ok" } else { "FAIL" };
        let outcome = if got == Some(true) {
            "succeeded"
        } else {
            "failed"
        };
        println!("{verdict}: [{label}] {name} {outcome}");
    }
    println!("[{label}] record: {record}");
    Ok(problems.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The action's directory, from this crate's.
    const ACTION: &str = "../../.github/actions/confine-probe";

    fn results(pairs: &[(&'static str, bool)]) -> Results {
        pairs.iter().copied().collect()
    }

    #[test]
    fn probes_pass_only_as_they_must() {
        let control = results(&[
            ("sudo", true),
            ("docker", true),
            ("world-write", true),
            ("metadata", true),
            ("environ", true),
            ("worker-diagnostics", true),
        ]);
        let confined = results(&[
            ("sudo", false),
            ("docker", false),
            ("world-write", false),
            ("metadata", false),
            ("environ", false),
            ("worker-diagnostics", false),
            ("owner-write", true),
        ]);
        let sandbox_user = results(&[
            ("user", true),
            ("user-enter", true),
            ("user-sudo", false),
            ("user-metadata", false),
        ]);
        let no_user = results(&[
            ("user", false),
            ("sudo", false),
            ("sudo-true-listed", false),
            ("sudo-rules", true),
            ("helper", true),
        ]);
        let passes = [
            (Mode::Control, &control),
            (Mode::Confined, &confined),
            (Mode::SandboxUser, &sandbox_user),
            (Mode::NoUser, &no_user),
        ];
        let refused: Results = confined.keys().map(|&n| (n, false)).collect();
        let missing = [
            "user: failed, must succeed",
            "user-enter: not probed, must succeed",
            "user-sudo: not probed, must fail",
            "user-metadata: not probed, must fail",
        ];

        let listing = "User runner may run the following commands on host:\n    (ALL) NOPASSWD: ALL\n    (ALL : ALL) !ALL\n    (root) NOPASSWD: /usr/local/libexec/agentic-job   helper *\n";
        let grant = "(ALL) NOPASSWD: ALL";
        let deny = "(ALL : ALL) !ALL";
        let helper = "(root) NOPASSWD: /usr/local/libexec/agentic-job helper *";
        let narrower = "(root) NOPASSWD: /usr/local/libexec/agentic-job helper enter *";
        let locks = |rules: &[&str]| {
            let rules: Vec<String> = rules.iter().map(|rule| (*rule).to_owned()).collect();
            locked(&rules)
        };

        let problem = |regular, uid, mode| fixture_problem(Some((regular, uid, mode)));
        let inval = format!("kill(0) failed with {}", Errno::INVAL);
        let stat = "2041 (Runner.Worker) S 1990 2041 2041 0 -1";

        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(ACTION);
        let action = fs::read_to_string(dir.join("action.yml")).unwrap();
        // Without a post entry the runner runs no post step, and the job
        // passes without the proof secure-host's threat model claims.
        let steps = |key: &str| {
            let script = dir.join(format!("{key}.mjs"));
            let script = fs::read_to_string(script).unwrap();
            let spawned = format!("spawnSync('secure-host', ['probe', 'confined', '{key}']");
            action.contains(&format!("\n  {key}: {key}.mjs\n")) && script.contains(&spawned)
        };

        // [what, whether it holds]
        let cases = [
            ("a label", valid_label("sandbox-user")),
            ("an empty label", !valid_label("")),
            ("a path for a label", !valid_label("../x")),
            ("an uppercase label", !valid_label("Main")),
            // Every write refused is no proof of the policy: the owner's
            // control fails it.
            (
                "every write refused",
                failures(Mode::Confined, &refused) == ["owner-write: failed, must succeed"],
            ),
            (
                "nothing probed",
                failures(Mode::Confined, &Results::new()).len() == 7,
            ),
            // No sandbox user where one must be: the rest is not probed,
            // and fails too.
            (
                "no sandbox user",
                failures(Mode::SandboxUser, &results(&[("user", false)])) == missing,
            ),
            (
                "sudo's listing",
                sudo_rules(listing) == [grant, deny, helper],
            ),
            ("the lock's listing", locked(&sudo_rules(listing))),
            ("no rules", !locks(&[])),
            ("the helper's rule alone", !locks(&[helper])),
            ("the deny rule alone", !locks(&[deny])),
            ("the helper's rule first", !locks(&[helper, deny])),
            ("a grant after", !locks(&[deny, helper, grant])),
            ("a narrower helper rule", !locks(&[deny, narrower])),
            // A fixture that DAC would refuse anyway proves nothing.
            ("root's 666 file", problem(true, 0, 0o100666).is_none()),
            (
                "another owner",
                problem(true, 1001, 0o100666).as_deref() == Some("owned by uid 1001, not root"),
            ),
            (
                "mode 664",
                problem(true, 0, 0o100664).as_deref() == Some("mode 664, not 666"),
            ),
            (
                "setuid",
                problem(true, 0, 0o104666).as_deref() == Some("mode 4666, not 666"),
            ),
            (
                "not a file",
                problem(false, 0, 0o100666).as_deref() == Some("not a regular file"),
            ),
            (
                "no fixture",
                fixture_problem(None).as_deref() == Some("missing"),
            ),
            // An orphan that is gone or not this user's proves nothing.
            ("a running orphan", orphan_problem(None).is_none()),
            (
                "a gone orphan",
                orphan_problem(Some(Errno::SRCH)).as_deref() == Some("not running"),
            ),
            (
                "another user's orphan",
                orphan_problem(Some(Errno::PERM)).as_deref() == Some("not this user's"),
            ),
            (
                "a refused signal",
                orphan_problem(Some(Errno::INVAL)) == Some(inval),
            ),
            (
                "the Worker's stat",
                parse_stat(stat) == Some(("Runner.Worker", 1990)),
            ),
            (
                "a name with a parenthesis",
                parse_stat("7 (a) b) S 1 7") == Some(("a) b", 1)),
            ),
            ("no name", parse_stat("7 S 1").is_none()),
            // The action probes in both its main and its post step.
            ("the main step", steps("main")),
            ("the post step", steps("post")),
            ("a node24 action", action.contains("\n  using: node24\n")),
        ];
        for (what, holds) in cases {
            assert!(holds, "{what}");
        }
        // Each passes as it is, and flipping any one probe fails it alone.
        for (mode, passing) in passes {
            assert!(failures(mode, passing).is_empty(), "{mode:?}");
            for &name in mode.names() {
                let mut flipped = passing.clone();
                flipped.insert(name, !passing[name]);
                let got = failures(mode, &flipped);
                assert_eq!(got.len(), 1, "{mode:?} {name}");
                assert!(got[0].starts_with(&format!("{name}: ")), "{got:?}");
            }
        }
    }
}
