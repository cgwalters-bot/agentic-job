//! Entering the sandbox: how the supervisor runs a command as the sandbox
//! user, with nothing of its own environment.
//!
//! `run0` starts the command as a transient systemd service through its
//! own PAM stack, so nothing of the caller's environment or cgroup comes
//! along, and `pam_systemd` gives it what an SSH login gets: a runtime
//! directory, the user's systemd manager and session bus, which rootless
//! podman relies on. The command runs in that session's scope, under the
//! user's slice, which is what the supervisor kills when the run ends.
//!
//! `run0` is root's to run. How the supervisor, the runner's user, gets
//! root to run it is [`super::root`]: the helper on a machine setup has
//! locked, sudo itself elsewhere.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use rustix::fs::FileType;
use rustix::process::{Pid, Signal, kill_process};

use super::host::{self, User};
use super::network;
use super::root::Root;
use crate::config::{Config, Sandbox};
use crate::workflow_commands;

/// `run0` came with systemd 256, and its `--pipe` with 257.
pub const RUN0: &str = "run0";

/// `run0` sets these as sudo would, and tools that see them may act as if
/// run under sudo; `--setenv` cannot unset them.
const SUDO_VARS: &[&str] = &["SUDO_USER", "SUDO_UID", "SUDO_GID"];

/// What lets a process ask for the job's identity token. `run0` passes on
/// none of the caller's environment, so they never reach the sandbox user;
/// they are unset all the same, so that stays true if `run0` changes.
pub const OIDC_REQUEST_VARS: &[&str] = &[
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
];

const LANG: &str = "C.UTF-8";

/// What a command run in the sandbox left: its status and all it wrote.
#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn success(&self) -> bool {
        self.status.success()
    }
}

/// The way into the sandbox for one configuration.
#[derive(Debug, Clone)]
pub struct Entry {
    user: User,
    env: BTreeMap<String, String>,
    root: Root,
    filesystem_view: bool,
}

impl Entry {
    /// The sandbox user of `config`, which `sandbox setup` has created.
    pub fn new(config: &Config) -> Result<Self> {
        let host = config.check_host()?;
        let name = &config.sandbox.user;
        let user = User::lookup(name)?
            .with_context(|| format!("no user {name}: `agentic-job sandbox setup` creates it"))?;
        ensure!(user.uid != 0, "the sandbox user {name} is root by uid");
        let proxy = if config.egress.proxy {
            network::proxy_environment(&host.direct)
        } else {
            BTreeMap::new()
        };
        let mut entry = Self::for_user(user, &config.sandbox, proxy, Root::detect());
        if config.setup.tools.is_some() {
            entry.prepend_tools_path();
        }
        Ok(entry)
    }

    fn prepend_tools_path(&mut self) {
        let path = self.env.get("PATH").cloned().unwrap_or_default();
        self.env.insert(
            "PATH".to_owned(),
            format!("{}/.local/bin:{path}", self.user.home.display()),
        );
    }

    /// The fixed variables, then the egress proxy's, then the
    /// configuration's own, each over the one before.
    fn for_user(
        user: User,
        sandbox: &Sandbox,
        proxy: BTreeMap<String, String>,
        root: Root,
    ) -> Self {
        let fixed = [
            ("LANG".to_owned(), LANG.to_owned()),
            ("PATH".to_owned(), host::PATH_DIRS.join(":")),
        ];
        let env = fixed
            .into_iter()
            .chain(proxy)
            .chain(sandbox.env.clone())
            .collect();
        Self {
            user,
            env,
            root,
            filesystem_view: sandbox.filesystem_view,
        }
    }

    pub fn user(&self) -> &User {
        &self.user
    }

    /// How root is had for the way in.
    pub fn root(&self) -> Root {
        self.root
    }

    pub fn home(&self) -> &Path {
        &self.user.home
    }

    /// The `run0` command line for `argv`, in `cwd`, with the configured
    /// variables and nothing else. The helper builds it as root from the
    /// root-owned configuration; where the runner's user has sudo, the
    /// runner's copy of the configuration is the same file.
    pub fn run0_argv(&self, argv: &[String], cwd: &Path) -> Result<Vec<String>> {
        ensure!(!argv.is_empty(), "an empty command for the sandbox");
        let forbidden: Vec<&str> = self
            .env
            .keys()
            .filter(|name| name.starts_with(Sandbox::FORBIDDEN_ENV_PREFIX))
            .map(String::as_str)
            .collect();
        ensure!(
            forbidden.is_empty(),
            "refusing to pass {} to {}",
            forbidden.join(", "),
            self.user.name
        );
        let head = [
            RUN0.to_owned(),
            "--pipe".to_owned(),
            "--no-ask-password".to_owned(),
            "--shell-prompt-prefix=".to_owned(),
            format!("--user={}", self.user.name),
            // Unlike `systemd-run --collect`, run0 leaves a failed unit
            // behind for every command that exits nonzero.
            "--property=CollectMode=inactive-or-failed".to_owned(),
            format!("--chdir={}", cwd.display()),
        ];
        let setenv = self
            .env
            .iter()
            .map(|(name, value)| format!("--setenv={name}={value}"));
        let unset = SUDO_VARS
            .iter()
            .chain(OIDC_REQUEST_VARS)
            // `run`'s alone, as the identity token's request is.
            .chain(&[crate::run::api_key::API_KEY_VAR, crate::run::mcp::TOKEN_VAR])
            .flat_map(|name| ["-u".to_owned(), (*name).to_owned()]);
        let properties = if self.filesystem_view {
            super::view::properties(&self.user)?
        } else {
            Vec::new()
        };
        Ok(head
            .into_iter()
            .chain(
                properties
                    .into_iter()
                    .map(|property| format!("--property={property}")),
            )
            .chain(setenv)
            .chain(["--".to_owned(), "env".to_owned()])
            .chain(unset)
            .chain(["--".to_owned()])
            .chain(argv.iter().cloned())
            .collect())
    }

    /// `argv` as the sandbox user, in a login session of its own. The
    /// caller connects its standard streams, and they must be sockets:
    /// run0 hands them to PID 1 over D-Bus, which refuses regular files,
    /// and SELinux keeps PID 1 from reading a pipe this process made.
    /// [`Entry::run`] does that for a command that runs to its end.
    pub fn command(&self, argv: &[String], cwd: Option<&Path>) -> Result<Command> {
        self.root.enter(self, argv, cwd.unwrap_or(self.home()))
    }

    /// Runs `argv` in the sandbox user's home, gives it `input`, and waits.
    pub fn run(&self, argv: &[&str], input: &[u8]) -> Result<Output> {
        let argv: Vec<String> = argv.iter().map(|&arg| arg.to_owned()).collect();
        let (mut stdin, child_stdin) = UnixStream::pair().context("socketpair")?;
        let (mut stdout, child_stdout) = UnixStream::pair().context("socketpair")?;
        let (mut stderr, child_stderr) = UnixStream::pair().context("socketpair")?;
        // The command object holds the child's ends: it has to be gone
        // before the reads below can see the streams close.
        let mut child = {
            let mut command = self.command(&argv, None)?;
            command
                .stdin(Stdio::from(OwnedFd::from(child_stdin)))
                .stdout(Stdio::from(OwnedFd::from(child_stdout)))
                .stderr(Stdio::from(OwnedFd::from(child_stderr)))
                .spawn()
                .with_context(|| format!("starting {RUN0} for {}", argv.join(" ")))?
        };
        let (out, err) = std::thread::scope(|scope| {
            scope.spawn(move || {
                // A command that reads none of its input is not an error.
                let _ = stdin.write_all(input);
                let _ = stdin.shutdown(Shutdown::Write);
            });
            let err = scope.spawn(move || {
                let mut bytes = Vec::new();
                let _ = stderr.read_to_end(&mut bytes);
                bytes
            });
            let mut out = Vec::new();
            let _ = stdout.read_to_end(&mut out);
            (out, err.join().unwrap_or_default())
        });
        let status = child.wait().context("waiting for run0")?;
        Ok(Output {
            status,
            stdout: out,
            stderr: err,
        })
    }

    /// Runs `argv` as the sandbox user with `input` as its standard input
    /// and this process's standard output and error as its own, each as
    /// it is written, and waits. Through sockets, like [`Entry::run`]:
    /// the caller's own streams are a job step's pipes or files.
    pub fn stream(
        &self,
        argv: &[String],
        cwd: Option<&Path>,
        input: impl Read + Send + 'static,
    ) -> Result<ExitStatus> {
        let command = self.command(argv, cwd)?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("creating the sandbox stream runtime")?
            .block_on(stream_command(command, input))
    }

    /// Whether `argv` ran and succeeded as the sandbox user.
    pub fn succeeds(&self, argv: &[&str]) -> Result<bool> {
        Ok(self.run(argv, b"")?.success())
    }
}

/// How long a signalled command has to exit before its immediate child
/// (sudo, which cannot relay SIGKILL) is killed. The runner's own cancel
/// sends SIGINT, then SIGTERM 7.5 seconds later.
const SIGNAL_GRACE: Duration = Duration::from_secs(5);

/// How the sandbox's output reaches one of this process's streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relay {
    /// As written: a regular file is data, not a runner log.
    Exact,
    /// With both command syntaxes broken.
    Escaped,
}

impl Relay {
    /// Anything but a regular file may reach the runner's log, through any
    /// pipeline (`| tail`, `| sort`, `| tee`) and alongside other writers:
    /// output with no `::` or `##[` left in it cannot form a command
    /// however it is filtered, reordered or interleaved by line.
    fn to(fd: BorrowedFd<'_>) -> Result<Self> {
        let stat = rustix::fs::fstat(fd).context("identifying a sandbox output destination")?;
        Ok(
            if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
                Self::Exact
            } else {
                Self::Escaped
            },
        )
    }

    fn writer<'a>(self, writer: impl Write + 'a) -> Box<dyn Write + 'a> {
        match self {
            Self::Exact => Box::new(writer),
            Self::Escaped => Box::new(workflow_commands::Escaping::new(writer)),
        }
    }
}

/// Regular files get the exact bytes; everything else is escaped. Written
/// to the descriptors themselves, not through `Stdout`'s line buffer, so
/// that each escaped write is one write to the pipe.
async fn stream_command(command: Command, input: impl Read + Send + 'static) -> Result<ExitStatus> {
    let [out, err] = [std::io::stdout().as_fd(), std::io::stderr().as_fd()].map(|fd| {
        let relay = Relay::to(fd)?;
        let fd = fd
            .try_clone_to_owned()
            .context("duplicating a sandbox output destination")?;
        Ok::<_, anyhow::Error>(relay.writer(std::fs::File::from(fd)))
    });
    stream_command_to(command, input, out?, err?).await
}

async fn stream_command_to(
    mut command: Command,
    mut input: impl Read + Send + 'static,
    mut log: Box<dyn Write + '_>,
    mut errors: Box<dyn Write + '_>,
) -> Result<ExitStatus> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt()).context("watching SIGINT")?;
    let mut terminate = signal(SignalKind::terminate()).context("watching SIGTERM")?;
    let mut hangup = signal(SignalKind::hangup()).context("watching SIGHUP")?;
    let (mut stdin, child_stdin) = UnixStream::pair().context("socketpair")?;
    let (stdout, child_stdout) = UnixStream::pair().context("socketpair")?;
    let (stderr, child_stderr) = UnixStream::pair().context("socketpair")?;
    let mut stdout = async_stream(stdout)?;
    let mut stderr = async_stream(stderr)?;
    command
        .stdin(Stdio::from(OwnedFd::from(child_stdin)))
        .stdout(Stdio::from(OwnedFd::from(child_stdout)))
        .stderr(Stdio::from(OwnedFd::from(child_stderr)));
    let mut child = tokio::process::Command::from(command)
        .kill_on_drop(true)
        .spawn()
        .context("starting the sandbox stream command")?;
    // Do not keep the child's socket ends open in the command object.
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut input, &mut stdin);
        let _ = stdin.shutdown(Shutdown::Write);
    });
    let outcome = tokio::select! {
        result = async {
            tokio::try_join!(relay(&mut stdout, &mut log), relay(&mut stderr, &mut errors), child.wait())
        } => Ok(result),
        _ = interrupt.recv() => Err((Signal::INT, "SIGINT")),
        _ = terminate.recv() => Err((Signal::TERM, "SIGTERM")),
        _ = hangup.recv() => Err((Signal::HUP, "SIGHUP")),
    };
    match outcome {
        Ok(Ok((_, _, status))) => Ok(status),
        Ok(Err(e)) => {
            stop(&mut child, Signal::TERM).await;
            Err(e).context("relaying sandbox output")
        }
        Err((signal, name)) => {
            stop(&mut child, signal).await;
            Err(anyhow!("sandbox stream interrupted by {name}"))
        }
    }
}

fn async_stream(stream: UnixStream) -> Result<tokio::net::UnixStream> {
    stream
        .set_nonblocking(true)
        .context("making a sandbox output socket nonblocking")?;
    tokio::net::UnixStream::from_std(stream).context("registering a sandbox output socket")
}

async fn relay(from: &mut tokio::net::UnixStream, to: &mut dyn Write) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;

    let mut bytes = [0; 8192];
    loop {
        let count = from.read(&mut bytes).await?;
        if count == 0 {
            return Ok(());
        }
        to.write_all(&bytes[..count])?;
        to.flush()?;
    }
}

/// Passes `signal` on rather than SIGKILL at once: sudo relays SIGINT,
/// SIGTERM and SIGHUP towards the command, while killing sudo would orphan
/// the command. Kills it if it has not exited within [`SIGNAL_GRACE`].
async fn stop(child: &mut tokio::process::Child, signal: Signal) {
    let pid = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw);
    if let Some(pid) = pid {
        let _ = kill_process(pid, signal);
        if tokio::time::timeout(SIGNAL_GRACE, child.wait())
            .await
            .is_ok()
        {
            return;
        }
    }
    let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs this test binary again, with `env`, as only `test`.
    fn rerun(test: &str, env: (&str, &str)) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", &format!("sandbox::enter::tests::{test}")])
            .env(env.0, env.1);
        command
    }

    fn shell(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    /// Whether `log` could still hold a command, however it is filtered.
    fn has_command_syntax(log: &[u8]) -> bool {
        log.windows(2).any(|w| w == b"::") || log.windows(3).any(|w| w == b"##[")
    }

    /// Both streams, as a log, whatever the command does or how it ends.
    #[tokio::test]
    async fn streamed_commands_are_escaped() {
        for script in [
            "printf '::set-output name=a::b\\npartial\\r'; printf '::add-mask::x\\n##[error]x' >&2",
            "printf ':'; printf ':stop-commands::x\\n#'; printf '#[group]' >&2; exit 7",
            "printf '  ::error::x'; kill -TERM $$",
        ] {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let _status = stream_command_to(
                shell(script),
                std::io::empty(),
                Relay::Escaped.writer(&mut out),
                Relay::Escaped.writer(&mut err),
            )
            .await
            .unwrap();
            assert!(!out.is_empty(), "{script}");
            for log in [&out, &err] {
                assert!(!has_command_syntax(log), "{}", String::from_utf8_lossy(log));
            }
        }
    }

    #[tokio::test]
    async fn failed_spawn_fails_and_file_transfers_are_exact() {
        assert!(
            stream_command_to(
                Command::new("/no/such/agentic-job-command"),
                std::io::empty(),
                Relay::Escaped.writer(Vec::new()),
                Relay::Escaped.writer(Vec::new()),
            )
            .await
            .is_err()
        );
        let script = "printf '\\000::set-output name=a::b\\r'; printf 'x::y\\n' >&2";
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert!(
            stream_command_to(
                shell(script),
                std::io::empty(),
                Relay::Exact.writer(&mut out),
                Relay::Exact.writer(&mut err),
            )
            .await
            .unwrap()
            .success()
        );
        assert_eq!(out, b"\0::set-output name=a::b\r");
        assert_eq!(err, b"x::y\n");
    }

    /// Regular files get exact bytes; anything else may be a log, through
    /// a pipeline or not. Closed stdout is /dev/null under Rust.
    #[test]
    fn relays_follow_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let file = std::fs::File::create(dir.path().join("out")).unwrap();
        let null = std::fs::File::options()
            .write(true)
            .open("/dev/null")
            .unwrap();
        let (_reader, pipe) = std::io::pipe().unwrap();
        for (fd, relay) in [
            (file.as_fd(), Relay::Exact),
            (null.as_fd(), Relay::Escaped),
            (pipe.as_fd(), Relay::Escaped),
        ] {
            assert_eq!(Relay::to(fd).unwrap(), relay);
        }
    }

    /// The signal is passed on, and a command that ignores it is killed
    /// after the grace period.
    #[test]
    fn supervisor_signals_reach_the_command() {
        const SCRIPT: &str = "AGENTIC_JOB_STREAM_TEST_SCRIPT";
        if let Ok(script) = std::env::var(SCRIPT) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = runtime.block_on(stream_command_to(
                shell(&script),
                std::io::empty(),
                Relay::Escaped.writer(Vec::new()),
                Relay::Escaped.writer(Vec::new()),
            ));
            assert!(result.is_err());
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path().display();
        // Signals are process-wide: isolate each case from parallel tests.
        for (name, ignore) in [
            ("INT", false),
            ("TERM", false),
            ("HUP", false),
            ("TERM", true),
        ] {
            let script = if ignore {
                format!(
                    "trap '' {name}; echo $$ > {dir}/pid; printf partial; kill -{name} $PPID; exec sleep 600"
                )
            } else {
                format!(
                    "echo $$ > {dir}/pid; trap 'echo {name} > {dir}/got; kill $!; exit 0' {name}; \
                     printf partial; sleep 600 & kill -{name} $PPID; wait"
                )
            };
            let _ = std::fs::remove_file(format!("{dir}/got"));
            let output = rerun("supervisor_signals_reach_the_command", (SCRIPT, &script))
                .arg("--nocapture")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            let got = std::fs::read_to_string(format!("{dir}/got")).ok();
            assert_eq!(
                got.as_deref(),
                (!ignore).then(|| format!("{name}\n")).as_deref()
            );
            let pid = std::fs::read_to_string(format!("{dir}/pid")).unwrap();
            assert!(
                !Path::new(&format!("/proc/{}", pid.trim())).exists(),
                "{name}"
            );
        }
    }

    fn entry(env: &[(&str, &str)]) -> Entry {
        let sandbox = Sandbox {
            env: env
                .iter()
                .map(|&(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            ..Sandbox::default()
        };
        let user = User {
            name: "agent".into(),
            uid: 1001,
            gid: 1001,
            home: "/home/agent".into(),
        };
        Entry::for_user(user, &sandbox, BTreeMap::new(), Root::Sudo)
    }

    #[test]
    fn tools_path_preserves_the_callers_path_without_changing_root_path() {
        let mut entry = entry(&[("PATH", "/opt/bin:/usr/bin")]);
        assert_eq!(entry.env["PATH"], "/opt/bin:/usr/bin");
        entry.prepend_tools_path();
        assert_eq!(
            entry.env["PATH"],
            "/home/agent/.local/bin:/opt/bin:/usr/bin"
        );
        assert!(!host::root_path().contains(".local"));
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|&s| s.to_owned()).collect()
    }

    #[test]
    fn run0_command_line() {
        let entry = entry(&[
            ("PATH", "/opt/bin:/usr/bin"),
            ("HTTPS_PROXY", "http://p"),
            ("LANG", "C"),
        ]);
        let argv = entry
            .run0_argv(&strings(&["git", "status"]), Path::new("/work"))
            .unwrap();
        assert_eq!(
            argv,
            strings(&[
                "run0",
                "--pipe",
                "--no-ask-password",
                "--shell-prompt-prefix=",
                "--user=agent",
                "--property=CollectMode=inactive-or-failed",
                "--chdir=/work",
                "--setenv=HTTPS_PROXY=http://p",
                // The configuration's values win over the fixed ones.
                "--setenv=LANG=C",
                "--setenv=PATH=/opt/bin:/usr/bin",
                "--",
                "env",
                "-u",
                "SUDO_USER",
                "-u",
                "SUDO_UID",
                "-u",
                "SUDO_GID",
                "-u",
                "ACTIONS_ID_TOKEN_REQUEST_URL",
                "-u",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                "-u",
                "AGENTIC_JOB_INFERENCE_KEY",
                "-u",
                "AGENTIC_JOB_MCP_TOKEN",
                "--",
                "git",
                "status",
            ])
        );
    }

    #[test]
    fn the_view_is_opt_in() {
        // The walk's switch is gone: a configuration that still asks for
        // it is refused rather than taken for protection it no longer has.
        assert!(Config::parse("[sandbox]\nworld-write-walk = true").is_err());
        for (text, view) in [("", false), ("[sandbox]\nfilesystem-view = true", true)] {
            let config = Config::parse(text).unwrap();
            assert_eq!(config.sandbox.filesystem_view, view);
            let entry = Entry::for_user(
                entry(&[]).user,
                &config.sandbox,
                BTreeMap::new(),
                Root::Sudo,
            );
            let argv = entry.run0_argv(&strings(&["true"]), entry.home()).unwrap();
            assert_eq!(
                argv.iter()
                    .any(|arg| arg == "--property=ProtectSystem=strict"),
                view
            );
        }
    }

    /// A configuration that validation should have refused, carrying one
    /// of the job's variables, gets no further here.
    #[test]
    fn the_jobs_variables_are_refused() {
        let cwd = Path::new("/");
        let cmd = strings(&["true"]);
        let err = entry(&[("ACTIONS_CACHE_URL", "x")])
            .run0_argv(&cmd, cwd)
            .unwrap_err();
        assert!(err.to_string().contains("ACTIONS_CACHE_URL"), "{err}");
        assert!(entry(&[]).run0_argv(&[], cwd).is_err());
    }

    /// Where the runner's user has sudo, the way in is sudo and run0;
    /// where setup locked the machine, the helper.
    #[test]
    fn the_way_in_depends_on_how_root_is_had() {
        let argv = |command: &Command| -> Vec<String> {
            std::iter::once(command.get_program())
                .chain(command.get_args())
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect()
        };
        let direct = entry(&[]).command(&strings(&["id"]), None).unwrap();
        if !rustix::process::geteuid().is_root() {
            assert_eq!(&argv(&direct)[..4], ["sudo", "-n", "--", "run0"]);
        }
        let user = User {
            name: "agent".into(),
            uid: 1001,
            gid: 1001,
            home: "/home/agent".into(),
        };
        let locked = Entry::for_user(user, &Sandbox::default(), BTreeMap::new(), Root::Helper);
        let command = locked
            .command(&strings(&["id", "-u"]), Some(Path::new("/home/agent/w")))
            .unwrap();
        assert_eq!(
            argv(&command),
            [
                "sudo",
                "-n",
                "--",
                "/usr/local/libexec/agentic-job",
                "helper",
                "enter",
                "--chdir",
                "/home/agent/w",
                "--",
                "id",
                "-u"
            ]
        );
    }
}
