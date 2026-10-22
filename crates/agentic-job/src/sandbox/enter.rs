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
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result, ensure};

use super::host::{self, User};
use super::network;
use super::root::Root;
use crate::config::{Config, Sandbox};

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
        ensure!(
            config.sandbox.create_user,
            "sandbox.create-user = false: there is no sandbox user to enter"
        );
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

    /// Whether `argv` ran and succeeded as the sandbox user.
    pub fn succeeds(&self, argv: &[&str]) -> Result<bool> {
        Ok(self.run(argv, b"")?.success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
