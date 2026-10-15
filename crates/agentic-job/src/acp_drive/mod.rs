//! `agentic-job acp-drive`: lets the main agent of a run start a second
//! agent over ACP and drive it turn by turn, through bash, to watch how
//! that agent works (docs/harness.md, "A second agent").
//!
//! `start` starts a daemon, as the user it is run as (in a run, the
//! sandbox user), that starts the child agent and holds its standard
//! streams; the other commands talk to the daemon on a socket in
//! [`DIR`], private to that user. The daemon writes every ACP message to
//! [`ACP_LOG`] and the child's standard error to [`STDERR_LOG`] there,
//! for `run` to put in the transcript.
//!
//! It holds nothing the main agent does not: it runs as the same user,
//! and the child reads the run token from a file of that user's, as the
//! main agent does. It is not a boundary. What bounds the child is the
//! run's: the inference proxy counts its requests under the run's token,
//! the session ends it with every process of the sandbox user, and only
//! a run whose configuration names a child agent has one configured.

mod daemon;
pub mod events;

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

use self::daemon::Request;
use crate::exit::Exit;
use crate::run::agent::{CHILD_VIBE_CONFIG_FILE, Kind};
use crate::run::launch;
use crate::session::{Policy, agents};

/// The command, as `run`'s brief names it.
pub const COMMAND: &str = "acp-drive";
/// Under the home directory: the daemon's socket, its log and the child's
/// transcript.
pub const DIR: &str = ".local/state/agentic-job/acp-drive";
/// In [`DIR`]: every ACP message, as `acp.jsonl` of the session.
pub const ACP_LOG: &str = "acp.jsonl";
/// In [`DIR`]: the child's standard error.
pub const STDERR_LOG: &str = "stderr.log";
/// In [`DIR`]: the daemon's own standard error.
const DAEMON_LOG: &str = "daemon.log";
const SOCKET: &str = "socket";
const PRIVATE_DIR_MODE: u32 = 0o700;
/// How long `start` waits for the session to be open.
const START_TIMEOUT: Duration = Duration::from_secs(300);
const START_POLL: Duration = Duration::from_millis(100);
/// The most of the daemon's log `start` shows of a daemon that failed.
const MAX_SHOWN_LOG: u64 = 4096;
/// The largest answer read: the events, which the daemon bounds.
const MAX_ANSWER_BYTES: u64 = 256 << 20;

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Start a child agent and the daemon that holds its ACP session
    Start(Start),
    /// Send a prompt, and wait for the turn to end; prints its stop reason
    Prompt {
        text: String,
        /// Give up waiting after this many seconds (exit 124); the turn goes on
        #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..))]
        timeout: Option<u64>,
    },
    /// Print the session's events from the Nth on, as JSON: messages,
    /// thinking, tool calls, permissions, compactions, turn ends and exit
    Events {
        #[arg(long, default_value_t = 0, value_name = "N")]
        since: usize,
    },
    /// Cancel the running turn
    Cancel,
    /// Stop the child agent and the daemon
    Stop,
    /// Print the child's session, model and state
    Status,
    /// The daemon, as `start` starts it
    #[command(hide = true)]
    Serve(Start),
}

#[derive(Debug, Clone, clap::Args)]
pub struct Start {
    /// The child agent: vibe, configured by the run's [child-agent]
    #[arg(long)]
    pub agent: String,
    /// The model to select, of those the child's configuration declares
    #[arg(long)]
    pub model: Option<String>,
    /// The child's working directory (default: the current one)
    #[arg(long, value_name = "DIR")]
    pub cwd: Option<PathBuf>,
}

fn home() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    home.filter(|home| home.is_absolute())
        .context("HOME must be an absolute path")
}

/// The driver's directory, made private to this user.
fn private_dir(home: &Path) -> Result<PathBuf> {
    let dir = home.join(DIR);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(PRIVATE_DIR_MODE)
        .create(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))
        .with_context(|| format!("making {} private", dir.display()))?;
    Ok(dir)
}

/// Sends REQUEST to the daemon at SOCKET and returns its answer, or
/// `None` if it gave none within TIMEOUT.
fn ask(socket: &Path, request: &Request, timeout: Option<Duration>) -> Result<Option<Value>> {
    let mut stream = UnixStream::connect(socket).with_context(|| {
        format!(
            "no child agent is running (nothing answers on {}): `{COMMAND} start` one",
            socket.display()
        )
    })?;
    stream.set_read_timeout(timeout)?;
    stream.write_all(serde_json::to_string(request)?.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut answer = String::new();
    match stream.take(MAX_ANSWER_BYTES).read_to_string(&mut answer) {
        Ok(_) => {}
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            return Ok(None);
        }
        Err(err) => return Err(err).context("reading the daemon's answer"),
    }
    let answer = serde_json::from_str(&answer).with_context(|| {
        format!(
            "the daemon gave no answer: see ~/{DIR}/{DAEMON_LOG} ({:?})",
            answer.trim()
        )
    })?;
    Ok(Some(answer))
}

/// Prints ANSWER, and exits as it says.
fn print(answer: &Value) -> Exit {
    println!("{answer}");
    if answer.get("error").is_some() {
        Exit::Failure
    } else {
        Exit::Success
    }
}

/// The last of the daemon's log, for a daemon that failed.
fn daemon_log(dir: &Path) -> String {
    let Ok(file) = std::fs::File::open(dir.join(DAEMON_LOG)) else {
        return String::new();
    };
    let len = file.metadata().map_or(0, |m| m.len());
    let mut text = String::new();
    let mut file = file;
    let _ = std::io::Seek::seek(
        &mut file,
        std::io::SeekFrom::Start(len.saturating_sub(MAX_SHOWN_LOG)),
    );
    let _ = file.take(MAX_SHOWN_LOG).read_to_string(&mut text);
    text.trim().to_owned()
}

/// What starts the child agent NAME, and Vibe's output cap for MODEL:
/// only Vibe, through the launcher, with the configuration `run` wrote
/// for a child; or the scripted fake agent, which has no model.
fn child_command(
    home: &Path,
    name: &str,
    model: Option<&str>,
) -> Result<(Vec<String>, Option<u64>)> {
    match Kind::parse(name)? {
        Kind::Vibe => {
            let config = home.join(CHILD_VIBE_CONFIG_FILE);
            let text = match std::fs::read_to_string(&config) {
                Ok(text) => text,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => bail!(
                    "this run has no child agent: its configuration names none in [child-agent] \
                     (no ~/{CHILD_VIBE_CONFIG_FILE})"
                ),
                Err(err) => {
                    return Err(err).with_context(|| format!("reading {}", config.display()));
                }
            };
            let cap = daemon::vibe_max_tokens(&text, model)?;
            let exe = std::env::current_exe().context("finding this program's own path")?;
            let exe = exe.to_str().context("this program's path is not UTF-8")?;
            Ok((launch::child_command(exe, Kind::Vibe), cap))
        }
        Kind::Fake => Ok((agents::builtin(Kind::Fake.as_str())?.command, None)),
        other => bail!(
            "{} cannot be a child agent: only vibe (or the scripted fake) can",
            other.as_str()
        ),
    }
}

fn start(args: &Start) -> Result<Exit> {
    let home = home()?;
    let dir = private_dir(&home)?;
    let socket = dir.join(SOCKET);
    if UnixStream::connect(&socket).is_ok() {
        bail!("a child agent is running already: `{COMMAND} stop` it first");
    }
    // Refused here, not in the daemon, so that the caller sees why.
    child_command(&home, &args.agent, args.model.as_deref())?;
    let _ = std::fs::remove_file(&socket);
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(DAEMON_LOG))
        .with_context(|| format!("opening {}", dir.join(DAEMON_LOG).display()))?;
    let exe = std::env::current_exe().context("finding this program's own path")?;
    let cwd = match &args.cwd {
        Some(cwd) => cwd.clone(),
        None => std::env::current_dir().context("finding the current directory")?,
    };
    let mut command = std::process::Command::new(exe);
    command.args([COMMAND, "serve", "--agent", &args.agent, "--cwd"]);
    command.arg(&cwd);
    if let Some(model) = &args.model {
        command.args(["--model", model]);
    }
    let mut daemon = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .context("starting the daemon")?;
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if let Some(status) = daemon.try_wait()? {
            bail!(
                "the daemon ended ({status}) before the session was open: {}",
                daemon_log(&dir)
            );
        }
        if socket.exists()
            && let Ok(Some(answer)) = ask(&socket, &Request::Status, Some(START_POLL * 10))
        {
            return Ok(print(&answer));
        }
        if Instant::now() > deadline {
            let _ = daemon.kill();
            bail!(
                "the session was not open after {}s: {}",
                START_TIMEOUT.as_secs(),
                daemon_log(&dir)
            );
        }
        std::thread::sleep(START_POLL);
    }
}

/// The daemon: its own session, so that what ends the caller's command
/// (a shell tool's process group) does not end it.
fn serve(args: &Start) -> Result<Exit> {
    let _ = rustix::process::setsid();
    let home = home()?;
    let dir = private_dir(&home)?;
    let (argv, max_tokens) = child_command(&home, &args.agent, args.model.as_deref())?;
    let cwd = match &args.cwd {
        Some(cwd) => std::path::absolute(cwd).context("finding the working directory")?,
        None => std::env::current_dir()?,
    };
    let child = daemon::Child {
        name: args.agent.clone(),
        argv,
        cwd,
        model: args.model.clone(),
        max_tokens,
        socket: dir.join(SOCKET),
        dir,
    };
    let policy = Policy::for_task(&home)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(daemon::serve(child, policy))?;
    // Not waiting for the tasks still reading a killed child's streams.
    runtime.shutdown_background();
    Ok(Exit::Success)
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        let socket = || -> Result<PathBuf> { Ok(home()?.join(DIR).join(SOCKET)) };
        let answer = |request: &Request| -> Result<Value> {
            ask(&socket()?, request, None)?.context("the daemon gave no answer")
        };
        Ok(match self {
            Self::Start(args) => start(args)?,
            Self::Serve(args) => serve(args)?,
            Self::Prompt { text, timeout } => {
                ensure!(!text.trim().is_empty(), "the prompt is empty");
                let request = Request::Prompt { text: text.clone() };
                match ask(&socket()?, &request, timeout.map(Duration::from_secs))? {
                    Some(answer) => print(&answer),
                    None => {
                        println!(
                            "{}",
                            serde_json::json!({"running": true,
                                "hint": "the turn goes on: read `events`, or `cancel` it"})
                        );
                        Exit::Timeout
                    }
                }
            }
            Self::Events { since } => print(&answer(&Request::Events { since: *since })?),
            Self::Cancel => print(&answer(&Request::Cancel)?),
            Self::Stop => print(&answer(&Request::Stop)?),
            Self::Status => print(&answer(&Request::Status)?),
        })
    }
}
