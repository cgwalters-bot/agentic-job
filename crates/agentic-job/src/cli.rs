//! The command line: the table in docs/plan.md, and nothing else.
//!
//! Each command's arguments live in its own module; this file only names
//! the commands and dispatches to them.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::config::compose;
use crate::exit::Exit;
use crate::{acp_drive, audit, check, event, policy, run, sandbox, workflows};

#[derive(Debug, Parser)]
#[command(name = "agentic-job", version, about, propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect downloaded run artifacts without executing or applying them
    Audit(audit::Args),
    /// Check one run's request against the caller's bounds and print policy.json
    Policy(policy::Args),
    /// Prepare and probe the host the agent runs on
    #[command(subcommand)]
    Sandbox(sandbox::Command),
    /// Run the agent in the sandbox and take what it hands back
    Run(run::Args),
    /// Check handed-back outputs and patch against the policy
    Check(check::Args),
    /// Inspect checked proposals with a bounded model request before apply
    Detect(crate::detect::Args),
    /// Decide whether the event that started the workflow may start a run, and write its task
    Event(event::Args),
    /// Write a run's configuration from a file and settings given one at a time
    Config(compose::Args),
    /// Check a repository's workflow files for the job shape that keeps untrusted steps sandboxed
    #[command(subcommand)]
    Workflows(workflows::Command),
    /// Start a second agent over ACP and drive it, as a run's agent: see docs/harness.md
    #[command(name = acp_drive::COMMAND, subcommand)]
    AcpDrive(acp_drive::Command),
    /// Become the agent, as the sandbox user: what `run` has the session start
    #[command(name = run::launch::COMMAND, hide = true)]
    LaunchAgent(run::launch::Args),
    /// The privileged operations the runner's user keeps after `sandbox setup`, run as root through its one sudo rule
    #[command(name = sandbox::helper::COMMAND, hide = true, subcommand)]
    Helper(sandbox::helper::Op),
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        match self {
            Self::Audit(args) => audit::run(args),
            Self::Policy(args) => policy::run(args),
            Self::Sandbox(command) => command.run(),
            Self::Run(args) => run::run(args),
            Self::Check(args) => check::run(args),
            Self::Detect(args) => crate::detect::run(args),
            Self::Event(args) => event::run(args),
            Self::Config(args) => compose::run(args),
            Self::Workflows(command) => command.run(),
            Self::AcpDrive(command) => command.run(),
            Self::LaunchAgent(args) => run::launch::run(args),
            Self::Helper(op) => sandbox::helper::run(op),
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn definition_is_consistent() {
        Cli::command().debug_assert();
    }

    /// The command lines of the plan's table.
    const PLAN: &[&[&str]] = &[
        &[
            "policy",
            "--allow",
            "allow.toml",
            "--repo",
            "owner/name",
            "--clone-url",
            "https://example.org/owner/name",
            "--base",
            "main",
            "--kind",
            "branch",
            "--outputs",
            "create_pull_request,noop",
            "--max-outputs",
            "2",
        ],
        &["sandbox", "setup", "--config", "c.toml"],
        &["sandbox", "check"],
        &[
            "run", "--policy", "p.json", "--task", "task.md", "--meta", "m.json", "--out", "out",
        ],
        &[
            "check",
            "--policy",
            "p.json",
            "--outputs",
            "dir",
            "--collected",
            "agent_output.json",
        ],
        &[
            "check",
            "--policy",
            "p.json",
            "--outputs",
            "dir",
            "--collected",
            "agent_output.json",
            "--report",
            "r.json",
        ],
    ];

    #[test]
    fn plan_commands_parse() {
        for args in PLAN {
            Cli::try_parse_from(std::iter::once(&"agentic-job").chain(*args))
                .unwrap_or_else(|err| panic!("{args:?}: {err}"));
        }
    }

    /// Not in the plan's table: what a workflow writes the configuration
    /// with, from inputs that may hold anything.
    #[test]
    fn the_configuration_writer_parses() {
        let cli = Cli::try_parse_from([
            "agentic-job",
            "config",
            "--from",
            "caller.toml",
            "--string",
            "agent.model=--help",
            "--string",
            "inference.url=",
            "--integer",
            "limits.budget=500",
            "--list",
            "setup.packages=just jq",
        ]);
        cli.unwrap();
    }

    /// Not in the plan's table: a host's configuration, and a step of a
    /// job as the sandbox user, the script as a step's shell is given it.
    #[test]
    fn a_job_without_an_agent_parses() {
        let lines: &[&[&str]] = &[
            &["config", "--host", "--boolean", "sandbox.lock-runner=true"],
            &["sandbox", "exec", "--", "make", "--help"],
            &[
                "sandbox",
                "exec",
                "--chdir",
                "/home/s/w",
                "--stdin",
                "/tmp/s.sh",
                "--",
                "bash",
                "-s",
            ],
        ];
        for args in lines {
            Cli::try_parse_from(std::iter::once(&"agentic-job").chain(*args))
                .unwrap_or_else(|err| panic!("{args:?}: {err}"));
        }
        assert!(Cli::try_parse_from(["agentic-job", "sandbox", "exec"]).is_err());
    }

    /// Not in the plan's table: `sandbox check` runs it as the sandbox user.
    #[test]
    fn the_hidden_prober_parses() {
        Cli::try_parse_from(["agentic-job", "sandbox", "probe-local"]).unwrap();
    }

    /// Not in the plan's table: what the runner's user has root do after
    /// setup, each operation as `sandbox::root` spells it.
    #[test]
    fn the_helper_parses() {
        let ops: &[&[&str]] = &[
            &["ping"],
            &["enter", "--chdir", "/home/agent", "--", "git", "status"],
            &[
                "enter",
                "--chdir",
                "/home/agent",
                "--",
                "sh",
                "-c",
                "--help",
            ],
            &["reap"],
            &["egress-log-size"],
            &["egress-log", "--from", "0"],
            &["tailscale-status"],
            &["pkexec-control"],
            &["disable-linger"],
            &["crontab-remove"],
        ];
        for op in ops {
            Cli::try_parse_from(["agentic-job", "helper"].iter().chain(*op))
                .unwrap_or_else(|err| panic!("{op:?}: {err}"));
        }
        for bad in [
            &["helper"][..],
            &["helper", "enter", "--chdir", "/home/agent"],
            &["helper", "enter", "--", "true"],
            &["helper", "egress-log"],
            &["helper", "reap", "--uid", "1"],
        ] {
            assert!(
                Cli::try_parse_from(["agentic-job"].iter().chain(bad)).is_err(),
                "{bad:?} parsed"
            );
        }
    }

    /// Not in the plan's table: what a run's agent drives a child with.
    #[test]
    fn the_driver_parses() {
        let lines: &[&[&str]] = &[
            &["start", "--agent", "vibe"],
            &["start", "--agent", "vibe", "--model", "m", "--cwd", "/w"],
            &["prompt", "--timeout", "100", "What is your task?"],
            &["prompt", "--", "--help"],
            &["events"],
            &["events", "--since", "12"],
            &["cancel"],
            &["stop"],
            &["status"],
        ];
        for args in lines {
            Cli::try_parse_from(["agentic-job", "acp-drive"].iter().chain(*args))
                .unwrap_or_else(|err| panic!("{args:?}: {err}"));
        }
        for bad in [
            &["acp-drive"][..],
            &["acp-drive", "start"],
            &["acp-drive", "prompt"],
            &["acp-drive", "prompt", "--timeout", "0", "x"],
            &["acp-drive", "events", "--since", "-1"],
        ] {
            assert!(
                Cli::try_parse_from(["agentic-job"].iter().chain(bad)).is_err(),
                "{bad:?} parsed"
            );
        }
    }

    #[test]
    fn bad_command_lines_are_refused() {
        let cases: &[&[&str]] = &[
            &[],
            &["egress", "serve"],
            &["policy"],
            &[
                "policy", "--allow", "a", "--repo", "r", "--base", "b", "--kind", "other",
            ],
            &["sandbox"],
            &["sandbox", "setup"],
            &["sandbox", "check", "--config", "c.toml"],
            &["run", "--policy", "p.json"],
            &["check", "--outputs", "dir"],
            &["check", "--policy", "p.json", "--outputs", "dir"],
            &["launch-agent"],
        ];
        for args in cases {
            let parsed = Cli::try_parse_from(std::iter::once(&"agentic-job").chain(*args));
            assert!(parsed.is_err(), "{args:?} parsed");
        }
    }
}
