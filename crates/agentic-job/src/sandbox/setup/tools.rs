//! Caller-trusted setup code, never root and never given runner credentials.

use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};

use crate::config::Tools;
use crate::sandbox::host::{self, User};

const FETCH_TIMEOUT: &str = "120";
const INSTALL_TIMEOUT: &str = "600";

fn commands(tools: &Tools, user: &User) -> Vec<Command> {
    let checkout = user.home.join(".agenthome-tools");
    let path = format!(
        "{}/.local/bin:{}",
        user.home.display(),
        host::PATH_DIRS.join(":")
    );
    let make = |seconds: &str, program: &str, args: &[&str]| {
        let mut command = Command::new("timeout");
        command
            .env_clear()
            .env("PATH", host::root_path())
            .current_dir(&user.home);
        command
            .args([
                "--kill-after=10",
                seconds,
                "runuser",
                "-u",
                &user.name,
                "--",
                "env",
                "-i",
            ])
            .arg(format!("HOME={}", user.home.display()))
            .arg(format!("PATH={path}"))
            .args(["LANG=C.UTF-8", "GIT_TERMINAL_PROMPT=0", program])
            .args(args);
        command
    };
    let dir = checkout.to_string_lossy();
    vec![
        make(FETCH_TIMEOUT, "git", &["init", "--", &dir]),
        make(
            FETCH_TIMEOUT,
            "git",
            &[
                "-C",
                &dir,
                "fetch",
                "--depth=1",
                "--no-tags",
                "--",
                &tools.repository,
                &tools.revision,
            ],
        ),
        make(
            FETCH_TIMEOUT,
            "git",
            &["-C", &dir, "checkout", "--detach", &tools.revision],
        ),
        make(
            INSTALL_TIMEOUT,
            "just",
            &[
                "--working-directory",
                &dir,
                "--justfile",
                &format!("{dir}/Justfile"),
                &tools.recipe,
            ],
        ),
    ]
}

pub(super) fn install(tools: &Tools, user: &User) -> Result<()> {
    // Network is still open here: the pinned installer fetches PyPI packages
    // and release assets. Do not expand the later sandbox egress allowlist.
    // Each phase is bounded, and failure prevents publishing the setup config.
    execute(commands(tools, user), run)
}

fn run(command: &mut Command) -> Result<()> {
    // No captured pipes: a background child can keep them open after timeout
    // exits. Nor may installer output issue workflow commands to the runner.
    // Discard transcripts rather than collecting an unbounded root-side log.
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("starting caller tools setup (requires timeout and runuser)")?;
    ensure!(
        status.success(),
        "caller tools setup failed ({status}); installer transcripts are suppressed"
    );
    Ok(())
}

fn execute(commands: Vec<Command>, mut run: impl FnMut(&mut Command) -> Result<()>) -> Result<()> {
    for mut command in commands {
        println!("caller tools: starting bounded setup phase");
        run(&mut command)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_phases_check_out_the_pin_not_the_default_branch() {
        let fixture = tempfile::tempdir().unwrap();
        let source = fixture.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .current_dir(&source)
                .args([
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.org",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        git(&["init"]);
        git(&["commit", "--allow-empty", "-m", "pinned"]);
        let pin = git(&["rev-parse", "HEAD"]);
        git(&["commit", "--allow-empty", "-m", "later"]);
        let user = User {
            name: "unused".into(),
            uid: 1001,
            gid: 1001,
            home: fixture.path().into(),
        };
        let tools = Tools {
            repository: source.to_str().unwrap().into(),
            revision: pin.clone(),
            recipe: "install-tools".into(),
        };
        // Execute the generated Git argv without runuser: this test neither
        // requires root nor changes host users or network rules.
        for command in commands(&tools, &user).iter().take(3) {
            let args: Vec<_> = command.get_args().collect();
            run(Command::new(args[12])
                .args(&args[13..])
                .env("GIT_CONFIG_NOSYSTEM", "1"))
            .unwrap();
        }
        let output = Command::new("git")
            .args([
                "-C",
                user.home.join(".agenthome-tools").to_str().unwrap(),
                "rev-parse",
                "HEAD",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), pin);
    }

    #[test]
    fn exited_child_with_background_output_does_not_hold_setup_open() {
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = run(Command::new("timeout").args([
                "--kill-after=0.1",
                "0.2",
                "sh",
                "-c",
                "sleep 2 & exit 0",
            ]));
            send.send(result).unwrap();
        });
        receive
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("setup hung on background output")
            .unwrap();
    }

    #[test]
    fn timeout_and_failed_installer_fail_setup() {
        for script in ["exit 1", "exec sleep 2"] {
            assert!(
                run(Command::new("timeout").args(["--kill-after=0.1", "0.1", "sh", "-c", script]))
                    .is_err()
            );
        }
    }

    #[test]
    fn every_failure_stops_setup_before_the_next_phase() {
        for fail_at in 0..4 {
            let mut calls = 0;
            let result = execute((0..4).map(|_| Command::new("unused")).collect(), |_| {
                calls += 1;
                anyhow::ensure!(calls != fail_at + 1, "setup failed");
                Ok(())
            });
            assert!(result.is_err());
            assert_eq!(calls, fail_at + 1);
        }
    }

    #[test]
    fn pinned_install_has_clean_environment_and_bounded_unprivileged_commands() {
        let tools = Tools {
            repository: "https://example.org/tools.git".into(),
            revision: "a".repeat(40),
            recipe: "install-tools".into(),
        };
        let user = User {
            name: "sandbox".into(),
            uid: 1001,
            gid: 1001,
            home: "/home/sandbox".into(),
        };
        let commands = commands(&tools, &user);
        assert_eq!(commands.len(), 4);
        for (i, command) in commands.iter().enumerate() {
            let args: Vec<_> = command.get_args().map(|a| a.to_str().unwrap()).collect();
            assert_eq!(
                &args[..9],
                &[
                    "--kill-after=10",
                    if i == 3 { "600" } else { "120" },
                    "runuser",
                    "-u",
                    "sandbox",
                    "--",
                    "env",
                    "-i",
                    "HOME=/home/sandbox"
                ]
            );
            assert_eq!(
                args[9],
                "PATH=/home/sandbox/.local/bin:/usr/local/bin:/usr/bin:/bin"
            );
            assert_eq!(command.get_envs().count(), 1);
        }
        let fetch: Vec<_> = commands[1].get_args().collect();
        assert_eq!(fetch[fetch.len() - 1], tools.revision.as_str());
        let install: Vec<_> = commands[3].get_args().collect();
        assert_eq!(install[install.len() - 1], "install-tools");
    }
}
