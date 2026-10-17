//! The built binary's exit states, which the unit tests cannot see.

use std::process::Command;

use clap::Parser;

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

/// What `exit::ERROR` is; spelled out because it is the interface.
const ERROR: i32 = 2;

#[test]
fn built_in_dispatch_installer_command_parses_without_entering_the_sandbox() {
    // Read at test time, not built in: the release pin's digest does not
    // cover the actions outside crates/.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../run/action.yml");
    let action = std::fs::read_to_string(path).unwrap();
    let command = action
        .lines()
        .find(|line| line.trim_start().starts_with("agentic-job sandbox exec "))
        .unwrap();
    // This fixed installer has only whitespace-separated words and one
    // quoted variable path; do not execute it or enter a privileged sandbox.
    let argv = command.split_whitespace().map(|arg| arg.trim_matches('"'));
    let cli = agentic_job::cli::Cli::try_parse_from(argv).unwrap();
    let agentic_job::cli::Command::Sandbox(agentic_job::sandbox::Command::Exec(args)) = cli.command
    else {
        panic!("expected a sandbox exec command");
    };
    assert_eq!(
        args.stdin.unwrap().to_str().unwrap(),
        "$ACTION/../workflow/dispatch-$PROFILE.sh"
    );
    assert_eq!(args.argv, ["sh", "-s"]);
}

#[test]
fn exit_states() {
    let cases: &[(&[&str], i32, &str)] = &[
        (&["--version"], 0, ""),
        // `sandbox check` itself depends on whether a sandbox is set up
        // where the tests run; tests/sandbox_host.rs covers it.
        (
            &["sandbox", "setup", "--config", "/nonexistent.toml"],
            ERROR,
            "/nonexistent.toml",
        ),
        (&["no-such-command"], ERROR, "unrecognized subcommand"),
        (&["run"], ERROR, "required arguments"),
    ];
    for (args, code, stderr) in cases {
        let output = Command::new(BIN).args(*args).output().unwrap();
        assert_eq!(output.status.code(), Some(*code), "{args:?}");
        let text = String::from_utf8_lossy(&output.stderr);
        assert!(text.contains(stderr), "{args:?}: stderr was {text:?}");
    }
}

/// Started as `secure-host`, the binary has only the host's commands,
/// and its setup refuses a run's table before it checks for root.
#[test]
fn secure_host_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("secure-host");
    std::fs::copy(BIN, &bin).unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "[agent]\nname = \"claude\"\n").unwrap();
    let config = config.to_str().unwrap();
    let cases: &[(&[&str], i32, &str)] = &[
        (&["--version"], 0, ""),
        (&["run"], ERROR, "unrecognized subcommand"),
        (&["inference", config], ERROR, "unrecognized subcommand"),
        (
            &["setup", "--config", config],
            ERROR,
            "unknown field `agent`",
        ),
    ];
    for (args, code, stderr) in cases {
        let output = Command::new(&bin).args(*args).output().unwrap();
        assert_eq!(output.status.code(), Some(*code), "{args:?}");
        let text = String::from_utf8_lossy(&output.stderr);
        assert!(text.contains(stderr), "{args:?}: stderr was {text:?}");
    }
    let version = Command::new(&bin).arg("--version").output().unwrap();
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("secure-host "));
}
