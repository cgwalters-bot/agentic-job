//! The built binary's exit states, which the unit tests cannot see.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

/// What `exit::ERROR` is; spelled out because it is the interface.
const ERROR: i32 = 2;

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

/// `config` reads `[sandbox]`, `[host]`'s deprecated name, with a warning
/// on standard error only, so that the TOML it prints stays a file. It
/// writes `[host]`, but `[sandbox]` in a host's file for the pinned image,
/// one with no `[host.prepared]`.
#[test]
fn config_warns_of_the_old_table_name_on_stderr() {
    const WARNING: &str = "warning: [sandbox] is the deprecated name of [host]";
    const RUN: &str = "[agent]\nname = \"fake\"\n[limits]\ntimeout-minutes = 10\nbudget = 100\n";
    let dir = tempfile::tempdir().unwrap();
    // The file's tables, the arguments after `config --from FILE`, and
    // the host table's name in what is printed (none for an error).
    let cases: &[(&str, &[&str], Option<&str>)] = &[
        ("[host]\nlock-runner = true\n", &["--host"], Some("sandbox")),
        (
            "[sandbox]\nlock-runner = true\n",
            &["--host"],
            Some("sandbox"),
        ),
        (
            "",
            &["--host", "--string", "sandbox.runner-user=runner"],
            Some("sandbox"),
        ),
        (
            "[sandbox]\nlock-runner = true\n",
            &["--host", "--prepared"],
            Some("host"),
        ),
        ("[sandbox]\nlock-runner = true\n", &[], Some("host")),
        ("[host]\nlock-runner = true\n", &[], Some("host")),
        (
            "",
            &["--string", "sandbox.runner-user=runner"],
            Some("host"),
        ),
        ("[host]\n[sandbox]\n", &["--host"], None),
    ];
    for (i, (tables, args, name)) in cases.iter().enumerate() {
        let from = dir.path().join(format!("{i}.toml"));
        std::fs::write(&from, format!("{RUN}{tables}")).unwrap();
        let output = Command::new(BIN)
            .args(["config", "--from", from.to_str().unwrap()])
            .args(*args)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let case = format!("{tables:?} {args:?}: {stderr}");
        let Some(name) = name else {
            assert_eq!(output.status.code(), Some(ERROR), "{case}");
            assert!(stderr.contains("both set"), "{case}");
            assert!(stdout.is_empty(), "{case}: {stdout}");
            continue;
        };
        assert_eq!(output.status.code(), Some(0), "{case}");
        let legacy = tables.contains("[sandbox]") || args.iter().any(|a| a.starts_with("sandbox."));
        assert_eq!(stderr.contains(WARNING), legacy, "{case}");
        assert!(!stdout.contains("warning"), "{case}: {stdout}");
        let printed: toml::Table = toml::from_str(&stdout).unwrap();
        let other = if *name == "host" { "sandbox" } else { "host" };
        assert!(
            printed.contains_key(*name) && !printed.contains_key(other),
            "{case}: {stdout}"
        );
    }
}
