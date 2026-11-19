//! The acceptance run and its step summary. Fresh disposable hosts only:
//! never run this inside an existing sandbox.

use crate::command::run;
use anyhow::{Context, Result, bail};
use regex::Regex;
use std::io::Write;
use std::time::{Duration, Instant};

const INPUTS: &[&str] = &[
    "secure-host/binary.sh",
    "crates/secure-host/bpf/build.sh",
    "crates/secure-host/bpf/world_write.bpf.c",
    "crates/secure-host/bpf/world_write_policy.h",
];
const OBJECT: &str = "world_write.bpf.o";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
/// Each stage's output in the summary is cut to this many UTF-16 code
/// units, as the JavaScript original's `slice` did.
const MAX_STAGE_OUTPUT: usize = 16_384;
const FENCE: &str = "```";
const FENCE_ESCAPED: &str = "'''";

const APT_INSTALL: &[&str] = &[
    "apt-get",
    "-o",
    "Acquire::Retries=3",
    "install",
    "-y",
    "--no-install-recommends",
];
const DNF_INSTALL: &[&str] = &["dnf", "install", "-y"];
const RHEL_PACKAGES: &[&str] = &["clang", "bpftool", "util-linux"];

// The stages, in order; the summary names each.
const ADMISSION: &str = "Host admission";
const SOURCE: &str = "Host and source";
const PACKAGES: &str = "Required packages";
const BUILD: &str = "Build inputs and object SHA-256";
const BASELINE: &str = "Baseline: foreign and owner writes succeed";
const POLICY: &str = "Policy active: every link checked, map enabled, denial and owner control";
const AFTER: &str =
    "After loader exits: foreign write EACCES, owner write succeeds; operation matrix";
const LOADER: &str = "Loader version";

/// What the evidence run does to the outside world, replaceable in tests.
pub trait Host {
    /// Runs a command to completion, returning its standard output.
    fn run(&mut self, program: &str, args: &[&str]) -> Result<String>;
    /// The SHA-256 of a file, in hex.
    fn hash(&mut self, path: &str) -> Result<String>;
    /// The commands that compile the policy object into `out`.
    fn build(&mut self, out: &str) -> Result<Vec<Vec<String>>>;
    fn publish(&mut self, text: &str) -> Result<()>;
    /// Seconds since an arbitrary fixed point.
    fn clock(&mut self) -> f64;
}

/// The real host: commands, files and the step summary.
pub struct RealHost {
    pub summary: String,
    pub start: Instant,
}

impl Host for RealHost {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<String> {
        run(program, args, true, COMMAND_TIMEOUT)
    }

    fn hash(&mut self, path: &str) -> Result<String> {
        let data = std::fs::read(path).with_context(|| format!("reading {path}"))?;
        let digest = ring::digest::digest(&ring::digest::SHA256, &data);
        Ok(digest.as_ref().iter().map(|b| format!("{b:02x}")).collect())
    }

    /// As the release build compiles it.
    fn build(&mut self, out: &str) -> Result<Vec<Vec<String>>> {
        let command = ["bash", "secure-host/binary.sh", "object", "--out", out];
        Ok(vec![command.map(str::to_owned).to_vec()])
    }

    fn publish(&mut self, text: &str) -> Result<()> {
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.summary)
            .and_then(|mut f| f.write_all(text.as_bytes()))
            .with_context(|| format!("appending to {}", self.summary))
    }

    fn clock(&mut self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }
}

/// Text for a fenced block: no fence inside, and at most the cap.
fn fenced(text: &str) -> String {
    let text = text.replace(FENCE, FENCE_ESCAPED);
    let mut units = 0;
    for (i, c) in text.char_indices() {
        units += c.len_utf16();
        if units > MAX_STAGE_OUTPUT {
            return text[..i].to_owned();
        }
    }
    text
}

fn os_id_is(os_release: &str, id: &str) -> bool {
    let pattern = format!(r#"(?m)^ID=["']?{}["']?$"#, regex::escape(id));
    Regex::new(&pattern).is_ok_and(|re| re.is_match(os_release))
}

struct Summary<'h, H: Host> {
    host: &'h mut H,
    lines: Vec<String>,
}

impl<H: Host> Summary<'_, H> {
    fn stage(&mut self, name: &str, action: impl FnOnce(&mut H) -> Result<String>) -> Result<()> {
        let start = self.host.clock();
        let result = action(&mut *self.host);
        let elapsed = self.host.clock() - start;
        let (verdict, text) = match &result {
            Ok(output) => ("PASS", output.clone()),
            Err(e) => ("FAIL", format!("{e:#}")),
        };
        self.lines.extend([
            format!("### {name}: {verdict} ({elapsed:.3} s)"),
            String::new(),
            format!("{FENCE}text"),
            fenced(&text),
            FENCE.to_owned(),
            String::new(),
        ]);
        result.map(drop)
    }
}

/// Records success only after each assertion-bearing command exits successfully.
/// A failed probe must never leave a green-looking acceptance summary.
/// `binary` is this checkout's agentic-job, which admits the host and loads
/// the policy as the secure-host action does; `exe` is this executable, whose
/// `host` mode root runs before and after loading.
pub fn evidence(
    out: &str,
    binary: &str,
    exe: &str,
    os_release: &str,
    host: &mut impl Host,
) -> Result<()> {
    let header = [
        "## World-write acceptance",
        "",
        "Threat: an unprivileged process changing another user's globally writable root-filesystem objects.",
        "Fresh host only; no fallback. RHEL results must not be inferred from Ubuntu.",
        "",
    ];
    let mut summary = Summary {
        host,
        lines: header.map(str::to_owned).to_vec(),
    };
    let result = stages(&mut summary, out, binary, exe, os_release);
    let verdict = if result.is_ok() {
        "**PASS: all controls passed.**"
    } else {
        "**FAIL: acceptance incomplete; do not run untrusted steps.**"
    };
    summary.lines.extend([verdict.to_owned(), String::new()]);
    let text = summary.lines.join("\n");
    summary.host.publish(&text)?;
    result
}

fn stages<H: Host>(
    s: &mut Summary<'_, H>,
    out: &str,
    binary: &str,
    exe: &str,
    os_release: &str,
) -> Result<()> {
    let object = format!("{out}/{OBJECT}");
    let admit = ["secure-host", "supported"];
    s.stage(ADMISSION, |h| h.run(binary, &admit))?;
    s.stage(SOURCE, |h| {
        let mut parts = vec![
            h.run("git", &["rev-parse", "HEAD"])?,
            h.run("uname", &["-a"])?,
            os_release.to_owned(),
        ];
        for path in INPUTS {
            parts.push(format!("{}  {path}", h.hash(path)?));
        }
        Ok(parts.join("\n"))
    })?;
    s.stage(PACKAGES, |h| packages(h, binary, os_release))?;
    s.stage(BUILD, |h| build(h, out, &object))?;
    let before = [exe, "host", "before"];
    s.stage(BASELINE, |h| h.run("sudo", &before))?;
    let load = [binary, "secure-host", "world-write", object.as_str()];
    s.stage(POLICY, |h| h.run("sudo", &load))?;
    let after = [exe, "host", "after"];
    s.stage(AFTER, |h| h.run("sudo", &after))?;
    let version = ["bpftool", "version"];
    s.stage(LOADER, |h| h.run("sudo", &version))?;
    Ok(())
}

/// Installs what the build and loader need, by distribution, and lists the
/// installed versions. There is no fallback between distributions.
fn packages(h: &mut impl Host, binary: &str, os_release: &str) -> Result<String> {
    if os_id_is(os_release, "ubuntu") {
        h.run("sudo", &[binary, "secure-host", "apt"])?;
        let tools = format!("linux-tools-{}", h.run("uname", &["-r"])?.trim());
        let packages = ["clang", "linux-tools-common", &tools, "util-linux"];
        h.run("sudo", &[APT_INSTALL, &packages[..]].concat())?;
        return h.run("dpkg-query", &[&["-W"][..], &packages[..]].concat());
    }
    if os_id_is(os_release, "rhel") {
        h.run("sudo", &[DNF_INSTALL, RHEL_PACKAGES].concat())?;
        return h.run("rpm", &[&["-q"][..], RHEL_PACKAGES].concat());
    }
    bail!("unsupported evidence host")
}

/// Builds the object, recording each command, then reports the compiler
/// and the object's digest.
fn build(h: &mut impl Host, out: &str, object: &str) -> Result<String> {
    let mut commands = Vec::new();
    for command in h.build(out)? {
        let Some((program, args)) = command.split_first() else {
            bail!("empty build command");
        };
        commands.push(serde_json::to_string(&command)?);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        h.run(program, &args)?;
    }
    let mut parts = vec![h.run("clang", &["--version"])?];
    parts.extend(commands);
    parts.push(format!("{}  {OBJECT}", h.hash(object)?));
    Ok(parts.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNSUPPORTED: &str = "secure-host: requires Ubuntu 26.04 or RHEL 10";
    const UBUNTU: &str = "ID=ubuntu\nVERSION_ID=26.04\n";
    const OLD_UBUNTU: &str = "ID=ubuntu\nVERSION_ID=24.04\n";
    const RHEL: &str = "ID=\"rhel\"\nVERSION_ID=\"10.1\"\n";
    const OUT: &str = "/tmp/object";
    const BINARY: &str = "/tmp/agentic-job";
    const EXE: &str = "/tmp/world-write-evidence";

    /// Whether `arg` is `failure`, or a path ending in it.
    fn fails(arg: &str, failure: &str) -> bool {
        let parent = arg.strip_suffix(failure);
        arg == failure || parent.is_some_and(|p| p.ends_with('/'))
    }

    #[derive(Default)]
    struct Fake {
        /// An argument (or a path ending in `/` and it) that fails `run`.
        failure: Option<&'static str>,
        /// Every command fails with this message.
        refuse_all: Option<&'static str>,
        /// Build returns no commands, as a hook that only records does.
        build_nothing: bool,
        built: bool,
        calls: Vec<Vec<String>>,
        summary: Option<String>,
    }

    impl Host for Fake {
        fn run(&mut self, program: &str, args: &[&str]) -> Result<String> {
            let call = std::iter::once(program).chain(args.iter().copied());
            self.calls.push(call.map(str::to_owned).collect());
            if let Some(message) = self.refuse_all {
                bail!("{message}");
            }
            if let Some(f) = self.failure
                && args.iter().any(|a| fails(a, f))
            {
                bail!("probe failed");
            }
            Ok("fixture output".to_owned())
        }

        fn hash(&mut self, _: &str) -> Result<String> {
            if self.failure == Some("hash") {
                bail!("hash failed");
            }
            Ok("a".repeat(64))
        }

        fn build(&mut self, out: &str) -> Result<Vec<Vec<String>>> {
            self.built = true;
            if self.failure == Some("build") {
                bail!("compiler failed");
            }
            if self.build_nothing {
                return Ok(Vec::new());
            }
            let object = format!("{out}/{OBJECT}");
            let command = ["clang", "-target", "bpfel", "-o", &object];
            Ok(vec![command.map(str::to_owned).to_vec()])
        }

        fn publish(&mut self, text: &str) -> Result<()> {
            self.summary = Some(text.to_owned());
            Ok(())
        }

        fn clock(&mut self) -> f64 {
            0.0
        }
    }

    impl Fake {
        fn called_with(&self, arg: &str) -> bool {
            self.calls.iter().any(|call| call.iter().any(|a| a == arg))
        }
    }

    #[test]
    fn evidence_fails_closed() {
        for failure in [
            None,
            Some("supported"),
            Some("before"),
            Some("world-write"),
            Some("after"),
            Some("build"),
            Some("install"),
            Some("-W"),
            Some("HEAD"),
            Some("version"),
            Some("hash"),
        ] {
            let mut fake = Fake {
                failure,
                ..Fake::default()
            };
            let result = evidence(OUT, BINARY, EXE, UBUNTU, &mut fake);
            assert_eq!(result.is_err(), failure.is_some(), "{failure:?}");
            let summary = fake.summary.as_deref().expect("published");
            let passed = summary.contains("PASS: all controls passed");
            assert_eq!(passed, failure.is_none(), "{failure:?}: {summary}");
            if failure.is_some() {
                let failed = summary.contains("FAIL: acceptance incomplete");
                assert!(failed, "{summary}");
                let reported = ["probe failed", "compiler failed", "hash failed"];
                assert!(reported.iter().any(|r| summary.contains(r)), "{summary}");
            } else {
                let after = "foreign write EACCES, owner write succeeds";
                assert!(summary.contains("world_write.bpf.o"));
                assert!(summary.contains(after));
                assert!(fake.called_with("after"));
            }
            let before_after = ["supported", "before", "world-write", "build"];
            if failure.is_some_and(|f| before_after.contains(&f)) {
                assert!(!fake.called_with("after"), "{failure:?}");
            }
        }
    }

    #[test]
    fn rhel_package_evidence_uses_the_same_controls_without_an_ubuntu_fallback() {
        let mut fake = Fake {
            build_nothing: true,
            ..Fake::default()
        };
        evidence(OUT, BINARY, EXE, RHEL, &mut fake).unwrap();
        assert!(fake.called_with("dnf"));
        assert!(fake.called_with("rpm"));
        assert!(fake.called_with("after"));
        assert!(!fake.called_with("apt-get"));
    }

    #[test]
    fn an_unsupported_host_fails_at_admission_before_any_other_command_or_build() {
        let mut fake = Fake {
            refuse_all: Some(UNSUPPORTED),
            ..Fake::default()
        };
        let err = evidence(OUT, BINARY, EXE, OLD_UBUNTU, &mut fake).unwrap_err();
        assert!(err.to_string().contains("requires Ubuntu 26.04 or RHEL 10"));
        assert_eq!(fake.calls, vec![vec![BINARY, "secure-host", "supported"]]);
        assert!(!fake.built, "must not build");
        assert!(fake.summary.unwrap().contains("Host admission: FAIL"));
    }

    #[test]
    fn an_unknown_os_is_refused_without_installing() {
        let mut fake = Fake::default();
        let err = evidence(OUT, BINARY, EXE, "ID=debian\n", &mut fake).unwrap_err();
        assert!(err.to_string().contains("unsupported evidence host"));
        assert!(!fake.called_with("apt-get") && !fake.called_with("dnf"));
        assert!(!fake.built);
    }

    #[test]
    fn matches_os_release_ids_like_the_original_pattern() {
        for (text, id, want) in [
            ("ID=ubuntu\n", "ubuntu", true),
            ("NAME=x\nID=\"rhel\"\n", "rhel", true),
            ("ID='ubuntu'", "ubuntu", true),
            ("ID_LIKE=ubuntu\n", "ubuntu", false),
            ("ID=ubuntu-core\n", "ubuntu", false),
            (" ID=ubuntu\n", "ubuntu", false),
        ] {
            assert_eq!(os_id_is(text, id), want, "{text:?}");
        }
    }

    #[test]
    fn stage_output_is_fenced_and_capped() {
        assert_eq!(fenced("a ``` b"), "a ''' b");
        let cut = |s: &str, n| fenced(&s.repeat(n)).chars().count();
        assert_eq!(cut("x", 20_000), MAX_STAGE_OUTPUT);
        // Cut after escaping.
        assert_eq!(cut("```", 6_000), MAX_STAGE_OUTPUT);
        // Counted in UTF-16 code units, and never inside a character.
        assert_eq!(cut("é", 20_000), MAX_STAGE_OUTPUT);
        assert_eq!(cut("😀", 9_000), MAX_STAGE_OUTPUT / 2);
    }

    #[test]
    fn summary_reports_each_stage_and_its_time() {
        let mut fake = Fake {
            failure: Some("after"),
            ..Fake::default()
        };
        assert!(evidence(OUT, BINARY, EXE, UBUNTU, &mut fake).is_err());
        let summary = fake.summary.unwrap();
        assert!(summary.starts_with("## World-write acceptance\n\n"));
        let baseline = format!("### {BASELINE}: PASS (0.000 s)\n\n```text\nfixture output\n```\n");
        assert!(summary.contains(&baseline), "{summary}");
        let after = format!("### {AFTER}: FAIL (0.000 s)\n\n```text\nprobe failed\n```\n");
        assert!(summary.contains(&after), "{summary}");
        assert!(!summary.contains(LOADER));
        let verdict = "**FAIL: acceptance incomplete; do not run untrusted steps.**\n";
        assert!(summary.ends_with(verdict), "{summary}");
        let host = [EXE, "host", "before"];
        assert!(fake.calls.iter().any(|c| c[0] == "sudo" && c[1..] == host));
    }
}
