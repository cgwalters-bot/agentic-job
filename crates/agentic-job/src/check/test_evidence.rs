//! Repeated-test evidence (docs/dispatch.md#repeated-test-evidence-and-acceptance):
//! `test-evidence.json`, a manifest of one test run some number of times
//! on the patched tree, and one log per attempt beside it in the hand-back,
//! each `test-evidence-N.log`. `run` packs them from the agent's `~/out`
//! where the policy has `[test_evidence]`; this holds them to it again.
//!
//! What is checked is the manifest's shape and bounds and its association
//! with the checked patch, never that the tests say what is true: its
//! `base` and `head` must be the commit the checked patch applies to, and
//! apply refuses its `tree` unless applying that patch there makes it
//! (`agentic-job test-evidence`). Every attempt the manifest plans has to
//! be in it, in order, with an outcome and a regular-file log, so a
//! failed, skipped or cancelled attempt cannot be dropped to leave a run
//! of passes.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use anyhow::{Result, anyhow, ensure};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::error::Category;

use crate::policy::{COMMIT_RE, MAX_TEST_ATTEMPTS, TestEvidence as Rules};

pub const TEST_EVIDENCE_FILE: &str = "test-evidence.json";
/// The manifest's version: another is refused, not read as this one.
pub const SCHEMA: &str = "agentic-job/test-evidence/v1";
/// The most the manifest may hold: its fields are short, and there are at
/// most [`crate::policy::MAX_TEST_ATTEMPTS`] attempts.
pub const MAX_MANIFEST_BYTES: u64 = 64 << 10;
/// How much of a log is read where the policy allows no evidence: it is
/// refused whatever it holds, but read with a bound like the rest.
pub const MAX_UNEXPECTED_LOG_BYTES: u64 = 4096;
const LOG_PREFIX: &str = "test-evidence-";
const LOG_SUFFIX: &str = ".log";
/// The longest attempt the manifest may report: a day, well over the
/// external runner's 300-minute lifetime.
const MAX_DURATION_S: u64 = 24 * 60 * 60;
const MAX_COMMAND_CHARS: usize = 1024;

/// An image, test or profile name: shown in the draft in a code span, so
/// nothing that ends one or starts markup.
static NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:/@+=-]{0,255}$").expect("a valid pattern")
});

/// The log of attempt N.
pub fn log_name(attempt: u32) -> String {
    format!("{LOG_PREFIX}{attempt}{LOG_SUFFIX}")
}

/// Whether NAME is an attempt's log, of an attempt up to the ceiling every
/// bound is under: one of an attempt beyond the policy's own bound is
/// read and refused for that, any other name unread as a stray file.
pub fn is_log_name(name: &str) -> bool {
    (1..=MAX_TEST_ATTEMPTS).any(|attempt| name == log_name(attempt))
}

/// `test-evidence.json`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    /// The commit checked out and tested, which the patch applies to.
    pub base: String,
    pub head: String,
    /// The tree of `base` with the patch applied.
    pub tree: String,
    pub image: String,
    pub test: String,
    pub command: String,
    pub profile: String,
    pub resources: Resources,
    pub planned_attempts: u32,
    pub attempts: Vec<Attempt>,
}

/// The effective resources the tests ran with.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub attempt: u32,
    pub outcome: Outcome,
    pub duration_s: u64,
    pub log: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Pass,
    Fail,
    Skipped,
    NotRun,
}

/// What the report says of accepted evidence: names check held to
/// [`NAME_RE`], commits and counts, never the command or the logs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub test: String,
    pub image: String,
    pub profile: String,
    pub base: String,
    pub tree: String,
    pub planned: u32,
    pub pass: u32,
    pub fail: u32,
    pub skipped: u32,
    pub not_run: u32,
}

impl Info {
    /// Whether every planned attempt passed: one pass after failures is
    /// not a repeated pass, nor is a skipped or cancelled attempt.
    pub fn all_passed(&self) -> bool {
        self.planned > 0 && self.pass == self.planned
    }

    /// One line of Markdown for the check's summary and the draft.
    pub fn line(&self) -> String {
        format!(
            "test evidence: `{}` on `{}` (`{}`), {} attempt(s) planned: {} pass, {} fail, \
             {} skipped, {} not run; {}. This is the run's own report: check held it to the \
             patch's base, not its results to the truth.",
            self.test,
            self.profile,
            self.image,
            self.planned,
            self.pass,
            self.fail,
            self.skipped,
            self.not_run,
            if self.all_passed() {
                "every attempt passed"
            } else {
                "not every attempt passed"
            }
        )
    }
}

/// Checks CONTENT, the manifest, under RULES, against PATCH_BASE, the
/// commit the checked patch applies to, with LOGS the names of the logs
/// the hand-back holds, each a regular file within the rules' bound.
pub fn check(
    content: &[u8],
    logs: &BTreeSet<&str>,
    rules: &Rules,
    patch_base: &str,
) -> Result<Info> {
    // Serde quotes what it refuses, decoded: say where, never what.
    let manifest: Manifest =
        serde_json::from_slice(content).map_err(|err| match err.classify() {
            Category::Data => anyhow!(
                "{TEST_EVIDENCE_FILE} is not a manifest of {SCHEMA}, at line {} column {}",
                err.line(),
                err.column()
            ),
            _ => err.into(),
        })?;
    ensure!(
        manifest.schema == SCHEMA,
        "{TEST_EVIDENCE_FILE}'s schema is not {SCHEMA}"
    );
    for (key, commit) in [
        ("base", &manifest.base),
        ("head", &manifest.head),
        ("tree", &manifest.tree),
    ] {
        ensure!(
            COMMIT_RE.is_match(commit),
            "{TEST_EVIDENCE_FILE}'s {key} is not a full object ID"
        );
    }
    for (key, commit) in [("base", &manifest.base), ("head", &manifest.head)] {
        ensure!(
            commit == patch_base,
            "{TEST_EVIDENCE_FILE}'s {key} {commit} is not {patch_base}, the commit the checked \
             patch applies to: the tests ran on another tree"
        );
    }
    for (key, name) in [
        ("image", &manifest.image),
        ("test", &manifest.test),
        ("profile", &manifest.profile),
    ] {
        ensure!(
            NAME_RE.is_match(name),
            "{TEST_EVIDENCE_FILE}'s {key} is not a name of letters, digits and ._:/@+=-"
        );
    }
    ensure!(
        !manifest.command.is_empty()
            && manifest.command.chars().count() <= MAX_COMMAND_CHARS
            && !manifest.command.chars().any(char::is_control),
        "{TEST_EVIDENCE_FILE}'s command is not one line of 1 to {MAX_COMMAND_CHARS} characters"
    );
    let resources = &manifest.resources;
    ensure!(
        resources.cpus > 0 && resources.memory_mib > 0 && resources.disk_gib > 0,
        "{TEST_EVIDENCE_FILE}'s resources are not all above zero"
    );
    ensure!(
        (1..=rules.max_attempts).contains(&manifest.planned_attempts),
        "{TEST_EVIDENCE_FILE} plans {} attempts, not 1 to {}",
        manifest.planned_attempts,
        rules.max_attempts
    );
    ensure!(
        manifest.attempts.len() == manifest.planned_attempts as usize,
        "{TEST_EVIDENCE_FILE} plans {} attempts and reports {}: every planned attempt is \
         reported, failed, skipped or not run",
        manifest.planned_attempts,
        manifest.attempts.len()
    );
    let mut info = Info {
        test: manifest.test,
        image: manifest.image,
        profile: manifest.profile,
        base: manifest.base,
        tree: manifest.tree,
        planned: manifest.planned_attempts,
        pass: 0,
        fail: 0,
        skipped: 0,
        not_run: 0,
    };
    let mut named = BTreeSet::new();
    for (n, attempt) in (1..).zip(&manifest.attempts) {
        ensure!(
            attempt.attempt == n,
            "{TEST_EVIDENCE_FILE}'s attempt {n} is numbered {}: attempts are 1 to {} in order, \
             each once",
            attempt.attempt,
            manifest.planned_attempts
        );
        ensure!(
            attempt.duration_s <= MAX_DURATION_S,
            "{TEST_EVIDENCE_FILE}'s attempt {n} took {} s, over {MAX_DURATION_S}",
            attempt.duration_s
        );
        let want = log_name(n);
        ensure!(
            attempt.log == want,
            "{TEST_EVIDENCE_FILE}'s attempt {n} names a log other than {want}"
        );
        ensure!(
            logs.contains(want.as_str()),
            "{TEST_EVIDENCE_FILE}'s attempt {n} has no log, {want}"
        );
        named.insert(want);
        *match attempt.outcome {
            Outcome::Pass => &mut info.pass,
            Outcome::Fail => &mut info.fail,
            Outcome::Skipped => &mut info.skipped,
            Outcome::NotRun => &mut info.not_run,
        } += 1;
    }
    if let Some(extra) = logs.iter().find(|log| !named.contains(**log)) {
        return Err(anyhow!(
            "{extra} is the log of no attempt {TEST_EVIDENCE_FILE} reports"
        ));
    }
    Ok(info)
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::{Value, json};

    use super::*;

    pub(crate) const BASE: &str = "1111111111111111111111111111111111111111";
    pub(crate) const TREE: &str = "2222222222222222222222222222222222222222";

    /// Three attempts: two failures, then a pass.
    pub(crate) fn manifest() -> Value {
        json!({
            "schema": SCHEMA,
            "base": BASE,
            "head": BASE,
            "tree": TREE,
            "image": "quay.io/example/bootc@sha256:abc",
            "test": "install-to-disk",
            "command": "cargo xtask test-install --repeat 3",
            "profile": "devspace-rhel10-64",
            "resources": {"cpus": 64, "memory_mib": 262144, "disk_gib": 500},
            "planned_attempts": 3,
            "attempts": [
                {"attempt": 1, "outcome": "fail", "duration_s": 600, "log": "test-evidence-1.log"},
                {"attempt": 2, "outcome": "fail", "duration_s": 610, "log": "test-evidence-2.log"},
                {"attempt": 3, "outcome": "pass", "duration_s": 590, "log": "test-evidence-3.log"},
            ],
        })
    }

    pub(crate) fn rules() -> Rules {
        Rules {
            max_attempts: 3,
            max_log_bytes: 1024,
        }
    }

    #[test]
    fn log_names() {
        for (name, log) in [
            ("test-evidence-1.log", true),
            ("test-evidence-10.log", true),
            ("test-evidence-11.log", false),
            ("test-evidence-99.log", false),
            ("test-evidence-0.log", false),
            ("test-evidence-01.log", false),
            ("test-evidence-.log", false),
            ("test-evidence-1.txt", false),
            ("test-evidence-1.log.sh", false),
            ("test-evidence.json", false),
        ] {
            assert_eq!(is_log_name(name), log, "{name}");
        }
        assert_eq!(log_name(3), "test-evidence-3.log");
    }

    #[test]
    fn what_evidence_is_accepted() {
        let all = [
            "test-evidence-1.log",
            "test-evidence-2.log",
            "test-evidence-3.log",
        ];
        let with = |change: &dyn Fn(&mut Value)| {
            let mut manifest = manifest();
            change(&mut manifest);
            manifest
        };
        let three_passes = with(&|m| {
            for attempt in m["attempts"].as_array_mut().unwrap() {
                attempt["outcome"] = json!("pass");
            }
        });
        // (the case, the manifest, the logs, the counts or what refuses it)
        type Case<'a> = (&'a str, Value, &'a [&'a str], Result<[u32; 4], &'a str>);
        let cases: &[Case] = &[
            (
                "two failures and a pass",
                manifest(),
                &all,
                Ok([1, 2, 0, 0]),
            ),
            ("three passes", three_passes, &all, Ok([3, 0, 0, 0])),
            (
                "skipped and not run are kept",
                with(&|m| {
                    m["attempts"][0]["outcome"] = json!("skipped");
                    m["attempts"][1]["outcome"] = json!("not-run");
                }),
                &all,
                Ok([1, 0, 1, 1]),
            ),
            (
                "not JSON",
                json!("{"),
                &all,
                Err("is not a manifest of agentic-job/test-evidence/v1"),
            ),
            (
                "an unknown field",
                with(&|m| m["digest"] = json!("sha256:0")),
                &all,
                Err("is not a manifest"),
            ),
            (
                "a missing field",
                with(&|m| {
                    m.as_object_mut().unwrap().remove("tree");
                }),
                &all,
                Err("is not a manifest"),
            ),
            (
                "an unknown outcome",
                with(&|m| m["attempts"][0]["outcome"] = json!("flaky")),
                &all,
                Err("is not a manifest"),
            ),
            (
                "another schema",
                with(&|m| m["schema"] = json!("agentic-job/test-evidence/v2")),
                &all,
                Err("schema is not agentic-job/test-evidence/v1"),
            ),
            (
                "another base",
                with(&|m| m["base"] = json!(TREE)),
                &all,
                Err("base 2222222222222222222222222222222222222222 is not 1111"),
            ),
            (
                "another head",
                with(&|m| m["head"] = json!(TREE)),
                &all,
                Err("head 2222222222222222222222222222222222222222 is not 1111"),
            ),
            (
                "a short tree",
                with(&|m| m["tree"] = json!("2222")),
                &all,
                Err("tree is not a full object ID"),
            ),
            (
                "an image with markup",
                with(&|m| m["image"] = json!("a`b")),
                &all,
                Err("image is not a name"),
            ),
            (
                "a two-line command",
                with(&|m| m["command"] = json!("true\nfalse")),
                &all,
                Err("command is not one line"),
            ),
            (
                "no memory",
                with(&|m| m["resources"]["memory_mib"] = json!(0)),
                &all,
                Err("resources are not all above zero"),
            ),
            (
                "more attempts than the bound",
                with(&|m| {
                    m["planned_attempts"] = json!(4);
                    m["attempts"].as_array_mut().unwrap().push(json!(
                        {"attempt": 4, "outcome": "pass", "duration_s": 1, "log": "test-evidence-4.log"}
                    ));
                }),
                &[
                    "test-evidence-1.log",
                    "test-evidence-2.log",
                    "test-evidence-3.log",
                    "test-evidence-4.log",
                ],
                Err("plans 4 attempts, not 1 to 3"),
            ),
            (
                "none planned",
                with(&|m| {
                    m["planned_attempts"] = json!(0);
                    m["attempts"] = json!([]);
                }),
                &[],
                Err("plans 0 attempts, not 1 to 3"),
            ),
            (
                "a dropped attempt",
                with(&|m| {
                    m["attempts"].as_array_mut().unwrap().remove(0);
                }),
                &all[1..],
                Err("plans 3 attempts and reports 2"),
            ),
            (
                "an extra attempt",
                with(&|m| {
                    m["planned_attempts"] = json!(2);
                }),
                &all,
                Err("plans 2 attempts and reports 3"),
            ),
            (
                "a duplicate attempt",
                with(&|m| m["attempts"][1]["attempt"] = json!(1)),
                &all,
                Err("attempt 2 is numbered 1"),
            ),
            (
                "an attempt out of order",
                with(&|m| {
                    m["attempts"][0]["attempt"] = json!(2);
                    m["attempts"][1]["attempt"] = json!(1);
                }),
                &all,
                Err("attempt 1 is numbered 2"),
            ),
            (
                "an endless attempt",
                with(&|m| m["attempts"][2]["duration_s"] = json!(MAX_DURATION_S + 1)),
                &all,
                Err("attempt 3 took 86401 s, over 86400"),
            ),
            (
                "a log path that escapes",
                with(&|m| m["attempts"][0]["log"] = json!("../outputs.jsonl")),
                &all,
                Err("attempt 1 names a log other than test-evidence-1.log"),
            ),
            (
                "a log under a directory",
                with(&|m| m["attempts"][0]["log"] = json!("logs/test-evidence-1.log")),
                &all,
                Err("attempt 1 names a log other than test-evidence-1.log"),
            ),
            (
                "another attempt's log",
                with(&|m| m["attempts"][0]["log"] = json!("test-evidence-2.log")),
                &all,
                Err("attempt 1 names a log other than test-evidence-1.log"),
            ),
            (
                "a missing log",
                manifest(),
                &all[..2],
                Err("attempt 3 has no log, test-evidence-3.log"),
            ),
            (
                "a log of no attempt",
                manifest(),
                &[
                    "test-evidence-1.log",
                    "test-evidence-2.log",
                    "test-evidence-3.log",
                    "test-evidence-4.log",
                ],
                Err("test-evidence-4.log is the log of no attempt"),
            ),
        ];
        for (name, manifest, logs, want) in cases {
            let logs: BTreeSet<&str> = logs.iter().copied().collect();
            let got = check(manifest.to_string().as_bytes(), &logs, &rules(), BASE);
            match (got, want) {
                (Ok(info), Ok(counts)) => {
                    assert_eq!(
                        [info.pass, info.fail, info.skipped, info.not_run],
                        *counts,
                        "{name}"
                    );
                    assert_eq!(info.all_passed(), counts[0] == 3, "{name}");
                    assert_eq!((info.base.as_str(), info.tree.as_str()), (BASE, TREE));
                }
                (Err(err), Err(want)) => {
                    assert!(format!("{err:#}").contains(want), "{name}: {err:#}");
                }
                (got, _) => panic!("{name}: {got:?}"),
            }
        }
        // A duplicated key is refused, not read as either value.
        let twice = manifest().to_string().replacen(
            "\"planned_attempts\":3",
            "\"planned_attempts\":3,\"planned_attempts\":2",
            1,
        );
        let logs: BTreeSet<&str> = all.into_iter().collect();
        let err = check(twice.as_bytes(), &logs, &rules(), BASE).unwrap_err();
        assert!(format!("{err:#}").contains("is not a manifest"), "{err:#}");
        // Serde's reason would quote the value it refuses: not repeated.
        let quoted = with(&|m| m["attempts"][0]["outcome"] = json!("ghp_quoted"));
        let err = check(quoted.to_string().as_bytes(), &logs, &rules(), BASE).unwrap_err();
        assert!(!format!("{err:#}").contains("quoted"), "{err:#}");
    }

    /// One pass after two failures is not a repeated pass, in words too.
    #[test]
    fn the_line_does_not_call_a_late_pass_green() {
        let logs: BTreeSet<&str> = [
            "test-evidence-1.log",
            "test-evidence-2.log",
            "test-evidence-3.log",
        ]
        .into_iter()
        .collect();
        let info = check(manifest().to_string().as_bytes(), &logs, &rules(), BASE).unwrap();
        assert_eq!(
            info.line(),
            "test evidence: `install-to-disk` on `devspace-rhel10-64` \
             (`quay.io/example/bootc@sha256:abc`), 3 attempt(s) planned: 1 pass, 2 fail, \
             0 skipped, 0 not run; not every attempt passed. This is the run's own report: \
             check held it to the patch's base, not its results to the truth."
        );
    }
}
