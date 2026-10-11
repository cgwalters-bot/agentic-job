//! The patch reader of `check` against git itself.
//!
//! `check` decides from [`read_patch`] which files a patch touches, and a
//! later job gives the same bytes to `git am`. If the two disagree, the
//! check is bypassed: so here git is asked. First what `git format-patch`
//! writes for real commits, made with the options `run` uses, is read:
//! the reader must name the files git says the commit touches, or refuse
//! what it refuses on purpose. Then each patch it accepts is damaged in
//! many ways (a seeded generator, so a run is repeatable), and each
//! mutant is given to both readers: whenever the reader finds nothing
//! wrong and `git am` applies it, git must have changed no path the
//! reader did not name, none that is protected, and no file's mode.
//! That the reader refuses what git takes is expected, and only counted.

// clippy.toml lets test functions unwrap, but not the helpers they share.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use agentic_job::check::{BASE_COMMIT_HEADER, PatchReading, read_patch};
use agentic_job::policy::{DEFAULT_PROTECTED_FILES, ProtectedFilesPolicy, PullRequest};
use agentic_job::run::handback::commit_message;

/// Git with no configuration but what is given here, and commits that
/// are the same on every run.
const GIT_ENV: [(&str, &str); 10] = [
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_AUTHOR_NAME", "agent"),
    ("GIT_AUTHOR_EMAIL", "agent@localhost"),
    ("GIT_AUTHOR_DATE", "2026-01-02T03:04:05Z"),
    ("GIT_COMMITTER_NAME", "agent"),
    ("GIT_COMMITTER_EMAIL", "agent@localhost"),
    ("GIT_COMMITTER_DATE", "2026-01-02T03:04:05Z"),
    ("LC_ALL", "C"),
    ("TZ", "UTC"),
];

/// `run`'s settings for git on the agent's checkout (`GIT_SETTINGS` of
/// `run/handback.rs`).
const GIT_SETTINGS: &[&str] = &[
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "commit.gpgsign=false",
];

/// The apply job's configuration of its checkout (`agentic-job.yml`).
const APPLY_SETTINGS: &[&str] = &[
    "core.hooksPath=/dev/null",
    "merge.renames=false",
    "diff.renames=false",
    "am.keepcr=true",
];

/// How `run` has the patch written (`FORMAT_PATCH` of `run/handback.rs`),
/// but for the commits, which come last.
const FORMAT_PATCH: &[&str] = &[
    "format-patch",
    "--stdout",
    "--no-renames",
    "--no-signature",
    "--no-add-header",
    "--no-to",
    "--no-cc",
    "--no-from",
    "--no-signoff",
    "--no-attach",
    "--no-thread",
    "--no-numbered",
    "--no-cover-letter",
    "--no-base",
    "--subject-prefix=PATCH",
];

/// How `run` commits the change (`build_patch`), but for the message,
/// which is read from a file here.
const COMMIT: &[&str] = &["commit", "-q", "--no-verify", "--cleanup=whitespace", "-F"];

const RUN_ID: &str = "42";
const MAX_PATCH_FILES: u32 = 100;

/// The generator's start. Change it to look at another corpus; a failure
/// prints it with the mutant.
const SEED: u64 = 0x5eed_0fa9_a7c4_0001;

/// The least the corpus must hold for the comparison to mean anything:
/// mutants, those git applied, and those both readers took where git
/// changed something (an application that changes nothing compares
/// nothing).
const MIN_MUTANTS: usize = 800;
const MIN_APPLIED: usize = 300;
const MIN_ACCEPTED_BY_BOTH: usize = 100;

/// How many clones apply mutants at once, at most.
const MAX_WORKERS: usize = 8;

const NO_MODE: &str = "000000";
const PLAIN_MODE: &str = "100644";
const EXECUTABLE_MODE: &str = "100755";

/// The modes of what a patch may change: no file (on the side where one
/// is added or deleted), a plain file, an executable.
const FILE_MODES: &[&str] = &[NO_MODE, PLAIN_MODE, EXECUTABLE_MODE];

/// The content of `a.txt` and of every file a change to it can be
/// pointed at instead, so that git applies the change there.
const TEXT: &[u8] = b"one\ntwo\nthree\nfour\nfive\n";

/// Lines that are a file's content here, and would be a patch's or a
/// mail's own outside a hunk.
const TRICKY: &[u8] = b"-- a/.github/x\n++ b/.github/x\ndiff --git a/y b/y\n@@ -1 +1 @@\n\
    From 1111111111111111111111111111111111111111 Mon Sep 17 00:00:00 2001\n---\n-- \n\n\
    trailing \nlast\n";

/// One change to a working tree.
#[derive(Clone, Copy)]
enum Op {
    Write(&'static str, &'static [u8]),
    Executable(&'static str),
    Link(&'static str, &'static str),
    Remove(&'static str),
    Move(&'static str, &'static str),
    /// This many new files, under `many/`.
    Many(u32),
}

use Op::{Executable, Link, Many, Move, Remove, Write};

/// The tree every patch is against.
const BASE: &[Op] = &[
    Write("a.txt", TEXT),
    Write("twin.txt", TEXT),
    Write("README.md", TEXT),
    Write(".github/workflows/ci.yml", TEXT),
    Write("docs/CODEOWNERS", TEXT),
    Write("sub/.gitattributes", TEXT),
    Write("twin.sh", TEXT),
    Executable("twin.sh"),
    Link("link", "a.txt"),
    Write("gone.txt", b"gone\n"),
    Write("run.sh", b"#!/bin/sh\necho run\n"),
    Executable("run.sh"),
    Write("nonl.txt", b"no newline"),
    Write("crlf.txt", b"a\r\nb\r\n"),
    Write("empty.txt", b""),
    Write("blob.bin", b"\0\x01\x02bin\0"),
    Write("latin1.txt", b"caf\xe9\n"),
    Write("tricky.md", TRICKY),
    Write("src/deep/er/x.rs", b"fn x() {}\n"),
    Write("a b.txt", b"space\n"),
    Write("caf\u{e9}.txt", b"unicode\n"),
    Write("q\"uote.txt", b"quote\n"),
    Write(
        "long.txt",
        b"1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\n",
    ),
];

/// The message of a case's commit.
#[derive(Clone, Copy)]
enum Message {
    /// A pull request's title and body, as `run` makes a message of them.
    Run(&'static str, &'static str),
    /// The text as it is, which `run` would not write.
    Raw(&'static str),
}

/// What the reader is to make of a patch git wrote.
#[derive(Clone, Copy)]
enum Want {
    Accepted,
    /// Refused, with a problem that holds this.
    Refused(&'static str),
}

use Want::{Accepted, Refused};

struct Case {
    name: &'static str,
    /// The changes, each committed on top of the one before.
    steps: Vec<&'static [Op]>,
    message: Message,
    /// Whether the commits become one, as `run` hands a change back, or
    /// stay a series, which it never writes.
    squash: bool,
    want: Want,
}

fn case(name: &'static str, ops: &'static [Op], want: Want) -> Case {
    Case {
        name,
        steps: vec![ops],
        message: Message::Run("Change things", "Why they change."),
        squash: true,
        want,
    }
}

impl Case {
    fn message(mut self, message: Message) -> Self {
        self.message = message;
        self
    }

    fn then(mut self, ops: &'static [Op]) -> Self {
        self.steps.push(ops);
        self
    }

    fn series(mut self) -> Self {
        self.squash = false;
        self
    }
}

const EDIT: &[Op] = &[Write("a.txt", b"one\n2\nthree\nfour\nfive\n")];

/// What an agent may write in a pull request's body to be read as a
/// patch, a mail or a header: `run` indents each such line.
const HOSTILE_BODY: &str = "--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n\
    @@ -1 +1 @@\n-one\n+1\ndiff --git a/README.md b/README.md\nIndex: README.md\n\
    From 1111111111111111111111111111111111111111 Mon Sep 17 00:00:00 2001\n\
    From: other <other@example.invalid>\nSubject: another\n---\n-- >8 --\n\
    Signed-off-by: other <other@example.invalid>\n[PATCH] another\nFrom now on it is so.";

/// The contract: what git writes for each kind of change, and whether the
/// reader takes it.
fn cases() -> Vec<Case> {
    vec![
        case("an edit", EDIT, Accepted),
        case(
            "a new file in new directories",
            &[Write("src/new/dir/file.rs", b"fn new() {}\n")],
            Accepted,
        ),
        case("a deletion", &[Remove("gone.txt")], Accepted),
        case(
            "a deletion in a directory",
            &[Remove("src/deep/er/x.rs")],
            Accepted,
        ),
        case(
            "an edit to an executable",
            &[Write("run.sh", b"#!/bin/sh\necho ran\n")],
            Accepted,
        ),
        case(
            "the deletion of an executable",
            &[Remove("run.sh")],
            Accepted,
        ),
        case("a new empty file", &[Write("new-empty.txt", b"")], Accepted),
        case(
            "the deletion of an empty file",
            &[Remove("empty.txt")],
            Accepted,
        ),
        case("a file emptied", &[Write("a.txt", b"")], Accepted),
        case(
            "an empty file filled",
            &[Write("empty.txt", b"full\n")],
            Accepted,
        ),
        case(
            "an edit without a newline at the end",
            &[Write("nonl.txt", b"still no newline")],
            Accepted,
        ),
        case(
            "a newline added at the end",
            &[Write("nonl.txt", b"no newline\n")],
            Accepted,
        ),
        case(
            "a new file without a newline at the end",
            &[Write("new-nonl.txt", b"x")],
            Accepted,
        ),
        case("a crlf file", &[Write("crlf.txt", b"a\r\nc\r\n")], Accepted),
        case(
            "content that is not UTF-8",
            &[Write("latin1.txt", b"caf\xe9 cr\xe8me\n")],
            Accepted,
        ),
        case(
            "content that looks like a patch",
            &[Write(
                "tricky.md",
                b"++ b/.github/x\ndiff --git a/z b/z\n@@ -1 +1 @@\n---\n\nlast\n",
            )],
            Accepted,
        ),
        case(
            "two hunks",
            &[Write(
                "long.txt",
                b"1\ntwo\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\n21\n",
            )],
            Accepted,
        ),
        case(
            "several files",
            &[
                Write("a.txt", b"one\ntwo\nthree\nfour\n5\n"),
                Write("src/added.rs", b"fn added() {}\n"),
                Remove("gone.txt"),
                Write("new-empty.txt", b""),
            ],
            Accepted,
        ),
        // Without rename detection: a deletion and a new file.
        case("a rename", &[Move("twin.txt", "moved.txt")], Accepted),
        case(
            "a name of every plain character",
            &[Write("x+y@z=1,2_3-4.txt", b"x\n")],
            Accepted,
        ),
        case("two commits made one", EDIT, Accepted).then(&[Write("src/added.rs", b"fn a() {}\n")]),
        case(
            "a body that reads as a patch, as run writes it",
            EDIT,
            Accepted,
        )
        .message(Message::Run("Change things", HOSTILE_BODY)),
        case("a message that is not ASCII", EDIT, Accepted).message(Message::Run(
            "Caf\u{e9} cr\u{e8}me",
            "Na\u{ef}ve \u{2014} d\u{e9}j\u{e0} vu.",
        )),
        case("a subject long enough to fold", EDIT, Accepted).message(Message::Raw(
            "A subject that goes on and on and on and on and on and on and on and on and on \
             and on and on and on and on and on and on and on and on and on\n\nBody.\n",
        )),
        // git drops the rest of the message there, and no more.
        case("a rule in the message", EDIT, Accepted)
            .message(Message::Raw("Subject\n\nabove\n---\nbelow\n")),
        case(
            "a file's old side in the message",
            EDIT,
            Refused("git would read as a patch"),
        )
        .message(Message::Raw(
            "Subject\n\n--- a/README.md\n+++ b/README.md\n",
        )),
        case(
            "a hunk in the message",
            EDIT,
            Refused("git would read as a patch"),
        )
        .message(Message::Raw("Subject\n\n@@ -1 +1 @@\n")),
        case(
            "a file's header in the message",
            EDIT,
            Refused("that is no part of one"),
        )
        .message(Message::Raw(
            "Subject\n\ndiff --git a/README.md b/README.md\n",
        )),
        case(
            "the start of a mail in the message",
            EDIT,
            Refused("git would read as a patch"),
        )
        .message(Message::Raw(
            "Subject\n\nFrom 1111111111111111111111111111111111111111 Mon Sep 17 00:00:00 2001\n",
        )),
        case("a series", EDIT, Refused("that is no part of one"))
            .then(&[Write("src/added.rs", b"fn a() {}\n")])
            .series(),
        case(
            "a mode change",
            &[Executable("a.txt")],
            Refused("mode change (old mode 100644)"),
        ),
        case(
            "a mode change with an edit",
            &[Write("a.txt", b"one\n"), Executable("a.txt")],
            Refused("mode change (old mode 100644)"),
        ),
        case(
            "a new executable",
            &[Write("new.sh", b"#!/bin/sh\n"), Executable("new.sh")],
            Refused("a new symlink, submodule, executable or special file (new file mode 100755)"),
        ),
        case(
            "a new symlink",
            &[Link("new-link", "/etc/passwd")],
            Refused("a new symlink, submodule, executable or special file (new file mode 120000)"),
        ),
        case(
            "a symlink pointed elsewhere",
            &[Remove("link"), Link("link", "README.md")],
            Refused("symlink, submodule or special file (index"),
        ),
        case(
            "the deletion of a symlink",
            &[Remove("link")],
            Refused("symlink, submodule or special file (deleted file mode 120000)"),
        ),
        case(
            "a file that becomes a symlink",
            &[Remove("gone.txt"), Link("gone.txt", "a.txt")],
            Refused("a new symlink, submodule, executable or special file (new file mode 120000)"),
        ),
        case(
            "a new binary file",
            &[Write("new.bin", b"\0\x01\x02\x03\0")],
            Refused("a binary file"),
        ),
        case(
            "an edit to a binary file",
            &[Write("blob.bin", b"\0\x03\x02\x01\0")],
            Refused("a binary file"),
        ),
        case(
            "a carriage return inside a line",
            &[Write("a.txt", b"one\rtwo\n")],
            Refused("a carriage return inside a line"),
        ),
        case(
            "a name with a space",
            &[Write("a b.txt", b"spaces\n")],
            Refused("\"a b.txt\": not a plain relative path"),
        ),
        case(
            "a name that is not ASCII",
            &[Write("caf\u{e9}.txt", b"Unicode\n")],
            Refused("unparseable header"),
        ),
        case(
            "a name with a quote",
            &[Write("q\"uote.txt", b"quoted\n")],
            Refused("unparseable header"),
        ),
        case(
            "a name that starts with a dash",
            &[Write("-x.txt", b"x\n")],
            Refused("\"-x.txt\": not a plain relative path"),
        ),
        case(
            "a protected name",
            &[Write("README.md", b"one\n")],
            Refused("protected files: README.md"),
        ),
        case(
            "CI",
            &[Write(".github/workflows/ci.yml", b"on: push\n")],
            Refused("protected files: .github/workflows/ci.yml"),
        ),
        case(
            "a nested file of git's",
            &[Write("src/.gitattributes", b"* -text\n")],
            Refused("\"src/.gitattributes\": protected path"),
        ),
        case(
            "nested owners",
            &[Write("docs/CODEOWNERS", b"* @agent\n")],
            Refused("\"docs/CODEOWNERS\": protected path"),
        ),
        case(
            "more files than the policy allows",
            &[Many(MAX_PATCH_FILES + 1)],
            Refused("the patch touches 101 files, over 100"),
        ),
    ]
}

/// Runs git in `dir`, with `settings` as its only configuration.
fn git(dir: &Path, settings: &[&str], args: &[&str]) -> Output {
    Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .envs(GIT_ENV)
        .args(settings.iter().flat_map(|setting| ["-c", setting]))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|err| panic!("this test needs `git` on PATH, and could not run it: {err}"))
}

/// What a git command that must succeed wrote.
fn git_ok(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = git(dir, GIT_SETTINGS, args);
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn change(dir: &Path, ops: &[Op]) {
    let write = |path: &str, content: &[u8]| {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    };
    for op in ops {
        match *op {
            Write(path, content) => write(path, content),
            Executable(path) => {
                std::fs::set_permissions(dir.join(path), std::fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
            Link(path, target) => std::os::unix::fs::symlink(target, dir.join(path)).unwrap(),
            Remove(path) => std::fs::remove_file(dir.join(path)).unwrap(),
            Move(from, to) => std::fs::rename(dir.join(from), dir.join(to)).unwrap(),
            Many(count) => (0..count).for_each(|i| write(&format!("many/{i}.txt"), b"x\n")),
        }
    }
}

/// The repository every patch is against, and its one commit.
struct Origin {
    scratch: tempfile::TempDir,
    base: String,
}

impl Origin {
    fn new() -> Self {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("origin");
        std::fs::create_dir(&dir).unwrap();
        git_ok(&dir, &["init", "-q", "-b", "main", "."]);
        change(&dir, BASE);
        git_ok(&dir, &["add", "--all"]);
        git_ok(&dir, &["commit", "-q", "-m", "Base"]);
        let base = git_ok(&dir, &["rev-parse", "--verify", "HEAD"]);
        Self {
            base: String::from_utf8(base).unwrap().trim().to_owned(),
            scratch,
        }
    }

    /// A new clone at the base commit.
    fn clone_as(&self, name: &str) -> PathBuf {
        let dir = self.scratch.path().join(name);
        git_ok(self.scratch.path(), &["clone", "-q", "origin", name]);
        dir
    }

    /// The patch `run` would hand back for `case` (or the series it would
    /// not), and the paths git says it touches.
    fn patch(&self, number: usize, case: &Case) -> (Vec<u8>, BTreeSet<String>) {
        let dir = self.clone_as(&format!("case-{number}"));
        let message_file = self.scratch.path().join(format!("message-{number}"));
        let message = match case.message {
            Message::Run(title, body) => commit_message(title, body, &[], RUN_ID),
            Message::Raw(text) => text.to_owned(),
        };
        std::fs::write(&message_file, message).unwrap();
        let commit: Vec<&str> = COMMIT
            .iter()
            .copied()
            .chain([message_file.to_str().unwrap()])
            .collect();
        for ops in &case.steps {
            change(&dir, ops);
            git_ok(&dir, &["add", "--all"]);
            git_ok(&dir, &commit);
        }
        let mut args: Vec<&str> = FORMAT_PATCH.to_vec();
        let range = format!("{}..HEAD", self.base);
        if case.squash {
            // As `build_patch` does it.
            git_ok(&dir, &["reset", "-q", "--soft", &self.base]);
            git_ok(&dir, &["add", "--all"]);
            git_ok(&dir, &commit);
            args.extend(["-1", "HEAD"]);
        } else {
            args.push(&range);
        }
        let formatted = git_ok(&dir, &args);
        let first = formatted.iter().position(|&b| b == b'\n').unwrap();
        let mut patch = formatted[..=first].to_vec();
        patch.extend_from_slice(format!("{BASE_COMMIT_HEADER}: {}\n", self.base).as_bytes());
        patch.extend_from_slice(&formatted[first + 1..]);

        let names = git_ok(
            &dir,
            &[
                "diff",
                "--name-only",
                "--no-renames",
                "-z",
                &self.base,
                "HEAD",
            ],
        );
        let touched = names
            .split(|&b| b == 0)
            .filter(|name| !name.is_empty())
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .collect();
        (patch, touched)
    }

    /// The reading `check` makes of a patch: of its text with what is not
    /// UTF-8 replaced.
    fn read(&self, patch: &[u8]) -> PatchReading {
        read_patch(
            &String::from_utf8_lossy(patch),
            &rules().rules(),
            &self.base,
        )
    }
}

/// The rules of a policy that allows a pull request, with gh-aw's
/// protected files.
fn rules() -> PullRequest {
    PullRequest {
        max: 1,
        protected_files: DEFAULT_PROTECTED_FILES
            .iter()
            .map(|&name| name.to_owned())
            .collect(),
        protect_top_level_dot_folders: true,
        unprotected_dot_folders: Vec::new(),
        protected_files_policy: ProtectedFilesPolicy::Blocked,
        draft: true,
        max_patch_size: 1024,
        max_patch_files: MAX_PATCH_FILES,
    }
}

/// Whether no patch may touch `path`, said again here without the
/// reader's patterns: a listed name, anything under a top-level
/// dot-folder, git's own files and hooks, owners.
fn is_protected(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    let name = parts.last().copied().unwrap_or_default();
    (parts.len() > 1 && parts[0].starts_with('.'))
        || parts
            .iter()
            .any(|part| part.starts_with(".git") || *part == ".husky")
        || DEFAULT_PROTECTED_FILES.contains(&name)
        || name == "CODEOWNERS"
}

fn files_of(reading: &PatchReading) -> BTreeSet<String> {
    reading.files.iter().cloned().collect()
}

#[test]
fn what_git_writes_is_read_as_git_means_it() {
    let origin = Origin::new();
    for (number, case) in cases().iter().enumerate() {
        let name = case.name;
        let (patch, touched) = origin.patch(number, case);
        let reading = origin.read(&patch);
        let text = String::from_utf8_lossy(&patch);
        match case.want {
            Accepted => {
                assert_eq!(reading.problems, Vec::<String>::new(), "{name}:\n{text}");
                assert_eq!(files_of(&reading), touched, "{name}:\n{text}");
            }
            Refused(why) => assert!(
                reading.problems.iter().any(|problem| problem.contains(why)),
                "{name}: {:#?}\n{text}",
                reading.problems
            ),
        }
    }
}

/// xorshift64: all the randomness a repeatable corpus needs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A number under `limit`, which is not zero.
    fn below(&mut self, limit: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(limit).unwrap()).unwrap()
    }

    /// One of `items`, if there is any.
    fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        (!items.is_empty()).then(|| &items[self.below(items.len())])
    }
}

type Lines = Vec<Vec<u8>>;

fn split(patch: &[u8]) -> Lines {
    patch
        .strip_suffix(b"\n")
        .unwrap_or(patch)
        .split(|&b| b == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

fn join(lines: &[Vec<u8>]) -> Vec<u8> {
    lines
        .iter()
        .flat_map(|line| line.iter().copied().chain(*b"\n"))
        .collect()
}

/// The lines of `text`; none of no text.
fn text_lines(text: &str) -> Lines {
    if text.is_empty() {
        Vec::new()
    } else {
        split(text.as_bytes())
    }
}

/// `line` with `from` replaced by `to`: everywhere, or only where it is
/// found first or last.
fn replaced(line: &[u8], from: &str, to: &str, which: Which) -> Vec<u8> {
    let (from, to) = (from.as_bytes(), to.as_bytes());
    let found: Vec<usize> = (0..line.len())
        .filter(|&at| line[at..].starts_with(from))
        .collect();
    let chosen: &[usize] = match (which, found.as_slice()) {
        (_, []) => &[],
        (Which::All, all) => all,
        (Which::First, [first, ..]) => std::slice::from_ref(first),
        (Which::Last, [.., last]) => std::slice::from_ref(last),
    };
    let mut out = Vec::new();
    let mut at = 0;
    for &start in chosen {
        // Two finds that overlap: the first is replaced.
        if start < at {
            continue;
        }
        out.extend_from_slice(&line[at..start]);
        out.extend_from_slice(to);
        at = start + from.len();
    }
    out.extend_from_slice(&line[at..]);
    out
}

#[derive(Clone, Copy)]
enum Which {
    All,
    First,
    Last,
}

const DIFF_HEADER: &str = "diff --git ";
const OLD_SIDE: &str = "--- ";
const NEW_SIDE: &str = "+++ ";
const NAMING: &[&str] = &[DIFF_HEADER, OLD_SIDE, NEW_SIDE];
const SEPARATOR: &[u8] = b"---";
const DEV_NULL: &[u8] = b"/dev/null";
const CRLF: &[u8] = b"\r\n";

fn starts(line: &[u8], start: &str) -> bool {
    line.starts_with(start.as_bytes())
}

fn names_a_path(line: &[u8]) -> bool {
    NAMING.iter().any(|start| starts(line, start))
}

/// The header of one file of a patch: its path, and its lines from
/// `diff --git` up to the first hunk.
struct Section {
    path: String,
    start: usize,
    end: usize,
}

fn sections(lines: &[Vec<u8>]) -> Vec<Section> {
    let mut found = Vec::new();
    for (start, line) in lines.iter().enumerate() {
        let Some(rest) = line.strip_prefix(b"diff --git a/") else {
            continue;
        };
        let rest = String::from_utf8_lossy(rest).into_owned();
        let Some((old, new)) = rest.split_once(" b/") else {
            continue;
        };
        if old != new {
            continue;
        }
        let end = (start + 1..lines.len())
            .find(|&at| {
                let line = &lines[at];
                line.is_empty() || starts(line, "@@ ") || starts(line, DIFF_HEADER)
            })
            .unwrap_or(lines.len());
        found.push(Section {
            path: old.to_owned(),
            start,
            end,
        });
    }
    found
}

/// Where a change can be pointed instead: files of the base with the
/// content of `a.txt` (plain, protected, executable, a link to one), new
/// files, and paths that are no path of the tree.
const TARGETS: &[&str] = &[
    "twin.txt",
    "twin.txt",
    "fresh.txt",
    "src/fresh.rs",
    "README.md",
    ".github/workflows/ci.yml",
    ".github/workflows/new.yml",
    "docs/CODEOWNERS",
    "new/CODEOWNERS",
    "sub/.gitattributes",
    "sub/.gitmodules",
    ".envrc",
    ".git/config",
    ".git/hooks/pre-commit",
    "twin.sh",
    "link",
    "link/x",
    "../x",
    "sub/../README.md",
    "./twin.txt",
    "/etc/x",
    "a b.txt",
    "package.json",
];

/// The whole header of one file names another path.
fn retarget(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let sections = sections(lines);
    let section = rng.pick(&sections)?;
    let target = rng.pick(TARGETS)?;
    let mut lines = lines.to_vec();
    for line in &mut lines[section.start..section.end] {
        if names_a_path(line) {
            *line = replaced(line, &section.path, target, Which::All);
        }
    }
    Some(join(&lines))
}

/// One line of a file's header names another path, or none.
fn one_side(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let sections = sections(lines);
    let section = rng.pick(&sections)?;
    let naming: Vec<usize> = (section.start..section.end)
        .filter(|&at| names_a_path(&lines[at]))
        .collect();
    let at = *rng.pick(&naming)?;
    let target = rng.pick(TARGETS)?;
    let which = *rng.pick(&[Which::All, Which::First, Which::Last])?;
    let mut lines = lines.to_vec();
    let line = &lines[at];
    let changed = if !starts(line, DIFF_HEADER) && rng.below(4) == 0 {
        [&line[..OLD_SIDE.len()], DEV_NULL].concat()
    } else {
        replaced(line, &section.path, target, which)
    };
    lines[at] = changed;
    Some(join(&lines))
}

fn duplicate_line(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let at = rng.below(lines.len());
    let mut lines = lines.to_vec();
    lines.insert(at, lines[at].clone());
    Some(join(&lines))
}

fn drop_line(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let mut lines = lines.to_vec();
    lines.remove(rng.below(lines.len()));
    Some(join(&lines))
}

fn swap_lines(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let mut lines = lines.to_vec();
    let at = rng.below(lines.len() - 1);
    lines.swap(at, at + 1);
    Some(join(&lines))
}

const ADD_CI: &str = "diff --git a/.github/workflows/evil.yml b/.github/workflows/evil.yml\n\
    new file mode 100644\nindex 0000000..1111111\n--- /dev/null\n\
    +++ b/.github/workflows/evil.yml\n@@ -0,0 +1 @@\n+on: push\n";
const ADD_PLAIN: &str = "diff --git a/spliced.txt b/spliced.txt\nnew file mode 100644\n\
    index 0000000..1111111\n--- /dev/null\n+++ b/spliced.txt\n@@ -0,0 +1 @@\n+spliced\n";
const BARE_CI: &str = "--- /dev/null\n+++ b/.github/workflows/evil.yml\n@@ -0,0 +1 @@\n+on: push\n";
const BARE_PLAIN: &str = "--- /dev/null\n+++ b/spliced.txt\n@@ -0,0 +1 @@\n+spliced\n";
const EDIT_README: &str = "diff --git a/README.md b/README.md\nindex 1111111..2222222 100644\n\
    --- a/README.md\n+++ b/README.md\n@@ -3,3 +3,3 @@\n three\n-four\n+4\n five\n";
const EDIT_TWIN: &str = "diff --git a/twin.sh b/twin.sh\nindex 1111111..2222222 100755\n\
    --- a/twin.sh\n+++ b/twin.sh\n@@ -3,3 +3,3 @@\n three\n-four\n+4\n five\n";
const OLD_STYLE: &str = "Index: README.md\n\
    ===================================================================\n\
    --- README.md\t(revision 1)\n+++ README.md\t(working copy)\n\
    @@ -3,3 +3,3 @@\n three\n-four\n+4\n five\n";
const MOVE_TO_CI: &str = "diff --git a/twin.sh b/.github/workflows/moved.yml\n\
    similarity index 100%\nrename from twin.sh\nrename to .github/workflows/moved.yml\n";
const COPY_TO_HOOK: &str = "diff --git a/twin.sh b/.husky/pre-commit\n\
    similarity index 100%\ncopy from twin.sh\ncopy to .husky/pre-commit\n";
const MAKE_EXECUTABLE: &str =
    "diff --git a/gone.txt b/gone.txt\nold mode 100644\nnew mode 100755\n";
const DELETE_CI: &str = "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n\
    deleted file mode 100644\nindex 1111111..0000000\n--- a/.github/workflows/ci.yml\n\
    +++ /dev/null\n@@ -1,5 +0,0 @@\n-one\n-two\n-three\n-four\n-five\n";
const SECOND_MAIL: &str = "From 1111111111111111111111111111111111111111 Mon Sep 17 00:00:00 2001\n\
    From: other <other@example.invalid>\nDate: Thu, 1 Jan 2026 00:00:00 +0000\n\
    Subject: [PATCH] Another\n";
const SECOND_MESSAGE: &str = "More.\n---\n";
const ENCODED: &str = "Content-Transfer-Encoding: base64";
const SIGNATURE: &str = "-- \n2.52.0\n\n";

/// What is put into a patch: changes git applies to the base where it
/// reads them, with and without `diff --git`, and whole mails.
fn payloads() -> Vec<String> {
    let mut all: Vec<String> = [
        ADD_CI,
        ADD_PLAIN,
        ADD_PLAIN,
        BARE_CI,
        BARE_PLAIN,
        EDIT_README,
        EDIT_TWIN,
        EDIT_TWIN,
        OLD_STYLE,
        MOVE_TO_CI,
        COPY_TO_HOOK,
        MAKE_EXECUTABLE,
        DELETE_CI,
    ]
    .iter()
    .map(|&payload| payload.to_owned())
    .collect();
    for change in [ADD_CI, ADD_PLAIN] {
        all.push(format!("{SECOND_MAIL}\n{SECOND_MESSAGE}{change}"));
        let body = base64(format!("{SECOND_MESSAGE}{change}").as_bytes());
        all.push(format!("{SECOND_MAIL}{ENCODED}\n\n{body}"));
    }
    all
}

/// A change, or a mail, where there was none: in the message, after its
/// end, between the files, after the last, around a signature.
fn splice(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let payloads = payloads();
    let payload = text_lines(rng.pick(&payloads)?);
    let separator = lines.iter().position(|line| line == SEPARATOR)?;
    let first_file = sections(lines).first()?.start;
    let (at, before, after) = match rng.below(8) {
        0 => (1 + rng.below(separator), "", ""),
        1 => (separator, "", ""),
        2 => (separator + 1, "", ""),
        3 => (first_file, "", ""),
        4 => (rng.below(lines.len() + 1), "", ""),
        5 => (lines.len(), "", ""),
        6 => (lines.len(), SIGNATURE, ""),
        _ => (lines.len(), "", SIGNATURE),
    };
    let mut out = lines[..at].to_vec();
    for part in [text_lines(before), payload, text_lines(after)] {
        out.extend(part);
    }
    out.extend_from_slice(&lines[at..]);
    Some(join(&out))
}

/// The counts a hunk's header may have instead of its own.
const COUNTS: &[&str] = &[
    "0",
    "1",
    "2",
    "3",
    "4",
    "6",
    "99",
    "4294967296",
    "4294967297",
];

fn hunk_count(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let hunks: Vec<usize> = (0..lines.len())
        .filter(|&at| starts(&lines[at], "@@ -"))
        .collect();
    let at = *rng.pick(&hunks)?;
    let line = &lines[at];
    let end = (3..line.len()).find(|&i| line[i..].starts_with(b" @@"))?;
    // Where each number of the header starts and ends.
    let mut numbers: Vec<(usize, usize)> = Vec::new();
    for i in (0..end).filter(|&i| line[i].is_ascii_digit()) {
        match numbers.last_mut() {
            Some((_, stop)) if *stop == i => *stop = i + 1,
            _ => numbers.push((i, i + 1)),
        }
    }
    let &(from, to) = rng.pick(&numbers)?;
    let mut lines = lines.to_vec();
    lines[at] = [&line[..from], rng.pick(COUNTS)?.as_bytes(), &line[to..]].concat();
    Some(join(&lines))
}

/// Lines git reads in a file's header; `{}` is the file's own path.
const HEADER_LINES: &[&str] = &[
    "old mode 100644\nnew mode 100755",
    "old mode 100755\nnew mode 100644",
    "new mode 100755",
    "new mode 120000",
    "new file mode 120000",
    "new file mode 100755",
    "new file mode 100644",
    "deleted file mode 100644",
    "rename from {}\nrename to fresh.txt",
    "rename from {}\nrename to .github/workflows/new.yml",
    "rename from twin.txt\nrename to {}",
    "copy from {}\ncopy to copied.txt",
    "similarity index 100%",
    "index 1111111..2222222 120000",
    "index 1111111..2222222 100755",
    "index 1111111..2222222",
    "GIT binary patch",
    "--- a/twin.txt",
    "+++ b/twin.txt",
];

fn header_line(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let sections = sections(lines);
    let section = rng.pick(&sections)?;
    let added = rng.pick(HEADER_LINES)?.replace("{}", &section.path);
    let at = section.start + 1 + rng.below(section.end - section.start);
    let mut lines = lines.to_vec();
    lines.splice(at..at, text_lines(&added));
    Some(join(&lines))
}

const MODES: &[&str] = &[
    "100755", "100644", "120000", "160000", "100600", "040000", "100644 ",
];

/// A line of a file's header states another mode.
fn mode(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let with_mode: Vec<usize> = sections(lines)
        .iter()
        .flat_map(|section| section.start + 1..section.end)
        .filter(|&at| lines[at].ends_with(b" 100644") || lines[at].ends_with(b" 100755"))
        .collect();
    let at = *rng.pick(&with_mode)?;
    let mut lines = lines.to_vec();
    let kept = lines[at].len() - PLAIN_MODE.len();
    lines[at].truncate(kept);
    lines[at].extend_from_slice(rng.pick(MODES)?.as_bytes());
    Some(join(&lines))
}

/// A file's change as git writes one for a file that moved as well.
fn rename(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let sections = sections(lines);
    let section = rng.pick(&sections)?;
    let (path, target) = (&section.path, rng.pick(TARGETS)?);
    let mut out = lines[..section.start].to_vec();
    out.extend(text_lines(&format!(
        "diff --git a/{path} b/{target}\nsimilarity index 50%\nrename from {path}\nrename to {target}"
    )));
    for line in &lines[section.start + 1..section.end] {
        out.push(if starts(line, NEW_SIDE) {
            format!("{NEW_SIDE}b/{target}").into_bytes()
        } else {
            line.clone()
        });
    }
    out.extend_from_slice(&lines[section.end..]);
    Some(join(&out))
}

/// A file's path as git quotes one, which it reads back as the same path.
fn quote_path(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let sections = sections(lines);
    let section = rng.pick(&sections)?;
    let path = &section.path;
    let quoted = if rng.below(2) == 0 {
        path.clone()
    } else {
        format!("\\{:03o}{}", path.as_bytes()[0], &path[1..])
    };
    // Every line that names the path, or one of them.
    let only = (rng.below(2) == 0).then(|| section.start + rng.below(section.end - section.start));
    let mut lines = lines.to_vec();
    let named = lines.iter_mut().enumerate();
    for (at, line) in named.take(section.end).skip(section.start) {
        if only.is_some_and(|only| only != at) {
            continue;
        }
        for side in ["a/", "b/"] {
            let (plain, quoted) = (format!("{side}{path}"), format!("\"{side}{quoted}\""));
            *line = replaced(line, &plain, &quoted, Which::All);
        }
    }
    Some(join(&lines))
}

/// A byte more or less in one line: what ends a line for some reader,
/// what ends a string for another, what is no text at all.
fn bytes(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let mut lines = lines.to_vec();
    let at = rng.below(lines.len());
    let line = &mut lines[at];
    let inside = rng.below(line.len() + 1);
    match rng.below(9) {
        0 => line.push(b'\r'),
        1 => line.push(b' '),
        2 => line.push(b'\t'),
        3 => line.insert(inside, 0),
        4 => line.insert(inside, b'\r'),
        5 => line.insert(inside, 0xff),
        6 => line.insert(0, b' '),
        7 => line.insert(0, b'>'),
        _ => {
            if !line.is_empty() {
                line.remove(0);
            }
        }
    }
    Some(join(&lines))
}

/// Every line ends as a mail's does on the wire.
fn crlf(lines: &[Vec<u8>], _: &mut Rng) -> Option<Vec<u8>> {
    Some(
        lines
            .iter()
            .flat_map(|line| [line.as_slice(), CRLF].concat())
            .collect(),
    )
}

fn truncate(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let whole = join(lines);
    Some(if rng.below(2) == 0 {
        join(&lines[..1 + rng.below(lines.len() - 1)])
    } else {
        whole[..rng.below(whole.len())].to_vec()
    })
}

/// Fields a mail may have, that git reads and `format-patch` did not write
/// here; `-` takes the patch's base away.
const MAIL_HEADERS: &[&str] = &[
    ENCODED,
    "Content-Transfer-Encoding: quoted-printable",
    "content-transfer-encoding: QUOTED-PRINTABLE",
    "Content-Type: multipart/mixed; boundary=x",
    "Content-Type: text/plain; charset=UTF-16",
    "Subject: [PATCH] Another",
    "From: other <other@example.invalid>",
    "X-Other: 1",
    " folded",
    "no colon",
    "X-GH-AW-Base-Commit: 1111111111111111111111111111111111111111",
    "-",
];

fn mail_header(lines: &[Vec<u8>], rng: &mut Rng) -> Option<Vec<u8>> {
    let end = lines.iter().position(Vec::is_empty)?;
    let mut lines = lines.to_vec();
    match *rng.pick(MAIL_HEADERS)? {
        "-" => {
            lines.retain(|line| !starts(line, BASE_COMMIT_HEADER));
        }
        field => lines.insert(1 + rng.below(end), field.as_bytes().to_vec()),
    }
    Some(join(&lines))
}

/// The whole body encoded, which git decodes and applies as it was.
fn encode(lines: &[Vec<u8>], _: &mut Rng) -> Option<Vec<u8>> {
    let end = lines.iter().position(Vec::is_empty)?;
    let mut out = join(&lines[..end]);
    out.extend_from_slice(format!("{ENCODED}\n\n").as_bytes());
    out.extend_from_slice(base64(&join(&lines[end + 1..])).as_bytes());
    Some(out)
}

fn unchanged(lines: &[Vec<u8>], _: &mut Rng) -> Option<Vec<u8>> {
    Some(join(lines))
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// How many bytes a line of an encoded body holds.
const BASE64_LINE_BYTES: usize = 57;

/// `data` as the body of an encoded mail.
fn base64(data: &[u8]) -> String {
    let mut out = String::new();
    for line in data.chunks(BASE64_LINE_BYTES) {
        for group in line.chunks(3) {
            let byte = |at: usize| u32::from(group.get(at).copied().unwrap_or(0));
            let bits = byte(0) << 16 | byte(1) << 8 | byte(2);
            for digit in 0..4 {
                let shown = digit <= group.len();
                let index = (bits >> (18 - 6 * digit)) & 0x3f;
                out.push(if shown {
                    char::from(BASE64[usize::try_from(index).unwrap()])
                } else {
                    '='
                });
            }
        }
        out.push('\n');
    }
    out
}

const UNCHANGED: &str = "unchanged";

type Mutation = fn(&[Vec<u8>], &mut Rng) -> Option<Vec<u8>>;

/// The ways a patch is damaged, and how many times each is tried on one
/// patch. A try that gives a mutant there already is, or none, is not
/// made up for.
const MUTATIONS: &[(&str, Mutation, usize)] = &[
    (UNCHANGED, unchanged, 1),
    ("retarget", retarget, 6),
    ("one side", one_side, 4),
    ("duplicate a line", duplicate_line, 2),
    ("drop a line", drop_line, 2),
    ("swap lines", swap_lines, 2),
    ("splice", splice, 8),
    ("hunk count", hunk_count, 2),
    ("header line", header_line, 4),
    ("mode", mode, 2),
    ("rename", rename, 1),
    ("quote a path", quote_path, 1),
    ("bytes", bytes, 4),
    ("crlf", crlf, 1),
    ("truncate", truncate, 2),
    ("mail header", mail_header, 3),
    ("encode", encode, 1),
];

struct Mutant {
    class: &'static str,
    /// The case whose patch it was made of.
    of: &'static str,
    text: Vec<u8>,
}

impl std::fmt::Display for Mutant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} of {:?} (seed {SEED:#x}):\n{}\nas a string: \"{}\"",
            self.class,
            self.of,
            String::from_utf8_lossy(&self.text),
            self.text.escape_ascii()
        )
    }
}

/// One file `git am` changed: its modes before and after, and its path.
#[derive(Debug)]
struct Changed {
    old_mode: String,
    new_mode: String,
    path: String,
}

/// What `git am` made of a patch.
enum Am {
    Refused,
    /// Git itself failed: an assertion of its own (`check_preimage` in
    /// `apply.c` of git 2.52, at a new file whose header is damaged).
    Died,
    Applied(Vec<Changed>),
    /// Applied, to a commit git cannot read back, for this reason (git
    /// 2.52 takes a new file of mode 040000, and writes a tree of it).
    Broken(String),
}

/// A clone at the base commit that patches are applied to, one after
/// another.
struct Trial<'a> {
    dir: PathBuf,
    patch: PathBuf,
    base: &'a str,
}

impl<'a> Trial<'a> {
    fn new(origin: &'a Origin, number: usize) -> Self {
        Self {
            dir: origin.clone_as(&format!("trial-{number}")),
            patch: origin.scratch.path().join(format!("trial-{number}.patch")),
            base: &origin.base,
        }
    }

    /// What `git am` changed, if it took the patch. The apply job's trial
    /// on the patch's own base is a plain `git am --keep-cr`; the handlers
    /// then run it with `--3way`, which is used here because it takes all
    /// that a plain `git am` takes, the same way, and may take more.
    fn am(&self, text: &[u8]) -> Am {
        // What the last patch left, applied or not.
        let _ = std::fs::remove_dir_all(self.dir.join(".git/rebase-apply"));
        let _ = std::fs::remove_file(self.dir.join(".git/index.lock"));
        git_ok(&self.dir, &["reset", "-q", "--hard", self.base]);
        git_ok(&self.dir, &["clean", "-q", "-fdx"]);
        std::fs::write(&self.patch, text).unwrap();
        let am = [
            "am",
            "-q",
            "--keep-cr",
            "--3way",
            self.patch.to_str().unwrap(),
        ];
        let out = git(&self.dir, APPLY_SETTINGS, &am);
        let stderr = |out: &Output| String::from_utf8_lossy(&out.stderr).trim().to_owned();
        match out.status.code() {
            Some(0) => {}
            Some(_) => return Am::Refused,
            None => return Am::Died,
        }
        let diff = [
            "diff",
            "--raw",
            "--no-renames",
            "--no-abbrev",
            "-z",
            self.base,
            "HEAD",
        ];
        let out = git(&self.dir, GIT_SETTINGS, &diff);
        if !out.status.success() {
            return Am::Broken(stderr(&out));
        }
        let fields: Vec<String> = out
            .stdout
            .split(|&b| b == 0)
            .map(|field| String::from_utf8_lossy(field).into_owned())
            .collect();
        // `:100644 100755 <old> <new> M`, then the path.
        Am::Applied(
            fields
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[modes, path]| {
                    let mut modes = modes.trim_start_matches(':').split(' ');
                    Changed {
                        old_mode: modes.next().unwrap().to_owned(),
                        new_mode: modes.next().unwrap().to_owned(),
                        path: path.clone(),
                    }
                })
                .collect(),
        )
    }
}

/// How `git am` went against what the reader allowed: empty if the
/// reading covers it.
fn disagreements(reading: &PatchReading, changed: &[Changed]) -> Vec<String> {
    let mut found = Vec::new();
    for Changed {
        old_mode,
        new_mode,
        path,
    } in changed
    {
        if !reading.files.contains(path) {
            found.push(format!(
                "git changed {path:?}, which the reader did not name"
            ));
        }
        if is_protected(path) {
            found.push(format!("git changed {path:?}, which is protected"));
        }
        // Only plain files and executables: a link or a submodule is none
        // the reader allows, whether or not its mode stays.
        for mode in [old_mode, new_mode] {
            if !FILE_MODES.contains(&mode.as_str()) {
                found.push(format!("git changed {path:?}, which is of mode {mode}"));
            }
        }
        // A new file is plain, and a file keeps the mode it had.
        let kept = new_mode == NO_MODE || old_mode == new_mode;
        if !(kept || (old_mode == NO_MODE && new_mode == PLAIN_MODE)) {
            found.push(format!("git made {path:?} {new_mode}, from {old_mode}"));
        }
    }
    found
}

/// Every mutant of the patches the reader accepts, in an order that
/// depends on `SEED` alone.
fn mutants(origin: &Origin) -> Vec<Mutant> {
    let mut rng = Rng(SEED);
    let mut seen = BTreeSet::new();
    let mut all = Vec::new();
    for (number, case) in cases().iter().enumerate() {
        if !matches!(case.want, Accepted) {
            continue;
        }
        let (patch, _) = origin.patch(number, case);
        let lines = split(&patch);
        for &(class, mutation, tries) in MUTATIONS {
            for _ in 0..tries {
                let Some(text) = mutation(&lines, &mut rng) else {
                    continue;
                };
                if class == UNCHANGED || seen.insert(text.clone()) {
                    all.push(Mutant {
                        class,
                        of: case.name,
                        text,
                    });
                }
            }
        }
    }
    all
}

#[test]
fn the_reader_names_all_that_git_am_changes() {
    let origin = Origin::new();
    let mutants = mutants(&origin);

    // Git's side, which is all of the time: each worker has a clone, and
    // takes every mutant whose number is its own.
    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(MAX_WORKERS);
    let trials: Vec<Trial<'_>> = (0..workers).map(|n| Trial::new(&origin, n)).collect();
    let mut applied: Vec<Am> = Vec::new();
    applied.resize_with(mutants.len(), || Am::Refused);
    std::thread::scope(|scope| {
        let handles: Vec<_> = trials
            .iter()
            .enumerate()
            .map(|(n, trial)| {
                let mutants = &mutants;
                scope.spawn(move || {
                    (n..mutants.len())
                        .step_by(workers)
                        .map(|at| (at, trial.am(&mutants[at].text)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in handles {
            for (at, changed) in handle.join().unwrap() {
                applied[at] = changed;
            }
        }
    });

    let (mut both, mut reader_only, mut git_only, mut neither, mut named_more) = (0, 0, 0, 0, 0);
    let (mut died, mut broken, mut compared) = (0, 0, 0);
    let mut failures = Vec::new();
    for (mutant, changed) in mutants.iter().zip(&applied) {
        let reading = origin.read(&mutant.text);
        let accepted = reading.problems.is_empty();
        match changed {
            Am::Died => died += 1,
            Am::Broken(why) => {
                broken += 1;
                // Nothing can be said of what git changed there.
                if accepted {
                    failures.push(format!("git cannot read what it applied ({why}): {mutant}"));
                }
            }
            Am::Refused | Am::Applied(_) => {}
        }
        match (accepted, changed) {
            (true, Am::Applied(changed)) => {
                both += 1;
                compared += usize::from(!changed.is_empty());
                let paths: BTreeSet<String> = changed.iter().map(|c| c.path.clone()).collect();
                let exact = paths == files_of(&reading);
                // Fewer is what `--3way` makes of a change the base holds
                // already, or of the deletion of a file that is not there.
                named_more += usize::from(!exact);
                let mut found = disagreements(&reading, changed);
                // What git wrote is read exactly, not only safely.
                if mutant.class == UNCHANGED && !exact {
                    found.push(format!("the reader named {:?}", reading.files));
                }
                if !found.is_empty() {
                    failures.push(format!("{found:#?}\nfor the mutant {mutant}"));
                }
            }
            (true, Am::Refused | Am::Died) => {
                git_only += 1;
                if mutant.class == UNCHANGED {
                    failures.push(format!("git am refuses what git wrote: {mutant}"));
                }
            }
            (_, Am::Broken(_)) | (false, Am::Applied(_)) => reader_only += 1,
            (false, Am::Refused | Am::Died) => {
                neither += 1;
                if mutant.class == UNCHANGED {
                    failures.push(format!(
                        "neither takes what git wrote: {:#?}\n{mutant}",
                        reading.problems
                    ));
                }
            }
        }
    }
    let git_applied = both + reader_only;
    eprintln!(
        "patch_git: seed {SEED:#x}, {} mutants: {both} accepted by both \
         ({compared} of them changed a path), \
         {reader_only} refused by the reader only, {git_only} refused by git only, \
         {neither} refused by both; git applied {git_applied}; \
         the reader named more than git changed in {named_more}; \
         git died on {died} and could not read what it applied of {broken}",
        mutants.len()
    );
    assert!(
        failures.is_empty(),
        "{} disagreements with git am:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    assert!(mutants.len() >= MIN_MUTANTS, "too few mutants");
    assert!(git_applied >= MIN_APPLIED, "git applied too few mutants");
    assert!(
        compared >= MIN_ACCEPTED_BY_BOTH,
        "too few mutants accepted by both that changed a path"
    );
}
