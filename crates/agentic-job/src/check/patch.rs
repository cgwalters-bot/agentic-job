//! The rules for a patch, read from its text.
//!
//! The patch is `git format-patch`'s output for one commit, made by `run`
//! with git running as the sandbox user in a checkout whose configuration
//! the agent controls. So all of it is untrusted, and it is later given
//! to `git am` on a machine that can write. Two readers of one text can
//! disagree about what it says: a patch in the commit message, a second
//! mail, an encoded body or a header only git understands would each be
//! applied by git and missed by a reader that looks for `diff --git`
//! lines alone. So the text is read as git reads it, line by line, and
//! must be exactly the shape `format-patch` writes. From the first file
//! on, every line has to be accounted for: a file's header, a hunk of the
//! length its header gives, or the signature. Before that is the commit
//! message, which is free text, so there the lines git would read as the
//! start of a patch or of a mail are refused.
//!
//! One thing the text cannot show. Where a patch does not apply as it
//! is, `git am --3way` looks for the file its `index` line names by
//! content, and with rename detection may apply the change to another
//! path than the one read here. So the paths are part of the verdict
//! ([`PatchReading::files`]), for the job that applies the patch to
//! compare with what changed, and that job should apply without rename
//! detection (`merge.renames=false`).

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::policy::{EXEMPTABLE_DOT_FOLDER, PatchRules};

/// The header `run` adds, naming the commit the patch is against (gh-aw's
/// name for it).
pub const BASE_COMMIT_HEADER: &str = "X-GH-AW-Base-Commit";

/// Paths never touched: git's own files at any depth (`.git`,
/// `.gitmodules`, `.gitattributes`, ...), and CI, hook, editor and shell
/// configuration that the protection of top-level dot-folders does not
/// reach (nested ones, and files).
static PROTECTED_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(^|/)\.git|(^|/)\.husky/|^\.pre-commit-config\.ya?ml$|^\.?lefthook\.ya?ml$",
        r"|^\.circleci/|^\.travis\.yml$|^\.tekton/|^\.packit\.ya?ml$|^\.envrc$",
        r"|^\.vscode/|(^|/)CODEOWNERS$",
    ))
    .expect("a valid pattern")
});

/// The paths a change may touch: relative, of plain characters (no
/// spaces, quotes or control characters). `.` and `..` are refused apart.
static PLAIN_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9_.+@=,][A-Za-z0-9_.+@=,-]*(/[A-Za-z0-9_.+@=,][A-Za-z0-9_.+@=,-]*)*$")
        .expect("a valid pattern")
});

/// The first line of a mail as `format-patch` writes it.
static MAIL_START_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^From [0-9a-f]{40}([0-9a-f]{24})? Mon Sep 17 00:00:00 2001$")
        .expect("a valid pattern")
});

/// A line `git mailsplit` may start another mail at. Its own test
/// (`is_from_line`) wants `From `, a time and a year; this takes any
/// `From ` line with a digit either side of a colon, which is more.
static MAIL_SPLIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^From .*\d:\d").expect("a valid pattern"));

static HUNK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@").expect("a valid pattern")
});

static FILE_MODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(new file mode|deleted file mode|index [0-9a-f]+\.\.[0-9a-f]+) ([0-9]+)$")
        .expect("a valid pattern")
});

static INDEX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^index [0-9a-f]+\.\.[0-9a-f]+$").expect("a valid pattern"));

/// How the lines of a file's header start that change its mode: git
/// reads the rest loosely (`apply.c`), so the start alone decides.
const MODE_CHANGES: &[&str] = &["old mode ", "new mode "];

/// Those that say where a file came from. Patches are made without
/// renames, so none is expected.
const RENAMES: &[&str] = &[
    "rename from ",
    "rename to ",
    "rename old ",
    "rename new ",
    "copy from ",
    "copy to ",
    "similarity index ",
    "dissimilarity index ",
];

/// Those that carry a file's mode, which must then be read in full.
const FILE_MODES: &[&str] = &["new file mode ", "deleted file mode ", "index "];

const DIFF_HEADER: &str = "diff --git ";
const NEW_FILE: &str = "new file mode";
const DELETED_FILE: &str = "deleted file mode";
const PLAIN_MODE: &str = "100644";
const EXECUTABLE_MODE: &str = "100755";
const DEV_NULL: &str = "/dev/null";

/// The line format-patch puts before its signature, git's version.
const SIGNATURE: &str = "-- ";

/// The mail headers `format-patch` writes, and for the fixed ones their
/// value. Anything else is refused: a `Content-Transfer-Encoding` or a
/// multipart `Content-Type` makes git decode a body this reads as text.
const FREE_HEADERS: &[&str] = &["From", "Date", "Subject", BASE_COMMIT_HEADER];
const FIXED_HEADERS: &[(&str, &str)] = &[
    ("MIME-Version", "1.0"),
    ("Content-Type", "text/plain; charset=UTF-8"),
    ("Content-Transfer-Encoding", "8bit"),
];

/// How much of an offending line a message quotes.
const QUOTED_CHARS: usize = 120;

fn quoted(line: &str) -> String {
    format!("{:?}", line.chars().take(QUOTED_CHARS).collect::<String>())
}

/// Why a path may not be in a change, if it may not. `PROTECTED_PATH_RE`
/// takes `.github/` for git's own; only where the policy exempts that
/// folder is it left out, and every component inside it is still matched.
fn path_problem(path: &str, github_exempt: bool) -> Option<&'static str> {
    let dotted = path.split('/').any(|part| part == "." || part == "..");
    let inside = match path.strip_prefix(".github/") {
        Some(inside) if github_exempt => inside,
        _ => path,
    };
    if !PLAIN_PATH_RE.is_match(path) || dotted {
        Some("not a plain relative path")
    } else if PROTECTED_PATH_RE.is_match(inside) {
        Some("protected path")
    } else {
        None
    }
}

/// Whether git could take `line`, outside a hunk, for the start of a
/// patch or of a mail: what `git mailsplit` starts a mail at, what
/// `git mailinfo` splits the message from the patch at, and what
/// `git apply` looks for. A `+++` line is not among them: git reads one
/// only right after a `---` line, which is.
fn reads_as_patch(line: &str) -> bool {
    starts_with_any(line, &["--- ", "---\t", "@@ -", "Index: ", "diff -"])
        || MAIL_SPLIT_RE.is_match(line)
}

fn starts_with_any(line: &str, starts: &[&str]) -> bool {
    starts.iter().any(|start| line.starts_with(start))
}

/// Where in the patch a line is.
#[derive(Debug)]
enum State {
    /// The mail's header fields, up to the first empty line. `folds` says
    /// whether the last field may continue on the next line.
    Mail { folds: bool },
    /// The commit message and the summary of changes.
    Message,
    /// The lines of one file before its hunks.
    File { path: String, stage: Stage },
    /// Inside a hunk that has this many lines of each side to come.
    Hunk { old: u32, new: u32 },
    /// After a complete hunk.
    AfterHunk,
    /// After an empty line that follows a file's change: another file, the
    /// signature or the end may follow.
    Between,
    /// After `-- `, which starts format-patch's signature: one line of it
    /// (`seen` once it was read), then nothing but empty lines.
    Signature { seen: bool },
    /// After a line that is a problem and is no part of anything: only
    /// further files are still looked for, to name them.
    Lost,
}

/// How far a file's header has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// The lines git adds: modes, index.
    Extended,
    /// After `---`: `+++` is next.
    Plus,
    /// After `+++`: a hunk is next.
    Hunks,
}

#[derive(Debug, Default)]
struct Reader {
    problems: Vec<String>,
    files: BTreeSet<String>,
    base_commit: Option<String>,
    /// Whether the policy exempts the top-level `.github/` folder.
    github_exempt: bool,
    /// What the header of the file being read said it does to the file,
    /// once it has stated a mode.
    change: Option<Change>,
}

/// What a file's header says the change does to the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    Added,
    Deleted,
    Edited,
}

impl Reader {
    fn problem(&mut self, text: impl Into<String>) {
        self.problems.push(text.into());
    }

    fn mail(&mut self, line: &str, folds: bool) -> State {
        if line.is_empty() {
            return State::Message;
        }
        // A line that only JavaScript ends at these: gh-aw's handler would
        // find a header in the middle of what is one line here.
        if line.contains(['\u{2028}', '\u{2029}']) {
            self.problem(format!(
                "a line separator in the mail header {}",
                quoted(line)
            ));
        }
        if line.starts_with([' ', '\t']) {
            if !folds {
                self.problem(format!("unexpected mail header {}", quoted(line)));
            }
            return State::Mail { folds };
        }
        // Without a colon git takes the headers to be over.
        let Some((name, value)) = line.split_once(':') else {
            self.problem(format!("unexpected mail header {}", quoted(line)));
            return State::Mail { folds: false };
        };
        let value = value.trim();
        let fixed = FIXED_HEADERS.iter().find(|(fixed, _)| *fixed == name);
        match fixed {
            Some((_, want)) if value.eq_ignore_ascii_case(want) => {}
            None if FREE_HEADERS.contains(&name) => {}
            _ => self.problem(format!("unexpected mail header {}", quoted(line))),
        }
        if name == BASE_COMMIT_HEADER && self.base_commit.replace(value.to_owned()).is_some() {
            self.problem(format!("{BASE_COMMIT_HEADER} twice"));
        }
        // Only a subject is long enough for git to fold it.
        State::Mail {
            folds: name == "Subject",
        }
    }

    /// A `diff --git` line: the start of a file's change.
    fn file(&mut self, line: &str) -> State {
        let rest = line.strip_prefix(DIFF_HEADER).unwrap_or_default();
        // Patches are made without renames, so both sides name one path,
        // and a plain path has no space: the split is not ambiguous.
        let Some((old, new)) = rest.strip_prefix("a/").and_then(|r| r.split_once(" b/")) else {
            self.problem(format!("unparseable header: {}", quoted(line)));
            return State::Lost;
        };
        for path in [old, new] {
            if let Some(why) = path_problem(path, self.github_exempt) {
                self.problem(format!("{path:?}: {why}"));
            }
            self.files.insert(path.to_owned());
        }
        if old != new {
            self.problem(format!("a header naming two paths: {}", quoted(line)));
        }
        self.change = None;
        State::File {
            path: new.to_owned(),
            stage: Stage::Extended,
        }
    }

    fn hunk(&mut self, line: &str) -> State {
        let count = |group: Option<regex::Match<'_>>| match group {
            // git leaves a count of one out.
            None => Some(1),
            Some(digits) => digits.as_str().parse::<u32>().ok(),
        };
        let counts = HUNK_RE
            .captures(line)
            .and_then(|found| Some((count(found.get(1))?, count(found.get(2))?)));
        match counts {
            Some((0, 0)) => State::AfterHunk,
            Some((old, new)) => State::Hunk { old, new },
            None => {
                self.problem(format!("a damaged hunk header: {}", quoted(line)));
                State::Lost
            }
        }
    }

    /// A line after a file's change that is no part of it. Nothing but
    /// another file, the signature or the end is expected there: git would
    /// skip what it cannot read, so whatever else is there is something
    /// only git could make sense of, and is refused unread.
    fn between(&mut self, line: &str) -> State {
        if line.starts_with(DIFF_HEADER) {
            self.file(line)
        } else if line.is_empty() {
            State::Between
        } else if line == SIGNATURE {
            State::Signature { seen: false }
        } else {
            self.problem(format!(
                "a line after a file's change that is no part of one: {}",
                quoted(line)
            ));
            State::Lost
        }
    }

    /// A line after one that was a problem already.
    fn lost(&mut self, line: &str) -> State {
        if line.starts_with(DIFF_HEADER) {
            self.file(line)
        } else {
            State::Lost
        }
    }

    /// A line of a file's header before `---`. Every line git reads as
    /// part of the header is either read in full here or a problem: a line
    /// taken for the header's end that git reads on from would hide what
    /// follows it.
    fn extended(&mut self, line: &str, path: String) -> State {
        if let Some(side) = line.strip_prefix("--- ") {
            // Only a file the header adds has no old side. Anything else
            // there is a second path, which git would act on.
            let old_side = match self.change {
                Some(Change::Added) => DEV_NULL.to_owned(),
                _ => format!("a/{path}"),
            };
            if side != old_side {
                self.problem(format!("{} under the header of {path:?}", quoted(line)));
            }
            // Without a mode in the header git takes the one the file has,
            // which may be a link's or a submodule's. With one, git refuses
            // a file of another type, so the mode read here is the file's.
            if self.change.is_none() {
                self.problem(format!("a change to {path:?} that does not state its mode"));
            }
            return State::File {
                path,
                stage: Stage::Plus,
            };
        }
        if line.starts_with("GIT binary patch") || line.starts_with("Binary files ") {
            self.problem("a binary file");
            return State::Lost;
        }
        if starts_with_any(line, MODE_CHANGES) {
            self.problem(format!("mode change ({line})"));
        } else if starts_with_any(line, RENAMES) {
            self.problem(format!(
                "a rename or copy ({line}); patches are made without them"
            ));
        } else if let Some(found) = FILE_MODE_RE.captures(line) {
            // A new file is plain. One that is changed or deleted keeps the
            // mode it had (an executable is no new executable), but is
            // never a link or a submodule.
            let (what, mode) = (&found[1], &found[2]);
            let change = match what {
                NEW_FILE => Change::Added,
                DELETED_FILE => Change::Deleted,
                _ => Change::Edited,
            };
            if self.change.replace(change).is_some() {
                self.problem(format!("two modes in the header of {path:?}"));
            }
            if what == NEW_FILE && mode != PLAIN_MODE {
                self.problem(format!(
                    "a new symlink, submodule, executable or special file ({line})"
                ));
            } else if ![PLAIN_MODE, EXECUTABLE_MODE].contains(&mode) {
                self.problem(format!("symlink, submodule or special file ({line})"));
            }
        } else if starts_with_any(line, FILE_MODES) {
            if !INDEX_RE.is_match(line) {
                self.problem(format!("a damaged header for {path:?}: {}", quoted(line)));
            }
        } else {
            // Nothing git reads as the header: it is over, as for an empty
            // file, which has no more than this.
            return self.between(line);
        }
        State::File {
            path,
            stage: Stage::Extended,
        }
    }

    fn line(&mut self, state: State, line: &str) -> State {
        match state {
            State::Mail { folds } => self.mail(line, folds),
            State::Message if line.starts_with(DIFF_HEADER) => self.file(line),
            State::Message => {
                // `---` alone ends the message, as format-patch writes it.
                if reads_as_patch(line) {
                    self.problem(format!(
                        "a line of the commit message that git would read as a patch: {}",
                        quoted(line)
                    ));
                }
                State::Message
            }
            State::File {
                path,
                stage: Stage::Extended,
            } => {
                if line.starts_with(DIFF_HEADER) {
                    self.file(line)
                } else {
                    self.extended(line, path)
                }
            }
            State::File {
                path,
                stage: Stage::Plus,
            } => match line.strip_prefix("+++ ") {
                Some(side) => {
                    let new_side = match self.change {
                        Some(Change::Deleted) => DEV_NULL.to_owned(),
                        _ => format!("b/{path}"),
                    };
                    if side != new_side {
                        self.problem(format!("{} under the header of {path:?}", quoted(line)));
                    }
                    State::File {
                        path,
                        stage: Stage::Hunks,
                    }
                }
                None => {
                    self.problem(format!("a damaged header for {path:?}: {}", quoted(line)));
                    self.lost(line)
                }
            },
            State::File {
                path,
                stage: Stage::Hunks,
            } => {
                if line.starts_with("@@ ") {
                    self.hunk(line)
                } else {
                    self.problem(format!("a header without a hunk for {path:?}"));
                    self.lost(line)
                }
            }
            State::Hunk { old, new } => {
                // An empty line is a context line that lost its space.
                let used = match line.bytes().next() {
                    Some(b'\\') => Some((0, 0)),
                    Some(b' ') | None => Some((1, 1)),
                    Some(b'-') => Some((1, 0)),
                    Some(b'+') => Some((0, 1)),
                    Some(_) => None,
                };
                let left = used.and_then(|(old_used, new_used)| {
                    Some((old.checked_sub(old_used)?, new.checked_sub(new_used)?))
                });
                match left {
                    Some((0, 0)) => State::AfterHunk,
                    Some((old, new)) => State::Hunk { old, new },
                    None => {
                        self.problem(format!("a damaged hunk at {}", quoted(line)));
                        self.lost(line)
                    }
                }
            }
            State::AfterHunk if line.starts_with("@@ ") => self.hunk(line),
            // "\ No newline at end of file" for the hunk's last line.
            State::AfterHunk if line.starts_with('\\') => State::AfterHunk,
            State::AfterHunk | State::Between => self.between(line),
            State::Signature { seen: false } if !line.is_empty() && !reads_as_patch(line) => {
                State::Signature { seen: true }
            }
            State::Signature { seen: true } if line.is_empty() => State::Signature { seen: true },
            State::Signature { .. } => {
                self.problem(format!("a line after the signature: {}", quoted(line)));
                State::Lost
            }
            State::Lost => self.lost(line),
        }
    }
}

/// The protected files among `paths`, by gh-aw's rule for
/// `create_pull_request` (`manifest_file_helpers.cjs`): a listed name at
/// any depth, and anything under a top-level directory whose name starts
/// with a dot.
fn protected<'p>(paths: &'p BTreeSet<String>, rules: &PatchRules<'_>) -> Vec<&'p str> {
    let listed = |path: &str| {
        let name = path.rsplit('/').next().unwrap_or(path);
        rules.protected_files.iter().any(|file| file == name)
    };
    let dot_folder = |path: &str| {
        rules.protect_top_level_dot_folders
            && path.split_once('/').is_some_and(|(top, _)| {
                top.len() > 1
                    && top.starts_with('.')
                    && !rules.unprotected_dot_folders.iter().any(|name| name == top)
            })
    };
    paths
        .iter()
        .map(String::as_str)
        .filter(|path| listed(path) || dot_folder(path))
        .collect()
}

/// What reading a patch gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchReading {
    /// Why it may not be applied; empty if it may.
    pub problems: Vec<String>,
    /// The paths it names, sorted.
    pub files: Vec<String>,
}

/// Reads a patch against `base_commit` under `rules`.
pub fn read_patch(patch: &str, rules: &PatchRules<'_>, base_commit: &str) -> PatchReading {
    let mut reader = Reader {
        github_exempt: rules
            .unprotected_dot_folders
            .iter()
            .any(|name| name == EXEMPTABLE_DOT_FOLDER),
        ..Reader::default()
    };
    let mut lines = patch.strip_suffix('\n').unwrap_or(patch).split('\n');

    // Git ends a line at a newline only. A reader that also ends one at a
    // carriage return sees other lines than git does, so there is none
    // but before a newline.
    if patch
        .split('\n')
        .any(|line| line.trim_end_matches('\r').contains('\r'))
        || patch.ends_with('\r')
    {
        reader.problem("a carriage return inside a line");
    }
    match lines.next() {
        Some(first) if MAIL_START_RE.is_match(first) => {}
        first => reader.problem(format!(
            "not the output of git format-patch: it starts with {}",
            quoted(first.unwrap_or_default())
        )),
    }
    let end = lines.fold(State::Mail { folds: false }, |state, line| {
        reader.line(state, line)
    });
    match end {
        State::Hunk { .. } => reader.problem("the patch ends inside a hunk"),
        State::File {
            path,
            stage: Stage::Plus | Stage::Hunks,
        } => {
            reader.problem(format!("the patch ends inside the header of {path:?}"));
        }
        _ => {}
    }

    let Reader {
        mut problems,
        files,
        base_commit: found,
        ..
    } = reader;
    if files.is_empty() {
        problems.push("the patch holds no change".to_owned());
    }
    if files.len() > usize::try_from(rules.max_patch_files).unwrap_or(usize::MAX) {
        problems.push(format!(
            "the patch touches {} files, over {}",
            files.len(),
            rules.max_patch_files
        ));
    }
    if found.as_deref() != Some(base_commit) {
        problems.push(format!(
            "the patch's {BASE_COMMIT_HEADER} is not the base commit {base_commit}"
        ));
    }
    let protected = protected(&files, rules);
    if !protected.is_empty() {
        problems.push(format!("protected files: {}", protected.join(", ")));
    }

    // Each once, in the order found.
    let mut seen = BTreeSet::new();
    problems.retain(|problem| seen.insert(problem.clone()));
    PatchReading {
        problems,
        files: files.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PullRequest;
    use crate::policy::tests::policy;

    const BASE: &str = "1111111111111111111111111111111111111111";

    fn patch_problems(patch: &str, rules: &PullRequest, base_commit: &str) -> Vec<String> {
        read_patch(patch, &rules.rules(), base_commit).problems
    }

    /// The mail headers and message of a patch against `BASE`.
    fn head() -> String {
        format!(
            "From 2222222222222222222222222222222222222222 Mon Sep 17 00:00:00 2001\n\
             {BASE_COMMIT_HEADER}: {BASE}\n\
             From: agent <agent@localhost>\n\
             Date: Tue, 6 Oct 2026 21:02:35 -0400\n\
             Subject: [PATCH] Change things\n\
             \n\
             Why it changes.\n\
             ---\n \
             src/lib.rs | 2 +-\n \
             1 file changed, 1 insertion(+), 1 deletion(-)\n\
             \n"
        )
    }

    fn edit(path: &str) -> String {
        format!(
            "diff --git a/{path} b/{path}\nindex f328e4d..a83147c 100644\n\
             --- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-fn main() {{}}\n+fn main() {{ 1 }}\n"
        )
    }

    fn add(path: &str, mode: &str) -> String {
        format!(
            "diff --git a/{path} b/{path}\nnew file mode {mode}\nindex 0000000..c600332\n\
             --- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n"
        )
    }

    fn remove(path: &str, mode: &str) -> String {
        format!(
            "diff --git a/{path} b/{path}\ndeleted file mode {mode}\nindex 1a24852..0000000\n\
             --- a/{path}\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
        )
    }

    fn problems(patch: &str) -> Vec<String> {
        let rules = policy().safe_outputs.create_pull_request.unwrap();
        patch_problems(patch, &rules, BASE)
    }

    #[test]
    fn exact_dot_folder_exemption_preserves_fixed_refusals() {
        for enabled in [false, true] {
            let mut pr = policy().safe_outputs.create_pull_request.unwrap();
            if enabled {
                pr.unprotected_dot_folders.push(".github".into());
            }
            for (path, allowed) in [
                (".github/workflows/check.yml", enabled),
                (".github/actions/build/action.yml", enabled),
                (".github-other/check.yml", false),
                (".agents/config.json", false),
                (".github/CODEOWNERS", false),
                (".github/.git/config", false),
                (".github/package.json", false),
                (".github/.husky/pre-commit", false),
            ] {
                assert_eq!(
                    patch_problems(&(head() + &edit(path)), &pr, BASE).is_empty(),
                    allowed,
                    "{enabled}: {path}"
                );
            }
        }
    }

    #[test]
    fn what_format_patch_writes_is_accepted() {
        let no_newline = "diff --git a/nonl b/nonl\nindex c1b0730..e25f181 100644\n\
            --- a/nonl\n+++ b/nonl\n@@ -1 +1 @@\n-x\n\\ No newline at end of file\n+y\n\
            \\ No newline at end of file\n";
        let empty = "diff --git a/empty.txt b/empty.txt\nnew file mode 100644\n\
            index 0000000..e69de29\n";
        let two_hunks = "diff --git a/a.rs b/a.rs\nindex f328e4d..a83147c 100644\n\
            --- a/a.rs\n+++ b/a.rs\n@@ -1,3 +1,4 @@ fn f()\n a\n+b\n\n c\n@@ -10,2 +11 @@\n-d\n e\n";
        // What a removed line that starts with "-- a/x" looks like, and an
        // added "++ b/x": content, since the hunk's counts say so.
        let dashes = "diff --git a/a.md b/a.md\nindex f328e4d..a83147c 100644\n\
            --- a/a.md\n+++ b/a.md\n@@ -1,2 +1,2 @@\n--- a/.github/x\n+++ b/.github/x\n \
            diff --git a/.github/y b/.github/y\n";
        let mime = head().replace(
            "\n\nWhy",
            "\nMIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\n\
             Content-Transfer-Encoding: 8bit\n\nWhy",
        );
        let folded = head().replace(
            "Change things",
            "Change things, and go on\n for a second line",
        );
        let cases: &[(&str, String)] = &[
            (
                "a message with lines git reads only after others",
                head().replace("Why it", "+++ great\n@@ mention\nFrom the start.\nWhy it")
                    + &edit("a.rs"),
            ),
            (
                "a signature after an empty file",
                head() + empty + "-- \n2.52.0\n\n",
            ),
            ("empty lines at the end", head() + &edit("a.rs") + "\n\n"),
            ("an edit", head() + &edit("src/lib.rs")),
            (
                "several files",
                head() + &edit("src/lib.rs") + &add("src/new.rs", "100644") + empty,
            ),
            ("an empty file last", head() + empty),
            ("an empty file first", head() + empty + &edit("a.rs")),
            ("no newline at the end", head() + no_newline + &edit("a.rs")),
            ("two hunks and an empty context line", head() + two_hunks),
            (
                "an edit to an executable",
                head() + &edit("run.sh").replace("100644", "100755"),
            ),
            (
                "the deletion of an executable",
                head() + &remove("gone.sh", "100755"),
            ),
            ("content that looks like headers", head() + dashes),
            // No README is protected, at any depth (#537).
            (
                "a README, at the top and nested",
                head() + &edit("README.md") + &add("tests/coccinelle/README.md", "100644"),
            ),
            ("a signature", head() + &edit("a.rs") + "-- \n2.52.0\n\n"),
            ("a message that is not ASCII", mime + &edit("a.rs")),
            ("a folded subject", folded + &edit("a.rs")),
            (
                "a crlf file",
                head() + &edit("a.rs").replace("{ 1 }\n", "{ 1 }\r\n"),
            ),
            (
                "a rule in the message",
                head().replace("Why it", "----\n\n- - -\n\nWhy it") + &edit("a.rs"),
            ),
            (
                "a message that starts a line with From",
                head().replace("Why it", "From now on it is so.\nWhy it") + &edit("a.rs"),
            ),
        ];
        for (name, patch) in cases {
            assert_eq!(problems(patch), Vec::<String>::new(), "{name}");
        }
    }

    #[test]
    fn what_is_refused() {
        let binary = "diff --git a/blob.bin b/blob.bin\nnew file mode 100644\n\
            index 0000000..1d27b5e\nGIT binary patch\nliteral 5\nMcmZQzWMT#Y01f~L\n\nliteral 0\n\
            HcmV?d00001\n\n";
        let mode = "diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n";
        let rename = "diff --git a/a.rs b/a.rs\nsimilarity index 100%\nrename from a.rs\n\
            rename to b.rs\n";
        // A change with no `diff --git` line, which `git apply` takes all
        // the same: in the message, after the last file, and under the
        // header of another file.
        let bare = "--- a/.github/workflows/x.yml\n+++ b/.github/workflows/x.yml\n\
            @@ -0,0 +1 @@\n+on: push\n";
        // Another mail, as `git mailsplit` finds one: its start need not be
        // format-patch's, and git decodes its body, which then holds
        // anything at all.
        let encoded_mail = "From evil Thu Jan  1 00:00:00 2026\nFrom: x <x@localhost>\n\
            Subject: injected\nContent-Transfer-Encoding: base64\n\n\
            ZGlmZiAtLWdpdCBhLy5naXRodWIveCBiLy5naXRodWIveAo=\n";
        let other_file = edit("a.rs").replace("+++ b/a.rs", "+++ b/.github/workflows/x.yml");
        let many: String = (0..101)
            .map(|i| add(&format!("f/{i}.rs"), "100644"))
            .collect();
        let cases: &[(&str, String, &str)] = &[
            // `/dev/null` where the header did not say so is a path of its
            // own to git: it deletes one file and adds `dev/null`.
            (
                "an edit with no new side",
                head() + &edit("a.rs").replace("+++ b/a.rs", "+++ /dev/null"),
                "\"+++ /dev/null\" under the header of \"a.rs\"",
            ),
            (
                "an edit with no old side",
                head() + &edit("a.rs").replace("--- a/a.rs", "--- /dev/null"),
                "\"--- /dev/null\" under the header of \"a.rs\"",
            ),
            (
                "a new file with an old side",
                head() + &add("a.rs", "100644").replace("--- /dev/null", "--- a/a.rs"),
                "\"--- a/a.rs\" under the header of \"a.rs\"",
            ),
            (
                "a deletion with a new side",
                head() + &remove("a.rs", "100644").replace("+++ /dev/null", "+++ b/a.rs"),
                "\"+++ b/a.rs\" under the header of \"a.rs\"",
            ),
            (
                "two modes",
                head()
                    + &add("a.rs", "100644")
                        .replace("index 0000000..c600332", "index 0000000..c600332 100755"),
                "two modes in the header of \"a.rs\"",
            ),
            (
                "a line separator in a folded mail header",
                head().replace(
                    "Change things",
                    &format!("x\n y\u{2029}{BASE_COMMIT_HEADER}: {}", "e".repeat(40)),
                ) + &edit("a.rs"),
                "a line separator in the mail header",
            ),
            // git takes the mode a file has when the header states none:
            // this would edit a link, or move a submodule, unseen.
            (
                "an edit without a mode",
                head() + &edit("link").replace(" 100644\n", "\n"),
                "a change to \"link\" that does not state its mode",
            ),
            (
                "an edit without an index line",
                head() + &edit("link").replace("index f328e4d..a83147c 100644\n", ""),
                "that does not state its mode",
            ),
            (
                "a hunk as long as a count can be",
                head()
                    + &edit("a.rs").replace("-1 +1", "-1,4294967295 +1,4294967295")
                    + "diff --git a/.github/x b/.github/x\n",
                "protected files: .github/x",
            ),
            (
                "digits that are not ASCII in a hunk",
                head() + &edit("a.rs").replace("-1 +1", "-\u{661} +\u{661}"),
                "a damaged hunk header",
            ),
            (
                "a mail header without a colon",
                head().replace("\nDate:", "\nSubject\nDate:") + &edit("a.rs"),
                "unexpected mail header \"Subject\"",
            ),
            (
                "a line separator in a mail header",
                head().replace(
                    "Change things",
                    &format!("x\u{2028}{BASE_COMMIT_HEADER}: {}", "e".repeat(40)),
                ) + &edit("a.rs"),
                "a line separator in the mail header",
            ),
            (
                "more after the signature",
                head() + &edit("a.rs") + "-- \n2.52.0\n\nmore\n",
                "a line after the signature",
            ),
            (
                "anything after the last file",
                head() + &edit("a.rs") + "Content-Transfer-Encoding: base64\n",
                "that is no part of one",
            ),
            (
                "nothing",
                String::new(),
                "not the output of git format-patch",
            ),
            ("no change", head(), "holds no change"),
            (
                "not a patch",
                "rm -rf /\n".to_owned(),
                "not the output of git format-patch",
            ),
            (
                "a protected file",
                head() + &edit("CONTRIBUTING.md"),
                "protected files: CONTRIBUTING.md",
            ),
            (
                "a protected file below",
                head() + &edit("docs/CONTRIBUTING.md"),
                "protected files: docs/CONTRIBUTING.md",
            ),
            (
                "a manifest",
                head() + &add("package.json", "100644"),
                "protected files: package.json",
            ),
            (
                "CI",
                head() + &add(".github/workflows/x.yml", "100644"),
                "\".github/workflows/x.yml\": protected path",
            ),
            (
                "a top-level dot-folder",
                head() + &add(".cursor/rules", "100644"),
                "protected files: .cursor/rules",
            ),
            (
                "a nested git file",
                head() + &add("sub/.gitattributes", "100644"),
                "protected path",
            ),
            (
                "an editor's settings",
                head() + &add(".envrc", "100644"),
                "protected path",
            ),
            (
                "nested owners",
                head() + &add("docs/CODEOWNERS", "100644"),
                "protected path",
            ),
            (
                "a path with a space",
                head() + &add("a b.rs", "100644"),
                "\"a b.rs\": not a plain relative path",
            ),
            (
                "a path that climbs",
                head() + &add("a/../b.rs", "100644"),
                "not a plain relative path",
            ),
            (
                "an absolute path",
                head() + &edit("a.rs").replace("a/a.rs b/a.rs", "a//etc/x b//etc/x"),
                "not a plain relative path",
            ),
            (
                "a quoted path",
                head() + "diff --git \"a/\\303\\251\" \"b/\\303\\251\"\nnew file mode 100644\n",
                "unparseable header",
            ),
            (
                "two paths",
                head() + &edit("a.rs").replace("b/a.rs\nindex", "b/b.rs\nindex"),
                "naming two paths",
            ),
            (
                "a new executable",
                head() + &add("run.sh", "100755"),
                "new symlink, submodule, executable",
            ),
            (
                "a symlink",
                head() + &add("link", "120000"),
                "new symlink, submodule, executable",
            ),
            (
                "a submodule",
                head() + &add("sub", "160000"),
                "new symlink, submodule, executable",
            ),
            (
                "the deletion of a symlink",
                head() + &remove("link", "120000"),
                "symlink, submodule or special file",
            ),
            (
                "an edit to a symlink",
                head() + &edit("link").replace("100644", "120000"),
                "symlink, submodule or special file",
            ),
            (
                "a mode change",
                head() + mode,
                "mode change (old mode 100644)",
            ),
            ("a binary file", head() + binary, "a binary file"),
            (
                "a rename",
                head() + rename,
                "a rename or copy (rename from a.rs)",
            ),
            (
                "a mode change with a space after it",
                head() + &mode.replace("100755\n", "100755 \n"),
                "mode change (new mode 100755 )",
            ),
            (
                "a mode change after a damaged line",
                head() + &mode.replace("old mode", "index zz\nold mode"),
                "mode change (old mode 100644)",
            ),
            (
                "a damaged index line",
                head() + &edit("a.rs").replace("f328e4d..a83147c", "zz"),
                "a damaged header for \"a.rs\"",
            ),
            (
                "a mode with a space after it",
                head() + &add("a.rs", "100755 "),
                "a damaged header for \"a.rs\"",
            ),
            (
                "a mode change after the names",
                head() + &edit("a.rs").replace("@@ -1", "old mode 100644\nnew mode 100755\n@@ -1"),
                "a header without a hunk",
            ),
            (
                "a hunk right under the header",
                head() + "diff --git a/a.rs b/a.rs\n@@ -1 +1 @@\n-a\n+b\n",
                "that is no part of one",
            ),
            (
                "too many files",
                head() + &many,
                "touches 101 files, over 100",
            ),
            (
                "another base",
                head().replace(BASE, &"0".repeat(40)) + &edit("a.rs"),
                "is not the base commit",
            ),
            (
                "no base",
                head().replace(BASE_COMMIT_HEADER, "X-Other") + &edit("a.rs"),
                "is not the base commit",
            ),
            (
                "two bases",
                head().replace("From: ", &format!("{BASE_COMMIT_HEADER}: {BASE}\nFrom: "))
                    + &edit("a.rs"),
                "twice",
            ),
            (
                "a patch in the message",
                head().replace("Why it changes.\n", bare) + &edit("a.rs"),
                "git would read as a patch",
            ),
            (
                "a patch after the separator",
                head().replace(" src/lib.rs | 2 +-\n", bare) + &edit("a.rs"),
                "git would read as a patch",
            ),
            (
                "a patch after the last file",
                head() + &edit("a.rs") + bare,
                "that is no part of one",
            ),
            (
                "a patch after an empty file",
                head() + add("e", "100644").split("---").next().unwrap() + bare,
                "under the header of \"e\"",
            ),
            (
                "a hunk for another file",
                head() + &other_file,
                "under the header of \"a.rs\"",
            ),
            (
                "an old-style diff",
                head() + "Index: a.rs\n" + &edit("a.rs"),
                "git would read as a patch",
            ),
            (
                "a second mail",
                head() + &edit("a.rs") + &head() + &edit(".github/x"),
                "that is no part of one",
            ),
            (
                "a second mail with an encoded body",
                head() + &edit("a.rs") + encoded_mail,
                "that is no part of one",
            ),
            (
                "a second mail in the message",
                head().replace("Why it changes.\n", encoded_mail) + &edit("a.rs"),
                "git would read as a patch",
            ),
            (
                "an encoded body",
                head().replace("\n\nWhy", "\nContent-Transfer-Encoding: base64\n\nWhy")
                    + &edit("a.rs"),
                "unexpected mail header",
            ),
            (
                "a header in another case",
                head().replace("\n\nWhy", "\ncontent-transfer-encoding: base64\n\nWhy")
                    + &edit("a.rs"),
                "unexpected mail header",
            ),
            (
                "more than one part",
                head().replace(
                    "\n\nWhy",
                    "\nContent-Type: multipart/mixed; boundary=x\n\nWhy",
                ) + &edit("a.rs"),
                "unexpected mail header",
            ),
            (
                "a folded header that is not the subject",
                head().replace("\nDate:", "\n base64\nDate:") + &edit("a.rs"),
                "unexpected mail header",
            ),
            (
                "a hunk cut short",
                head() + edit("a.rs").trim_end_matches("+fn main() { 1 }\n"),
                "ends inside a hunk",
            ),
            (
                "a hunk with too little",
                head() + &edit("a.rs").replace("-1 +1", "-1,3 +1,3") + &edit("b.rs"),
                "a damaged hunk",
            ),
            (
                "a header cut short",
                head() + "diff --git a/a.rs b/a.rs\nindex 1..2 100644\n--- a/a.rs\n",
                "ends inside the header",
            ),
            (
                "a header without a hunk",
                head() + "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n" + &edit("b.rs"),
                "a header without a hunk",
            ),
            (
                "a carriage return in a line",
                head() + &edit("a.rs").replace("{ 1 }", "{ 1\rdiff --git a/x b/x }"),
                "a carriage return inside a line",
            ),
        ];
        for (name, patch, want) in cases {
            let found = problems(patch);
            assert!(found.iter().any(|p| p.contains(want)), "{name}: {found:#?}");
        }
    }

    #[test]
    fn each_problem_is_reported_once() {
        let patch = head() + &add("a b.rs", "100644");
        let found = problems(&patch);
        assert_eq!(found, ["\"a b.rs\": not a plain relative path"]);
    }

    #[test]
    fn unprotected_names_and_folders_follow_the_policy() {
        let mut rules = policy().safe_outputs.create_pull_request.unwrap();
        rules
            .protected_files
            .retain(|name| name != "CONTRIBUTING.md");
        let patch =
            head() + &edit("CONTRIBUTING.md") + &edit("docs/CONTRIBUTING.md") + &edit("AGENTS.md");
        assert_eq!(
            patch_problems(&patch, &rules, BASE),
            ["protected files: AGENTS.md"]
        );
    }
}
