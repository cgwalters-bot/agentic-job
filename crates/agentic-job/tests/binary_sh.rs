//! `secure-host/binary.sh`: the digest names content, modes and names and
//! nothing else, and a file that is not the pinned one is refused.
//! binary.sh runs in a copy of a small source tree, with gh and the build
//! tools replaced by stubs: gh serves fixture files as GitHub's REST API
//! would and logs what it was asked, and sleep logs the waits of the
//! retries.

// clippy.toml lets only test functions unwrap, and the helpers here are
// test code too.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, UNIX_EPOCH};

use regex::Regex;
use serde_json::{Map, Value, json};
use tempfile::TempDir;

const REPOSITORY: &str = "cgwalters-forge/agentic-job";
const TARGET: &str = "x86_64-unknown-linux-musl";
const NAMES: [&str; 3] = ["agentic-job", "fake-agent", "secure-host"];
const OBJECT: &str = "world_write.bpf.o";
const BYTES: &str = "binary";
/// The environment `binary.sh` would take a tagged release's identity from,
/// which the caller's own must not leak into.
const WORKFLOW_PREFIX: &str = "WORKFLOW_";

/// gh's API calls log the URL they stand for. The Nth call fails with the
/// trace in trace-N, where there is one; a URL ending in the name in
/// `fail` fails with a server error. A release's assets get IDs in the
/// order they are listed.
const GH: &str = r#"
missing() { printf '< HTTP/2.0 404 Not Found\n' >&2; exit 1; }
serve() {
  echo "fetch https://$1" >> "$STUB_LOG"
  if [ -e "$STUB_FILES/fail" ] && [[ "$1" == */"$(cat "$STUB_FILES/fail")" ]]; then
    printf '< HTTP/2.0 500 Internal Server Error\n' >&2; exit 1
  fi
  [ -f "$STUB_FILES/$1" ] || missing
  cat "$STUB_FILES/$1"
}
if [ "$1" != api ]; then
  echo "gh $*" >> "$STUB_LOG"
  [ ! -e "$STUB_FILES/gh-fail" ] || { echo "signature refused" >&2; exit 1; }
  exit 0
fi
[ "$GH_DEBUG" = api ] || { echo "no API trace asked for" >&2; exit 3; }
calls=$(( $(cat "$STUB_FILES/calls" 2> /dev/null || echo 0) + 1 ))
echo "$calls" > "$STUB_FILES/calls"
[ ! -e "$STUB_FILES/trace-$calls" ] || { cat "$STUB_FILES/trace-$calls" >&2; exit 1; }
shift
if [ "$1" = -H ]; then
  [ "$2" = "Accept: application/octet-stream" ] || exit 3
  serve "$(cat "$STUB_FILES/asset-${3##*/}")"
elif [[ "$1" =~ ^repos/([^/]+/[^/]+)/releases/tags/([^/]+)$ ]]; then
  release="github.com/${BASH_REMATCH[1]}/releases/download/${BASH_REMATCH[2]}"
  [ -d "$STUB_FILES/$release" ] || missing
  for name in "$STUB_FILES/$release"/*; do
    id=$(( $(cat "$STUB_FILES/ids" 2> /dev/null || echo 0) + 1 ))
    echo "$id" > "$STUB_FILES/ids"
    echo "$release/${name##*/}" > "$STUB_FILES/asset-$id"
    jq -n --arg name "${name##*/}" --argjson id "$id" '{name: $name, id: $id}'
  done | jq -s '{assets: .}'
else
  serve "api.github.com/$1"
fi
"#;

const CLANG: &str =
    r#"echo "clang $*" >> "$STUB_LOG"; while [ "$1" != -o ]; do shift; done; echo object > "$2""#;

const CARGO: &str = r#"
echo "cargo $*" >> "$STUB_LOG"; mkdir -p target/x86_64-unknown-linux-musl/release
for name in agentic-job fake-agent secure-host; do echo built > target/x86_64-unknown-linux-musl/release/$name; done"#;

const STUBS: [(&str, &str); 7] = [
    ("gh", GH),
    ("sleep", r#"echo "sleep $*" >> "$STUB_LOG""#),
    ("clang", CLANG),
    ("musl-gcc", "exit 0"),
    ("rustup", r#"echo "rustup $*" >> "$STUB_LOG""#),
    ("cargo", CARGO),
    ("sudo", r#"echo "sudo $*" >> "$STUB_LOG""#),
];

/// Held while a stub is written and while a child is forked: a child forked
/// while another thread has a stub open for writing would keep it open, and
/// running that stub would fail with ETXTBSY.
static SPAWN: Mutex<()> = Mutex::new(());

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../secure-host/binary.sh")
}

fn built_from() -> Vec<String> {
    let text = fs::read_to_string(script()).unwrap();
    let re = Regex::new(r"(?m)^BUILT_FROM=\(([^)]*)\)$").unwrap();
    let names = &re.captures(&text).unwrap()[1];
    names.split(' ').map(str::to_owned).collect()
}

fn sha256(bytes: impl AsRef<[u8]>) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes.as_ref())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn tempdir(prefix: &str) -> TempDir {
    tempfile::Builder::new().prefix(prefix).tempdir().unwrap()
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn matches(text: &str, pattern: &str) -> bool {
    Regex::new(pattern).unwrap().is_match(text)
}

fn write_stub(dir: &Path, name: &str, body: &str) {
    let _guard = SPAWN.lock().unwrap();
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/bash\n{body}\n")).unwrap();
    chmod(&path, 0o755);
}

fn spawn(command: &mut Command) -> Output {
    let child = {
        let _guard = SPAWN.lock().unwrap();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    child.wait_with_output().unwrap()
}

fn bin() -> &'static Path {
    static BIN: OnceLock<TempDir> = OnceLock::new();
    BIN.get_or_init(|| {
        let bin = tempdir("stubs-");
        for (name, body) in STUBS {
            write_stub(bin.path(), name, body);
        }
        bin
    })
    .path()
}

/// A source with every part of BUILT_FROM, and this binary.sh in it.
fn tree() -> TempDir {
    let root = tempdir("source-");
    for name in built_from() {
        if name.contains('.') {
            write(&root.path().join(&name), &name);
        } else {
            write(&root.path().join(&name).join("src/lib.rs"), "// lib\n");
        }
    }
    fs::copy(script(), root.path().join("secure-host/binary.sh")).unwrap();
    root
}

#[derive(Default)]
struct Opts {
    env: Vec<(String, String)>,
    files: Vec<(String, String)>,
    fail: Option<String>,
    gh_fail: bool,
    traces: Vec<Option<String>>,
    script: Option<PathBuf>,
}

struct Run {
    status: Option<i32>,
    stdout: String,
    stderr: String,
    log: Vec<String>,
    output: String,
}

fn lines(text: &str) -> Vec<String> {
    text.trim()
        .split('\n')
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn run(root: &Path, args: &[&str], opts: Opts) -> Run {
    let served = tempdir("served-");
    let served = served.path();
    for (at, trace) in opts.traces.iter().enumerate() {
        if let Some(trace) = trace {
            write(&served.join(format!("trace-{}", at + 1)), trace);
        }
    }
    for (url, bytes) in &opts.files {
        write(
            &served.join(url.strip_prefix("https://").unwrap_or(url)),
            bytes,
        );
    }
    if let Some(fail) = &opts.fail {
        write(&served.join("fail"), fail);
    }
    if opts.gh_fail {
        write(&served.join("gh-fail"), "");
    }
    let log = served.join("log");
    write(&log, "");
    let output = served.join("output");
    let path = std::env::var("PATH").unwrap_or_default();
    let script = opts
        .script
        .unwrap_or_else(|| root.join("secure-host/binary.sh"));
    let mut command = Command::new("bash");
    command
        .arg(script)
        .args(args)
        .env_clear()
        .envs(
            std::env::vars_os()
                .filter(|(key, _)| !key.to_string_lossy().starts_with(WORKFLOW_PREFIX)),
        )
        .env("PATH", format!("{}:{path}", s(bin())))
        .env("STUB_FILES", served)
        .env("STUB_LOG", &log)
        .env("GITHUB_OUTPUT", &output)
        .envs(opts.env);
    let result = spawn(&mut command);
    Run {
        status: result.status.code(),
        stdout: String::from_utf8(result.stdout).unwrap(),
        stderr: String::from_utf8(result.stderr).unwrap(),
        log: lines(&fs::read_to_string(&log).unwrap()),
        output: fs::read_to_string(&output).unwrap_or_default(),
    }
}

/// By this checkout's binary.sh, which a change to the tree's copy leaves as it is.
fn digest(root: &Path) -> String {
    let result = run(
        root,
        &["digest", "--root", s(root)],
        Opts {
            script: Some(script()),
            ..Opts::default()
        },
    );
    assert_eq!(result.status, Some(0), "{}", result.stderr);
    result.stdout.trim().to_owned()
}

fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn digest_is_of_content_modes_and_names_and_nothing_else() {
    type Change<'a> = (&'a str, fn(&Path), bool);
    let changes: &[Change] = &[
        (
            "a file's content",
            |root| write(&root.join("crates/src/lib.rs"), "// other\n"),
            true,
        ),
        (
            "a file's name",
            |root| {
                fs::rename(
                    root.join("crates/src/lib.rs"),
                    root.join("crates/src/main.rs"),
                )
                .unwrap()
            },
            true,
        ),
        (
            "a new file",
            |root| write(&root.join("egress/new.py"), ""),
            true,
        ),
        (
            "a dotfile",
            |root| write(&root.join("egress/.new"), ""),
            true,
        ),
        (
            "the executable bit",
            |root| chmod(&root.join("crates/src/lib.rs"), 0o755),
            true,
        ),
        (
            "a link",
            |root| symlink("lib.rs", root.join("crates/src/link.rs")).unwrap(),
            true,
        ),
        (
            "Cargo.lock",
            |root| write(&root.join("Cargo.lock"), "changed"),
            true,
        ),
        (
            "what a release holds",
            |root| write(&root.join("secure-host/binary.sh"), "changed"),
            true,
        ),
        (
            "a file's time",
            |root| {
                let time = UNIX_EPOCH + Duration::from_secs(1);
                fs::File::open(root.join("crates/src/lib.rs"))
                    .unwrap()
                    .set_times(fs::FileTimes::new().set_accessed(time).set_modified(time))
                    .unwrap()
            },
            false,
        ),
        (
            "group and other bits",
            |root| chmod(&root.join("crates/src/lib.rs"), 0o600),
            false,
        ),
        (
            "an empty directory",
            |root| fs::create_dir(root.join("crates/empty")).unwrap(),
            false,
        ),
        (
            "a file outside the source",
            |root| write(&root.join("README.md"), "x"),
            false,
        ),
    ];
    for (what, change, changes_it) in changes {
        let root = tree();
        let before = digest(root.path());
        assert!(matches(&before, "^[0-9a-f]{64}$"), "{what}: {before}");
        assert_eq!(
            digest(tree().path()),
            before,
            "two copies of one source differ"
        );
        change(root.path());
        assert_eq!(digest(root.path()) != before, *changes_it, "{what}");
    }
}

/// Each line `KIND SHA256 PATH`, a directory's names in byte order, depth
/// first: `a/b` before `a.c`, though `.` sorts before `/`.
#[test]
fn digest_is_of_the_listing_binary_sh_documents() {
    let tree = tree();
    let root = tree.path();
    fs::create_dir(root.join("crates/a")).unwrap();
    write(&root.join("crates/a/b"), "b");
    write(&root.join("crates/a.c"), "c");
    chmod(&root.join("crates/a.c"), 0o755);
    symlink("../x", root.join("egress/l")).unwrap();
    let file = |path: &str| sha256(fs::read(root.join(path)).unwrap());
    let listing = [
        format!("f {} Cargo.lock", file("Cargo.lock")),
        format!("f {} Cargo.toml", file("Cargo.toml")),
        format!("f {} crates/a/b", file("crates/a/b")),
        format!("x {} crates/a.c", file("crates/a.c")),
        format!("f {} crates/src/lib.rs", file("crates/src/lib.rs")),
        format!("l {} egress/l", sha256("../x")),
        format!("f {} egress/src/lib.rs", file("egress/src/lib.rs")),
        format!("f {} skills/src/lib.rs", file("skills/src/lib.rs")),
        format!("f {} workflow/review.md", file("workflow/review.md")),
        format!("f {} secure-host/binary.sh", file("secure-host/binary.sh")),
    ];
    assert_eq!(
        built_from(),
        [
            "Cargo.lock",
            "Cargo.toml",
            "crates",
            "egress",
            "skills",
            "workflow/review.md",
            "secure-host/binary.sh"
        ]
    );
    let text: String = listing.iter().map(|line| format!("{line}\n")).collect();
    assert_eq!(digest(root), sha256(text));
}

#[test]
fn link_is_its_target_not_what_the_target_holds() {
    let (one, other) = (tree(), tree());
    symlink("lib.rs", one.path().join("crates/src/link.rs")).unwrap();
    symlink("../src/lib.rs", other.path().join("crates/src/link.rs")).unwrap();
    assert_ne!(digest(one.path()), digest(other.path()));
}

#[test]
fn link_target_is_all_of_it_and_a_name_with_a_newline_has_no_digest() {
    let (one, other) = (tree(), tree());
    symlink("lib.rs", one.path().join("crates/src/link.rs")).unwrap();
    symlink("lib.rs\n", other.path().join("crates/src/link.rs")).unwrap();
    assert_ne!(digest(one.path()), digest(other.path()));
    let root = tree();
    write(&root.path().join("crates/src/lib.rs\n"), "// lib\n");
    let result = run(
        root.path(),
        &["digest", "--root", s(root.path())],
        Opts {
            script: Some(script()),
            ..Opts::default()
        },
    );
    assert_eq!(result.status, Some(1));
    assert!(
        matches(&result.stderr, "has a newline in its name"),
        "{}",
        result.stderr
    );
}

#[test]
fn source_with_a_part_missing_has_no_digest() {
    let root = tree();
    fs::rename(root.path().join("egress"), root.path().join("elsewhere")).unwrap();
    let result = run(
        root.path(),
        &["digest", "--root", s(root.path())],
        Opts::default(),
    );
    assert_eq!(result.status, Some(1));
    assert_eq!(result.stdout, "");
    assert!(
        matches(
            &result.stderr,
            "egress is neither a file, a link nor a directory"
        ),
        "{}",
        result.stderr
    );
}

fn checksums() -> Value {
    Value::Object(
        NAMES
            .iter()
            .chain([&OBJECT])
            .map(|name| ((*name).to_owned(), Value::from(sha256(BYTES))))
            .collect(),
    )
}

fn assets(from: &str, change: impl Fn(&str) -> String) -> Vec<(String, String)> {
    NAMES
        .iter()
        .map(|name| format!("{name}-{TARGET}"))
        .chain([OBJECT.to_owned()])
        .map(|asset| (format!("{from}/{asset}"), change(&asset)))
        .collect()
}

/// The build `get` runs where it takes no release.
fn cargo_build() -> String {
    format!("cargo build --release --locked --target {TARGET} -p agentic-job -p secure-host")
}

/// What `get` left in OUT, and that every file there is the release's.
fn fetched(out: &Path) {
    for name in NAMES {
        assert_eq!(mode(&out.join(name)), 0o755, "{name}");
    }
    assert_eq!(mode(&out.join(OBJECT)), 0o644);
    for name in NAMES.iter().chain([&OBJECT]) {
        assert_eq!(fs::read_to_string(out.join(name)).unwrap(), BYTES, "{name}");
    }
}

/// `{...manifest, ...change}`.
fn merged(manifest: &Value, change: &Value) -> Value {
    let mut merged = manifest.as_object().unwrap().clone();
    merged.extend(change.as_object().unwrap().clone());
    Value::Object(merged)
}

/// What a source-addressed release's `release.json` is.
enum Manifest {
    /// The valid one with these fields replaced.
    Merge(Value),
    /// No release at all.
    Absent,
    /// These bytes.
    Raw(&'static str),
}

struct Case {
    name: String,
    manifest: Manifest,
    gh_fail: bool,
    bad: Option<String>,
    fail: Option<String>,
    /// The refusal stderr matches, or success.
    expected: Option<&'static str>,
}

fn case(name: &str, manifest: Manifest, expected: Option<&'static str>) -> Case {
    Case {
        name: name.to_owned(),
        manifest,
        gh_fail: false,
        bad: None,
        fail: None,
        expected,
    }
}

#[test]
fn source_addressed_releases_verify_before_trusting_bytes_and_fail_closed() {
    let tree = tree();
    let root = tree.path();
    let source = digest(root);
    let from = format!("https://github.com/{REPOSITORY}/releases/download/build-{source}");
    let manifest = json!({
        "repository": REPOSITORY, "release": format!("build-{source}"), "target": TARGET,
        "source": source, "sha256": checksums(),
    });
    let verify = format!(
        "gh attestation verify OUT/release.json --bundle OUT/provenance.jsonl --repo {REPOSITORY} --cert-identity https://github.com/{REPOSITORY}/.github/workflows/pin.yml@refs/heads/main --source-ref refs/heads/main --deny-self-hosted-runners"
    );
    let refusing = Some("refusing it");
    let names_only: Map<String, Value> = NAMES
        .iter()
        .map(|name| ((*name).to_owned(), Value::from(sha256(BYTES))))
        .collect();
    let mut short = checksums();
    short["fake-agent"] = json!("0");
    let mut cases = vec![
        case("valid", Manifest::Merge(json!({})), None),
        case("absent", Manifest::Absent, None),
        case(
            "wrong source",
            Manifest::Merge(json!({"source": "b".repeat(64)})),
            refusing,
        ),
        case(
            "wrong repository",
            Manifest::Merge(json!({"repository": "other/repo"})),
            refusing,
        ),
        case(
            "wrong target",
            Manifest::Merge(json!({"target": "other"})),
            refusing,
        ),
        case(
            "wrong tag",
            Manifest::Merge(json!({"release": "latest"})),
            refusing,
        ),
        case(
            "no checksum for the object",
            Manifest::Merge(json!({"sha256": names_only})),
            Some(r"no checksum for world_write\.bpf\.o"),
        ),
        case(
            "a short checksum",
            Manifest::Merge(json!({"sha256": short})),
            Some("no checksum for fake-agent"),
        ),
        case("not JSON", Manifest::Raw("{"), refusing),
        Case {
            gh_fail: true,
            ..case(
                "bad attestation",
                Manifest::Merge(json!({})),
                Some("signature refused"),
            )
        },
        Case {
            bad: Some(format!("agentic-job-{TARGET}")),
            ..case(
                "bad binary",
                Manifest::Merge(json!({})),
                Some(
                    "agentic-job of build-[0-9a-f]+ has SHA-256 [0-9a-f]{64}, and the pin says [0-9a-f]{64}: refusing it",
                ),
            )
        },
        Case {
            bad: Some(OBJECT.to_owned()),
            ..case(
                "bad object",
                Manifest::Merge(json!({})),
                Some(r"world_write\.bpf\.o of .* refusing it"),
            )
        },
    ];
    for asset in [
        "release.json".to_owned(),
        "provenance.jsonl".to_owned(),
        format!("agentic-job-{TARGET}"),
        OBJECT.to_owned(),
    ] {
        cases.push(Case {
            fail: Some(asset.clone()),
            ..case(
                &format!("{asset} cannot be fetched"),
                Manifest::Merge(json!({})),
                Some("error: fetching https://.*: GitHub request failed"),
            )
        });
    }
    for Case {
        name,
        manifest: change,
        gh_fail,
        bad,
        fail,
        expected,
    } in cases
    {
        let parent = tempdir("release-");
        let out = parent.path().join("bin");
        let release = match change {
            Manifest::Absent => None,
            Manifest::Raw(text) => Some(text.to_owned()),
            Manifest::Merge(change) => Some(merged(&manifest, &change).to_string()),
        };
        let files = match release {
            None => vec![],
            Some(release) => {
                let mut files = vec![
                    (format!("{from}/release.json"), release),
                    (format!("{from}/provenance.jsonl"), "bundle".to_owned()),
                ];
                files.extend(assets(&from, |asset| {
                    if bad.as_deref() == Some(asset) {
                        "tampered".to_owned()
                    } else {
                        BYTES.to_owned()
                    }
                }));
                files
            }
        };
        let result = run(
            root,
            &["get", "--out", s(&out)],
            Opts {
                files,
                fail,
                gh_fail,
                ..Opts::default()
            },
        );
        if let Some(expected) = expected {
            assert_eq!(result.status, Some(1), "{name}");
            assert!(
                matches(&result.stderr, expected),
                "{name}: {}",
                result.stderr
            );
            assert_eq!(result.output, "", "{name}");
            assert!(
                !result.log.iter().any(|line| line.starts_with("cargo")),
                "{name}: built in place of a refused release"
            );
        } else {
            assert_eq!(result.status, Some(0), "{name}: {}", result.stderr);
        }
        // Nothing but the manifest and its bundle before the attestation.
        let at = result.log.iter().position(|line| line.starts_with("gh "));
        if let Some(at) = at {
            assert_eq!(result.log[at].replace(s(&out), "OUT"), verify, "{name}");
            assert_eq!(
                result.log[..at],
                [
                    format!("fetch {from}/release.json"),
                    format!("fetch {from}/provenance.jsonl")
                ],
                "{name}"
            );
        }
        if name == "valid" {
            fetched(&out);
            assert_eq!(result.output, format!("fetched=true\nsource={source}\n"));
            assert!(
                matches(
                    &result.stdout,
                    &format!("fetched build-{source} by its attested checksums")
                ),
                "{}",
                result.stdout
            );
        }
        if name == "absent" {
            assert_eq!(at, None);
            assert!(
                matches(&result.stdout, "::notice::No release exists for source"),
                "{}",
                result.stdout
            );
            assert_eq!(result.output, format!("fetched=false\nsource={source}\n"));
            assert!(result.log.contains(&cargo_build()), "{:?}", result.log);
            for name in NAMES {
                assert_eq!(mode(&out.join(name)), 0o755, "{name}");
            }
        }
    }
}

#[test]
fn requested_build_fetches_nothing_and_installs_only_the_compilers_missing() {
    let tree = tree();
    let root = tree.path();
    let parent = tempdir("build-");
    let out = parent.path().join("bin");
    let result = run(root, &["get", "--out", s(&out), "--build"], Opts::default());
    assert_eq!(result.status, Some(0), "{}", result.stderr);
    assert!(
        !result.log.iter().any(|line| {
            ["fetch", "gh", "sudo"]
                .iter()
                .any(|prefix| line.starts_with(prefix))
        }),
        "{}",
        result.log.join("\n")
    );
    assert_eq!(
        result.log,
        [
            format!(
                "clang -O2 -g -target bpfel -Wall -Wextra -Werror -c {}/crates/agentic-job/bpf/world_write.bpf.c -o {}/{OBJECT}",
                s(root),
                s(&out)
            ),
            format!("rustup target add {TARGET}"),
            cargo_build(),
        ]
    );
    assert!(
        matches(&result.stdout, "::notice::A build was requested"),
        "{}",
        result.stdout
    );
    assert!(
        matches(&result.output, "^fetched=false\n"),
        "{}",
        result.output
    );
    for name in NAMES {
        assert_eq!(fs::read_to_string(out.join(name)).unwrap(), "built\n");
    }
    assert_eq!(fs::read_to_string(out.join(OBJECT)).unwrap(), "object\n");
}

#[test]
fn tagged_releases_check_identity_and_bytes_and_fail_closed() {
    let tree = tree();
    let root = tree.path();
    let source = digest(root);
    let (repository, commit) = ("example/tool", "a".repeat(40));
    let from = format!("https://github.com/{repository}/releases/download/v1.2.3");
    let identity = json!({
        "workflow_ref": format!("{repository}/.github/workflows/policy.yml@refs/tags/v1.2.3"),
        "other": 1,
    })
    .to_string();
    let base_env = env(&[
        ("WORKFLOW_REPOSITORY", repository),
        ("WORKFLOW_SHA", &commit),
        ("WORKFLOW_IDENTITY", &identity),
    ]);
    let manifest = json!({
        "repository": repository, "commit": commit, "source": source, "release": "v1.2.3",
        "target": TARGET, "sha256": checksums(),
    });
    let other_commit = "b".repeat(40);
    for bad in [
        None,
        Some("annotated"),
        Some("absent-ref"),
        Some("tag"),
        Some("attestation"),
        Some("repository"),
        Some("commit"),
        Some("source"),
        Some("release"),
        Some("target"),
        Some("sha256"),
        Some("bytes"),
        Some("missing"),
        Some("identity"),
    ] {
        let parent = tempdir("tagged-");
        let out = parent.path().join("bin");
        let sha = if bad == Some("tag") {
            &other_commit
        } else {
            &commit
        };
        let mut files = vec![];
        if bad != Some("absent-ref") {
            let kind = if bad == Some("annotated") {
                "tag"
            } else {
                "commit"
            };
            files.push((
                format!("https://api.github.com/repos/{repository}/git/ref/tags/v1.2.3"),
                json!({"object": {"type": kind, "sha": sha}}).to_string(),
            ));
        }
        files.push((
            format!("https://api.github.com/repos/{repository}/commits/v1.2.3"),
            json!({"sha": sha}).to_string(),
        ));
        let change = bad.map_or_else(|| json!({}), |bad| json!({bad: "wrong"}));
        files.push((
            format!("{from}/release.json"),
            merged(&manifest, &change).to_string(),
        ));
        files.push((format!("{from}/provenance.jsonl"), "bundle".to_owned()));
        let bytes = if bad == Some("bytes") {
            "altered"
        } else {
            BYTES
        };
        files.extend(assets(&from, |_| bytes.to_owned()));
        let mut env = base_env.clone();
        if bad == Some("identity") {
            env.push(("WORKFLOW_SHA".to_owned(), "main".to_owned()));
        }
        let result = run(
            root,
            &["get", "--out", s(&out)],
            Opts {
                files,
                gh_fail: bad == Some("attestation"),
                fail: (bad == Some("missing")).then(|| "release.json".to_owned()),
                env,
                ..Opts::default()
            },
        );
        let resolved_by_commit = matches!(bad, Some("annotated" | "absent-ref"));
        if bad.is_some() && !resolved_by_commit {
            assert_eq!(result.status, Some(1), "{bad:?}");
            let source_addressed = format!("/{REPOSITORY}/");
            assert!(
                !result
                    .log
                    .iter()
                    .any(|line| { line.starts_with("cargo") || line.contains(&source_addressed) }),
                "{bad:?}: {}",
                result.log.join("\n")
            );
            continue;
        }
        assert_eq!(result.status, Some(0), "{}", result.stderr);
        assert_eq!(
            result
                .log
                .iter()
                .any(|line| line.contains("/commits/v1.2.3")),
            resolved_by_commit,
            "{bad:?}"
        );
        let out = s(&out);
        let gh: Vec<_> = result
            .log
            .iter()
            .filter(|line| line.starts_with("gh "))
            .collect();
        assert_eq!(
            gh,
            [&format!(
                "gh attestation verify {out}/release.json --bundle {out}/provenance.jsonl --repo {repository} --cert-identity https://github.com/{repository}/.github/workflows/release.yml@refs/heads/main --source-ref refs/heads/main --source-digest {commit} --deny-self-hosted-runners"
            )]
        );
        fetched(Path::new(out));
        assert!(
            matches(
                &result.stdout,
                "fetched tagged release by its attested checksums"
            ),
            "{}",
            result.stdout
        );
        assert_eq!(result.output, format!("fetched=true\nsource={source}\n"));
    }
}

#[test]
fn branches_commit_pins_and_caller_refs_do_not_select_tagged_assets() {
    let tree = tree();
    let root = tree.path();
    let commit = "a".repeat(40);
    let pinned = format!("example/tool/.github/workflows/policy.yml@{commit}");
    for workflow_ref in [
        None,
        Some("example/tool/.github/workflows/policy.yml@refs/heads/main"),
        Some(pinned.as_str()),
        Some("other/caller/.github/workflows/policy.yml@refs/tags/v1.2.3"),
    ] {
        let parent = tempdir("untagged-");
        let out = parent.path().join("bin");
        let identity = match workflow_ref {
            None => json!({}),
            Some(workflow_ref) => json!({"workflow_ref": workflow_ref}),
        }
        .to_string();
        let result = run(
            root,
            &["get", "--out", s(&out)],
            Opts {
                env: env(&[
                    ("WORKFLOW_REPOSITORY", "example/tool"),
                    ("WORKFLOW_SHA", &commit),
                    ("WORKFLOW_IDENTITY", &identity),
                ]),
                ..Opts::default()
            },
        );
        assert_eq!(result.status, Some(0), "{}", result.stderr);
        assert!(
            !result.log.iter().any(|line| line.contains("example/tool")),
            "{workflow_ref:?}"
        );
        assert!(
            matches(&result.stdout, "built from this source"),
            "{}",
            result.stdout
        );
    }
}

#[test]
fn manifest_binds_the_source_digest_to_the_checksums_of_the_build() {
    let tree = tree();
    let root = tree.path();
    let dist = tempdir("dist-");
    for name in NAMES {
        write(&dist.path().join(format!("{name}-{TARGET}")), name);
    }
    write(&dist.path().join(OBJECT), OBJECT);
    let dist_path = s(dist.path());
    let pinned = run(
        root,
        &[
            "pin",
            "--dist",
            dist_path,
            "--release",
            "build-x",
            "--repository",
            "example/tool",
        ],
        Opts {
            env: env(&[("GITHUB_SHA", &"c".repeat(40))]),
            ..Opts::default()
        },
    );
    assert_eq!(pinned.status, Some(0), "{}", pinned.stderr);
    let sha256s: Map<String, Value> = NAMES
        .iter()
        .chain([&OBJECT])
        .map(|name| ((*name).to_owned(), Value::from(sha256(name))))
        .collect();
    assert_eq!(
        serde_json::from_str::<Value>(&pinned.stdout).unwrap(),
        json!({
            "repository": "example/tool", "release": "build-x", "target": TARGET,
            "source": digest(root), "commit": "c".repeat(40), "sha256": sha256s,
        })
    );
    let local = run(
        root,
        &["pin", "--dist", dist_path, "--release", "build-x"],
        Opts {
            env: env(&[("GITHUB_SHA", "")]),
            ..Opts::default()
        },
    );
    let local: Value = serde_json::from_str(&local.stdout).unwrap();
    assert_eq!(local["repository"], REPOSITORY);
    assert_eq!(local.get("commit"), None);
    let missing = tempdir("dist-");
    let refused = run(
        root,
        &["pin", "--dist", s(missing.path()), "--release", "build-x"],
        Opts::default(),
    );
    assert_eq!(refused.status, Some(1));
    assert_eq!(refused.stdout, "");
}

#[test]
fn unknown_command_or_argument_is_refused() {
    let root = tree();
    let cases: &[&[&str]] = &[
        &[],
        &["verify"],
        &["get", "--out"],
        &["get", "--outdir", "x"],
        &["object"],
    ];
    for args in cases {
        let result = run(root.path(), args, Opts::default());
        assert_eq!(result.status, Some(1), "{args:?}");
        assert!(
            matches(&result.stderr, "^error: "),
            "{args:?}: {}",
            result.stderr
        );
    }
}

struct Fetch {
    result: Run,
    bytes: Option<String>,
    waits: Vec<i64>,
}

/// One fetch as `get` makes it: the bytes, exit status 2 for an absent
/// resource where that is asked for, and the waits it slept.
fn fetch_one(
    url: &str,
    missing: bool,
    traces: &[Option<&str>],
    files: &[(String, String)],
) -> Fetch {
    let root = tree();
    let parent = tempdir("fetch-");
    let file = parent.path().join("file");
    let mut args = vec!["fetch", "--url", url, "--out", s(&file)];
    if missing {
        args.push("--missing");
    }
    let result = run(
        root.path(),
        &args,
        Opts {
            traces: traces.iter().map(|t| t.map(str::to_owned)).collect(),
            files: files.to_vec(),
            ..Opts::default()
        },
    );
    let waits = result
        .log
        .iter()
        .filter_map(|line| line.strip_prefix("sleep "))
        .map(|wait| wait.parse().unwrap())
        .collect();
    Fetch {
        bytes: fs::read_to_string(&file).ok(),
        result,
        waits,
    }
}

#[test]
fn fetch_tells_an_absent_resource_from_a_refusal() {
    let url = "https://api.github.com/repos/o/r/ok";
    let files = [(url.to_owned(), "bytes".to_owned())];
    let cases: &[(&str, bool, Option<&str>, i32)] = &[
        ("ok", false, None, 0),
        ("ok", true, None, 0),
        ("absent", true, None, 2),
        ("absent", false, None, 1),
        ("ok", true, Some("< HTTP/2.0 403 Forbidden\n"), 1),
    ];
    for &(resource, missing, trace, expected) in cases {
        let Fetch {
            result,
            bytes,
            waits,
        } = fetch_one(
            &format!("https://api.github.com/repos/o/r/{resource}"),
            missing,
            &[trace],
            &files,
        );
        assert_eq!(
            result.status,
            Some(expected),
            "{resource} {missing}: {}",
            result.stderr
        );
        if expected == 0 {
            assert_eq!(bytes.as_deref(), Some("bytes"));
        }
        if expected == 1 {
            assert!(
                matches(
                    &result.stderr,
                    r"(?m)^error: fetching https://api\.github\.com/repos/o/r/\w+: GitHub request failed \(HTTP 40[34]\); check token permissions"
                ),
                "{}",
                result.stderr
            );
        }
        assert_eq!(waits, [] as [i64; 0]);
    }
}

/// How a throttled fetch ends.
enum Waits {
    /// It succeeds after one wait of any of these.
    OneOf(Vec<i64>),
    /// It fails at once.
    Failed,
    /// It fails at once, as the wait would exceed the budget.
    Budget,
}

/// The failed response's own headers decide, not a redirect's before it,
/// and a wait that would end past the two minutes fails at once.
#[test]
fn only_a_throttled_response_is_retried_as_long_as_github_asks_within_the_budget() {
    let now = || chrono::Utc::now().timestamp();
    let http_date = chrono::DateTime::from_timestamp(now() + 20, 0)
        .unwrap()
        .format("%a, %d %b %Y %H:%M:%S GMT");
    let url = "https://api.github.com/repos/o/r/ok";
    let files = [(url.to_owned(), "bytes".to_owned())];
    let cases = [
        (
            "< HTTP/2.0 403 Forbidden\n< Retry-After: 0\n".to_owned(),
            Waits::OneOf(vec![1]),
        ),
        (
            "< HTTP/2.0 403 Forbidden\n\nYou have exceeded a secondary rate limit.\n".to_owned(),
            Waits::OneOf(vec![1]),
        ),
        (
            "< HTTP/2.0 429 Too Many Requests\n< retry-after: 3\n".to_owned(),
            Waits::OneOf(vec![3]),
        ),
        (
            format!("< HTTP/2.0 429 Too Many Requests\n< Retry-After: {http_date}\n"),
            Waits::OneOf(vec![19, 20]),
        ),
        (
            format!(
                "< HTTP/2.0 403 Forbidden\n< X-Ratelimit-Remaining: 0\n< X-Ratelimit-Reset: {}\n",
                now() + 10
            ),
            Waits::OneOf(vec![9, 10]),
        ),
        (
            format!(
                "< HTTP/2.0 302 Found\n< X-Ratelimit-Remaining: 4999\n< X-Ratelimit-Reset: 1\n< HTTP/2.0 403 Forbidden\n< X-Ratelimit-Remaining: 0\n< X-Ratelimit-Reset: {}\n",
                now() + 60
            ),
            Waits::OneOf(vec![59, 60]),
        ),
        ("< HTTP/2.0 403 Forbidden\n".to_owned(), Waits::Failed),
        (
            "< HTTP/2.0 302 Found\n< Retry-After: 1\n< HTTP/2.0 403 Forbidden\n".to_owned(),
            Waits::Failed,
        ),
        (
            "< HTTP/2.0 500 Internal Server Error\n< Retry-After: 1\n".to_owned(),
            Waits::Failed,
        ),
        (
            "< HTTP/2.0 429 Too Many Requests\n< Retry-After: 121\n".to_owned(),
            Waits::Budget,
        ),
    ];
    for (trace, expected) in cases {
        let Fetch {
            result,
            bytes,
            waits,
        } = fetch_one(url, false, &[Some(&trace)], &files);
        match expected {
            Waits::OneOf(allowed) => {
                assert_eq!(result.status, Some(0), "{trace}: {}", result.stderr);
                assert_eq!(bytes.as_deref(), Some("bytes"));
                assert_eq!(waits.len(), 1, "{trace}");
                assert!(allowed.contains(&waits[0]), "{trace}: waited {waits:?}");
            }
            Waits::Failed | Waits::Budget => {
                let pattern = if matches!(expected, Waits::Budget) {
                    r"GitHub rate limit \(HTTP 429\); retry budget exhausted"
                } else {
                    "GitHub request failed"
                };
                assert_eq!(result.status, Some(1), "{trace}");
                assert!(
                    matches(&result.stderr, pattern),
                    "{trace}: {}",
                    result.stderr
                );
                assert_eq!(waits, [] as [i64; 0], "{trace}");
            }
        }
    }
    // Backoff doubles while GitHub names no wait.
    let limited = Some("< HTTP/2.0 429 Too Many Requests\n< X-Ratelimit-Remaining: 0\n");
    let Fetch { result, waits, .. } = fetch_one(url, false, &[limited, limited, limited], &files);
    assert_eq!(result.status, Some(0), "{}", result.stderr);
    assert_eq!(waits, [1, 2, 4]);
}

/// In `get`, where a fetch's failure must still stop the job: a throttled
/// lookup of the release waits and takes it, a refused one builds nothing.
#[test]
fn get_waits_out_a_throttled_lookup_and_stops_at_a_refused_one() {
    let tree = tree();
    let root = tree.path();
    let source = digest(root);
    let from = format!("https://github.com/{REPOSITORY}/releases/download/build-{source}");
    let manifest = json!({
        "repository": REPOSITORY, "release": format!("build-{source}"), "target": TARGET,
        "source": source, "sha256": checksums(),
    });
    let mut files = vec![
        (format!("{from}/release.json"), manifest.to_string()),
        (format!("{from}/provenance.jsonl"), "bundle".to_owned()),
    ];
    files.extend(assets(&from, |_| BYTES.to_owned()));
    for (trace, expected) in [
        ("< HTTP/2.0 429 Too Many Requests\n< Retry-After: 2\n", 0),
        ("< HTTP/2.0 403 Forbidden\n", 1),
    ] {
        let parent = tempdir("throttled-");
        let out = parent.path().join("bin");
        let result = run(
            root,
            &["get", "--out", s(&out)],
            Opts {
                files: files.clone(),
                traces: vec![Some(trace.to_owned())],
                ..Opts::default()
            },
        );
        assert_eq!(result.status, Some(expected), "{}", result.stderr);
        assert!(
            !result.log.iter().any(|line| line.starts_with("cargo")),
            "{}",
            result.log.join("\n")
        );
        if expected == 0 {
            fetched(&out);
            let sleeps: Vec<_> = result
                .log
                .iter()
                .filter(|line| line.starts_with("sleep "))
                .collect();
            assert_eq!(sleeps, ["sleep 2"]);
        } else {
            assert!(
                matches(
                    &result.stderr,
                    r"fetching .*release\.json: GitHub request failed \(HTTP 403\)"
                ),
                "{}",
                result.stderr
            );
        }
    }
}

#[test]
fn release_asset_comes_from_one_rest_lookup_then_the_asset_by_its_id() {
    let from = "https://github.com/o/r/releases/download/build-1";
    let files = [
        (format!("{from}/other"), "other".to_owned()),
        (format!("{from}/release.json"), "manifest".to_owned()),
    ];
    // The exit status, or the refusal stderr matches.
    let cases: &[(&str, bool, Result<i32, &str>)] = &[
        ("release.json", false, Ok(0)),
        ("release.json", true, Ok(0)),
        ("absent", true, Ok(2)),
        ("absent", false, Err("release build-1 has no asset absent")),
    ];
    for &(name, missing, expected) in cases {
        let Fetch { result, bytes, .. } =
            fetch_one(&format!("{from}/{name}"), missing, &[], &files);
        match expected {
            Err(pattern) => {
                assert_eq!(result.status, Some(1), "{name}");
                assert!(matches(&result.stderr, pattern), "{}", result.stderr);
            }
            Ok(status) => assert_eq!(result.status, Some(status), "{}", result.stderr),
        }
        if expected == Ok(0) {
            assert_eq!(bytes.as_deref(), Some("manifest"));
        }
    }
    // An absent release is the lookup's 404.
    for (missing, expected) in [(true, 2), (false, 1)] {
        let fetch = fetch_one(
            "https://github.com/o/r/releases/download/build-2/release.json",
            missing,
            &[],
            &files,
        );
        assert_eq!(fetch.result.status, Some(expected), "{missing}");
    }
    assert_eq!(
        fetch_one("https://example.com/release.json", false, &[], &[])
            .result
            .status,
        Some(1)
    );
}

/// With only what `gh` needs on PATH: the stubs, and dirname for the script.
#[test]
fn gh_is_installed_only_where_it_is_missing_by_dnf_or_apt_get() {
    // What is logged, or the refusal stderr matches.
    type Case<'a> = (&'a [&'a str], Result<&'a [&'a str], &'a str>);
    let cases: &[Case] = &[
        (&["gh", "dnf"], Ok(&[])),
        (&["dnf", "apt-get"], Ok(&["sudo dnf install -y gh"])),
        (&["apt-get"], Ok(&["sudo apt-get install -y gh"])),
        (&[], Err("no supported package manager")),
    ];
    let dirname = spawn(Command::new("bash").args(["-c", "command -v dirname"]));
    let dirname = String::from_utf8(dirname.stdout).unwrap();
    for (present, expected) in cases {
        let bin = tempdir("path-");
        let log = bin.path().join("log");
        for name in present.iter().chain(&["sudo"]) {
            write_stub(
                bin.path(),
                name,
                &format!(r#"echo "{name} $*" >> "{}""#, s(&log)),
            );
        }
        symlink(dirname.trim(), bin.path().join("dirname")).unwrap();
        let mut command = Command::new("/bin/bash");
        command
            .arg(script())
            .arg("gh")
            .env_clear()
            .env("PATH", bin.path());
        let result = spawn(&mut command);
        let stderr = String::from_utf8(result.stderr).unwrap();
        let logged = fs::read_to_string(&log)
            .map(|text| lines(&text))
            .unwrap_or_default();
        match expected {
            Err(pattern) => {
                assert_eq!(result.status.code(), Some(1), "{present:?}");
                assert!(matches(&stderr, pattern), "{stderr}");
            }
            Ok(expected) => {
                assert_eq!(result.status.code(), Some(0), "{stderr}");
                assert_eq!(logged, *expected, "{present:?}");
            }
        }
    }
}
