//! `agentic-job secure-host supported`: refuse a host family nobody has
//! validated before the action changes the machine. `/etc/os-release` is
//! read as data, never as shell code, and `ID_LIKE` is no evidence of
//! support: a derivative is not the distribution it derives from.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

/// The one refusal, whatever the reason: a missing, unreadable, ambiguous
/// or unsupported release file alike.
pub const REFUSAL: &str = "secure-host: requires Ubuntu 26.04 or RHEL 10 or CentOS Stream 10; cannot establish a supported host from /etc/os-release";

pub const OS_RELEASE: &str = "/etc/os-release";

/// One identity field, its value unquoted or in matching quotes, and
/// nothing a shell would expand.
static FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(ID|VERSION_ID)=(?:"([a-z0-9.]+)"|'([a-z0-9.]+)'|([a-z0-9.]+))$"#)
        .expect("a valid pattern")
});

static RHEL_10: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^10(?:\.[0-9]+)*$").expect("a valid pattern"));

/// Whether os-release TEXT names Ubuntu 26.04, RHEL 10 or CentOS Stream 10. A malformed or
/// repeated `ID` or `VERSION_ID` line refuses the whole file.
pub fn supported(text: &str) -> bool {
    let mut id = None;
    let mut version = None;
    for line in text.split('\n') {
        if !(line.starts_with("ID=") || line.starts_with("VERSION_ID=")) {
            continue;
        }
        let Some(captures) = FIELD.captures(line) else {
            return false;
        };
        let value = (2..=4)
            .find_map(|group| captures.get(group))
            .map(|value| value.as_str());
        let field = if &captures[1] == "ID" {
            &mut id
        } else {
            &mut version
        };
        if field.replace(value).is_some() {
            return false;
        }
    }
    match (id.flatten(), version.flatten().unwrap_or_default()) {
        (Some("ubuntu"), version) => version == "26.04",
        (Some("rhel"), version) => RHEL_10.is_match(version),
        (Some("centos"), "10") => true,
        _ => false,
    }
}

/// Whether the release file at PATH names a supported host; one that
/// cannot be read cannot establish support either.
pub fn supported_file(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|text| supported(&text))
}

/// The admission table, which another parser of os-release that must agree
/// with [`supported`] (a caller's bootstrap script) is tested against too.
#[cfg(any(test, feature = "test-support"))]
pub mod cases {
    /// `ID`, `VERSION_ID` and whether [`super::supported`] admits them.
    pub const RELEASES: &[(&str, &str, bool)] = &[
        ("ubuntu", "26.04", true),
        ("ubuntu", "24.04", false),
        ("ubuntu", "22.04", false),
        ("ubuntu", "26.10", false),
        ("ubuntu", "26.04.1", false),
        ("rhel", "10", true),
        ("rhel", "10.0", true),
        ("rhel", "10.2", true),
        ("rhel", "9.6", false),
        ("rhel", "11", false),
        ("rhel", "100", false),
        ("rhel", "10.", false),
        ("centos", "10", true),
        ("centos", "9", false),
        ("centos", "10.0", false),
        ("centos", "11", false),
        ("rocky", "10", false),
        ("almalinux", "10", false),
        ("fedora", "44", false),
        ("debian", "13", false),
    ];

    /// Each of [`RELEASES`] as a release file, its fields unquoted and in
    /// either quotes, beside fields that are no evidence of support.
    pub fn release_files() -> impl Iterator<Item = (&'static str, String, bool)> {
        RELEASES.iter().flat_map(|&(id, version, expected)| {
            ["", "\"", "'"].map(|quote| {
                let text = format!(
                    "# release\nNAME=\"Example Linux\"\nID={quote}{id}{quote}\nVERSION_ID={quote}{version}{quote}\nID_LIKE=\"ubuntu rhel\"\n"
                );
                (id, text, expected)
            })
        })
    }

    /// Release files with a missing, ambiguous or shell-like field, which
    /// are refused.
    pub const MALFORMED: &[&str] = &[
        "",
        "ID=ubuntu\n",
        "VERSION_ID=\"26.04\"\n",
        "ID_LIKE=ubuntu\nVERSION_ID=\"26.04\"\n",
        "ID=ubuntu\nID=rhel\nVERSION_ID=\"26.04\"\n",
        "ID=ubuntu\nVERSION_ID=\"26.04\"\nVERSION_ID=\"24.04\"\n",
        "ID=\"ubuntu\nVERSION_ID=\"26.04\"\n",
        "ID=$(printf ubuntu)\nVERSION_ID=\"26.04\"\n",
        "ID=ubuntu\nVERSION_ID=\"$VERSION\"\n",
        "ID=ubuntu\r\nVERSION_ID=26.04\r\n",
        "ID=ubuntu\nVERSION_ID=\"26.04'\n",
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_is_by_id_and_release_not_id_like() {
        for (_, text, expected) in cases::release_files() {
            assert_eq!(supported(&text), expected, "{text}");
        }
    }

    #[test]
    fn missing_ambiguous_and_shell_fields_fail_closed() {
        for text in cases::MALFORMED {
            assert!(!supported(text), "{text:?}");
        }
    }

    #[test]
    fn an_unreadable_release_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("os-release");
        for text in [
            "ID=ubuntu\nVERSION_ID=\"26.04\"\n",
            "ID=rhel\nVERSION_ID=\"10.2\"\n",
        ] {
            std::fs::write(&path, text).unwrap();
            assert!(supported_file(&path));
        }
        std::fs::write(&path, "ID=fedora\nVERSION_ID=\"44\"\n").unwrap();
        for refused in [
            path.clone(),
            dir.path().to_owned(),
            dir.path().join("missing"),
        ] {
            assert!(!supported_file(&refused), "{}", refused.display());
        }
        assert_eq!(REFUSAL.lines().count(), 1);
    }
}
