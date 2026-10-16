//! Links in what is posted, as gh-aw's sanitizer treats them.
//!
//! gh-aw's collector, as check.yml runs it (`allowed-or-code-region`),
//! redacts a URL in prose to a host the policy does not keep
//! ([`Policy::keeps_link_to`]) into `(host/redacted)`. Its pattern takes a
//! Markdown link's closing parenthesis as part of the URL's path, so
//! `[text](https://host/path)` is posted as `[text]((host/redacted)`: no
//! link, and its brackets shown (#908). [`repair`] makes that
//! `text (host/redacted)`, which is what the redaction means to leave.
//! [`redacted_hosts`] tells the agent, before its session ends, which hosts
//! the collector will redact.
//!
//! Both skip code as gh-aw does, nearly: a fenced block, and an inline span
//! within one line. gh-aw's idea of code differs at the edges
//! (docs/safe-outputs.md), where a repair is missed or a warning wrong;
//! neither decides what is posted, which gh-aw's sanitizer does.

use std::ops::Range;
use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde_json::Value;

use crate::policy::Policy;

/// What the collector leaves of a Markdown link or image to a host it
/// redacts: the link's text, then the redaction in a second pair of
/// parentheses. The closing parenthesis after it is the link's own when
/// the URL had no path, which the collector's pattern does not take.
static MANGLED_LINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"!?\[([^\[\]\n]*)\]\(\(((?:[A-Za-z0-9.…]+/)?redacted)\)\)?")
        .expect("a valid pattern")
});

/// A URL's scheme and host, as the collector's patterns find them: the
/// scheme not right after a letter or digit, the host up to a character
/// other than a word character, dot or dash.
static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[^a-z0-9])([a-z][a-z0-9+.-]*)://([a-z0-9_.-]*)").expect("a valid pattern")
});

/// What may come right before a link that is mended: dropping its `[`
/// after anything else would join that to its text, which the collector
/// saw apart (`https:/[/host]` to a URL, `@[name]` to a mention).
fn mends_after(before: Option<char>) -> bool {
    before.is_none_or(|c| c.is_whitespace() || "([{\"'*_>~|,;".contains(c))
}

/// TEXT with each link the collector redacted made plain text again.
pub fn repair(text: &str) -> String {
    let mut repaired = String::with_capacity(text.len());
    for (code, range) in regions(text) {
        let part = &text[range];
        if code {
            repaired.push_str(part);
        } else {
            repaired.push_str(&MANGLED_LINK_RE.replace_all(part, |caps: &Captures<'_>| {
                let whole = caps.get(0).map_or(0..0, |m| m.range());
                if !mends_after(part[..whole.start].chars().next_back()) {
                    return part[whole].to_owned();
                }
                let label = caps[1].trim();
                if label.is_empty() {
                    format!("({})", &caps[2])
                } else {
                    format!("{label} ({})", &caps[2])
                }
            }));
        }
    }
    repaired
}

/// Every string in VALUE, repaired.
pub fn repair_value(value: &mut Value) {
    match value {
        Value::String(text) => {
            if text.contains("redacted)") {
                *text = repair(text);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(repair_value),
        Value::Object(map) => map.values_mut().for_each(repair_value),
        _ => {}
    }
}

/// The hosts of the URLs in the prose of VALUE's strings that the
/// collector redacts under POLICY, lowercase: an https URL to a host the
/// policy does not keep, and every URL of another scheme (as `scheme://`
/// where it names no host). Each once, in the order found.
pub fn redacted_hosts(value: &Value, policy: &Policy) -> Vec<String> {
    let mut hosts = Vec::new();
    collect_hosts(value, policy, &mut hosts);
    hosts
}

fn collect_hosts(value: &Value, policy: &Policy, hosts: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            for (_, range) in regions(text).into_iter().filter(|(code, _)| !code) {
                for caps in URL_RE.captures_iter(&text[range]) {
                    let scheme = caps[1].to_ascii_lowercase();
                    let host = caps[2].to_ascii_lowercase();
                    let redacted = match (scheme.as_str(), host.is_empty()) {
                        ("https", true) => continue,
                        ("https", false) if policy.keeps_link_to(&host) => continue,
                        (_, false) => host,
                        (_, true) => format!("{scheme}://"),
                    };
                    if !hosts.contains(&redacted) {
                        hosts.push(redacted);
                    }
                }
            }
        }
        Value::Array(values) => values.iter().for_each(|v| collect_hosts(v, policy, hosts)),
        Value::Object(map) => map.values().for_each(|v| collect_hosts(v, policy, hosts)),
        _ => {}
    }
}

/// TEXT cut into code (`true`) and prose, in order and covering all of it.
fn regions(text: &str) -> Vec<(bool, Range<usize>)> {
    let mut regions: Vec<(bool, Range<usize>)> = Vec::new();
    let mut push = |code: bool, range: Range<usize>| match regions.last_mut() {
        Some((last, prev)) if *last == code && prev.end == range.start => prev.end = range.end,
        _ if range.is_empty() => {}
        _ => regions.push((code, range)),
    };
    // The open fence's character and length.
    let mut fence: Option<(char, usize)> = None;
    let mut start = 0;
    for line in text.split_inclusive('\n') {
        let range = start..start + line.len();
        start = range.end;
        let trimmed = line.trim_start();
        let marker = trimmed
            .chars()
            .next()
            .filter(|c| matches!(c, '`' | '~'))
            .map(|c| (c, trimmed.chars().take_while(|&d| d == c).count()))
            .filter(|(_, n)| *n >= 3);
        match (fence, marker) {
            (None, Some(open)) => {
                fence = Some(open);
                push(true, range);
            }
            (Some((c, n)), Some((d, m))) if c == d && m >= n => {
                fence = None;
                push(true, range);
            }
            (Some(_), _) => push(true, range),
            (None, None) => {
                let base = range.start;
                let mut at = 0;
                for (code, span) in inline_code(line) {
                    push(false, base + at..base + span.start);
                    push(code, base + span.start..base + span.end);
                    at = span.end;
                }
                push(false, base + at..range.end);
            }
        }
    }
    regions
}

/// The inline code spans of LINE: a run of backticks to the next run of
/// the same length.
fn inline_code(line: &str) -> Vec<(bool, Range<usize>)> {
    let bytes = line.as_bytes();
    let run_at = |i: usize| bytes[i..].iter().take_while(|&&b| b == b'`').count();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'`' {
            i += 1;
            continue;
        }
        let n = run_at(i);
        let mut j = i + n;
        let close = loop {
            match bytes[j..].iter().position(|&b| b == b'`') {
                None => break None,
                Some(k) => {
                    let m = run_at(j + k);
                    if m == n {
                        break Some(j + k + m);
                    }
                    j += k + m;
                }
            }
        };
        match close {
            Some(end) => {
                spans.push((true, i..end));
                i = end;
            }
            None => i += n,
        }
    }
    spans
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn mangled_links_become_text_and_the_host() {
        // Left: what the pinned collector made of a request (its output for
        // these inputs, with no allowed domains); right: what is posted.
        for (collected, posted) in [
            (
                "See [Fedora]((src.fedoraproject.org/redacted) and more.",
                "See Fedora (src.fedoraproject.org/redacted) and more.",
            ),
            (
                "Bare [b]((bugzilla.redhat.com/redacted)) here.",
                "Bare b (bugzilla.redhat.com/redacted) here.",
            ),
            (
                "(see [t]((evil.example/redacted), next",
                "(see t (evil.example/redacted), next",
            ),
            (
                "![img]((evil.example/redacted)",
                "img (evil.example/redacted)",
            ),
            (
                "[t (title)]((evil.example/redacted)",
                "t (title) (evil.example/redacted)",
            ),
            (
                "[f]((foo.example/redacted) and [x]((redacted)",
                "f (foo.example/redacted) and x (redacted)",
            ),
            (
                "[x]((e.example/redacted)(e.example/redacted)",
                "x (e.example/redacted)(e.example/redacted)",
            ),
            ("[]((e.example/redacted)", "(e.example/redacted)"),
            // Nothing is joined to the text that the collector saw apart.
            (
                "https:/[/evil.example]((x.example/redacted) @[octocat]((x.example/redacted)",
                "https:/[/evil.example]((x.example/redacted) @[octocat]((x.example/redacted)",
            ),
            (
                "*[a]((x.example/redacted)*, ([b]((x.example/redacted)",
                "*a (x.example/redacted)*, (b (x.example/redacted)",
            ),
            // Kept links, plain redactions and code are left alone.
            (
                "[ok](https://github.com/a/b) and plain (evil.example/redacted)",
                "[ok](https://github.com/a/b) and plain (evil.example/redacted)",
            ),
            (
                "`[x]((e.example/redacted)` and\n```\n[y]((e.example/redacted)\n```\n",
                "`[x]((e.example/redacted)` and\n```\n[y]((e.example/redacted)\n```\n",
            ),
        ] {
            assert_eq!(repair(collected), posted, "{collected:?}");
        }
        let mut item = json!({"type": "add_comment", "body": "[a]((h.example/redacted)", "n": [1, "[b]((redacted)"]});
        repair_value(&mut item);
        assert_eq!(
            item,
            json!({"type": "add_comment", "body": "a (h.example/redacted)", "n": [1, "b (redacted)"]})
        );
    }

    #[test]
    fn hosts_the_collector_redacts() {
        let mut policy = crate::policy::tests::policy();
        let body = |text: &str| json!({"type": "add_comment", "body": text});
        let text = "[F](https://src.fedoraproject.org/x) [G](https://github.com/a) \
                    https://raw.githubusercontent.com/x http://example.org/x file:///etc \
                    `https://in.code.example/` path+file://x \
                    [B](https://Bugzilla.redhat.com/1) https://src.fedoraproject.org/y\n\
                    ```\nhttps://fenced.example/\n```\n";
        assert_eq!(
            redacted_hosts(&body(text), &policy),
            [
                "src.fedoraproject.org",
                "example.org",
                "file://",
                "x",
                "bugzilla.redhat.com"
            ]
        );
        policy.allowed_domains = crate::policy::GH_AW_LINK_DOMAINS
            .iter()
            .chain(&["fedoraproject.org", "redhat.com"])
            .map(|d| (*d).to_owned())
            .collect();
        assert_eq!(
            redacted_hosts(&body(text), &policy),
            ["example.org", "file://", "x"]
        );
        assert!(redacted_hosts(&json!({"title": "no links"}), &policy).is_empty());
    }

    #[test]
    fn code_regions() {
        let text = "a `b` c ``d`e`` f `g\n~~~~\nh\n~~~\ni\n~~~~\nj";
        let code: Vec<&str> = regions(text)
            .into_iter()
            .filter(|(code, _)| *code)
            .map(|(_, range)| &text[range])
            .collect();
        assert_eq!(code, ["`b`", "``d`e``", "~~~~\nh\n~~~\ni\n~~~~\n"]);
    }
}
