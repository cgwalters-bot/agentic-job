//! gh-aw's sanitizer (`sanitize_content.cjs` and
//! `sanitize_content_core.cjs` at the pinned commit), as its collector
//! runs it on a request's text in check.yml: URLs filtered outside code
//! (`allowed-or-code-region`), links kept to the policy's hosts, and no
//! commands, allowed mentions or reference restrictions configured, so
//! the steps those switch on are left out.
//!
//! Each step is the original's, in its order. Patterns the `regex` crate
//! cannot write (JavaScript's lookaround) are scans of their own. Where
//! JavaScript differs from Rust in what a pattern means, the pattern says
//! JavaScript's: `\s` is [`JS_SPACE`], `\w` and `\d` are ASCII. Lengths
//! are UTF-16 units, as JavaScript counts them; a cut that would split a
//! surrogate pair leaves the pair out instead.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::{Captures, NoExpand, Regex};
use unicode_normalization::UnicodeNormalization;

use super::markdown::{balance, outside_code};

/// JavaScript's `\s`, the body of a character class.
const JS_SPACE: &str = r"\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}";

/// Whether C is in JavaScript's `\s`, which is also what its `trim` drops.
pub fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{B}' | '\u{C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

/// JavaScript's `String.prototype.trim`.
pub fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_space)
}

/// How many lines text keeps (`applyTruncation`).
const MAX_LINES: usize = 65_000;

/// How many closing references (`fixes #1`) are left as they are.
const MAX_BOT_TRIGGER_REFERENCES: usize = 10;

/// The longest run of backticks a code span around a neutralized mention
/// or reference may need before `<code>` is used instead.
const MAX_CODE_SPAN_DELIMITER: usize = 16;

fn pattern(text: &str) -> Regex {
    Regex::new(text).expect("a valid pattern")
}

/// What a URL's authority may hold (`URL_AUTHORITY_CHAR`), or the tab
/// and line breaks URL parsers drop from it.
fn authority() -> String {
    format!(r#"(?:[^{JS_SPACE}/?#,()<>\[\]{{}}"'`|\\]|[\t\r\n])*"#)
}

static SCHEME_USERINFO_RE: LazyLock<Regex> = LazyLock::new(|| {
    pattern(&format!(
        r"(?i)([a-z][a-z0-9+.-]{{0,30}}://)({})",
        authority()
    ))
});

/// `URL_START_DELIMITERS`, then a protocol-relative URL's authority.
static PROTOCOL_RELATIVE_USERINFO_RE: LazyLock<Regex> = LazyLock::new(|| {
    pattern(&format!(
        r#"(^|[{JS_SPACE}(\[{{"'<=,>|`])([/\\]{{2}})({})"#,
        authority()
    ))
});

static PERCENT_25_RE: LazyLock<Regex> = LazyLock::new(|| pattern(r"%25([0-9A-Fa-f]{2})"));
static PERCENT_3A_RE: LazyLock<Regex> = LazyLock::new(|| pattern(r"%3[Aa]"));
static SINGLE_COLON_SCHEME_RE: LazyLock<Regex> = LazyLock::new(|| {
    pattern(&format!(
        r"(?i)(?:data|javascript|vbscript|about|mailto|tel|magnet):[^{JS_SPACE}]+"
    ))
});
static ANGLE_AUTOLINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    pattern(&format!(
        r"<https://([A-Za-z0-9_.-]+(?::[0-9]+)?)(/[^{JS_SPACE}<>|]*)?(?:\|([^<>]*))?>"
    ))
});

static ANSI_RE: LazyLock<Regex> = LazyLock::new(|| pattern(r"\x1b\[[0-9;]*[mGKH]"));
static CONTROL_RE: LazyLock<Regex> = LazyLock::new(|| pattern(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]"));

static INLINE_LINK_TITLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    pattern(&format!(
        r#"(\[)([^\]]*)(\]\()(?:(<[^>]*>)|([^{JS_SPACE})]+))[{JS_SPACE}]+(?:"([^"]*)"|'([^']*)'|\(([^)]*)\))([{JS_SPACE}]*\))"#
    ))
});
static REFERENCE_LINK_TITLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    pattern(&format!(
        r#"(?mR)^(\[[^\]]+\]:[{JS_SPACE}]+[^{JS_SPACE}]+)[{JS_SPACE}]+(?:"[^"]*"|'[^']*'|\([^)]*\))[{JS_SPACE}]*$"#
    ))
});

static CDATA_RE: LazyLock<Regex> = LazyLock::new(|| pattern(r"<!\[CDATA\[((?s:.)*?)\]\]>"));
static CDATA_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"<(/?[A-Za-z][A-Za-z0-9]*(?:[^>]*?))>"));
static TAG_RE: LazyLock<Regex> = LazyLock::new(|| pattern(r"<(/?[A-Za-z!][^>]*?)>"));
static TAG_AUTOLINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    pattern(&format!(
        r"^https://[A-Za-z0-9_.-]+(?::[0-9]+)?(/[^{JS_SPACE}<>|]*)?(?:\|[^<>]*)?$"
    ))
});
static TAG_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| pattern(&format!(r"^/?[{JS_SPACE}]*([A-Za-z][A-Za-z0-9]*)")));
static DANGEROUS_ATTRIBUTE_RE: LazyLock<Regex> = LazyLock::new(|| {
    pattern(&format!(
        r#"(?i)[{JS_SPACE}/]+(?:on[A-Za-z0-9_]+|style|title|data-[A-Za-z0-9_-]+)(?:[{JS_SPACE}]*=[{JS_SPACE}]*(?:"[^"]*"|'[^']*'|[^{JS_SPACE}>"'`]*))?"#
    ))
});

/// The HTML tags GitHub renders that are kept, without their dangerous
/// attributes; any other is shown in parentheses.
const ALLOWED_TAGS: &[&str] = &[
    "abbr",
    "b",
    "blockquote",
    "br",
    "code",
    "del",
    "details",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "img",
    "ins",
    "kbd",
    "li",
    "mark",
    "ol",
    "p",
    "pre",
    "s",
    "span",
    "strong",
    "sub",
    "summary",
    "sup",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "ul",
];

static MENTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    pattern(
        r"(^|[^A-Za-z0-9])@([A-Za-z0-9](?:[A-Za-z0-9_-]{0,37}[A-Za-z0-9])?(?:/[A-Za-z0-9._-]+)?)",
    )
});
static BOT_TRIGGER_RE: LazyLock<Regex> = LazyLock::new(|| {
    pattern(&format!(
        r"(?i)(?-u:\b)(fixes?|closes?|resolves?|fix|close|resolve)[{JS_SPACE}]+#([A-Za-z0-9_]+)"
    ))
});

/// HTML entities that could hide a mention or an invisible character,
/// once or twice encoded, in `decodeHtmlEntities`'s order.
static NAMED_ENTITIES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        ("commat", "@"),
        ("gt", ">"),
        ("lt", "<"),
        ("amp", "&"),
        ("shy", "\u{AD}"),
        ("zwnj", "\u{200C}"),
        ("zwj", "\u{200D}"),
        ("lrm", "\u{200E}"),
        ("rlm", "\u{200F}"),
        ("ZeroWidthSpace", "\u{200B}"),
        ("NoBreak", "\u{2060}"),
        ("(?:af|ApplyFunction)", "\u{2061}"),
        ("(?:it|InvisibleTimes)", "\u{2062}"),
        ("(?:ic|InvisibleComma)", "\u{2063}"),
        ("(?:ip|InvisiblePlus)", "\u{2064}"),
    ]
    .into_iter()
    .map(|(name, text)| (pattern(&format!("(?i)&(?:amp;)?{name};")), text))
    .collect()
});
static DECIMAL_ENTITY_RE: LazyLock<Regex> = LazyLock::new(|| pattern(r"&(?:amp;)?#([0-9]+);"));
static HEX_ENTITY_RE: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"&(?:amp;)?#[xX]([0-9a-fA-F]+);"));

/// TEXT as gh-aw's collector sanitizes a field of at most MAX_LENGTH,
/// keeping https links to the hosts KEEPS_LINK takes. With
/// NEUTRALIZE_MENTIONS, `sanitizeContentCore`, which wraps every mention
/// in code; without, the path of `sanitizeContent` that leaves them to
/// the trusted job, as the collector does for the types that post.
pub fn sanitize(
    text: &str,
    max_length: usize,
    neutralize_mentions: bool,
    keeps_link: &dyn Fn(&str) -> bool,
) -> String {
    if text.is_empty() {
        return String::new();
    }
    // The core truncates first as well, so as not to work on more.
    let mut s = if neutralize_mentions {
        truncate(text, max_length)
    } else {
        text.to_owned()
    };
    s = harden_unicode(&s);
    s = ANSI_RE.replace_all(&s, "").into_owned();
    s = CONTROL_RE.replace_all(&s, "").into_owned();
    s = outside_code(&s, &mut |t, _, _| remove_xml_comments(t));
    s = outside_code(&s, &mut |t, _, _| neutralize_link_titles(t));
    s = outside_code(&s, &mut |t, _, _| convert_xml_tags(t));
    s = outside_code(&s, &mut |t, _, _| sanitize_url_protocols(t));
    s = outside_code(&s, &mut |t, _, _| sanitize_url_domains(t, keeps_link));
    s = truncate(&s, max_length);
    if neutralize_mentions {
        s = neutralize_all_mentions(&s);
    }
    s = neutralize_bot_triggers(&s);
    s = outside_code(&s, &mut |t, _, _| escape_template_delimiters(t));
    js_trim(&balance(&s)).to_owned()
}

fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// The longest start of S of at most UNITS UTF-16 units.
fn utf16_prefix(s: &str, units: usize) -> &str {
    let mut seen = 0;
    for (at, c) in s.char_indices() {
        seen += c.len_utf16();
        if seen > units {
            return &s[..at];
        }
    }
    s
}

/// `applyTruncation`: at most [`MAX_LINES`] lines and MAX_LENGTH units,
/// saying which limit cut it.
pub fn truncate(content: &str, max_length: usize) -> String {
    const LINES_CUT: &str = "\n[Content truncated due to line count]";
    if let Some((cut, _)) = content.match_indices('\n').nth(MAX_LINES - 1) {
        let kept = format!("{}{LINES_CUT}", &content[..cut]);
        if utf16_len(&kept) > max_length {
            let room = max_length.saturating_sub(LINES_CUT.len());
            return format!("{}{LINES_CUT}", utf16_prefix(&kept, room));
        }
        return kept;
    }
    if utf16_len(content) > max_length {
        return format!(
            "{}\n[Content truncated due to length]",
            utf16_prefix(content, max_length)
        );
    }
    content.to_owned()
}

/// `decodeHtmlEntities`. A numeric entity for a lone surrogate, which
/// JavaScript decodes to one, is U+FFFD here: Rust has no such `char`.
fn decode_html_entities(text: &str) -> String {
    let mut s = text.to_owned();
    for (re, decoded) in NAMED_ENTITIES.iter() {
        s = re.replace_all(&s, NoExpand(decoded)).into_owned();
    }
    let decode = |radix: u32| {
        move |caps: &Captures<'_>| match u32::from_str_radix(&caps[1], radix) {
            Ok(code) if code <= 0x10FFFF => char::from_u32(code)
                .unwrap_or(char::REPLACEMENT_CHARACTER)
                .to_string(),
            _ => caps[0].to_owned(),
        }
    };
    s = DECIMAL_ENTITY_RE.replace_all(&s, decode(10)).into_owned();
    HEX_ENTITY_RE.replace_all(&s, decode(16)).into_owned()
}

/// Characters that hide text, or reverse it, dropped by `hardenUnicodeText`.
fn is_hiding(c: char) -> bool {
    matches!(
        c,
        '\u{AD}'
            | '\u{34F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2060}'..='\u{2064}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// The Latin letter a Cyrillic or Greek one looks like, after TR#39.
fn homoglyph(c: char) -> char {
    match c {
        '\u{410}' | '\u{391}' => 'A',
        '\u{412}' | '\u{392}' => 'B',
        '\u{415}' | '\u{395}' => 'E',
        '\u{41A}' | '\u{39A}' => 'K',
        '\u{41C}' | '\u{39C}' => 'M',
        '\u{41D}' | '\u{397}' => 'H',
        '\u{41E}' | '\u{39F}' => 'O',
        '\u{420}' | '\u{3A1}' => 'P',
        '\u{421}' => 'C',
        '\u{422}' | '\u{3A4}' => 'T',
        '\u{425}' | '\u{3A7}' => 'X',
        '\u{405}' => 'S',
        '\u{406}' | '\u{399}' => 'I',
        '\u{430}' => 'a',
        '\u{435}' => 'e',
        '\u{43E}' | '\u{3BF}' => 'o',
        '\u{440}' => 'p',
        '\u{441}' => 'c',
        '\u{445}' => 'x',
        '\u{443}' => 'y',
        '\u{456}' | '\u{3B9}' => 'i',
        '\u{455}' => 's',
        '\u{458}' => 'j',
        '\u{396}' => 'Z',
        '\u{39D}' => 'N',
        '\u{3A5}' => 'Y',
        '\u{3BD}' => 'v',
        _ => c,
    }
}

/// `hardenUnicodeText`: one form for each character, entities decoded,
/// hiding characters dropped, full-width ASCII made ASCII, compatibility
/// forms decomposed, and look-alike letters made Latin. Its per-character
/// steps 3 to 5 are one pass here, which changes nothing: none of them
/// makes a character another drops.
fn harden_unicode(text: &str) -> String {
    let composed: String = text.nfc().collect();
    let decoded = decode_html_entities(&composed);
    let visible: String = decoded
        .chars()
        .filter(|&c| !is_hiding(c))
        .map(|c| match c {
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            _ => c,
        })
        .collect();
    visible.nfkc().map(homoglyph).collect()
}

/// `removeXmlComments`, counting nested openers so that what follows an
/// inner closer is still dropped.
fn remove_xml_comments(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut depth = 0usize;
    let mut rest = s;
    while let Some(c) = rest.chars().next() {
        if rest.starts_with("<!--") {
            depth += 1;
            rest = &rest[4..];
        } else if depth > 0 && rest.starts_with("--!>") {
            depth -= 1;
            rest = &rest[4..];
        } else if depth > 0 && rest.starts_with("-->") {
            depth -= 1;
            rest = &rest[3..];
        } else {
            if depth == 0 {
                result.push(c);
            }
            rest = &rest[c.len_utf8()..];
        }
    }
    result
}

/// `neutralizeMarkdownLinkTitles`: an inline link's title, which only a
/// hover shows, moved into its text; a reference definition's dropped.
fn neutralize_link_titles(s: &str) -> String {
    let s = INLINE_LINK_TITLE_RE.replace_all(s, |caps: &Captures<'_>| {
        let url = caps
            .get(4)
            .or_else(|| caps.get(5))
            .map_or("", |m| m.as_str());
        let title = caps
            .get(6)
            .or_else(|| caps.get(7))
            .or_else(|| caps.get(8))
            .map_or("", |m| m.as_str());
        format!(
            "{}{} ({title}){}{url}{}",
            &caps[1], &caps[2], &caps[3], &caps[9]
        )
    });
    REFERENCE_LINK_TITLE_RE.replace_all(&s, "${1}").into_owned()
}

/// `convertXmlTags`: tags in parentheses, but for the tags GitHub
/// renders, kept without their event handlers, styles, titles and data,
/// and https autolinks, left for the URL filter.
fn convert_xml_tags(s: &str) -> String {
    let s = CDATA_RE.replace_all(s, |caps: &Captures<'_>| {
        format!(
            "(![CDATA[{}]])",
            CDATA_TAG_RE.replace_all(&caps[1], "(${1})")
        )
    });
    TAG_RE
        .replace_all(&s, |caps: &Captures<'_>| {
            let content = &caps[1];
            if TAG_AUTOLINK_RE.is_match(content) {
                return caps[0].to_owned();
            }
            let allowed = TAG_NAME_RE
                .captures(content)
                .is_some_and(|name| ALLOWED_TAGS.contains(&name[1].to_ascii_lowercase().as_str()));
            if allowed {
                format!("<{}>", DANGEROUS_ATTRIBUTE_RE.replace_all(content, ""))
            } else {
                format!("({content})")
            }
        })
        .into_owned()
}

/// `stripUrlUserinfo`: no `user:password@` in a `scheme://` URL, cut at
/// its last `@`, so that a host before one is not taken for the host.
fn strip_url_userinfo(s: &str) -> String {
    SCHEME_USERINFO_RE
        .replace_all(s, |caps: &Captures<'_>| {
            let cleaned: String = caps[2].chars().filter(|c| !"\t\r\n".contains(*c)).collect();
            match cleaned.rfind('@') {
                Some(at) => format!("{}{}", &caps[1], &cleaned[at + 1..]),
                None => caps[0].to_owned(),
            }
        })
        .into_owned()
}

/// `stripProtocolRelativeUserinfo`: the same for `//host` URLs.
fn strip_protocol_relative_userinfo(s: &str) -> String {
    PROTOCOL_RELATIVE_USERINFO_RE
        .replace_all(s, |caps: &Captures<'_>| {
            let cleaned: String = caps[3].chars().filter(|c| !"\t\r\n".contains(*c)).collect();
            match cleaned.rfind('@') {
                Some(at) => format!("{}//{}", &caps[1], &cleaned[at + 1..]),
                None => caps[0].to_owned(),
            }
        })
        .into_owned()
}

/// `sanitizeDomainName`: the letters and digits of each label of DOMAIN,
/// with its middle elided past 48 characters.
fn sanitize_domain_name(domain: &str) -> String {
    let labels: Vec<String> = domain
        .split('.')
        .map(|label| label.chars().filter(char::is_ascii_alphanumeric).collect())
        .filter(|label: &String| !label.is_empty())
        .collect();
    let joined = labels.join(".");
    if joined.len() > 48 {
        return format!("{}…{}", &joined[..24], &joined[joined.len() - 24..]);
    }
    joined
}

fn redaction(host: &str) -> String {
    let sanitized = sanitize_domain_name(host);
    if sanitized.is_empty() {
        "(redacted)".to_owned()
    } else {
        format!("({sanitized}/redacted)")
    }
}

fn is_host_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-'
}

fn starts_with_https(s: &str) -> bool {
    s.get(..8)
        .is_some_and(|start| start.eq_ignore_ascii_case("https://"))
}

/// Where the run of bytes from FROM that MATCHES ends.
fn run_end(s: &str, from: usize, matches: impl Fn(u8) -> bool) -> usize {
    from + s.as_bytes()[from..]
        .iter()
        .take_while(|&&b| matches(b))
        .count()
}

/// Where a URL's optional `:port` after AT ends.
fn port_end(s: &str, at: usize) -> usize {
    let b = s.as_bytes();
    if b.get(at) == Some(&b':') && b.get(at + 1).is_some_and(u8::is_ascii_digit) {
        run_end(s, at + 1, |b| b.is_ascii_digit())
    } else {
        at
    }
}

/// Where a path from AT ends: from a `/`, up to whitespace, a comma, or
/// where STOP says the next URL starts.
fn path_end(s: &str, at: usize, stop: impl Fn(&str) -> bool) -> usize {
    if s.as_bytes().get(at) != Some(&b'/') {
        return at;
    }
    let mut end = at + 1;
    while let Some(c) = s[end..].chars().next() {
        if stop(&s[end..]) || is_js_space(c) || c == ',' {
            break;
        }
        end += c.len_utf8();
    }
    end
}

/// Replaces each match of FIND, which gives the end of a match at a
/// position or none, by what REPLACE makes of its range, as a global
/// JavaScript `replace` does.
fn replace_scanned(
    s: &str,
    find: impl Fn(usize) -> Option<usize>,
    mut replace: impl FnMut(usize, usize) -> String,
) -> String {
    let mut out = String::with_capacity(s.len());
    let (mut last, mut at) = (0, 0);
    while at < s.len() {
        if let Some(end) = find(at) {
            out.push_str(&s[last..at]);
            out.push_str(&replace(at, end));
            last = end;
            at = end;
        } else {
            at += s[at..].chars().next().map_or(1, char::len_utf8);
        }
    }
    out.push_str(&s[last..]);
    out
}

/// `sanitizeUrlProtocols`: every `scheme://` URL but https, and the
/// one-colon schemes that run code or leave the page, redacted.
fn sanitize_url_protocols(s: &str) -> String {
    let mut normalized = strip_url_userinfo(s);
    // Percent-encoded percent signs, then colons, so that an encoded
    // `javascript%3A` is seen; the text keeps them decoded.
    for _ in 0..4 {
        let next = PERCENT_25_RE.replace_all(&normalized, "%${1}").into_owned();
        if next == normalized {
            break;
        }
        normalized = next;
    }
    let normalized = PERCENT_3A_RE.replace_all(&normalized, ":").into_owned();
    // `(?<![a-z0-9])(?!https://)([a-z][a-z0-9+.-]*)(://)([\w.-]*)([^\s]*)`
    let b = normalized.as_bytes();
    // Where the scheme characters last found end: a start further in the
    // same run (`a.b.c`) ends there too, which is not looked for again,
    // so that a long run takes time in its length and not its square.
    let run = std::cell::Cell::new(0);
    let url_at = |at: usize| {
        if !b[at].is_ascii_alphabetic()
            || (at > 0 && b[at - 1].is_ascii_alphanumeric())
            || starts_with_https(&normalized[at..])
        {
            return None;
        }
        if at >= run.get() {
            run.set(run_end(&normalized, at + 1, |b| {
                b.is_ascii_alphanumeric() || b == b'+' || b == b'.' || b == b'-'
            }));
        }
        let scheme_end = run.get();
        if !normalized[scheme_end..].starts_with("://") {
            return None;
        }
        let host_end = run_end(&normalized, scheme_end + 3, is_host_byte);
        let end = normalized[host_end..]
            .find(is_js_space)
            .map_or(normalized.len(), |at| host_end + at);
        Some(end)
    };
    let redacted = replace_scanned(&normalized, url_at, |at, _| {
        let scheme_end = at + normalized[at..].find("://").unwrap_or(0);
        let host_start = scheme_end + 3;
        let host = &normalized[host_start..run_end(&normalized, host_start, is_host_byte)];
        if host.is_empty() {
            "(redacted)".to_owned()
        } else {
            redaction(&host.to_ascii_lowercase())
        }
    });
    SINGLE_COLON_SCHEME_RE
        .replace_all(&redacted, "(redacted)")
        .into_owned()
}

/// `sanitizeUrlDomains`: https and protocol-relative URLs to a host
/// KEEPS_LINK does not take redacted, userinfo first stripped.
fn sanitize_url_domains(s: &str, keeps_link: &dyn Fn(&str) -> bool) -> String {
    let s = strip_protocol_relative_userinfo(&strip_url_userinfo(s));
    // The URL URL to the host and port HOST, or its redaction.
    let filter = |url: &str, host: &str| -> String {
        let host = host.split(':').next().unwrap_or("").to_ascii_lowercase();
        if keeps_link(&host) {
            url.to_owned()
        } else {
            redaction(&host)
        }
    };

    // Autolinks first, a label after `|` kept where the link is not.
    let s = ANGLE_AUTOLINK_RE.replace_all(&s, |caps: &Captures<'_>| {
        let url = format!(
            "https://{}{}",
            &caps[1],
            caps.get(2).map_or("", |m| m.as_str())
        );
        let filtered = filter(&url, &caps[1]);
        if filtered == url {
            return caps[0].to_owned();
        }
        match caps.get(3).map(|m| m.as_str()).filter(|l| !l.is_empty()) {
            Some(label) => format!("{filtered}|{label}"),
            None => filtered,
        }
    });

    // `https://([\w.-]+(?::\d+)?)(\/(?:(?!https:\/\/)[^\s,])*)?`, any case.
    let https = |at: usize| -> Option<(usize, usize)> {
        if !starts_with_https(&s[at..]) {
            return None;
        }
        let host_end = run_end(&s, at + 8, is_host_byte);
        if host_end == at + 8 {
            return None;
        }
        let port_end = port_end(&s, host_end);
        Some((port_end, path_end(&s, port_end, starts_with_https)))
    };
    let s = replace_scanned(
        &s,
        |at| https(at).map(|(_, end)| end),
        |at, end| {
            let (host_end, _) = https(at).unwrap_or((end, end));
            filter(&s[at..end], &s[at + 8..host_end])
        },
    );

    // `(^|DELIMITERS)([/\\]{2})([\w.-]+(?::\d+)?)((?:/(?:(?![/\\]{2})[^\s,])*)?)`:
    // `//host`, which a browser on an https page fetches over https, after
    // the start or a delimiter, so not a `//` in an https URL's path.
    let is_slash = |b: Option<&u8>| matches!(b, Some(b'/' | b'\\'));
    let two_slashes =
        |rest: &str| is_slash(rest.as_bytes().first()) && is_slash(rest.as_bytes().get(1));
    let after_slashes = |from: usize| -> Option<(usize, usize)> {
        if !two_slashes(&s[from..]) {
            return None;
        }
        let host_end = run_end(&s, from + 2, is_host_byte);
        if host_end == from + 2 {
            return None;
        }
        let port_end = port_end(&s, host_end);
        Some((port_end, path_end(&s, port_end, two_slashes)))
    };
    let is_delimiter = |c: char| is_js_space(c) || "([{\"'<=,>|`".contains(c);
    // The start of the slashes, the end of the host and port, and the end.
    let relative = |at: usize| -> Option<(usize, usize, usize)> {
        if at == 0
            && let Some((host_end, end)) = after_slashes(0)
        {
            return Some((0, host_end, end));
        }
        let c = s[at..].chars().next()?;
        if !is_delimiter(c) {
            return None;
        }
        let from = at + c.len_utf8();
        after_slashes(from).map(|(host_end, end)| (from, host_end, end))
    };
    replace_scanned(
        &s,
        |at| relative(at).map(|(.., end)| end),
        |at, end| {
            let (from, host_end, _) = relative(at).unwrap_or((at, at, end));
            let url = format!("//{}", &s[from + 2..end]);
            format!("{}{}", &s[at..from], filter(&url, &s[from + 2..host_end]))
        },
    )
}

/// `createRenderSafeCodeSpanWrapper`: code spans whose delimiter is a run
/// of backticks the text has none of, so that none of its own close one.
enum CodeSpan {
    Backticks(String),
    Html,
}

impl CodeSpan {
    fn for_text(s: &str) -> Self {
        let mut runs = BTreeSet::new();
        let mut run = 0;
        for b in s.bytes().chain([0]) {
            if b == b'`' {
                run += 1;
            } else if run > 0 {
                runs.insert(run);
                run = 0;
            }
        }
        let length = (1..).find(|n| !runs.contains(n)).unwrap_or(1);
        if length > MAX_CODE_SPAN_DELIMITER {
            Self::Html
        } else {
            Self::Backticks("`".repeat(length))
        }
    }

    fn wrap(&self, text: &str, before: Option<char>, after: Option<char>) -> String {
        match self {
            Self::Backticks(delimiter) => {
                let lead = if before == Some('`') { " " } else { "" };
                let trail = if after == Some('`') { " " } else { "" };
                format!("{lead}{delimiter}{text}{delimiter}{trail}")
            }
            Self::Html => {
                let mut escaped = String::with_capacity(text.len());
                for c in text.chars() {
                    match c {
                        '&' => escaped.push_str("&amp;"),
                        '<' => escaped.push_str("&lt;"),
                        '>' => escaped.push_str("&gt;"),
                        '"' => escaped.push_str("&quot;"),
                        '\'' => escaped.push_str("&#39;"),
                        _ => escaped.push(c),
                    }
                }
                format!("<code>{escaped}</code>")
            }
        }
    }
}

/// The characters around a match from START to END of SEGMENT, those
/// around SEGMENT standing in at its edges.
fn neighbours(
    segment: &str,
    start: usize,
    end: usize,
    region: (Option<char>, Option<char>),
) -> (Option<char>, Option<char>) {
    let before = segment[..start]
        .chars()
        .next_back()
        .or(if start == 0 { region.0 } else { None });
    let after =
        segment[end..]
            .chars()
            .next()
            .or(if end == segment.len() { region.1 } else { None });
    (before, after)
}

/// `neutralizeAllMentions`: each `@name` outside code wrapped in code.
fn neutralize_all_mentions(s: &str) -> String {
    let span = CodeSpan::for_text(s);
    outside_code(s, &mut |segment, region_before, region_after| {
        MENTION_RE
            .replace_all(segment, |caps: &Captures<'_>| {
                let whole = caps.get(0).map_or(0..0, |m| m.range());
                let prefix = &caps[1];
                let (before, after) = neighbours(
                    segment,
                    whole.start + prefix.len(),
                    whole.end,
                    (region_before, region_after),
                );
                let before = prefix.chars().next_back().or(before);
                let mention = format!("@{}", &caps[2]);
                format!("{prefix}{}", span.wrap(&mention, before, after))
            })
            .into_owned()
    })
}

/// `neutralizeBotTriggers`: past the first ten, each `fixes #1` outside
/// code wrapped in code, so that it closes nothing.
fn neutralize_bot_triggers(s: &str) -> String {
    let span = CodeSpan::for_text(s);
    let mut count = 0;
    outside_code(s, &mut |segment, region_before, region_after| {
        BOT_TRIGGER_RE
            .replace_all(segment, |caps: &Captures<'_>| {
                count += 1;
                if count <= MAX_BOT_TRIGGER_REFERENCES {
                    return caps[0].to_owned();
                }
                let whole = caps.get(0).map_or(0..0, |m| m.range());
                let (before, after) = neighbours(
                    segment,
                    whole.start,
                    whole.end,
                    (region_before, region_after),
                );
                span.wrap(&format!("{} #{}", &caps[1], &caps[2]), before, after)
            })
            .into_owned()
    })
}

/// `neutralizeTemplateDelimiters`, on text outside code: Jinja, ERB,
/// JavaScript template, Jinja comment and Liquid tag openers escaped.
fn escape_template_delimiters(text: &str) -> String {
    text.replace("{{", r"\{\{")
        .replace("<%=", r"\<%=")
        .replace("${", r"\$\{")
        .replace("{#", r"\{\#")
        .replace("{%", r"\{\%")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keeps_public(host: &str) -> bool {
        crate::policy::link_domains()
            .iter()
            .any(|tld| host == tld || host.ends_with(&format!(".{tld}")))
    }

    /// Each step against inputs whose output gh-aw's sanitizer gave; the
    /// collector fixtures (`collect::tests`) cover them together.
    #[test]
    fn steps() {
        let cases: &[(&str, &str)] = &[
            ("see <!-- hidden --> this", "see  this"),
            ("<!-- a <!-- b --> c --> d", "d"),
            // `.example` is no top-level domain.
            (
                "[t](https://a.example \"tip\")",
                "[t (tip)]((a.example/redacted))",
            ),
            (
                "[t](https://a.example.org \"tip\")",
                "[t (tip)](https://a.example.org)",
            ),
            ("<script>x</script>", "(script)x(/script)"),
            ("<b onclick=\"x\">b</b>", "<b>b</b>"),
            ("http://a.example/x y", "(a.example/redacted) y"),
            ("javascript:alert(1)", "(redacted)"),
            ("javascript%253Aalert(1)", "(redacted)"),
            ("https://user:pw@github.com/x", "https://github.com/x"),
            ("https://a.internal/x", "(a.internal/redacted)"),
            ("https://github.com/x,y", "https://github.com/x,y"),
            ("//a.internal/x", "(a.internal/redacted)"),
            ("`http://kept`", "`http://kept`"),
            ("{{ x }} ${y}", r"\{\{ x }} \$\{y}"),
            ("&commat;a &#64;b", "@a @b"),
            ("a\u{200B}b\u{202E}c", "abc"),
            ("ｆｕｌｌ", "full"),
            ("\u{FB01}x", "fix"),
            ("\u{0430}pple", "apple"),
            ("\x1b[31mred\x1b[0m\x07", "red"),
            ("```js\ncode", "```js\ncode\n```"),
        ];
        for (input, want) in cases {
            assert_eq!(
                &sanitize(input, 1000, false, &keeps_public),
                want,
                "{input:?}"
            );
        }
    }

    #[test]
    fn mentions() {
        let cases: &[(&str, bool, &str)] = &[
            ("hi @someone", false, "hi @someone"),
            ("hi @someone", true, "hi `@someone`"),
            ("a `x` @b", true, "a `x` ``@b``"),
            ("mail@example.com", true, "mail@example.com"),
            ("@org/team!", true, "`@org/team`!"),
        ];
        for (input, neutralize, want) in cases {
            assert_eq!(
                &sanitize(input, 1000, *neutralize, &keeps_public),
                want,
                "{input:?}"
            );
        }
    }

    #[test]
    fn bot_triggers_past_ten() {
        let input = (1..=11)
            .map(|n| format!("fixes #{n}"))
            .collect::<Vec<_>>()
            .join(" ");
        let output = sanitize(&input, 1000, false, &keeps_public);
        assert!(output.starts_with("fixes #1 fixes #2"), "{output}");
        assert!(output.ends_with("fixes #10 `fixes #11`"), "{output}");
        assert_eq!(
            sanitize("prefixes #1", 100, false, &keeps_public),
            "prefixes #1"
        );
    }

    #[test]
    fn truncation() {
        assert_eq!(
            truncate("abcdef", 3),
            "abc\n[Content truncated due to length]"
        );
        // A pair is not split: four units with the emoji, at most three kept.
        assert_eq!(truncate("ab😀", 3), "ab\n[Content truncated due to length]");
        let lines = "x\n".repeat(MAX_LINES + 1);
        let cut = truncate(&lines, usize::MAX);
        assert!(cut.ends_with("x\n[Content truncated due to line count]"));
        assert_eq!(cut.matches('\n').count(), MAX_LINES);
        assert_eq!(
            truncate(&lines, 10),
            "\n[Content truncated due to line count]"
        );
    }

    /// A field is read whole before it is cut to its length: a run of
    /// scheme characters as long as a hand-back allows takes a moment,
    /// where looking for its end from each label took two minutes.
    #[test]
    fn long_scheme_runs_are_linear() {
        let text = "a.".repeat(500_000);
        let start = std::time::Instant::now();
        let sanitized = sanitize(&text, 100, false, &keeps_public);
        assert!(sanitized.starts_with("a.a."), "{sanitized}");
        assert!(start.elapsed() < std::time::Duration::from_secs(20));
    }
}
