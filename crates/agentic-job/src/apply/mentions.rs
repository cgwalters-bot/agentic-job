//! Last-mile notification filtering, after collection and before publication.
//! Code is kept verbatim; no agent-selected identity is allowed to notify.

use std::sync::LazyLock;

use regex::Regex;

use crate::collect::markdown::outside_code;

struct Syntax {
    forge: &'static str,
    bang_references: bool,
    reopen: bool,
}

// Group and broadcast mentions use the same @ prefix as user mentions.
const SYNTAX: &[Syntax] = &[
    Syntax {
        forge: "github",
        bang_references: false,
        reopen: false,
    },
    Syntax {
        forge: "forgejo",
        bang_references: true,
        reopen: true,
    },
    Syntax {
        forge: "gitlab",
        bang_references: true,
        reopen: false,
    },
];

const MAX_REFERENCES: usize = 10;
const BREAK: char = '\u{200b}';

static TOKENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)@[\p{L}\p{N}_][\p{L}\p{N}_./-]*|![0-9]+|\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?|reopen(?:ed|s)?|implement(?:ed|s)?)\s+(?:[\w.-]+/[\w.-]+)?[#!][0-9]+")
        .expect("valid notification pattern")
});

pub(super) fn filter(body: &str, forge: &str) -> String {
    let syntax = SYNTAX
        .iter()
        .find(|syntax| syntax.forge == forge)
        .expect("publisher has a syntax entry");
    let mut references = 0;
    outside_code(body, &mut |text, before, _| {
        let mut result = String::new();
        let mut end = 0;
        for token in TOKENS.find_iter(text) {
            result.push_str(&text[end..token.start()]);
            let value = token.as_str();
            let previous = text[..token.start()].chars().next_back().or(before);
            let boundary = !previous.is_some_and(|c| c.is_alphanumeric() || "_./-".contains(c));
            let neutralize = if value.starts_with('@') {
                boundary
            } else if value.starts_with('!') {
                syntax.bang_references
            } else if (!value.to_ascii_lowercase().starts_with("reopen") || syntax.reopen)
                && (!value.to_ascii_lowercase().starts_with("implement") || forge == "gitlab")
            {
                references += 1;
                references > MAX_REFERENCES || (syntax.bang_references && value.contains('!'))
            } else {
                false
            };
            if neutralize {
                // Break the syntax itself, rather than wrapping potentially
                // attacker-controlled Markdown delimiters in more delimiters.
                let first = value.chars().next().expect("nonempty token");
                result.push(first);
                result.push(BREAK);
                let rest = value[first.len_utf8()..].replace('#', &format!("#{BREAK}"));
                if syntax.bang_references {
                    result.push_str(&rest.replace('!', &format!("!{BREAK}")));
                } else {
                    result.push_str(&rest);
                }
            } else {
                result.push_str(value);
            }
            end = token.end();
        }
        result.push_str(&text[end..]);
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_cases() {
        for (forge, input, expected) in [
            ("forgejo", "hi @user", "hi @\u{200b}user"),
            ("forgejo", "@org/team", "@\u{200b}org/team"),
            (
                "gitlab",
                "@all @here @group",
                "@\u{200b}all @\u{200b}here @\u{200b}group",
            ),
            (
                "forgejo",
                "`@user !1`\n~~~\n@org/team\n~~~",
                "`@user !1`\n~~~\n@org/team\n~~~",
            ),
            ("forgejo", "user@example.com", "user@example.com"),
            ("forgejo", "see !12", "see !\u{200b}12"),
            ("forgejo", "Closes !12", "C\u{200b}loses !\u{200b}12"),
            ("github", "see !12", "see !12"),
        ] {
            assert_eq!(filter(input, forge), expected, "{forge}: {input}");
        }
    }

    #[test]
    fn close_and_reopen_share_the_cap() {
        let prefix = "Closes #1\n".repeat(MAX_REFERENCES);
        for keyword in ["Closes", "Fixes", "Resolves", "Reopens", "Reopened"] {
            let input = format!("{prefix}{keyword} #2");
            let output = filter(&input, "forgejo");
            assert_eq!(
                output,
                format!(
                    "{prefix}{}{}{} #{BREAK}2",
                    &keyword[..1],
                    BREAK,
                    &keyword[1..]
                )
            );
        }
    }
}
