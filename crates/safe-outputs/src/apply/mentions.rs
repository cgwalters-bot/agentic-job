//! Last-mile notification filtering, after collection and before publication.
//! Code is kept verbatim except on GitLab; no agent-selected identity is
//! allowed to notify. On GitLab, mentions and quick actions are broken in
//! code too, so differing Markdown parsers cannot bypass the filter.

use std::sync::LazyLock;

use regex::Regex;

use crate::collect::markdown::outside_code;

struct Syntax {
    forge: &'static str,
    bang_references: bool,
    reopen: bool,
    /// A mention is an `@` after anything but an ASCII letter, digit or
    /// `_`, as GitLab's `(?<!\w)@` reads it: `x.@all` and `é@all` notify
    /// there.
    ascii_boundary: bool,
    /// A line starting with `/` is a command run with the poster's rights.
    quick_actions: bool,
}

// Group and broadcast mentions use the same @ prefix as user mentions.
const SYNTAX: &[Syntax] = &[
    Syntax {
        forge: "github",
        bang_references: false,
        reopen: false,
        ascii_boundary: false,
        quick_actions: false,
    },
    Syntax {
        forge: "forgejo",
        bang_references: true,
        reopen: true,
        ascii_boundary: false,
        quick_actions: false,
    },
    Syntax {
        forge: "gitlab",
        bang_references: true,
        reopen: false,
        ascii_boundary: true,
        quick_actions: true,
    },
];

const MAX_REFERENCES: usize = 10;
const BREAK: char = '\u{200b}';

static TOKENS: LazyLock<Regex> = LazyLock::new(|| {
    tokens(
        r"[\w.-]+/[\w.-]+",
        r"(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?|reopen(?:ed|s)?|implement(?:ed|s)?)\s+",
    )
});

// Nested GitLab namespaces must count toward the same closing-reference cap:
// otherwise a producer can bypass it just by naming a subgroup's project.
static GITLAB_TOKENS: LazyLock<Regex> = LazyLock::new(|| {
    // GitLab's default closing pattern also accepts -ing, a colon and an
    // issue(s) prefix. Omitting these lets repeated pairs bypass the cap.
    // https://docs.gitlab.com/user/project/issues/managing_issues/#default-closing-pattern
    tokens(
        r"(?:[\w.-]+/)+[\w.-]+",
        r"(?:clos(?:e[sd]?|ing)|fix(?:e[sd]|ing)?|resolv(?:e[sd]?|ing)|implement(?:ed|s|ing)?):?\s+(?:issues?\s+)?",
    )
});

fn tokens(project: &str, closing: &str) -> Regex {
    // A GitLab namespace path may start with `.`.
    Regex::new(&format!(
        r"(?i)@[\p{{L}}\p{{N}}_.][\p{{L}}\p{{N}}_./-]*|![0-9]+|\b{closing}(?:{project})?[#!][0-9]+"
    ))
    .expect("valid notification pattern")
}

/// BODY with no mention, reference or (on GitLab) quick action left
/// that would notify or act: FORGE is `github`, `forgejo` or `gitlab`.
pub fn filter(body: &str, forge: &str) -> String {
    let syntax = SYNTAX
        .iter()
        .find(|syntax| syntax.forge == forge)
        .expect("publisher has a syntax entry");
    let mut references = 0;
    let tokens = if forge == "gitlab" {
        &*GITLAB_TOKENS
    } else {
        &*TOKENS
    };
    let mut filter_text = |text: &str, before: Option<char>, _: Option<char>| {
        let mut result = String::new();
        let mut end = 0;
        for token in tokens.find_iter(text) {
            result.push_str(&text[end..token.start()]);
            let value = token.as_str();
            let previous = text[..token.start()].chars().next_back().or(before);
            let boundary = !previous.is_some_and(|c| {
                if syntax.ascii_boundary {
                    c.is_ascii_alphanumeric() || c == '_'
                } else {
                    c.is_alphanumeric() || "_./-".contains(c)
                }
            });
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
    };
    // GitLab may parse escapes and fences differently from outside_code.
    // Filter even purported code regions rather than trusting that they
    // cannot notify (for example, backslash-escaped backticks are literal).
    let filtered = if forge == "gitlab" {
        filter_text(body, None, None)
    } else {
        outside_code(body, &mut filter_text)
    };
    if syntax.quick_actions {
        quick_actions(&filtered)
    } else {
        filtered
    }
}

/// TEXT with a break before the `/` that starts a line, after any
/// indentation, so that GitLab runs no quick action (`/merge`, `/approve`,
/// `/close`) in a note or description with the token's rights. In code
/// too, though GitLab skips code there: a fence it reads otherwise than
/// [`outside_code`] does would run the command.
fn quick_actions(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut line_start = true;
    for c in text.chars() {
        if line_start && c == '/' {
            result.push(BREAK);
        }
        result.push(c);
        line_start = matches!(c, '\n' | '\r') || (line_start && c.is_whitespace());
    }
    result
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
            ("gitlab", "hi @user", "hi @\u{200b}user"),
            ("gitlab", "@group/subgroup", "@\u{200b}group/subgroup"),
            (
                "gitlab",
                "@all, then @here.",
                "@\u{200b}all, then @\u{200b}here.",
            ),
            ("gitlab", "@.dotted", "@\u{200b}.dotted"),
            // GitLab reads a mention after anything but an ASCII word
            // character; Forgejo not after a path's.
            ("gitlab", "x.@all", "x.@\u{200b}all"),
            ("gitlab", "path/@here", "path/@\u{200b}here"),
            ("gitlab", "é@all", "é@\u{200b}all"),
            ("forgejo", "path/@user", "path/@user"),
            ("gitlab", "user@example.com", "user@example.com"),
            ("gitlab", "`@all`", "`@\u{200b}all`"),
            ("gitlab", r"\`@all\`", "\\`@\u{200b}all\\`"),
            ("forgejo", "user@example.com", "user@example.com"),
            ("forgejo", "see !12", "see !\u{200b}12"),
            ("forgejo", "Closes !12", "C\u{200b}loses !\u{200b}12"),
            ("github", "see !12", "see !12"),
        ] {
            assert_eq!(filter(input, forge), expected, "{forge}: {input}");
        }
    }

    /// No line of a GitLab note or description starts a quick action,
    /// indented, after a CR or in code; elsewhere nothing changes.
    #[test]
    fn quick_actions() {
        for (forge, input, expected) in [
            ("gitlab", "/merge", "\u{200b}/merge"),
            (
                "gitlab",
                "Done.\n/approve\n/assign @me",
                "Done.\n\u{200b}/approve\n\u{200b}/assign @\u{200b}me",
            ),
            (
                "gitlab",
                "a\r/close\r\n  /close",
                "a\r\u{200b}/close\r\n  \u{200b}/close",
            ),
            ("gitlab", "```\n/close\n```", "```\n\u{200b}/close\n```"),
            ("gitlab", "see a/b and /c", "see a/b and /c"),
            ("gitlab", "> /close", "> /close"),
            ("forgejo", "/close", "/close"),
            ("github", "/close", "/close"),
        ] {
            assert_eq!(filter(input, forge), expected, "{forge}: {input:?}");
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

    #[test]
    fn nested_gitlab_references_share_the_cap() {
        for keyword in ["Closes", "Fixes", "Resolves", "Implements"] {
            for project in [
                "group/project",
                "group/subgroup/project",
                "group/a/b/project",
            ] {
                let reference = format!("{keyword} {project}#2\n");
                let prefix = reference.repeat(MAX_REFERENCES);
                assert_eq!(filter(&prefix, "gitlab"), prefix);
                let input = format!("{prefix}Closes #3\n{reference}");
                let expected = format!(
                    "{prefix}C{BREAK}loses #{BREAK}3\n{}{BREAK}{} {project}#{BREAK}2\n",
                    &keyword[..1],
                    &keyword[1..]
                );
                assert_eq!(filter(&input, "gitlab"), expected, "{input}");
                assert_eq!(filter(&expected, "gitlab"), expected);
            }
        }
    }

    #[test]
    fn gitlab_closing_keyword_variants_share_the_cap() {
        for keyword in [
            "Close",
            "Closes",
            "Closed",
            "Closing",
            "Fix",
            "Fixes",
            "Fixed",
            "Fixing",
            "Resolve",
            "Resolves",
            "Resolved",
            "Resolving",
            "Implement",
            "Implements",
            "Implemented",
            "Implementing",
        ] {
            for separator in [" ", ": ", " issue ", ": issue ", " issues ", ": issues "] {
                for project in ["", "group/project", "group/subgroup/project"] {
                    let reference = format!("{keyword}{separator}{project}#2\n");
                    let prefix = reference.repeat(MAX_REFERENCES);
                    assert_eq!(filter(&prefix, "gitlab"), prefix);
                    let expected = format!(
                        "{prefix}{}{BREAK}{}{separator}{project}#{BREAK}2\n",
                        &keyword[..1],
                        &keyword[1..]
                    );
                    let input = format!("{prefix}{reference}");
                    assert_eq!(filter(&input, "gitlab"), expected, "{input}");
                    assert_eq!(filter(&expected, "gitlab"), expected);
                    // New forms and old forms consume the same budget.
                    assert_eq!(
                        filter(&format!("{prefix}Closes #3"), "gitlab"),
                        format!("{prefix}C{BREAK}loses #{BREAK}3")
                    );
                }
            }
        }
        for forge in ["github", "forgejo"] {
            for reference in ["Closing #1", "Fixes: #1", "Closes issue #1"] {
                let input = format!("{reference}\n").repeat(MAX_REFERENCES + 1);
                assert_eq!(filter(&input, forge), input);
            }
        }
        let prefix = "`fIxInG: issue group/subgroup/project#1`\n".repeat(MAX_REFERENCES);
        assert_eq!(
            filter(&format!("{prefix}Resolving: #2"), "gitlab"),
            format!("{prefix}R{BREAK}esolving: #{BREAK}2")
        );
    }

    #[test]
    fn nested_gitlab_references_in_code_are_counted() {
        let prefix = "`Closes group/subgroup/project#1`\n".repeat(MAX_REFERENCES);
        assert_eq!(
            filter(&format!("{prefix}Fixes #2"), "gitlab"),
            format!("{prefix}F{BREAK}ixes #{BREAK}2")
        );
        // Other forges do not have GitLab's nested project syntax.
        for forge in ["github", "forgejo"] {
            let input = "Closes group/subgroup/project#1\n".repeat(MAX_REFERENCES + 1);
            assert_eq!(filter(&input, forge), input);
        }
    }
}
