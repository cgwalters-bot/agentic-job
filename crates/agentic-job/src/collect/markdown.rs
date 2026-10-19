//! Markdown code regions as gh-aw's sanitizer finds them: fenced blocks
//! and inline spans, which most of its rewriting skips; the outer fence an
//! agent wraps a whole body in, which it takes off; and fences it closes
//! or leaves (`sanitize_content_core.cjs`, `markdown_unfencing.cjs` and
//! `markdown_code_region_balancer.cjs` at the pinned commit).
//!
//! Offsets are bytes where JavaScript's are UTF-16 units: every delimiter
//! looked for is ASCII, so both split the text at the same characters.

use std::ops::Range;

use super::sanitize::{is_js_space, js_trim};

/// What JavaScript's `.` does not match, besides `\n`, which no line here
/// holds: a fence line with one of these in it is not a fence to gh-aw.
fn is_line_terminator(c: char) -> bool {
    matches!(c, '\r' | '\u{2028}' | '\u{2029}')
}

/// A fence line's parts: its indent of at most three spaces, its run of
/// three or more backticks or tildes, and the rest, which holds no line
/// terminator.
struct Fence<'a> {
    indent: usize,
    char: u8,
    len: usize,
    rest: &'a str,
}

/// `^( {0,3})(`{3,}|~{3,})(.*)$` on LINE.
fn fence(line: &str) -> Option<Fence<'_>> {
    let indent = line.bytes().take_while(|&b| b == b' ').count();
    if indent > 3 {
        return None;
    }
    let after = &line[indent..];
    let char = *after
        .as_bytes()
        .first()
        .filter(|&&b| b == b'`' || b == b'~')?;
    let len = after.bytes().take_while(|&b| b == char).count();
    let rest = &after[len..];
    (len >= 3 && !rest.contains(is_line_terminator)).then_some(Fence {
        indent,
        char,
        len,
        rest,
    })
}

/// `getFencedCodeRanges`: the fenced blocks in S, each from its opening
/// line to the end of its closing one, or to the end of S if unclosed.
fn fenced_ranges(s: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut pos = 0;
    let mut open: Option<(usize, u8, usize)> = None;
    let mut lines = s.split('\n').peekable();
    while let Some(line) = lines.next() {
        let end = pos + line.len() + usize::from(lines.peek().is_some());
        match open {
            None => {
                if let Some(f) = fence(line)
                    && (f.char != b'`' || !f.rest.contains('`'))
                {
                    open = Some((pos, f.char, f.len));
                }
            }
            Some((start, char, len)) => {
                let indent = line.bytes().take_while(|&b| b == b' ').count();
                let run = line[indent..].bytes().take_while(|&b| b == char).count();
                if indent <= 3 && run >= len && line[indent + run..].chars().all(is_js_space) {
                    ranges.push(start..end);
                    open = None;
                }
            }
        }
        pos = end;
    }
    if let Some((start, ..)) = open {
        ranges.push(start..s.len());
    }
    ranges
}

/// What gh-aw passes a rewrite of the text outside code: the text, and
/// the characters right before and after it, if any.
pub type Rewrite<'a> = dyn FnMut(&str, Option<char>, Option<char>) -> String + 'a;

/// `applyFnOutsideInlineCode`: F on each run of TEXT outside inline code
/// spans, a span being a run of backticks up to the next run of as many.
fn outside_inline_code(
    text: &str,
    f: &mut Rewrite<'_>,
    outer_before: Option<char>,
    outer_after: Option<char>,
) -> String {
    if text.is_empty() {
        return f(text, outer_before, outer_after);
    }
    let bytes = text.as_bytes();
    let before = |at: usize| {
        if at > 0 {
            text[..at].chars().next_back()
        } else {
            outer_before
        }
    };
    let mut parts = String::with_capacity(text.len());
    let (mut i, mut text_start) = (0, 0);
    while i < bytes.len() {
        if bytes[i] != b'`' {
            i += 1;
            continue;
        }
        let bt_start = i;
        while i < bytes.len() && bytes[i] == b'`' {
            i += 1;
        }
        let count = i - bt_start;
        let mut close = None;
        let mut j = i;
        while j < bytes.len() {
            if bytes[j] == b'`' {
                let run_start = j;
                while j < bytes.len() && bytes[j] == b'`' {
                    j += 1;
                }
                if j - run_start == count {
                    close = Some(run_start);
                    break;
                }
            } else {
                j += 1;
            }
        }
        if let Some(close) = close {
            if text_start < bt_start {
                parts.push_str(&f(
                    &text[text_start..bt_start],
                    before(text_start),
                    Some('`'),
                ));
            }
            parts.push_str(&text[bt_start..close + count]);
            text_start = close + count;
            i = text_start;
        }
    }
    if text_start < text.len() {
        parts.push_str(&f(&text[text_start..], before(text_start), outer_after));
    }
    parts
}

/// `applyToNonCodeRegions`: F on the text of S outside fenced blocks and
/// inline spans, which are kept as they are.
pub fn outside_code(s: &str, f: &mut Rewrite<'_>) -> String {
    if s.is_empty() {
        return String::new();
    }
    let ranges = fenced_ranges(s);
    if ranges.is_empty() {
        return outside_inline_code(s, f, None, None);
    }
    let char_before = |at: usize| s[..at].chars().next_back();
    let mut parts = String::with_capacity(s.len());
    let mut pos = 0;
    for range in ranges {
        if pos < range.start {
            parts.push_str(&outside_inline_code(
                &s[pos..range.start],
                f,
                char_before(pos),
                s[range.start..].chars().next(),
            ));
        }
        parts.push_str(&s[range.clone()]);
        pos = range.end;
    }
    if pos < s.len() {
        parts.push_str(&outside_inline_code(&s[pos..], f, char_before(pos), None));
    }
    parts
}

/// `unfenceMarkdown`: CONTENT without the fence around all of it, where
/// that fence is plain or says `markdown` or `md`.
pub fn unfence(content: &str) -> String {
    let trimmed = js_trim(content);
    let lines: Vec<&str> = trimmed.split('\n').collect();
    let (Some(first), Some(last)) = (lines.first(), lines.last()) else {
        return content.to_owned();
    };
    let (first, last) = (js_trim(first), js_trim(last));
    if lines.len() < 2 {
        return content.to_owned();
    }
    let char = if first.starts_with("```") {
        b'`'
    } else if first.starts_with("~~~") {
        b'~'
    } else {
        return content.to_owned();
    };
    let len = first.bytes().take_while(|&b| b == char).count();
    let tag = js_trim(&first[len..]).to_lowercase();
    if !(tag.is_empty() || tag == "markdown" || tag == "md") {
        return content.to_owned();
    }
    let closing = last.bytes().take_while(|&b| b == char).count();
    if closing < len || !js_trim(&last[closing..]).is_empty() {
        return content.to_owned();
    }
    js_trim(&lines[1..lines.len() - 1].join("\n")).to_owned()
}

/// A fence line as the balancer reads it: `^( {0,3})(`{3,}|~{3,})([^`~\s]*)?(.*)$`.
struct BalancerFence {
    line: usize,
    indent: usize,
    char: u8,
    len: usize,
    bare: bool,
}

fn balancer_fence(line: &str, index: usize) -> Option<BalancerFence> {
    let f = fence(line)?;
    if f.char == b'`' && f.rest.contains('`') {
        return None;
    }
    let language = f
        .rest
        .chars()
        .take_while(|&c| c != '`' && c != '~' && !is_js_space(c))
        .count();
    Some(BalancerFence {
        line: index,
        indent: f.indent,
        char: f.char,
        len: f.len,
        bare: language == 0,
    })
}

/// `countCodeRegions`: how many blocks open, and how many of those close.
fn count_regions(markdown: &str) -> (usize, usize) {
    let (mut total, mut balanced) = (0, 0);
    let mut open: Option<(u8, usize)> = None;
    for line in markdown.split('\n') {
        let Some(f) = balancer_fence(line, 0) else {
            continue;
        };
        match open {
            None => {
                total += 1;
                open = Some((f.char, f.len));
            }
            Some((char, len)) => {
                if f.char == char && f.len >= len && f.bare {
                    balanced += 1;
                    open = None;
                }
            }
        }
    }
    (total, total - balanced)
}

/// `balanceCodeRegions`: MARKDOWN with `\r\n` made `\n` and a closing
/// fence added for each block left open, unless that leaves more open.
pub fn balance(markdown: &str) -> String {
    if markdown.is_empty() {
        return String::new();
    }
    let normalized = markdown.replace("\r\n", "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();

    let mut comments: Vec<(usize, usize)> = Vec::new();
    let mut comment_start = None;
    for (i, line) in lines.iter().enumerate() {
        if comment_start.is_none() && line.contains("<!--") {
            comment_start = Some(i);
        }
        if let Some(start) = comment_start
            && line.contains("-->")
        {
            comments.push((start, i));
            comment_start = None;
        }
    }
    let in_comment = |i: usize| comments.iter().any(|&(start, end)| i >= start && i <= end);
    let fences: Vec<BalancerFence> = lines
        .iter()
        .enumerate()
        .filter(|&(i, _)| !in_comment(i))
        .filter_map(|(i, line)| balancer_fence(line, i))
        .collect();

    let mut processed = vec![false; fences.len()];
    let mut deferred = Vec::new();
    let mut unclosed: Vec<usize> = Vec::new();
    let mut paired: Vec<(usize, usize)> = Vec::new();
    let inside = |line: usize, paired: &[(usize, usize)], unclosed: &[usize]| {
        paired
            .iter()
            .any(|&(start, end)| line > start && line < end)
            || unclosed.iter().any(|&open| line > fences[open].line)
    };
    // Asked before `inside`, which walks every block: the same answer,
    // without a walk for each fence that could not close the block anyway.
    let closes = |open: &BalancerFence, f: &BalancerFence| {
        f.char == open.char && f.len >= open.len && f.bare && f.indent == open.indent
    };

    let mut i = 0;
    while i < fences.len() {
        if processed[i] {
            i += 1;
            continue;
        }
        processed[i] = true;
        let open = &fences[i];
        let first_closer = (i + 1..fences.len()).find(|&j| {
            !processed[j] && closes(open, &fences[j]) && !inside(fences[j].line, &paired, &unclosed)
        });
        match first_closer {
            Some(j) => {
                let opener_between = (i + 1..j)
                    .any(|k| !processed[k] && !fences[k].bare && fences[k].indent == open.indent);
                if opener_between {
                    deferred.push(i);
                    processed[i] = false;
                    i += 1;
                } else {
                    processed[j] = true;
                    paired.push((open.line, fences[j].line));
                    i = j + 1;
                }
            }
            None => {
                if !inside(open.line, &paired, &unclosed) {
                    unclosed.push(i);
                }
                i += 1;
            }
        }
    }
    for i in deferred {
        if processed[i] {
            continue;
        }
        processed[i] = true;
        let open = &fences[i];
        let closer = (i + 1..fences.len()).find(|&j| {
            !processed[j] && closes(open, &fences[j]) && !inside(fences[j].line, &paired, &unclosed)
        });
        match closer {
            Some(j) => {
                processed[j] = true;
                paired.push((open.line, fences[j].line));
            }
            None => {
                if !inside(open.line, &paired, &unclosed) {
                    unclosed.push(i);
                }
            }
        }
    }

    let mut result = normalized.clone();
    for &open in &unclosed {
        let f = &fences[open];
        result.push('\n');
        result.push_str(&" ".repeat(f.indent));
        result.push_str(&(f.char as char).to_string().repeat(f.len));
    }
    let (total_before, open_before) = count_regions(&normalized);
    let (total_after, open_after) = count_regions(&result);
    if open_after > open_before
        || (open_after == open_before && result != normalized && total_after > total_before)
    {
        return normalized;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_skipped() {
        let mut upper = |s: &str, _: Option<char>, _: Option<char>| s.to_uppercase();
        let cases = [
            ("a `b` c", "A `b` C"),
            ("a ``b`` `c", "A ``b`` `C"),
            ("x\n```\ny\n```\nz", "X\n```\ny\n```\nZ"),
            ("x\n~~~\ny", "X\n~~~\ny"),
            // A backtick in a backtick fence's info string: no fence,
            // and no span either, with none to close it.
            ("```a`b\nc", "```A`B\nC"),
            // Four spaces in: no fence.
            ("    ```\nc", "    ```\nC"),
            // A carriage return in the line: no fence to gh-aw.
            ("```\r\nc\n```", "```\r\nC\n```"),
        ];
        for (input, want) in cases {
            assert_eq!(outside_code(input, &mut upper), want, "{input:?}");
        }
    }

    #[test]
    fn neighbours_are_passed() {
        let mut seen = Vec::new();
        let mut record = |s: &str, before: Option<char>, after: Option<char>| {
            seen.push((s.to_owned(), before, after));
            s.to_owned()
        };
        outside_code("a`b`c", &mut record);
        assert_eq!(
            seen,
            [
                ("a".to_owned(), None, Some('`')),
                ("c".to_owned(), Some('`'), None)
            ]
        );
    }

    #[test]
    fn unfencing() {
        let cases = [
            ("```markdown\n# Hi\n```", "# Hi"),
            ("  ~~~md\nbody\n~~~~  ", "body"),
            ("```\nbody\n```", "body"),
            ("```rust\nbody\n```", "```rust\nbody\n```"),
            ("````\nbody\n```", "````\nbody\n```"),
            ("```", "```"),
            ("plain", "plain"),
        ];
        for (input, want) in cases {
            assert_eq!(unfence(input), want, "{input:?}");
        }
    }

    #[test]
    fn balancing() {
        let cases = [
            ("```js\ncode", "```js\ncode\n```"),
            ("a\r\nb", "a\nb"),
            ("```\na\n```", "```\na\n```"),
            ("  ```\nx", "  ```\nx\n  ```"),
            ("<!--\n```\n-->", "<!--\n```\n-->"),
        ];
        for (input, want) in cases {
            assert_eq!(balance(input), want, "{input:?}");
        }
    }

    /// Blocks, then openers none of them can close, in a body's 65,000
    /// characters: asking whether each could close a block before
    /// whether it is in one took this from 25 seconds to a moment.
    #[test]
    fn many_fences_are_quick() {
        let text = format!("{}{}", "```\n```\n".repeat(3000), "```a\n".repeat(8000));
        let start = std::time::Instant::now();
        let balanced = balance(&text);
        assert!(
            balanced.ends_with("```a\n\n```"),
            "{}",
            &balanced[balanced.len() - 20..]
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(20));
    }
}
