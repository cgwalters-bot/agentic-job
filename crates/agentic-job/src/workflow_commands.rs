//! Keep untrusted log text from becoming GitHub Actions workflow commands.
//!
//! `workflow/workflow-commands.cjs` is this module's twin for the apply
//! job, whose pinned handlers log the agent's patch; keep the two in step.

/// Breaks `::` and `##[` with a space. The runner only reads a command at
/// the start of a line, after leading whitespace (`TryParseV2` after
/// `TrimStart`); breaking them anywhere is what keeps it complete: with
/// neither left anywhere, no filter, reordering or interleaving of whole
/// lines downstream can form one, and there is no runner state (such as a
/// `stop-commands` token) to leave behind.
#[derive(Debug, Default)]
struct Escaper {
    last: [u8; 2],
}

impl Escaper {
    /// Whether a space goes before `byte`, given what came before it.
    fn space_before(&mut self, byte: u8) -> bool {
        let space = match byte {
            b':' => self.last[1] == b':',
            b'[' => self.last == *b"##",
            _ => false,
        };
        self.last = [if space { b' ' } else { self.last[1] }, byte];
        space
    }
}

/// `text` with both command syntaxes broken; see [`Escaper`].
pub(crate) fn escaped(text: &str) -> String {
    let mut escaper = Escaper::default();
    let mut shown = String::with_capacity(text.len());
    for c in text.chars() {
        // Other characters only need to reset the state.
        if escaper.space_before(u8::try_from(c).unwrap_or(0)) {
            shown.push(' ');
        }
        shown.push(c);
    }
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_breaks_both_syntaxes() {
        for (text, expected) in [
            ("::set-output name=a::b", ": :set-output name=a: :b"),
            ("::::add-mask::x\r\n", ": : : :add-mask: :x\r\n"),
            ("prefix ##[error]x", "prefix ## [error]x"),
            ("###[x] #[y] ##x", "### [x] #[y] ##x"),
            // Only the two syntaxes: URLs, times and single `#` stay.
            ("https://x/#a 12:34", "https://x/#a 12:34"),
            ("é::ü##[", "é: :ü## ["),
        ] {
            assert_eq!(escaped(text), expected);
            assert_eq!(escaped(expected), expected, "idempotent");
        }
    }
}
