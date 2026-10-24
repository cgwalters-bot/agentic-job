//! Why a model request failed, as far as the words that reach the
//! session say.
//!
//! The session never talks to the provider: it sees a failed request
//! only as the agent reports it, in the JSON-RPC error it answers the
//! turn with (opencode, Vibe, and Claude Code's adapter: `Internal
//! error: API Error: Request rejected (429) ...` with `errorKind` in the
//! data), in a message that starts with the agent's `provider-error`
//! words (`AgentSpec::provider_error`), or on its standard error before
//! it dies of it. [`classify`] sorts those words into a [`Class`]: the
//! three that waiting may clear, two that it will not, and the rest.
//! The class is what the session retries on (`driver`), what the run's
//! summary files the failure under, and what reaches a caller as the
//! `failure-class` output (run/action.yml): a fixed word and numbers,
//! never the agent's text.
//!
//! The words are the providers' and the agents' as seen in real runs'
//! transcripts (`tests/data/provider/errors.json`), not a specification:
//! a failure none of them fit is `Other`, which is retried no more than
//! today, and reported as the agent's.

use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// What a failed model request was, by what can be done about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// The provider refused the request for its rate (HTTP 429, "rate
    /// limit"): a wait clears it, and the request may say how long.
    RateLimited,
    /// The provider could not serve it (HTTP 5xx, Anthropic's 529,
    /// "overloaded"): a wait usually clears it.
    Overloaded,
    /// The provider could not be reached, or the connection dropped
    /// (refused, reset, closed, EOF mid-stream, a timeout).
    Unreachable,
    /// A usage or spending limit that waiting will not clear within the
    /// run: retrying it spends the run's time for nothing.
    Quota,
    /// The provider refused the credential (HTTP 401 or 403): no retry
    /// will change that.
    Unauthorized,
    /// Words none of the above fit.
    Other,
}

impl Class {
    /// Every class, in the order the words are tried: a usage limit's
    /// words may mention a rate limit, so the one that is not retried is
    /// found first.
    pub const ALL: [Class; 6] = [
        Class::Quota,
        Class::Unauthorized,
        Class::RateLimited,
        Class::Overloaded,
        Class::Unreachable,
        Class::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Class::RateLimited => "rate_limited",
            Class::Overloaded => "overloaded",
            Class::Unreachable => "unreachable",
            Class::Quota => "quota",
            Class::Unauthorized => "unauthorized",
            Class::Other => "other",
        }
    }

    /// Whether a wait may clear it, so the request is worth another try.
    pub fn transient(self) -> bool {
        matches!(
            self,
            Class::RateLimited | Class::Overloaded | Class::Unreachable
        )
    }

    /// The kind `summary.json` files a run that ended on it under, and
    /// the `failure-class` a caller gets; none for `Other`, which stays
    /// the agent's failure (`agent_exit`).
    pub fn kind(self) -> Option<&'static str> {
        Some(match self {
            Class::RateLimited => "inference_rate_limited",
            Class::Overloaded => "inference_overloaded",
            Class::Unreachable => "inference_unreachable",
            Class::Quota => "inference_quota",
            Class::Unauthorized => "inference_unauthorized",
            Class::Other => return None,
        })
    }

    /// What the provider did, for a sentence that starts "the provider".
    pub fn describe(self) -> &'static str {
        match self {
            Class::RateLimited => "rate-limited a request",
            Class::Overloaded => "was overloaded",
            Class::Unreachable => "was unreachable",
            Class::Quota => "refused a request for a usage or spending limit",
            Class::Unauthorized => "refused the credential",
            Class::Other => "failed a request",
        }
    }
}

/// The words of each class but `Other`, case-insensitive. A status code
/// counts only next to a word that makes it one (`HTTP 503`, `error
/// 429`, `rejected (429)`, `429 Too Many Requests`): a bare number in a
/// log line is a count or an id as often as not. Likewise a word that
/// an agent's own log uses for other things (a tool's pipe that broke,
/// a tool call that timed out, an MCP connection that closed, a path
/// that is forbidden, a quota of tool calls) counts only with the words
/// a provider puts around it: the lines of an agent's standard error
/// are classified too, and a false match there would file the agent's
/// crash as the provider's failure.
static WORDS: LazyLock<[(Class, Regex); 5]> = LazyLock::new(|| {
    let re = |words: &str| Regex::new(&format!("(?i){words}")).expect("a fixed pattern");
    let status = |codes: &str| {
        format!(
            r"(?:\b(?:http|status|error|code|rejected|request failed|client error|server error)\b\W{{0,4}}(?:{codes})\b)"
        )
    };
    [
        (
            Class::Quota,
            re(&[
                r"usage limit",
                r"spend(?:ing)? limit",
                r"insufficient[_ ]quota",
                r"(?:exceeded|exhausted|reached) (?:your |the )?(?:current )?quota",
                r"quota (?:exceeded|exhausted|reached)",
                r"out of credits",
                r"insufficient (?:credits|funds|balance)",
                r"credit balance",
                r"billing (?:hard )?limit",
                r"hit your (?:\w+ )?limit",
                r"(?:monthly|weekly|daily|plan) (?:usage |spending )?limit",
                r"\b402 payment required\b",
            ]
            .join("|")),
        ),
        (
            Class::Unauthorized,
            re(&[
                &status("401|403"),
                r"\b40[13]\s+(?:unauthorized|forbidden)",
                r"\bunauthori[sz]ed\b",
                r"invalid[ _]?(?:api[ _]?key|x-api-key|api token|bearer token|credentials?)",
                r"authentication[_ ]?(?:error|failed|required)",
                r"\bpermission_error\b",
                r"not authenticated",
                r"api key (?:is )?(?:invalid|missing|not valid|expired)",
            ]
            .join("|")),
        ),
        (
            Class::RateLimited,
            re(&[
                &status("429"),
                r"\b429\s+too many",
                r"rate[ _-]?limit",
                r"too many requests",
                r"throttl",
                r"(?:requests|tokens) per (?:minute|second|day)",
                r"resource[_ ]exhausted",
                r"resource has been exhausted",
            ]
            .join("|")),
        ),
        (
            Class::Overloaded,
            re(&[
                &status(r"5\d\d"),
                r"\b5\d\d\s+(?:internal server error|service unavailable|bad gateway|gateway time)",
                r"\boverloaded",
                r"service (?:temporarily )?unavailable",
                r"bad gateway",
                r"gateway time",
                r"internal server error",
                r"\bserver[_ ]error\b",
                r"\bapi_error\b",
                r"\bupstream (?:error|failure|connect)",
                r"\b(?:at|over|no) capacity\b",
                r"temporarily unavailable",
            ]
            .join("|")),
        ),
        (
            Class::Unreachable,
            re(&[
                r"connection (?:refused|reset|aborted|timed out|error)",
                r"connection closed before",
                r"\be(?:conn(?:refused|reset|aborted)|timedout|notfound|hostunreach|netunreach|ai_again)\b",
                r"socket hang up",
                r"unexpected (?:eof|end of (?:stream|file|json))",
                r"fetch failed",
                r"network (?:error|is unreachable|unreachable)",
                r"(?:request|read|connect(?:ion)?|handshake|response|upstream|read operation) timed out",
                r"request timeout",
                r"remote (?:end|host|peer) closed",
                r"(?:could not|cannot|can't|unable to|failed to) (?:connect|resolve|reach)",
                r"getaddrinfo",
                r"no route to host",
                r"tls handshake",
                r"\bssl error\b",
            ]
            .join("|")),
        ),
    ]
});

/// What the words of a failed model request say it was: the first class
/// whose words they hold, in [`Class::ALL`]'s order, or `Other`.
pub fn classify(text: &str) -> Class {
    WORDS
        .iter()
        .find(|(_, words)| words.is_match(text))
        .map_or(Class::Other, |(class, _)| *class)
}

/// How long the words say to wait before the request is tried again
/// (`Retry-After: 30`, `retry after 30 seconds`, `try again in 1.5s`,
/// `retryDelay: 20s`, `resets in 2 minutes`), if they say; the caller
/// decides what to do with it. Nothing from words that name a time of
/// day or a date (`retry after 2026-10-24`).
pub fn retry_after(text: &str) -> Option<Duration> {
    static SAYS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)(?:retry[- ]?after|retry[- ]?delay|(?:retry|try again|resets?) (?:in|after))\W{0,4}(\d+(?:\.\d+)?)\s*(ms|milliseconds?|s|secs?|seconds?|m|mins?|minutes?)?\b",
        )
        .expect("a fixed pattern")
    });
    let found = SAYS.captures(text)?;
    // A number that goes on as a date or a clock time is not a wait.
    let rest = &text[found.get(0)?.end()..];
    if rest.starts_with(['-', '/', ':']) {
        return None;
    }
    let number: f64 = found.get(1)?.as_str().parse().ok()?;
    let unit = found
        .get(2)
        .map_or("s", |m| m.as_str())
        .to_ascii_lowercase();
    let seconds = match unit.as_str() {
        "ms" | "millisecond" | "milliseconds" => number / 1000.0,
        "m" | "min" | "mins" | "minute" | "minutes" => number * 60.0,
        _ => number,
    };
    (seconds.is_finite() && seconds >= 0.0).then(|| Duration::from_secs_f64(seconds))
}

/// The most a wait grows by jitter: a quarter, so that runs refused
/// together do not all ask again together.
const JITTER: f64 = 0.25;

/// WAIT, plus a random share of up to [`JITTER`] of it. The share comes
/// from the standard library's randomly keyed hasher, which is enough to
/// spread retries and needs no crate of its own.
pub fn jittered(wait: Duration) -> Duration {
    use std::hash::{BuildHasher, RandomState};
    let share = (RandomState::new().hash_one(0u8) % 1000) as f64 / 1000.0;
    wait.saturating_add(wait.mul_f64(share * JITTER))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The words of each class, including those of the audited runs'
    /// transcripts, redacted (also `tests/data/provider/errors.json`).
    #[test]
    fn words_are_classified() {
        use Class::*;
        let cases = [
            // Claude Code's adapter, answering the turn with an error.
            (
                "Internal error: API Error: Request rejected (429) · This request would exceed \
                 your account's rate limit. Please try again later. {\"errorKind\":\"rate_limit\"}",
                RateLimited,
            ),
            (
                "API Error: 429 {\"type\":\"error\",\"error\":{\"type\":\"rate_limit_error\",\"message\":\"This request would exceed the rate limit for your organization\"}}",
                RateLimited,
            ),
            (
                "API Error: 529 {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}",
                Overloaded,
            ),
            (
                "API Error: 500 {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"Internal server error\"}}",
                Overloaded,
            ),
            (
                "API Error: 401 {\"type\":\"error\",\"error\":{\"type\":\"authentication_error\",\"message\":\"invalid x-api-key\"}}",
                Unauthorized,
            ),
            ("API Error: Connection error.", Unreachable),
            ("API Error (Request timed out.)", Unreachable),
            ("Claude AI usage limit reached|1761087600", Quota),
            ("You've hit your limit · resets 3pm (UTC)", Quota),
            ("Credit balance is too low", Quota),
            // Vibe, answering the turn with its RateLimitError, and on
            // its standard error before it died.
            (
                "Rate limit exceeded for a-provider (model: a-model).",
                RateLimited,
            ),
            (
                "WARNING:vibe:Retrying GenericBackend._send_parsed_streaming_request after error \
                 attempt=4 delay=60.00s error=HTTPStatusError(\"Client error '429 Too Many \
                 Requests' for url 'http://proxy.invalid/v1/chat/completions'\")",
                RateLimited,
            ),
            (
                "httpx.ReadTimeout: The read operation timed out",
                Unreachable,
            ),
            // opencode's AI SDK errors.
            (
                "AI_RetryError: Failed after 3 attempts. Last error: Service Unavailable",
                Overloaded,
            ),
            (
                "AI_APICallError: Cannot connect to API: fetch failed",
                Unreachable,
            ),
            ("AI_APICallError: Bad Gateway", Overloaded),
            ("ProviderAuthError: Unauthorized", Unauthorized),
            // Other providers' words.
            (
                "You exceeded your current quota, please check your plan and billing details.",
                Quota,
            ),
            // Google's words for a rate limit, which mention a quota in
            // passing; its quota proper says it was exceeded.
            (
                "Resource has been exhausted (e.g. check quota).",
                RateLimited,
            ),
            ("RESOURCE_EXHAUSTED: Quota exceeded for metric", Quota),
            ("Error: 403 Forbidden", Unauthorized),
            ("HTTP 503 Service Unavailable", Overloaded),
            ("socket hang up", Unreachable),
            ("read ECONNRESET", Unreachable),
            ("connect ECONNREFUSED 127.0.0.1:18080", Unreachable),
            ("getaddrinfo ENOTFOUND api.example", Unreachable),
            (
                "The model is at capacity, retry after 20 seconds",
                Overloaded,
            ),
            // The adapter's own crash, a tool's error, a count: none is
            // the provider's.
            (
                "Unexpected case: {\"type\":\"system\",\"subtype\":\"ui_invalidate\",\"event\":\"ui.render\"}",
                Other,
            ),
            ("Internal error", Other),
            (
                "[session/create] phase=sdk-initialize durationMs=529 totalMs=534",
                Other,
            ),
            ("Read 429 lines from the file", Other),
            (
                "bash failed: Command failed: 'grep -n plan README.md'",
                Other,
            ),
            // Lines an agent's own log has for other things.
            ("MCP server 'github' connection closed", Other),
            ("Error: write EPIPE", Other),
            ("Timed out waiting for the tool to finish", Other),
            ("The tool call timed out.", Other),
            ("ACP stream error: invalid JSON", Other),
            ("DNS lookup for the proxy skipped", Other),
            ("warning: billing info not available", Other),
            ("Setting a quota of 100 tool calls", Other),
            ("sandbox: forbidden path /etc/shadow", Other),
            ("This operation is forbidden by the policy", Other),
            ("unknown error code 5031 in config", Other),
            ("", Other),
        ];
        for (text, want) in cases {
            assert_eq!(classify(text), want, "{text:?}");
        }
    }

    #[test]
    fn classes_are_fixed_words() {
        for class in Class::ALL {
            assert_eq!(
                serde_json::to_value(class).unwrap(),
                serde_json::Value::String(class.as_str().to_owned())
            );
            assert_eq!(class.kind().is_some(), class != Class::Other, "{class:?}");
            assert_eq!(
                class.kind().unwrap_or("inference_other"),
                format!("inference_{}", class.as_str())
            );
        }
        assert_eq!(
            Class::ALL.iter().filter(|c| c.transient()).count(),
            3,
            "rate-limited, overloaded and unreachable"
        );
        assert!(!Class::Quota.transient() && !Class::Unauthorized.transient());
        assert!(!Class::Other.transient());
    }

    #[test]
    fn retry_after_is_read_where_said() {
        let secs = Duration::from_secs;
        let cases = [
            ("Retry-After: 30", Some(secs(30))),
            ("retry after 45 seconds", Some(secs(45))),
            (
                "Please try again in 1.5s.",
                Some(Duration::from_millis(1500)),
            ),
            (
                "Please try again in 250ms",
                Some(Duration::from_millis(250)),
            ),
            ("retryDelay: 20s", Some(secs(20))),
            ("resets in 2 minutes", Some(secs(120))),
            ("retry after 2m", Some(secs(120))),
            ("Please try again later.", None),
            ("resets 3pm", None),
            ("retry after 2026-10-24", None),
            ("retry after 15:30", None),
            ("", None),
        ];
        for (text, want) in cases {
            assert_eq!(retry_after(text), want, "{text:?}");
        }
    }

    #[test]
    fn jitter_adds_at_most_a_quarter() {
        let wait = Duration::from_secs(40);
        for _ in 0..100 {
            let got = jittered(wait);
            assert!(got >= wait && got <= Duration::from_secs(50), "{got:?}");
        }
        assert_eq!(jittered(Duration::ZERO), Duration::ZERO);
    }
}
