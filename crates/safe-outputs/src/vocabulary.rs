//! The request vocabulary: gh-aw's output type names, the forge profile
//! that says which of them mean the same off GitHub, and the hand-back's
//! file of requests and its bound. A caller's bounds and policy name types
//! by these; the collector ([`crate::collect`]) validates them.

use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

/// The requests the agent wrote, one JSON object to a line.
pub const OUTPUTS_FILE: &str = "outputs.jsonl";

/// The most of an [`OUTPUTS_FILE`] that is read, and collected.
pub const MAX_OUTPUTS_BYTES: u64 = 1 << 20;

/// The output type that carries a patch for a new pull request.
pub const CREATE_PULL_REQUEST: &str = "create_pull_request";

/// The output type that carries a patch for an open pull request's
/// branch: one commit on top of the head the run started from.
pub const PUSH_TO_PULL_REQUEST_BRANCH: &str = "push_to_pull_request_branch";

/// The output type that says the run did nothing, and why.
pub const NOOP: &str = "noop";

/// The output type that says the run could not do its task without
/// something it was not given: a prerequisite, a decision, another
/// repository.
pub const MISSING_DATA: &str = "missing_data";

/// The output type that takes a pull request out of draft. Off unless a
/// bounds file lists it: apply opens a pull request as a draft unless its
/// work is complete under `ready_when_complete`, and this, like `draft:
/// false` in an update, would take one out of draft on the agent's word.
pub const MARK_READY: &str = "mark_pull_request_as_ready_for_review";

/// Hides (minimizes) a comment on the run's triggering item: moderation of
/// what other people wrote there, so it is listed in bounds only by callers
/// who want an agent to do that.
pub const HIDE_COMMENT: &str = "hide_comment";

/// Inline review comments on the run's triggering pull request, without a
/// verdict: a new comment on a line of its diff, a reply to one, and
/// resolving a thread. Check and apply hold each to that pull request, so
/// text an agent read cannot steer it to comment on, or resolve the
/// threads of, another one.
pub const CREATE_REVIEW_COMMENT: &str = "create_pull_request_review_comment";
pub const REPLY_TO_REVIEW_COMMENT: &str = "reply_to_pull_request_review_comment";
pub const RESOLVE_REVIEW_THREAD: &str = "resolve_pull_request_review_thread";
pub const REVIEW_THREAD_OUTPUTS: &[&str] = &[
    CREATE_REVIEW_COMMENT,
    REPLY_TO_REVIEW_COMMENT,
    RESOLVE_REVIEW_THREAD,
];

/// The reasons gh-aw's collector lets a `hide_comment` give (its enum,
/// which it normalizes requests to), and so all `allowed_reasons` may name.
pub const HIDE_REASONS: &[&str] = &[
    "SPAM",
    "ABUSE",
    "OFF_TOPIC",
    "OUTDATED",
    "RESOLVED",
    "LOW_QUALITY",
];

/// The output types a bounds file may list. Each is one that gh-aw's
/// collector validates with the configuration written here; another type
/// needs settings of its own, so it is added here with them and not by a
/// caller's file alone.
pub const OUTPUT_TYPES: &[&str] = &[
    "document",
    CREATE_PULL_REQUEST,
    "add_comment",
    "create_issue",
    "create_discussion",
    HIDE_COMMENT,
    CREATE_REVIEW_COMMENT,
    REPLY_TO_REVIEW_COMMENT,
    RESOLVE_REVIEW_THREAD,
    "close_issue",
    "add_labels",
    "remove_labels",
    "update_issue",
    "update_pull_request",
    MARK_READY,
    "add_reviewer",
    "assign_to_user",
    "close_pull_request",
    "link_sub_issue",
    "create_check_run",
    "update_project",
    PUSH_TO_PULL_REQUEST_BRANCH,
    NOOP,
    "missing_tool",
    MISSING_DATA,
];

/// The forge a run's outputs are applied on, from the bounds file: what
/// the caller's repository says, never the request. The wire format is
/// gh-aw's on every forge; this decides which of its types and fields
/// mean the same there (docs/safe-outputs.md#neutral-profile).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Forge {
    #[default]
    Github,
    Forgejo,
    Gitlab,
}

/// The version of the neutral profile [`Forge`] and [`NEUTRAL_OUTPUTS`]
/// describe, written into `policy.json`. It follows the gh-aw commit the
/// type names and fields are read from,
/// 462ed682857c4ab64d40f2c85e3738fa27834839, and is raised when a type or
/// field changes meaning there, so that check refuses a policy written
/// for another profile rather than read its types the new way.
pub const CONTRACT: u32 = 1;

/// The types whose fields mean the same on GitHub, Forgejo and GitLab,
/// and the only ones a run off GitHub may be allowed. A list of what is
/// held, not of what is refused: a type nobody has mapped onto a forge
/// stays GitHub-only, so a publisher never meets a request it would have
/// to guess at.
pub const NEUTRAL_OUTPUTS: &[&str] = &[
    CREATE_PULL_REQUEST,
    PUSH_TO_PULL_REQUEST_BRANCH,
    "add_comment",
    "create_issue",
    "close_issue",
    "close_pull_request",
    "add_labels",
    "remove_labels",
    CREATE_REVIEW_COMMENT,
    NOOP,
    "missing_tool",
    MISSING_DATA,
];

/// gh-aw's target field for an issue or a pull request alike. GitLab
/// numbers the two apart (`#5` and `!5` are different items), so there a
/// request names `issue_number` or `pull_request_number`; one naming this
/// could act on the wrong item.
pub const ITEM_NUMBER: &str = "item_number";

/// gh-aw's target fields that name the kind of item: an issue, and a pull
/// request (on GitLab a merge request). On GitLab, `add_labels` and
/// `remove_labels` name their item by exactly one of these.
pub const KIND_TARGETS: &[&str] = &["issue_number", "pull_request_number"];

impl Forge {
    /// The name a bounds file gives it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Forgejo => "forgejo",
            Self::Gitlab => "gitlab",
        }
    }

    /// Whether the profile holds OUTPUT on this forge.
    pub fn holds(self, output: &str) -> bool {
        self == Self::Github || NEUTRAL_OUTPUTS.contains(&output)
    }

    /// Whether a request on this forge may not have the field KEY.
    pub fn refuses_field(self, key: &str) -> bool {
        self == Self::Gitlab && key == ITEM_NUMBER
    }
}

/// The domains whose links gh-aw's sanitizer keeps when it is given none
/// (`buildAllowedDomains` in `sanitize_content_core.cjs` at the pinned
/// commit). `GH_AW_ALLOWED_DOMAINS` replaces this list, not extends it.
pub const GH_AW_LINK_DOMAINS: &[&str] = &[
    "github.com",
    "github.io",
    "githubusercontent.com",
    "githubassets.com",
    "github.dev",
    "codespaces.new",
];

/// IANA's list of top-level domains (`just refresh-top-level-domains`).
const TOP_LEVEL_DOMAINS: &str = include_str!("top-level-domains.txt");

/// What `policy` gives gh-aw as `GH_AW_ALLOWED_DOMAINS`: every top-level
/// domain, lowercase, so that its sanitizer keeps a link to any public
/// host as written (#918). The pinned sanitizer has no setting that keeps
/// every https link, and no wildcard for every domain; it does keep a
/// listed domain's subdomains. Links to an address, a host of one label
/// or a domain newer than this list are still redacted, as is every
/// non-https URL outside code. The filter stopped no leak (the sandbox
/// holds no credential worth one, and its reads are open to any host) and
/// cost reports their sources.
pub fn link_domains() -> &'static [String] {
    static DOMAINS: LazyLock<Vec<String>> = LazyLock::new(|| {
        TOP_LEVEL_DOMAINS
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    });
    &DOMAINS
}

/// Whether gh-aw's sanitizer, given ALLOWED as `GH_AW_ALLOWED_DOMAINS`,
/// keeps a link to HOST, as its `sanitizeUrlDomains` decides: the domain
/// itself or a subdomain, of [`GH_AW_LINK_DOMAINS`] where ALLOWED is empty.
pub fn keeps_link(allowed: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let kept = |domain: &str| {
        host == domain
            || host
                .strip_suffix(domain)
                .is_some_and(|sub| sub.ends_with('.'))
    };
    if allowed.is_empty() {
        GH_AW_LINK_DOMAINS.iter().any(|domain| kept(domain))
    } else {
        allowed.iter().any(|domain| kept(domain))
    }
}
