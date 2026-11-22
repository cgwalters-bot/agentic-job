//! The GitHub reader of the item watch: how an issue or pull request of
//! github.com (or a GitHub Enterprise server, where `GITHUB_API_URL`
//! says) is read, and what on it is an update.
//!
//! The polls are conditional (`If-None-Match`), so an item that did not
//! change costs nothing of the token's rate limit, and a poll GitHub
//! refuses for a limit waits for as long as GitHub says. An answer that
//! says the token has almost no requests left in its window
//! (`LOW_QUOTA`) holds off the next request until the window resets,
//! so that the watch does not spend the last of a quota it shares with
//! the token's other users.

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SubsecRound, Utc};
use serde_json::Value;

use super::{Kind, MAX_RESPONSE, MAX_WAIT, PER_PAGE, Seen, State, Update, polled};

/// What GitHub's API is reached at unless the CI system says
/// (`GITHUB_API_URL`).
pub const DEFAULT_API: &str = "https://api.github.com";
const API_VERSION: &str = "2022-11-28";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The requests left in the token's window (`X-RateLimit-Remaining`) at
/// or below which the watch makes no more until it resets: what is left
/// is the token's other users'.
const LOW_QUOTA: u64 = 100;

/// An issue or pull request, as `OWNER/NAME#NUMBER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub repo: String,
    pub number: u64,
}

impl FromStr for Item {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parse = || {
            let (repo, digits) = s.split_once('#')?;
            let (owner, name) = repo.split_once('/')?;
            // GitHub's names, `.github` included, but no path step.
            let part = |p: &str| {
                !p.is_empty()
                    && p != "."
                    && p != ".."
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            };
            let number: u64 = digits.parse().ok().filter(|n| *n > 0)?;
            // As GitHub writes it: no sign, no leading zero.
            (part(owner) && part(name) && number.to_string() == digits).then(|| Item {
                repo: repo.to_owned(),
                number,
            })
        };
        parse().with_context(|| format!("{s:?} is not an item as OWNER/NAME#NUMBER"))
    }
}

/// A GitHub item to watch. No `Debug`: it holds the token.
#[derive(Clone)]
pub struct Watch {
    pub item: Item,
    /// GitHub's API, without a trailing slash.
    pub api: String,
    pub token: String,
    pub interval: Duration,
}

/// A changed payload and its validator; the poll only takes the validator
/// after using the payload.
struct Changed {
    value: Value,
    etag: Option<String>,
}

/// The GitHub watch's state between polls.
pub struct Poller {
    watch: Watch,
    http: ureq::Agent,
    /// Comments written before it are not updates.
    start: DateTime<Utc>,
    state: State,
    issue_etag: Option<String>,
    comments_etag: Option<String>,
    /// The body last seen; `None` until the first poll read it.
    body: Option<String>,
    item_url: Option<String>,
    seen: HashSet<u64>,
}

impl Poller {
    pub fn new(watch: Watch) -> Self {
        let http = ureq::Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .http_status_as_error(false)
            .max_redirects(0)
            .build()
            .into();
        Self {
            watch,
            http,
            // GitHub's times are in whole seconds.
            start: Utc::now().trunc_subsecs(0),
            state: State::new(),
            issue_etag: None,
            comments_etag: None,
            body: None,
            item_url: None,
            seen: HashSet::new(),
        }
    }

    /// Reads the item and its comments once: what changed since the last
    /// poll, and how long to wait for the next.
    pub fn poll(&mut self) -> (Vec<Seen>, Duration) {
        let mut seen = Vec::new();
        let mut delay = None;
        let read = self.read(&mut seen, &mut delay).map(|()| delay);
        let wait = polled(
            &mut self.state,
            self.watch.interval,
            "GitHub",
            read,
            &mut seen,
        );
        // On error, polled logs the read failure and returns the ordinary
        // interval. The quota delay still applies, within the same bounds.
        (seen, wait.max(delay.unwrap_or_default().min(MAX_WAIT)))
    }

    /// Whether the run's updates are used up.
    pub fn done(&self) -> bool {
        self.state.done()
    }

    /// A conditional request. Record any delay from the headers before
    /// reading the payload, so errors can't clear the delay.
    fn get(
        &self,
        url: &str,
        etag: Option<&str>,
        delay: &mut Option<Duration>,
    ) -> Result<Option<Changed>> {
        let mut request = self
            .http
            .get(url)
            .header("Authorization", &format!("Bearer {}", self.watch.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .header("User-Agent", env!("CARGO_PKG_NAME"));
        if let Some(etag) = etag {
            request = request.header("If-None-Match", etag);
        }
        let mut response = request.call()?;
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let status = response.status().as_u16();
        if matches!(status, 200 | 304) {
            *delay = low_quota(
                header("x-ratelimit-remaining").as_deref(),
                header("x-ratelimit-reset").as_deref(),
                Utc::now().timestamp(),
            );
        }
        match status {
            304 => Ok(None),
            200 => {
                let etag = header("etag");
                let text = response
                    .body_mut()
                    .with_config()
                    .limit(MAX_RESPONSE)
                    .read_to_string()?;
                let value = serde_json::from_str(&text).context("parsing GitHub's answer")?;
                Ok(Some(Changed { value, etag }))
            }
            403 | 429 => {
                let secs = |v: Option<String>| v.and_then(|v| v.trim().parse::<i64>().ok());
                let wait = match secs(header("retry-after")) {
                    Some(after) => Some(after),
                    None if header("x-ratelimit-remaining").as_deref() == Some("0") => {
                        secs(header("x-ratelimit-reset"))
                            .map(|reset| reset - Utc::now().timestamp())
                    }
                    None => None,
                };
                match wait {
                    Some(s) => {
                        *delay = Some(Duration::from_secs(s.max(1).unsigned_abs()));
                        Ok(None)
                    }
                    None => bail!("GitHub refused the request ({status})"),
                }
            }
            _ => bail!("GitHub answered {status}"),
        }
    }

    /// One poll. A delay on the issue's answer leaves the comments unread
    /// until an issue response permits the comments request again.
    fn read(&mut self, seen: &mut Vec<Seen>, delay: &mut Option<Duration>) -> Result<()> {
        let Item { repo, number } = &self.watch.item;
        let issue = format!("{}/repos/{repo}/issues/{number}", self.watch.api);
        if let Some(Changed { value, etag }) =
            self.get(&issue, self.issue_etag.as_deref(), delay)?
        {
            let url = value["html_url"]
                .as_str()
                .context("the item has no html_url")?;
            self.item_url = Some(url.to_owned());
            let body = value["body"].as_str().unwrap_or_default().to_owned();
            // The first read is what the brief was written from.
            if let Some(last) = self.body.replace(body.clone())
                && last != body
            {
                let update = Update {
                    kind: Kind::Body,
                    item_url: url.to_owned(),
                    url: url.to_owned(),
                    author: login(&value),
                    at: value["updated_at"].as_str().unwrap_or("?").to_owned(),
                    text: body,
                };
                self.state.take(seen, update);
            }
            self.issue_etag = etag;
        }
        if delay.is_some() {
            return Ok(());
        }
        // The item's URL is the issue's answer's: until there is one, no
        // comment can say where it is.
        let Some(item_url) = self.item_url.clone() else {
            return Ok(());
        };
        // Comments updated since the start, in the order they were made:
        // an older one edited since is not new. A run with more than a page
        // of them would have used up its updates long before.
        let since = self
            .start
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let comments = format!("{issue}/comments?since={since}&per_page={PER_PAGE}");
        if let Some(Changed { value, etag }) =
            self.get(&comments, self.comments_etag.as_deref(), delay)?
        {
            let list = value.as_array().context("the comments are not a list")?;
            for comment in list {
                let Some(id) = comment["id"].as_u64() else {
                    continue;
                };
                let created = comment["created_at"]
                    .as_str()
                    .and_then(|t| DateTime::parse_from_rfc3339(t).ok());
                if created.is_none_or(|t| t < self.start) || !self.seen.insert(id) {
                    continue;
                }
                let update = Update {
                    kind: Kind::Comment,
                    item_url: item_url.clone(),
                    url: comment["html_url"].as_str().unwrap_or(&item_url).to_owned(),
                    author: login(comment),
                    at: comment["created_at"].as_str().unwrap_or("?").to_owned(),
                    text: comment["body"].as_str().unwrap_or_default().to_owned(),
                };
                self.state.take(seen, update);
            }
            self.comments_etag = etag;
        }
        Ok(())
    }
}

/// How long an answer's rate-limit headers ask the watch to hold off,
/// at NOW (Unix seconds): until the window resets, where at most
/// LOW_QUOTA requests are left of it. A header missing or not a number,
/// or a reset not after NOW, is no hint, and the watch polls as usual;
/// how long a hint may hold it off is bounded where it is waited out.
fn low_quota(remaining: Option<&str>, reset: Option<&str>, now: i64) -> Option<Duration> {
    let remaining: u64 = remaining?.trim().parse().ok()?;
    let reset: i64 = reset?.trim().parse().ok()?;
    (remaining <= LOW_QUOTA && reset > now).then(|| Duration::from_secs(reset.abs_diff(now)))
}

fn login(value: &Value) -> String {
    value["user"]["login"]
        .as_str()
        .unwrap_or("unknown")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::super::MAX_UPDATES;
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn items() {
        for (text, want) in [
            ("o/r#1", Some(("o/r", 1))),
            ("my-org/a.b_c#925", Some(("my-org/a.b_c", 925))),
            ("o/r#0", None),
            ("o/r#+1", None),
            ("o/r#01", None),
            ("o/r", None),
            ("o#1", None),
            ("o/r/x#1", None),
            ("org/.github#5", Some(("org/.github", 5))),
            ("../r#1", None),
            ("o/..#1", None),
            ("o/.#1", None),
            ("o/r#1#2", None),
            ("o r/x#1", None),
            ("/r#1", None),
        ] {
            let got = text.parse::<Item>().ok();
            let want = want.map(|(repo, number)| Item {
                repo: repo.to_owned(),
                number,
            });
            assert_eq!(got, want, "{text}");
        }
    }

    /// A stub of GitHub's issue and comments endpoints: each answer is
    /// the next of ANSWERS for its path (the last repeats), as status,
    /// headers and body; it records each request's head.
    struct Stub {
        api: String,
        heads: Arc<Mutex<Vec<String>>>,
    }

    type Answer = (u16, Vec<(&'static str, String)>, String);

    fn stub(issue: Vec<Answer>, comments: Vec<Answer>) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let heads = Arc::new(Mutex::new(Vec::new()));
        let recorded = heads.clone();
        std::thread::spawn(move || {
            let (mut issue_n, mut comments_n) = (0, 0);
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    head.push_str(&line);
                }
                let path = head.split(' ').nth(1).unwrap_or_default().to_owned();
                recorded.lock().unwrap().push(head);
                let (list, n) = if path.contains("/comments") {
                    (&comments, &mut comments_n)
                } else {
                    (&issue, &mut issue_n)
                };
                let (status, headers, body) = &list[(*n).min(list.len() - 1)];
                *n += 1;
                let mut out = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (k, v) in headers {
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str("\r\n");
                out.push_str(body);
                let _ = stream.write_all(out.as_bytes());
            }
        });
        Stub { api, heads }
    }

    fn poller(api: &str) -> Poller {
        let mut poller = Poller::new(Watch {
            item: "o/r#1".parse().unwrap(),
            api: api.to_owned(),
            token: "t".into(),
            interval: Duration::from_secs(60),
        });
        poller.start = DateTime::parse_from_rfc3339("2026-10-16T10:00:00Z")
            .unwrap()
            .into();
        poller
    }

    fn issue(body: &str, etag: &str) -> Answer {
        let value = serde_json::json!({"html_url": "https://github.com/o/r/issues/1",
            "body": body, "user": {"login": "opener"}, "updated_at": "2026-10-16T10:05:00Z"});
        (200, vec![("ETag", etag.to_owned())], value.to_string())
    }

    fn comments(list: &[(u64, &str, &str)], etag: &str) -> Answer {
        let value: Vec<Value> = list
            .iter()
            .map(|(id, created, body)| {
                serde_json::json!({"id": id, "created_at": created, "body": body,
                    "html_url": format!("https://github.com/o/r/issues/1#issuecomment-{id}"),
                    "user": {"login": format!("user{id}")}})
            })
            .collect();
        (
            200,
            vec![("ETag", etag.to_owned())],
            Value::from(value).to_string(),
        )
    }

    fn not_modified() -> Answer {
        (304, vec![], String::new())
    }

    fn updates(seen: &[Seen]) -> Vec<(Kind, String, String)> {
        seen.iter()
            .filter_map(|s| match s {
                Seen::Update(u) => Some((u.kind.clone(), u.author.clone(), u.text.clone())),
                Seen::Note(_) => None,
            })
            .collect()
    }

    /// New comments and an edit of the body are each taken once; what
    /// was there before the watch, and what did not change, is not.
    #[test]
    fn new_comments_and_body_edits_once() {
        let older = (1, "2026-10-16T09:59:59Z", "before the run");
        let first = (2, "2026-10-16T10:00:00Z", "first");
        let second = (3, "2026-10-16T10:03:00Z", "second");
        let s = stub(
            vec![
                issue("brief", "\"i1\""),
                not_modified(),
                issue("brief, edited", "\"i2\""),
                not_modified(),
            ],
            vec![
                comments(&[older, first], "\"c1\""),
                not_modified(),
                comments(&[older, first, second], "\"c2\""),
                not_modified(),
            ],
        );
        let mut p = poller(&s.api);
        let comment = |id: &str, text: &str| (Kind::Comment, format!("user{id}"), text.to_owned());
        let polls: [Vec<(Kind, String, String)>; 4] = [
            vec![comment("2", "first")],
            vec![],
            vec![
                (Kind::Body, "opener".into(), "brief, edited".into()),
                comment("3", "second"),
            ],
            vec![],
        ];
        for (i, want) in polls.into_iter().enumerate() {
            let (seen, wait) = p.poll();
            assert_eq!(updates(&seen), want, "poll {i}");
            assert_eq!(seen.len(), want.len(), "poll {i}: {seen:?}");
            assert_eq!(wait, Duration::from_secs(60));
        }
        let heads = s.heads.lock().unwrap();
        assert_eq!(heads.len(), 8);
        assert!(
            heads[0].starts_with("GET /repos/o/r/issues/1 HTTP/1.1"),
            "{}",
            heads[0]
        );
        assert!(
            heads[1].starts_with(
                "GET /repos/o/r/issues/1/comments?since=2026-10-16T10:00:00Z&per_page=100 "
            ),
            "{}",
            heads[1]
        );
        let has = |i: usize, line: &str| heads[i].to_ascii_lowercase().contains(line);
        assert!(has(0, "authorization: bearer t\r\n"));
        assert!(!has(0, "if-none-match"));
        // Each poll after the first is conditional on the last answer.
        assert!(has(2, "if-none-match: \"i1\"\r\n"), "{}", heads[2]);
        assert!(has(3, "if-none-match: \"c1\"\r\n"), "{}", heads[3]);
        assert!(has(6, "if-none-match: \"i2\"\r\n"), "{}", heads[6]);
        assert!(has(7, "if-none-match: \"c2\"\r\n"), "{}", heads[7]);
    }

    /// A rate limit is waited out as GitHub says, within bounds; an error
    /// is noted once while it lasts.
    #[test]
    fn limits_and_errors() {
        let reset = (Utc::now().timestamp() + 600).to_string();
        let s = stub(
            vec![
                (429, vec![("Retry-After", "120".into())], String::new()),
                (403, vec![("Retry-After", "1".into())], String::new()),
                (
                    403,
                    vec![
                        ("X-RateLimit-Remaining", "0".into()),
                        ("X-RateLimit-Reset", reset),
                    ],
                    String::new(),
                ),
                (429, vec![("Retry-After", "99999".into())], String::new()),
                (404, vec![], String::new()),
                (404, vec![], String::new()),
                (403, vec![], String::new()),
            ],
            vec![],
        );
        let mut p = poller(&s.api);
        let notes = |seen: &[Seen]| -> Vec<String> {
            seen.iter()
                .filter_map(|s| match s {
                    Seen::Note(n) => Some(n.clone()),
                    Seen::Update(_) => None,
                })
                .collect()
        };
        let mut waits = Vec::new();
        let mut all = Vec::new();
        for _ in 0..7 {
            let (seen, wait) = p.poll();
            waits.push(wait.as_secs());
            all.extend(notes(&seen));
        }
        assert_eq!(waits[..2], [120, 60]);
        assert!((590..=600).contains(&waits[2]), "{waits:?}");
        assert_eq!(waits[3..], [3600, 60, 60, 60]);
        assert_eq!(all.len(), 6, "{all:#?}");
        assert!(
            all[4].contains("could not be read: GitHub answered 404"),
            "{}",
            all[4]
        );
        assert!(
            all[5].contains("GitHub refused the request (403)"),
            "{}",
            all[5]
        );
    }

    /// Only a quota at or below LOW_QUOTA with a reset still to come is a
    /// hint; anything else leaves the watch as it was.
    #[test]
    fn low_quota_hints() {
        let now = 1_000_000;
        for (remaining, reset, want) in [
            (Some("4999"), Some("1000600"), None),
            (Some("101"), Some("1000600"), None),
            (Some("100"), Some("1000600"), Some(600)),
            (Some("0"), Some(" 1000001 "), Some(1)),
            (Some("5"), Some("1000000"), None),
            (Some("5"), Some("999000"), None),
            // Bounded where it is waited out, not here.
            (Some("5"), Some("1099999"), Some(99999)),
            (None, Some("1000600"), None),
            (Some("5"), None, None),
            (Some(""), Some("1000600"), None),
            (Some("-1"), Some("1000600"), None),
            (Some("lots"), Some("1000600"), None),
            (Some("5"), Some("soon"), None),
            (Some("5"), Some("1000600.5"), None),
        ] {
            assert_eq!(
                low_quota(remaining, reset, now),
                want.map(Duration::from_secs),
                "{remaining:?} {reset:?}"
            );
        }
    }

    /// A low quota on a 200 or a 304 holds off the next request, the
    /// comments of the same poll included, within the watch's bounds;
    /// what was read is delivered, and what was not is read later
    /// against the last answer's ETag. Missing, malformed or past hints
    /// and a healthy quota leave the interval alone.
    #[test]
    fn low_quota_defers_requests() {
        let now = Utc::now().timestamp();
        let low = |answer: Answer, secs: i64| {
            let (status, mut headers, body) = answer;
            headers.push(("X-RateLimit-Remaining", "5".into()));
            headers.push(("X-RateLimit-Reset", (now + secs).to_string()));
            (status, headers, body)
        };
        let remaining = |answer: Answer, left: &str| {
            let (status, mut headers, body) = answer;
            headers.push(("X-RateLimit-Remaining", left.to_owned()));
            headers.push(("X-RateLimit-Reset", (now + 600).to_string()));
            (status, headers, body)
        };
        let first = (2, "2026-10-16T10:01:00Z", "first");
        let second = (3, "2026-10-16T10:02:00Z", "second");
        let s = stub(
            vec![
                issue("brief", "\"i1\""),
                low(issue("brief, edited", "\"i2\""), 120),
                remaining(not_modified(), "plenty"),
                low(not_modified(), -10),
            ],
            vec![
                low(comments(&[first], "\"c1\""), 600),
                remaining(comments(&[first, second], "\"c2\""), "4000"),
                low(not_modified(), 99999),
            ],
        );
        let mut p = poller(&s.api);
        let comment = |id: &str, text: &str| (Kind::Comment, format!("user{id}"), text.to_owned());
        // Each poll's updates and the bounds of its wait: a reset is
        // counted from a clock that moves on.
        let polls = [
            (vec![comment("2", "first")], 590, 600),
            (
                vec![(Kind::Body, "opener".into(), "brief, edited".into())],
                110,
                120,
            ),
            (vec![comment("3", "second")], 60, 60),
            (vec![], 3600, 3600),
        ];
        for (i, (want, least, most)) in polls.into_iter().enumerate() {
            let (seen, wait) = p.poll();
            assert_eq!(updates(&seen), want, "poll {i}");
            assert!(
                (least..=most).contains(&wait.as_secs()),
                "poll {i}: {wait:?}"
            );
        }
        let heads = s.heads.lock().unwrap();
        let paths: Vec<bool> = heads.iter().map(|h| h.contains("/comments")).collect();
        // The second poll stops after the issue.
        assert_eq!(paths, [false, true, false, false, true, false, true]);
        let has = |i: usize, line: &str| heads[i].to_ascii_lowercase().contains(line);
        assert!(has(2, "if-none-match: \"i1\"\r\n"), "{}", heads[2]);
        assert!(has(4, "if-none-match: \"c1\"\r\n"), "{}", heads[4]);
        assert!(has(5, "if-none-match: \"i2\"\r\n"), "{}", heads[5]);
        assert!(has(6, "if-none-match: \"c2\"\r\n"), "{}", heads[6]);
    }

    #[test]
    fn low_quota_survives_bad_payloads() {
        let reset = (Utc::now().timestamp() + 7200).to_string();
        for (on_issue, body) in [
            (false, " ".repeat(MAX_RESPONSE as usize) + "[]"),
            (false, "[".into()),
            (false, "{}".into()),
            (true, "{}".into()),
        ] {
            let bad = (
                200,
                vec![
                    ("ETag", "\"bad\"".into()),
                    ("X-RateLimit-Remaining", "5".into()),
                    ("X-RateLimit-Reset", reset.clone()),
                ],
                body,
            );
            let mut issue_answers = vec![issue("brief", "\"i1\"")];
            let mut comment_answers = vec![comments(&[], "\"c1\"")];
            if on_issue {
                issue_answers.push(bad);
            } else {
                issue_answers.push(not_modified());
                comment_answers.push(bad);
            }
            issue_answers.push(not_modified());
            comment_answers.push(comments(
                &[(2, "2026-10-16T10:01:00Z", "after the pause")],
                "\"c2\"",
            ));
            let s = stub(issue_answers, comment_answers);
            let mut p = poller(&s.api);
            p.poll();
            let (seen, wait) = p.poll();
            assert_eq!(wait, Duration::from_secs(3600), "{seen:?}");
            assert!(
                seen.iter()
                    .any(|s| matches!(s, Seen::Note(n) if n.contains("could not be read"))),
                "{seen:?}"
            );
            assert_eq!(s.heads.lock().unwrap().len(), if on_issue { 3 } else { 4 });

            let (seen, wait) = p.poll();
            assert_eq!(wait, Duration::from_secs(60));
            assert_eq!(
                updates(&seen),
                [(Kind::Comment, "user2".into(), "after the pause".into())]
            );
            let heads = s.heads.lock().unwrap();
            let retry = &heads[heads.len() - 2..];
            assert!(
                retry[0]
                    .to_ascii_lowercase()
                    .contains("if-none-match: \"i1\"\r\n")
            );
            assert!(
                retry[1]
                    .to_ascii_lowercase()
                    .contains("if-none-match: \"c1\"\r\n")
            );
        }
    }

    /// A run takes at most MAX_UPDATES, and then says so and stops.
    #[test]
    fn updates_are_capped() {
        let list: Vec<(u64, String)> = (1..=MAX_UPDATES as u64 + 3)
            .map(|id| (id, format!("comment {id}")))
            .collect();
        let refs: Vec<(u64, &str, &str)> = list
            .iter()
            .map(|(id, text)| (*id, "2026-10-16T10:01:00Z", text.as_str()))
            .collect();
        let s = stub(
            vec![issue("brief", "\"i\"")],
            vec![comments(&refs, "\"c\"")],
        );
        let mut p = poller(&s.api);
        let (seen, _) = p.poll();
        assert_eq!(updates(&seen).len(), MAX_UPDATES);
        assert!(p.done());
        assert_eq!(
            seen.last(),
            Some(&Seen::Note(format!(
                "the run's item gave its {MAX_UPDATES} updates: it is watched no more"
            )))
        );
    }
}
