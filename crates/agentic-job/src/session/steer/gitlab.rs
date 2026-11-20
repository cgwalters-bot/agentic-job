//! The GitLab reader of the item watch: how an issue of a GitLab server
//! (gitlab.com or a self-hosted one) is read, and what on it is an
//! update.
//!
//! The item is a GitLab issue's web address, as the caller gives it:
//! `https://SERVER/GROUP/…/PROJECT/-/issues/NUMBER`. The server is read
//! at the same origin (`/api/v4` under it), so a private server's API is
//! not sent anywhere else, and the project is named by its path with
//! namespace — each segment written as the web address writes it (nested
//! namespaces included), joined for the API with `%2F`. An issue only:
//! merge requests are not watched.
//!
//! GitLab's notes API has no `since`, so each poll lists the issue's
//! notes newest first and works back to the watch's start, a page at a
//! time. The page URLs are built from the configured origin alone,
//! never taken from an answer, and a redirect is refused rather than
//! followed with the token. A comment made before the watch began is
//! not an update however often it is edited since (the cursor is a
//! note's creation, not its last change), and each note is delivered
//! once, however many pages or polls it shows up on. A poll that a page
//! refuses delivers nothing and marks nothing as read; a poll that stops
//! at its page or byte bound delivers what it examined and says the
//! coverage was reduced. Either way, no cursor moves past a note that
//! was not delivered: the next poll reads what was left.
//!
//! GitLab's own system notes (labels changed, branches merged) are not
//! anyone's words, and neither are the run-status notes this harness's
//! callers leave on items ([`RUN_MARKER`]): both are skipped.

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SubsecRound, Utc};
use serde_json::Value;

use super::{Kind, PER_PAGE, Seen, State, Update, polled};

/// Where the run's read-only GitLab token is, mirroring the GitHub
/// watch's `GH_TOKEN`: the caller gives it to the run for this watch,
/// and the agent is not given it — the watch reads the item, not the
/// agent.
pub const TOKEN_VAR: &str = "GITLAB_READ_TOKEN";
/// Notes carrying this marker are this harness's own run-status notes
/// (a caller's automation reporting a run on the item), not input: they
/// are skipped.
pub const RUN_MARKER: &str = "<!-- agentic-job: run-status -->";
/// The most pages one poll reads: past it the scan stops and says so,
/// leaving the rest for the next poll.
const MAX_PAGES: u32 = 10;
/// The largest response read: one page of notes.
const MAX_RESPONSE: u64 = 1 << 20;
/// The most bytes one poll reads across its pages.
const MAX_POLL_BYTES: u64 = 8 << 20;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A GitLab issue, as its web address names it:
/// `https://SERVER/GROUP/…/PROJECT/-/issues/NUMBER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The server, as `https://host[:port]` with no trailing slash.
    pub origin: String,
    /// The project's path with namespace, its segments as the web
    /// address writes them (`a%20b` for a name with a space), joined
    /// with `/`.
    pub project: String,
    /// The issue's IID, positive.
    pub iid: u64,
}

impl Target {
    /// The issue's page, for the provenance of an update.
    fn web_url(&self) -> String {
        format!("{}/{}/-/issues/{}", self.origin, self.project, self.iid)
    }

    /// The notes of page N, newest first, built from the configured
    /// origin alone: an answer's own pagination links are never followed
    /// with the token.
    fn notes_page(&self, page: u32) -> String {
        // Double-encode so a segment's own escapes cannot redefine the
        // project path: "%2F" in a name must stay data, not a separator.
        let project = self.project.replace('%', "%25").replace('/', "%2F");
        format!(
            "{}/api/v4/projects/{}/issues/{}/notes?order_by=created_at&sort=desc\
             &per_page={PER_PAGE}&page={page}",
            self.origin, project, self.iid
        )
    }
}

/// A host as an https URL writes it: a name, and a port if it says one.
fn is_host(host: &str) -> bool {
    let (name, port) = match host.split_once(':') {
        Some((name, port)) => (name, port),
        None => (host, ""),
    };
    !name.is_empty()
        && (port.is_empty() || (port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit())))
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-.".contains(&b))
}

/// A path segment as a web address writes it: letters, digits and
/// `-_.`, and whole percent escapes, but no path step.
fn is_segment(segment: &str) -> bool {
    if segment.is_empty() || segment == "." || segment == ".." {
        return false;
    }
    let bytes = segment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len()
                    || !bytes[i + 1].is_ascii_hexdigit()
                    || !bytes[i + 2].is_ascii_hexdigit()
                {
                    return false;
                }
                i += 3;
            }
            b if b.is_ascii_alphanumeric() || b"-_.".contains(&b) => i += 1,
            _ => return false,
        }
    }
    true
}

impl FromStr for Target {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parse = || {
            let rest = s.strip_prefix("https://")?;
            if rest.contains(['?', '#']) {
                return None;
            }
            let (head, digits) = rest.split_once("/-/issues/")?;
            let (host, project) = head.split_once('/')?;
            let number: u64 = digits.parse().ok().filter(|n| *n > 0)?;
            let segments = project.split('/').collect::<Vec<_>>();
            // As GitLab writes it: no sign, no leading zero; a group and
            // a project at least.
            (is_host(host)
                && segments.len() >= 2
                && segments.iter().all(|s| is_segment(s))
                && number.to_string() == digits)
                .then(|| Target {
                    origin: format!("https://{host}"),
                    project: project.to_owned(),
                    iid: number,
                })
        };
        parse().with_context(|| {
            format!(
                "{s:?} is not a GitLab issue as \
                 https://SERVER/GROUP/…/PROJECT/-/issues/NUMBER"
            )
        })
    }
}

/// A GitLab item to watch. No `Debug`: it holds the token.
#[derive(Clone)]
pub struct Watch {
    pub target: Target,
    pub token: String,
    pub interval: Duration,
}

/// A response to a request for a page of notes.
enum Got {
    Notes {
        value: Value,
        bytes: u64,
    },
    /// GitLab refused for a rate limit, and says for how long.
    Wait(Duration),
}

/// The GitLab watch's state between polls.
pub struct Poller {
    watch: Watch,
    http: ureq::Agent,
    /// Notes written before it are not updates.
    start: DateTime<Utc>,
    state: State,
    /// The notes delivered, by their id.
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
            // GitLab's times are in whole seconds.
            start: Utc::now().trunc_subsecs(0),
            state: State::new(),
            seen: HashSet::new(),
        }
    }

    /// Reads the issue's notes once: what is new since the last poll,
    /// and how long to wait for the next.
    pub fn poll(&mut self) -> (Vec<Seen>, Duration) {
        let mut seen = Vec::new();
        let read = self.read(&mut seen);
        let wait = polled(
            &mut self.state,
            self.watch.interval,
            "GitLab",
            read,
            &mut seen,
        );
        (seen, wait)
    }

    /// Whether the run's updates are used up.
    pub fn done(&self) -> bool {
        self.state.done()
    }

    fn get(&self, url: &str) -> Result<Got> {
        let mut response = self
            .http
            .get(url)
            .header("Authorization", &format!("Bearer {}", self.watch.token))
            .header("User-Agent", env!("CARGO_PKG_NAME"))
            .call()?;
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let status = response.status().as_u16();
        match status {
            200 => {
                let text = response
                    .body_mut()
                    .with_config()
                    .limit(MAX_RESPONSE)
                    .read_to_string()?;
                let bytes = text.len() as u64;
                let value = serde_json::from_str(&text).context("parsing GitLab's answer")?;
                Ok(Got::Notes { value, bytes })
            }
            // The watch reads the configured server only: a redirect is
            // not followed with the token.
            301..=308 => bail!("GitLab redirected the notes ({status})"),
            403 | 429 => match retry_after {
                Some(s) => Ok(Got::Wait(Duration::from_secs(s.max(1)))),
                None => bail!("GitLab refused the request ({status})"),
            },
            _ => bail!("GitLab answered {status}"),
        }
    }

    /// One poll: the notes made since the watch began, in the order they
    /// were made. `Some` for how long a rate limit asks it to wait.
    fn read(&mut self, seen: &mut Vec<Seen>) -> Result<Option<Duration>> {
        let item_url = self.watch.target.web_url();
        // The pages are newest first, so the scan works back to the
        // watch's start; what it does not reach is left for the next
        // poll to find, with nothing marked as read that was not
        // delivered.
        let mut fresh: Vec<(DateTime<Utc>, u64, Update)> = Vec::new();
        let mut scanned = HashSet::new();
        let mut bytes = 0;
        let mut page = 1;
        let mut complete = false;
        loop {
            match self.get(&self.watch.target.notes_page(page))? {
                Got::Wait(d) => return Ok(Some(d)),
                Got::Notes { value, bytes: len } => {
                    bytes += len;
                    if bytes > MAX_POLL_BYTES {
                        break;
                    }
                    let list = value.as_array().context("the notes are not a list")?;
                    let mut reached_start = false;
                    for note in list {
                        if note["system"].as_bool() == Some(true) {
                            continue;
                        }
                        let text = note["body"].as_str().unwrap_or_default();
                        if text.contains(RUN_MARKER) {
                            continue;
                        }
                        let Some(id) = note["id"].as_u64() else {
                            continue;
                        };
                        // A time GitLab does not stand behind is not one
                        // to deliver a note by: the note is left unread.
                        let Some(created) = note["created_at"]
                            .as_str()
                            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                            .map(DateTime::<Utc>::from)
                        else {
                            continue;
                        };
                        if created < self.start {
                            reached_start = true;
                            break;
                        }
                        // A note that shows up on two pages — one made
                        // while the scan ran, say — is taken once.
                        if !scanned.insert(id) {
                            continue;
                        }
                        fresh.push((
                            created,
                            id,
                            Update {
                                kind: Kind::Comment,
                                item_url: item_url.clone(),
                                url: format!("{item_url}#note_{id}"),
                                author: note["author"]["username"]
                                    .as_str()
                                    .unwrap_or("unknown")
                                    .to_owned(),
                                at: note["created_at"].as_str().unwrap_or("?").to_owned(),
                                text: text.to_owned(),
                            },
                        ));
                    }
                    if reached_start || list.len() < PER_PAGE as usize {
                        complete = true;
                        break;
                    }
                    page += 1;
                    if page > MAX_PAGES {
                        break;
                    }
                }
            }
        }
        // As they were made: a tie on the second is broken by the note's
        // id, which GitLab hands out in that order.
        fresh.sort_by_key(|(created, id, _)| (*created, *id));
        for (_, id, update) in fresh {
            if self.seen.insert(id) {
                self.state.take(seen, update);
            }
        }
        if !complete {
            self.state.note(
                seen,
                "GitLab gave more of the item's notes than this poll read: the rest is read \
                 next poll"
                    .to_owned(),
            );
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use super::super::MAX_UPDATES;

    /// The grammar of a GitLab issue's address, as the caller writes it.
    #[test]
    fn targets() {
        for (text, want) in [
            (
                "https://gitlab.com/g/p/-/issues/1",
                Some(("https://gitlab.com", "g/p", 1)),
            ),
            (
                "https://ghe.example:8443/group/sub/deep.proj/-/issues/925",
                Some(("https://ghe.example:8443", "group/sub/deep.proj", 925)),
            ),
            (
                "https://gitlab.com/g/my%20proj/-/issues/3",
                Some(("https://gitlab.com", "g/my%20proj", 3)),
            ),
            (
                "https://gitlab.com/g/p_a/-/issues/12",
                Some(("https://gitlab.com", "g/p_a", 12)),
            ),
            ("https://gitlab.com/g/p/-/issues/0", None),
            ("https://gitlab.com/g/p/-/issues/01", None),
            ("https://gitlab.com/g/p/-/issues/+1", None),
            ("https://gitlab.com/g/p/-/issues", None),
            ("https://gitlab.com/g/-/issues/1", None),
            ("https://gitlab.com/p/-/issues/1", None),
            ("https://gitlab.com/g/p/merge_requests/1", None),
            ("http://gitlab.com/g/p/-/issues/1", None),
            ("https://gitlab.com/g/p/-/issues/1?x=1", None),
            ("https://gitlab.com/g/p/-/issues/1#note", None),
            ("https://gitlab.com/g/../p/-/issues/1", None),
            ("https://gitlab.com/g//p/-/issues/1", None),
            ("https://gitlab.com/g/p%2z/-/issues/1", None),
            ("https://gitlab.com/g/p%-1/-/issues/1", None),
            ("https:///g/p/-/issues/1", None),
            ("https://git lab.com/g/p/-/issues/1", None),
        ] {
            let got = text.parse::<Target>().ok();
            let want = want.map(|(origin, project, iid)| Target {
                origin: origin.to_owned(),
                project: project.to_owned(),
                iid,
            });
            assert_eq!(got, want, "{text}");
        }
        let target: Target = "https://gitlab.com/g/s/p/-/issues/7".parse().unwrap();
        assert_eq!(target.web_url(), "https://gitlab.com/g/s/p/-/issues/7");
        assert!(
            target.notes_page(2).starts_with(
                "https://gitlab.com/api/v4/projects/g%2Fs%2Fp/issues/7/notes?order_by=created_at\
                 &sort=desc&per_page=100&page=2"
            ),
            "{}",
            target.notes_page(2)
        );
        // A segment's own escapes are data: "%2F" in a project name
        // must not become a path separator at the API.
        let esc: Target = "https://gitlab.com/g/p%252Fq/-/issues/1".parse().unwrap();
        assert!(
            esc.notes_page(1)
                .starts_with("https://gitlab.com/api/v4/projects/g%2Fp%25252Fq/issues/1/notes"),
            "{}",
            esc.notes_page(1)
        );
    }

    /// A stub of GitLab's notes endpoint: the answers of each page, in
    /// order (the last repeats), as status, headers and body; it records
    /// each request's head. PAGES is indexed by the page a request asks
    /// for.
    struct Stub {
        api: String,
        heads: Arc<Mutex<Vec<String>>>,
    }

    type Answer = (u16, Vec<(&'static str, String)>, String);

    fn stub(pages: Vec<Vec<Answer>>) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let heads = Arc::new(Mutex::new(Vec::new()));
        let recorded = heads.clone();
        std::thread::spawn(move || {
            let mut counts = vec![0; pages.len()];
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
                let page: usize = path
                    .split('&')
                    .find(|p| p.starts_with("page="))
                    .and_then(|p| p.strip_prefix("page="))
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(1);
                let at = (page - 1).min(pages.len() - 1);
                let answers = &pages[at];
                let n = &mut counts[at];
                let (status, headers, body) = &answers[(*n).min(answers.len() - 1)];
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
        // The stub speaks plain http on loopback; the grammar is tested
        // above, so the target is built as the parser would have.
        let mut poller = Poller::new(Watch {
            target: Target {
                origin: api.to_owned(),
                project: "g/p".to_owned(),
                iid: 1,
            },
            token: "t".into(),
            interval: Duration::from_secs(60),
        });
        poller.start = DateTime::parse_from_rfc3339("2026-10-16T10:00:00Z")
            .unwrap()
            .into();
        poller
    }

    fn note(id: u64, created: &str, body: &str) -> Value {
        serde_json::json!({"id": id, "created_at": created, "body": body,
            "system": false, "author": {"username": format!("user{id}")}})
    }

    fn system(id: u64, created: &str) -> Value {
        serde_json::json!({"id": id, "created_at": created, "body": "changed a label",
            "system": true, "author": {"username": "bot"}})
    }

    fn page(list: &[Value]) -> Answer {
        (200, vec![], Value::from(list.to_vec()).to_string())
    }

    fn updates(seen: &[Seen]) -> Vec<(String, String)> {
        seen.iter()
            .filter_map(|s| match s {
                Seen::Update(u) => Some((u.author.clone(), u.text.clone())),
                Seen::Note(_) => None,
            })
            .collect()
    }

    fn notes(seen: &[Seen]) -> Vec<&String> {
        seen.iter()
            .filter_map(|s| match s {
                Seen::Note(n) => Some(n),
                Seen::Update(_) => None,
            })
            .collect()
    }

    /// The pages are read newest first and delivered in the order they
    /// were made, a tie on the second broken by the note's id; each note
    /// is delivered once however many polls show it, and the scan stops
    /// at a note older than the watch.
    #[test]
    fn pages_newest_first_delivered_oldest_first_once() {
        // A full first page (system notes fill it) and a second page
        // that ends in a note older than the watch.
        let mut first = vec![note(9, "2026-10-16T10:03:00Z", "d")];
        first.push(note(8, "2026-10-16T10:03:00Z", "c"));
        for id in 20..116 {
            first.push(system(id, "2026-10-16T10:02:00Z"));
        }
        first.push(note(2, "2026-10-16T10:01:00Z", "b"));
        first.push(note(1, "2026-10-16T10:01:00Z", "a"));
        assert_eq!(first.len(), PER_PAGE as usize);
        let second = vec![
            note(6, "2026-10-16T10:00:30Z", "z"),
            note(5, "2026-10-16T10:00:00Z", "e"),
            note(4, "2026-10-16T09:59:59Z", "before the run"),
        ];
        let s = stub(vec![
            vec![page(&first)],
            vec![page(&second.clone()), page(&[second[2].clone()])],
        ]);
        let mut p = poller(&s.api);
        let (seen, wait) = p.poll();
        assert_eq!(
            updates(&seen),
            vec![
                ("user5".to_owned(), "e".to_owned()),
                ("user6".to_owned(), "z".to_owned()),
                ("user1".to_owned(), "a".to_owned()),
                ("user2".to_owned(), "b".to_owned()),
                ("user8".to_owned(), "c".to_owned()),
                ("user9".to_owned(), "d".to_owned()),
            ],
            "{seen:?}"
        );
        assert!(notes(&seen).is_empty(), "{seen:?}");
        assert_eq!(wait, Duration::from_secs(60));
        // The page URLs are built from the configured origin, newest
        // first, and the token goes with every request.
        let heads = s.heads.lock().unwrap();
        assert_eq!(heads.len(), 2, "{heads:?}");
        for (i, head) in heads.iter().enumerate() {
            assert!(
                head.starts_with(&format!(
                    "GET /api/v4/projects/g%2Fp/issues/1/notes?order_by=created_at&sort=desc&\
                     per_page={PER_PAGE}&page={} ",
                    i + 1
                )),
                "{head}"
            );
            assert!(
                head.to_ascii_lowercase()
                    .contains("authorization: bearer t\r\n"),
                "{head}"
            );
        }
        drop(heads);
        // The next poll reads the same pages and delivers nothing new:
        // the note older than the watch ends the scan either way.
        let (seen, _) = p.poll();
        assert_eq!(updates(&seen), Vec::<(String, String)>::new(), "{seen:?}");
        assert_eq!(s.heads.lock().unwrap().len(), 4);
    }

    /// GitLab's own system notes and the harness's run-status notes are
    /// not input, and a note whose time GitLab does not stand behind is
    /// not delivered.
    #[test]
    fn system_and_status_notes_are_skipped() {
        let list = vec![
            note(2, "2026-10-16T10:00:00Z", "real"),
            system(3, "2026-10-16T10:00:00Z"),
            note(4, "not a time", "malformed"),
            serde_json::json!({"id": 5, "created_at": "2026-10-16T10:00:00Z",
                "body": format!("run: done\n{RUN_MARKER}"), "system": false,
                "author": {"username": "automation"}}),
        ];
        let s = stub(vec![vec![page(&list)]]);
        let mut p = poller(&s.api);
        let (seen, _) = p.poll();
        assert_eq!(
            updates(&seen),
            vec![("user2".to_owned(), "real".to_owned())],
            "{seen:?}"
        );
    }

    /// A scan that does not reach the watch's start leaves what it did
    /// not read for the next poll: a refused page moves no cursor past
    /// an unexamined note, and the reduced coverage is said.
    #[test]
    fn a_partial_scan_moves_no_cursor() {
        let mut first = vec![note(2, "2026-10-16T10:01:00Z", "second")];
        for id in 10..109 {
            first.push(system(id, "2026-10-16T10:00:30Z"));
        }
        assert_eq!(first.len(), PER_PAGE as usize);
        let second = vec![note(1, "2026-10-16T10:00:00Z", "first")];
        // Poll 1: page 2 is refused, so the scan fails and nothing is
        // marked as read — not even page 1's note, which the failed scan
        // examined but did not deliver.
        let s = stub(vec![
            vec![page(&first)],
            vec![(500, vec![], String::new()), page(&second)],
        ]);
        let mut p = poller(&s.api);
        let (seen, _) = p.poll();
        assert_eq!(updates(&seen), Vec::<(String, String)>::new(), "{seen:?}");
        assert_eq!(notes(&seen).len(), 1, "{seen:?}");
        assert!(
            notes(&seen)[0].contains("could not be read: GitLab answered 500"),
            "{}",
            notes(&seen)[0]
        );
        // Poll 2: the page answers, and both notes — the one the failed
        // scan examined and the one it never reached — are delivered,
        // in the order they were made.
        let (seen, _) = p.poll();
        assert_eq!(
            updates(&seen),
            vec![
                ("user1".to_owned(), "first".to_owned()),
                ("user2".to_owned(), "second".to_owned()),
            ],
            "{seen:?}"
        );
        assert!(notes(&seen).is_empty(), "{seen:?}");
    }

    /// More pages than a poll reads stops the scan at its page cap and
    /// says so.
    #[test]
    fn the_page_cap_leaves_the_rest() {
        let list: Vec<Value> = (1..=PER_PAGE)
            .map(|id| note(id as u64, "2026-10-16T10:00:00Z", "note"))
            .collect();
        let s = stub(vec![vec![page(&list)]; MAX_PAGES as usize]);
        let mut p = poller(&s.api);
        let (seen, _) = p.poll();
        assert_eq!(updates(&seen).len(), MAX_UPDATES, "{seen:?}");
        assert!(
            notes(&seen)
                .iter()
                .any(|n| n.contains("GitLab gave more of the item's notes than this poll read")),
            "{seen:?}"
        );
        assert_eq!(s.heads.lock().unwrap().len(), MAX_PAGES as usize);
    }

    /// More bytes than a poll reads stops the scan at its byte cap and
    /// says so.
    #[test]
    fn the_byte_cap_leaves_the_rest() {
        // Nine pages of just under the response bound: the eighth stays
        // within the poll's bound, the ninth crosses it.
        let body = "x".repeat(9_800);
        let list: Vec<Value> = (1..=PER_PAGE)
            .map(|id| note(id as u64, "2026-10-16T10:00:00Z", &body))
            .collect();
        let answer = page(&list);
        assert!(answer.2.len() as u64 <= 1 << 20);
        let s = stub(vec![vec![answer]; 9]);
        let mut p = poller(&s.api);
        let (seen, _) = p.poll();
        assert_eq!(updates(&seen).len(), MAX_UPDATES, "{seen:?}");
        assert!(
            notes(&seen)
                .iter()
                .any(|n| n.contains("GitLab gave more of the item's notes than this poll read")),
            "{seen:?}"
        );
        assert!(
            (8..=9).contains(&s.heads.lock().unwrap().len()),
            "{}",
            s.heads.lock().unwrap().len()
        );
    }

    /// A redirect is refused, and the token is not sent onward.
    #[test]
    fn a_redirect_is_refused() {
        let s = stub(vec![vec![(
            302,
            vec![("Location", "http://elsewhere.example/api/v4".to_owned())],
            String::new(),
        )]]);
        let mut p = poller(&s.api);
        let (seen, _) = p.poll();
        assert_eq!(updates(&seen), Vec::<(String, String)>::new(), "{seen:?}");
        assert!(
            notes(&seen)
                .iter()
                .any(|n| n.contains("GitLab redirected the notes (302)")),
            "{seen:?}"
        );
        assert_eq!(s.heads.lock().unwrap().len(), 1);
    }

    /// A page larger than the response bound is refused, not read in
    /// part.
    #[test]
    fn a_page_over_the_bound_is_refused() {
        let big = "x".repeat(MAX_RESPONSE as usize + 1);
        let s = stub(vec![vec![(200, vec![], big)]]);
        let mut p = poller(&s.api);
        let (seen, _) = p.poll();
        assert_eq!(updates(&seen), Vec::<(String, String)>::new(), "{seen:?}");
        assert!(
            notes(&seen).iter().any(|n| n.contains("could not be read")),
            "{seen:?}"
        );
    }

    /// A rate limit is waited out as GitLab says, within bounds.
    #[test]
    fn a_rate_limit_is_waited_out() {
        let s = stub(vec![vec![
            (429, vec![("Retry-After", "120".to_owned())], String::new()),
            (
                429,
                vec![("Retry-After", "99999".to_owned())],
                String::new(),
            ),
            (403, vec![], String::new()),
        ]]);
        let mut p = poller(&s.api);
        let (seen, wait) = p.poll();
        assert_eq!(wait, Duration::from_secs(120));
        assert_eq!(updates(&seen), Vec::<(String, String)>::new(), "{seen:?}");
        assert!(
            notes(&seen)
                .iter()
                .any(|n| n.contains("GitLab rate-limits the item's watch: next poll in 120s")),
            "{seen:?}"
        );
        let (_, wait) = p.poll();
        assert_eq!(wait, Duration::from_secs(3600));
        let (seen, _) = p.poll();
        assert!(
            notes(&seen)
                .iter()
                .any(|n| n.contains("GitLab refused the request (403)")),
            "{seen:?}"
        );
    }

    /// A run takes at most MAX_UPDATES, and then says so and stops.
    #[test]
    fn updates_are_capped() {
        let list: Vec<Value> = (1..=MAX_UPDATES as u64 + 3)
            .map(|id| note(id, "2026-10-16T10:01:00Z", &format!("comment {id}")))
            .collect();
        let s = stub(vec![vec![page(&list)]]);
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
