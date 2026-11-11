//! Neutral inline comments: one fixed item, one checked head, one diff line.
//! No review verdict, replies, resolution, or lossy range conversion.

use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value};

use super::{MAX_BODY_CHARS, Target, mentions, with_footer};
use crate::contract::Policy;

// The target check writes and apply reads back is check's, so that
// neither depends on the other for it.
pub use crate::check::inline::{CheckedTarget, checked_target};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineComment {
    pub target: CheckedTarget,
    pub path: String,
    pub line: u64,
    pub left: bool,
    pub body: String,
}

/// Refuse unsupported fields in check too, before publishing can be attempted.
pub fn fields(item: &Map<String, Value>, forge: crate::Forge) -> Result<()> {
    crate::collect::inline_field_names(item)?;
    ensure!(
        item.get("line")
            .and_then(Value::as_u64)
            .is_some_and(|n| n > 0 && n <= i64::MAX as u64),
        "inline comment needs a positive representable line"
    );
    ensure!(
        item.get("side")
            .is_none_or(|side| side == "LEFT" || side == "RIGHT"),
        "inline comment side must be LEFT or RIGHT"
    );
    ensure!(
        item.get("path")
            .and_then(Value::as_str)
            .is_some_and(|path| !path.is_empty() && !path.chars().any(char::is_control)),
        "inline comment needs a path"
    );
    ensure!(
        item.get("body")
            .and_then(Value::as_str)
            .is_some_and(|body| !body.trim().is_empty() && body.chars().count() <= MAX_BODY_CHARS),
        "inline comment needs a body of at most {MAX_BODY_CHARS} characters"
    );
    // Use the existing comment envelope, including its reserved footer/link
    // allowance, rather than giving inline findings a larger publish budget.
    let mut envelope = item.clone();
    envelope.insert("type".into(), Value::String("add_comment".into()));
    let syntax = match forge {
        crate::Forge::Forgejo => "forgejo",
        crate::Forge::Gitlab => "gitlab",
        crate::Forge::Github => {
            anyhow::bail!("neutral inline comments require a neutral forge")
        }
    };
    // Escaping notifications/quick actions can grow a valid input beyond the
    // envelope. Measure that text in check too, with its reserved footer budget.
    envelope.insert(
        "body".into(),
        mentions::filter(item["body"].as_str().context("missing body")?, syntax).into(),
    );
    let refusals = crate::check::handler_limits::refusals(&envelope);
    ensure!(refusals.is_empty(), "{}", refusals.join("; "));
    Ok(())
}

pub(super) fn plan(
    item: &Map<String, Value>,
    checked: Option<&CheckedTarget>,
    policy: &Policy,
    target: &Target<'_>,
) -> Result<InlineComment> {
    fields(item, policy.forge)?;
    let checked = checked.context("check recorded no inline target/head")?;
    let expected = checked_target(
        target.comment_target.map(|number| (target.repo, number)),
        Some(&checked.head),
        policy,
    )?;
    ensure!(
        *checked == expected,
        "inline target is not the policy-authorized PR/MR"
    );
    let body = with_footer(
        &mentions::filter(
            item["body"].as_str().context("missing body")?,
            target.forge.syntax(),
        ),
        policy.provenance_footer.as_deref(),
        target.provenance.name,
        target.run_url,
    );
    // A caller-supplied run link need not fit in the reserved footer allowance.
    // Bound the actual published text, not only the request before expansion.
    ensure!(
        body.encode_utf16().count() <= MAX_BODY_CHARS,
        "published inline comment including its footer exceeds {MAX_BODY_CHARS} UTF-16 units"
    );
    Ok(InlineComment {
        target: expected,
        path: item["path"].as_str().context("missing path")?.to_owned(),
        line: item["line"].as_u64().context("missing line")?,
        left: item.get("side").is_some_and(|side| side == "LEFT"),
        body,
    })
}

/// A diff line can name both sides (context), or just one (addition/deletion).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Position {
    pub old: Option<u64>,
    pub new: Option<u64>,
}

/// Validate the entire patch, including hunk lengths, before selecting a line.
/// This refuses truncated API diffs rather than guessing at their positions.
pub(crate) fn position(patch: &str, comment: &InlineComment) -> Result<Position> {
    let mut old = 0_u64;
    let mut new = 0_u64;
    let mut remaining = (0_u64, 0_u64);
    let mut found = None;
    let mut hunk = false;
    for line in patch.lines() {
        if line.starts_with("@@ ") {
            ensure!(remaining == (0, 0), "truncated diff hunk");
            let parts: Vec<_> = line.split_whitespace().collect();
            ensure!(
                parts.len() >= 4 && parts[0] == "@@" && parts[3] == "@@",
                "invalid diff hunk"
            );
            let range = |text: &str, sign: char| -> Result<(u64, u64)> {
                let text = text.strip_prefix(sign).context("invalid diff range")?;
                let (start, count) = text.split_once(',').unwrap_or((text, "1"));
                Ok((start.parse()?, count.parse()?))
            };
            let (start, count) = range(parts[1], '-')?;
            old = start;
            remaining.0 = count;
            let (start, count) = range(parts[2], '+')?;
            new = start;
            remaining.1 = count;
            hunk = true;
            continue;
        }
        if line == "\\ No newline at end of file" {
            continue;
        }
        ensure!(hunk, "diff has no hunk");
        let (has_old, has_new) = match line.as_bytes().first() {
            Some(b' ') => (true, true),
            Some(b'-') => (true, false),
            Some(b'+') => (false, true),
            _ => anyhow::bail!("invalid diff line"),
        };
        let pos = Position {
            old: has_old.then_some(old),
            new: has_new.then_some(new),
        };
        if (if comment.left { pos.old } else { pos.new }) == Some(comment.line) {
            ensure!(found.is_none(), "ambiguous diff line");
            found = Some(pos);
        }
        if has_old {
            remaining.0 = remaining
                .0
                .checked_sub(1)
                .context("invalid old diff length")?;
            old = old.checked_add(1).context("diff line overflow")?;
        }
        if has_new {
            remaining.1 = remaining
                .1
                .checked_sub(1)
                .context("invalid new diff length")?;
            new = new.checked_add(1).context("diff line overflow")?;
        }
    }
    ensure!(remaining == (0, 0), "truncated diff hunk");
    found.context("inline comment line is outside the diff")
}

/// Select one file from a bounded raw Forgejo diff. Quoted/ambiguous paths,
/// binary patches and files absent from the diff are deliberately unsupported.
pub(crate) fn forgejo_patch(diff: &str, path: &str) -> Result<String> {
    let mut found = None;
    let diff = diff
        .strip_prefix("diff --git ")
        .context("diff has no file header")?;
    for file in diff.split("\ndiff --git ") {
        let mut old = None;
        let mut new = None;
        let mut patch = String::new();
        let mut in_hunk = false;
        for line in file.lines() {
            if line.starts_with("@@ ") {
                in_hunk = true;
            }
            if in_hunk {
                patch.push_str(line);
                patch.push('\n');
            } else if let Some(name) = line.strip_prefix("--- ") {
                old = Some(name);
            } else if let Some(name) = line.strip_prefix("+++ ") {
                new = Some(name);
            }
        }
        let name = new
            .and_then(|name| name.strip_prefix("b/"))
            .or_else(|| old.and_then(|name| name.strip_prefix("a/")));
        if name == Some(path) {
            ensure!(found.is_none(), "ambiguous file in diff");
            found = Some(patch);
        }
    }
    found.context("inline comment file is absent from the diff")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CREATE_REVIEW_COMMENT;
    use crate::apply::testing::{Request, serve_with_headers};
    use crate::apply::tests::{collector_config, upload};
    use crate::apply::{Forge, Neutral, Op, Publisher, forgejo::Forgejo, gitlab::Gitlab};
    use crate::contract::OutputLimit;
    use serde_json::json;

    const HEAD: &str = "2222222222222222222222222222222222222222";
    const TOKEN: &str = "test-token-not-secret";
    const DIFF: &str = include_str!("../../tests/data/inline/changes.diff");

    fn fixture(name: &str) -> Value {
        serde_json::from_str(match name {
            "forgejo" => include_str!("../../tests/data/inline/forgejo.json"),
            "gitlab" => include_str!("../../tests/data/inline/gitlab.json"),
            "diffs" => include_str!("../../tests/data/inline/gitlab-diffs.json"),
            _ => panic!("unknown fixture"),
        })
        .unwrap()
    }

    fn comment() -> InlineComment {
        InlineComment {
            target: CheckedTarget {
                repo: "owner/name".into(),
                number: 9,
                head: HEAD.into(),
            },
            path: "src/x".into(),
            line: 2,
            left: false,
            body: "Finding.".into(),
        }
    }

    fn item() -> Value {
        json!({"type": CREATE_REVIEW_COMMENT, "repo": "owner/name", "pull_request_number": 9,
            "path": "src/x", "line": 2, "body": "Finding. @all @group/team !12\n/merge"})
    }

    fn policy(forge: Forge) -> Policy {
        let mut policy = crate::apply::tests::policy();
        policy.repo = "owner/name".into();
        policy.forge = match forge {
            Forge::Forgejo => crate::Forge::Forgejo,
            Forge::Gitlab => crate::Forge::Gitlab,
        };
        policy.safe_outputs.others.insert(
            CREATE_REVIEW_COMMENT.into(),
            OutputLimit {
                max: 2,
                ..Default::default()
            },
        );
        policy
    }

    fn target(forge: Forge) -> Target<'static> {
        Target {
            forge,
            repo: "owner/name",
            ..crate::apply::tests::target(Some(9))
        }
    }

    fn planned(
        forge: Forge,
        items: &[Value],
        binding: Option<CheckedTarget>,
    ) -> Result<Vec<Op>, Vec<String>> {
        let dir = crate::apply::tests::checked(items);
        let path = dir.path().join(super::super::REPORT_FILE);
        let mut report: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        report["inline_target"] = json!(binding);
        std::fs::write(path, report.to_string()).unwrap();
        super::super::plan(&upload(dir.path()), &policy(forge), &target(forge))
    }

    #[test]
    fn neutral_inline_planning_and_check_guards() {
        for forge in [Forge::Forgejo, Forge::Gitlab] {
            let binding = Some(comment().target);
            let ops = planned(forge, &[item()], binding.clone()).unwrap();
            let Op::Inline(comment) = &ops[0] else {
                panic!("{ops:?}")
            };
            assert!(comment.body.contains("@\u{200b}all @\u{200b}group/team"));
            if forge == Forge::Gitlab {
                assert!(comment.body.contains("\n\u{200b}/merge"));
            }
            assert!(
                planned(forge, &[item()], None)
                    .unwrap_err()
                    .join(";")
                    .contains("no inline target")
            );
            for (key, value) in [
                ("repo", json!("foreign/name")),
                ("pull_request_number", json!(10)),
                ("line", json!(0)),
                ("line", json!(-1)),
                ("side", json!("OTHER")),
                ("start_line", json!(1)),
                ("start_side", json!("LEFT")),
                ("body", json!("x".repeat(MAX_BODY_CHARS + 1))),
                ("body", json!(" ")),
                ("path", json!("")),
                ("body", json!("https://example.com ".repeat(50))),
            ] {
                let mut item = item();
                item[key] = value;
                let errors = planned(forge, &[item.clone()], binding.clone()).unwrap_err();
                assert!(!errors.is_empty(), "{forge:?}: {key}");
                let refusals = crate::check::redirections_to(
                    item.as_object().unwrap(),
                    &policy(forge),
                    Some(("owner/name", 9)),
                    &Neutral,
                );
                assert!(!refusals.is_empty(), "check: {forge:?}: {key}");
            }
            let mut foreign = binding.clone().unwrap();
            foreign.number = 10;
            assert!(planned(forge, &[item()], Some(foreign)).is_err());
            assert!(planned(forge, &[item(), item(), item()], binding).is_err());
            assert!(checked_target(Some(("owner/name", 9)), None, &policy(forge)).is_err());
            assert!(checked_target(Some(("owner/name", 9)), Some("bad"), &policy(forge)).is_err());
        }
    }

    #[test]
    fn neutral_inline_collection_keeps_refusals_and_bounds_expanded_bodies() {
        for forge in [Forge::Forgejo, Forge::Gitlab] {
            let policy = policy(forge);
            let config = collector_config(&policy);
            for (key, value) in [
                ("start_line", json!(1)),
                ("start_side", json!("LEFT")),
                ("event", json!("APPROVE")),
                ("commit_id", json!(HEAD)),
                ("unknown", json!(null)),
            ] {
                let mut request = item();
                request[key] = value;
                let collected =
                    crate::collect::collect(&request.to_string(), &config, policy.forge, &|_| true);
                assert!(
                    collected.items.is_empty(),
                    "{forge:?}: {key}: {collected:?}"
                );
                assert!(collected.errors.join(";").contains(key), "{collected:?}");
            }
            for (body, accepted) in [
                ("@a ".repeat(21_000), false),
                ("@a ".repeat(10_000), true),
                ("\n/a".repeat(21_000), forge == Forge::Forgejo),
                ("🦀".repeat(16_000), true),
            ] {
                let mut request = item();
                request["body"] = body.into();
                let collected =
                    crate::collect::collect(&request.to_string(), &config, policy.forge, &|_| true);
                assert!(collected.errors.is_empty(), "{collected:?}");
                let checked = crate::check::redirections_to(
                    &collected.items[0],
                    &policy,
                    Some(("owner/name", 9)),
                    &Neutral,
                );
                assert_eq!(checked.is_empty(), accepted, "{forge:?}: {checked:?}");
                let requests: Vec<Value> = collected.items.into_iter().map(Value::Object).collect();
                let result = planned(forge, &requests, Some(comment().target));
                assert_eq!(result.is_ok(), accepted, "{forge:?}: {result:?}");
                if let Ok(ops) = result {
                    let Op::Inline(comment) = &ops[0] else {
                        panic!("{ops:?}")
                    };
                    assert!(comment.body.encode_utf16().count() <= MAX_BODY_CHARS);
                }
            }
            // The trusted run link is appended after the reserved-envelope check.
            let run_url = format!("https://example.com/{}", "a".repeat(2_000));
            let target = Target {
                run_url: &run_url,
                ..target(forge)
            };
            let mut request = item();
            request["body"] = "x".repeat(63_600).into();
            fields(request.as_object().unwrap(), policy.forge).unwrap();
            let error = plan(
                request.as_object().unwrap(),
                Some(&comment().target),
                &policy,
                &target,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("including its footer"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn inline_diff_positions() {
        let patch = forgejo_patch(DIFF, "src/x").unwrap();
        for (line, left, want) in [
            (
                1,
                false,
                Position {
                    old: Some(1),
                    new: Some(1),
                },
            ),
            (
                2,
                false,
                Position {
                    old: None,
                    new: Some(2),
                },
            ),
            (
                2,
                true,
                Position {
                    old: Some(2),
                    new: None,
                },
            ),
            (
                10,
                false,
                Position {
                    old: None,
                    new: Some(10),
                },
            ),
        ] {
            assert_eq!(
                position(
                    &patch,
                    &InlineComment {
                        line,
                        left,
                        ..comment()
                    }
                )
                .unwrap(),
                want
            );
        }
        assert!(
            position(
                &patch,
                &InlineComment {
                    line: 5,
                    ..comment()
                }
            )
            .is_err()
        );
        assert!(forgejo_patch(DIFF, "absent").is_err());
        for patch in [
            "@@ -1 +1,2 @@\n x\n",
            "@@ -1 +1 @@\n+x\n",
            "@@ -1 +1 @@\n?x\n",
        ] {
            assert!(position(patch, &comment()).is_err());
        }
        // A diff header in an added line must not become a new file.
        assert!(forgejo_patch(&DIFF.replace("+new", "+diff --git a/fake b/fake"), "fake").is_err());
    }

    /// Recorded API-shaped fixtures, replayed through the real HTTP adapter.
    /// These are not proof against a live forge deployment.
    #[test]
    fn inline_publishers_map_both_sides_and_context() {
        for forge in [Forge::Forgejo, Forge::Gitlab] {
            for (line, left) in [(1, false), (2, false), (2, true), (10, false)] {
                let (server, requests) = server(forge, if line == 10 { "paged" } else { "ok" });
                let publisher = publisher(forge, &server);
                let comment = InlineComment {
                    line,
                    left,
                    ..comment()
                };
                let urls =
                    super::super::publish(&[Op::Inline(comment.clone())], publisher.as_ref())
                        .unwrap();
                assert_eq!(urls.len(), 1);
                let sent: Vec<_> = requests.try_iter().collect();
                assert!(
                    sent.iter().all(|r| !r.line.contains("/issues/")),
                    "colliding issue iid must not be used"
                );
                let writes: Vec<_> = sent.iter().filter(|r| r.line.starts_with("POST")).collect();
                assert_eq!(writes.len(), 1);
                let write = writes[0];
                let body = &write.body;
                match forge {
                    Forge::Forgejo => {
                        assert_eq!(write.authorization, format!("token {TOKEN}"));
                        assert_eq!(
                            write.line,
                            "POST /api/v1/repos/owner/name/pulls/9/reviews HTTP/1.1"
                        );
                        assert_eq!(
                            *body,
                            json!({"commit_id": HEAD, "event": "COMMENT", "comments": [{
                            "path": "src/x", "body": "Finding.", "old_position": if left {line} else {0},
                            "new_position": if left {0} else {line}}]})
                        );
                    }
                    Forge::Gitlab => {
                        assert_eq!(write.authorization, format!("Bearer {TOKEN}"));
                        assert_eq!(
                            write.line,
                            "POST /api/v4/projects/1/merge_requests/9/discussions HTTP/1.1"
                        );
                        let mut expected = json!({"position_type": "text", "old_path": "src/x", "new_path": "src/x",
                            "base_sha": "1".repeat(40), "start_sha": "3".repeat(40), "head_sha": HEAD});
                        if left || line == 1 {
                            expected["old_line"] = line.into();
                        }
                        if !left {
                            expected["new_line"] = line.into();
                        }
                        assert_eq!(*body, json!({"body": "Finding.", "position": expected}));
                    }
                }
            }
        }
    }

    fn publisher(forge: Forge, server: &str) -> Box<dyn Publisher> {
        match forge {
            Forge::Forgejo => {
                Box::new(Forgejo::new(server, "owner/name", TOKEN.into(), &[]).unwrap())
            }
            Forge::Gitlab => {
                Box::new(Gitlab::new(server, "owner/name", TOKEN.into(), &[]).unwrap())
            }
        }
    }

    fn server(forge: Forge, fault: &'static str) -> (String, std::sync::mpsc::Receiver<Request>) {
        let mut reads = 0;
        let mut writes = 0;
        let mut answer = move |request: &Request| {
            let route = request.line.trim_end_matches(" HTTP/1.1");
            if route.starts_with("POST") {
                writes += 1;
                if fault == "partial" && writes == 2 {
                    return (500, format!("failure {TOKEN}"));
                }
                let answer = match forge {
                    Forge::Forgejo => {
                        json!({"id": writes, "html_url": format!("https://forge.example/review/{writes}")})
                    }
                    Forge::Gitlab => json!({"id": "discussion", "notes": [{"id": writes}]}),
                };
                return (201, answer.to_string());
            }
            let target_route = match forge {
                Forge::Forgejo => "GET /api/v1/repos/owner/name/pulls/9",
                Forge::Gitlab => "GET /api/v4/projects/1/merge_requests/9",
            };
            let answer = if route == target_route {
                reads += 1;
                let mut answer = fixture(match forge {
                    Forge::Forgejo => "forgejo",
                    Forge::Gitlab => "gitlab",
                });
                if fault == "stale" || (fault == "moved" && reads > 2) {
                    match forge {
                        Forge::Forgejo => answer["head"]["sha"] = json!("4".repeat(40)),
                        Forge::Gitlab => answer["sha"] = json!("4".repeat(40)),
                    }
                }
                if fault == "foreign" {
                    match forge {
                        Forge::Forgejo => {
                            answer["base"]["repo"]["full_name"] = json!("foreign/name")
                        }
                        Forge::Gitlab => answer["target_project_id"] = json!(2),
                    }
                }
                if fault == "refs" {
                    answer["diff_refs"]["start_sha"] = Value::Null;
                }
                answer
            } else if route == "GET /api/v4/projects/owner%2Fname" {
                json!({"id": 1, "path_with_namespace": "owner/name", "visibility": "public"})
            } else if let Some(page) =
                route.strip_prefix("GET /api/v1/repos/owner/name/pulls/9/reviews?page=")
            {
                match page {
                    "1&limit=50" if fault == "hidden" => json!([]),
                    "1&limit=50" if fault == "pending" => {
                        json!([{"id": 1, "state": "COMMENT"}, {"id": 2, "state": "PENDING"}])
                    }
                    "1&limit=50" => json!([{"id": 1, "state": "COMMENT"}]),
                    "2&limit=50" if matches!(fault, "hidden" | "later-pending") => {
                        json!([{"id": 2, "state": "PENDING"}])
                    }
                    "2&limit=50" if fault == "paged" => json!([{"id": 2, "state": "COMMENT"}]),
                    _ => json!([]),
                }
            } else if route == "GET /api/v1/repos/owner/name/pulls/9.diff" {
                return (200, DIFF.into());
            } else if route == "GET /api/v4/projects/1/merge_requests/9/diffs?page=1&per_page=100" {
                fixture("diffs")
            } else {
                return (404, "{}".into());
            };
            (200, answer.to_string())
        };
        serve_with_headers(100, move |request| {
            let (status, body) = answer(request);
            let headers = if request.line.contains("/reviews?page=") {
                match fault {
                    "no-count" => String::new(),
                    "bad-count" => "X-Total-Count: invalid\r\n".into(),
                    "hidden" | "later-pending" => "X-Total-Count: 51\r\n".into(),
                    "pending" | "paged" => "X-Total-Count: 2\r\n".into(),
                    _ => "X-Total-Count: 1\r\n".into(),
                }
            } else {
                String::new()
            };
            (status, headers, body)
        })
    }

    #[test]
    fn inline_publishers_refuse_before_writes_and_report_partial_failures() {
        for forge in [Forge::Forgejo, Forge::Gitlab] {
            for fault in [
                "stale",
                "foreign",
                "moved",
                "missing",
                "line",
                "refs",
                "binding",
                "pending",
                "hidden",
                "later-pending",
                "no-count",
                "bad-count",
            ] {
                if (forge == Forge::Forgejo && fault == "refs")
                    || (forge == Forge::Gitlab
                        && matches!(
                            fault,
                            "pending" | "hidden" | "later-pending" | "no-count" | "bad-count"
                        ))
                {
                    continue;
                }
                let (server, requests) = server(forge, fault);
                let publisher = publisher(forge, &server);
                let mut comment = comment();
                if fault == "missing" {
                    comment.path = "absent".into();
                }
                if fault == "line" {
                    comment.line = 5;
                }
                if fault == "binding" {
                    comment.target.repo = "foreign/name".into();
                }
                let err = super::super::publish(&[Op::Inline(comment.clone())], publisher.as_ref())
                    .unwrap_err();
                assert!(!format!("{err:#}").contains(TOKEN));
                if matches!(fault, "pending" | "later-pending") {
                    assert!(format!("{err:#}").contains("pending review"), "{err:#}");
                }
                if fault == "hidden" {
                    assert!(format!("{err:#}").contains("incomplete"), "{err:#}");
                }
                if matches!(fault, "no-count" | "bad-count") {
                    assert!(format!("{err:#}").contains("review total count"), "{err:#}");
                }
                assert!(
                    requests.try_iter().all(|r| r.line.starts_with("GET")),
                    "{forge:?}: {fault}"
                );
            }
            // All preflights happen before the first write, including bad later anchors.
            let (server, requests) = server(forge, "ok");
            let publisher = publisher(forge, &server);
            let ops = [
                Op::Inline(comment()),
                Op::Inline(InlineComment {
                    line: 5,
                    ..comment()
                }),
            ];
            assert!(super::super::publish(&ops, publisher.as_ref()).is_err());
            assert!(requests.try_iter().all(|r| r.line.starts_with("GET")));

            let (server, requests) = self::server(forge, "partial");
            let publisher = self::publisher(forge, &server);
            let ops = [Op::Inline(comment()), Op::Inline(comment())];
            let err = format!(
                "{:#}",
                super::super::publish(&ops, publisher.as_ref()).unwrap_err()
            );
            assert!(err.contains("after publishing https://"), "{err}");
            assert!(!err.contains(TOKEN), "{err}");
            assert_eq!(
                requests
                    .try_iter()
                    .filter(|r| r.line.starts_with("POST"))
                    .count(),
                2
            );
        }
    }
}
