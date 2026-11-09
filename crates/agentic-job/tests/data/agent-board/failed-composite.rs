// Appended to the pinned agent-board pass/tests.rs by workflows.rs. Reuse
// its replay helpers to exercise Scheduler::before_agent through apply,
// including the failed outer composite, annotation reads and rerun write.
#[test]
fn agentic_job_failed_composite() {
    const ID: u64 = 39718949900;
    let annotation = std::env::var("AGENTIC_JOB_HOST_ANNOTATION").unwrap();
    let near_miss = annotation.replacen("exit state 4", "exit state 40", 1);
    let quoted = format!("the agent said: {annotation}");
    for (message, level, reruns) in [
        (annotation.as_str(), "failure", 1),
        (
            "the host check could not reach a host (control_unreachable)",
            "failure",
            0,
        ),
        ("", "failure", 0),
        (near_miss.as_str(), "failure", 0),
        (quoted.as_str(), "failure", 0),
        (annotation.as_str(), "warning", 0),
    ] {
        let config = config(json!({"starts": {}}));
        // The pinned replay owns these identities, not agentic-job policy.
        let repository = &config.dispatch_repo;
        let mut forge = Forge::new(None, false);
        let mut run = ended_run(&forge.replay, ID, 60, "failure");
        run["display_title"] = format!("implement {repository}#468 (claude)").into();
        failed(&mut forge.replay, vec![run]);
        failed_at(&mut forge.replay, ID, agent_failed(), message);
        for request in &mut forge.replay.requests {
            if request["request"]["get"].as_str().is_some_and(|url| {
                url.ends_with(&format!("/check-runs/{}/annotations?per_page=50", ID + 1))
            }) {
                request["answer"]["body"][0]["annotation_level"] = level.into();
            }
        }
        newest_runs(&mut forge.replay, vec![], vec![]);
        // The recording's unrelated open PR overlaps this implement plan.
        for nodes in forge
            .replay
            .requests
            .iter_mut()
            .filter_map(|e| e["answer"].pointer_mut("/data/repository/pullRequests/nodes"))
            .filter_map(Value::as_array_mut)
        {
            nodes.retain(|n| n["number"] != 889);
        }
        text_468(&mut forge.replay, "Work.");
        let report = apply(&forge, &config);
        assert_eq!(report.failures, 0, "{message}: {:#?}", report.lines);
        let writes = forge.writes.borrow();
        let sent = writes
            .iter()
            .filter(|(_, url, _)| url.ends_with(&format!("/runs/{ID}/rerun-failed-jobs")))
            .count();
        assert_eq!(sent, reruns, "{level}: {message}: {:#?}", report.lines);
        assert_eq!(
            report.lines.iter().any(|line| {
                line.contains(&format!("run rerun {repository}#468:"))
                    && line.contains("failed before the agent started")
            }),
            reruns == 1,
            "{:#?}",
            report.lines
        );
    }
}
