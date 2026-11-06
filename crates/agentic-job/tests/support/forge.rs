//! Shared hand-backs and git fixtures for disposable forge integration tests.
#![allow(dead_code, clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

pub const PROXY_VARS: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
];

pub fn assert_success(what: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{what}: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A checked upload of ITEMS alone.
pub fn checked_items(dir: &Path, items: &[Value]) {
    std::fs::create_dir(dir).unwrap();
    let report = json!({"ok": true, "errors": [], "items": items, "patch": null});
    std::fs::write(dir.join("report.json"), report.to_string()).unwrap();
}

/// A checked comment and pull request adding FILE on BASE.
pub fn checked(dir: &Path, base: &str, branch: &str, file: &str, mention: &str) {
    checked_items(
        dir,
        &[
            json!({"type": "add_comment", "body": format!("Done, {mention}.")}),
            json!({"type": "create_pull_request", "title": "Fix it", "body": format!("Why, {mention}."), "branch": branch}),
        ],
    );
    let patch = format!(
        "From 2222222222222222222222222222222222222222 Mon Sep 17 00:00:00 2001\n\
         X-GH-AW-Base-Commit: {base}\n\
         From: agent <agent@localhost>\n\
         Date: Tue, 6 Oct 2026 21:02:35 -0400\n\
         Subject: [PATCH] Change things\n\
         \n\
         ---\n \
         {file} | 1 +\n\
         \n\
         diff --git a/{file} b/{file}\nnew file mode 100644\nindex 0000000..587be6b\n\
         --- /dev/null\n+++ b/{file}\n@@ -0,0 +1 @@\n+x\n"
    );
    let name = format!("aw-{branch}.patch");
    std::fs::write(dir.join(&name), &patch).unwrap();
    let path = dir.join("report.json");
    let mut report: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    report["patch"] =
        json!({"file": name, "bytes": patch.len(), "base_commit": base, "files": [file]});
    std::fs::write(path, report.to_string()).unwrap();
}

/// Push fixture commits with the same scoped token apply uses.
pub fn git(dir: &Path, user: &str, token: &str, args: &[&str]) {
    let mut command = Command::new("git");
    for name in PROXY_VARS {
        command.env_remove(name);
    }
    let authorization = STANDARD.encode(format!("{user}:{token}"));
    let output = command
        .current_dir(dir)
        .args([
            "-c",
            &format!("http.extraHeader=Authorization: Basic {authorization}"),
        ])
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.org",
        ])
        .args(args)
        .output()
        .unwrap();
    assert_success(&format!("git {}", args.join(" ")), &output);
}
