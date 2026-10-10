// SPDX-License-Identifier: Apache-2.0
//! Synthetic SOU-12 evidence; no discovered tool, URL or recipient is contacted.
use agentfw::mcp::admission::Invocation;
use agentfw::mcp::resources::{
    canonical_recipient, canonical_url, extract, EvidenceSource, ExecutorContext, Resource,
    ResourceProfile,
};
use serde_json::{json, Value};
use soup_wall_agent::{
    ActionClass, AgentEvent, AgentFirewall, AgentPolicySet, EventKind, Verdict, DEFAULT_TAINT_CAP,
};

fn temporary() -> tempfile::TempDir {
    // macOS exposes its temporary directory through /var -> /private/var.
    let root = std::env::temp_dir();
    #[cfg(unix)]
    let root = root.canonicalize().unwrap();
    tempfile::tempdir_in(root).unwrap()
}

fn invocation(args: Value) -> Invocation {
    Invocation {
        server_id: "fixture".into(),
        host_call_id: json!("original-call"),
        registry_sha256: "b".repeat(64),
        snapshot_sha256: "c".repeat(64),
        schema_sha256: "a".repeat(64),
        tool: "deliver_report".into(),
        description: "untrusted read-only claim".into(),
        schema: json!({"default":"https://unreviewed.example/"}),
        definition: json!({"name":"deliver_report"}),
        definition_sha256: "d".repeat(64),
        server_info: json!({"name":"fixture","version":"1"}),
        input_sha256: "e".repeat(64),
        classifier_revision: Some("f".repeat(64)),
        args,
        baseline: ActionClass::Network,
    }
}
fn profile(selectors: Value) -> ResourceProfile {
    serde_json::from_value(json!({"server_id":"fixture","tool_name":"deliver_report",
        "schema_sha256":"a".repeat(64),"selectors":selectors}))
    .unwrap()
}
fn context(dir: &std::path::Path) -> ExecutorContext<'_> {
    ExecutorContext {
        os: std::env::consts::OS,
        workspace: dir,
        cwd: dir,
        fixed_destinations: true,
    }
}

#[test]
fn reusable_destination_cases_preserve_input_and_ambiguity() {
    let dir = temporary();
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/mcp_resources/cases.json")).unwrap();
    for case in cases {
        let input = invocation(case["args"].clone());
        let output = extract(
            &input,
            &profile(case["selectors"].clone()),
            &context(dir.path()),
        );
        if let Some(reason) = case["error"].as_str() {
            assert!(!output.complete(), "{}", case["id"]);
            assert!(output.hosts_for_policy().is_err());
            assert!(
                output.issues.iter().any(|issue| issue.reason == reason),
                "{}: {:?}",
                case["id"],
                output.issues
            );
        } else {
            assert!(output.complete(), "{}: {:?}", case["id"], output.issues);
            assert_eq!(
                json!(output.hosts_for_policy().unwrap()),
                case["hosts"],
                "{}",
                case["id"]
            );
        }
        assert_eq!(
            input.args, case["args"],
            "extraction must never insert defaults or rewrite args"
        );
        assert_eq!(input.host_call_id, "original-call");
    }
}

#[test]
fn typed_hosts_feed_existing_policy_and_all_recipients_remain_restricted() {
    let dir = temporary();
    let policy = "agent_policies:\n  - name: unlisted\n    when: {egress_not_allowlisted: true}\n    action: ask\negress_allowlist: [approved.example]\ndefault: allow\n";
    let selectors = profile(json!([{"pointer":"/to","kind":"recipient"}]));
    for (recipients, expected) in [
        (json!(["one@approved.example"]), Verdict::Allow),
        (
            json!(["one@approved.example", "two@outside.example"]),
            Verdict::Ask,
        ),
    ] {
        let input = invocation(json!({"to":recipients}));
        let result = extract(&input, &selectors, &context(dir.path()));
        let hosts = result.hosts_for_policy().unwrap();
        let event = AgentEvent {
            session: "fixture".into(),
            agent: "main".into(),
            parent: None,
            seq: 1,
            at_ms: 0,
            kind: EventKind::ToolCall {
                tool: input.tool,
                args: input.args,
            },
        };
        let mut firewall = AgentFirewall::new(
            AgentPolicySet::from_yaml(policy).unwrap(),
            DEFAULT_TAINT_CAP,
        );
        assert_eq!(
            firewall
                .inspect_native_call(&event, ActionClass::Network, &hosts)
                .verdict,
            expected
        );
    }
}

#[test]
fn server_selected_destinations_and_redirects_are_explicitly_unsupported() {
    let dir = temporary();
    let mut executor = context(dir.path());
    executor.fixed_destinations = false;
    let result = extract(
        &invocation(json!({"url":"https://approved.example/"})),
        &profile(json!([{"pointer":"/url","kind":"url"}])),
        &executor,
    );
    assert_eq!(
        result.issues[0].reason,
        "resource_destination_control_unsupported"
    );
    assert!(result.hosts_for_policy().is_err());
}

#[test]
fn defaults_require_review_and_do_not_replace_invalid_values() {
    let dir = temporary();
    let input = invocation(json!({}));
    let mut reviewed = profile(json!([{"pointer":"/url","kind":"url"}]));
    assert!(!extract(&input, &reviewed, &context(dir.path())).complete());
    reviewed.selectors[0].default = Some(json!("https://approved.example/"));
    let result = extract(&input, &reviewed, &context(dir.path()));
    assert!(result.complete());
    assert_eq!(result.resources[0].source, EvidenceSource::ReviewedDefault);
    for invalid in [
        Value::Null,
        json!(false),
        json!([]),
        json!({"$ref":"/other"}),
    ] {
        assert!(!extract(
            &invocation(json!({"url":invalid})),
            &reviewed,
            &context(dir.path())
        )
        .complete());
    }
}

#[test]
fn resources_are_bound_to_original_server_schema_arguments_and_reviewed_profile() {
    let dir = temporary();
    let mut input = invocation(json!({"url":"https://approved.example/"}));
    let mut reviewed = profile(json!([{"pointer":"/url","kind":"url"}]));
    let first = extract(&input, &reviewed, &context(dir.path()));
    let other = temporary();
    assert_ne!(
        first.executor_sha256,
        extract(&input, &reviewed, &context(other.path())).executor_sha256
    );
    input.args["url"] = json!("https://outside.example/");
    let second = extract(&input, &reviewed, &context(dir.path()));
    assert_ne!(first.args_sha256, second.args_sha256);
    reviewed.selectors[0].optional = true;
    assert_ne!(
        second.profile_sha256,
        extract(&input, &reviewed, &context(dir.path())).profile_sha256
    );
    for field in ["server", "schema", "tool"] {
        let mut changed = input.clone();
        match field {
            "server" => changed.server_id.push('x'),
            "schema" => changed.schema_sha256 = "d".repeat(64),
            _ => changed.tool.push('x'),
        }
        assert_eq!(
            extract(&changed, &reviewed, &context(dir.path())).issues[0].reason,
            "resource_profile_identity_mismatch"
        );
    }
}

#[test]
fn local_paths_use_executor_cwd_and_existing_parent_without_creating_files() {
    let dir = temporary();
    std::fs::create_dir(dir.path().join("notes")).unwrap();
    std::fs::write(dir.path().join("notes/read.txt"), "synthetic").unwrap();
    let cwd = dir.path().join("notes");
    let executor = ExecutorContext {
        cwd: &cwd,
        ..context(dir.path())
    };
    let read = extract(
        &invocation(json!({"path":"read.txt"})),
        &profile(json!([{"pointer":"/path","kind":"path"}])),
        &executor,
    );
    assert!(read.complete(), "{:?}", read.issues);
    assert_eq!(
        read.resources[0].resource,
        Resource::Path {
            canonical: cwd
                .join("read.txt")
                .canonicalize()
                .unwrap()
                .to_str()
                .unwrap()
                .into()
        }
    );
    assert!(
        read.hosts_for_policy().is_err(),
        "host-only policy must not discard path restrictions"
    );
    let create = extract(
        &invocation(json!({"path":"new.txt"})),
        &profile(json!([{"pointer":"/path","kind":"path","allow_missing_leaf":true}])),
        &executor,
    );
    assert!(create.complete(), "{:?}", create.issues);
    assert!(!cwd.join("new.txt").exists());
}

#[test]
fn traversal_outside_paths_missing_parents_and_foreign_os_are_refused() {
    let dir = temporary();
    let outside = temporary();
    std::fs::write(outside.path().join("outside.txt"), "synthetic").unwrap();
    let reviewed = profile(json!([{"pointer":"/path","kind":"path","allow_missing_leaf":true}]));
    for path in [
        "../outside.txt".to_string(),
        "missing/leaf.txt".into(),
        "".into(),
        "*.txt".into(),
        outside.path().join("outside.txt").to_str().unwrap().into(),
    ] {
        let result = extract(
            &invocation(json!({"path":path})),
            &reviewed,
            &context(dir.path()),
        );
        assert!(!result.complete(), "accepted {path}");
    }
    let executor = ExecutorContext {
        os: "unselected-remote-os",
        ..context(dir.path())
    };
    assert_eq!(
        extract(&invocation(json!({"path":"new.txt"})), &reviewed, &executor).issues[0].reason,
        "resource_executor_os_unsupported"
    );
}

#[cfg(windows)]
#[test]
fn windows_device_ads_drive_relative_and_unc_paths_are_refused() {
    let dir = temporary();
    let reviewed = profile(json!([{"pointer":"/path","kind":"path","allow_missing_leaf":true}]));
    for path in [
        "NUL",
        "COM1.txt",
        "CONIN$",
        "CONOUT$",
        "COM\u{b9}.txt",
        "COM\u{b2}",
        "COM\u{b3}",
        "LPT\u{b9}.txt",
        "LPT\u{b2}",
        "LPT\u{b3}",
        "new.txt:stream",
        "C:relative.txt",
        "\\root-relative.txt",
        "\\\\server\\share\\x",
        "new.txt.",
        "new.txt ",
    ] {
        assert!(
            !extract(
                &invocation(json!({"path":path})),
                &reviewed,
                &context(dir.path())
            )
            .complete(),
            "accepted {path}"
        );
    }
    assert!(
        extract(
            &invocation(json!({"path":"report-\u{b9}.txt"})),
            &reviewed,
            &context(dir.path())
        )
        .complete(),
        "ordinary Unicode file names remain supported"
    );
}

#[cfg(unix)]
#[test]
fn symlink_leaf_parent_and_dangling_link_are_refused() {
    let dir = temporary();
    let outside = temporary();
    std::fs::write(outside.path().join("file"), "synthetic").unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("linked-dir")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("file"), dir.path().join("linked-file"))
        .unwrap();
    std::os::unix::fs::symlink(outside.path().join("absent"), dir.path().join("dangling")).unwrap();
    let root = dir.path().canonicalize().unwrap();
    let reviewed = profile(json!([{"pointer":"/path","kind":"path","allow_missing_leaf":true}]));
    for path in ["linked-dir/file", "linked-file", "dangling"] {
        assert!(!extract(
            &invocation(json!({"path":path})),
            &reviewed,
            &context(&root)
        )
        .complete());
    }
}

#[cfg(windows)]
#[test]
fn windows_junction_parent_is_refused() {
    let dir = temporary();
    let outside = temporary();
    std::fs::write(outside.path().join("file.txt"), "synthetic").unwrap();
    let link = dir.path().join("junction");
    assert!(link.starts_with(dir.path()));
    let created = std::process::Command::new("cmd.exe")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(outside.path())
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "synthetic junction must be created for this test"
    );
    let result = extract(
        &invocation(json!({"path":"junction/file.txt"})),
        &profile(json!([{"pointer":"/path","kind":"path"}])),
        &context(dir.path()),
    );
    assert!(!result.complete());
    assert!(result
        .issues
        .iter()
        .any(|issue| issue.reason == "resource_path_reparse_point"
            || issue.reason == "resource_path_link"));
}

#[test]
fn mixed_path_and_network_evidence_cannot_be_reduced_to_host_only_permission() {
    let dir = temporary();
    std::fs::write(dir.path().join("file.txt"), "synthetic").unwrap();
    let result = extract(
        &invocation(json!({"path":"file.txt","url":"https://approved.example/"})),
        &profile(json!([{"pointer":"/path","kind":"path"},{"pointer":"/url","kind":"url"}])),
        &context(dir.path()),
    );
    assert!(result.complete());
    assert_eq!(result.resources.len(), 2);
    assert_eq!(
        result.hosts_for_policy().unwrap_err(),
        "resource_path_policy_binding_unsupported"
    );
}

#[test]
fn malformed_selectors_and_oversized_values_cannot_produce_hosts() {
    let dir = temporary();
    for selectors in [
        json!([]),
        json!([{"pointer":"url","kind":"url"}]),
        json!([{"pointer":"/~2url","kind":"url"}]),
        json!([{"pointer":"/url","kind":"url","aliases":["/url"]}]),
        json!([{"pointer":"/url","kind":"url","allow_missing_leaf":true}]),
    ] {
        assert!(extract(
            &invocation(json!({"url":"https://approved.example/"})),
            &profile(selectors),
            &context(dir.path())
        )
        .hosts_for_policy()
        .is_err());
    }
    let reviewed = profile(json!([{"pointer":"/url","kind":"url"}]));
    for value in [
        json!(vec!["https://approved.example/"; 257]),
        json!(format!("https://approved.example/{}", "x".repeat(4096))),
    ] {
        assert!(!extract(
            &invocation(json!({"url":value})),
            &reviewed,
            &context(dir.path())
        )
        .complete());
    }
}

#[test]
fn ambiguous_url_and_mailbox_forms_are_refused_without_network_io() {
    for url in [
        "https:approved.example",
        "https:///approved.example",
        "https://user:pass@approved.example/",
        "file:///tmp/x",
        "https://approved.example/ a",
        "https://approved.example../",
        "https://approved..example/",
        "https://approved.example\\@outside.example",
    ] {
        assert!(canonical_url(url).is_err(), "accepted {url}");
    }
    assert_eq!(canonical_url("https://[::1]:8443/a").unwrap().1, "::1");
    for recipient in [
        "Name <a@approved.example>",
        "a@approved.example,b@outside.example",
        "a@@approved.example",
        ".a@approved.example",
        "a@approved.example.",
    ] {
        assert!(
            canonical_recipient(recipient).is_err(),
            "accepted {recipient}"
        );
    }
}
