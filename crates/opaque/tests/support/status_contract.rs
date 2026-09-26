//! Read-only status assertions use the parent's private HOME, synthetic service
//! controller and mandatory macOS Keychain-denial sandbox.
use super::*;
use serde_json::{Value, json};

fn status(f: &Fixture) -> Value {
    let output = f.run(&["--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn status_uses_selected_config_without_mutating_service_or_policy() {
    let f = Fixture::new();
    fs::write(f.home.join(".opaque/config.toml"), "invalid = [").unwrap();
    let before = fs::read(&f.config).unwrap();
    let state = status(&f);
    assert_eq!(state["config"], json!({"exists":true,"path":f.config}));
    assert_eq!(
        state["daemon"],
        json!({"reachable":false,"socket_path":f.home.join("broker.sock")})
    );
    assert_eq!(
        state["service"],
        json!({"installed":false,"running":false,"pid":null})
    );
    assert_eq!(state["mcp"], json!({"connected":false,"tool":null}));
    assert_eq!(fs::read(&f.config).unwrap(), before);
    assert!(!f.service.exists());
    assert!(!f.home.join("controller.calls").exists());
}

#[test]
fn first_use_status_describes_setup_without_creating_missing_state() {
    let f = Fixture::new();
    fs::remove_file(&f.config).unwrap();
    let output = f.ok(&[]);
    assert!(output.contains("Get started in 60 seconds"));
    assert!(output.contains("opaque quickstart") && output.contains("Verify everything works"));
    assert_eq!(status(&f)["config"]["exists"], false);
    assert!(!f.config.exists() && !f.service.exists());
}

#[test]
fn status_reports_seal_failure_and_service_state_without_claiming_daemon_liveness() {
    let f = Fixture::new();
    assert!(f.ok(&[]).contains("UNSEALED"));
    f.ok(&["setup", "--seal"]);
    assert!(f.ok(&[]).contains("SEALED"));
    fs::write(&f.config, "require_seal = false\n").unwrap();
    assert!(f.ok(&[]).contains("TAMPERED"));
    fs::remove_file(f.key()).unwrap();
    assert!(f.ok(&[]).contains("KEY MISSING"));
    fs::remove_file(f.seal()).unwrap();
    fs::write(
        f.seal(),
        opaque_core::seal::compute_seal(&fs::read(&f.config).unwrap()),
    )
    .unwrap();
    assert!(f.ok(&[]).contains("SEALED (legacy)"));
    fs::write(f.seal(), "invalid fixture seal").unwrap();
    assert!(f.ok(&[]).contains("TAMPERED"));
    fs::remove_file(f.seal()).unwrap();
    fs::create_dir(f.seal()).unwrap();
    assert!(f.ok(&[]).contains("UNKNOWN"));
    f.ok(&["service", "install"]);
    let running = status(&f);
    assert_eq!(
        running["service"],
        json!({"installed":true,"running":true,"pid":1234})
    );
    assert_eq!(running["daemon"]["reachable"], false);
    let output = f.ok(&[]);
    assert!(
        output.contains("installed but not responding") && output.contains("installed, running")
    );
    f.ok(&["service", "stop"]);
    assert_eq!(status(&f)["service"]["running"], false);
    let output = f.ok(&[]);
    assert!(output.contains("installed, stopped") && output.contains("opaque service start"));
}

#[test]
fn status_detects_each_mcp_configuration_and_handles_unreadable_files() {
    let f = Fixture::new();
    for (file, document, name) in [
        // Claude Code reads user-scope MCP servers from ~/.claude.json, not
        // from ~/.claude/settings.json.
        (
            ".claude.json",
            r#"{"mcpServers":{"opaque":{"command":"opaque-mcp"}}}"#,
            "Claude Code",
        ),
        (
            ".cursor/mcp.json",
            r#"{"mcpServers":{"opaque":{"command":"opaque-mcp"}}}"#,
            "Cursor",
        ),
        (
            ".codex/config.toml",
            "[mcp_servers.opaque]\ncommand = \"opaque-mcp\"\n",
            "Codex",
        ),
    ] {
        let path = f.home.join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "fixture without an integration").unwrap();
        assert_eq!(status(&f)["mcp"]["connected"], false);
        fs::write(&path, document).unwrap();
        assert_eq!(status(&f)["mcp"], json!({"connected":true,"tool":name}));
        assert!(f.ok(&[]).contains(&format!("connected to {name}")));
        assert_eq!(fs::read_to_string(&path).unwrap(), document);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(status(&f)["mcp"], json!({"connected":false,"tool":null}));
    }
}
