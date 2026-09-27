//! `sandbox.exec` through the REAL `opaqued` binary on Linux: the daemon
//! probes the host, picks a sandbox strategy, runs the workload inside it and
//! names the strategy in the audit trail (issues #121 and #123).
//!
//! The expectation is computed from the same probe the daemon runs, so the
//! test is meaningful on every host: where a namespace wrapper exists the
//! exec must succeed under exactly that strategy; where none exists the
//! daemon must refuse before spawning anything, with the reason in the
//! error, and must not claim a sandbox was created.
#![cfg(target_os = "linux")]

#[cfg(coverage)]
#[path = "support/coverage.rs"]
mod coverage;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use opaque_core::audit::{AuditEventKind, AuditFilter, query_audit_db};
use opaque_sandbox::linux::{SandboxCapabilities, SandboxStrategy};
use serde_json::{Value, json};

fn rand_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).unwrap();
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

struct Fixture {
    home: tempfile::TempDir,
    runtime_dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp_base = Path::new("/tmp")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        let runtime_dir = tmp_base.join(format!("oqsbx{}-{}", std::process::id(), rand_hex(4)));
        std::fs::create_dir_all(&runtime_dir).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            // The sandbox bind-mounts the project directory by its real path;
            // keep it under a canonical prefix so the profile and the mount
            // agree (the fixture's HOME is also the profile root).
            home: tempfile::Builder::new()
                .prefix("oqsbx-home")
                .tempdir_in(&tmp_base)
                .unwrap(),
            runtime_dir,
        }
    }

    /// Auto-approved `sandbox.exec` for every client class. The daemon
    /// requires an approval on each sandbox call regardless of the rule; the
    /// insecure backend (config AND env) grants it for the test.
    fn write_config(&self) -> PathBuf {
        let config_path = self.home.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
approval_backend = "insecure_auto_approve"

[[rules]]
name = "allow-e2e-sandbox"
operation_pattern = "sandbox.exec"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "always"
factors = ["local_bio"]
"#,
        )
        .unwrap();
        config_path
    }

    fn write_profile(&self, project_dir: &Path) {
        let profiles = self.home.path().join(".opaque").join("profiles");
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::write(
            profiles.join("e2e.toml"),
            format!(
                r#"
[profile]
name = "e2e"
description = "sandbox_exec_e2e fixture"
project_dir = "{}"
extra_read_paths = []

[network]
allow = []

[limits]
timeout_secs = 60
max_output_bytes = 1048576
"#,
                project_dir.display()
            ),
        )
        .unwrap();
    }

    fn spawn(&self, config_path: &Path) -> Daemon {
        let sock = self.runtime_dir.join("opaque").join("opaqued.sock");
        let token_path = self.runtime_dir.join("opaque").join("daemon.token");
        let log = self.home.path().join(format!("daemon-{}.log", rand_hex(3)));
        let log_file = std::fs::File::create(&log).unwrap();
        let log_stdout = log_file.try_clone().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_opaqued"));
        cmd.env("HOME", self.home.path())
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env("OPAQUE_CONFIG", config_path)
            .env("RUST_LOG", "info")
            .env("OPAQUE_INSECURE_AUTO_APPROVE", "1")
            .env_remove("OPAQUE_SOCK")
            .stdout(Stdio::from(log_stdout))
            .stderr(log_file);
        #[cfg(coverage)]
        coverage::subprocess(&mut cmd, "daemon");
        let child = cmd.spawn().expect("spawn opaqued");

        let mut daemon = Daemon {
            child,
            sock,
            token: String::new(),
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while (!daemon.sock.exists() || !token_path.exists()) && Instant::now() < deadline {
            if let Ok(Some(status)) = daemon.child.try_wait() {
                panic!("daemon exited early ({status}):\n{}", daemon.log());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            daemon.sock.exists() && token_path.exists(),
            "daemon did not come up:\n{}",
            daemon.log()
        );
        daemon.token = std::fs::read_to_string(&token_path)
            .expect("daemon token")
            .trim()
            .to_owned();
        daemon
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
    }
}

struct Daemon {
    child: Child,
    sock: PathBuf,
    token: String,
    log: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// tracing colors its output even when stdout is a file; the assertions
/// below match on `key=value` pairs, which the escapes would split.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

impl Daemon {
    fn log(&self) -> String {
        strip_ansi(&std::fs::read_to_string(&self.log).unwrap_or_default())
    }

    async fn call(&self, method: &str, params: Value) -> Value {
        use futures_util::{SinkExt, StreamExt};
        use tokio_util::codec::{Framed, LengthDelimitedCodec};

        let stream = tokio::net::UnixStream::connect(&self.sock)
            .await
            .unwrap_or_else(|e| panic!("connect: {e}\ndaemon log:\n{}", self.log()));
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
            .new_codec();
        let mut framed = Framed::new(stream, codec);

        let handshake = json!({"handshake": "v1", "daemon_token": self.token});
        framed
            .send(serde_json::to_vec(&handshake).unwrap().into())
            .await
            .expect("send handshake");
        framed
            .send(
                serde_json::to_vec(&json!({"id": 1, "method": method, "params": params}))
                    .unwrap()
                    .into(),
            )
            .await
            .expect("send request");
        match tokio::time::timeout(Duration::from_secs(90), framed.next()).await {
            Ok(Some(Ok(frame))) => serde_json::from_slice(&frame).expect("response json"),
            other => panic!("{method} failed: {other:?}\ndaemon log:\n{}", self.log()),
        }
    }

    fn shutdown(mut self) {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
    }
}

fn audit_details(db: &Path, kind: AuditEventKind) -> Vec<String> {
    query_audit_db(
        db,
        &AuditFilter {
            kind: Some(kind),
            limit: 50,
            ..AuditFilter::default()
        },
    )
    .expect("audit db readable")
    .into_iter()
    .map(|event| {
        format!(
            "outcome={} detail={}",
            event.outcome.unwrap_or_default(),
            event.detail.unwrap_or_default()
        )
    })
    .collect()
}

#[tokio::test]
async fn sandbox_exec_runs_under_the_probed_strategy_and_audits_it() {
    let fixture = Fixture::new();
    let project = fixture.home.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    fixture.write_profile(&project);
    let config_path = fixture.write_config();
    let daemon = fixture.spawn(&config_path);
    let audit_db = fixture.home.path().join(".opaque").join("audit.db");

    // The same probe the daemon ran at startup decides what to expect.
    let caps = SandboxCapabilities::detect();
    let expected = SandboxStrategy::select(&caps);
    let log = daemon.log();
    assert!(
        log.contains("linux sandbox capabilities detected") && log.contains("landlock_evidence="),
        "startup must log the probed capabilities with evidence:\n{log}"
    );

    let response = daemon
        .call(
            "exec",
            json!({
                "profile": "e2e",
                "command": ["/bin/sh", "-c", "echo hello-from-daemon > out.txt; cat out.txt"],
            }),
        )
        .await;

    match expected {
        Ok(strategy) => {
            let name = strategy.name();
            assert!(
                log.contains(&format!("strategy={name}")),
                "startup must log the selected strategy {name}:\n{log}"
            );
            assert!(
                response["error"].is_null(),
                "sandboxed exec must succeed under {name}: {response}\ndaemon log:\n{}",
                daemon.log()
            );
            assert_eq!(
                response["result"]["exit_code"],
                0,
                "{response}\ndaemon log:\n{}",
                daemon.log()
            );
            assert_eq!(response["result"]["stdout_length"], 18, "{response}");
            assert_eq!(
                std::fs::read_to_string(project.join("out.txt"))
                    .expect("workload wrote into the project dir")
                    .trim(),
                "hello-from-daemon"
            );

            let created = audit_details(&audit_db, AuditEventKind::SandboxCreated);
            assert!(
                created.iter().any(|d| d.contains("profile=e2e")
                    && d.contains("argument_count=3")
                    && d.contains(&format!("sandbox={name}"))),
                "sandbox.created must name the strategy {name}: {created:?}"
            );
            let completed = audit_details(&audit_db, AuditEventKind::SandboxCompleted);
            assert!(
                completed.iter().any(|d| d.contains("outcome=success")
                    && d.contains("exit_code=0")
                    && d.contains(&format!("sandbox={name}"))),
                "sandbox.completed must name the strategy {name}: {completed:?}"
            );
        }
        Err(refusal) => {
            let message = response["error"]["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("no sandbox strategy available"),
                "a host without a namespace wrapper must be refused explicitly \
                 (probe said: {refusal}); got {response}\ndaemon log:\n{}",
                daemon.log()
            );
            assert!(
                !project.join("out.txt").exists(),
                "nothing may run when no sandbox strategy exists"
            );
            assert!(
                audit_details(&audit_db, AuditEventKind::SandboxCreated).is_empty(),
                "no sandbox.created event may be recorded for a refused exec"
            );
            assert!(
                !audit_details(&audit_db, AuditEventKind::OperationFailed).is_empty(),
                "the refusal must be audited as operation.failed"
            );
        }
    }

    daemon.shutdown();
}
