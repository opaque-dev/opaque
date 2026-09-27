//! End-to-end check of the Linux sandbox strategies against the real
//! wrappers on this host (issues #121 and #123).
//!
//! `harness = false` because this binary doubles as the sandbox helper:
//! `execute_with_strategy` re-invokes `current_exe()` with `HELPER_ARG`
//! inside bwrap/unshare, exactly as `opaqued` does, and a libtest binary
//! could not take that role. Each wrapper the host can run gets a trivial
//! workload plus proof that Landlock and seccomp landed on the workload and
//! not on the wrapper, which is the failure mode that made every exec die in
//! 0.4.0 and 0.5.0.
//!
//! The binary speaks the libtest command line that `cargo test`, nextest
//! (`--list --format terse`, `<name> --nocapture --exact`) and the coverage
//! collector (`--list`, `--list --ignored`, `--exact <name>`) drive, and
//! prints libtest-shaped results, so it behaves as one test named
//! `linux_sandbox_strategies` everywhere. Diagnostics are buffered and shown
//! only on failure or with `--nocapture`, like captured test output.
//!
//! Strategies the host cannot run are reported as SKIP lines and do not fail
//! the test, unless `OPAQUE_SANDBOX_E2E_REQUIRE` names them (comma
//! separated: `bubblewrap`, `unshare`). The Linux verification containers set
//! it so a skip can never pass silently there.

use std::time::Instant;

/// The single test this binary reports.
const TEST_NAME: &str = "linux_sandbox_strategies";

/// libtest's exit status for a failed test run.
const LIBTEST_FAILURE: i32 = 101;

/// The libtest arguments this harness understands (unknown flags are ignored).
#[derive(Debug, Default)]
struct Invocation {
    list: bool,
    terse: bool,
    ignored: bool,
    nocapture: bool,
    exact: bool,
    filters: Vec<String>,
    skips: Vec<String>,
}

impl Invocation {
    fn parse(args: impl IntoIterator<Item = String>) -> Self {
        let mut inv = Self::default();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--list" => inv.list = true,
                "--ignored" => inv.ignored = true,
                "--exact" => inv.exact = true,
                "--nocapture" | "--no-capture" => inv.nocapture = true,
                "--format" => inv.terse = args.next().as_deref() == Some("terse"),
                "--skip" => inv.skips.extend(args.next()),
                // Flags that take a value we do not use.
                "--test-threads" | "--color" | "--logfile" | "-Z" | "--shuffle-seed" => {
                    args.next();
                }
                _ if arg.starts_with("--format=") => {
                    inv.terse = arg.ends_with("=terse");
                }
                _ if arg.starts_with("--skip=") => {
                    inv.skips.push(arg["--skip=".len()..].to_owned());
                }
                _ if arg.starts_with('-') => {}
                _ => inv.filters.push(arg),
            }
        }
        inv
    }

    /// Whether the libtest filters select our one test.
    fn selects(&self) -> bool {
        let matches = |pattern: &String| {
            if self.exact {
                pattern == TEST_NAME
            } else {
                TEST_NAME.contains(pattern.as_str())
            }
        };
        (self.filters.is_empty() || self.filters.iter().any(matches))
            && !self.skips.iter().any(matches)
    }
}

fn print_inventory(inv: &Invocation) {
    // Nothing is ignored, so `--ignored` lists an empty set.
    let count = usize::from(!inv.ignored);
    if count == 1 {
        println!("{TEST_NAME}: test");
    }
    if !inv.terse {
        println!();
        println!(
            "{count} {}, 0 benchmarks",
            if count == 1 { "test" } else { "tests" }
        );
    }
}

fn print_summary(ok: bool, ran: usize, filtered_out: usize, elapsed: f64) {
    println!();
    println!(
        "test result: {}. {} passed; {} failed; 0 ignored; 0 measured; {filtered_out} filtered out; finished in {elapsed:.2}s",
        if ok { "ok" } else { "FAILED" },
        usize::from(ok) * ran,
        usize::from(!ok) * ran,
    );
    println!();
}

fn main() {
    #[cfg(target_os = "linux")]
    opaque_sandbox::linux::maybe_run_helper();

    let inv = Invocation::parse(std::env::args().skip(1));
    if inv.list {
        print_inventory(&inv);
        return;
    }
    if !inv.selects() {
        println!();
        println!("running 0 tests");
        print_summary(true, 0, 1, 0.0);
        return;
    }

    println!();
    println!("running 1 test");
    let start = Instant::now();
    let mut report = String::new();
    let ok = run_checks(&mut report);
    if ok {
        println!("test {TEST_NAME} ... ok");
        if inv.nocapture {
            eprint!("{report}");
        }
    } else {
        println!("test {TEST_NAME} ... FAILED");
        println!();
        println!("failures:");
        println!();
        println!("---- {TEST_NAME} stdout ----");
        print!("{report}");
        println!();
        println!("failures:");
        println!("    {TEST_NAME}");
    }
    print_summary(ok, 1, 0, start.elapsed().as_secs_f64());
    if !ok {
        std::process::exit(LIBTEST_FAILURE);
    }
}

#[cfg(not(target_os = "linux"))]
fn run_checks(report: &mut String) -> bool {
    report.push_str("not a Linux host, nothing to verify\n");
    true
}

#[cfg(target_os = "linux")]
fn run_checks(report: &mut String) -> bool {
    linux::run(report)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::fmt::Write as _;
    use std::path::Path;

    use opaque_core::proto::{ExecFrame, ExecStream};
    use opaque_sandbox::linux::{
        LinuxSandboxConfig, NamespaceWrapper, SandboxCapabilities, SandboxError, SandboxStrategy,
        execute_with_strategy,
    };

    struct Outcome {
        result: Result<i32, SandboxError>,
        stdout: String,
        stderr: String,
        started: bool,
        completed: Option<i32>,
    }

    impl Outcome {
        fn describe(&self) -> String {
            format!(
                "result={:?} started={} completed={:?} stdout={:?} stderr={:?}",
                self.result.as_ref().map_err(|e| e.to_string()),
                self.started,
                self.completed,
                self.stdout,
                self.stderr
            )
        }
    }

    async fn run_workload(
        strategy: &SandboxStrategy,
        project: &Path,
        extra_read_paths: Vec<std::path::PathBuf>,
        network_allow: Vec<String>,
        env: HashMap<String, String>,
        command: &[&str],
    ) -> Outcome {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let config = LinuxSandboxConfig {
            command: command.iter().map(|s| s.to_string()).collect(),
            env,
            project_dir: project.to_path_buf(),
            extra_read_paths,
            network_allow,
            timeout_secs: 30,
            max_output_bytes: 1 << 20,
        };
        let result = execute_with_strategy(config, strategy, tx).await;
        let mut outcome = Outcome {
            result,
            stdout: String::new(),
            stderr: String::new(),
            started: false,
            completed: None,
        };
        while let Ok(frame) = rx.try_recv() {
            match frame {
                ExecFrame::ExecStarted { .. } => outcome.started = true,
                ExecFrame::Output {
                    stream: ExecStream::Stdout,
                    data,
                } => outcome.stdout.push_str(&data),
                ExecFrame::Output {
                    stream: ExecStream::Stderr,
                    data,
                } => outcome.stderr.push_str(&data),
                ExecFrame::ExecCompleted { exit_code, .. } => outcome.completed = Some(exit_code),
            }
        }
        outcome
    }

    /// Collects check results into the buffered report.
    struct Report<'a> {
        out: &'a mut String,
        failures: usize,
        exercised: usize,
    }

    impl Report<'_> {
        fn line(&mut self, text: &str) {
            let _ = writeln!(self.out, "{text}");
        }

        fn check(&mut self, label: &str, ok: bool, detail: &str) {
            if ok {
                self.line(&format!("  ok    {label}"));
            } else {
                self.failures += 1;
                self.line(&format!("  FAIL  {label}: {detail}"));
            }
        }
    }

    async fn exercise(strategy: &SandboxStrategy, report: &mut Report<'_>) {
        let name = strategy.name();
        report.line(&format!("== strategy {name}"));
        report.exercised += 1;
        let project = tempfile::tempdir().expect("tempdir");
        let project_path = project
            .path()
            .canonicalize()
            .expect("canonical project dir");

        // 1. A trivial workload runs, and the frames say so.
        let hello = run_workload(
            strategy,
            &project_path,
            vec![],
            vec![],
            HashMap::new(),
            &["sh", "-c", "echo hello-from-sandbox"],
        )
        .await;
        report.check(
            &format!("{name}: trivial workload exits 0 with its output streamed"),
            matches!(hello.result, Ok(0))
                && hello.started
                && hello.completed == Some(0)
                && hello.stdout.contains("hello-from-sandbox"),
            &hello.describe(),
        );

        // 2. The workload's exit code is the one reported.
        let three = run_workload(
            strategy,
            &project_path,
            vec![],
            vec![],
            HashMap::new(),
            &["sh", "-c", "exit 3"],
        )
        .await;
        report.check(
            &format!("{name}: workload exit code propagates"),
            matches!(three.result, Ok(3)) && three.completed == Some(3),
            &three.describe(),
        );

        // 3. Profile environment reaches the workload through wrapper and helper.
        let env = HashMap::from([("E2E_MARKER".to_string(), "marker-4711".to_string())]);
        let marker = run_workload(
            strategy,
            &project_path,
            vec![],
            vec![],
            env,
            &["sh", "-c", "echo $E2E_MARKER; echo $OPAQUE_SOCK"],
        )
        .await;
        report.check(
            &format!("{name}: profile env injected, OPAQUE_SOCK absent"),
            matches!(marker.result, Ok(0))
                && marker.stdout.contains("marker-4711")
                && !marker.stdout.contains("opaque"),
            &marker.describe(),
        );

        // 4. The project directory is writable and is the working directory.
        let write = run_workload(
            strategy,
            &project_path,
            vec![],
            vec![],
            HashMap::new(),
            &["sh", "-c", "echo fine > ok.txt"],
        )
        .await;
        let written = std::fs::read_to_string(project_path.join("ok.txt")).unwrap_or_default();
        report.check(
            &format!("{name}: project dir is the writable working directory"),
            matches!(write.result, Ok(0)) && written.trim() == "fine",
            &format!("written={written:?} {}", write.describe()),
        );

        // 5. Landlock is on the workload, proven by a location that the mount
        //    layer and DAC leave writable but the Landlock ruleset does not:
        //    a new file directly under /dev (bwrap's own devtmpfs, or the
        //    host's when this test runs as root) and the invoking user's real
        //    home directory (writable as the mapped root under unshare). The
        //    same probe under the same wrapper WITHOUT Landlock must succeed,
        //    so the denial can only have come from Landlock. Device nodes and
        //    reads keep working under the ruleset.
        if strategy.landlock {
            let host_home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
            let probe_env = HashMap::from([("E2E_HOST_HOME".to_string(), host_home.clone())]);
            let probe_script = "for target in /dev/opaque-e2e-$$ \"$E2E_HOST_HOME/opaque-e2e-$$\"; do \
                 if echo x > \"$target\" 2>/dev/null; then rm -f \"$target\"; exit 9; fi; done; \
                 cat /etc/hostname > /dev/null || exit 8; \
                 echo devnull > /dev/null || exit 8; \
                 exit 0";
            let restricted = run_workload(
                strategy,
                &project_path,
                vec![],
                vec![],
                probe_env.clone(),
                &["sh", "-c", probe_script],
            )
            .await;
            report.check(
                &format!(
                    "{name}: landlock denies writes outside the writable set while /dev/null and reads work"
                ),
                matches!(restricted.result, Ok(0)),
                &restricted.describe(),
            );
            let control_strategy = SandboxStrategy {
                landlock: false,
                ..strategy.clone()
            };
            let control = run_workload(
                &control_strategy,
                &project_path,
                vec![],
                vec![],
                probe_env,
                &["sh", "-c", probe_script],
            )
            .await;
            report.check(
                &format!(
                    "{name}: control run without landlock ({}) can write there, so the denial was landlock",
                    control_strategy.name()
                ),
                matches!(control.result, Ok(9)),
                &format!("host_home={host_home} {}", control.describe()),
            );
        }

        // 6. seccomp is on the workload: connect(2) fails with EPERM, not with
        //    the network namespace's ENETUNREACH/ECONNREFUSED.
        if strategy.seccomp {
            if Path::new("/bin/bash").exists() || Path::new("/usr/bin/bash").exists() {
                let connect = run_workload(
                    strategy,
                    &project_path,
                    vec![],
                    vec![],
                    HashMap::new(),
                    &["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/1"],
                )
                .await;
                report.check(
                    &format!("{name}: seccomp denies connect(2) with EPERM"),
                    connect.stderr.to_lowercase().contains("not permitted"),
                    &connect.describe(),
                );
            } else {
                report.line(&format!(
                    "  SKIP  {name}: seccomp connect probe needs bash inside the sandbox"
                ));
            }
        }

        // 7. A wrapper that dies before the workload is an explicit error
        //    carrying the wrapper's own diagnostic, never a fake exit code.
        if strategy.wrapper == NamespaceWrapper::Bubblewrap {
            let missing = project_path.join("does-not-exist");
            let broken = run_workload(
                strategy,
                &project_path,
                vec![missing],
                vec![],
                HashMap::new(),
                &["sh", "-c", "echo should-not-run"],
            )
            .await;
            let message = broken
                .result
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            report.check(
                &format!(
                    "{name}: wrapper failure surfaces as SandboxError::Wrapper with bwrap's stderr"
                ),
                matches!(broken.result, Err(SandboxError::Wrapper(_)))
                    && message.contains("does-not-exist")
                    && !broken.started
                    && broken.stdout.is_empty(),
                &format!("message={message:?} {}", broken.describe()),
            );
        }
    }

    fn required() -> Vec<String> {
        std::env::var("OPAQUE_SANDBOX_E2E_REQUIRE")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Run every check the host allows, appending the report to `out`.
    /// Returns whether all checks passed.
    pub fn run(out: &mut String) -> bool {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let caps = SandboxCapabilities::detect();
        let mut report = Report {
            out,
            failures: 0,
            exercised: 0,
        };
        report.line(&format!(
            "host: kernel={} bubblewrap={} ({}) landlock={} ({}) seccomp={} user_namespaces={} ({})",
            std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap_or_default()
                .trim(),
            caps.bubblewrap,
            caps.bubblewrap_evidence,
            caps.landlock,
            caps.landlock_evidence,
            caps.seccomp,
            caps.user_namespaces,
            caps.user_namespaces_evidence
        ));
        let required = required();

        for (wrapper, key, available, why) in [
            (
                NamespaceWrapper::Bubblewrap,
                "bubblewrap",
                caps.bubblewrap,
                caps.bubblewrap_evidence.as_str(),
            ),
            (
                NamespaceWrapper::Unshare,
                "unshare",
                caps.user_namespaces,
                caps.user_namespaces_evidence.as_str(),
            ),
        ] {
            if !available {
                if required.iter().any(|r| r == key) {
                    report.failures += 1;
                    report.line(&format!(
                        "FAIL  {key}: required by OPAQUE_SANDBOX_E2E_REQUIRE but {why}"
                    ));
                } else {
                    report.line(&format!("SKIP  {key}: {why}"));
                }
                continue;
            }
            let strategy = SandboxStrategy {
                wrapper,
                landlock: caps.landlock,
                seccomp: caps.seccomp,
            };
            runtime.block_on(exercise(&strategy, &mut report));
        }

        // Selection must refuse a host with no wrapper at all, before spawning.
        let none = SandboxCapabilities {
            bubblewrap: false,
            bubblewrap_evidence: "bwrap is not on PATH".into(),
            landlock: caps.landlock,
            landlock_evidence: caps.landlock_evidence.clone(),
            seccomp: caps.seccomp,
            user_namespaces: false,
            user_namespaces_evidence: "unshare probe exit status: 1: unshare failed".into(),
        };
        let refused = SandboxStrategy::select(&none);
        report.check(
            "no namespace wrapper: strategy selection fails closed",
            matches!(refused, Err(SandboxError::Setup(_))),
            &format!("{refused:?}"),
        );

        if report.exercised == 0 {
            report.line("no sandbox strategy could be exercised on this host");
        }
        let (failures, exercised) = (report.failures, report.exercised);
        if failures > 0 {
            report.line(&format!("linux_sandbox_e2e: {failures} check(s) FAILED"));
            return false;
        }
        report.line(&format!(
            "linux_sandbox_e2e: all checks passed across {exercised} strateg{}",
            if exercised == 1 { "y" } else { "ies" }
        ));
        true
    }
}
