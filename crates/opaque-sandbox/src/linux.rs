//! Linux sandbox using layered isolation: Bubblewrap + Landlock + seccomp-BPF.
//!
//! Creates a hardened sandbox via a layered strategy (strongest available first):
//!
//! 1. **Bubblewrap** (`bwrap`): mount namespace isolation with read-only root,
//!    writable project dir, tmpfs, PID/net namespace, die-with-parent.
//! 2. **Landlock**: kernel-level filesystem access control (kernel 5.13+).
//!    Read-only globally, read-write for project dir and temp, deny sensitive dirs.
//! 3. **seccomp-BPF**: syscall filtering. Blocks network syscalls when no network
//!    is allowed, always blocks ptrace and io_uring.
//! 4. **unshare**: fallback namespace isolation via `unshare(1)`.
//!
//! The layers compose, and the order in which they are applied is load-bearing.
//! The daemon spawns the namespace wrapper (bwrap or unshare) *unrestricted*
//! so the wrapper can finish its own setup: loopback configuration, uid maps,
//! mounts. The wrapper's target is not the user's command but the daemon
//! binary re-invoked as the sandbox helper ([`HELPER_ARG`]). The helper runs
//! inside the new namespaces, installs NO_NEW_PRIVS + Landlock + seccomp on
//! itself, reports readiness on an inherited pipe, and only then execs the
//! workload. Every restriction is inherited across exec, so the workload and
//! all of its descendants stay confined while the wrapper never was.
//! Restricting the wrapper itself was the cause of issue #123: seccomp denied
//! bwrap's netlink bind, Landlock denied unshare's uid_map write, and every
//! exec failed closed on every Landlock-capable kernel.
//!
//! Detection is evidence-based (issue #121). Landlock counts as available only
//! when the kernel answers the `landlock_create_ruleset` ABI probe; the LSM
//! list from securityfs is recorded next to that answer. A layer the kernel
//! lacks is dropped explicitly and the strategy actually used is named in the
//! `sandbox.created` and `sandbox.completed` audit events. When no namespace
//! wrapper can run at all, execution fails closed before anything is spawned.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tracing::{info, warn};

use opaque_core::proto::{ExecFrame, ExecStream};

/// Maximum output chunk size sent per frame (16 KB).
const OUTPUT_CHUNK_SIZE: usize = 16 * 1024;

/// Paths that must never be accessible inside the sandbox.
const PROTECTED_DIRS: &[&str] = &[".opaque", ".ssh", ".gnupg"];

/// First argument that turns the daemon binary into the sandbox helper.
///
/// The binary embedding [`execute`] must call [`maybe_run_helper`] before it
/// does anything else in `main`; `opaqued` does.
pub const HELPER_ARG: &str = "__opaque-sandbox-helper";

/// Exit status of the helper when it could not restrict the workload. The
/// workload never ran. Distinct from 126/127, which mirror the shell's
/// "cannot execute" and "not found".
pub const HELPER_EXIT_RESTRICT_FAILED: i32 = 125;
const HELPER_EXIT_CANNOT_EXEC: i32 = 126;
const HELPER_EXIT_NOT_FOUND: i32 = 127;

/// File descriptor the helper reports readiness on. It is dup2'd onto the
/// wrapper in `pre_exec` without CLOEXEC, inherited through bwrap/unshare,
/// and closed by the helper before the workload execs.
const READY_FD: libc::c_int = 3;
const READY_TOKEN: &[u8] = b"ok\n";

/// Active LSM list exported by securityfs. Absent inside most containers.
const LSM_LIST_PATH: &str = "/sys/kernel/security/lsm";

/// `landlock_create_ruleset(2)` shares number 444 on every architecture.
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

/// Errors from sandbox execution.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox setup failed: {0}")]
    Setup(String),

    #[error("child process failed to spawn: {0}")]
    Spawn(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sandbox wrapper failed before the workload started: {0}")]
    Wrapper(String),
}

/// Configuration for a Linux sandbox execution.
pub struct LinuxSandboxConfig {
    /// Command to execute (first element is the binary).
    pub command: Vec<String>,
    /// Environment variables to inject (secrets + literal env).
    pub env: HashMap<String, String>,
    /// Project directory (bind-mounted writable).
    pub project_dir: PathBuf,
    /// Extra paths to bind-mount read-only.
    pub extra_read_paths: Vec<PathBuf>,
    /// Network host:port entries to allow (empty = no network).
    pub network_allow: Vec<String>,
    /// Timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum output bytes to capture.
    pub max_output_bytes: usize,
}

// ---------------------------------------------------------------------------
// Sandbox capabilities probing
// ---------------------------------------------------------------------------

/// Evidence behind the Landlock decision.
///
/// Both sources are kernel facts, not library behaviour: the ABI probe is the
/// raw `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`
/// call (EOPNOTSUPP when the LSM is built but not enabled at boot, ENOSYS
/// when the kernel predates it or a seccomp filter hides it), and the LSM
/// list is what securityfs reports when it is mounted at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockProbe {
    /// Trimmed contents of `/sys/kernel/security/lsm`, when readable.
    pub lsm_list: Option<String>,
    /// Highest Landlock ABI the kernel supports, or the probe's errno.
    pub abi: Result<u32, i32>,
}

impl LandlockProbe {
    /// Probe the running kernel.
    pub fn run() -> Self {
        Self::from_parts(
            std::fs::read_to_string(LSM_LIST_PATH).ok(),
            probe_landlock_abi(),
        )
    }

    /// Assemble a probe from already-collected evidence (tests, logging).
    pub fn from_parts(lsm_list: Option<String>, abi: Result<u32, i32>) -> Self {
        Self {
            lsm_list: lsm_list.map(|list| list.trim().to_owned()),
            abi,
        }
    }

    /// `Some(true)` when securityfs lists `landlock`, `Some(false)` when the
    /// list is readable and omits it, `None` when securityfs is unreadable.
    pub fn lsm_lists_landlock(&self) -> Option<bool> {
        self.lsm_list.as_deref().map(lsm_list_names_landlock)
    }

    /// Landlock is usable exactly when the kernel accepted the ABI probe. A
    /// securityfs list that disagrees is logged, never trusted over the
    /// syscall: if the kernel later refuses to enforce, the helper fails
    /// closed instead of running the workload unconfined.
    pub fn available(&self) -> bool {
        self.abi.is_ok()
    }

    /// The probe's two answers disagree (only possible with a broken
    /// securityfs or a syscall filter that fakes a success).
    pub fn contradictory(&self) -> bool {
        self.abi.is_ok() && self.lsm_lists_landlock() == Some(false)
    }

    /// One-line evidence string for logs and audit details.
    pub fn evidence(&self) -> String {
        let lsm = match self.lsm_lists_landlock() {
            Some(true) => "lsm=landlock-listed",
            Some(false) => "lsm=landlock-not-listed",
            None => "lsm=securityfs-unreadable",
        };
        match self.abi {
            Ok(abi) if self.contradictory() => {
                format!("{lsm} abi=v{abi} (securityfs disagrees; the syscall probe wins)")
            }
            Ok(abi) => format!("{lsm} abi=v{abi}"),
            Err(errno) => format!("{lsm} abi-probe={}", describe_errno(errno)),
        }
    }
}

/// Whether a comma-separated LSM list (the securityfs format) names Landlock.
pub fn lsm_list_names_landlock(list: &str) -> bool {
    list.split(',').any(|name| name.trim() == "landlock")
}

fn probe_landlock_abi() -> Result<u32, i32> {
    // SAFETY: a NULL attr with size 0 and the VERSION flag is the documented
    // ABI query; it touches no memory and creates nothing.
    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(rc as u32)
    }
}

fn describe_errno(errno: i32) -> String {
    match errno {
        libc::EOPNOTSUPP => "EOPNOTSUPP (LSM built but not enabled at boot)".into(),
        libc::ENOSYS => "ENOSYS (kernel too old or syscall filtered)".into(),
        libc::EPERM => "EPERM (syscall denied by a seccomp filter)".into(),
        other => format!("errno {other}"),
    }
}

/// Describes which sandbox mechanisms are available on this host.
#[derive(Debug, Clone)]
pub struct SandboxCapabilities {
    /// `bwrap` binary found on PATH.
    pub bubblewrap: bool,
    /// Kernel enforces Landlock (ABI probe answered).
    pub landlock: bool,
    /// Evidence behind `landlock`, see [`LandlockProbe::evidence`].
    pub landlock_evidence: String,
    /// seccomp-bpf available.
    pub seccomp: bool,
    /// Unprivileged user namespaces enabled.
    pub user_namespaces: bool,
}

impl SandboxCapabilities {
    /// Probe the current host for available sandbox mechanisms.
    pub fn detect() -> Self {
        let probe = LandlockProbe::run();
        if probe.contradictory() {
            warn!(
                evidence = %probe.evidence(),
                "landlock: securityfs does not list the LSM but the kernel answers the ABI probe"
            );
        }
        Self {
            bubblewrap: detect_bubblewrap(),
            landlock: probe.available(),
            landlock_evidence: probe.evidence(),
            seccomp: detect_seccomp(),
            user_namespaces: detect_user_namespaces(),
        }
    }

    /// Log the detected capabilities at info level.
    pub fn log_capabilities(&self) {
        info!(
            bubblewrap = self.bubblewrap,
            landlock = self.landlock,
            landlock_evidence = %self.landlock_evidence,
            seccomp = self.seccomp,
            user_namespaces = self.user_namespaces,
            "linux sandbox capabilities detected"
        );
    }
}

/// Probe once at daemon startup and log what `sandbox.exec` will do on this
/// host, so a missing layer or an unusable host is visible before the first
/// exec instead of surfacing as an unexplained failure.
pub fn log_startup_capabilities() -> SandboxCapabilities {
    let caps = SandboxCapabilities::detect();
    caps.log_capabilities();
    match SandboxStrategy::select(&caps) {
        Ok(strategy) => info!(
            strategy = %strategy.name(),
            "linux sandbox strategy selected for sandbox.exec"
        ),
        Err(error) => warn!(%error, "sandbox.exec will fail closed on this host"),
    }
    caps
}

/// Check if `bwrap` is available on PATH.
fn detect_bubblewrap() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Check if seccomp-bpf is available. On any remotely modern Linux (3.5+) it is.
fn detect_seccomp() -> bool {
    // seccomp is available on Linux >= 3.5 and is essentially universal.
    // We check via prctl(PR_GET_SECCOMP) which returns the current mode.
    // A return of 0 means seccomp is available but not yet engaged.
    let result = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
    // Returns 0 (disabled), 1 (strict), 2 (filter), or -1 on error.
    // Any non-negative value means seccomp is supported.
    result >= 0
}

/// Check if unprivileged user namespaces are enabled.
fn detect_user_namespaces() -> bool {
    std::process::Command::new("unshare")
        .args(["--user", "--", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Strategy selection
// ---------------------------------------------------------------------------

/// The namespace wrapper that provides mount/PID/network isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceWrapper {
    /// `bwrap`: read-only root, tmpfs masks, fresh /proc and /dev.
    Bubblewrap,
    /// `unshare --user --mount --pid --fork --map-root-user [--net]`.
    Unshare,
}

impl NamespaceWrapper {
    /// The program spawned by the daemon.
    pub fn program(self) -> &'static str {
        match self {
            Self::Bubblewrap => "bwrap",
            Self::Unshare => "unshare",
        }
    }
}

/// The layers a `sandbox.exec` will actually run with on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxStrategy {
    pub wrapper: NamespaceWrapper,
    pub landlock: bool,
    pub seccomp: bool,
}

impl SandboxStrategy {
    /// Pick the strongest strategy the detected capabilities support.
    ///
    /// Missing kernel layers fail over explicitly (logged at warn level and
    /// visible in [`SandboxStrategy::name`]). No usable namespace wrapper is
    /// an error: nothing is spawned, and the caller sees why.
    pub fn select(caps: &SandboxCapabilities) -> Result<Self, SandboxError> {
        let wrapper = if caps.bubblewrap {
            NamespaceWrapper::Bubblewrap
        } else if caps.user_namespaces {
            NamespaceWrapper::Unshare
        } else {
            return Err(SandboxError::Setup(format!(
                "no sandbox strategy available: bwrap is not on PATH and unprivileged user \
                 namespaces are unavailable (`unshare --user` failed); install bubblewrap or \
                 enable unprivileged user namespaces (Ubuntu 24.04: \
                 sysctl kernel.apparmor_restrict_unprivileged_userns=0); landlock: {}",
                caps.landlock_evidence
            )));
        };
        if !caps.landlock {
            warn!(
                wrapper = wrapper.program(),
                evidence = %caps.landlock_evidence,
                "landlock unavailable on this kernel; failing over to namespace isolation without the filesystem layer"
            );
        }
        if !caps.seccomp {
            warn!(
                wrapper = wrapper.program(),
                "seccomp unavailable on this kernel; failing over without the syscall filter"
            );
        }
        Ok(Self {
            wrapper,
            landlock: caps.landlock,
            seccomp: caps.seccomp,
        })
    }

    /// Stable name for logs and audit details, e.g. `bubblewrap+landlock+seccomp`.
    pub fn name(&self) -> String {
        let mut name = String::from(match self.wrapper {
            NamespaceWrapper::Bubblewrap => "bubblewrap",
            NamespaceWrapper::Unshare => "unshare",
        });
        if self.landlock {
            name.push_str("+landlock");
        }
        if self.seccomp {
            name.push_str("+seccomp");
        }
        name
    }
}

// ---------------------------------------------------------------------------
// Landlock filesystem restriction
// ---------------------------------------------------------------------------

/// Build the list of protected paths that must never be readable.
fn protected_paths() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PROTECTED_DIRS
        .iter()
        .map(|dir| PathBuf::from(&home).join(dir))
        .collect()
}

/// Build the Landlock ruleset for the workload.
///
/// - Global read-only access to `/`
/// - Read-write access to: project_dir, /tmp, /var/tmp, /dev/shm
/// - Read/write on existing device nodes under `/dev` (no file creation), so
///   `/dev/null`, `/dev/zero`, `/dev/tty` and pseudo-terminals keep working
/// - Protected directories (~/.opaque, ~/.ssh, ~/.gnupg) get no extra grant;
///   the bubblewrap layer additionally masks them with tmpfs.
///
/// The helper builds this inside the wrapper's mount namespace, so the
/// path rules resolve against the view the workload will actually see (the
/// bwrap tmpfs at /tmp, the bind-mounted project directory).
pub fn build_landlock_ruleset(
    project_dir: &Path,
    extra_read_paths: &[PathBuf],
) -> Result<landlock::RulesetCreated, String> {
    use landlock::{
        ABI, Access, AccessFs, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr,
    };

    let read_access = AccessFs::from_read(ABI::V3);
    let readwrite_access = AccessFs::from_all(ABI::V3);
    // Existing device nodes only: no MakeReg/MakeDir/Remove* under /dev.
    let device_access =
        AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::WriteFile | AccessFs::Truncate;

    // Base ABI is a HARD requirement: on a kernel without Landlock this
    // errors instead of silently building a no-op ruleset (BestEffort's
    // failure mode); the caller treats that as fail-closed. Newer ABI
    // features degrade best-effort on older Landlock kernels.
    let ruleset = Ruleset::default()
        .set_compatibility(landlock::CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .map_err(|e| format!("landlock base ABI unavailable: {e}"))?
        .set_compatibility(landlock::CompatLevel::BestEffort)
        .handle_access(readwrite_access)
        .map_err(|e| format!("landlock handle_access: {e}"))?;

    let mut created = ruleset
        .create()
        .map_err(|e| format!("landlock ruleset creation: {e}"))?;

    // Helper: add a rule if the path exists.
    let mut add_rule = |path: &Path, access| {
        if let Ok(fd) = PathFd::new(path) {
            let rule = PathBeneath::new(fd, access);
            if let Err(e) = (&mut created).add_rule(rule) {
                warn!("landlock: failed to add rule for {}: {e}", path.display());
            }
        }
    };

    // Global read-only access.
    add_rule(Path::new("/"), read_access);

    // Read-write access for writable directories.
    add_rule(project_dir, readwrite_access);
    add_rule(Path::new("/tmp"), readwrite_access);
    add_rule(Path::new("/var/tmp"), readwrite_access);

    // Device nodes stay usable; POSIX shared memory is scratch space like /tmp.
    add_rule(Path::new("/dev"), device_access);
    add_rule(Path::new("/dev/shm"), readwrite_access);

    // Extra read paths.
    for path in extra_read_paths {
        add_rule(path, read_access);
    }

    // Note: Landlock has no explicit "deny" primitive for sub-paths of an
    // allowed tree. Protected dirs are blocked from WRITES because they are
    // not in the writable set; the bubblewrap tmpfs mask is what hides their
    // contents from reads.

    Ok(created)
}

/// Build a Landlock ruleset configuration for inspection (used in tests).
///
/// Returns the list of (path, writable) pairs that would be configured.
#[allow(dead_code)]
pub fn landlock_ruleset_paths(
    project_dir: &Path,
    extra_read_paths: &[PathBuf],
) -> Vec<(PathBuf, bool)> {
    let mut paths = vec![
        // Global read-only.
        (PathBuf::from("/"), false),
        // Writable paths.
        (project_dir.to_path_buf(), true),
        (PathBuf::from("/tmp"), true),
        (PathBuf::from("/var/tmp"), true),
        (PathBuf::from("/dev/shm"), true),
        // Device nodes: read/write on existing nodes, no file creation.
        (PathBuf::from("/dev"), false),
    ];

    // Extra read paths.
    for p in extra_read_paths {
        paths.push((p.clone(), false));
    }

    paths
}

// ---------------------------------------------------------------------------
// seccomp-BPF syscall filtering
// ---------------------------------------------------------------------------

/// Compile the seccomp-BPF program for the workload.
///
/// When `network_blocked` is true, blocks network syscalls (connect, bind,
/// listen, accept, accept4, sendto, sendmsg, sendmmsg) with EPERM.
/// Always blocks ptrace and io_uring syscalls.
pub fn build_seccomp_program(network_blocked: bool) -> Result<seccompiler::BpfProgram, String> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
    use std::collections::BTreeMap;

    let default_action = SeccompAction::Allow;
    let block_action = SeccompAction::Errno(libc::EPERM as u32);

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Always block ptrace (sandbox escape via debugging).
    rules.insert(libc::SYS_ptrace, vec![]);

    // Always block io_uring (bypass vector).
    rules.insert(libc::SYS_io_uring_setup, vec![]);
    rules.insert(libc::SYS_io_uring_enter, vec![]);
    rules.insert(libc::SYS_io_uring_register, vec![]);

    // Block network syscalls when network is not allowed.
    if network_blocked {
        // Block these unconditionally (we can't filter by AF_* easily with
        // seccompiler's API, and the namespace already provides AF_UNIX isolation
        // when using bwrap/unshare --net). These are blocked to add defense-in-depth.
        let network_syscalls = [
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
            libc::SYS_sendmmsg,
        ];
        for syscall in network_syscalls {
            rules.insert(syscall, vec![]);
        }
    }

    let target_arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| format!("unsupported seccomp arch {}: {e}", std::env::consts::ARCH))?;

    let filter = SeccompFilter::new(rules, default_action, block_action, target_arch)
        .map_err(|e| format!("seccomp filter construction: {e}"))?;

    let bpf: BpfProgram = filter
        .try_into()
        .map_err(|e| format!("seccomp BPF compilation: {e}"))?;
    Ok(bpf)
}

/// Build a list of syscalls that would be blocked for the given configuration.
/// Used in tests to verify filter construction without actually applying it.
#[allow(dead_code)]
pub fn seccomp_blocked_syscalls(network_blocked: bool) -> Vec<i64> {
    let mut blocked = vec![
        libc::SYS_ptrace,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ];

    if network_blocked {
        blocked.extend_from_slice(&[
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
            libc::SYS_sendmmsg,
        ]);
    }

    blocked
}

// ---------------------------------------------------------------------------
// Restriction layers (built and applied by the helper, inside the namespaces)
// ---------------------------------------------------------------------------

/// Restriction layers built for the workload. Both inherit across exec and
/// into every descendant.
#[derive(Debug)]
pub struct PreparedRestrictions {
    landlock: Option<landlock::RulesetCreated>,
    seccomp: Option<seccompiler::BpfProgram>,
}

impl PreparedRestrictions {
    /// Build exactly the layers the strategy asked for.
    ///
    /// FAIL CLOSED: a requested layer that cannot be built is an error, never
    /// a silent skip. Layers the strategy left out were already declared
    /// absent by detection and named in the audit trail.
    pub fn prepare(
        landlock: bool,
        seccomp: bool,
        project_dir: &Path,
        extra_read_paths: &[PathBuf],
        network_blocked: bool,
    ) -> Result<Self, SandboxError> {
        let landlock = if landlock {
            Some(
                build_landlock_ruleset(project_dir, extra_read_paths).map_err(|e| {
                    SandboxError::Setup(format!("landlock requested but unusable: {e}"))
                })?,
            )
        } else {
            None
        };

        let seccomp =
            if seccomp {
                Some(build_seccomp_program(network_blocked).map_err(|e| {
                    SandboxError::Setup(format!("seccomp requested but unusable: {e}"))
                })?)
            } else {
                None
            };

        Ok(PreparedRestrictions { landlock, seccomp })
    }

    pub fn landlock_prepared(&self) -> bool {
        self.landlock.is_some()
    }

    pub fn seccomp_prepared(&self) -> bool {
        self.seccomp.is_some()
    }

    /// Restrict the calling process: NO_NEW_PRIVS, then the Landlock ruleset,
    /// then the seccomp filter. Any failure is an error; a workload that
    /// cannot be restricted never runs.
    pub fn apply(self) -> std::io::Result<()> {
        use landlock::RulesetCreatedAttr;

        // NO_NEW_PRIVS: required for unprivileged seccomp, sound for
        // Landlock, and independently the right property for a sandbox
        // child (no setuid re-escalation).
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }

        if let Some(ruleset) = self.landlock {
            let status = ruleset
                .no_new_privs(false) // already set above
                .restrict_self()
                .map_err(|e| std::io::Error::other(format!("landlock restrict: {e}")))?;
            if matches!(status.ruleset, landlock::RulesetStatus::NotEnforced) {
                return Err(std::io::Error::other(
                    "landlock restrict returned NOT ENFORCED; refusing to run the workload",
                ));
            }
        }

        if let Some(bpf) = &self.seccomp {
            seccompiler::apply_filter(bpf)
                .map_err(|e| std::io::Error::other(format!("seccomp apply: {e}")))?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sandbox helper: the wrapper's target, restricts itself then execs the workload
// ---------------------------------------------------------------------------

/// What the daemon asks the helper to do, encoded as argv after [`HELPER_ARG`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperRequest {
    pub project_dir: PathBuf,
    pub extra_read_paths: Vec<PathBuf>,
    pub network_blocked: bool,
    pub landlock: bool,
    pub seccomp: bool,
    /// Inherited fd to write the readiness token on once restricted, then close.
    pub ready_fd: Option<libc::c_int>,
    pub command: Vec<String>,
}

impl HelperRequest {
    /// Full argv tail for the daemon binary: `HELPER_ARG` followed by the
    /// encoded request and the workload command.
    pub fn to_args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec![HELPER_ARG.into()];
        args.push("--project-dir".into());
        args.push(self.project_dir.clone().into_os_string());
        for path in &self.extra_read_paths {
            args.push("--read".into());
            args.push(path.clone().into_os_string());
        }
        if self.network_blocked {
            args.push("--block-network".into());
        }
        if self.landlock {
            args.push("--landlock".into());
        }
        if self.seccomp {
            args.push("--seccomp".into());
        }
        if let Some(fd) = self.ready_fd {
            args.push("--ready-fd".into());
            args.push(fd.to_string().into());
        }
        args.push("--".into());
        args.extend(self.command.iter().map(OsString::from));
        args
    }

    /// Parse the arguments that follow [`HELPER_ARG`].
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut args = args.into_iter();
        let mut project_dir = None;
        let mut extra_read_paths = Vec::new();
        let mut network_blocked = false;
        let mut landlock = false;
        let mut seccomp = false;
        let mut ready_fd = None;
        let mut command = Vec::new();
        let value = |args: &mut dyn Iterator<Item = OsString>, flag: &str| {
            args.next().ok_or_else(|| format!("{flag} needs a value"))
        };
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("--project-dir") => {
                    project_dir = Some(PathBuf::from(value(&mut args, "--project-dir")?));
                }
                Some("--read") => extra_read_paths.push(PathBuf::from(value(&mut args, "--read")?)),
                Some("--block-network") => network_blocked = true,
                Some("--landlock") => landlock = true,
                Some("--seccomp") => seccomp = true,
                Some("--ready-fd") => {
                    ready_fd = Some(
                        value(&mut args, "--ready-fd")?
                            .to_str()
                            .and_then(|s| s.parse::<libc::c_int>().ok())
                            .ok_or_else(|| "--ready-fd must be an integer".to_string())?,
                    );
                }
                Some("--") => {
                    for rest in args.by_ref() {
                        command.push(
                            rest.into_string()
                                .map_err(|_| "command arguments must be UTF-8".to_string())?,
                        );
                    }
                    break;
                }
                _ => return Err(format!("unexpected helper argument {arg:?}")),
            }
        }
        let project_dir = project_dir.ok_or_else(|| "--project-dir is required".to_string())?;
        if command.is_empty() {
            return Err("no workload command after --".into());
        }
        Ok(Self {
            project_dir,
            extra_read_paths,
            network_blocked,
            landlock,
            seccomp,
            ready_fd,
            command,
        })
    }
}

/// If this process was started as the sandbox helper, become it and never
/// return. Otherwise return immediately. Must be the first thing `main` does
/// in any binary that embeds [`execute`], before logging, config or argument
/// parsing, so a workload argument such as `--help` can never be mistaken for
/// the daemon's own.
pub fn maybe_run_helper() {
    let mut args = std::env::args_os();
    let _argv0 = args.next();
    if args.next().as_deref() != Some(OsStr::new(HELPER_ARG)) {
        return;
    }
    match HelperRequest::parse(args) {
        Ok(request) => run_helper(request),
        Err(error) => {
            eprintln!("opaque sandbox helper: {error}");
            std::process::exit(HELPER_EXIT_RESTRICT_FAILED)
        }
    }
}

/// Restrict this process as requested, report readiness, exec the workload.
pub fn run_helper(request: HelperRequest) -> ! {
    let (message, code) = match restrict_then_exec(request) {
        Ok(never) => match never {},
        Err(failure) => failure,
    };
    eprintln!("opaque sandbox helper: {message}");
    std::process::exit(code)
}

fn restrict_then_exec(request: HelperRequest) -> Result<std::convert::Infallible, (String, i32)> {
    use std::os::unix::process::CommandExt as _;

    let prepared = PreparedRestrictions::prepare(
        request.landlock,
        request.seccomp,
        &request.project_dir,
        &request.extra_read_paths,
        request.network_blocked,
    )
    .map_err(|e| (e.to_string(), HELPER_EXIT_RESTRICT_FAILED))?;
    prepared.apply().map_err(|e| {
        (
            format!("cannot restrict the workload: {e}"),
            HELPER_EXIT_RESTRICT_FAILED,
        )
    })?;
    if let Some(fd) = request.ready_fd {
        signal_ready(fd).map_err(|e| {
            (
                format!("cannot report readiness on fd {fd}: {e}"),
                HELPER_EXIT_RESTRICT_FAILED,
            )
        })?;
    }

    let mut command = std::process::Command::new(&request.command[0]);
    command.args(&request.command[1..]);
    let error = command.exec();
    let code = if error.kind() == std::io::ErrorKind::NotFound {
        HELPER_EXIT_NOT_FOUND
    } else {
        HELPER_EXIT_CANNOT_EXEC
    };
    Err((format!("cannot exec {}: {error}", request.command[0]), code))
}

/// Write the readiness token and close the fd so the workload never inherits
/// a channel back to the daemon.
fn signal_ready(fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: the daemon dup2'd the pipe onto this exact fd for us to own.
    let mut pipe = unsafe { std::fs::File::from_raw_fd(fd) };
    pipe.write_all(READY_TOKEN)
}

// ---------------------------------------------------------------------------
// Bubblewrap mount isolation
// ---------------------------------------------------------------------------

/// Build the bubblewrap argument list for the given configuration.
///
/// Ends with the `--` separator; the caller appends the target argv.
pub fn build_bubblewrap_args(config: &LinuxSandboxConfig) -> Vec<String> {
    let protected = protected_paths();

    let mut args: Vec<String> = Vec::new();

    // Read-only root filesystem.
    args.extend_from_slice(&["--ro-bind".into(), "/".into(), "/".into()]);

    // Minimal device tree.
    args.extend_from_slice(&["--dev".into(), "/dev".into()]);

    // Fresh proc mount.
    args.extend_from_slice(&["--proc".into(), "/proc".into()]);

    // Writable temp. Mounted before the project bind: bwrap stacks mounts in
    // argument order, and a project directory under /tmp would otherwise be
    // hidden (read-only) beneath this tmpfs.
    args.extend_from_slice(&["--tmpfs".into(), "/tmp".into()]);

    // Writable project directory.
    let proj = config.project_dir.to_string_lossy().into_owned();
    args.extend_from_slice(&["--bind".into(), proj.clone(), proj]);

    // Block protected paths by overlaying them with tmpfs (effectively empty).
    for protected_path in &protected {
        if protected_path.exists() {
            let p = protected_path.to_string_lossy().into_owned();
            args.extend_from_slice(&["--tmpfs".into(), p]);
        }
    }

    // Extra read paths.
    for path in &config.extra_read_paths {
        let p = path.to_string_lossy().into_owned();
        args.extend_from_slice(&["--ro-bind".into(), p.clone(), p]);
    }

    // PID namespace.
    args.push("--unshare-pid".into());

    // Network namespace (only when network is not allowed).
    if config.network_allow.is_empty() {
        args.push("--unshare-net".into());
    }

    // Die with parent: cleanup on parent exit.
    args.push("--die-with-parent".into());

    // New session: prevent terminal escape.
    args.push("--new-session".into());

    // Separator.
    args.push("--".into());

    args
}

// ---------------------------------------------------------------------------
// Unshare fallback
// ---------------------------------------------------------------------------

/// Build the unshare argument list (fallback when bwrap is unavailable).
///
/// Ends with the `--` separator; the caller appends the target argv.
pub fn build_unshare_args(config: &LinuxSandboxConfig) -> Vec<String> {
    let mut args: Vec<String> = ["--user", "--mount", "--pid", "--fork", "--map-root-user"]
        .into_iter()
        .map(String::from)
        .collect();

    // Only unshare network when no network is allowed.
    if config.network_allow.is_empty() {
        args.push("--net".into());
    }

    args.push("--".into());
    args
}

/// The wrapper command for a strategy, with `target` as the program it runs
/// inside the namespaces (the helper argv, in production).
fn wrapper_command(
    wrapper: NamespaceWrapper,
    config: &LinuxSandboxConfig,
    target: &[OsString],
) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(wrapper.program());
    match wrapper {
        NamespaceWrapper::Bubblewrap => cmd.args(build_bubblewrap_args(config)),
        NamespaceWrapper::Unshare => cmd.args(build_unshare_args(config)),
    };
    cmd.args(target);
    cmd
}

// ---------------------------------------------------------------------------
// Main executor
// ---------------------------------------------------------------------------

/// Locate the binary that will serve as the helper inside the sandbox.
fn helper_executable() -> Result<PathBuf, SandboxError> {
    let exe = std::env::current_exe().map_err(|e| {
        SandboxError::Setup(format!(
            "cannot locate the daemon executable for the sandbox helper: {e}"
        ))
    })?;
    check_helper_visible(&exe, &protected_paths())?;
    Ok(exe)
}

/// The helper must be reachable from inside the sandbox; the protected
/// directories are masked there, so a daemon installed under one cannot
/// serve as its own helper.
fn check_helper_visible(exe: &Path, protected: &[PathBuf]) -> Result<(), SandboxError> {
    if let Some(dir) = protected.iter().find(|dir| exe.starts_with(dir)) {
        return Err(SandboxError::Setup(format!(
            "daemon executable {} lives under protected path {}, which is hidden inside the sandbox; \
             install it elsewhere (for example /usr/local/bin)",
            exe.display(),
            dir.display()
        )));
    }
    Ok(())
}

fn ready_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 fills the two-element array we hand it.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both descriptors are freshly created and owned by nobody else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Make the pipe's write end appear as [`READY_FD`] without CLOEXEC in the
/// wrapper, so it survives the wrapper's exec and reaches the helper.
fn inherit_ready_fd(cmd: &mut tokio::process::Command, write_end: RawFd) {
    unsafe {
        cmd.pre_exec(move || {
            if write_end == READY_FD {
                let flags = libc::fcntl(READY_FD, libc::F_GETFD);
                if flags < 0 || libc::fcntl(READY_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(write_end, READY_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Block until the helper reports readiness or every writer is gone.
fn read_ready(read_end: OwnedFd) -> std::io::Result<bool> {
    let mut pipe = std::fs::File::from(read_end);
    let mut received = Vec::with_capacity(READY_TOKEN.len());
    let mut buf = [0u8; 16];
    loop {
        let n = pipe.read(&mut buf)?;
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
        if received.len() >= READY_TOKEN.len() {
            break;
        }
    }
    Ok(received == READY_TOKEN)
}

/// Collect what the wrapper said before it died, then reap it.
async fn wrapper_failure(
    strategy: &SandboxStrategy,
    child: &mut tokio::process::Child,
    custody: &mut super::custody::ProcessCustody,
) -> SandboxError {
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pipe.read_to_end(&mut stderr),
        )
        .await;
    }
    let status =
        match tokio::time::timeout(std::time::Duration::from_secs(5), custody.wait(child)).await {
            Ok(Ok(status)) => status.to_string(),
            Ok(Err(e)) => format!("unknown status ({e})"),
            Err(_) => {
                custody.kill_group();
                let _ = child.kill().await;
                "killed after not exiting".to_string()
            }
        };
    stderr.truncate(4096);
    let stderr = String::from_utf8_lossy(&stderr).trim().to_owned();
    SandboxError::Wrapper(format!(
        "{} ({}) {status}: {}",
        strategy.wrapper.program(),
        strategy.name(),
        if stderr.is_empty() {
            "no diagnostic output".to_owned()
        } else {
            stderr
        }
    ))
}

/// Execute a command inside a Linux sandbox using the strongest strategy the
/// host supports. See [`execute_with_strategy`].
pub async fn execute(
    config: LinuxSandboxConfig,
    tx: mpsc::Sender<ExecFrame>,
) -> Result<i32, SandboxError> {
    if config.command.is_empty() {
        return Err(SandboxError::Setup("empty command".into()));
    }
    let caps = SandboxCapabilities::detect();
    caps.log_capabilities();
    let strategy = SandboxStrategy::select(&caps)?;
    execute_with_strategy(config, &strategy, tx).await
}

/// Execute a command inside a Linux sandbox with an already-selected strategy.
///
/// Sends streaming `ExecFrame` messages through the provided channel once
/// the helper has confirmed the workload is restricted; `ExecStarted` means
/// the sandbox exists. A wrapper that dies first is a [`SandboxError::Wrapper`]
/// carrying its stderr, never a fake exit code. Returns the workload's exit
/// code.
pub async fn execute_with_strategy(
    config: LinuxSandboxConfig,
    strategy: &SandboxStrategy,
    tx: mpsc::Sender<ExecFrame>,
) -> Result<i32, SandboxError> {
    if config.command.is_empty() {
        return Err(SandboxError::Setup("empty command".into()));
    }

    info!(strategy = %strategy.name(), "executing sandbox command");

    let helper = helper_executable()?;
    let request = HelperRequest {
        project_dir: config.project_dir.clone(),
        extra_read_paths: config.extra_read_paths.clone(),
        network_blocked: config.network_allow.is_empty(),
        landlock: strategy.landlock,
        seccomp: strategy.seccomp,
        ready_fd: Some(READY_FD),
        command: config.command.clone(),
    };
    let mut target: Vec<OsString> = vec![helper.into_os_string()];
    target.extend(request.to_args());

    let mut cmd = wrapper_command(strategy.wrapper, &config, &target);

    // Clear all environment and inject only allowed vars. The wrapper and
    // the helper pass this environment through to the workload unchanged.
    cmd.env_clear();

    // Standard PATH inside the sandbox.
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    cmd.env("HOME", "/tmp/home");

    // Inherit TERM for proper terminal handling.
    if let Ok(term) = std::env::var("TERM") {
        cmd.env("TERM", term);
    }

    // Inject profile environment variables (secrets + literals).
    for (key, value) in &config.env {
        cmd.env(key, value);
    }

    // Do NOT set OPAQUE_SOCK: the workload must not connect to the daemon.

    // Set working directory to the project dir.
    cmd.current_dir(&config.project_dir);

    // Capture stdout/stderr.
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdin(std::process::Stdio::null());

    // The wrapper runs unrestricted; the helper restricts itself inside the
    // namespaces and confirms on this pipe before the workload execs.
    let (ready_rx, ready_tx) = ready_pipe()?;
    inherit_ready_fd(&mut cmd, ready_tx.as_raw_fd());

    cmd.process_group(0).kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| SandboxError::Spawn(format!("{}: {e}", strategy.wrapper.program())))?;
    drop(ready_tx);

    let pid = child.id().unwrap_or(0);
    let mut custody = super::custody::ProcessCustody::new(pid);
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(config.timeout_secs);

    let ready = tokio::task::spawn_blocking(move || read_ready(ready_rx));
    let established = tokio::select! {
        _ = tx.closed() => {
            custody.kill_group();
            let _ = child.kill().await;
            return Err(SandboxError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "execution consumer disconnected")));
        }
        result = ready => result.map_err(std::io::Error::other)??,
        _ = tokio::time::sleep_until(deadline) => {
            custody.kill_group();
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(SandboxError::Wrapper(format!(
                "{} did not establish the sandbox within {}s",
                strategy.wrapper.program(),
                config.timeout_secs
            )));
        }
    };
    if !established {
        return Err(wrapper_failure(strategy, &mut child, &mut custody).await);
    }

    super::custody::send_frame(&tx, ExecFrame::ExecStarted { pid }, deadline).await?;

    let start = std::time::Instant::now();

    // Stream stdout and stderr concurrently.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SandboxError::Spawn("stdout not piped".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| SandboxError::Spawn("stderr not piped".into()))?;

    let tx_out = tx.clone();
    let tx_err = tx.clone();
    let max_bytes = config.max_output_bytes;

    let stdout_task = tokio::spawn(stream_output(
        stdout,
        tx_out,
        ExecStream::Stdout,
        max_bytes,
        deadline,
    ));
    let stderr_task = tokio::spawn(stream_output(
        stderr,
        tx_err,
        ExecStream::Stderr,
        max_bytes,
        deadline,
    ));
    custody.reader(&stdout_task);
    custody.reader(&stderr_task);

    // Wait for child with timeout.

    let exit_status = tokio::select! {
        _ = tx.closed() => return Err(SandboxError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "execution consumer disconnected"))),
        result = custody.wait(&mut child) => {
            result.map_err(SandboxError::Io)?
        }
        _ = tokio::time::sleep_until(deadline) => {
            // Kill the child on timeout.
            custody.kill_group();
            let _ = child.kill().await;
            let _ = child.wait().await;
            // Send a timeout indication via exit code -1.
            let duration_ms = start.elapsed().as_millis() as u64;
            super::custody::send_frame(&tx, ExecFrame::ExecCompleted {
                exit_code: -1,
                duration_ms,
            }, super::custody::completion_deadline()).await?;
            return Ok(-1);
        }
    };

    // Descendants may retain inherited pipes after the main child exits. The
    // original deadline also bounds reader completion; errors are never hidden.
    match tokio::time::timeout_at(deadline, async {
        stdout_task.await.map_err(std::io::Error::other)??;
        stderr_task.await.map_err(std::io::Error::other)?
    })
    .await
    {
        Ok(result) => result.map_err(SandboxError::Io)?,
        Err(_) => {
            custody.kill_group();
            super::custody::send_frame(
                &tx,
                ExecFrame::ExecCompleted {
                    exit_code: -1,
                    duration_ms: start.elapsed().as_millis() as u64,
                },
                super::custody::completion_deadline(),
            )
            .await?;
            return Ok(-1);
        }
    }

    let exit_code = exit_status.code().unwrap_or(-1);
    let duration_ms = start.elapsed().as_millis() as u64;

    super::custody::send_frame(
        &tx,
        ExecFrame::ExecCompleted {
            exit_code,
            duration_ms,
        },
        super::custody::completion_deadline(),
    )
    .await?;

    Ok(exit_code)
}

/// Stream output from an async reader to the frame channel.
async fn stream_output(
    mut reader: impl AsyncReadExt + Unpin,
    tx: mpsc::Sender<ExecFrame>,
    stream: ExecStream,
    max_bytes: usize,
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; OUTPUT_CHUNK_SIZE];
    let mut total = 0usize;

    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break, // EOF
            Ok(n) => {
                total += n;
                if total > max_bytes {
                    // Truncate: send what we can and stop.
                    let allowed = n.saturating_sub(total - max_bytes);
                    if allowed > 0 {
                        let data = String::from_utf8_lossy(&buf[..allowed]).into_owned();
                        super::custody::send_frame(
                            &tx,
                            ExecFrame::Output { stream, data },
                            deadline,
                        )
                        .await?;
                    }
                    break;
                }
                let data = String::from_utf8_lossy(&buf[..n]).into_owned();
                super::custody::send_frame(&tx, ExecFrame::Output { stream, data }, deadline)
                    .await?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn caps(
        bubblewrap: bool,
        landlock: bool,
        seccomp: bool,
        user_namespaces: bool,
    ) -> SandboxCapabilities {
        SandboxCapabilities {
            bubblewrap,
            landlock,
            landlock_evidence: "test".into(),
            seccomp,
            user_namespaces,
        }
    }

    #[test]
    fn sandbox_error_display() {
        let err = SandboxError::Setup("test".into());
        assert!(format!("{err}").contains("sandbox setup failed"));

        let err = SandboxError::Spawn("test".into());
        assert!(format!("{err}").contains("child process failed to spawn"));

        let err = SandboxError::Wrapper("bwrap exited".into());
        assert!(format!("{err}").contains("sandbox wrapper failed before the workload started"));
    }

    #[tokio::test]
    async fn empty_command_rejected() {
        let (tx, _rx) = mpsc::channel(16);
        let config = LinuxSandboxConfig {
            command: vec![],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp"),
            extra_read_paths: vec![],
            network_allow: vec![],
            timeout_secs: 10,
            max_output_bytes: 1024,
        };
        let result = execute(config, tx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty command"));
    }

    // -----------------------------------------------------------------------
    // Detection evidence (#121)
    // -----------------------------------------------------------------------

    #[test]
    fn lsm_list_parsing_finds_landlock_only_as_a_whole_name() {
        assert!(lsm_list_names_landlock(
            "lockdown,capability,landlock,yama,apparmor"
        ));
        assert!(lsm_list_names_landlock("capability,bpf,landlock\n"));
        assert!(lsm_list_names_landlock("landlock"));
        assert!(!lsm_list_names_landlock("capability,yama,apparmor"));
        assert!(!lsm_list_names_landlock("landlocked,capability"));
        assert!(!lsm_list_names_landlock(""));
    }

    #[test]
    fn landlock_probe_present_lsm_and_abi_is_available() {
        let probe = LandlockProbe::from_parts(Some("capability,bpf,landlock\n".into()), Ok(8));
        assert!(probe.available());
        assert!(!probe.contradictory());
        assert_eq!(probe.lsm_lists_landlock(), Some(true));
        assert_eq!(probe.evidence(), "lsm=landlock-listed abi=v8");
    }

    #[test]
    fn landlock_probe_absent_lsm_and_failed_abi_is_unavailable_with_reason() {
        let probe = LandlockProbe::from_parts(
            Some("capability,yama,apparmor".into()),
            Err(libc::EOPNOTSUPP),
        );
        assert!(!probe.available());
        assert_eq!(probe.lsm_lists_landlock(), Some(false));
        assert_eq!(
            probe.evidence(),
            "lsm=landlock-not-listed abi-probe=EOPNOTSUPP (LSM built but not enabled at boot)"
        );
        let old_kernel = LandlockProbe::from_parts(None, Err(libc::ENOSYS));
        assert!(!old_kernel.available());
        assert!(old_kernel.evidence().contains("ENOSYS"));
    }

    #[test]
    fn landlock_probe_trusts_the_syscall_when_securityfs_is_unreadable() {
        // Containers rarely mount securityfs; the kernel answer is what counts.
        let probe = LandlockProbe::from_parts(None, Ok(4));
        assert!(probe.available());
        assert_eq!(probe.evidence(), "lsm=securityfs-unreadable abi=v4");
    }

    #[test]
    fn landlock_probe_flags_a_contradiction_but_still_uses_the_kernel_answer() {
        let probe = LandlockProbe::from_parts(Some("capability,yama".into()), Ok(3));
        assert!(probe.available());
        assert!(probe.contradictory());
        assert!(probe.evidence().contains("securityfs disagrees"));
    }

    #[test]
    fn live_probe_agrees_with_the_landlock_crate() {
        // Both must answer the same question about this kernel.
        use landlock::{ABI, AccessFs, Compatible, Ruleset, RulesetAttr};
        let crate_says = Ruleset::default()
            .set_compatibility(landlock::CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_read(ABI::V1))
            .and_then(|rs| rs.create())
            .is_ok();
        let probe = LandlockProbe::run();
        eprintln!("landlock probe on this kernel: {}", probe.evidence());
        assert_eq!(probe.available(), crate_says, "{}", probe.evidence());
    }

    #[test]
    fn sandbox_capabilities_detection() {
        // Verify that capability probing does not panic and carries evidence.
        let caps = SandboxCapabilities::detect();
        let debug = format!("{caps:?}");
        assert!(debug.contains("bubblewrap"));
        assert!(debug.contains("landlock"));
        assert!(debug.contains("seccomp"));
        assert!(debug.contains("user_namespaces"));
        assert!(caps.landlock_evidence.contains("lsm="));
        assert!(caps.landlock_evidence.contains("abi"));
    }

    // -----------------------------------------------------------------------
    // Strategy selection and failover
    // -----------------------------------------------------------------------

    #[test]
    fn sandbox_strategy_prefers_bubblewrap_with_every_layer() {
        let strategy = SandboxStrategy::select(&caps(true, true, true, true)).unwrap();
        assert_eq!(strategy.wrapper, NamespaceWrapper::Bubblewrap);
        assert_eq!(strategy.name(), "bubblewrap+landlock+seccomp");
    }

    #[test]
    fn sandbox_strategy_falls_back_to_unshare() {
        let strategy = SandboxStrategy::select(&caps(false, true, true, true)).unwrap();
        assert_eq!(strategy.wrapper, NamespaceWrapper::Unshare);
        assert_eq!(strategy.name(), "unshare+landlock+seccomp");
    }

    #[test]
    fn sandbox_strategy_fails_over_without_landlock_and_says_so() {
        let strategy = SandboxStrategy::select(&caps(true, false, true, true)).unwrap();
        assert!(!strategy.landlock);
        assert_eq!(strategy.name(), "bubblewrap+seccomp");
        let bare = SandboxStrategy::select(&caps(false, false, false, true)).unwrap();
        assert_eq!(bare.name(), "unshare");
    }

    #[test]
    fn sandbox_strategy_fails_closed_without_a_namespace_wrapper() {
        let err = SandboxStrategy::select(&caps(false, true, true, false)).unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, SandboxError::Setup(_)), "{message}");
        assert!(
            message.contains("no sandbox strategy available"),
            "{message}"
        );
        assert!(message.contains("bubblewrap"), "{message}");
        assert!(
            message.contains("apparmor_restrict_unprivileged_userns"),
            "{message}"
        );
    }

    // -----------------------------------------------------------------------
    // Helper protocol
    // -----------------------------------------------------------------------

    #[test]
    fn helper_request_round_trips_through_argv() {
        let request = HelperRequest {
            project_dir: PathBuf::from("/home/user/proj with space"),
            extra_read_paths: vec![PathBuf::from("/opt/tools"), PathBuf::from("/srv/data")],
            network_blocked: true,
            landlock: true,
            seccomp: false,
            ready_fd: Some(3),
            command: vec!["sh".into(), "-c".into(), "echo --help -- done".into()],
        };
        let args = request.to_args();
        assert_eq!(args[0], OsString::from(HELPER_ARG));
        let parsed = HelperRequest::parse(args.into_iter().skip(1)).unwrap();
        assert_eq!(parsed, request);

        let minimal = HelperRequest {
            project_dir: PathBuf::from("/tmp"),
            extra_read_paths: vec![],
            network_blocked: false,
            landlock: false,
            seccomp: false,
            ready_fd: None,
            command: vec!["true".into()],
        };
        let parsed = HelperRequest::parse(minimal.to_args().into_iter().skip(1)).unwrap();
        assert_eq!(parsed, minimal);
    }

    #[test]
    fn helper_request_rejects_malformed_argv() {
        let parse = |args: &[&str]| HelperRequest::parse(args.iter().map(OsString::from));
        assert!(
            parse(&["--project-dir", "/p"])
                .unwrap_err()
                .contains("no workload command")
        );
        assert!(
            parse(&["--", "true"])
                .unwrap_err()
                .contains("--project-dir is required")
        );
        assert!(
            parse(&["--project-dir"])
                .unwrap_err()
                .contains("needs a value")
        );
        assert!(
            parse(&["--project-dir", "/p", "--ready-fd", "x", "--", "true"])
                .unwrap_err()
                .contains("integer")
        );
        assert!(
            parse(&["--project-dir", "/p", "--bogus", "--", "true"])
                .unwrap_err()
                .contains("unexpected helper argument")
        );
    }

    #[test]
    fn helper_must_not_live_under_a_protected_path() {
        let protected = vec![
            PathBuf::from("/home/u/.opaque"),
            PathBuf::from("/home/u/.ssh"),
        ];
        assert!(check_helper_visible(Path::new("/usr/local/bin/opaqued"), &protected).is_ok());
        let err = check_helper_visible(Path::new("/home/u/.opaque/bin/opaqued"), &protected)
            .unwrap_err()
            .to_string();
        assert!(err.contains("protected path"), "{err}");
    }

    // -----------------------------------------------------------------------
    // Layer construction
    // -----------------------------------------------------------------------

    #[test]
    fn landlock_ruleset_construction() {
        // Verify that the ruleset path list contains expected entries.
        let project_dir = PathBuf::from("/home/user/myproject");
        let extra = vec![PathBuf::from("/opt/shared-libs")];
        let paths = landlock_ruleset_paths(&project_dir, &extra);

        // Check global read-only root.
        assert!(paths.contains(&(PathBuf::from("/"), false)));

        // Check writable project dir.
        assert!(paths.contains(&(PathBuf::from("/home/user/myproject"), true)));

        // Check writable /tmp.
        assert!(paths.contains(&(PathBuf::from("/tmp"), true)));

        // Check writable /var/tmp.
        assert!(paths.contains(&(PathBuf::from("/var/tmp"), true)));

        // Check extra read path.
        assert!(paths.contains(&(PathBuf::from("/opt/shared-libs"), false)));

        // Device nodes are usable but /dev itself is not a writable tree.
        assert!(paths.contains(&(PathBuf::from("/dev"), false)));
        assert!(paths.contains(&(PathBuf::from("/dev/shm"), true)));

        // Verify writable paths count (project_dir, /tmp, /var/tmp, /dev/shm).
        let writable_count = paths.iter().filter(|(_, w)| *w).count();
        assert_eq!(writable_count, 4);
    }

    #[test]
    fn seccomp_filter_blocks_connect() {
        // Verify the blocked syscall list contains connect when network is blocked.
        let blocked = seccomp_blocked_syscalls(true);
        assert!(blocked.contains(&libc::SYS_connect));
        assert!(blocked.contains(&libc::SYS_bind));
        assert!(blocked.contains(&libc::SYS_listen));
        assert!(blocked.contains(&libc::SYS_accept));
        assert!(blocked.contains(&libc::SYS_accept4));
        assert!(blocked.contains(&libc::SYS_sendto));
        assert!(blocked.contains(&libc::SYS_sendmsg));
        assert!(blocked.contains(&libc::SYS_sendmmsg));

        // ptrace and io_uring always blocked.
        assert!(blocked.contains(&libc::SYS_ptrace));
        assert!(blocked.contains(&libc::SYS_io_uring_setup));
        assert!(blocked.contains(&libc::SYS_io_uring_enter));
        assert!(blocked.contains(&libc::SYS_io_uring_register));
    }

    #[test]
    fn seccomp_filter_allows_network_when_permitted() {
        // When network is allowed, network syscalls should NOT be in the blocked list.
        let blocked = seccomp_blocked_syscalls(false);
        assert!(!blocked.contains(&libc::SYS_connect));
        assert!(!blocked.contains(&libc::SYS_bind));
        assert!(!blocked.contains(&libc::SYS_listen));
        assert!(!blocked.contains(&libc::SYS_sendto));

        // ptrace and io_uring are ALWAYS blocked.
        assert!(blocked.contains(&libc::SYS_ptrace));
        assert!(blocked.contains(&libc::SYS_io_uring_setup));
    }

    #[test]
    fn bubblewrap_command_construction() {
        // Verify bwrap args are correct for a given config.
        let config = LinuxSandboxConfig {
            command: vec!["echo".into(), "hello".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/home/user/project"),
            extra_read_paths: vec![PathBuf::from("/opt/tools")],
            network_allow: vec![],
            timeout_secs: 30,
            max_output_bytes: 1024,
        };

        let args = build_bubblewrap_args(&config);

        // Check read-only root bind.
        let ro_bind_pos = args
            .windows(3)
            .position(|w| w == ["--ro-bind", "/", "/"])
            .expect("should have --ro-bind / /");
        assert_eq!(ro_bind_pos, 0, "--ro-bind / / should be first");

        // Check /dev.
        assert!(args.windows(2).any(|w| w == ["--dev", "/dev"]));

        // Check /proc.
        assert!(args.windows(2).any(|w| w == ["--proc", "/proc"]));

        // Check writable project dir.
        let bind_pos = args
            .windows(3)
            .position(|w| {
                w[0] == "--bind" && w[1] == "/home/user/project" && w[2] == "/home/user/project"
            })
            .expect("should bind the project dir writable");

        // Check tmpfs /tmp, mounted before the project bind so a project
        // under /tmp is not hidden beneath it.
        let tmpfs_pos = args
            .windows(2)
            .position(|w| w == ["--tmpfs", "/tmp"])
            .expect("should mount a tmpfs on /tmp");
        assert!(
            tmpfs_pos < bind_pos,
            "--tmpfs /tmp must precede the project --bind: {args:?}"
        );

        // Check extra read path.
        assert!(
            args.windows(3)
                .any(|w| { w[0] == "--ro-bind" && w[1] == "/opt/tools" && w[2] == "/opt/tools" })
        );

        // Check PID namespace.
        assert!(args.contains(&"--unshare-pid".to_string()));

        // Check die-with-parent.
        assert!(args.contains(&"--die-with-parent".to_string()));

        // Check new-session.
        assert!(args.contains(&"--new-session".to_string()));

        // Check separator.
        assert_eq!(args.last().unwrap(), "--");
    }

    #[test]
    fn bubblewrap_command_with_network() {
        // When network_allow is non-empty, --unshare-net should NOT be present.
        let config = LinuxSandboxConfig {
            command: vec!["curl".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp/proj"),
            extra_read_paths: vec![],
            network_allow: vec!["api.github.com:443".into()],
            timeout_secs: 30,
            max_output_bytes: 1024,
        };

        let args = build_bubblewrap_args(&config);

        // --unshare-net must NOT be present when network is allowed.
        assert!(
            !args.contains(&"--unshare-net".to_string()),
            "--unshare-net should not be present when network_allow is non-empty"
        );

        // --unshare-pid should still be present.
        assert!(args.contains(&"--unshare-pid".to_string()));
    }

    #[test]
    fn bubblewrap_command_without_network() {
        // When network_allow is empty, --unshare-net MUST be present.
        let config = LinuxSandboxConfig {
            command: vec!["echo".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp/proj"),
            extra_read_paths: vec![],
            network_allow: vec![],
            timeout_secs: 30,
            max_output_bytes: 1024,
        };

        let args = build_bubblewrap_args(&config);

        assert!(
            args.contains(&"--unshare-net".to_string()),
            "--unshare-net should be present when network_allow is empty"
        );
    }

    #[test]
    fn bubblewrap_command_writable_paths() {
        // Verify project_dir is bind-mounted writable (--bind, not --ro-bind).
        let config = LinuxSandboxConfig {
            command: vec!["ls".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/workspace/myapp"),
            extra_read_paths: vec![],
            network_allow: vec![],
            timeout_secs: 30,
            max_output_bytes: 1024,
        };

        let args = build_bubblewrap_args(&config);

        // The project dir should use --bind (writable), not --ro-bind.
        let has_writable_bind = args
            .windows(3)
            .any(|w| w[0] == "--bind" && w[1] == "/workspace/myapp" && w[2] == "/workspace/myapp");
        assert!(has_writable_bind, "project dir must be --bind (writable)");

        // It should NOT appear as --ro-bind.
        let has_readonly_bind = args.windows(3).any(|w| {
            w[0] == "--ro-bind" && w[1] == "/workspace/myapp" && w[2] == "/workspace/myapp"
        });
        assert!(!has_readonly_bind, "project dir must not be --ro-bind");
    }

    #[test]
    fn unshare_command_construction() {
        let blocked = LinuxSandboxConfig {
            command: vec!["true".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp/proj"),
            extra_read_paths: vec![],
            network_allow: vec![],
            timeout_secs: 30,
            max_output_bytes: 1024,
        };
        let args = build_unshare_args(&blocked);
        for flag in [
            "--user",
            "--mount",
            "--pid",
            "--fork",
            "--map-root-user",
            "--net",
        ] {
            assert!(args.contains(&flag.to_string()), "missing {flag}: {args:?}");
        }
        assert_eq!(args.last().unwrap(), "--");

        let allowed = LinuxSandboxConfig {
            network_allow: vec!["api.github.com:443".into()],
            ..blocked
        };
        assert!(!build_unshare_args(&allowed).contains(&"--net".to_string()));
    }

    #[test]
    fn wrapper_command_targets_the_helper_not_the_workload() {
        let config = LinuxSandboxConfig {
            command: vec!["echo".into(), "hi".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp/proj"),
            extra_read_paths: vec![],
            network_allow: vec![],
            timeout_secs: 30,
            max_output_bytes: 1024,
        };
        let request = HelperRequest {
            project_dir: config.project_dir.clone(),
            extra_read_paths: vec![],
            network_blocked: true,
            landlock: true,
            seccomp: true,
            ready_fd: Some(READY_FD),
            command: config.command.clone(),
        };
        let mut target: Vec<OsString> = vec!["/usr/local/bin/opaqued".into()];
        target.extend(request.to_args());
        for wrapper in [NamespaceWrapper::Bubblewrap, NamespaceWrapper::Unshare] {
            let cmd = wrapper_command(wrapper, &config, &target);
            let std_cmd = cmd.as_std();
            assert_eq!(std_cmd.get_program(), wrapper.program());
            let argv: Vec<&OsStr> = std_cmd.get_args().collect();
            let separator = argv
                .iter()
                .position(|a| *a == "--")
                .expect("wrapper separator");
            assert_eq!(argv[separator + 1], "/usr/local/bin/opaqued");
            assert_eq!(argv[separator + 2], HELPER_ARG);
            // The workload only appears after the helper's own separator.
            let helper_separator = argv[separator + 1..]
                .iter()
                .position(|a| *a == "--")
                .expect("helper separator");
            assert_eq!(argv[separator + 1 + helper_separator + 1], "echo");
        }
    }

    #[test]
    fn protected_paths_are_blocked() {
        // Verify ~/.ssh, ~/.gnupg, ~/.opaque are in the protected list.
        let paths = protected_paths();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());

        let expected_suffixes = [".opaque", ".ssh", ".gnupg"];
        for suffix in &expected_suffixes {
            let expected = PathBuf::from(&home).join(suffix);
            assert!(
                paths.contains(&expected),
                "protected paths should contain {}, got: {:?}",
                expected.display(),
                paths
            );
        }
    }

    #[test]
    fn protected_dirs_constant_matches_expectations() {
        assert_eq!(PROTECTED_DIRS.len(), 3);
        assert!(PROTECTED_DIRS.contains(&".opaque"));
        assert!(PROTECTED_DIRS.contains(&".ssh"));
        assert!(PROTECTED_DIRS.contains(&".gnupg"));
    }

    // -----------------------------------------------------------------------
    // Enforcement of the layers on a direct child (no wrapper involved)
    // -----------------------------------------------------------------------

    /// Apply prepared restrictions in a child's pre_exec, the way the helper
    /// applies them to itself.
    fn apply_in_child(cmd: &mut tokio::process::Command, prepared: PreparedRestrictions) {
        let slot = std::sync::Mutex::new(Some(prepared));
        unsafe {
            cmd.pre_exec(move || {
                match slot
                    .lock()
                    .map_err(|_| std::io::Error::other("restriction slot poisoned"))?
                    .take()
                {
                    Some(prepared) => prepared.apply(),
                    None => Ok(()),
                }
            });
        }
    }

    /// Run `sh -c <script>` with the given prepared restrictions applied,
    /// returning (exit_success, stderr).
    async fn run_restricted(script: &str, prepared: PreparedRestrictions) -> (bool, String) {
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c").arg(script);
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::piped());
        cmd.stdin(std::process::Stdio::null());
        apply_in_child(&mut cmd, prepared);
        let out = cmd.output().await.expect("child must spawn");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn seccomp_only(network_blocked: bool) -> PreparedRestrictions {
        PreparedRestrictions::prepare(false, true, Path::new("/tmp"), &[], network_blocked)
            .expect("seccomp must build")
    }

    /// ENFORCEMENT: with the network-blocking filter, connect(2) fails with
    /// EPERM, and the control run without the block fails with connection
    /// refused instead, proving the EPERM came from seccomp and not the
    /// environment. Uses bash's /dev/tcp (a plain connect under the hood).
    #[tokio::test]
    async fn seccomp_enforcement_blocks_connect_with_eperm() {
        if !detect_seccomp() {
            eprintln!("SKIP: seccomp unavailable on this kernel");
            return;
        }
        // Port 1 on loopback: nothing listens; the syscall outcome is what
        // distinguishes the runs.
        let (_ok, blocked_err) =
            run_restricted("bash -c 'exec 3<>/dev/tcp/127.0.0.1/1'", seccomp_only(true)).await;
        assert!(
            blocked_err.to_lowercase().contains("not permitted"),
            "blocked run must fail with EPERM, got: {blocked_err}"
        );

        let (_ok, control_err) = run_restricted(
            "bash -c 'exec 3<>/dev/tcp/127.0.0.1/1'",
            seccomp_only(false),
        )
        .await;
        assert!(
            control_err.to_lowercase().contains("refused"),
            "control run must reach the network stack (ECONNREFUSED), got: {control_err}"
        );
    }

    /// ENFORCEMENT: a restricted child still runs normal programs (the
    /// filter is a targeted blocklist, not a straitjacket).
    #[tokio::test]
    async fn seccomp_enforcement_leaves_normal_execution_alone() {
        if !detect_seccomp() {
            eprintln!("SKIP: seccomp unavailable on this kernel");
            return;
        }
        let (ok, err) = run_restricted("echo hello && ls / > /dev/null", seccomp_only(true)).await;
        assert!(ok, "benign child must run under the filter: {err}");
    }

    /// ENFORCEMENT (Landlock kernels only; a kernel without it prints a loud
    /// skip): writes outside the writable set fail, writes inside the project
    /// succeed, and the daemon's protected state stays unwritable.
    #[tokio::test]
    async fn landlock_enforcement_confines_writes_to_project() {
        if !LandlockProbe::run().available() {
            eprintln!("SKIP: landlock unavailable on this kernel (verified in CI instead)");
            return;
        }
        let project = tempfile::tempdir().expect("tempdir");
        let prepared = PreparedRestrictions::prepare(true, false, project.path(), &[], true)
            .expect("ruleset must build");
        assert!(prepared.landlock_prepared() && !prepared.seccomp_prepared());

        let inside = project.path().join("ok.txt");
        let script = format!(
            "echo denied > /usr/landlock-probe-{} 2>/dev/null && exit 7; echo fine > {} || exit 8; exit 0",
            std::process::id(),
            inside.display(),
        );
        let (ok, err) = run_restricted(&script, prepared).await;
        assert!(
            ok,
            "outside-write must fail and inside-write must succeed: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&inside)
                .expect("inside file")
                .trim(),
            "fine"
        );
    }

    /// FAIL CLOSED: a strategy that asks for Landlock on a kernel without it
    /// errors at preparation; the workload never runs unrestricted. (Only
    /// stageable on kernels WITHOUT Landlock.)
    #[test]
    fn prepare_fails_closed_when_landlock_requested_but_unusable() {
        if LandlockProbe::run().available() {
            eprintln!("SKIP: kernel actually has landlock; the lie cannot be staged");
            return;
        }
        let err =
            PreparedRestrictions::prepare(true, false, Path::new("/tmp"), &[], true).unwrap_err();
        assert!(
            matches!(err, SandboxError::Setup(_)),
            "must fail closed, got: {err:?}"
        );
    }

    #[test]
    fn landlock_ruleset_has_no_protected_paths_writable() {
        // Protected paths must NOT appear as writable in the ruleset.
        let project_dir = PathBuf::from("/home/user/project");
        let paths = landlock_ruleset_paths(&project_dir, &[]);

        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        for dir in PROTECTED_DIRS {
            let protected = PathBuf::from(&home).join(dir);
            // Should not be in the writable set.
            assert!(
                !paths.contains(&(protected.clone(), true)),
                "{} must not be writable",
                protected.display()
            );
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod reader_lifecycle_tests {

    #[tokio::test]
    async fn output_cap_keeps_exact_prefix_and_stops_at_zero_budget() {
        for (limit, expected) in [(0, ""), (3, "abc"), (6, "abcdef"), (7, "abcdef")] {
            let (tx, mut rx) = mpsc::channel(4);
            stream_output(
                &b"abcdef"[..],
                tx,
                ExecStream::Stdout,
                limit,
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
            let mut output = String::new();
            while let Some(frame) = rx.recv().await {
                if let ExecFrame::Output { stream, data } = frame {
                    assert_eq!(stream, ExecStream::Stdout);
                    output.push_str(&data);
                }
            }
            assert_eq!(output, expected);
        }
    }
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn output_delivery_errors_are_reported_to_the_execution_owner() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(ExecFrame::ExecStarted { pid: 0 }).await.unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        let error = stream_output(
            &b"output"[..],
            tx.clone(),
            ExecStream::Stdout,
            1024,
            deadline,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        rx.recv().await.unwrap();
        drop(rx);
        let error = stream_output(&b"output"[..], tx, ExecStream::Stdout, 1024, deadline)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);

        struct FailedReader;
        impl tokio::io::AsyncRead for FailedReader {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::Error::other("injected read failure")))
            }
        }
        let (tx, _rx) = mpsc::channel(1);
        let error = stream_output(FailedReader, tx, ExecStream::Stdout, 1024, deadline)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
    }
}
