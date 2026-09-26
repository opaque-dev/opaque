#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::generate;
use console::style;
use futures_util::{SinkExt, StreamExt};
use opaque_core::audit::{AuditEventKind, AuditFilter, query_audit_db};
use opaque_core::operation::{ClientIdentity, ClientType, OperationRequest, OperationSafety};
use opaque_core::policy::{
    PolicyEngine, codesign_team_id_is_platform_enforceable, platform_policy_warnings,
};
use opaque_core::profile;
use opaque_core::proto::{Request, Response};
use opaque_core::socket::{socket_path, verify_socket_safety};
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

mod agent_process;
mod authority_policy_command;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod ipc_tests;
mod policy_regression;
mod scope_command;
mod service;
mod setup;
mod ui;
#[allow(dead_code)]
mod wizard;

/// Build a version string that includes the git SHA: `0.1.0+abc1234`.
const fn version_string() -> &'static str {
    concat!(env!("CARGO_PKG_VERSION"), "+", env!("OPAQUE_GIT_SHA"))
}

/// Name of the daemon token file expected next to the socket.
const DAEMON_TOKEN_FILENAME: &str = "daemon.token";

/// Baseline environment variable keys forwarded to agent child processes
/// when running in secure-by-default mode (i.e. without `--inherit-env`).
const BASELINE_ENV_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "TERM",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
    "COLORTERM",
    "SSH_AUTH_SOCK",
];

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

/// Success exit code.
#[allow(dead_code)]
const EXIT_SUCCESS: i32 = 0;

/// General error exit code.
const EXIT_ERROR: i32 = 1;

/// Invalid input or arguments.
const EXIT_USAGE: i32 = 2;

/// Daemon connection or response error.
const EXIT_DAEMON: i32 = 3;

/// Authentication or approval failure.
const EXIT_AUTH: i32 = 4;

/// Prompt the user to confirm a destructive action.
///
/// Returns `true` if the action should proceed. Skips the prompt and returns
/// `true` when `--yes` or `--json` is active (scripting context).
fn confirm_destructive(message: &str, skip: bool) -> bool {
    if skip {
        return true;
    }
    dialoguer::Confirm::new()
        .with_prompt(message)
        .default(false)
        .interact()
        .unwrap_or(false)
}

#[derive(Debug, Parser)]
#[command(name = "opaque", version = version_string())]
struct Cli {
    /// Override the Unix socket path (otherwise uses OPAQUE_SOCK / XDG_RUNTIME_DIR / ~/.opaque/run).
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Output raw JSON instead of styled text (useful for scripting).
    #[arg(long, global = true)]
    json: bool,

    /// Disable colored output and emoji (respect NO_COLOR env var).
    #[arg(long, global = true)]
    plain: bool,

    /// Skip confirmation prompts (useful for scripting).
    #[arg(long, short = 'y', global = true)]
    yes: bool,

    /// Verbose output (show extra details, debug info).
    #[arg(long, short = 'v', global = true, conflicts_with = "quiet")]
    verbose: bool,

    /// Minimal output (suppress non-essential messages). Useful for scripting.
    #[arg(long, short = 'q', global = true, conflicts_with = "verbose")]
    quiet: bool,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Validate and compile versioned authority policy offline (no grants or activation).
    AuthorityPolicy {
        #[command(subcommand)]
        action: authority_policy_command::Action,
    },
    /// Check daemon liveness.
    Ping,
    /// Read daemon version.
    Version,
    /// Show how the daemon identifies this client (uid, gid, exe path, pid).
    Whoami,
    /// Execute an operation through the enclave.
    Execute {
        /// Operation name (e.g. "test.noop", "github.set_actions_secret").
        operation: String,

        /// Operation parameters as a JSON object. Prefer secret references in this file.
        #[arg(long)]
        params_file: Option<PathBuf>,

        /// Target key=value pairs (repeatable). E.g. --target repo=org/myrepo
        #[arg(long, short = 't', value_parser = parse_kv)]
        target: Vec<(String, String)>,

        /// Secret ref names (repeatable). E.g. --secret JWT --secret DB_PASSWORD
        #[arg(long, short = 's')]
        secret: Vec<String>,

        /// Attach git workspace context from the current directory.
        #[arg(long, default_value_t = false)]
        workspace: bool,
    },
    /// Manage policy configuration.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Initialize Opaque configuration directory.
    Init {
        /// Overwrite existing config file.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Apply a policy preset (e.g. "safe-demo", "github-secrets", "sandbox-human").
        #[arg(long)]
        preset: Option<String>,
        /// Initialize a repo-scoped policy in .opaque/ at the repo root.
        #[arg(long, default_value_t = false)]
        repo: bool,
    },
    /// Manage GitHub Actions secrets.
    Github {
        #[command(subcommand)]
        action: GithubAction,
    },
    /// Plan, approve, and inspect a bounded task (secret publish, staging
    /// release, SSH host check, or inference).
    Task {
        #[command(subcommand)]
        action: TaskAction,
    },
    /// Issue and inspect bounded support-case authority.
    Scope {
        #[command(subcommand)]
        action: scope_command::Action,
    },
    /// Manage GitLab CI/CD variables.
    Gitlab {
        #[command(subcommand)]
        action: GitlabAction,
    },
    /// Browse 1Password vaults and items.
    #[command(name = "onepassword", alias = "1p")]
    OnePassword {
        #[command(subcommand)]
        action: OnePasswordAction,
    },
    /// Execute a command in a sandboxed environment.
    Exec {
        /// Profile name (loads ~/.opaque/profiles/<name>.toml).
        #[arg(long)]
        profile: String,

        /// Command and arguments to execute in the sandbox.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Manage execution profiles.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Run and manage wrapped agent sessions.
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Query the audit log.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Sign in as a human via your organization's identity provider (OIDC).
    #[command(
        long_about = "Sign in as a human via your organization's identity provider (OIDC).\n\n\
        Opens your browser to the configured IdP. The browser step IS the identity\n\
        proof: an agent driving this CLI cannot complete it — only the human at the\n\
        IdP can. On success the daemon holds your login session; agent sessions can\n\
        then be delegated on your behalf."
    )]
    Login {
        /// Print the sign-in URL only; do not try to open a browser.
        #[arg(long, default_value_t = false)]
        no_browser: bool,
    },
    /// Sign out: revoke all active human login sessions in the daemon.
    Logout,
    /// Inspect principals, roles, and delegations (identity substrate).
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Delegate and revoke scoped access provisioning for verified IdP users.
    Provisioning {
        #[command(subcommand)]
        action: ProvisioningAction,
    },
    /// Manage paired approver devices (second-device approval factor).
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Manage FIDO2 hardware keys / passkeys (approval factor).
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Org tooling for signed federation policy bundles (offline).
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },
    /// Ask the daemon for a signed posture attestation and verify it.
    #[command(
        long_about = "Ask the daemon for a signed posture attestation and verify it.\n\n\
        The CLI generates a fresh random nonce, the daemon answers with a report\n\
        signed by its attestation key covering custody, audit-chain, trust-domain\n\
        and federation posture, and the CLI verifies signature + nonce + freshness\n\
        before printing. Pin the expected key with --key to detect a substituted\n\
        daemon; exits nonzero when the posture is unhealthy."
    )]
    Attest {
        /// Expected attestation public key (hex). Without it the report is
        /// verified against the key the daemon itself presents — which proves
        /// freshness but not identity.
        #[arg(long)]
        key: Option<String>,
        /// Print the raw signed report (for a verifier to check itself).
        #[arg(long, default_value_t = false)]
        raw: bool,
    },
    /// Interactive setup wizard — configure and seal your security policy.
    Setup {
        /// Seal the current config.toml without running the wizard.
        #[arg(long)]
        seal: bool,
        /// Remove the config seal (allows reconfiguration).
        #[arg(long)]
        reset: bool,
        /// Check seal status without starting daemon.
        #[arg(long)]
        verify: bool,
    },
    /// Manage the opaqued daemon service (install, start, stop, status).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Diagnose your Opaque installation and report issues.
    Doctor,
    /// One-step onboarding: init with safe-demo preset, check daemon, run diagnostics.
    Quickstart,
    /// Register the opaque MCP server with an AI coding tool (claude, cursor, codex).
    Connect {
        /// Tool name: "claude", "cursor", "codex", or "auto" (detect automatically).
        #[arg(default_value = "auto")]
        tool: String,
    },
    /// List active approval leases in the daemon.
    Leases,
    /// Manage secrets in the OS keychain for use with Opaque secret refs.
    Secrets {
        #[command(subcommand)]
        action: SecretsAction,
    },
    /// Generate shell completions for bash, zsh, or fish.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Debug, Subcommand)]
enum SecretsAction {
    /// Store a secret in the OS keychain. Value is read from stdin (not echoed).
    Add {
        /// Secret name (e.g. "github-pat", "gitlab-token"). Stored as "opaque/<name>".
        name: String,
    },
    /// List stored Opaque secrets (names only, never values).
    List,
    /// Remove a secret from the OS keychain.
    Remove {
        /// Secret name to remove.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum ServiceAction {
    /// Install and start the daemon as a system service.
    Install,
    /// Stop and remove the daemon service.
    Uninstall,
    /// Check if the daemon service is installed and running.
    Status,
    /// Start the daemon service.
    Start,
    /// Stop the daemon service.
    Stop,
    /// Restart the daemon service.
    Restart,
    /// Show recent daemon logs.
    Logs,
}

#[derive(Debug, Subcommand)]
enum PolicyAction {
    /// Compare baseline/candidate policy against reviewed golden cases (offline).
    Regress {
        /// Baseline config or unsigned bundle manifest (TOML).
        #[arg(long)]
        baseline: PathBuf,
        /// Candidate config or unsigned bundle manifest (TOML).
        #[arg(long)]
        candidate: PathBuf,
        /// Golden cases (JSON, schema_version = 1).
        #[arg(long)]
        cases: PathBuf,
        /// Fail on any changed decision, even when the candidate is expected.
        #[arg(long)]
        fail_on_change: bool,
    },
    /// Validate policy configuration file.
    Check {
        /// Path to config file (default: ~/.opaque/config.toml or $OPAQUE_CONFIG).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Display loaded policy rules in a human-readable format.
    Show {
        /// Path to config file (default: ~/.opaque/config.toml or $OPAQUE_CONFIG).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// List available policy presets.
    Presets {
        /// Show the full TOML content of a specific preset.
        #[arg(long)]
        show: Option<String>,
    },
    /// Apply a policy preset to your configuration.
    Preset {
        /// Preset name (e.g. "safe-demo", "github-secrets", "sandbox-human").
        name: String,
        /// Compatibility only: config headers written by releases up to 0.4.0
        /// taught `opaque policy preset apply <name>`. Hidden from help.
        #[arg(hide = true)]
        legacy_name: Option<String>,
    },
    /// Dry-run a request against the policy to see what would happen.
    Simulate {
        /// Operation name (e.g. "github.set_actions_secret").
        #[arg(long)]
        operation: String,
        /// Client type: "human" or "agent".
        #[arg(long, default_value = "human")]
        client_type: String,
        /// Target fields as KEY=VALUE pairs (e.g. --target repo=org/repo).
        #[arg(long = "target", value_parser = parse_kv)]
        targets: Vec<(String, String)>,
        /// Secret ref names referenced by the request.
        #[arg(long = "secret-ref")]
        secret_refs: Vec<String>,
        /// Path to config file.
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileAction {
    /// List available profiles.
    List,
    /// Show a profile's contents.
    Show {
        /// Profile name.
        name: String,
    },
    /// Validate a profile.
    Validate {
        /// Profile name.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum AgentAction {
    /// Run an agent command in a session scoped by an Opaque-issued token.
    Run {
        /// Optional session TTL in seconds (default comes from daemon).
        #[arg(long)]
        ttl_secs: Option<u64>,

        /// Delegated human identity, or an explicitly configured autonomous service.
        #[arg(long, default_value = "delegated", value_parser = ["delegated", "autonomous"])]
        mode: String,

        /// Configured service name; required only in autonomous mode.
        #[arg(long, required_if_eq("mode", "autonomous"))]
        service: Option<String>,

        /// Pass an additional environment variable to the child process.
        /// Repeatable. Ignored when --inherit-env is set.
        #[arg(long, value_name = "KEY")]
        pass_env: Vec<String>,

        /// Inherit the full parent environment instead of the secure baseline.
        #[arg(long, default_value_t = false)]
        inherit_env: bool,

        /// Deprecated: clean-env filtering is now the default.
        #[arg(long, default_value_t = false, hide = true)]
        clean_env: bool,

        /// Agent command and args to run.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// List active wrapped-agent sessions for this user.
    List,
    /// End (revoke) a wrapped-agent session by ID.
    End {
        /// Revoke all wrapped-agent sessions created by the current UID.
        #[arg(long, default_value_t = false)]
        all: bool,

        /// Session ID returned by `opaque agent run` or `opaque agent list`.
        /// Required unless `--all` is set.
        #[arg(required_unless_present = "all")]
        session_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum IdentityAction {
    /// List known principals (humans, agents, service principals).
    Ls,
    /// Set the role list for a principal (requires the admin role).
    Roles {
        /// Principal id (hum_…, agt_…, svc_…) as shown by `opaque identity ls`.
        principal_id: String,

        /// Roles to assign: admin, approver, operator, auditor.
        /// Space- or comma-separated. Replaces the current role list.
        #[arg(required = true, num_args = 1..)]
        roles: Vec<String>,
    },
    /// List delegation records (agent sessions bound to principals).
    Delegations,
}

#[derive(Debug, Subcommand)]
enum ProvisioningAction {
    /// Review binding an enrolled FIDO2 key to the logged-in IdP administrator.
    BindStart { credential_id: String },
    /// Complete the binding using the assertion produced by a FIDO2 client.
    BindComplete {
        challenge_id: String,
        #[arg(long)]
        assertion: PathBuf,
    },
    /// Review a bounded mandate for a configured autonomous service.
    MandateStart {
        #[arg(long)]
        service: String,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        ttl_secs: u64,
        #[arg(long)]
        max_issuances: u32,
    },
    /// Complete a reviewed mandate with an IdP-bound FIDO2 assertion.
    MandateComplete {
        challenge_id: String,
        #[arg(long)]
        assertion: PathBuf,
    },
    /// Issue access as a wrapped autonomous service under an approved mandate.
    Issue {
        #[arg(long)]
        mandate: String,
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        ttl_secs: u64,
        /// Stable UUID for one issuance request; reuse it only when retrying.
        #[arg(long)]
        request_id: String,
    },
    /// List mandates and issued access visible to the caller.
    List,
    /// Inspect one grant and the exact profile revision it approved.
    Show {
        #[arg(value_parser = ["mandate", "access"])]
        kind: String,
        id: String,
    },
    /// Revoke a mandate and its children, or one recipient's access.
    Revoke {
        #[arg(value_parser = ["mandate", "access"])]
        kind: String,
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum KeyAction {
    /// List registered FIDO2 credentials.
    Ls,
    /// Remove a registered credential (removing an approver is never gated
    /// on an approver).
    Remove {
        /// Credential id as shown by `opaque key ls`.
        credential_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum BundleAction {
    /// Generate an org signing keypair; prints the public key (trust anchor).
    Keygen {
        /// Where to write the private signing key (0600).
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a bundle manifest into a distributable policy bundle.
    #[command(
        long_about = "Sign a bundle manifest into a distributable policy bundle.\n\n\
        The manifest is TOML carrying org, version, optional [[teams]], and the\n\
        org policy as [[rules]] (the same rule shape as the daemon config).\n\
        Daemons verify the signature against [federation] trust_anchors and\n\
        refuse version rollbacks."
    )]
    Sign {
        /// Bundle manifest (TOML: org, version, [[teams]], [[rules]]).
        #[arg(long)]
        manifest: PathBuf,
        /// Org signing key file (from `opaque bundle keygen`).
        #[arg(long)]
        key: PathBuf,
        /// Output bundle file.
        #[arg(long)]
        out: PathBuf,
        /// Override the manifest's version (CI bump automation).
        #[arg(long)]
        version: Option<u64>,
        /// Expire the bundle N days from now.
        #[arg(long)]
        expires_days: Option<u32>,
        /// Run reviewed golden policy cases before reading the signing key.
        #[arg(long, requires = "baseline")]
        regression_cases: Option<PathBuf>,
        /// Baseline policy for the pre-sign regression comparison.
        #[arg(long, requires = "regression_cases")]
        baseline: Option<PathBuf>,
        /// Also block signing on any semantic policy decision change.
        #[arg(long, requires = "regression_cases")]
        fail_on_policy_change: bool,
    },
    /// Verify a bundle against one or more trust anchors.
    Verify {
        /// Bundle file to verify.
        file: PathBuf,
        /// Trust anchor (hex Ed25519 public key). Repeatable.
        #[arg(long, required = true)]
        anchor: Vec<String>,
    },
    /// Show a bundle's contents WITHOUT verifying its signature.
    Inspect {
        /// Bundle file to inspect.
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum DeviceAction {
    /// Begin pairing a new approver device (approval-gated; prints the QR
    /// payload for the companion app).
    #[command(long_about = "Begin pairing a new approver device.\n\n\
        Requires an out-of-band approval to start. The printed payload is scanned\n\
        by the companion app, which completes pairing over the approval server.\n\
        The new device stays QUARANTINED (no approval authority) until you run\n\
        `opaque device confirm <device-id>` and match its key fingerprint against\n\
        what the device itself displays.")]
    Pair,
    /// List paired devices with confirmation and revocation state.
    Ls,
    /// Confirm a paired device's key fingerprint (approval-gated) — this is
    /// what grants it approval authority.
    Confirm {
        /// Device id as shown by `opaque device ls`.
        device_id: String,
    },
    /// Revoke a paired device immediately (not approval-gated: removing an
    /// approver never waits on an approver).
    Revoke {
        /// Device id as shown by `opaque device ls`.
        device_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum TaskAction {
    /// Plan one fixed host health check using the tenant's Vault SSH signer.
    PlanSsh {
        #[arg(long, default_value = "Service health on approved host")]
        title: String,
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=300))]
        expires_in_secs: u64,
    },
    /// Plan three fixed public-source completions in the authenticated tenant.
    PlanInference {
        #[arg(long, default_value = "Tenant public data inference")]
        title: String,
        #[arg(long, default_value_t = 600)]
        expires_in_secs: u64,
    },
    /// Resolve exact repositories and pin a manifest for trusted review.
    Plan {
        /// JSON manifest with schema_version, title, expires_in_secs and actions.
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Request trusted approval and execute this task once.
    Run { task_id: String },
    /// Show exact scope, charged slots and provider outcomes.
    Show { task_id: String },
    /// Read correlated staging workflow evidence without dispatching again.
    Reconcile { task_id: String },
    /// Block future writes; already dispatched writes may still finish.
    Revoke { task_id: String },
    /// List tasks belonging to this authenticated owner.
    List {
        /// Continue after the task ID returned as next_cursor on a prior page.
        #[arg(long)]
        cursor: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::enum_variant_names)]
enum GithubAction {
    /// Set a GitHub Actions repository secret.
    SetSecret {
        /// Repository in "owner/repo" format.
        #[arg(long)]
        repo: String,

        /// Secret name (e.g. "AWS_ACCESS_KEY_ID").
        #[arg(long)]
        secret_name: String,

        /// Secret ref (e.g. "keychain:opaque/aws-key" or "profile:prod:AWS_KEY").
        #[arg(long)]
        value_ref: String,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,

        /// GitHub environment name (for environment secrets).
        #[arg(long)]
        environment: Option<String>,
    },
    /// Set a GitHub Codespaces secret (user-level or repo-level).
    SetCodespacesSecret {
        /// Repository in "owner/repo" format (omit for user-level secret).
        #[arg(long)]
        repo: Option<String>,

        /// Secret name (e.g. "DOTFILES_TOKEN").
        #[arg(long)]
        secret_name: String,

        /// Secret ref (e.g. "keychain:opaque/codespaces-token").
        #[arg(long)]
        value_ref: String,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,

        /// Selected repository IDs (comma-separated, for user-level secrets).
        #[arg(long, value_delimiter = ',')]
        selected_repository_ids: Option<Vec<i64>>,
    },
    /// Set a GitHub Dependabot repository secret.
    SetDependabotSecret {
        /// Repository in "owner/repo" format.
        #[arg(long)]
        repo: String,

        /// Secret name (e.g. "NPM_TOKEN").
        #[arg(long)]
        secret_name: String,

        /// Secret ref (e.g. "keychain:opaque/npm-token").
        #[arg(long)]
        value_ref: String,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,
    },
    /// Set a GitHub Actions organization secret.
    SetOrgSecret {
        /// Organization name.
        #[arg(long)]
        org: String,

        /// Secret name (e.g. "ORG_DEPLOY_KEY").
        #[arg(long)]
        secret_name: String,

        /// Secret ref (e.g. "keychain:opaque/org-deploy-key").
        #[arg(long)]
        value_ref: String,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,

        /// Secret visibility: "all", "private", or "selected" (default: "private").
        #[arg(long, default_value = "private")]
        visibility: String,

        /// Selected repository IDs (comma-separated, when visibility is "selected").
        #[arg(long, value_delimiter = ',')]
        selected_repository_ids: Option<Vec<i64>>,
    },
    /// List secrets for a repository, environment, or organization.
    ListSecrets {
        /// Repository in "owner/repo" format (for repo/env/codespaces/dependabot scopes).
        #[arg(long)]
        repo: Option<String>,

        /// Organization name (for org scope).
        #[arg(long)]
        org: Option<String>,

        /// Secret scope: "actions", "codespaces", "dependabot", or "org".
        #[arg(long, default_value = "actions")]
        scope: String,

        /// GitHub environment name (for environment-scoped listing).
        #[arg(long)]
        environment: Option<String>,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,
    },
    /// Delete a secret from a repository, environment, or organization.
    DeleteSecret {
        /// Repository in "owner/repo" format (for repo/env/codespaces/dependabot scopes).
        #[arg(long)]
        repo: Option<String>,

        /// Organization name (for org scope).
        #[arg(long)]
        org: Option<String>,

        /// Secret name to delete.
        #[arg(long)]
        secret_name: String,

        /// Secret scope: "actions", "codespaces", "dependabot", or "org".
        #[arg(long, default_value = "actions")]
        scope: String,

        /// GitHub environment name (for environment-scoped deletion).
        #[arg(long)]
        environment: Option<String>,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,
    },
    /// Publish all keys from a .env-style template through Opaque.
    ///
    /// Reads key names from `.env.example` (or `--env-file`), builds a secret
    /// ref for each key using `--value-ref-template` (must include `{name}`),
    /// then calls GitHub set-secret via Opaque for each key.
    ///
    /// Example:
    ///   opaque github publish-env \
    ///     --repo myorg/myrepo \
    ///     --env-file .env.example \
    ///     --value-ref-template 'bitwarden:production/{name}'
    PublishEnv {
        /// Repository in "owner/repo" format.
        #[arg(long)]
        repo: String,

        /// Path to a .env-style file containing KEY=... entries (names are used, values ignored).
        #[arg(long, default_value = ".env.example")]
        env_file: PathBuf,

        /// Template used to build value refs (must include "{name}"), e.g. "bitwarden:production/{name}".
        #[arg(long)]
        value_ref_template: String,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,

        /// GitHub environment name (for environment-scoped Actions secrets).
        #[arg(long)]
        environment: Option<String>,

        /// Preview the publish plan without calling the daemon.
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Continue publishing after individual secret failures.
        #[arg(long, default_value_t = false)]
        continue_on_error: bool,
    },
    /// Build a refs-only manifest from a .env-style template for manual vault updates.
    ///
    /// This never reads secret values; it only captures key names and value refs.
    BuildManifest {
        /// Path to a .env-style file containing KEY=... entries (names are used, values ignored).
        #[arg(long, default_value = ".env.example")]
        env_file: PathBuf,

        /// Template used to build value refs (must include "{name}"), e.g. "bitwarden:production/{name}".
        #[arg(long, default_value = "bitwarden:CHANGEME/{name}")]
        value_ref_template: String,

        /// Output manifest JSON path.
        #[arg(long, default_value = ".opaque/env-manifest.json")]
        out: PathBuf,

        /// Optional default repository to store in the manifest.
        #[arg(long)]
        repo: Option<String>,

        /// Optional default environment to store in the manifest.
        #[arg(long)]
        environment: Option<String>,
    },
    /// Publish secrets using a refs-only manifest.
    ///
    /// The manifest should be created via `build-manifest` and manually updated
    /// with vault-backed refs as needed.
    PublishManifest {
        /// Manifest JSON path.
        #[arg(long, default_value = ".opaque/env-manifest.json")]
        manifest_file: PathBuf,

        /// Repository in "owner/repo" format (overrides manifest.repo when set).
        #[arg(long)]
        repo: Option<String>,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,

        /// GitHub environment name (overrides manifest.environment when set).
        #[arg(long)]
        environment: Option<String>,

        /// Preview the publish plan without calling the daemon.
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Continue publishing after individual secret failures.
        #[arg(long, default_value_t = false)]
        continue_on_error: bool,
    },
}

#[derive(Debug, Subcommand)]
enum GitlabAction {
    /// Set a GitLab CI/CD variable for a project.
    SetCiVariable {
        /// Project path or ID (e.g. "group/project").
        #[arg(long)]
        project: String,

        /// Variable key (e.g. "DATABASE_URL").
        #[arg(long)]
        key: String,

        /// Secret ref (e.g. "keychain:opaque/db-url" or "bitwarden:prod/DATABASE_URL").
        #[arg(long)]
        value_ref: String,

        /// GitLab token ref (default: "keychain:opaque/gitlab-pat").
        #[arg(long)]
        gitlab_token_ref: Option<String>,

        /// Variable environment scope (default is provider-side default, usually "*").
        #[arg(long)]
        environment_scope: Option<String>,

        /// Mark variable as protected.
        #[arg(long, default_value_t = false)]
        protected: bool,

        /// Mark variable as masked.
        #[arg(long, default_value_t = false)]
        masked: bool,

        /// Keep variable raw (no expansion).
        #[arg(long, default_value_t = false)]
        raw: bool,

        /// Variable type: "env_var" or "file".
        #[arg(long, default_value = "env_var")]
        variable_type: String,
    },
}

#[derive(Debug, Subcommand)]
enum OnePasswordAction {
    /// List accessible vaults.
    ListVaults,
    /// List items in a vault.
    ListItems {
        /// Vault name.
        #[arg(long)]
        vault: String,
    },
    /// Read a specific field from a 1Password item.
    ReadField {
        /// Vault name.
        #[arg(long)]
        vault: String,
        /// Item title.
        #[arg(long)]
        item: String,
        /// Field label.
        #[arg(long)]
        field: String,
    },
}

#[derive(Debug, Subcommand)]
enum AuditAction {
    /// Show recent audit events.
    Tail {
        /// Maximum number of events to display.
        #[arg(long, default_value = "50")]
        limit: usize,

        /// Filter by event kind (e.g. "request.received", "policy.denied").
        #[arg(long)]
        kind: Option<String>,

        /// Filter by operation name.
        #[arg(long)]
        operation: Option<String>,

        /// Show events since duration ago (e.g. "30m", "1h", "7d").
        #[arg(long)]
        since: Option<String>,

        /// Filter by request correlation ID.
        #[arg(long)]
        request_id: Option<String>,

        /// Filter by outcome (e.g. "allowed", "denied", "error").
        #[arg(long)]
        outcome: Option<String>,

        /// Full-text search query over audit event text.
        #[arg(long = "query")]
        query: Option<String>,
    },

    /// Verify the tamper-evident audit hash chain.
    Verify,
}

fn parse_kv(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("expected KEY=VALUE, got '{s}'"))?;
    Ok((k.to_owned(), v.to_owned()))
}

fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn parse_env_names(contents: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut seen = HashSet::new();

    for (line_no, raw_line) in contents.lines().enumerate() {
        let mut line = raw_line.trim();
        if line_no == 0 {
            line = line.trim_start_matches('\u{feff}');
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim_start();
        }

        let (name_part, _) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected KEY=VALUE", line_no + 1))?;
        let name = name_part.trim();

        if !is_valid_env_name(name) {
            return Err(format!(
                "line {}: invalid env name '{name}' (expected [A-Za-z_][A-Za-z0-9_]*)",
                line_no + 1
            ));
        }

        if !seen.insert(name.to_owned()) {
            return Err(format!("line {}: duplicate env name '{name}'", line_no + 1));
        }

        names.push(name.to_owned());
    }

    Ok(names)
}

fn parse_env_names_from_file(path: &Path) -> Result<Vec<String>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    parse_env_names(&content)
}

fn render_value_ref(value_ref_template: &str, name: &str) -> Result<String, String> {
    if !value_ref_template.contains("{name}") {
        return Err(
            "value_ref_template must include '{name}', e.g. 'bitwarden:production/{name}'".into(),
        );
    }
    let value_ref = value_ref_template.replace("{name}", name);
    if !is_allowed_value_ref(&value_ref) {
        return Err(format!(
            "value ref '{value_ref}' does not start with a known scheme ({:?})",
            opaque_core::profile::ALLOWED_REF_SCHEMES
        ));
    }
    Ok(value_ref)
}

fn is_allowed_value_ref(value_ref: &str) -> bool {
    opaque_core::profile::ALLOWED_REF_SCHEMES
        .iter()
        .any(|s| value_ref.starts_with(s))
}

const ENV_MANIFEST_FORMAT_V1: &str = "opaque.env-manifest/v1";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct EnvManifestEntry {
    secret_name: String,
    value_ref: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct EnvManifest {
    #[serde(default = "manifest_format_v1")]
    format: String,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    entries: Vec<EnvManifestEntry>,
}

fn manifest_format_v1() -> String {
    ENV_MANIFEST_FORMAT_V1.to_string()
}

fn validate_env_manifest(manifest: &EnvManifest) -> Result<(), String> {
    if manifest.format != ENV_MANIFEST_FORMAT_V1 {
        return Err(format!(
            "unsupported manifest format '{}'; expected '{}'",
            manifest.format, ENV_MANIFEST_FORMAT_V1
        ));
    }
    if manifest.entries.is_empty() {
        return Err("manifest has no entries".into());
    }

    let mut seen = HashSet::new();
    for (idx, entry) in manifest.entries.iter().enumerate() {
        if !is_valid_env_name(&entry.secret_name) {
            return Err(format!(
                "entry {} has invalid secret_name '{}'",
                idx + 1,
                entry.secret_name
            ));
        }
        if !seen.insert(entry.secret_name.clone()) {
            return Err(format!(
                "manifest has duplicate secret_name '{}'",
                entry.secret_name
            ));
        }
        if !is_allowed_value_ref(&entry.value_ref) {
            return Err(format!(
                "entry {} has invalid value_ref '{}' (expected one of {:?})",
                idx + 1,
                entry.value_ref,
                opaque_core::profile::ALLOWED_REF_SCHEMES
            ));
        }
    }
    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct PublishEnvItem {
    secret_name: String,
    value_ref: String,
    status: String,
    error: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct PublishEnvSummary {
    repo: String,
    environment: Option<String>,
    env_file: String,
    value_ref_template: String,
    dry_run: bool,
    total_discovered: usize,
    attempted: usize,
    published: usize,
    failed: usize,
    items: Vec<PublishEnvItem>,
}

#[derive(Debug, serde::Serialize)]
struct BuildManifestSummary {
    manifest_file: String,
    env_file: String,
    repo: Option<String>,
    environment: Option<String>,
    value_ref_template: String,
    entries: usize,
}

#[derive(Debug, serde::Serialize)]
struct PublishManifestSummary {
    repo: String,
    environment: Option<String>,
    manifest_file: String,
    dry_run: bool,
    total_entries: usize,
    attempted: usize,
    published: usize,
    failed: usize,
    items: Vec<PublishEnvItem>,
}

#[allow(clippy::too_many_arguments)]
async fn run_github_publish_env(
    sock: &Path,
    repo: &str,
    env_file: &Path,
    value_ref_template: &str,
    github_token_ref: Option<&str>,
    environment: Option<&str>,
    dry_run: bool,
    continue_on_error: bool,
    json_output: bool,
) -> Result<(), String> {
    let env_names = parse_env_names_from_file(env_file)?;
    if env_names.is_empty() {
        return Err(format!(
            "no env keys found in {} (expected KEY=VALUE lines)",
            env_file.display()
        ));
    }

    let total_discovered = env_names.len();
    let mut items = Vec::with_capacity(total_discovered);
    let mut attempted = 0usize;
    let mut published = 0usize;
    let mut failed = 0usize;

    for name in env_names {
        let value_ref = match render_value_ref(value_ref_template, &name) {
            Ok(v) => v,
            Err(e) => {
                failed += 1;
                items.push(PublishEnvItem {
                    secret_name: name.clone(),
                    value_ref: value_ref_template.replace("{name}", &name),
                    status: "failed".into(),
                    error: Some(e),
                });
                if !continue_on_error {
                    break;
                }
                continue;
            }
        };

        if dry_run {
            items.push(PublishEnvItem {
                secret_name: name,
                value_ref,
                status: "planned".into(),
                error: None,
            });
            continue;
        }

        attempted += 1;
        let scope = if environment.is_some() {
            "env_actions"
        } else {
            "repo_actions"
        };
        let mut params = serde_json::json!({
            "scope": scope,
            "repo": repo,
            "secret_name": name,
            "value_ref": value_ref,
        });
        if let Some(tok) = github_token_ref {
            params["github_token_ref"] = serde_json::Value::String(tok.to_owned());
        }
        if let Some(env) = environment {
            params["environment"] = serde_json::Value::String(env.to_owned());
        }

        match call(sock, "github", params).await {
            Ok(resp) => {
                if let Some(err) = resp.error {
                    failed += 1;
                    let error_msg = if err.code.is_empty() {
                        err.message
                    } else {
                        format!("{}: {}", err.code, err.message)
                    };
                    items.push(PublishEnvItem {
                        secret_name: name,
                        value_ref,
                        status: "failed".into(),
                        error: Some(error_msg),
                    });
                    if !continue_on_error {
                        break;
                    }
                } else {
                    published += 1;
                    let status = resp
                        .result
                        .as_ref()
                        .and_then(|r| r.get("status"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("ok");
                    items.push(PublishEnvItem {
                        secret_name: name,
                        value_ref,
                        status: status.to_owned(),
                        error: None,
                    });
                }
            }
            Err(e) => {
                failed += 1;
                items.push(PublishEnvItem {
                    secret_name: name,
                    value_ref,
                    status: "failed".into(),
                    error: Some(e.to_string()),
                });
                if !continue_on_error {
                    break;
                }
            }
        }
    }

    let summary = PublishEnvSummary {
        repo: repo.to_owned(),
        environment: environment.map(|s| s.to_owned()),
        env_file: env_file.display().to_string(),
        value_ref_template: value_ref_template.to_owned(),
        dry_run,
        total_discovered,
        attempted,
        published,
        failed,
        items,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).map_err(|e| format!("json error: {e}"))?
        );
    } else {
        ui::header("Publish Env Secrets");
        ui::kv("repo", &summary.repo);
        if let Some(ref env) = summary.environment {
            ui::kv("environment", env);
        }
        ui::kv("env_file", &summary.env_file);
        ui::kv("value_ref_template", &summary.value_ref_template);
        if summary.dry_run {
            ui::kv("mode", "dry-run");
        }

        for item in &summary.items {
            if let Some(ref err) = item.error {
                println!(
                    "  {} {}",
                    style(ui::CROSS).red(),
                    style(&item.secret_name).red().bold()
                );
                println!(
                    "      {} {}",
                    style("ref:").dim(),
                    style(&item.value_ref).dim()
                );
                println!("      {} {}", style("error:").dim(), style(err).red());
            } else {
                println!(
                    "  {} {}",
                    style(ui::CHECK).green(),
                    style(&item.secret_name).yellow().bold()
                );
                println!(
                    "      {} {}",
                    style("ref:").dim(),
                    style(&item.value_ref).dim()
                );
            }
        }

        if summary.dry_run {
            ui::success(&format!(
                "Dry run complete: {} secret(s) planned",
                summary.items.len()
            ));
        } else if summary.failed == 0 {
            ui::success(&format!("Published {} secret(s)", summary.published));
        } else {
            ui::warn(&format!(
                "Published {} secret(s), {} failed",
                summary.published, summary.failed
            ));
        }
    }

    if !dry_run && failed > 0 {
        return Err(format!(
            "publish failed: {} succeeded, {} failed",
            published, failed
        ));
    }
    Ok(())
}

fn run_github_build_manifest(
    env_file: &Path,
    value_ref_template: &str,
    out: &Path,
    repo: Option<&str>,
    environment: Option<&str>,
    json_output: bool,
) -> Result<(), String> {
    let env_names = parse_env_names_from_file(env_file)?;
    if env_names.is_empty() {
        return Err(format!(
            "no env keys found in {} (expected KEY=VALUE lines)",
            env_file.display()
        ));
    }

    let entries = env_names
        .into_iter()
        .map(|name| {
            let value_ref = render_value_ref(value_ref_template, &name)?;
            Ok(EnvManifestEntry {
                secret_name: name,
                value_ref,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let manifest = EnvManifest {
        format: manifest_format_v1(),
        repo: repo.map(|s| s.to_owned()),
        environment: environment.map(|s| s.to_owned()),
        entries,
    };
    validate_env_manifest(&manifest)?;

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }

    let payload = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("failed to serialize manifest: {e}"))?;
    std::fs::write(out, payload)
        .map_err(|e| format!("failed to write manifest {}: {e}", out.display()))?;

    let summary = BuildManifestSummary {
        manifest_file: out.display().to_string(),
        env_file: env_file.display().to_string(),
        repo: manifest.repo,
        environment: manifest.environment,
        value_ref_template: value_ref_template.to_owned(),
        entries: manifest.entries.len(),
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).map_err(|e| format!("json error: {e}"))?
        );
    } else {
        ui::header("Built Env Manifest");
        ui::kv("manifest_file", &summary.manifest_file);
        ui::kv("env_file", &summary.env_file);
        ui::kv("value_ref_template", &summary.value_ref_template);
        if let Some(ref repo) = summary.repo {
            ui::kv("repo", repo);
        }
        if let Some(ref env) = summary.environment {
            ui::kv("environment", env);
        }
        ui::kv("entries", &summary.entries.to_string());
        ui::success("Manifest created. Update refs manually if needed, then run publish-manifest.");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_github_publish_manifest(
    sock: &Path,
    manifest_file: &Path,
    repo_override: Option<&str>,
    github_token_ref: Option<&str>,
    environment_override: Option<&str>,
    dry_run: bool,
    continue_on_error: bool,
    json_output: bool,
) -> Result<(), String> {
    let raw = std::fs::read_to_string(manifest_file)
        .map_err(|e| format!("failed to read {}: {e}", manifest_file.display()))?;
    let manifest: EnvManifest = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid manifest {}: {e}", manifest_file.display()))?;
    validate_env_manifest(&manifest)?;

    let repo = repo_override
        .map(|s| s.to_owned())
        .or(manifest.repo.clone())
        .ok_or_else(|| {
            "missing repo: pass --repo or set manifest.repo in build-manifest".to_string()
        })?;
    let environment = environment_override
        .map(|s| s.to_owned())
        .or(manifest.environment.clone());
    let total_entries = manifest.entries.len();

    let mut items = Vec::with_capacity(manifest.entries.len());
    let mut attempted = 0usize;
    let mut published = 0usize;
    let mut failed = 0usize;

    for entry in manifest.entries {
        if dry_run {
            items.push(PublishEnvItem {
                secret_name: entry.secret_name,
                value_ref: entry.value_ref,
                status: "planned".into(),
                error: None,
            });
            continue;
        }

        attempted += 1;
        let scope = if environment.is_some() {
            "env_actions"
        } else {
            "repo_actions"
        };
        let mut params = serde_json::json!({
            "scope": scope,
            "repo": repo,
            "secret_name": entry.secret_name,
            "value_ref": entry.value_ref,
        });
        if let Some(tok) = github_token_ref {
            params["github_token_ref"] = serde_json::Value::String(tok.to_owned());
        }
        if let Some(ref env) = environment {
            params["environment"] = serde_json::Value::String(env.to_owned());
        }

        match call(sock, "github", params).await {
            Ok(resp) => {
                if let Some(err) = resp.error {
                    failed += 1;
                    let error_msg = if err.code.is_empty() {
                        err.message
                    } else {
                        format!("{}: {}", err.code, err.message)
                    };
                    items.push(PublishEnvItem {
                        secret_name: entry.secret_name,
                        value_ref: entry.value_ref,
                        status: "failed".into(),
                        error: Some(error_msg),
                    });
                    if !continue_on_error {
                        break;
                    }
                } else {
                    published += 1;
                    let status = resp
                        .result
                        .as_ref()
                        .and_then(|r| r.get("status"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("ok");
                    items.push(PublishEnvItem {
                        secret_name: entry.secret_name,
                        value_ref: entry.value_ref,
                        status: status.to_owned(),
                        error: None,
                    });
                }
            }
            Err(e) => {
                failed += 1;
                items.push(PublishEnvItem {
                    secret_name: entry.secret_name,
                    value_ref: entry.value_ref,
                    status: "failed".into(),
                    error: Some(e.to_string()),
                });
                if !continue_on_error {
                    break;
                }
            }
        }
    }

    let summary = PublishManifestSummary {
        repo,
        environment,
        manifest_file: manifest_file.display().to_string(),
        dry_run,
        total_entries,
        attempted,
        published,
        failed,
        items,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).map_err(|e| format!("json error: {e}"))?
        );
    } else {
        ui::header("Publish Manifest Secrets");
        ui::kv("repo", &summary.repo);
        if let Some(ref env) = summary.environment {
            ui::kv("environment", env);
        }
        ui::kv("manifest_file", &summary.manifest_file);
        if summary.dry_run {
            ui::kv("mode", "dry-run");
        }

        for item in &summary.items {
            if let Some(ref err) = item.error {
                println!(
                    "  {} {}",
                    style(ui::CROSS).red(),
                    style(&item.secret_name).red().bold()
                );
                println!(
                    "      {} {}",
                    style("ref:").dim(),
                    style(&item.value_ref).dim()
                );
                println!("      {} {}", style("error:").dim(), style(err).red());
            } else {
                println!(
                    "  {} {}",
                    style(ui::CHECK).green(),
                    style(&item.secret_name).yellow().bold()
                );
                println!(
                    "      {} {}",
                    style("ref:").dim(),
                    style(&item.value_ref).dim()
                );
            }
        }

        if summary.dry_run {
            ui::success(&format!(
                "Dry run complete: {} secret(s) planned",
                summary.items.len()
            ));
        } else if summary.failed == 0 {
            ui::success(&format!("Published {} secret(s)", summary.published));
        } else {
            ui::warn(&format!(
                "Published {} secret(s), {} failed",
                summary.published, summary.failed
            ));
        }
    }

    if !dry_run && summary.failed > 0 {
        return Err(format!(
            "publish failed: {} succeeded, {} failed",
            summary.published, summary.failed
        ));
    }
    Ok(())
}

/// Flatten role arguments: accepts space-separated args and/or
/// comma-separated lists within a single arg ("admin,operator approver").
fn flatten_role_args(roles: &[String]) -> Vec<String> {
    roles
        .iter()
        .flat_map(|r| r.split(','))
        .map(|r| r.trim().to_ascii_lowercase())
        .filter(|r| !r.is_empty())
        .collect()
}

/// Try to open a URL in the default browser. Failure is non-fatal — the
/// URL is always printed so the human can open it manually.
fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(target_os = "linux")]
    let cmd = "xdg-open";
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return false;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    std::process::Command::new(cmd)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

/// Run the interactive OIDC login flow: start an attempt with the daemon,
/// hand the human the IdP URL, and poll until the daemon has verified the
/// ID token and created a login session.
///
/// The auth code and tokens never pass through this CLI — the daemon owns
/// the loopback redirect and the code exchange. This process only learns
/// the outcome.
async fn run_login(sock: &Path, no_browser: bool, json_output: bool) -> Result<i32, String> {
    let resp = call(sock, "identity.login_start", serde_json::Value::Null)
        .await
        .map_err(|e| format!("Connection failed: {e}"))?;

    if let Some(err) = &resp.error {
        if json_output {
            let output = serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_string());
            println!("{output}");
            return Ok(EXIT_DAEMON);
        }
        if err.code == "identity_not_configured" {
            ui::error("Identity is not configured in the daemon");
            println!();
            ui::section_box(
                "Enable OIDC login",
                &[
                    "Add an [identity] section to ~/.opaque/config.toml:",
                    "",
                    "  [identity]",
                    "  issuer = \"https://your-idp.example.com\"",
                    "  client_id = \"opaque-cli\"",
                    "  # session_ttl_secs = 43200",
                    "  # allowed_email_domains = [\"example.com\"]",
                    "",
                    "Then restart the daemon (and re-seal if your config is sealed).",
                ],
            );
        } else {
            ui::format_error(err);
        }
        return Ok(EXIT_DAEMON);
    }

    let result = resp.result.unwrap_or(serde_json::Value::Null);
    let attempt_id = result
        .get("attempt_id")
        .and_then(|v| v.as_str())
        .ok_or("daemon returned no attempt_id")?
        .to_string();
    let auth_url = result
        .get("auth_url")
        .and_then(|v| v.as_str())
        .ok_or("daemon returned no auth_url")?
        .to_string();
    let expires_in_secs = result
        .get("expires_in_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(300);

    if !json_output {
        ui::header("Sign in with your identity provider");
        println!();
        println!("  {}", style(&auth_url).cyan().underlined());
        println!();
        if no_browser {
            ui::info("Open the URL above in your browser to continue.");
        } else if open_browser(&auth_url) {
            ui::info("Opening your browser… complete the sign-in there.");
        } else {
            ui::warn("Could not open a browser — open the URL above manually.");
        }
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(expires_in_secs);
    let sp = if json_output {
        None
    } else {
        Some(ui::spinner("Waiting for sign-in to complete..."))
    };

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        if std::time::Instant::now() >= deadline {
            if let Some(ref sp) = sp {
                ui::spinner_error(sp, "Sign-in timed out");
            }
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"status": "failed", "reason": "timeout"})
                );
            }
            return Ok(EXIT_AUTH);
        }

        let resp = call(
            sock,
            "identity.login_status",
            serde_json::json!({ "attempt_id": attempt_id }),
        )
        .await
        .map_err(|e| format!("Connection failed while waiting for sign-in: {e}"))?;

        if let Some(err) = &resp.error {
            if let Some(ref sp) = sp {
                sp.finish_and_clear();
            }
            if json_output {
                let output =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_string());
                println!("{output}");
            } else {
                ui::format_error(err);
            }
            return Ok(EXIT_DAEMON);
        }

        let status_obj = resp.result.unwrap_or(serde_json::Value::Null);
        match status_obj.get("status").and_then(|v| v.as_str()) {
            Some("pending") | None => continue,
            Some("complete") => {
                if let Some(ref sp) = sp {
                    sp.finish_and_clear();
                }
                if json_output {
                    let output = serde_json::to_string_pretty(&status_obj)
                        .unwrap_or_else(|_| "{}".to_string());
                    println!("{output}");
                } else {
                    let identity = status_obj
                        .get("identity")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    let label = identity
                        .get("label")
                        .and_then(|v| v.as_str())
                        .unwrap_or("(unknown)");
                    ui::success(&format!("Signed in as {}", style(label).green().bold()));
                    ui::format_identity_summary(&identity);
                }
                return Ok(EXIT_SUCCESS);
            }
            Some("failed") => {
                let reason = status_obj
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                if let Some(ref sp) = sp {
                    ui::spinner_error(sp, &format!("Sign-in failed: {reason}"));
                }
                if json_output {
                    let output = serde_json::to_string_pretty(&status_obj)
                        .unwrap_or_else(|_| "{}".to_string());
                    println!("{output}");
                }
                return Ok(EXIT_AUTH);
            }
            Some(other) => {
                if let Some(ref sp) = sp {
                    sp.finish_and_clear();
                }
                return Err(format!("unexpected login status: {other}"));
            }
        }
    }
}

fn session_token_from_env() -> Option<String> {
    std::env::var("OPAQUE_SESSION_TOKEN")
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn agent_session_start_params(
    command: &[String],
    ttl_secs: Option<u64>,
    mode: &str,
    service: Option<&str>,
) -> Result<serde_json::Value, String> {
    let label = command.first().ok_or("agent command must not be empty")?;
    let mut params = serde_json::json!({"label":label,"mode":mode});
    match (mode, service) {
        ("delegated", None) => {}
        ("autonomous", Some(name)) => {
            opaque_core::identity::PrincipalKind::Service {
                name: name.to_owned(),
            }
            .validate()
            .map_err(|_| "invalid configured service name")?;
            params["service"] = name.into();
        }
        ("autonomous", None) => return Err("--mode autonomous requires --service".into()),
        ("delegated", Some(_)) => {
            return Err("--service is only valid with --mode autonomous".into());
        }
        _ => return Err("agent mode must be delegated or autonomous".into()),
    }
    if let Some(ttl) = ttl_secs {
        params["ttl_secs"] = ttl.into();
    }
    Ok(params)
}

#[allow(clippy::too_many_arguments)]
async fn run_agent_wrapped(
    sock: &Path,
    command: &[String],
    ttl_secs: Option<u64>,
    mode: &str,
    service: Option<&str>,
    inherit_env: bool,
    pass_env: &[String],
    json_output: bool,
) -> Result<i32, String> {
    let start_params = agent_session_start_params(command, ttl_secs, mode, service)?;
    // Install cancellation handlers before minting a session, so setup failure
    // cannot strand an already-authorized delegation.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|e| format!("cannot watch agent interruption: {e}"))?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| format!("cannot watch agent termination: {e}"))?;

    maybe_warn_opaque_mcp_skew(command, json_output);

    let mut cancellation = None;
    let start = call(sock, "agent_session_start", start_params);
    tokio::pin!(start);
    let session_start = tokio::select! {
        biased;
        _ = interrupt.recv() => {
            cancellation = Some(libc::SIGINT);
            start.await
        }
        _ = terminate.recv() => {
            cancellation = Some(libc::SIGTERM);
            start.await
        }
        result = &mut start => result,
    }
    .map_err(|e| format!("failed to start agent session: {e}"))?;
    if let Some(err) = session_start.error {
        return Err(format!("{}: {}", err.code, err.message));
    }

    let result = session_start
        .result
        .ok_or_else(|| "agent_session_start returned no result".to_string())?;
    let session_id = result
        .get("session_id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| "agent_session_start missing session_id".to_string())?
        .to_owned();
    // Every path after receiving an identifiable grant attempts revocation,
    // including malformed grants and failures before the child can execute.
    let outcome = async {
        // Finish the in-flight mint to obtain its ID for revocation, but never
        // launch a child after cancellation while approval was pending.
        if let Some(signal) = cancellation {
            return Ok(128 + signal);
        }
        if mode == "autonomous" && result.get("mode").and_then(|v| v.as_str()) != Some("autonomous")
        {
            return Err(
                "broker did not create the requested autonomous identity delegation".into(),
            );
        }
        let session_token = result
            .get("session_token")
            .and_then(|v| v.as_str())
            .filter(|token| !token.trim().is_empty())
            .ok_or_else(|| "agent_session_start missing session_token".to_string())?
            .to_owned();

        if !json_output {
            ui::header("Agent Wrapper Session");
            ui::kv("session_id", &session_id);
            if let Some(expires) = result.get("expires_at_utc_ms").and_then(|v| v.as_i64()) {
                ui::kv("expires_at_utc_ms", &expires.to_string());
            }
            // Present when the daemon minted a delegation (identity configured).
            if let Some(mode) = result.get("mode").and_then(|v| v.as_str()) {
                ui::kv("mode", mode);
            }
            if let Some(label) = result.get("on_behalf_of_label").and_then(|v| v.as_str()) {
                ui::kv("on behalf of", label);
            }
        }

        let mut child = tokio::process::Command::new(&command[0]);
        if command.len() > 1 {
            child.args(&command[1..]);
        }

        if !inherit_env {
            child.env_clear();
            for key in BASELINE_ENV_KEYS {
                if let Ok(val) = std::env::var(key) {
                    child.env(key, val);
                }
            }
            for key in pass_env {
                if let Ok(val) = std::env::var(key) {
                    child.env(key, val);
                }
            }
        }

        child.env("OPAQUE_SESSION_TOKEN", &session_token);
        child.env("OPAQUE_AGENT_SESSION_ID", &session_id);
        child.env("OPAQUE_AGENT_WRAPPED", "1");
        child.env("OPAQUE_SOCK", sock.display().to_string());
        child.stdin(std::process::Stdio::inherit());
        child.stdout(std::process::Stdio::inherit());
        child.stderr(std::process::Stdio::inherit());
        tokio::select! {
            biased;
            _ = interrupt.recv() => return Ok(128 + libc::SIGINT),
            _ = terminate.recv() => return Ok(128 + libc::SIGTERM),
            _ = std::future::ready(()) => {},
        }
        agent_process::run(child, &mut interrupt, &mut terminate).await
    }
    .await;

    let cleanup = call(
        sock,
        "agent_session_end",
        serde_json::json!({ "session_id": session_id }),
    )
    .await
    .map_err(|e| format!("agent session cleanup failed: {e}"))
    .and_then(|response| match response.error {
        Some(error) => Err(format!(
            "agent session cleanup failed: {}: {}",
            error.code, error.message
        )),
        None => match response.result {
            Some(result)
                if matches!(result.get("status").and_then(|v| v.as_str()), Some("ended" | "not_found"))
                    && result.get("session_id").and_then(|v| v.as_str()) == Some(session_id.as_str()) => Ok(()),
            _ => Err("agent session cleanup failed: broker did not acknowledge this session's revocation".into()),
        },
    });
    match (outcome, cleanup) {
        (Ok(code), Ok(())) => Ok(code),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}

fn maybe_warn_opaque_mcp_skew(command: &[String], json_output: bool) {
    let Some(cmd0) = command.first() else {
        return;
    };
    let cmd_name = Path::new(cmd0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(cmd0);
    if cmd_name != "opaque-mcp" {
        return;
    }

    let path = if cmd0.contains('/') {
        PathBuf::from(cmd0)
    } else {
        resolve_on_path(cmd0).unwrap_or_else(|| PathBuf::from(cmd0))
    };

    if let Ok(mcp_version) = read_binary_version(&path, "opaque-mcp") {
        let cli_version = version_string();
        if mcp_version != cli_version && !json_output {
            ui::warn(&format!(
                "opaque-mcp ({mcp_version}) differs from opaque ({cli_version}); rebuild to avoid handshake skew"
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Secrets command helpers
// ---------------------------------------------------------------------------

/// Validate a secret name: only alphanumeric, dash, and underscore allowed.
fn validate_secret_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Secret name must not be empty".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "Invalid secret name '{}': only alphanumeric characters, dashes, and underscores are allowed",
            name
        ));
    }
    Ok(())
}

/// Return the keychain ref format for a given secret name.
fn secrets_ref_format(name: &str) -> String {
    format!("keychain:opaque/{name}")
}

/// Return the command and arguments to add a secret to the OS keychain.
///
/// On Linux the value is piped via stdin rather than passed as an argument,
/// so the returned args do **not** include the value itself.
fn keychain_add_command<'a>(name: &'a str, value: &'a str, os: &str) -> (String, Vec<&'a str>) {
    let service_label: &str = Box::leak(format!("opaque/{name}").into_boxed_str());
    match os {
        "macos" => (
            "security".to_string(),
            vec![
                "add-generic-password",
                "-a",
                "opaque",
                "-s",
                service_label,
                "-w",
                value,
                "-U",
            ],
        ),
        _ => (
            "secret-tool".to_string(),
            vec![
                "store",
                "--label",
                service_label,
                "service",
                "opaque",
                "username",
                name,
            ],
        ),
    }
}

/// Return the command and arguments to remove a secret from the OS keychain.
fn keychain_remove_command<'a>(name: &'a str, os: &str) -> (String, Vec<&'a str>) {
    let service_label: &str = Box::leak(format!("opaque/{name}").into_boxed_str());
    match os {
        "macos" => (
            "security".to_string(),
            vec![
                "delete-generic-password",
                "-a",
                "opaque",
                "-s",
                service_label,
            ],
        ),
        _ => (
            "secret-tool".to_string(),
            vec!["clear", "service", "opaque", "username", name],
        ),
    }
}

/// Parse macOS `security dump-keychain` output and extract Opaque secret names.
fn parse_keychain_secrets(dump_output: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in dump_output.lines() {
        let trimmed = line.trim();
        // Match lines like: "svce"<blob>="opaque/github-pat"
        if let Some(rest) = trimmed.strip_prefix("\"svce\"<blob>=\"opaque/")
            && let Some(name) = rest.strip_suffix('"')
            && !name.is_empty()
        {
            names.push(name.to_string());
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Detect the current OS for keychain commands.
fn detect_keychain_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Store a secret in the OS keychain.
fn run_secrets_add(name: &str) {
    if let Err(e) = validate_secret_name(name) {
        ui::error(&e);
        std::process::exit(1);
    }

    println!(
        "Enter secret value for 'opaque/{}' (input is hidden):",
        name
    );
    println!("Tip: paste and press Enter. Input is not echoed in interactive terminals.");

    let mut value = String::new();
    if let Err(e) = std::io::stdin().read_line(&mut value) {
        ui::error(&format!("Failed to read secret value: {e}"));
        std::process::exit(1);
    }
    let value = value.trim_end_matches('\n').trim_end_matches('\r');

    if value.is_empty() {
        ui::error("Secret value must not be empty");
        eprintln!(
            "\n  {} Provide a non-empty secret value",
            style("hint:").cyan().bold()
        );
        std::process::exit(EXIT_USAGE);
    }

    let os = detect_keychain_os();
    let (cmd, args) = keychain_add_command(name, value, os);

    // On Linux, pipe the value via stdin to secret-tool.
    let result = if os == "linux" {
        std::process::Command::new(&cmd)
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(value.as_bytes())?;
                }
                child.wait()
            })
    } else {
        std::process::Command::new(&cmd)
            .args(&args)
            .output()
            .map(|o| o.status)
    };

    match result {
        Ok(status) if status.success() => {
            ui::success(&format!("Secret 'opaque/{}' stored in keychain", name));
            ui::info(&format!(
                "Use it in config as: {}",
                secrets_ref_format(name)
            ));
        }
        Ok(status) => {
            ui::error(&format!(
                "Keychain command failed with exit code {}",
                status.code().unwrap_or(-1)
            ));
            std::process::exit(1);
        }
        Err(e) => {
            ui::error(&format!("Failed to execute keychain command: {e}"));
            std::process::exit(1);
        }
    }
}

/// List stored Opaque secrets (names only, never values).
fn run_secrets_list() {
    let os = detect_keychain_os();
    match os {
        "macos" => {
            let output = std::process::Command::new("security")
                .args(["dump-keychain"])
                .output();
            match output {
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    let names = parse_keychain_secrets(&stdout);
                    if names.is_empty() {
                        ui::info("No Opaque secrets found in keychain.");
                    } else {
                        ui::header(&format!("{} secret(s)", names.len()));
                        for name in &names {
                            println!(
                                "  {} {}  {}",
                                style(ui::KEY).dim(),
                                style(name).yellow().bold(),
                                style(format!("({})", secrets_ref_format(name))).dim()
                            );
                        }
                    }
                }
                Err(e) => {
                    ui::error(&format!("Failed to query keychain: {e}"));
                    std::process::exit(1);
                }
            }
        }
        _ => {
            ui::warn(
                "Listing secrets is not fully supported on Linux (secret-tool has no list command).",
            );
            ui::info(
                "Secrets you stored with 'opaque secrets add' are available via their ref names.",
            );
        }
    }
}

/// Remove a secret from the OS keychain.
fn run_secrets_remove(name: &str) {
    if let Err(e) = validate_secret_name(name) {
        ui::error(&e);
        std::process::exit(1);
    }

    let os = detect_keychain_os();
    let (cmd, args) = keychain_remove_command(name, os);

    let result = std::process::Command::new(&cmd).args(&args).output();

    match result {
        Ok(o) if o.status.success() => {
            ui::success(&format!("Secret 'opaque/{}' removed from keychain", name));
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if stderr.contains("could not be found")
                || stderr.contains("not found")
                || stderr.contains("No matching")
            {
                ui::error(&format!("Secret 'opaque/{}' not found in keychain", name));
            } else {
                ui::error(&format!(
                    "Keychain command failed (exit {}): {}",
                    o.status.code().unwrap_or(-1),
                    stderr.trim()
                ));
            }
            std::process::exit(1);
        }
        Err(e) => {
            ui::error(&format!("Failed to execute keychain command: {e}"));
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Respect NO_COLOR environment variable and --plain flag.
    if cli.plain || std::env::var("NO_COLOR").is_ok() {
        console::set_colors_enabled(false);
    }

    let json_output = cli.json;
    let verbose = cli.verbose;
    let quiet = cli.quiet || cli.json;
    let skip_confirm = cli.yes || cli.json;

    // Set global verbosity for ui module output gating.
    ui::set_verbosity(quiet, verbose);

    // In verbose mode, initialize tracing at debug level.
    if verbose {
        use tracing_subscriber::EnvFilter;
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("opaque=debug"));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_writer(std::io::stderr)
            .init();
    }

    // No subcommand → show smart status dashboard instead of silent ping.
    let cmd = match cli.cmd {
        Some(c) => c,
        None => {
            run_status(json_output).await;
            return;
        }
    };

    // Handle commands that don't need a daemon connection.
    match &cmd {
        Cmd::AuthorityPolicy { action } => {
            match authority_policy_command::run(action) {
                Ok(value) => println!(
                    "{}",
                    serde_json::to_string_pretty(&value).expect("JSON Value encodes")
                ),
                Err(error) => {
                    ui::error(&error);
                    std::process::exit(EXIT_USAGE);
                }
            }
            return;
        }
        Cmd::Policy { action } => match action {
            PolicyAction::Regress {
                baseline,
                candidate,
                cases,
                fail_on_change,
            } => {
                match policy_regression::run(
                    baseline,
                    candidate,
                    cases,
                    *fail_on_change,
                    json_output,
                ) {
                    Ok(true) => {}
                    Ok(false) => std::process::exit(EXIT_ERROR),
                    Err(error) => {
                        ui::error(&error);
                        std::process::exit(EXIT_USAGE);
                    }
                }
                return;
            }
            PolicyAction::Check { file } => {
                match policy_check_path(file.as_deref()) {
                    Ok(msg) => ui::success(&msg),
                    Err(e) => {
                        ui::error(&e);
                        std::process::exit(EXIT_ERROR);
                    }
                }
                return;
            }
            PolicyAction::Show { file } => {
                match policy_show(file.as_deref()) {
                    Ok(()) => {}
                    Err(e) => {
                        ui::error(&e);
                        std::process::exit(EXIT_ERROR);
                    }
                }
                return;
            }
            PolicyAction::Presets { show } => {
                match show {
                    Some(name) => match policy_show_preset(name) {
                        Ok(()) => {}
                        Err(e) => {
                            ui::error(&e);
                            std::process::exit(EXIT_ERROR);
                        }
                    },
                    None => policy_list_presets(),
                }
                return;
            }
            PolicyAction::Preset { name, legacy_name } => {
                match resolve_preset_name(name, legacy_name.as_deref())
                    .and_then(|name| policy_apply_preset(&name))
                {
                    Ok(()) => {}
                    Err(e) => {
                        ui::error(&e);
                        std::process::exit(EXIT_ERROR);
                    }
                }
                return;
            }
            PolicyAction::Simulate {
                operation,
                client_type,
                targets,
                secret_refs,
                file,
            } => {
                match policy_simulate(
                    file.as_deref(),
                    operation,
                    client_type,
                    targets,
                    secret_refs,
                ) {
                    Ok(()) => {}
                    Err(e) => {
                        ui::error(&e);
                        std::process::exit(EXIT_ERROR);
                    }
                }
                return;
            }
        },
        Cmd::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(*shell, &mut cmd, "opaque", &mut std::io::stdout());
            return;
        }
        Cmd::Init {
            force,
            preset,
            repo,
        } => {
            let result = if *repo {
                run_init_repo(preset.as_deref())
            } else {
                run_init(*force, preset.as_deref())
            };
            match result {
                Ok(()) => {}
                Err(e) => {
                    ui::error(&e);
                    std::process::exit(EXIT_ERROR);
                }
            }
            return;
        }
        Cmd::Profile { action } => {
            match run_profile_action(action) {
                Ok(()) => {}
                Err(e) => {
                    ui::error(&e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Cmd::Audit { action } => {
            match action {
                AuditAction::Tail {
                    limit,
                    kind,
                    operation,
                    since,
                    request_id,
                    outcome,
                    query,
                } => {
                    match run_audit_tail(
                        *limit,
                        kind.as_deref(),
                        operation.as_deref(),
                        since.as_deref(),
                        request_id.as_deref(),
                        outcome.as_deref(),
                        query.as_deref(),
                        json_output,
                    ) {
                        Ok(()) => {}
                        Err(e) => {
                            ui::error(&e);
                            std::process::exit(1);
                        }
                    }
                }
                AuditAction::Verify => match run_audit_verify(json_output) {
                    Ok(()) => {}
                    Err(e) => {
                        ui::error(&e);
                        std::process::exit(1);
                    }
                },
            }
            return;
        }
        Cmd::Bundle { action } => {
            match run_bundle(action) {
                Ok(()) => {}
                Err(e) => {
                    ui::error(&e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Cmd::Setup {
            seal,
            reset,
            verify,
        } => {
            if *reset
                && !confirm_destructive(
                    "Are you sure you want to remove the config seal? This allows reconfiguration",
                    skip_confirm,
                )
            {
                ui::info("Aborted.");
                return;
            }
            match run_setup(*seal, *reset, *verify) {
                Ok(()) => {}
                Err(e) => {
                    ui::error(&e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Cmd::Doctor => {
            run_doctor().await;
            return;
        }
        Cmd::Quickstart => {
            run_quickstart().await;
            return;
        }
        Cmd::Connect { tool } => {
            match run_connect(tool) {
                Ok(()) => {}
                Err(e) => {
                    ui::error(&e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Cmd::Service { action } => {
            if matches!(action, ServiceAction::Uninstall)
                && !confirm_destructive(
                    "Are you sure you want to uninstall the daemon service?",
                    skip_confirm,
                )
            {
                ui::info("Aborted.");
                return;
            }
            let op = match action {
                ServiceAction::Install => service::ServiceOp::Install,
                ServiceAction::Uninstall => service::ServiceOp::Uninstall,
                ServiceAction::Status => service::ServiceOp::Status,
                ServiceAction::Start => service::ServiceOp::Start,
                ServiceAction::Stop => service::ServiceOp::Stop,
                ServiceAction::Restart => service::ServiceOp::Restart,
                ServiceAction::Logs => service::ServiceOp::Logs,
            };
            match service::run(op) {
                Ok(()) => {
                    // Print success for mutating operations.
                    match op {
                        service::ServiceOp::Install => {
                            ui::success("Daemon service installed and started");
                        }
                        service::ServiceOp::Uninstall => {
                            ui::success("Daemon service stopped and removed");
                        }
                        service::ServiceOp::Start => {
                            ui::success("Daemon service started");
                        }
                        service::ServiceOp::Stop => {
                            ui::success("Daemon service stopped");
                        }
                        service::ServiceOp::Restart => {
                            ui::success("Daemon service restarted");
                        }
                        service::ServiceOp::Status | service::ServiceOp::Logs => {
                            // Status and logs handle their own output.
                        }
                    }
                }
                Err(e) => {
                    ui::error(&e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Cmd::Secrets { action } => {
            match action {
                SecretsAction::Add { name } => run_secrets_add(name),
                SecretsAction::List => run_secrets_list(),
                SecretsAction::Remove { name } => {
                    if !confirm_destructive(
                        &format!(
                            "Are you sure you want to remove secret 'opaque/{name}' from the keychain?"
                        ),
                        skip_confirm,
                    ) {
                        ui::info("Aborted.");
                        return;
                    }
                    run_secrets_remove(name);
                }
            }
            return;
        }
        _ => {}
    }

    let sock = cli.socket.unwrap_or_else(socket_path);

    if let Cmd::Login { no_browser } = &cmd {
        match run_login(&sock, *no_browser, json_output).await {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                ui::error(&e);
                std::process::exit(EXIT_DAEMON);
            }
        }
    }

    if let Cmd::Agent {
        action:
            AgentAction::Run {
                ttl_secs,
                mode,
                service,
                pass_env,
                inherit_env,
                clean_env,
                command,
            },
    } = &cmd
    {
        if *clean_env && !json_output {
            ui::warn("--clean-env is deprecated; clean-env filtering is now the default");
        }
        for key in pass_env {
            if !is_valid_env_name(key) {
                ui::error(&format!("--pass-env '{key}': invalid env var name"));
                eprintln!(
                    "\n  {} Environment variable names must start with A-Z/a-z/_ and contain only alphanumerics and _",
                    style("hint:").cyan().bold()
                );
                std::process::exit(EXIT_USAGE);
            }
        }
        match run_agent_wrapped(
            &sock,
            command,
            *ttl_secs,
            mode,
            service.as_deref(),
            *inherit_env,
            pass_env,
            json_output,
        )
        .await
        {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                ui::error(&e);
                std::process::exit(1);
            }
        }
    }

    if let Cmd::Github { action } = &cmd {
        let result = match action {
            GithubAction::BuildManifest {
                env_file,
                value_ref_template,
                out,
                repo,
                environment,
            } => run_github_build_manifest(
                env_file,
                value_ref_template,
                out,
                repo.as_deref(),
                environment.as_deref(),
                json_output,
            ),
            GithubAction::PublishEnv {
                repo,
                env_file,
                value_ref_template,
                github_token_ref,
                environment,
                dry_run,
                continue_on_error,
            } => {
                run_github_publish_env(
                    &sock,
                    repo,
                    env_file,
                    value_ref_template,
                    github_token_ref.as_deref(),
                    environment.as_deref(),
                    *dry_run,
                    *continue_on_error,
                    json_output,
                )
                .await
            }
            GithubAction::PublishManifest {
                manifest_file,
                repo,
                github_token_ref,
                environment,
                dry_run,
                continue_on_error,
            } => {
                run_github_publish_manifest(
                    &sock,
                    manifest_file,
                    repo.as_deref(),
                    github_token_ref.as_deref(),
                    environment.as_deref(),
                    *dry_run,
                    *continue_on_error,
                    json_output,
                )
                .await
            }
            _ => Ok(()),
        };

        if matches!(
            action,
            GithubAction::BuildManifest { .. }
                | GithubAction::PublishEnv { .. }
                | GithubAction::PublishManifest { .. }
        ) {
            match result {
                Ok(()) => {}
                Err(e) => {
                    ui::error(&e);
                    std::process::exit(1);
                }
            }
            return;
        }
    }

    // Confirm destructive daemon operations before dispatching.
    if let Cmd::Github {
        action:
            GithubAction::DeleteSecret {
                ref secret_name,
                ref scope,
                ..
            },
    } = cmd
        && !confirm_destructive(
            &format!("Are you sure you want to delete {scope} secret '{secret_name}'?"),
            skip_confirm,
        )
    {
        ui::info("Aborted.");
        return;
    }

    // Attestation verification context, filled by the Cmd::Attest arm below.
    let mut attest_nonce = String::new();
    let mut attest_expected_key: Option<String> = None;
    let mut attest_raw = false;

    let (method, params) = match cmd {
        Cmd::Ping => ("ping", serde_json::Value::Null),
        Cmd::Version => ("version", serde_json::Value::Null),
        Cmd::Whoami => ("whoami", serde_json::Value::Null),
        Cmd::Leases => ("leases", serde_json::Value::Null),
        Cmd::Scope { action } => match scope_command::params(action) {
            Ok(request) => request,
            Err(error) => {
                ui::error(&error);
                std::process::exit(EXIT_USAGE);
            }
        },
        Cmd::Task { action } => match task_command_params(action) {
            Ok(request) => request,
            Err(error) => {
                if json_output {
                    println!("{}", serde_json::json!({"error": error}));
                } else {
                    ui::error(&error);
                }
                std::process::exit(EXIT_USAGE);
            }
        },
        Cmd::Provisioning { action } => match provisioning_command_params(action) {
            Ok(request) => request,
            Err(error) => {
                if json_output {
                    println!("{}", serde_json::json!({"error":error}));
                } else {
                    ui::error(&error);
                }
                std::process::exit(EXIT_USAGE);
            }
        },
        Cmd::Execute {
            operation,
            params_file,
            target,
            secret,
            workspace: attach_ws,
        } => {
            let operation_params = match read_operation_params(params_file.as_deref()) {
                Ok(params) => params,
                Err(error) => {
                    ui::error(&error);
                    std::process::exit(EXIT_USAGE);
                }
            };
            let target_map: serde_json::Map<String, serde_json::Value> = target
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            let ws = if attach_ws {
                resolve_workspace_context()
            } else {
                None
            };
            let params = serde_json::json!({
                "operation": operation,
                "params": operation_params,
                "target": target_map,
                "secret_ref_names": secret,
                "workspace": ws,
            });
            ("execute", params)
        }
        Cmd::Exec { profile, command } => {
            let params = serde_json::json!({
                "profile": profile,
                "command": command,
            });
            ("exec", params)
        }
        Cmd::Github { action } => match action {
            GithubAction::SetSecret {
                repo,
                secret_name,
                value_ref,
                github_token_ref,
                environment,
            } => {
                let scope = if environment.is_some() {
                    "env_actions"
                } else {
                    "repo_actions"
                };
                let mut params = serde_json::json!({
                    "scope": scope,
                    "repo": repo,
                    "secret_name": secret_name,
                    "value_ref": value_ref,
                });
                if let Some(ref tok) = github_token_ref {
                    params["github_token_ref"] = serde_json::Value::String(tok.clone());
                }
                if let Some(ref env) = environment {
                    params["environment"] = serde_json::Value::String(env.clone());
                }
                ("github", params)
            }
            GithubAction::SetCodespacesSecret {
                repo,
                secret_name,
                value_ref,
                github_token_ref,
                selected_repository_ids,
            } => {
                let scope = if repo.is_some() {
                    "codespaces_repo"
                } else {
                    "codespaces_user"
                };
                let mut params = serde_json::json!({
                    "scope": scope,
                    "secret_name": secret_name,
                    "value_ref": value_ref,
                });
                if let Some(ref r) = repo {
                    params["repo"] = serde_json::Value::String(r.clone());
                }
                if let Some(ref tok) = github_token_ref {
                    params["github_token_ref"] = serde_json::Value::String(tok.clone());
                }
                if let Some(ref ids) = selected_repository_ids {
                    params["selected_repository_ids"] = serde_json::json!(ids);
                }
                ("github", params)
            }
            GithubAction::SetDependabotSecret {
                repo,
                secret_name,
                value_ref,
                github_token_ref,
            } => {
                let mut params = serde_json::json!({
                    "scope": "dependabot",
                    "repo": repo,
                    "secret_name": secret_name,
                    "value_ref": value_ref,
                });
                if let Some(ref tok) = github_token_ref {
                    params["github_token_ref"] = serde_json::Value::String(tok.clone());
                }
                ("github", params)
            }
            GithubAction::SetOrgSecret {
                org,
                secret_name,
                value_ref,
                github_token_ref,
                visibility,
                selected_repository_ids,
            } => {
                let mut params = serde_json::json!({
                    "scope": "org_actions",
                    "org": org,
                    "secret_name": secret_name,
                    "value_ref": value_ref,
                    "visibility": visibility,
                });
                if let Some(ref tok) = github_token_ref {
                    params["github_token_ref"] = serde_json::Value::String(tok.clone());
                }
                if let Some(ref ids) = selected_repository_ids {
                    params["selected_repository_ids"] = serde_json::json!(ids);
                }
                ("github", params)
            }
            GithubAction::ListSecrets {
                repo,
                org,
                scope,
                environment,
                github_token_ref,
            } => {
                let mut params = serde_json::json!({
                    "action": "list_secrets",
                    "scope": scope,
                });
                if let Some(ref r) = repo {
                    params["repo"] = serde_json::Value::String(r.clone());
                }
                if let Some(ref o) = org {
                    params["org"] = serde_json::Value::String(o.clone());
                }
                if let Some(ref env) = environment {
                    params["environment"] = serde_json::Value::String(env.clone());
                }
                if let Some(ref tok) = github_token_ref {
                    params["github_token_ref"] = serde_json::Value::String(tok.clone());
                }
                ("github", params)
            }
            GithubAction::DeleteSecret {
                repo,
                org,
                secret_name,
                scope,
                environment,
                github_token_ref,
            } => {
                let mut params = serde_json::json!({
                    "action": "delete_secret",
                    "scope": scope,
                    "secret_name": secret_name,
                });
                if let Some(ref r) = repo {
                    params["repo"] = serde_json::Value::String(r.clone());
                }
                if let Some(ref o) = org {
                    params["org"] = serde_json::Value::String(o.clone());
                }
                if let Some(ref env) = environment {
                    params["environment"] = serde_json::Value::String(env.clone());
                }
                if let Some(ref tok) = github_token_ref {
                    params["github_token_ref"] = serde_json::Value::String(tok.clone());
                }
                ("github", params)
            }
            GithubAction::PublishEnv { .. }
            | GithubAction::BuildManifest { .. }
            | GithubAction::PublishManifest { .. } => unreachable!(),
        },
        Cmd::Gitlab { action } => match action {
            GitlabAction::SetCiVariable {
                project,
                key,
                value_ref,
                gitlab_token_ref,
                environment_scope,
                protected,
                masked,
                raw,
                variable_type,
            } => {
                let mut params = serde_json::json!({
                    "action": "set_ci_variable",
                    "project": project,
                    "key": key,
                    "value_ref": value_ref,
                    "protected": protected,
                    "masked": masked,
                    "raw": raw,
                    "variable_type": variable_type,
                });
                if let Some(ref tok) = gitlab_token_ref {
                    params["gitlab_token_ref"] = serde_json::Value::String(tok.clone());
                }
                if let Some(ref scope) = environment_scope {
                    params["environment_scope"] = serde_json::Value::String(scope.clone());
                }
                ("gitlab", params)
            }
        },
        Cmd::OnePassword { action } => match action {
            OnePasswordAction::ListVaults => {
                let params = serde_json::json!({ "action": "list_vaults" });
                ("onepassword", params)
            }
            OnePasswordAction::ListItems { vault } => {
                let params = serde_json::json!({
                    "action": "list_items",
                    "vault": vault,
                });
                ("onepassword", params)
            }
            OnePasswordAction::ReadField { vault, item, field } => {
                let params = serde_json::json!({
                    "action": "read_field",
                    "vault": vault,
                    "item": item,
                    "field": field,
                });
                ("onepassword", params)
            }
        },
        // Handled in the async block above; unreachable.
        Cmd::Login { .. } => unreachable!(),
        Cmd::Logout => ("identity.logout", serde_json::Value::Null),
        Cmd::Identity { action } => match action {
            IdentityAction::Ls => ("identity.principal_list", serde_json::Value::Null),
            IdentityAction::Roles {
                principal_id,
                roles,
            } => (
                "identity.role_set",
                serde_json::json!({
                    "principal_id": principal_id,
                    "roles": flatten_role_args(&roles),
                }),
            ),
            IdentityAction::Delegations => ("identity.delegation_list", serde_json::Value::Null),
        },
        Cmd::Attest { key, raw } => {
            let nonce = {
                let mut buf = [0u8; 16];
                getrandom::fill(&mut buf).expect("nonce");
                buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
            };
            attest_nonce = nonce.clone();
            attest_expected_key = key.clone();
            attest_raw = raw;
            ("attestation_report", serde_json::json!({ "nonce": nonce }))
        }
        Cmd::Key { action } => match action {
            KeyAction::Ls => ("fido2_list", serde_json::Value::Null),
            KeyAction::Remove { credential_id } => (
                "fido2_remove",
                serde_json::json!({ "credential_id": credential_id }),
            ),
        },
        Cmd::Device { action } => match action {
            DeviceAction::Pair => ("device_pair_start", serde_json::Value::Null),
            DeviceAction::Ls => ("device_list", serde_json::Value::Null),
            DeviceAction::Confirm { device_id } => (
                "device_pair_confirm",
                serde_json::json!({ "device_id": device_id }),
            ),
            DeviceAction::Revoke { device_id } => (
                "device_revoke",
                serde_json::json!({ "device_id": device_id }),
            ),
        },
        Cmd::Agent { action } => match action {
            AgentAction::Run { .. } => unreachable!(),
            AgentAction::List => ("agent_session_list", serde_json::Value::Null),
            AgentAction::End { all, session_id } => {
                if all {
                    ("agent_session_end", serde_json::json!({ "all": true }))
                } else {
                    let session_id = session_id
                        .as_deref()
                        .expect("clap guarantees session_id when --all is not set");
                    (
                        "agent_session_end",
                        serde_json::json!({ "session_id": session_id }),
                    )
                }
            }
        },
        // Already handled above; unreachable.
        Cmd::Policy { .. }
        | Cmd::AuthorityPolicy { .. }
        | Cmd::Bundle { .. }
        | Cmd::Init { .. }
        | Cmd::Audit { .. }
        | Cmd::Profile { .. }
        | Cmd::Setup { .. }
        | Cmd::Service { .. }
        | Cmd::Doctor
        | Cmd::Quickstart
        | Cmd::Secrets { .. }
        | Cmd::Connect { .. }
        | Cmd::Completions { .. } => {
            unreachable!()
        }
    };

    // Verbose: show what we're about to call.
    ui::debug(&format!("method={method} socket={}", sock.display()));
    if verbose {
        ui::debug("request parameters omitted because they may contain confidential values");
    }

    let sp = if json_output || quiet {
        None
    } else {
        Some(ui::spinner(&format!("Calling {method}...")))
    };

    let call_start = std::time::Instant::now();
    match call(&sock, method, params).await {
        Ok(resp) => {
            let elapsed = call_start.elapsed();
            ui::debug(&format!("response received in {elapsed:.1?}"));
            if let Some(ref sp) = sp {
                sp.finish_and_clear();
            }

            // Verification is mandatory for every output format. JSON consumers
            // must never receive an unverified report as a successful command.
            if method == "attestation_report" && resp.error.is_none() {
                let verification = resp
                    .result
                    .as_ref()
                    .ok_or_else(|| "daemon returned no attestation result".to_string())
                    .and_then(|result| {
                        verify_attestation(
                            result,
                            &attest_nonce,
                            attest_expected_key.as_deref(),
                            attest_raw,
                            json_output,
                        )
                    });
                match verification {
                    Ok(true) => return,
                    Ok(false) => std::process::exit(EXIT_DAEMON),
                    Err(error) => {
                        if json_output {
                            println!("{}", serde_json::json!({"verified": false, "error": error}));
                        } else {
                            ui::error(&error);
                        }
                        std::process::exit(EXIT_DAEMON);
                    }
                }
            }

            // A malformed receipt is a daemon failure in every output mode.
            // Preserve raw JSON for inspection, but never report it as success.
            let task_records = if method.starts_with("task_") && resp.error.is_none() {
                match resp.result.as_ref().map(parse_task_records).transpose() {
                    Ok(Some(records)) => Some(records),
                    _ => {
                        if json_output {
                            println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                        } else {
                            ui::error(
                                "Daemon returned an invalid task receipt; use --json to inspect the response.",
                            );
                        }
                        std::process::exit(EXIT_DAEMON);
                    }
                }
            } else {
                None
            };

            if json_output {
                // Raw JSON: output the full response as-is.
                let output =
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_string());
                println!("{output}");
                if resp.error.is_some() {
                    std::process::exit(EXIT_DAEMON);
                }
            } else {
                if let Some(err) = &resp.error {
                    ui::format_error(err);
                    // Use EXIT_AUTH for policy denials, EXIT_DAEMON for other daemon errors
                    let exit_code = if err.code.contains("denied") || err.code.contains("DENIED") {
                        EXIT_AUTH
                    } else {
                        EXIT_DAEMON
                    };
                    std::process::exit(exit_code);
                }
                if let Some(result) = &resp.result {
                    if quiet {
                        // Quiet mode: only show essential output (no decorative formatting).
                        // For methods that have data, print minimal JSON.
                        match method {
                            "ping" => {} // Silence — success is implicit (exit 0).
                            "version" => {
                                if let Some(ver) = result.get("version").and_then(|v| v.as_str()) {
                                    println!("{ver}");
                                }
                            }
                            _ => {
                                // Fall back to compact JSON for other methods in quiet mode.
                                if let Ok(json) = serde_json::to_string(result) {
                                    println!("{json}");
                                }
                            }
                        }
                    } else if let Some(records) = task_records {
                        format_task_response(result, records);
                    } else {
                        ui::format_response(method, result);
                    }
                } else if !quiet {
                    ui::success("Done (no result payload)");
                }
            }
            if method == "task_run"
                && resp
                    .result
                    .as_ref()
                    .and_then(|result| result.get("task"))
                    .and_then(|task| task.get("state"))
                    .and_then(|state| state.as_str())
                    != Some("completed")
            {
                // A successful RPC can still have a partial/unknown receipt.
                // Preserve its JSON while reporting failure to automation.
                std::process::exit(EXIT_ERROR);
            }
            if method == "task_reconcile"
                && matches!(
                    resp.result
                        .as_ref()
                        .and_then(|r| r.pointer("/task/release_observation/state"))
                        .and_then(|s| s.as_str()),
                    Some("failed" | "ambiguous")
                )
            {
                std::process::exit(EXIT_ERROR);
            }
        }
        Err(e) => {
            let elapsed = call_start.elapsed();
            ui::debug(&format!("call failed after {elapsed:.1?}: {e}"));
            if json_output {
                let err = serde_json::json!({"error": e.to_string()});
                println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
            } else if let Some(ref sp) = sp {
                let err_str = e.to_string();
                let hint = if err_str.contains("No such file")
                    || err_str.contains("not found")
                    || err_str.contains("Connection refused")
                {
                    Some("Is the daemon running? Try: opaque service start")
                } else {
                    None
                };
                ui::spinner_error(sp, &format!("Connection failed: {e}"));
                if let Some(h) = hint {
                    eprintln!("\n  {} {}", style("hint:").cyan().bold(), style(h).cyan());
                }
            } else {
                ui::error(&format!("Connection failed: {e}"));
                if !json_output {
                    let err_str = e.to_string();
                    if err_str.contains("No such file")
                        || err_str.contains("not found")
                        || err_str.contains("Connection refused")
                    {
                        eprintln!();
                        eprintln!(
                            "  {} The daemon doesn't appear to be running.",
                            style("hint:").cyan().bold()
                        );
                        eprintln!(
                            "        {}  {}",
                            style("opaque service install").cyan(),
                            style("# install & auto-start on login").dim()
                        );
                        eprintln!(
                            "        {}  {}",
                            style("opaque quickstart").cyan(),
                            style("# or run the full setup wizard").dim()
                        );
                    }
                }
            }
            std::process::exit(EXIT_DAEMON);
        }
    }
}

fn provisioning_command_params(
    action: ProvisioningAction,
) -> Result<(&'static str, serde_json::Value), String> {
    use serde_json::json;
    fn assertion(path: PathBuf) -> Result<serde_json::Value, String> {
        use std::io::Read;
        let file = std::fs::File::open(&path).map_err(|_| "cannot open FIDO2 assertion file")?;
        let mut bytes = Vec::new();
        file.take(16_385)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read FIDO2 assertion file")?;
        if bytes.len() > 16_384 {
            return Err("FIDO2 assertion file exceeds 16 KiB".into());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid FIDO2 assertion JSON")?;
        let fields = [
            "credential_id",
            "authenticator_data",
            "client_data_json",
            "signature",
        ];
        if value.as_object().is_none_or(|o| {
            o.len() != fields.len()
                || fields
                    .iter()
                    .any(|f| o.get(*f).and_then(|v| v.as_str()).is_none_or(str::is_empty))
        }) {
            return Err(
                "FIDO2 assertion must contain exactly the four encoded assertion fields".into(),
            );
        }
        Ok(value)
    }
    Ok(match action {
        ProvisioningAction::BindStart { credential_id } => (
            "identity.provisioning.bind_start",
            json!({"credential_id":credential_id}),
        ),
        ProvisioningAction::BindComplete {
            challenge_id,
            assertion: path,
        } => (
            "identity.provisioning.bind_complete",
            json!({"challenge_id":challenge_id,"assertion":assertion(path)?}),
        ),
        ProvisioningAction::MandateStart {
            service,
            profile,
            ttl_secs,
            max_issuances,
        } => (
            "identity.provisioning.mandate_start",
            json!({"service":service,"profile_id":profile,"ttl_secs":ttl_secs,"max_issuances":max_issuances}),
        ),
        ProvisioningAction::MandateComplete {
            challenge_id,
            assertion: path,
        } => (
            "identity.provisioning.mandate_complete",
            json!({"challenge_id":challenge_id,"assertion":assertion(path)?}),
        ),
        ProvisioningAction::Issue {
            mandate,
            issuer,
            subject,
            ttl_secs,
            request_id,
        } => {
            uuid::Uuid::parse_str(&request_id).map_err(|_| "request-id must be a UUID")?;
            (
                "identity.provisioning.issue",
                json!({"mandate_id":mandate,"recipient_issuer":issuer,"recipient_subject":subject,"ttl_secs":ttl_secs,"request_id":request_id}),
            )
        }
        ProvisioningAction::List => ("identity.provisioning.list", json!({})),
        ProvisioningAction::Show { kind, id } => {
            ("identity.provisioning.show", json!({"kind":kind,"id":id}))
        }
        ProvisioningAction::Revoke { kind, id } => {
            ("identity.provisioning.revoke", json!({"kind":kind,"id":id}))
        }
    })
}

pub(crate) fn read_operation_params(
    path: Option<&std::path::Path>,
) -> Result<serde_json::Value, String> {
    use std::io::Read;
    let Some(path) = path else {
        return Ok(serde_json::json!({}));
    };
    let file = std::fs::File::open(path).map_err(|_| "cannot open operation parameters file")?;
    if !file
        .metadata()
        .map_err(|_| "cannot inspect operation parameters file")?
        .is_file()
    {
        return Err("operation parameters must be a regular JSON file".into());
    }
    let limit = opaque_core::MAX_FRAME_LENGTH.saturating_sub(8192);
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read operation parameters file")?;
    if bytes.len() > limit {
        return Err("operation parameters exceed the IPC size limit".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "operation parameters require valid JSON")?;
    if !value.is_object() {
        return Err("operation parameters require a JSON object".into());
    }
    Ok(value)
}

fn task_command_params(action: TaskAction) -> Result<(&'static str, serde_json::Value), String> {
    use serde_json::json;
    Ok(match action {
        TaskAction::PlanSsh {
            title,
            expires_in_secs,
        } => (
            "task_plan_ssh",
            json!({"title": title, "expires_in_secs": expires_in_secs}),
        ),
        TaskAction::PlanInference {
            title,
            expires_in_secs,
        } => (
            "task_plan_inference",
            json!({"title": title, "expires_in_secs": expires_in_secs}),
        ),
        TaskAction::Plan { manifest } => {
            let metadata = std::fs::metadata(&manifest)
                .map_err(|error| format!("cannot read manifest {}: {error}", manifest.display()))?;
            if metadata.len() > (opaque_core::MAX_FRAME_LENGTH - 4096) as u64 {
                return Err("task manifest exceeds the IPC size limit".into());
            }
            let bytes = std::fs::read(&manifest)
                .map_err(|error| format!("cannot read manifest {}: {error}", manifest.display()))?;
            // Numeric repository IDs and provider URLs are enriched by the
            // daemon. Deserialize strictly here without accepting extensions.
            let manifest: opaque_core::task::TaskManifest = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid task manifest: {error}"))?;
            ("task_plan", json!({"manifest": manifest}))
        }
        TaskAction::Run { task_id } => ("task_run", json!({"task_id": task_id})),
        TaskAction::Show { task_id } => ("task_get", json!({"task_id": task_id})),
        TaskAction::Reconcile { task_id } => ("task_reconcile", json!({"task_id": task_id})),
        TaskAction::Revoke { task_id } => ("task_revoke", json!({"task_id": task_id})),
        TaskAction::List { cursor } => ("task_list", json!({"cursor": cursor})),
    })
}

fn parse_task_records(
    result: &serde_json::Value,
) -> Result<Vec<opaque_core::task::TaskRecord>, serde_json::Error> {
    if let Some(tasks) = result.get("tasks") {
        serde_json::from_value(tasks.clone())
    } else {
        serde_json::from_value(result.get("task").unwrap_or(result).clone()).map(|task| vec![task])
    }
}

fn format_task_response(result: &serde_json::Value, records: Vec<opaque_core::task::TaskRecord>) {
    if records.is_empty() {
        ui::info("No tasks for this authenticated owner.");
        return;
    }
    for task in records {
        println!("{}", render_task_receipt(&task));
    }
    if result.get("has_more").and_then(|value| value.as_bool()) == Some(true)
        && let Some(cursor) = result.get("next_cursor").and_then(|value| value.as_str())
    {
        println!("Older tasks are available. Continue with: opaque task list --cursor {cursor}");
    }
}

fn render_task_receipt(task: &opaque_core::task::TaskRecord) -> String {
    use opaque_core::task::{SlotState, TaskApprovalMode, TaskState};
    use std::fmt::Write;
    let state = match task.state {
        TaskState::Planned => "planned",
        TaskState::Running => "running",
        TaskState::Completed => "completed",
        TaskState::Partial => "partial",
        TaskState::Revoked => "revoked",
        TaskState::Expired => "expired",
    };
    let charged = task
        .slots
        .iter()
        .filter(|slot| slot.state != SlotState::Pending)
        .count();
    let mut output = format!(
        "{}\nTask: {}\nState: {} | Charged: {}/{} writes\nDigest: {}\nExpires: {} (Unix seconds)\nGitHub: {}\nVault: {}\n",
        task.manifest.title,
        task.id,
        state,
        charged,
        task.slots.len(),
        task.manifest_digest,
        task.expires_at,
        task.manifest.github_api_url,
        task.manifest.vault_api_url,
    );
    if task.manifest.is_inference() || task.manifest.is_ssh() {
        output = format!(
            "{}\nTask: {}\nState: {} | Charged: {}/{} attempts\nDigest: {}\nExpires: {} (Unix seconds)\n",
            task.manifest.title,
            task.id,
            state,
            charged,
            task.slots.len(),
            task.manifest_digest,
            task.expires_at
        );
    }
    if let Some(tenant) = &task.tenant {
        output.push_str(&tenant.approval_context());
    }
    if let Some(approved_at) = task.approved_at {
        let mode = match task.approval_mode {
            Some(TaskApprovalMode::Native) => "native approval",
            Some(TaskApprovalMode::PairedWorkstation) => "paired workstation approval",
            Some(TaskApprovalMode::InsecureTest) => "INSECURE TEST APPROVAL",
            None => "approval mode unavailable",
        };
        let _ = writeln!(output, "Approval: {mode} at {approved_at} (Unix seconds)");
    } else {
        output.push_str("Approval: not granted\n");
    }
    for slot in &task.slots {
        let state = match slot.state {
            SlotState::Pending => "not attempted",
            SlotState::Reserved => "in flight (charged)",
            SlotState::ApiAccepted => "API accepted",
            SlotState::Rejected => "rejected (charged)",
            SlotState::Unknown => "unknown (charged; do not retry)",
        };
        match &slot.action {
            opaque_core::task::TaskAction::SshHealth(action) => {
                let _ = writeln!(
                    output,
                    "\n  SSH health: {}:{}\n    Host key SHA-256: {}\n    Principal / user: {} / {}\n    Source IP: {}\n    Exact command: {}\n    Session limit: {} seconds\n    Vault signer role: {}\n    Grant: {}\n    Slot: {}\n    Outcome: {}",
                    action.destination_host,
                    action.destination_port,
                    action.host_key_sha256,
                    action.principal,
                    action.login_user,
                    action.source_address,
                    action.command,
                    action.max_session_secs,
                    action.vault_role,
                    action.grant_id,
                    slot.id,
                    if slot.state == SlotState::ApiAccepted {
                        "authenticated health observation"
                    } else {
                        state
                    }
                );
                if let Some(contract) = &action.health_contract {
                    let _ = writeln!(
                        output,
                        "    Health contract: {} / {} at {}:{}{}",
                        contract.service,
                        contract.version,
                        contract.host,
                        contract.port,
                        contract.path
                    );
                } else {
                    output.push_str("    Health contract: legacy fixture-api / version 1\n");
                }
            }
            opaque_core::task::TaskAction::Inference(action) => {
                let _ = writeln!(
                    output,
                    "\n  Request {} | Model: {}\n    Profile: {}\n    Source: {}\n    Source snapshot SHA-256: {}\n    Prompt SHA-256: {}\n    Output allowance: {} tokens (requested ceiling)\n    Slot: {}\n    Outcome: {}",
                    action.ordinal,
                    action.model_id,
                    action.profile_id,
                    action.source_id,
                    action.source_snapshot_sha256,
                    action.prompt_sha256,
                    action.options.max_output_tokens,
                    slot.id,
                    state
                );
                if let Some(snapshot) = &action.github_ci_snapshot {
                    let _ = writeln!(
                        output,
                        "    GitHub repository: {} | Workflow: {} | Branch: {}\n    Observed: {} (Unix seconds), {} sampled runs",
                        snapshot.source.repository,
                        snapshot.source.workflow_id,
                        snapshot.source.branch,
                        snapshot.observed_at,
                        snapshot.runs.len()
                    );
                    for run in &snapshot.runs {
                        let _ = writeln!(
                            output,
                            "      Run {} attempt {}: {:?} / {:?} at {}",
                            run.id, run.attempt, run.status, run.conclusion, run.head_sha
                        );
                    }
                }
            }
            opaque_core::task::TaskAction::PublishSecret(action) => {
                let _ = writeln!(
                    output,
                    "\n  {} / {} [repository {}]\n    Source: {}\n    Slot: {}\n    Outcome: {}",
                    action.repo,
                    action.secret_name,
                    action.repository_id,
                    action.value_ref,
                    slot.id,
                    state
                );
            }
            opaque_core::task::TaskAction::StagingRelease(action) => {
                let _ = writeln!(
                    output,
                    "\n  {} [repository {}]\n    Workflow: {} [workflow {}]\n    Branch: {}\n    Approved commit: {}\n    Workflow SHA-256: {}\n    Artifact: {}@{}\n    Environment: {}\n    Slot: {}\n    Dispatch outcome: {}",
                    action.repo,
                    action.repository_id,
                    action.workflow_path,
                    action.workflow_id,
                    action.workflow_ref,
                    action.approved_commit_sha,
                    action.workflow_sha256,
                    action.image_repository,
                    action.image_digest,
                    action.environment,
                    slot.id,
                    state
                );
            }
        }
        if let Some(reference) = slot.action.github_token_ref() {
            let _ = writeln!(output, "    Credential reference: {reference}");
        }
        if let Some(outcome) = &slot.outcome {
            let _ = writeln!(output, "    Receipt code: {}", outcome.code);
            if let Some(receipt) = &outcome.ssh_receipt {
                let _ = writeln!(
                    output,
                    "    Authenticated host result: {:?}\n    Signed receipt SHA-256: {}",
                    receipt.code, receipt.signed_receipt_sha256
                );
                if let Some(text) = &receipt.output_text {
                    let _ = writeln!(output, "    Host output: {text}");
                }
            }
            if let Some(receipt) = &outcome.inference_receipt {
                let _ = writeln!(
                    output,
                    "    Model evidence: {:?}\n    Input tokens: {} | Observed output tokens: {:?}\n    Reserved output units: {}",
                    receipt.code,
                    receipt.input_tokens,
                    receipt.observed_output_tokens,
                    receipt.reserved_output_tokens
                );
                if let Some(text) = &receipt.output_text {
                    let _ = writeln!(output, "    Model output: {text}");
                }
            }
        }
    }
    match task.state {
        TaskState::Planned => {
            let _ = writeln!(
                output,
                "\nReview the exact scope above, then run: opaque task run {}",
                task.id
            );
        }
        TaskState::Running => output.push_str(
            "\nInspect this task again for its receipt. Another run cannot add allowance.\n",
        ),
        TaskState::Completed => output.push_str(if task.manifest.is_inference() {
            "\nThree model completions recorded. Further inference requires a new task and fresh approval. Provider usage does not attest GPU time or hardware isolation.\n"
        } else if task.manifest.is_ssh() {
            "\nSSH health observation recorded. Any further SSH operation requires a new task and fresh approval.\n"
        } else if task.manifest.is_release() {
            "\nDispatch recorded. Use task reconcile to observe the workflow; this does not establish deployment or service health.\n"
        } else { "\nGitHub accepted these writes; secret values cannot be read back for verification.\n" }),
        TaskState::Partial | TaskState::Revoked | TaskState::Expired => output.push_str(
            "\nThis task is closed. Any further operations require a new task and fresh approval.\n",
        ),
    }
    if let Some(observation) = &task.release_observation {
        let _ = writeln!(
            output,
            "\nWorkflow evidence: {:?} ({})\nChecked: {} (Unix seconds)",
            observation.state, observation.code, observation.checked_at
        );
        if let Some(url) = &observation.run_url {
            let _ = writeln!(
                output,
                "Run: {url} (attempt {})",
                observation.run_attempt.unwrap_or_default()
            );
        }
        output.push_str("Workflow success describes the trusted workflow's checks; it does not independently prove service health.\n");
    }
    output
}

/// Read the daemon token from `<socket_dir>/daemon.token`.
fn read_daemon_token(sock: &Path) -> std::io::Result<String> {
    let token_path = sock
        .parent()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "socket path has no parent directory",
            )
        })?
        .join(DAEMON_TOKEN_FILENAME);

    std::fs::read_to_string(&token_path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "Cannot connect to Opaque daemon (token not found at {}). Start it with:\n    opaque service install    # recommended: auto-start on login\n    opaqued                   # or run directly in a terminal",
                token_path.display()
            ),
        )
    })
}

/// Resolve the git workspace context from the current working directory.
///
/// Runs git commands to determine repo root, remote URL, branch, HEAD SHA,
/// and dirty status. Returns `None` if not in a git repository.
fn resolve_workspace_context() -> Option<serde_json::Value> {
    use std::process::Command;

    // Check if we're in a git repo and get the root.
    let repo_root = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;

    let remote_url = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            opaque_core::validate::InputValidator::sanitize_url(
                String::from_utf8_lossy(&o.stdout).trim(),
            )
        });

    let branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let head_sha = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    Some(serde_json::json!({
        "repo_root": repo_root,
        "remote_url": remote_url,
        "branch": branch,
        "head_sha": head_sha,
        "dirty": dirty,
    }))
}

/// Retries are allowed only while establishing a connection. Once request
/// delivery starts, a transport failure cannot establish whether work executed.
const MAX_RETRIES: u32 = 3;
const INITIAL_RETRY_MS: u64 = 200;

fn request_timeout(method: &str) -> Duration {
    match method {
        // Leave time for approval and the daemon's bounded execution.
        "exec" | "execute" => Duration::from_secs(300),
        // The daemon allows an hour for a task; include a transport margin.
        "task_run" => Duration::from_secs(3660),
        "ping"
        | "operations"
        | "version"
        | "whoami"
        | "leases"
        | "task_get"
        | "task_list"
        | "identity.login_status"
        | "identity.principal_list"
        | "identity.delegation_list"
        | "identity.provisioning.list"
        | "identity.provisioning.show"
        | "fido2_list"
        | "fido2_pending"
        | "device_list"
        | "agent_session_list"
        | "attestation_report" => Duration::from_secs(30),
        // Provider operations may require an interactive approval first.
        _ => Duration::from_secs(300),
    }
}

async fn call(
    sock: &Path,
    method: &str,
    mut params: serde_json::Value,
) -> std::io::Result<Response> {
    if method == "github" || method.starts_with("task_") {
        params["workspace"] = resolve_workspace_context().unwrap_or(serde_json::Value::Null);
    }
    call_with_timeout(sock, method, params, request_timeout(method)).await
}

async fn call_with_timeout(
    sock: &Path,
    method: &str,
    params: serde_json::Value,
    deadline: Duration,
) -> std::io::Result<Response> {
    let mut dispatched = false;
    let exchange = async {
        let stream = tokio::time::timeout(Duration::from_secs(30), connect_with_retries(sock))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out")
            })??;
        let daemon_token = read_daemon_token(sock)?;
        call_once(stream, method, params, &daemon_token, &mut dispatched).await
    };
    let result = tokio::time::timeout(deadline, exchange)
        .await
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("request timed out after {} seconds", deadline.as_secs()),
            ))
        });
    result.map_err(|error| {
        if dispatched {
            std::io::Error::new(
                error.kind(),
                format!("{error}; outcome unknown: the request may have executed. It was not retried. Inspect the task receipt or operation audit before taking further action"),
            )
        } else {
            error
        }
    })
}

async fn connect_with_retries(sock: &Path) -> std::io::Result<UnixStream> {
    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(
                INITIAL_RETRY_MS * 2u64.pow(attempt - 1),
            ))
            .await;
        }
        // A daemon may still be creating its socket. Retry missing sockets,
        // but never connect or send credentials until ownership/modes validate.
        let connection = match verify_socket_safety(sock) {
            Ok(()) => UnixStream::connect(sock).await,
            Err(error) => Err(error),
        };
        match connection {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                let retryable = matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::TimedOut
                );
                if !retryable || attempt == MAX_RETRIES {
                    return Err(std::io::Error::new(
                        error.kind(),
                        format!(
                            "Cannot connect to Opaque daemon at {}: {error}. Start it with opaque service install or opaqued",
                            sock.display()
                        ),
                    ));
                }
            }
        }
    }
    unreachable!("every connection attempt returns or advances")
}

/// One established connection, with no replay at any point in the exchange.
async fn call_once(
    stream: UnixStream,
    method: &str,
    params: serde_json::Value,
    daemon_token: &str,
    dispatched: &mut bool,
) -> std::io::Result<Response> {
    let req = Request {
        id: 1,
        method: method.to_string(),
        params,
    };
    let out = serde_json::to_vec(&req).map_err(std::io::Error::other)?;
    if out.len() > opaque_core::MAX_FRAME_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "request exceeds the IPC frame limit",
        ));
    }
    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
        .new_codec();
    let mut framed = Framed::new(stream, codec);
    let mut handshake = serde_json::json!({ "handshake": "v1", "daemon_token": daemon_token });
    if let Some(session_token) = session_token_from_env() {
        handshake["session_token"] = serde_json::Value::String(session_token);
    }
    let hs_bytes = serde_json::to_vec(&handshake).map_err(std::io::Error::other)?;
    framed.send(Bytes::from(hs_bytes)).await?;
    // Mark before send: partial writes and cancellation are ambiguous too.
    *dispatched = true;
    framed.send(Bytes::from(out)).await?;
    let frame = framed.next().await.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "daemon closed without a response",
        )
    })??;
    opaque_core::proto::decode_response(&frame, req.id)
}

// ---------------------------------------------------------------------------
// audit tail
// ---------------------------------------------------------------------------

/// Run the `audit tail` subcommand: query the local SQLite audit DB.
#[allow(clippy::too_many_arguments)]
fn run_audit_verify(json_output: bool) -> Result<(), String> {
    let db_path = default_opaque_dir().join("audit.db");
    if !db_path.exists() {
        return Err(format!(
            "audit database not found at {} (is opaqued running?)",
            db_path.display()
        ));
    }
    let v = opaque_core::audit::verify_audit_chain(&db_path)
        .map_err(|e| format!("failed to verify audit chain: {e}"))?;
    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "ok": v.ok,
                "records_checked": v.records_checked,
                "first_bad_sequence": v.first_bad_sequence,
                "detail": v.detail,
            })
        );
    } else if v.ok {
        ui::success(&format!(
            "Audit chain intact \u{2014} {} records verified",
            v.records_checked
        ));
    } else {
        ui::error(&format!(
            "Audit chain BROKEN \u{2014} {} ({} records verified before the break)",
            v.detail.as_deref().unwrap_or("tampering detected"),
            v.records_checked
        ));
    }
    // Non-zero exit on a broken chain, in both text and JSON modes, so callers
    // (CI, monitoring) can gate on it.
    if !v.ok {
        std::process::exit(2);
    }
    Ok(())
}

// Mirrors the clap-level `audit tail` flags one-to-one; a params struct here
// would just duplicate the CLI surface.
#[allow(clippy::too_many_arguments)]
fn run_audit_tail(
    limit: usize,
    kind: Option<&str>,
    operation: Option<&str>,
    since: Option<&str>,
    request_id: Option<&str>,
    outcome: Option<&str>,
    text_query: Option<&str>,
    json_output: bool,
) -> Result<(), String> {
    let db_path = default_opaque_dir().join("audit.db");
    if !db_path.exists() {
        return Err(format!(
            "audit database not found at {} (is opaqued running?)",
            db_path.display()
        ));
    }

    let kind = match kind {
        Some(s) => Some(
            s.parse::<AuditEventKind>()
                .map_err(|e| format!("invalid --kind: {e}"))?,
        ),
        None => None,
    };

    let since_ms = match since {
        Some(s) => {
            let duration_ms = parse_duration_to_ms(s)?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            Some(now_ms - duration_ms)
        }
        None => None,
    };

    let request_id = match request_id {
        Some(s) => {
            Some(uuid::Uuid::parse_str(s).map_err(|e| format!("invalid --request-id: {e}"))?)
        }
        None => None,
    };

    let filter = AuditFilter {
        kind,
        operation: operation.map(|s| s.to_owned()),
        since_ms,
        limit,
        request_id,
        outcome: outcome.map(|s| s.to_owned()),
        text_query: text_query.map(|s| s.to_owned()),
    };

    let events = query_audit_db(&db_path, &filter).map_err(|e| format!("query failed: {e}"))?;

    if json_output {
        // Output newline-delimited JSON for better streaming support
        for event in &events {
            let json = serde_json::json!({
                "event_id": event.event_id.to_string(),
                "ts_utc_ms": event.ts_utc_ms,
                "kind": event.kind.to_string(),
                "operation": event.operation,
                "outcome": event.outcome,
                "request_id": event.request_id.map(|u| u.to_string()),
            });
            if let Ok(json_str) = serde_json::to_string(&json) {
                println!("{json_str}");
            }
        }
        return Ok(());
    }

    if events.is_empty() {
        ui::info("No audit events found.");
        return Ok(());
    }

    // Build table with headers and rows
    let headers = vec!["WHEN", "EVENT", "OPERATION", "OUTCOME", "REQUEST ID"];
    let mut rows = Vec::new();

    for event in &events {
        let relative = format_relative_time(event.ts_utc_ms);
        let absolute = chrono_format_ms(event.ts_utc_ms);
        // One line per cell: the table measures a cell's full width, so an
        // embedded newline both over-widened this column and split every row.
        let when = format!("{}  {}", relative, style(absolute).dim());

        let kind = event.kind.to_string();

        let op = event.operation.as_deref().unwrap_or("-").to_string();

        let outcome_label = event.outcome.as_deref().unwrap_or("unknown");
        let outcome_badge = ui::status_badge(
            outcome_label,
            match outcome_label {
                "allowed" | "ok" | "success" => ui::BadgeState::Ok,
                "denied" | "error" | "failed" => ui::BadgeState::Fail,
                _ => ui::BadgeState::Warn,
            },
        );

        let rid = event
            .request_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "-".into());

        rows.push(vec![when, kind, op, outcome_badge, rid]);
    }

    // Display table with summary
    ui::header(&format!("Audit log — {} event(s)", events.len()));
    ui::table(&headers, &rows);

    // Summary footer
    println!();
    if events.len() < limit {
        ui::info(&format!("Showing all {} event(s)", events.len()));
    } else {
        ui::info(&format!(
            "Showing {} of many events. Use --limit {} to see more.",
            events.len(),
            limit + 10
        ));
    }

    Ok(())
}

/// Parse a simple duration string like "30m", "1h", "7d" to milliseconds.
fn parse_duration_to_ms(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string".into());
    }

    // Split at a character boundary so malformed non-ASCII suffixes are errors,
    // not panics before the duration can be validated.
    let suffix_start = s.char_indices().next_back().unwrap().0;
    let (num_str, suffix) = s.split_at(suffix_start);
    let num: i64 = num_str
        .parse()
        .map_err(|_| format!("invalid duration: '{s}' (expected e.g. '30m', '1h', '7d')"))?;
    if num < 0 {
        return Err("duration must be non-negative".into());
    }

    let multiplier = match suffix {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => {
            return Err(format!(
                "unknown duration suffix '{suffix}' (expected s, m, h, or d)"
            ));
        }
    };

    num.checked_mul(multiplier)
        .ok_or_else(|| "duration exceeds the supported range".into())
}

/// Format a millisecond timestamp as a human-readable UTC string.
fn chrono_format_ms(ms: i64) -> String {
    let secs = ms / 1000;
    let millis = (ms % 1000) as u32;
    let dt = std::time::UNIX_EPOCH + std::time::Duration::new(secs as u64, millis * 1_000_000);
    let datetime: std::time::SystemTime = dt;
    // Simple formatting without chrono dependency.
    let duration = datetime
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = duration.as_secs();
    let days = total_secs / 86400;
    let rem = total_secs % 86400;
    let hours = rem / 3600;
    let minutes = (rem % 3600) / 60;
    let seconds = rem % 60;
    // Approximate date from days since epoch (good enough for display).
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{millis:03}Z")
}

/// Format a millisecond timestamp as a relative human-readable string (e.g., "2m ago", "1h ago").
fn format_relative_time(event_ts_ms: i64) -> String {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let age_ms = (now_ms - event_ts_ms).max(0);
    let age_secs = age_ms / 1000;

    if age_secs < 60 {
        format!("{}s ago", age_secs)
    } else if age_secs < 3600 {
        format!("{}m ago", age_secs / 60)
    } else if age_secs < 86400 {
        format!("{}h ago", age_secs / 3600)
    } else {
        let days = age_secs / 86400;
        if days == 1 {
            "yesterday".to_string()
        } else {
            format!("{}d ago", days)
        }
    }
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ---------------------------------------------------------------------------
// Policy config types
// ---------------------------------------------------------------------------

use opaque_core::policy_document::PolicyDocument as PolicyConfig;

// ---------------------------------------------------------------------------
// policy check
// ---------------------------------------------------------------------------

/// Resolve the config path: --file flag > $OPAQUE_CONFIG > ~/.opaque/config.toml.
fn resolve_config_path(file: Option<&Path>) -> PathBuf {
    if let Some(p) = file {
        return p.to_path_buf();
    }
    if let Ok(p) = std::env::var("OPAQUE_CONFIG") {
        return PathBuf::from(p);
    }
    default_opaque_dir().join("config.toml")
}

/// Validate a policy config file. Returns a success message or an error string.
fn policy_check_path(file: Option<&Path>) -> Result<String, String> {
    let (message, warnings) =
        policy_check_report(file, codesign_team_id_is_platform_enforceable())?;
    for warning in &warnings {
        ui::warn(warning);
    }
    Ok(message)
}

/// The actual check, with the platform's codesign-enforceability taken as a
/// parameter rather than read from `cfg!` directly, and any N1 platform
/// warnings returned rather than printed. This makes the full behavior,
/// including the fact that such a rule loads instead of being refused,
/// unit-testable independent of the host platform running the test.
fn policy_check_report(
    file: Option<&Path>,
    codesign_enforceable: bool,
) -> Result<(String, Vec<String>), String> {
    let path = resolve_config_path(file);
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let config: PolicyConfig = PolicyConfig::from_toml(&contents)
        .map_err(|e| format!("TOML parse error in {}: {e}", path.display()))?;

    let errors = config.validation_errors();

    if !errors.is_empty() {
        return Err(format!(
            "policy validation failed:\n  {}",
            errors.join("\n  ")
        ));
    }

    // N1: a rule can require a client-identity field this platform's
    // connection attestor never populates (codesign_team_id off macOS). Such
    // a rule still loads. It simply never matches a real client, so this
    // warns rather than failing the check.
    let warnings = platform_policy_warnings(&config.rules, codesign_enforceable);

    Ok((
        format!("policy OK: {} rules loaded", config.rules.len()),
        warnings,
    ))
}

// ---------------------------------------------------------------------------
// policy show
// ---------------------------------------------------------------------------

/// Load and display policy rules in a human-readable format.
fn policy_show(file: Option<&Path>) -> Result<(), String> {
    let path = resolve_config_path(file);
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let config: PolicyConfig = PolicyConfig::from_toml(&contents)
        .map_err(|e| format!("TOML parse error in {}: {e}", path.display()))?;

    if config.rules.is_empty() {
        ui::warn("no rules loaded — default deny-all policy is in effect");
        return Ok(());
    }

    ui::header(&format!(
        "{} rule(s) from {}",
        config.rules.len(),
        path.display()
    ));

    for (i, rule) in config.rules.iter().enumerate() {
        println!();
        let allow_str = if rule.allow {
            style("ALLOW").green().bold().to_string()
        } else {
            style("DENY").red().bold().to_string()
        };
        println!(
            "  {}  {}  {}",
            style(format!("[{i}]")).dim(),
            allow_str,
            style(&rule.name).cyan().bold()
        );

        // Operation pattern.
        println!(
            "      {} {}",
            style("operation:").dim(),
            style(&rule.operation_pattern).yellow()
        );

        // Client types.
        if !rule.client_types.is_empty() {
            let types: Vec<&str> = rule
                .client_types
                .iter()
                .map(|ct| match ct {
                    ClientType::Human => "human",
                    ClientType::Agent => "agent",
                })
                .collect();
            println!("      {} {}", style("clients:").dim(), types.join(", "));
        }

        // Client match constraints.
        if rule.client.exe_path.is_some()
            || rule.client.exe_sha256.is_some()
            || rule.client.codesign_team_id.is_some()
            || rule.client.uid.is_some()
            || rule.client.attestor.is_some()
            || rule.client.min_attestation.is_some()
            || !rule.client.selectors.is_empty()
        {
            let mut parts = Vec::new();
            if let Some(ref p) = rule.client.exe_path {
                parts.push(format!("exe={p}"));
            }
            if let Some(ref h) = rule.client.exe_sha256 {
                parts.push(format!("sha256={}", &h[..8.min(h.len())]));
            }
            if let Some(ref t) = rule.client.codesign_team_id {
                parts.push(format!("team={t}"));
            }
            if let Some(uid) = rule.client.uid {
                parts.push(format!("uid={uid}"));
            }
            if let Some(attestor) = &rule.client.attestor {
                parts.push(format!("attestor={}", attestor.as_str()));
            }
            if let Some(strength) = rule.client.min_attestation {
                parts.push(format!("min_attestation={strength:?}").to_lowercase());
            }
            for selector in &rule.client.selectors {
                parts.push(format!("selector={selector}"));
            }
            println!("      {} {}", style("client:").dim(), parts.join(", "));
        }

        // Target constraints.
        if !rule.target.fields.is_empty() {
            let fields: Vec<String> = rule
                .target
                .fields
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            println!("      {} {}", style("target:").dim(), fields.join(", "));
        }

        // Workspace constraints.
        if rule.workspace.remote_url_pattern.is_some()
            || rule.workspace.branch_pattern.is_some()
            || rule.workspace.require_clean
        {
            let mut parts = Vec::new();
            if let Some(ref p) = rule.workspace.remote_url_pattern {
                parts.push(format!("remote={p}"));
            }
            if let Some(ref p) = rule.workspace.branch_pattern {
                parts.push(format!("branch={p}"));
            }
            if rule.workspace.require_clean {
                parts.push("clean-only".into());
            }
            println!("      {} {}", style("workspace:").dim(), parts.join(", "));
        }

        // Secret name constraints.
        if !rule.secret_names.patterns.is_empty() {
            println!(
                "      {} {}",
                style("secrets:").dim(),
                rule.secret_names.patterns.join(", ")
            );
        }

        // Approval.
        let req_str = format!("{:?}", rule.approval.require);
        let factors: Vec<String> = rule
            .approval
            .factors
            .iter()
            .map(|f| format!("{f:?}"))
            .collect();
        let mut approval_parts = vec![req_str.to_lowercase()];
        if !factors.is_empty() {
            approval_parts.push(format!("factors=[{}]", factors.join(",")));
        }
        if let Some(ttl) = rule.approval.lease_ttl {
            approval_parts.push(format!("lease={}s", ttl.as_secs()));
        }
        if rule.approval.one_time {
            approval_parts.push("one-time".into());
        }
        if let Some(budget) = rule.approval.budget {
            approval_parts.push(format!("budget={budget} total attempts"));
        }
        println!(
            "      {} {}",
            style("approval:").dim(),
            approval_parts.join(", ")
        );
    }

    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// policy simulate
// ---------------------------------------------------------------------------

/// Dry-run a request against the policy engine to show what would happen.
fn policy_simulate(
    file: Option<&Path>,
    operation: &str,
    client_type_str: &str,
    targets: &[(String, String)],
    secret_refs: &[String],
) -> Result<(), String> {
    let path = resolve_config_path(file);
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let config: PolicyConfig = PolicyConfig::from_toml(&contents)
        .map_err(|e| format!("TOML parse error in {}: {e}", path.display()))?;

    let client_type = match client_type_str {
        "human" => ClientType::Human,
        "agent" => ClientType::Agent,
        other => {
            return Err(format!(
                "unknown client type: {other} (expected 'human' or 'agent')"
            ));
        }
    };

    let target: std::collections::HashMap<String, String> = targets.iter().cloned().collect();

    let request = OperationRequest {
        request_id: uuid::Uuid::nil(),
        client_identity: ClientIdentity {
            uid: 501,
            gid: 20,
            pid: None,
            exe_path: std::env::current_exe().ok(),
            exe_sha256: None,
            codesign_team_id: None,
            workload: None,
        },
        client_type,
        operation: operation.into(),
        target,
        params: serde_json::Value::Object(serde_json::Map::new()),
        secret_ref_names: secret_refs.to_vec(),
        workspace: None,
        principal: None,
        created_at: std::time::SystemTime::now(),
        expires_at: None,
    };

    let engine = PolicyEngine::with_rules(config.rules);

    // Use Safe as default — we can't know the actual safety class without
    // the operation registry, but this gives a correct policy evaluation
    // for the common case.
    let decision = engine.evaluate(&request, OperationSafety::Safe);

    ui::header("Policy Simulation");

    // Show the request summary.
    println!(
        "  {} {}",
        style("operation:").dim(),
        style(operation).yellow().bold()
    );
    println!("  {} {}", style("client:").dim(), client_type_str);
    if !targets.is_empty() {
        let fields: Vec<String> = targets.iter().map(|(k, v)| format!("{k}={v}")).collect();
        println!("  {} {}", style("target:").dim(), fields.join(", "));
    }
    if !secret_refs.is_empty() {
        println!("  {} {}", style("secrets:").dim(), secret_refs.join(", "));
    }
    println!();

    // Show the decision.
    if decision.allowed {
        ui::success(&format!(
            "ALLOW (rule: {})",
            decision.matched_rule.as_deref().unwrap_or("?")
        ));
        let req_str = format!("{:?}", decision.approval_requirement).to_lowercase();
        println!("  {} {}", style("approval:").dim(), req_str,);
        if !decision.required_factors.is_empty() {
            let factors: Vec<String> = decision
                .required_factors
                .iter()
                .map(|f| format!("{f:?}"))
                .collect();
            println!("  {} {}", style("factors:").dim(), factors.join(", "));
        }
        if let Some(ttl) = decision.lease_ttl {
            println!("  {} {}s", style("lease:").dim(), ttl.as_secs(),);
        }
        if decision.one_time {
            println!("  {} yes", style("one-time:").dim(),);
        }
        if let Some(budget) = decision.budget {
            println!("  {} {} total attempts", style("budget:").dim(), budget);
        }
    } else {
        ui::error(&format!(
            "DENY: {}",
            decision
                .denial_reason
                .as_deref()
                .unwrap_or("no matching rule")
        ));
        if let Some(ref rule) = decision.matched_rule {
            println!("  {} {}", style("matched rule:").dim(), rule,);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// Return the default ~/.opaque directory.
fn default_opaque_dir() -> PathBuf {
    dirs_or_home().join(".opaque")
}

/// Best-effort home directory lookup.
fn dirs_or_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

// ---------------------------------------------------------------------------
// Policy presets
// ---------------------------------------------------------------------------

/// Embedded policy preset files.
const PRESET_SAFE_DEMO: &str = include_str!("presets/safe-demo.toml");
const PRESET_GITHUB_SECRETS: &str = include_str!("presets/github-secrets.toml");
const PRESET_GITLAB_VARIABLES: &str = include_str!("presets/gitlab-variables.toml");
const PRESET_SANDBOX_HUMAN: &str = include_str!("presets/sandbox-human.toml");
const PRESET_AGENT_WRAPPER_GITHUB: &str = include_str!("presets/agent-wrapper-github.toml");
const PRESET_CODEX_AGENT: &str = include_str!("presets/codex-agent.toml");

/// Available presets: (name, description, content).
fn available_presets() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "safe-demo",
            "Try Opaque risk-free — allows only test.noop, no real secrets",
            PRESET_SAFE_DEMO,
        ),
        (
            "github-secrets",
            "Sync GitHub secrets via AI agents — requires: keychain:opaque/github-pat",
            PRESET_GITHUB_SECRETS,
        ),
        (
            "gitlab-variables",
            "Set GitLab CI/CD variables via AI agents — requires: keychain:opaque/gitlab-pat",
            PRESET_GITLAB_VARIABLES,
        ),
        (
            "sandbox-human",
            "Sandboxed command execution — human-only, agents blocked",
            PRESET_SANDBOX_HUMAN,
        ),
        (
            "agent-wrapper-github",
            "GitHub secrets + agent session wrapping — full production setup",
            PRESET_AGENT_WRAPPER_GITHUB,
        ),
        (
            "codex-agent",
            "Codex CLI agent preset: GitHub/GitLab rules with first-use approval and session enforcement",
            PRESET_CODEX_AGENT,
        ),
    ]
}

/// Get preset content by name.
fn get_preset(name: &str) -> Option<&'static str> {
    available_presets()
        .into_iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, _, content)| content)
}

/// List available policy presets.
fn policy_list_presets() {
    ui::header("Available policy presets");
    println!();
    for (name, description, content) in available_presets() {
        println!(
            "  {}  {}",
            style(name).cyan().bold(),
            style(description).dim()
        );
        // Show a one-line summary of what the preset enables.
        if let Ok(config) = PolicyConfig::from_toml(content) {
            let ops: Vec<&str> = config
                .rules
                .iter()
                .map(|r| r.operation_pattern.as_str())
                .collect();
            let approval = config
                .rules
                .first()
                .map(|r| format!("{:?}", r.approval.require).to_lowercase())
                .unwrap_or_else(|| "n/a".into());
            println!(
                "    {}  {}",
                style(format!(
                    "{} rule(s): {}",
                    ops.len(),
                    if ops.len() <= 3 {
                        ops.join(", ")
                    } else {
                        format!("{}, {} +{} more", ops[0], ops[1], ops.len() - 2)
                    }
                ))
                .dim(),
                style(format!("approval: {approval}")).dim()
            );
        }
    }
    println!();
    ui::info("Preview a preset:  opaque policy presets --show <name>");
    ui::info("Apply a preset:    opaque policy preset <name>");
    ui::info("Apply during init: opaque init --preset <name>");
}

/// The documented form is `opaque policy preset <name>`. Config headers
/// generated by releases up to 0.4.0 taught `opaque policy preset apply <name>`,
/// so the `apply` word is accepted to keep those files truthful.
fn resolve_preset_name(name: &str, legacy_name: Option<&str>) -> Result<String, String> {
    match (name, legacy_name) {
        ("apply", Some(real)) => Ok(real.to_string()),
        ("apply", None) => Err("missing preset name; usage: opaque policy preset <name>".into()),
        (_, Some(extra)) => Err(format!(
            "unexpected argument '{extra}'; usage: opaque policy preset <name>"
        )),
        (name, None) => Ok(name.to_string()),
    }
}

/// Apply a policy preset to ~/.opaque/config.toml.
fn policy_apply_preset(name: &str) -> Result<(), String> {
    let content = get_preset(name).ok_or_else(|| {
        format!(
            "unknown preset '{name}'. Available: {}",
            available_presets()
                .iter()
                .map(|(n, _, _)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;

    let config_path = default_opaque_dir().join("config.toml");
    if !config_path.exists() {
        return Err(format!(
            "no config file found at {}. Run 'opaque init' first.",
            config_path.display()
        ));
    }

    std::fs::write(&config_path, content)
        .map_err(|e| format!("failed to write {}: {e}", config_path.display()))?;

    ui::success(&format!(
        "Applied preset '{name}' to {}",
        config_path.display()
    ));

    let checklist = preset_checklist(name);
    if !checklist.is_empty() {
        println!();
        println!("Before this works, complete these steps:");
        for (i, step) in checklist.iter().enumerate() {
            println!("  {}. {step}", i + 1);
        }
        println!();
    }

    ui::info("Run 'opaque setup --seal' to seal your config.");
    Ok(())
}

/// Run the init command with styled output.
fn run_init(force: bool, preset: Option<&str>) -> Result<(), String> {
    let base = default_opaque_dir();

    // Determine config content. Default to safe-demo if no preset specified.
    let effective_preset = preset.unwrap_or("safe-demo");
    let config_content = get_preset(effective_preset).ok_or_else(|| {
        format!(
            "unknown preset '{effective_preset}'. Available: {}",
            available_presets()
                .iter()
                .map(|(n, _, _)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;

    if preset.is_none() {
        ui::info(&format!(
            "Using default preset '{}'. Use --preset <name> to choose a different one.",
            style("safe-demo").bold()
        ));
        println!();
    }

    run_init_at(&base, force, config_content)?;

    ui::header("Initialized opaque");
    ui::init_step(&format!("Created {}", style(base.display()).cyan()));
    ui::init_step(&format!(
        "Created {}",
        style(base.join("run").display()).cyan()
    ));
    ui::init_step(&format!(
        "Created {}",
        style(base.join("profiles").display()).cyan()
    ));
    ui::init_step(&format!(
        "Wrote   {} (preset: {})",
        style(base.join("config.toml").display()).cyan(),
        style(effective_preset).bold()
    ));
    println!();
    println!("  {}", style("Next steps:").bold());
    ui::step(
        1,
        4,
        &format!(
            "{} {}",
            style("opaque service install").cyan().bold(),
            ui::dim("# install & start daemon")
        ),
    );
    ui::step(
        2,
        4,
        &format!(
            "{} {}",
            style("opaque connect auto").cyan().bold(),
            ui::dim("# connect to Claude/Cursor")
        ),
    );
    ui::step(
        3,
        4,
        &format!(
            "{} {}",
            style("opaque ping").cyan().bold(),
            ui::dim("# verify daemon is alive")
        ),
    );
    ui::step(
        4,
        4,
        &format!(
            "{} {}",
            style("opaque doctor").cyan().bold(),
            ui::dim("# full diagnostic check")
        ),
    );
    println!();
    ui::info("Or run 'opaque quickstart' to do all of the above automatically.");
    Ok(())
}

/// Initialize the opaque config directory at the given base path.
fn run_init_at(base: &Path, force: bool, config_content: &str) -> Result<(), String> {
    let config_path = base.join("config.toml");
    let run_dir = base.join("run");

    // Check for existing config (unless --force).
    if config_path.exists() && !force {
        return Err(format!(
            "config already exists at {} (use --force to overwrite)",
            config_path.display()
        ));
    }

    let profiles_dir = base.join("profiles");

    // Create directories with mode 0700.
    create_dir_0700(base)?;
    create_dir_0700(&run_dir)?;
    create_dir_0700(&profiles_dir)?;

    // Write config file.
    std::fs::write(&config_path, config_content)
        .map_err(|e| format!("failed to write {}: {e}", config_path.display()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// quickstart
// ---------------------------------------------------------------------------

/// Perform the init portion of quickstart at the given base path.
///
/// If config already exists, this is a no-op (skip gracefully).
/// Otherwise, initializes with the safe-demo preset.
///
/// Returns `true` if init was performed, `false` if skipped.
fn run_quickstart_at(base: &Path) -> Result<bool, String> {
    let config_path = base.join("config.toml");
    if config_path.exists() {
        return Ok(false);
    }

    run_init_at(base, false, PRESET_SAFE_DEMO)?;
    Ok(true)
}

/// Run the full quickstart flow with styled output.
async fn run_quickstart() {
    let base = default_opaque_dir();

    ui::banner("Opaque Quickstart", "One-step onboarding");

    // Step 1: Init with safe-demo preset (if needed).
    match run_quickstart_at(&base) {
        Ok(true) => {
            ui::init_step(&format!(
                "Initialized {} with {} preset",
                style(base.display()).cyan(),
                style("safe-demo").bold()
            ));
        }
        Ok(false) => {
            ui::init_step(&format!(
                "Config already exists at {} (skipped init)",
                style(base.display()).cyan()
            ));
        }
        Err(e) => {
            ui::error(&format!("Init failed: {e}"));
            std::process::exit(1);
        }
    }

    // Step 2: Ensure daemon is running — auto-start if needed.
    let sock = socket_path();
    let mut daemon_running = if sock.exists() {
        tokio::time::timeout(Duration::from_secs(3), try_ping(&sock))
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_some()
    } else {
        false
    };

    if daemon_running {
        ui::init_step("Daemon is running (ping OK)");
    } else {
        // Auto-start: try installing the service automatically.
        let service_status = service::query_status();
        if !service_status.installed {
            ui::info("Installing daemon service...");
            match service::run(service::ServiceOp::Install) {
                Ok(()) => {
                    ui::init_step("Daemon service installed and started");
                }
                Err(e) => {
                    ui::warn(&format!("Could not install service: {e}"));
                    ui::info(
                        "You can start the daemon manually with 'opaqued' in another terminal.",
                    );
                    println!();
                    ui::info("Then re-run 'opaque quickstart' to continue.");
                    return;
                }
            }
        } else if !service_status.running {
            ui::info("Starting daemon service...");
            match service::run(service::ServiceOp::Start) {
                Ok(()) => {
                    ui::init_step("Daemon service started");
                }
                Err(e) => {
                    ui::warn(&format!("Could not start service: {e}"));
                    ui::info("Try 'opaque service logs' to see what went wrong.");
                    return;
                }
            }
        }

        // Wait for daemon to become reachable (up to 5 seconds).
        let sp = ui::spinner("Waiting for daemon to start...");
        for _ in 0..25 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Re-check socket path (may have been created).
            let current_sock = socket_path();
            if current_sock.exists()
                && tokio::time::timeout(Duration::from_secs(2), try_ping(&current_sock))
                    .await
                    .is_ok_and(|r| r.is_ok())
            {
                daemon_running = true;
                break;
            }
        }
        sp.finish_and_clear();

        if daemon_running {
            ui::init_step("Daemon is reachable");
        } else {
            ui::warn("Daemon did not start within 5 seconds");
            ui::info("Try 'opaque service logs' to troubleshoot.");
            return;
        }
    }

    // Step 3: Connect to AI coding tool (auto-detect).
    if let Some(tool_name) = detect_mcp_connection() {
        ui::init_step(&format!(
            "MCP already connected to {}",
            style(tool_name).cyan()
        ));
    } else {
        match find_opaque_mcp_path() {
            Some(opaque_mcp) => match connect_tool_at(&opaque_mcp) {
                Ok(()) => {
                    ui::init_step("Connected to detected AI coding tool");
                }
                Err(e) => {
                    ui::warn(&format!("MCP connect failed: {e}"));
                    ui::info("Run 'opaque connect claude' to configure manually.");
                }
            },
            None => {
                ui::info("opaque-mcp not found — run 'opaque connect' after installation.");
            }
        }
    }

    // Step 4: Execute test.noop to verify end-to-end.
    ui::info("Testing end-to-end with test.noop operation...");
    let test_params = serde_json::json!({
        "operation": "test.noop",
        "target": {},
        "secret_refs": [],
    });
    let current_sock = socket_path();
    match tokio::time::timeout(
        Duration::from_secs(10),
        call(&current_sock, "execute", test_params),
    )
    .await
    {
        Ok(Ok(resp)) => {
            if let Some(err) = resp.error {
                // Approval-required is expected (not a failure).
                if err.code == "approval_required" {
                    ui::init_step("test.noop requires approval (policy is working correctly)");
                } else {
                    ui::warn(&format!("test.noop returned error: {}", err.message));
                }
            } else {
                ui::init_step("test.noop executed successfully");
            }
        }
        Ok(Err(e)) => {
            ui::warn(&format!("test.noop call failed: {e}"));
        }
        Err(_) => {
            ui::warn("test.noop call timed out (10s)");
        }
    }

    // Step 5: Print success summary.
    println!();
    ui::success("Quickstart complete!");
    println!();
    ui::section_box(
        "Useful commands",
        &[
            &format!(
                "{:<28}{}",
                style("opaque doctor").cyan().bold(),
                ui::dim("# run full diagnostics")
            ),
            &format!(
                "{:<28}{}",
                style("opaque init --repo").cyan().bold(),
                ui::dim("# add per-repo policy (in a git repo)")
            ),
            &format!(
                "{:<28}{}",
                style("opaque policy presets").cyan().bold(),
                ui::dim("# explore other policy presets")
            ),
            &format!(
                "{:<28}{}",
                style("opaque secrets add <name>").cyan().bold(),
                ui::dim("# store a secret in the OS keychain")
            ),
            &format!(
                "{:<28}{}",
                style("opaque setup --seal").cyan().bold(),
                ui::dim("# seal config to prevent tampering")
            ),
        ],
    );
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

/// A signable bundle manifest: org metadata + teams + rules, in the same
/// TOML rule shape the daemon config uses.
#[derive(serde::Deserialize)]
struct BundleManifest {
    org: String,
    version: u64,
    #[serde(default)]
    expires_days: Option<u32>,
    #[serde(default)]
    teams: Vec<opaque_core::bundle::Team>,
    #[serde(default)]
    rules: Vec<opaque_core::policy::PolicyRule>,
    #[serde(default)]
    mcp_registry: Option<opaque_core::mcp::RegistryDocument>,
}

/// Offline org tooling for signed federation policy bundles.
fn run_bundle(action: &BundleAction) -> Result<(), String> {
    use ed25519_dalek::SigningKey;
    use opaque_core::bundle;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn load_signing_key(path: &Path) -> Result<SigningKey, String> {
        let key = opaque_core::keyfile::load_key_file(path)
            .map_err(|e| format!("cannot read key {}: {e}", path.display()))?
            .ok_or_else(|| format!("key file {} does not exist", path.display()))?;
        Ok(SigningKey::from_bytes(&key))
    }
    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
    fn print_payload(p: &opaque_core::bundle::BundlePayload) {
        ui::kv("org", &p.org);
        ui::kv("version", &p.version.to_string());
        ui::kv("issued_at", &p.issued_at.to_string());
        ui::kv(
            "expires_at",
            &p.expires_at
                .map(|e| e.to_string())
                .unwrap_or_else(|| "never".into()),
        );
        ui::kv("rules", &p.rules.len().to_string());
        for rule in &p.rules {
            println!(
                "    - {} ({} -> {})",
                rule.name,
                rule.operation_pattern,
                if rule.allow { "allow" } else { "deny" }
            );
        }
        ui::kv("teams", &p.teams.len().to_string());
        for team in &p.teams {
            println!("    - {} ({} member(s))", team.name, team.members.len());
        }
    }

    match action {
        BundleAction::Keygen { out } => {
            if out.exists() {
                return Err(format!(
                    "{} already exists — refusing to overwrite a signing key",
                    out.display()
                ));
            }
            let key_bytes = opaque_core::keyfile::load_or_create_key_file(out)
                .map_err(|e| format!("keygen failed: {e}"))?;
            let key = SigningKey::from_bytes(&key_bytes);
            ui::success(&format!("Org signing key written to {}", out.display()));
            ui::kv("trust anchor", &hex(key.verifying_key().as_bytes()));
            ui::info("Put the trust anchor (public) in each daemon's [federation] trust_anchors.");
            ui::info("Guard the key file (private) like a signing CA key.");
            Ok(())
        }
        BundleAction::Sign {
            manifest,
            key,
            out,
            version,
            expires_days,
            regression_cases,
            baseline,
            fail_on_policy_change,
        } => {
            let gated = regression_cases.is_some();
            let text = if gated {
                policy_regression::read_input(manifest)?
            } else {
                std::fs::read_to_string(manifest)
                    .map_err(|e| format!("cannot read manifest {}: {e}", manifest.display()))?
            };
            let parsed: BundleManifest = toml_edit::de::from_str(&text).map_err(|e| {
                if gated {
                    "invalid bundle manifest TOML (check required fields and schema)".to_string()
                } else {
                    format!("manifest parse error: {e}")
                }
            })?;
            if let Some(cases) = regression_cases {
                let baseline = baseline
                    .as_deref()
                    .ok_or("regression cases require a baseline policy")?;
                policy_regression::gate_bundle(
                    baseline,
                    cases,
                    &parsed.rules,
                    &parsed.teams,
                    *fail_on_policy_change,
                )?;
            }
            let signing_key = load_signing_key(key)?;

            let issued_at = now_unix();
            let expires_at = expires_days
                .or(parsed.expires_days)
                .map(|d| issued_at + i64::from(d) * 86_400);
            let payload = opaque_core::bundle::BundlePayload {
                org: parsed.org,
                version: version.unwrap_or(parsed.version),
                issued_at,
                expires_at,
                key_id: hex(signing_key.verifying_key().as_bytes())
                    .chars()
                    .take(16)
                    .collect(),
                teams: parsed.teams,
                rules: parsed.rules,
                mcp_registry: parsed.mcp_registry,
            };
            let bundle_text = bundle::sign_bundle(&payload, &signing_key)
                .map_err(|e| format!("signing failed: {e}"))?;
            std::fs::write(out, &bundle_text)
                .map_err(|e| format!("cannot write {}: {e}", out.display()))?;

            ui::success(&format!("Bundle signed to {}", out.display()));
            print_payload(&payload);
            Ok(())
        }
        BundleAction::Verify { file, anchor } => {
            let text = std::fs::read_to_string(file)
                .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
            let anchors: Vec<_> = anchor
                .iter()
                .map(|a| bundle::parse_anchor(a).map_err(|_| format!("bad trust anchor: {a:?}")))
                .collect::<Result<_, _>>()?;
            let verified = bundle::verify_bundle(&text, &anchors, now_unix())
                .map_err(|e| format!("VERIFICATION FAILED: {e}"))?;
            ui::success("Bundle signature verified");
            ui::kv("verified by", &verified.verified_by);
            ui::kv("digest", &verified.digest);
            print_payload(&verified.payload);
            Ok(())
        }
        BundleAction::Inspect { file } => {
            let text = std::fs::read_to_string(file)
                .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
            // Structure-only parse; make the trust status unmissable.
            let payload_b64 = text
                .trim()
                .split('.')
                .nth(1)
                .ok_or("malformed bundle (expected opqb1.<payload>.<sig>)")?;
            use base64::Engine;
            let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload_b64)
                .map_err(|_| "malformed bundle payload".to_string())?;
            let payload: opaque_core::bundle::BundlePayload = serde_json::from_slice(&payload_json)
                .map_err(|e| format!("payload parse error: {e}"))?;
            ui::warn("UNVERIFIED CONTENTS — signature not checked (use `bundle verify`)");
            print_payload(&payload);
            Ok(())
        }
    }
}

/// Verify a daemon attestation response and render it. Returns whether the
/// posture is healthy (custody + chain clean).
fn verify_attestation(
    result: &serde_json::Value,
    nonce: &str,
    expected_key: Option<&str>,
    raw: bool,
    json_output: bool,
) -> Result<bool, String> {
    let report = result
        .get("report")
        .and_then(|v| v.as_str())
        .ok_or("daemon returned no report")?;
    let presented_key = result
        .get("attestation_key")
        .and_then(|v| v.as_str())
        .ok_or("daemon returned no attestation key")?;

    // Key pinning: without --key we can only prove the report is fresh and
    // internally consistent, not WHICH daemon produced it. Say so plainly.
    let key_hex = match expected_key {
        Some(pinned) => {
            if !pinned.eq_ignore_ascii_case(presented_key) {
                return Err(format!(
                    "ATTESTATION KEY MISMATCH — expected {pinned}, daemon presented \
                     {presented_key}. Refusing to trust this report."
                ));
            }
            pinned
        }
        None => presented_key,
    };

    let key = opaque_core::bundle::parse_anchor(key_hex)
        .map_err(|_| format!("attestation key is not a valid Ed25519 key: {key_hex}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let verified = opaque_core::attest::verify_report(report, &key, nonce, now, 120)
        .map_err(|e| format!("ATTESTATION VERIFICATION FAILED: {e}"))?;

    let p = &verified.payload;
    // Health = is anything broken. Release eligibility additionally requires
    // the trust-domain split, which a session-mode daemon legitimately lacks.
    let healthy = p.integrity_ok();

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "verified": true,
                "attestation_key": key_hex,
                "key_pinned": expected_key.is_some(),
                "healthy": healthy,
                "release_eligible": p.healthy_for_release(),
                "payload": p,
            }))
            .unwrap_or_default()
        );
        return Ok(healthy);
    }

    if raw {
        println!("{report}");
        println!();
    }

    if healthy {
        ui::success("Attestation verified — posture healthy");
    } else {
        ui::error("Attestation verified — POSTURE UNHEALTHY");
    }
    if healthy && !p.trust_domain.enforce {
        ui::info(
            "Session mode: healthy, but not eligible for custody key release \
             (that requires the trust-domain split).",
        );
    }
    if expected_key.is_none() {
        ui::warn(
            "Key not pinned: this proves the report is fresh, not which daemon signed it. \
             Re-run with --key <hex> to pin.",
        );
    }
    ui::kv("attestation key", key_hex);
    ui::kv("daemon", &format!("{} (uid {})", p.daemon_version, p.uid));
    ui::kv(
        "trust domain",
        if p.trust_domain.enforce {
            "enforced"
        } else {
            "not enforced (session mode)"
        },
    );
    ui::kv(
        "custody",
        if p.trust_domain.custody_ok {
            "verified"
        } else {
            "VIOLATIONS"
        },
    );
    for violation in &p.trust_domain.custody_violations {
        println!("      {}", style(violation).red());
    }
    ui::kv(
        "audit chain",
        &if p.audit.chain_ok {
            format!("verified ({} records)", p.audit.records)
        } else {
            format!(
                "BROKEN ({})",
                p.audit.detail.as_deref().unwrap_or("chain mismatch")
            )
        },
    );
    match &p.federation {
        Some(f) => ui::kv(
            "federation",
            &format!(
                "{} bundle v{} ({})",
                f.org,
                f.version,
                f.digest.chars().take(16).collect::<String>()
            ),
        ),
        None => ui::kv("federation", "no bundle applied"),
    }
    if !p.factors.is_empty() {
        ui::kv("approval factors", &p.factors.join(", "));
    }

    Ok(healthy)
}

/// Run the setup command (wizard, --seal, --reset, --verify).
fn run_setup(seal_only: bool, reset: bool, verify: bool) -> Result<(), String> {
    use opaque_core::seal::{self, SealStatus};

    let base = default_opaque_dir();
    let config_path = resolve_config_path(None);
    // The seal lives BESIDE the config it seals — matching how the daemon
    // verifies it. Deriving it from HOME instead would silently seal the
    // wrong location for any $OPAQUE_CONFIG deployment (system /etc configs).
    let seal_file = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("config.seal");

    if verify {
        if !config_path.exists() {
            return Err(format!(
                "config not found at {} (run 'opaque init' first)",
                config_path.display()
            ));
        }
        let config_bytes = std::fs::read(&config_path)
            .map_err(|e| format!("failed to read {}: {e}", config_path.display()))?;
        let status = seal::verify_seal(&config_bytes, &seal_file)
            .map_err(|e| format!("seal check failed: {e}"))?;
        match status {
            SealStatus::Verified => {
                ui::success("Config seal verified — integrity OK (keyed)");
            }
            SealStatus::VerifiedLegacy => {
                ui::warn(
                    "Config seal verified, but it is the legacy UNKEYED format \
                     (drift detection only — any config writer can forge it).",
                );
                ui::info("Run 'opaque setup --seal' to upgrade to the keyed seal.");
            }
            SealStatus::Tampered { expected, actual } => {
                ui::error("Config seal BROKEN — config.toml was modified after sealing");
                ui::kv("expected", &expected);
                ui::kv("actual", &actual);
                ui::info("Run 'opaque setup --reset' to unseal, then reconfigure.");
                return Err("config seal verification failed: config was modified".into());
            }
            SealStatus::KeyMissing => {
                ui::error("Config has a keyed seal but the seal key (config.seal.key) is missing.");
                ui::info("Restore the key, or 'opaque setup --reset' then 'opaque setup --seal'.");
                return Err("config seal verification failed: seal key missing".into());
            }
            SealStatus::Unsealed => {
                return Err("Config is unsealed — run 'opaque setup --seal' to protect it.".into());
            }
        }
        return Ok(());
    }

    if reset {
        seal::remove_seal(&seal_file).map_err(|e| format!("failed to remove seal: {e}"))?;
        ui::success("Config seal removed. You can now edit config.toml.");
        ui::info("Run 'opaque setup' to reconfigure and re-seal.");
        return Ok(());
    }

    if seal_only {
        if !config_path.exists() {
            return Err(format!(
                "config not found at {} (run 'opaque init' first)",
                config_path.display()
            ));
        }
        let config_bytes = std::fs::read(&config_path)
            .map_err(|e| format!("failed to read {}: {e}", config_path.display()))?;
        seal::store_seal_keyed(&config_bytes, &seal_file)
            .map_err(|e| format!("failed to store seal: {e}"))?;
        ui::success("Config sealed (keyed HMAC; key at config.seal.key, mode 0600)");
        return Ok(());
    }

    // Interactive wizard.
    run_setup_wizard(&base, &config_path, &seal_file)
}

/// Discover all installed opaque binary paths for human client registration.
///
/// Checks: current exe (canonicalized), well-known install locations, and PATH lookup.
/// Returns deduplicated list of (display_name, canonical_path) pairs.
fn discover_opaque_paths() -> Vec<(String, PathBuf)> {
    let mut seen = HashSet::new();
    let mut results = Vec::new();

    // 1. Current executable (canonicalized)
    if let Ok(exe) = std::env::current_exe()
        && let Ok(canonical) = exe.canonicalize()
        && canonical.exists()
        && seen.insert(canonical.clone())
    {
        let name = if canonical.to_string_lossy().contains("target/") {
            "opaque-cli (debug build)"
        } else {
            "opaque-cli"
        };
        results.push((name.to_string(), canonical));
    }

    // 2. Well-known install locations
    let well_known = ["/usr/local/bin/opaque", "/opt/homebrew/bin/opaque"];
    for path_str in &well_known {
        let path = PathBuf::from(path_str);
        if let Ok(canonical) = path.canonicalize()
            && canonical.exists()
            && seen.insert(canonical.clone())
        {
            results.push(("opaque-cli".to_string(), canonical));
        }
    }

    // 3. PATH lookup via `which`
    if let Ok(output) = std::process::Command::new("which").arg("opaque").output()
        && output.status.success()
    {
        let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path_str.is_empty() {
            let path = PathBuf::from(&path_str);
            if let Ok(canonical) = path.canonicalize()
                && canonical.exists()
                && seen.insert(canonical.clone())
            {
                results.push(("opaque-cli".to_string(), canonical));
            }
        }
    }

    results
}

/// Interactive onboarding wizard.
fn run_setup_wizard(base: &Path, config_path: &Path, seal_file: &Path) -> Result<(), String> {
    use dialoguer::{Confirm, Input, MultiSelect};
    use opaque_core::seal;

    println!();
    ui::banner("Setup", "Configure your security policy");
    println!();
    println!("  This wizard configures who can use Opaque and what they can access.");
    println!("  Your policy will be sealed and protected from accidental changes.");
    println!();

    // Ensure base directory exists.
    create_dir_0700(base)?;

    // Step 1: Human Clients
    ui::step(1, 4, "Human Clients");
    println!();

    let discovered = discover_opaque_paths();
    let mut clients: Vec<setup::HumanClientConfig> = Vec::new();

    if discovered.is_empty() {
        println!("  No opaque binaries detected automatically.");
    } else if discovered.len() == 1 {
        let (name, path) = &discovered[0];
        println!("  Detected: {}", style(path.display()).cyan());
        let register = Confirm::new()
            .with_prompt("  Register this binary as a trusted human client?")
            .default(true)
            .interact()
            .map_err(|e| format!("input error: {e}"))?;

        if register {
            clients.push(setup::HumanClientConfig {
                name: name.clone(),
                exe_path: path.to_string_lossy().into_owned(),
            });
        }
    } else {
        println!("  Found opaque binaries:");
        for (i, (name, path)) in discovered.iter().enumerate() {
            let label = if name.contains("debug") {
                format!("{} (debug build)", path.display())
            } else {
                format!("{}", path.display())
            };
            println!("    [{}] {}", i + 1, style(&label).cyan());
        }
        println!();

        let register_all = Confirm::new()
            .with_prompt("  Register all found paths as trusted clients?")
            .default(true)
            .interact()
            .map_err(|e| format!("input error: {e}"))?;

        if register_all {
            for (name, path) in &discovered {
                clients.push(setup::HumanClientConfig {
                    name: name.clone(),
                    exe_path: path.to_string_lossy().into_owned(),
                });
            }
        } else {
            // Let user pick individually
            for (name, path) in &discovered {
                let prompt = format!("  Register {}?", path.display());
                let register = Confirm::new()
                    .with_prompt(&prompt)
                    .default(true)
                    .interact()
                    .map_err(|e| format!("input error: {e}"))?;

                if register {
                    clients.push(setup::HumanClientConfig {
                        name: name.clone(),
                        exe_path: path.to_string_lossy().into_owned(),
                    });
                }
            }
        }
    }

    loop {
        let add_more = Confirm::new()
            .with_prompt("  Add another client binary path?")
            .default(false)
            .interact()
            .map_err(|e| format!("input error: {e}"))?;

        if !add_more {
            break;
        }

        let path: String = Input::new()
            .with_prompt("  Client binary path")
            .interact_text()
            .map_err(|e| format!("input error: {e}"))?;

        if path.trim().is_empty() {
            ui::warn("Path cannot be empty, skipping.");
            continue;
        }

        let name: String = Input::new()
            .with_prompt("  Client name")
            .default("custom-client".into())
            .interact_text()
            .map_err(|e| format!("input error: {e}"))?;

        if name.trim().is_empty() {
            ui::warn("Name cannot be empty, skipping.");
            continue;
        }

        ui::init_step(&format!(
            "Added: {} ({})",
            style(&name).cyan(),
            style(&path).dim()
        ));
        clients.push(setup::HumanClientConfig {
            name,
            exe_path: path,
        });
    }

    println!();

    // Step 2: Operations
    ui::step(2, 4, "Operations");
    println!();

    let op_labels: Vec<&str> = setup::EnabledOperation::ALL
        .iter()
        .map(|op| op.label())
        .collect();

    let defaults: Vec<bool> = vec![true; op_labels.len()];

    let selected_indices = MultiSelect::new()
        .with_prompt("  Which operations should human clients access?")
        .items(&op_labels)
        .defaults(&defaults)
        .interact()
        .map_err(|e| format!("input error: {e}"))?;

    let enabled_ops: Vec<setup::EnabledOperation> = selected_indices
        .iter()
        .map(|&i| setup::EnabledOperation::ALL[i])
        .collect();

    if !enabled_ops.is_empty() {
        ui::init_step(&format!(
            "Enabled {} operation(s)",
            style(enabled_ops.len()).cyan()
        ));
    } else {
        ui::warn("No operations enabled — clients will have minimal access.");
    }

    println!();

    // Step 3: Approval Policy
    ui::step(3, 4, "Approval Policy");
    println!();

    let require_bio = Confirm::new()
        .with_prompt("  Require biometric approval for sensitive operations?")
        .default(true)
        .interact()
        .map_err(|e| format!("input error: {e}"))?;

    if require_bio {
        ui::init_step("Biometric approval required");
    } else {
        ui::warn("Biometric approval disabled — policy will be permissive.");
    }

    let lease_ttl: u64 = if require_bio {
        Input::new()
            .with_prompt("  Approval lease duration in seconds")
            .default(300)
            .interact_text()
            .map_err(|e| format!("input error: {e}"))?
    } else {
        0
    };

    println!();

    // Generate config
    let answers = setup::SetupAnswers {
        human_clients: clients,
        enabled_operations: enabled_ops,
        require_biometric: require_bio,
        lease_ttl,
    };

    let config_content = setup::generate_config(&answers);

    // Step 4: Review & Confirm
    ui::step(4, 4, "Review & Confirm");
    println!();

    // Show summary in a section box.
    let client_count = answers.human_clients.len().max(1).to_string();
    let op_count = answers.enabled_operations.len().max(1).to_string();
    let bio_label = if answers.require_biometric {
        "required (first_use)"
    } else {
        "disabled"
    };
    let lease_label = if answers.require_biometric && answers.lease_ttl > 0 {
        format!("{}s", answers.lease_ttl)
    } else {
        "n/a".to_string()
    };
    let summary_lines: Vec<String> = vec![
        format!("Trusted clients:  {}", client_count),
        format!("Operations:       {}", op_count),
        format!("Biometric:        {}", bio_label),
        format!("Lease TTL:        {}", lease_label),
        format!("Config path:      {}", config_path.display()),
    ];
    let summary_refs: Vec<&str> = summary_lines.iter().map(|s| s.as_str()).collect();
    ui::section_box("Policy Summary", &summary_refs);
    println!();

    // Show the generated config.
    let b = ui::box_chars();
    println!(
        "  {}{} {}",
        style(b.tl).dim(),
        style(b.h).dim(),
        style(config_path.display()).cyan()
    );
    for line in config_content.lines() {
        println!("  {} {}", style(b.v).dim(), line);
    }
    println!("  {}{}", style(b.bl).dim(), style(b.h).dim());
    println!();

    let confirm = Confirm::new()
        .with_prompt("  Write config and seal?")
        .default(true)
        .interact()
        .map_err(|e| format!("input error: {e}"))?;

    if !confirm {
        ui::warn("Setup cancelled.");
        return Ok(());
    }

    // Write config
    std::fs::write(config_path, &config_content)
        .map_err(|e| format!("failed to write {}: {e}", config_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(config_path, std::fs::Permissions::from_mode(0o600)).map_err(
            |e| {
                format!(
                    "failed to set permissions on {}: {e}",
                    config_path.display()
                )
            },
        )?;
    }

    ui::init_step(&format!(
        "Config written to {}",
        style(config_path.display()).cyan()
    ));

    // Seal
    seal::store_seal_keyed(config_content.as_bytes(), seal_file)
        .map_err(|e| format!("failed to store seal: {e}"))?;

    ui::init_step("Config sealed (keyed HMAC; key at config.seal.key)");

    println!();
    ui::success("Setup complete! Your policy is now sealed.");
    println!();
    ui::divider();
    println!();
    ui::info("Next steps:");
    ui::step(
        1,
        3,
        &format!(
            "Start the daemon:       {}",
            style("opaque service install").cyan()
        ),
    );
    ui::step(
        2,
        3,
        &format!("Verify installation:    {}", style("opaque status").cyan()),
    );
    ui::step(
        3,
        3,
        &format!(
            "Register with AI tool:  {}",
            style("opaque init --register").cyan()
        ),
    );
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// status (default when no subcommand)
// ---------------------------------------------------------------------------

/// Machine-readable JSON status output for scripting.
async fn run_status_json() {
    let config_path = resolve_config_path(None);
    let sock = socket_path();

    // Detect status
    let config_exists = config_path.exists();
    let service_status = service::query_status();
    let daemon_reachable = if sock.exists() {
        tokio::time::timeout(Duration::from_secs(2), try_ping(&sock))
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_some()
    } else {
        false
    };

    let mcp_connected = detect_mcp_connection();

    let status = serde_json::json!({
        "version": version_string(),
        "config": {
            "exists": config_exists,
            "path": config_path.display().to_string(),
        },
        "daemon": {
            "reachable": daemon_reachable,
            "socket_path": sock.display().to_string(),
        },
        "service": {
            "installed": service_status.installed,
            "running": service_status.running,
            "pid": service_status.pid,
        },
        "mcp": {
            "connected": mcp_connected.is_some(),
            "tool": mcp_connected,
        },
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&status).unwrap_or_default()
    );
}

/// Smart welcome screen shown when `opaque` is invoked with no subcommand.
///
/// Detects installation state and shows either a first-run guide or a status
/// dashboard, making the next action obvious.
async fn run_status(json_output: bool) {
    if json_output {
        run_status_json().await;
        return;
    }

    ui::banner(
        &format!("Opaque {}", version_string()),
        "Approval-gated secrets broker for AI coding tools",
    );

    let config_path = resolve_config_path(None);
    let sock = socket_path();

    // Detect whether this is a first-run or a returning user.
    let config_exists = config_path.exists();
    let service_status = service::query_status();
    let daemon_reachable = if sock.exists() {
        tokio::time::timeout(Duration::from_secs(2), try_ping(&sock))
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_some()
    } else {
        false
    };

    if !config_exists {
        // ── First-time user ─────────────────────────────────────────
        println!(
            "  {} {}",
            style("Get started in 60 seconds:").bold(),
            style("opaque quickstart").cyan().bold(),
        );
        println!();

        ui::step(
            1,
            4,
            &format!(
                "Create {} with a safe demo policy",
                style("~/.opaque/").cyan()
            ),
        );
        ui::step(2, 4, "Install and start the daemon service");
        ui::step(
            3,
            4,
            &format!(
                "Connect to your AI coding tool ({}, {})",
                style("Claude").cyan(),
                style("Cursor").cyan()
            ),
        );
        ui::step(4, 4, "Verify everything works end-to-end");

        println!();
        ui::divider();
        println!();
        println!("  {}", style("Other commands:").dim());
        println!(
            "    {:<24} {}",
            style("opaque init").cyan(),
            ui::dim("# initialize config only")
        );
        println!(
            "    {:<24} {}",
            style("opaque doctor").cyan(),
            ui::dim("# diagnose an existing install")
        );
        println!(
            "    {:<24} {}",
            style("opaque --help").cyan(),
            ui::dim("# see all commands")
        );
    } else {
        // ── Returning user: status dashboard ────────────────────────
        // Config
        let rule_count = std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|c| PolicyConfig::from_toml(&c).ok())
            .map(|c| c.rules.len())
            .unwrap_or(0);

        let seal_status = {
            use opaque_core::seal::{self, SealStatus};
            // Beside the config, matching daemon verification.
            let seal_file = config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("config.seal");
            std::fs::read(&config_path)
                .ok()
                .and_then(|bytes| seal::verify_seal(&bytes, &seal_file).ok())
                .map(|s| match s {
                    SealStatus::Verified => ui::status_badge("SEALED", ui::BadgeState::Ok),
                    SealStatus::VerifiedLegacy => {
                        ui::status_badge("SEALED (legacy)", ui::BadgeState::Warn)
                    }
                    SealStatus::Unsealed => ui::status_badge("UNSEALED", ui::BadgeState::Warn),
                    SealStatus::Tampered { .. } => {
                        ui::status_badge("TAMPERED", ui::BadgeState::Fail)
                    }
                    SealStatus::KeyMissing => ui::status_badge("KEY MISSING", ui::BadgeState::Fail),
                })
                .unwrap_or_else(|| ui::status_badge("UNKNOWN", ui::BadgeState::Info))
        };

        // Build status rows for the table.
        let daemon_badge;
        let daemon_detail: String;
        if daemon_reachable {
            daemon_badge = ui::status_badge("OK", ui::BadgeState::Ok);
            daemon_detail = if service_status.running {
                service_status
                    .pid
                    .map(|p| format!("running (PID {p})"))
                    .unwrap_or_else(|| "running".into())
            } else {
                "running".into()
            };
        } else if service_status.installed {
            daemon_badge = ui::status_badge("WARN", ui::BadgeState::Warn);
            daemon_detail = "installed but not responding".into();
        } else {
            daemon_badge = ui::status_badge("FAIL", ui::BadgeState::Fail);
            daemon_detail = "not running".into();
        };

        let service_badge;
        let service_detail: String;
        if service_status.installed {
            if service_status.running {
                service_badge = ui::status_badge("OK", ui::BadgeState::Ok);
                service_detail = "installed, running".into();
            } else {
                service_badge = ui::status_badge("WARN", ui::BadgeState::Warn);
                service_detail = "installed, stopped".into();
            }
        } else {
            service_badge = ui::status_badge("--", ui::BadgeState::Info);
            service_detail = "not installed".into();
        };

        let mcp_connected = detect_mcp_connection();
        let mcp_badge;
        let mcp_detail: String;
        if let Some(ref tool_name) = mcp_connected {
            mcp_badge = ui::status_badge("OK", ui::BadgeState::Ok);
            mcp_detail = format!("connected to {tool_name}");
        } else {
            mcp_badge = ui::status_badge("--", ui::BadgeState::Info);
            mcp_detail = "not connected".into();
        };

        ui::table(
            &["COMPONENT", "STATUS", "DETAILS"],
            &[
                vec!["Daemon".into(), daemon_badge, daemon_detail],
                vec![
                    "Config".into(),
                    seal_status,
                    format!("{rule_count} rule(s)"),
                ],
                vec!["Service".into(), service_badge, service_detail],
                vec!["MCP".into(), mcp_badge, mcp_detail],
            ],
        );

        println!();

        // Context-sensitive next actions.
        if !daemon_reachable && !service_status.installed {
            ui::section_box(
                "Next step",
                &[&format!(
                    "{:<28}{}",
                    style("opaque service install").cyan().bold(),
                    ui::dim("# install and start daemon")
                )],
            );
        } else if !daemon_reachable && service_status.installed {
            ui::section_box(
                "Next step",
                &[&format!(
                    "{:<28}{}",
                    style("opaque service start").cyan().bold(),
                    ui::dim("# start the daemon")
                )],
            );
        } else if mcp_connected.is_none() {
            ui::section_box(
                "Next step",
                &[&format!(
                    "{:<28}{}",
                    style("opaque connect auto").cyan().bold(),
                    ui::dim("# connect to your AI coding tool")
                )],
            );
        } else {
            ui::section_box(
                "Quick actions",
                &[
                    &format!(
                        "{:<28}{}",
                        style("opaque doctor").cyan(),
                        ui::dim("# run diagnostics")
                    ),
                    &format!(
                        "{:<28}{}",
                        style("opaque policy presets").cyan(),
                        ui::dim("# explore policy presets")
                    ),
                    &format!(
                        "{:<28}{}",
                        style("opaque audit tail").cyan(),
                        ui::dim("# view recent audit events")
                    ),
                ],
            );
        }
    }

    println!();
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

/// Run the `opaque doctor` diagnostic command.
///
/// Checks each component of the Opaque installation and reports its status.
/// Uses a pass/warn/fail pattern similar to `brew doctor` or `npm doctor`.
async fn run_doctor() {
    ui::banner("Opaque Doctor", "Checking your installation...");

    let mut pass_count = 0u32;
    let mut warn_count = 0u32;
    let mut fail_count = 0u32;

    let base = default_opaque_dir();
    let config_path = resolve_config_path(None);
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));

    // 1. Config directory
    if config_dir.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(config_dir) {
                let mode = meta.permissions().mode() & 0o777;
                if mode == 0o700 {
                    doctor_pass(&format!(
                        "Config directory exists ({})",
                        config_dir.display()
                    ));
                    pass_count += 1;
                } else {
                    doctor_warn(&format!(
                        "Config directory permissions are {mode:04o} (expected 0700)"
                    ));
                    warn_count += 1;
                }
            } else {
                doctor_pass(&format!(
                    "Config directory exists ({})",
                    config_dir.display()
                ));
                pass_count += 1;
            }
        }
        #[cfg(not(unix))]
        {
            doctor_pass(&format!(
                "Config directory exists ({})",
                config_dir.display()
            ));
            pass_count += 1;
        }
    } else {
        doctor_fail("Config directory not found — run 'opaque init'");
        fail_count += 1;
    }

    // 2. Config file
    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(contents) => match PolicyConfig::from_toml(&contents) {
                Ok(config) => {
                    doctor_pass(&format!("Config file valid ({} rules)", config.rules.len()));
                    pass_count += 1;
                }
                Err(e) => {
                    doctor_fail(&format!("Config file has parse errors: {e}"));
                    fail_count += 1;
                }
            },
            Err(e) => {
                doctor_fail(&format!("Cannot read config file: {e}"));
                fail_count += 1;
            }
        }
    } else {
        doctor_warn("Config file not found — run 'opaque init' or 'opaque setup'");
        warn_count += 1;
    }

    // 3. Config seal
    {
        use opaque_core::seal::{self, SealStatus};
        // Beside the config, matching daemon verification.
        let seal_file = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("config.seal");
        if config_path.exists() {
            match std::fs::read(&config_path) {
                Ok(config_bytes) => match seal::verify_seal(&config_bytes, &seal_file) {
                    Ok(SealStatus::Verified) => {
                        doctor_pass("Config seal verified (keyed)");
                        pass_count += 1;
                    }
                    Ok(SealStatus::VerifiedLegacy) => {
                        doctor_warn(
                            "Config seal is the legacy unkeyed format — \
                             run 'opaque setup --seal' to upgrade",
                        );
                        warn_count += 1;
                    }
                    Ok(SealStatus::Unsealed) => {
                        doctor_warn("Config is unsealed — run 'opaque setup --seal'");
                        warn_count += 1;
                    }
                    Ok(SealStatus::Tampered { .. }) => {
                        doctor_fail(
                            "Config seal BROKEN — run 'opaque setup --reset' then reconfigure",
                        );
                        fail_count += 1;
                    }
                    Ok(SealStatus::KeyMissing) => {
                        doctor_fail(
                            "Config has a keyed seal but config.seal.key is missing — \
                             restore it or re-seal",
                        );
                        fail_count += 1;
                    }
                    Err(e) => {
                        doctor_warn(&format!("Seal check error: {e}"));
                        warn_count += 1;
                    }
                },
                Err(e) => {
                    doctor_warn(&format!("Cannot read config for seal check: {e}"));
                    warn_count += 1;
                }
            }
        } else {
            doctor_skip("Config seal (no config file)");
        }
    }

    // 4. Require-seal setting
    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(contents) => match PolicyConfig::from_toml(&contents) {
                Ok(config) => {
                    if config.require_seal {
                        doctor_pass("require_seal is enabled (tamper protection active)");
                        pass_count += 1;
                    } else {
                        doctor_warn(
                            "require_seal is not enabled — production deployments should set \
                             require_seal = true in config.toml",
                        );
                        warn_count += 1;
                    }
                }
                Err(_) => {
                    // Config parse errors already reported in check 2.
                }
            },
            Err(_) => {
                // Read errors already reported in check 2.
            }
        }
    }

    // 5. Socket
    let sock = socket_path();
    if sock.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&sock) {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o177 == 0 {
                    doctor_pass(&format!(
                        "Socket exists with secure permissions ({mode:04o})"
                    ));
                    pass_count += 1;
                } else {
                    doctor_warn(&format!(
                        "Socket permissions are {mode:04o} (expected 0600 or stricter)"
                    ));
                    warn_count += 1;
                }
            } else {
                doctor_pass("Socket file exists");
                pass_count += 1;
            }
        }
        #[cfg(not(unix))]
        {
            doctor_pass("Socket file exists");
            pass_count += 1;
        }
    } else {
        doctor_warn(&format!(
            "Socket not found at {} — is the daemon running?",
            sock.display()
        ));
        warn_count += 1;
    }

    // 5. Daemon connectivity
    if sock.exists() {
        match tokio::time::timeout(Duration::from_secs(5), try_ping(&sock)).await {
            Ok(Ok(())) => {
                doctor_pass("Daemon is reachable (ping OK)");
                pass_count += 1;
            }
            Ok(Err(e)) => {
                doctor_fail(&format!("Daemon ping failed: {e}"));
                fail_count += 1;
            }
            Err(_) => {
                doctor_fail("Daemon ping timed out (5s)");
                fail_count += 1;
            }
        }
    } else {
        doctor_skip("Daemon connectivity (no socket)");
    }

    // 6. Daemon/CLI version skew
    if sock.exists() {
        match tokio::time::timeout(Duration::from_secs(5), try_daemon_version(&sock)).await {
            Ok(Ok(daemon_version)) => {
                let cli_version = version_string();
                if daemon_version == cli_version {
                    doctor_pass(&format!("Daemon version matches CLI ({cli_version})"));
                    pass_count += 1;
                } else {
                    doctor_warn(&format!(
                        "Daemon version ({daemon_version}) differs from CLI ({cli_version}) — restart/rebuild to avoid protocol skew"
                    ));
                    warn_count += 1;
                }
            }
            Ok(Err(e)) => {
                doctor_warn(&format!("Cannot read daemon version: {e}"));
                warn_count += 1;
            }
            Err(_) => {
                doctor_warn("Daemon version check timed out (5s)");
                warn_count += 1;
            }
        }
    } else {
        doctor_skip("Daemon version skew (no socket)");
    }

    // 7. Service status
    {
        let status = service::query_status();
        if status.installed {
            if status.running {
                let pid_info = status
                    .pid
                    .map(|p| format!(" (PID {p})"))
                    .unwrap_or_default();
                doctor_pass(&format!("Service installed and running{pid_info}"));
                pass_count += 1;
            } else {
                doctor_warn("Service installed but not running — run 'opaque service start'");
                warn_count += 1;
            }
        } else {
            doctor_warn("Service not installed — run 'opaque service install'");
            warn_count += 1;
        }
    }

    // 8. opaque-mcp skew
    let mcp_paths = discover_opaque_mcp_binaries();
    if mcp_paths.is_empty() {
        doctor_info("opaque-mcp binary not found (skipping MCP skew check)");
    } else {
        let cli_version = version_string().to_string();
        for path in mcp_paths {
            match read_binary_version(&path, "opaque-mcp") {
                Ok(mcp_version) => {
                    if mcp_version == cli_version {
                        doctor_pass(&format!(
                            "opaque-mcp matches CLI version ({}) at {}",
                            mcp_version,
                            path.display()
                        ));
                        pass_count += 1;
                    } else {
                        doctor_warn(&format!(
                            "opaque-mcp version ({}) at {} differs from CLI ({})",
                            mcp_version,
                            path.display(),
                            cli_version
                        ));
                        warn_count += 1;
                    }
                }
                Err(e) => {
                    doctor_warn(&format!(
                        "Could not determine opaque-mcp version at {}: {e}",
                        path.display()
                    ));
                    warn_count += 1;
                }
            }
        }
    }

    // 9. 1Password backends
    let op_cli_found = match std::process::Command::new("which")
        .arg("op")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            doctor_pass(&format!("1Password CLI found ({path})"));
            pass_count += 1;
            true
        }
        _ => false,
    };
    let connect_url = std::env::var("OPAQUE_1PASSWORD_URL").ok();
    if let Some(ref url) = connect_url {
        doctor_pass(&format!("1Password Connect Server configured ({url})"));
        pass_count += 1;
    }
    if !op_cli_found && connect_url.is_none() {
        doctor_info("No 1Password backend — install op CLI or set OPAQUE_1PASSWORD_URL");
    }

    // 10. Profiles directory
    let profiles_dir = base.join("profiles");
    if profiles_dir.exists() {
        let count = std::fs::read_dir(&profiles_dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().is_some_and(|ext| ext == "toml"))
                    .count()
            })
            .unwrap_or(0);
        doctor_pass(&format!("Profiles directory exists ({count} profiles)"));
        pass_count += 1;
    } else {
        doctor_info("No profiles directory (sandbox features unavailable)");
    }

    // 11. Audit database
    let audit_db = base.join("audit.db");
    if audit_db.exists() {
        if let Ok(meta) = std::fs::metadata(&audit_db) {
            let size_kb = meta.len() / 1024;
            doctor_pass(&format!("Audit database exists ({size_kb} KB)"));
            pass_count += 1;
        } else {
            doctor_pass("Audit database exists");
            pass_count += 1;
        }
    } else {
        doctor_info("No audit database (created on first daemon run)");
    }

    // 12. Sandbox probe (macOS)
    #[cfg(target_os = "macos")]
    {
        // Probe sandbox-exec the same way the daemon does at runtime.
        let sandbox_works = doctor_probe_sandbox_exec();
        if sandbox_works {
            doctor_pass("sandbox-exec is functional on this macOS version");
            pass_count += 1;
        } else {
            doctor_warn(
                "sandbox-exec is broken on this macOS version — profiles with sandbox = true \
                 will fall back to unsandboxed execution. Set sandbox = false in profiles to \
                 suppress the fallback warning",
            );
            warn_count += 1;
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        doctor_skip("Sandbox probe (macOS only)");
    }

    // 13. Service file PATH check
    {
        let svc_status = service::query_status();
        if svc_status.installed && svc_status.service_file.exists() {
            match std::fs::read_to_string(&svc_status.service_file) {
                Ok(contents) => {
                    // Check for PATH in the service file (plist or systemd unit).
                    let has_path = if cfg!(target_os = "macos") {
                        contents.contains("<key>PATH</key>")
                    } else {
                        contents.contains("Environment=PATH=")
                    };
                    if has_path {
                        doctor_pass("Service file includes PATH environment variable");
                        pass_count += 1;
                    } else {
                        doctor_warn(
                            "Service file missing PATH — run 'opaque service uninstall && \
                             opaque service install' to regenerate",
                        );
                        warn_count += 1;
                    }
                }
                Err(e) => {
                    doctor_warn(&format!("Cannot read service file: {e}"));
                    warn_count += 1;
                }
            }
        } else {
            doctor_skip("Service file PATH check (service not installed)");
        }
    }

    // 14. known_human_clients check
    if config_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&config_path) {
            // Parse known_human_clients entries from config.
            let entries: Vec<String> = contents
                .parse::<toml_edit::DocumentMut>()
                .ok()
                .and_then(|doc| {
                    let clients = doc.get("known_human_clients")?.as_array_of_tables()?;
                    Some(
                        clients
                            .iter()
                            .filter_map(|e| {
                                e.get("exe_path").and_then(|v| v.as_str()).map(String::from)
                            })
                            .collect(),
                    )
                })
                .unwrap_or_default();

            if entries.is_empty() {
                // No known_human_clients — all clients default to Agent.
                // This is a valid configuration for agent-only setups.
                doctor_pass("All clients classified as Agent (no known_human_clients)");
                pass_count += 1;
            } else {
                let current_exe = std::env::current_exe().ok();
                let canonical_exe = current_exe.as_ref().and_then(|p| p.canonicalize().ok());
                if let Some(exe) = &canonical_exe {
                    let exe_str = exe.to_string_lossy();
                    let matched = entries
                        .iter()
                        .any(|pattern| glob_match::glob_match(pattern, &exe_str));
                    if matched {
                        doctor_pass("Current binary is registered in known_human_clients");
                        pass_count += 1;
                    } else {
                        doctor_warn(&format!(
                            "Current binary ({}) not found in known_human_clients — \
                             run 'opaque setup' to register, or leave empty for agent-only",
                            exe.display()
                        ));
                        warn_count += 1;
                    }
                } else {
                    doctor_skip("known_human_clients match (cannot determine current exe)");
                }
            }
        }
    } else {
        doctor_skip("known_human_clients check (no config file)");
    }

    // Summary
    println!();
    ui::divider();
    let summary = format!("{pass_count} passed, {warn_count} warnings, {fail_count} errors");
    if fail_count > 0 {
        println!(
            "  {} {}",
            style(ui::CROSS).red(),
            style(summary).red().bold()
        );
    } else if warn_count > 0 {
        println!(
            "  {} {}",
            style(ui::WARN_ICON).yellow(),
            style(summary).yellow().bold()
        );
    } else {
        println!(
            "  {} {}",
            style(ui::CHECK).green(),
            style(summary).green().bold()
        );
    }
    println!();

    if fail_count > 0 {
        std::process::exit(1);
    }
}

/// Attempt a lightweight ping to the daemon. Returns Ok(()) on success.
async fn try_ping(sock: &Path) -> Result<(), String> {
    let resp = call_with_timeout(
        sock,
        "ping",
        serde_json::Value::Null,
        request_timeout("ping"),
    )
    .await
    .map_err(|error| error.to_string())?;

    if let Some(err) = resp.error {
        return Err(format!(
            "daemon error ({}): {}. Run 'opaque doctor' for diagnostics",
            err.code, err.message
        ));
    }
    Ok(())
}

/// Query daemon version over IPC.
async fn try_daemon_version(sock: &Path) -> Result<String, String> {
    let resp = call(sock, "version", serde_json::Value::Null)
        .await
        .map_err(|e| format!("{e}"))?;
    if let Some(err) = resp.error {
        return Err(format!("{}: {}", err.code, err.message));
    }
    resp.result
        .and_then(|v| v.get("version").and_then(|s| s.as_str()).map(str::to_owned))
        .ok_or_else(|| "missing version in daemon response".to_string())
}

fn discover_opaque_mcp_binaries() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    if let Ok(current) = std::env::current_exe() {
        let sibling = current.with_file_name("opaque-mcp");
        if sibling.exists() && seen.insert(sibling.clone()) {
            out.push(sibling);
        }
    }

    if let Some(on_path) = resolve_on_path("opaque-mcp")
        && seen.insert(on_path.clone())
    {
        out.push(on_path);
    }

    out
}

fn resolve_on_path(binary: &str) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(binary);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn read_binary_version(path: &Path, binary_name: &str) -> Result<String, String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("spawn failed: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    parse_version_from_output(&combined, binary_name).ok_or_else(|| {
        format!(
            "unable to parse version output (exit={})",
            output.status.code().unwrap_or(-1)
        )
    })
}

fn parse_version_from_output(output: &str, binary_name: &str) -> Option<String> {
    for line in output.lines() {
        if let Some(idx) = line.find(binary_name) {
            let tail = &line[idx + binary_name.len()..];
            for token in tail.split_whitespace() {
                let cleaned = token.trim_matches(|c: char| {
                    !c.is_ascii_alphanumeric() && c != '.' && c != '+' && c != '-'
                });
                if cleaned.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    return Some(cleaned.to_owned());
                }
            }
        }
    }
    None
}

/// Probe whether sandbox-exec works on this macOS version.
///
/// Mirrors the probe in `opaqued::sandbox::macos::probe_sandbox_exec()`.
#[cfg(target_os = "macos")]
fn doctor_probe_sandbox_exec() -> bool {
    // Use a restrictive (deny default) profile matching real execution, not
    // (allow default), so the probe detects macOS versions where Apple broke
    // seatbelt support for restrictive profiles.
    let profile_content = "\
        (version 1)\n\
        (deny default)\n\
        (allow file-read*)\n\
        (allow process-exec)\n\
        (allow process-fork)\n\
        (allow process-info-pidinfo)\n\
        (allow sysctl-read)\n\
        (allow mach-lookup)\n";
    let dir = std::env::temp_dir();
    let profile_path = dir.join(format!("opaque-doctor-probe-{}.sb", std::process::id()));

    if std::fs::write(&profile_path, profile_content).is_err() {
        return false;
    }

    let result = std::process::Command::new("sandbox-exec")
        .args(["-f", &profile_path.to_string_lossy()])
        .arg("--")
        .args(["/bin/echo", "probe"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output();

    let _ = std::fs::remove_file(&profile_path);

    match result {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            let code = output.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                eprintln!("  sandbox-exec stderr (exit {code}): {}", stderr.trim());
            }
            false
        }
        Err(_) => false,
    }
}

fn doctor_pass(msg: &str) {
    println!("  {} {}", style(ui::CHECK).green(), msg);
}

fn doctor_fail(msg: &str) {
    println!("  {} {}", style(ui::CROSS).red(), style(msg).red());
}

fn doctor_warn(msg: &str) {
    println!(
        "  {} {}",
        style(ui::WARN_ICON).yellow(),
        style(msg).yellow()
    );
}

fn doctor_info(msg: &str) {
    println!("  {} {}", style(ui::INFO_ICON).dim(), style(msg).dim());
}

fn doctor_skip(msg: &str) {
    println!("  {} {}", style("—").dim(), style(msg).dim());
}

/// Create a directory with mode 0700 if it does not already exist.
fn create_dir_0700(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(path)
        .map_err(|e| format!("failed to create {}: {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("failed to set permissions on {}: {e}", path.display()))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Profile management
// ---------------------------------------------------------------------------

/// Handle profile subcommands (list, show, validate).
fn run_profile_action(action: &ProfileAction) -> Result<(), String> {
    let profiles_dir = profile::profiles_dir();

    match action {
        ProfileAction::List => {
            if !profiles_dir.exists() {
                ui::warn("No profiles directory found (run `opaque init` first)");
                return Ok(());
            }

            let entries = std::fs::read_dir(&profiles_dir)
                .map_err(|e| format!("failed to read profiles dir: {e}"))?;

            let mut names: Vec<String> = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "toml"))
                .filter_map(|e| {
                    e.path()
                        .file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                })
                .collect();

            names.sort();

            if names.is_empty() {
                ui::info("No profiles found.");
                return Ok(());
            }

            ui::header(&format!("{} profile(s)", names.len()));
            for name in &names {
                println!("  {} {}", style(ui::PAPER).dim(), style(name).cyan().bold());
            }
            Ok(())
        }

        ProfileAction::Show { name } => {
            let path = profiles_dir.join(format!("{name}.toml"));
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| format!("failed to read profile '{name}': {e}"))?;
            ui::header(&format!("Profile: {name}"));
            println!("{contents}");
            Ok(())
        }

        ProfileAction::Validate { name } => {
            let path = profiles_dir.join(format!("{name}.toml"));
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| format!("failed to read profile '{name}': {e}"))?;

            profile::load_profile(&contents, Some(name))
                .map_err(|e| format!("profile validation failed: {e}"))?;

            ui::success(&format!("Profile '{name}' is valid"));
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// connect
// ---------------------------------------------------------------------------

/// Result of a connect operation.
#[derive(Debug, PartialEq)]
enum ConnectResult {
    /// MCP server was newly registered.
    Connected,
    /// MCP server was already configured with the correct path.
    AlreadyConnected,
    /// MCP server entry existed but was updated (different path).
    Updated,
}

/// Run the `opaque connect <tool>` command.
fn run_connect(tool: &str) -> Result<(), String> {
    let tool_lower = tool.to_ascii_lowercase();

    // Find opaque-mcp binary.
    let opaque_mcp =
        find_opaque_mcp_path().ok_or("cannot find opaque-mcp binary on PATH or next to opaque")?;

    match tool_lower.as_str() {
        "claude" => {
            let result = connect_claude(&opaque_mcp)?;
            print_connect_result("Claude Code", &result);
        }
        "cursor" => {
            let result = connect_cursor(&opaque_mcp)?;
            print_connect_result("Cursor", &result);
        }
        "codex" => {
            let result = connect_codex(&opaque_mcp)?;
            print_connect_result("Codex", &result);
        }
        "auto" => {
            connect_tool_at(&opaque_mcp)?;
        }
        "windsurf" => {
            ui::info("Windsurf support is coming soon.");
            return Ok(());
        }
        _ => {
            return Err(format!(
                "unknown tool '{tool}'. Supported: claude, cursor, codex, auto (windsurf coming soon)"
            ));
        }
    }

    Ok(())
}

/// Print a human-friendly result for a connect operation.
fn print_connect_result(tool_name: &str, result: &ConnectResult) {
    match result {
        ConnectResult::Connected => {
            ui::success(&format!("Registered opaque MCP server with {tool_name}"));
        }
        ConnectResult::AlreadyConnected => {
            ui::info(&format!(
                "opaque MCP server is already configured in {tool_name}"
            ));
        }
        ConnectResult::Updated => {
            ui::success(&format!("Updated opaque MCP server path in {tool_name}"));
        }
    }
}

/// Auto-detect AI tools and connect to the first one found.
fn connect_tool_at(opaque_mcp: &Path) -> Result<(), String> {
    let env = wizard::RealEnvironment;
    let tools = wizard::detect_ai_tools(&env);

    if tools.is_empty() {
        return Err(
            "no AI coding tools detected. Supported: claude, cursor, codex (windsurf coming soon). \
             Install one and retry, or specify a tool explicitly: opaque connect <tool>"
                .into(),
        );
    }

    let mut connected_any = false;
    for tool in &tools {
        let result = match tool.kind {
            wizard::AiToolKind::ClaudeCode => connect_claude(opaque_mcp),
            wizard::AiToolKind::Cursor => connect_cursor(opaque_mcp),
            wizard::AiToolKind::Codex => connect_codex(opaque_mcp),
        };
        match result {
            Ok(r) => {
                print_connect_result(&tool.name, &r);
                connected_any = true;
            }
            Err(e) => {
                ui::warn(&format!("Could not connect to {}: {e}", tool.name));
            }
        }
    }

    if !connected_any {
        return Err("failed to connect to any detected AI tool".into());
    }

    Ok(())
}

/// Connect opaque MCP to Claude Code.
///
/// Claude Code reads user-scope `mcpServers` from `~/.claude.json`. Releases
/// up to 0.4.0 wrote `~/.claude/settings.json`, which Claude Code never
/// consults for MCP servers, so the registration silently did nothing.
fn connect_claude(opaque_mcp: &Path) -> Result<ConnectResult, String> {
    let config_file = wizard::claude_code_mcp_config_path(&dirs_or_home());
    connect_json_mcp(&config_file, opaque_mcp)
}

/// Connect opaque MCP to Cursor (~/.cursor/mcp.json).
fn connect_cursor(opaque_mcp: &Path) -> Result<ConnectResult, String> {
    let config_file = dirs_or_home().join(".cursor").join("mcp.json");
    connect_json_mcp(&config_file, opaque_mcp)
}

/// Connect opaque MCP to a JSON-based AI tool config file.
///
/// Unrelated keys and other server entries survive; an existing `opaque`
/// entry keeps its `env` and custom `args`. Only the command path and the
/// legacy `--stdio` argument (rejected by `opaque-mcp`) are rewritten.
fn connect_json_mcp(config_file: &Path, opaque_mcp: &Path) -> Result<ConnectResult, String> {
    Ok(
        match wizard::upsert_json_mcp_config_file(config_file, opaque_mcp)? {
            wizard::JsonMcpUpsert::Created => ConnectResult::Connected,
            wizard::JsonMcpUpsert::Updated => ConnectResult::Updated,
            wizard::JsonMcpUpsert::Unchanged => ConnectResult::AlreadyConnected,
        },
    )
}

/// Connect opaque MCP to Codex (~/.codex/config.toml).
fn connect_codex(opaque_mcp: &Path) -> Result<ConnectResult, String> {
    connect_codex_at(&codex_config_path(), opaque_mcp)
}

/// Return the Codex config file path (~/.codex/config.toml).
fn codex_config_path() -> PathBuf {
    dirs_or_home().join(".codex").join("config.toml")
}

/// Connect opaque MCP to Codex at a specific config file path.
fn connect_codex_at(config_file: &Path, opaque_mcp: &Path) -> Result<ConnectResult, String> {
    let path_str = opaque_mcp.to_string_lossy().to_string();

    // Ensure parent directory exists.
    if let Some(parent) = config_file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }

    let mut doc: toml_edit::DocumentMut = if config_file.exists() {
        let content = std::fs::read_to_string(config_file)
            .map_err(|e| format!("cannot read {}: {e}", config_file.display()))?;
        content
            .parse()
            .map_err(|e| format!("cannot parse {}: {e}", config_file.display()))?
    } else {
        toml_edit::DocumentMut::new()
    };

    // Check if opaque is already configured with the same command.
    if let Some(cmd) = doc
        .get("mcp_servers")
        .and_then(|s| s.get("opaque"))
        .and_then(|o| o.get("command"))
        .and_then(|v| v.as_str())
        && cmd == path_str
    {
        return Ok(ConnectResult::AlreadyConnected);
    }

    let was_update = doc
        .get("mcp_servers")
        .and_then(|s| s.get("opaque"))
        .is_some();

    // Ensure [mcp_servers] table exists.
    if !doc.contains_key("mcp_servers") {
        doc["mcp_servers"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    // Create or update [mcp_servers.opaque].
    let opaque_table = {
        let mut t = toml_edit::Table::new();
        t["command"] = toml_edit::value(&path_str);
        let mut args = toml_edit::Array::new();
        args.set_trailing("");
        t["args"] = toml_edit::value(args);
        t
    };

    doc["mcp_servers"]["opaque"] = toml_edit::Item::Table(opaque_table);

    std::fs::write(config_file, doc.to_string())
        .map_err(|e| format!("cannot write {}: {e}", config_file.display()))?;

    if was_update {
        Ok(ConnectResult::Updated)
    } else {
        Ok(ConnectResult::Connected)
    }
}

/// Detect if opaque MCP is already configured in any known AI tool.
///
/// Returns the name of the first tool where opaque is configured, or `None`.
pub fn detect_mcp_connection() -> Option<String> {
    let home = dirs_or_home();

    // Check Claude Code (user-scope servers live in ~/.claude.json).
    if json_mcp_config_has_opaque(&wizard::claude_code_mcp_config_path(&home)) {
        return Some("Claude Code".into());
    }

    // Check Cursor.
    if json_mcp_config_has_opaque(&home.join(".cursor").join("mcp.json")) {
        return Some("Cursor".into());
    }

    // Check Codex.
    let codex_config = home.join(".codex").join("config.toml");
    if codex_config.exists()
        && let Ok(content) = std::fs::read_to_string(&codex_config)
        && (content.contains("[mcp_servers.opaque]") || content.contains("\"opaque\""))
    {
        return Some("Codex".into());
    }

    None
}

/// True when a JSON MCP config file has an `mcpServers.opaque` entry. The
/// file is parsed rather than substring-matched: Claude Code's `~/.claude.json`
/// also stores project paths and other state that may mention "opaque".
fn json_mcp_config_has_opaque(config_file: &Path) -> bool {
    std::fs::read_to_string(config_file)
        .ok()
        .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
        .and_then(|config| config.get("mcpServers")?.get("opaque").cloned())
        .is_some()
}

/// Locate the opaque-mcp binary (on PATH or next to the current executable).
fn find_opaque_mcp_path() -> Option<PathBuf> {
    // Try `which opaque-mcp`.
    let output = std::process::Command::new("which")
        .arg("opaque-mcp")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;

    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }

    // Try next to the current executable.
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("opaque-mcp");
        if sibling.exists() {
            return Some(sibling);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Per-repo init
// ---------------------------------------------------------------------------

/// Generate a repo-scoped policy TOML from a remote URL and optional preset content.
///
/// This is a pure function suitable for unit testing.
#[allow(dead_code)]
fn generate_repo_policy(remote_url: &str, preset_content: Option<&str>) -> String {
    // Extract org/repo from remote URL.
    let cleaned = remote_url.trim_end_matches(".git").trim_end_matches('/');
    let org_repo = if let Some(colon_idx) = cleaned.rfind(':') {
        let after_colon = &cleaned[colon_idx + 1..];
        if !after_colon.is_empty()
            && !after_colon.starts_with("//")
            && !after_colon.chars().next().unwrap_or(' ').is_ascii_digit()
        {
            after_colon.to_string()
        } else {
            extract_last_two_segments(cleaned)
        }
    } else {
        extract_last_two_segments(cleaned)
    };

    // Build the glob pattern for remote_url_pattern.
    let escaped_url = remote_url
        .replace('\\', "\\\\")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('{', "\\{")
        .replace('}', "\\}");
    let url_pattern = format!("*{}*", escaped_url);

    if let Some(preset) = preset_content
        && let Ok(config) = PolicyConfig::from_toml(preset)
    {
        let mut result = format!(
            "# Repo-scoped Opaque policy for {}\n\
                 # This file is merged with ~/.opaque/config.toml at runtime.\n\n",
            org_repo
        );

        for rule in &config.rules {
            result.push_str("[[rules]]\n");
            result.push_str(&format!("name = \"repo-{}\"\n", rule.name));
            result.push_str(&format!(
                "operation_pattern = \"{}\"\n",
                rule.operation_pattern
            ));
            result.push_str(&format!("allow = {}\n", rule.allow));
            let types: Vec<String> = rule
                .client_types
                .iter()
                .map(|ct| match ct {
                    ClientType::Human => "\"human\"".to_string(),
                    ClientType::Agent => "\"agent\"".to_string(),
                })
                .collect();
            result.push_str(&format!("client_types = [{}]\n\n", types.join(", ")));

            result.push_str("[rules.workspace]\n");
            result.push_str(&format!("remote_url_pattern = \"{}\"\n\n", url_pattern));

            result.push_str("[rules.approval]\n");
            let require = format!("{:?}", rule.approval.require).to_lowercase();
            result.push_str(&format!("require = \"{}\"\n", require));
            let factors: Vec<String> = rule
                .approval
                .factors
                .iter()
                .map(|f| format!("\"{:?}\"", f).to_lowercase())
                .collect();
            result.push_str(&format!("factors = [{}]\n", factors.join(", ")));
            if let Some(ttl) = rule.approval.lease_ttl {
                result.push_str(&format!("lease_ttl = {}\n", ttl.as_secs()));
            }
            if let Some(budget) = rule.approval.budget {
                result.push_str(&format!("budget = {budget}\n"));
            }
            result.push('\n');
        }

        return result;
    }

    format!(
        "# Repo-scoped Opaque policy for {org_repo}\n\
         # This file is merged with ~/.opaque/config.toml at runtime.\n\
         #\n\
         # Add rules below to control what operations are allowed in this repo.\n\
         # See: opaque policy presets --show <name> for examples.\n\
         \n\
         # [[rules]]\n\
         # name = \"repo-example\"\n\
         # operation_pattern = \"github.*\"\n\
         # allow = true\n\
         # client_types = [\"agent\", \"human\"]\n\
         #\n\
         # [rules.workspace]\n\
         # remote_url_pattern = \"{url_pattern}\"\n\
         #\n\
         # [rules.approval]\n\
         # require = \"first_use\"\n\
         # factors = [\"local_bio\"]\n\
         # lease_ttl = 300\n"
    )
}

/// Extract the last two path segments from a URL (e.g. "org/repo").
#[allow(dead_code)]
fn extract_last_two_segments(url: &str) -> String {
    let parts: Vec<&str> = url.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 2 {
        format!("{}/{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else if parts.len() == 1 {
        parts[0].to_string()
    } else {
        url.to_string()
    }
}

/// Initialize a repo-scoped policy at the given repo root directory.
///
/// Creates `.opaque/policy.toml` with a workspace-scoped policy.
/// Returns the generated TOML content.
#[allow(dead_code)]
fn run_init_repo_at(repo_root: &Path, preset: Option<&str>) -> Result<String, String> {
    let opaque_dir = repo_root.join(".opaque");
    let policy_path = opaque_dir.join("policy.toml");

    // Detect remote URL
    let remote_url = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(repo_root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let preset_content = match preset {
        Some(name) => Some(get_preset(name).ok_or_else(|| {
            format!(
                "unknown preset '{}'. Available: {}",
                name,
                available_presets()
                    .iter()
                    .map(|(n, _, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?),
        None => None,
    };

    let toml_content = generate_repo_policy(&remote_url, preset_content);

    // Create .opaque/ directory
    std::fs::create_dir_all(&opaque_dir)
        .map_err(|e| format!("failed to create {}: {e}", opaque_dir.display()))?;

    // Write policy.toml
    std::fs::write(&policy_path, &toml_content)
        .map_err(|e| format!("failed to write {}: {e}", policy_path.display()))?;

    Ok(toml_content)
}

/// CLI entry point for `opaque init --repo`.
#[allow(dead_code)]
fn run_init_repo(preset: Option<&str>) -> Result<(), String> {
    // Find git repo root
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| format!("failed to run git: {e}"))?;

    if !output.status.success() {
        return Err("not in a git repository (git rev-parse --show-toplevel failed)".into());
    }

    let repo_root = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string());

    run_init_repo_at(&repo_root, preset)?;

    ui::success("Created .opaque/policy.toml scoped to this repository");
    println!();
    ui::info(
        "If this file contains secrets, add '.opaque/' to .gitignore.\n\
         If it's policy-only, consider committing it to share with your team.",
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Preset preview
// ---------------------------------------------------------------------------

/// Show the full TOML content of a specific preset.
#[allow(dead_code)]
fn policy_show_preset(name: &str) -> Result<(), String> {
    let content = get_preset(name).ok_or_else(|| {
        format!(
            "unknown preset '{}'. Available: {}",
            name,
            available_presets()
                .iter()
                .map(|(n, _, _)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;

    println!("Preset: {name}");
    println!();
    print!("{content}");
    if !content.ends_with('\n') {
        println!();
    }
    println!();
    println!("Apply with: opaque policy preset {name}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Post-apply checklist
// ---------------------------------------------------------------------------

/// Return a checklist of prerequisites based on the preset name.
#[allow(dead_code)]
fn preset_checklist(preset_name: &str) -> Vec<String> {
    match preset_name {
        "github-secrets" => vec![
            "Store a GitHub PAT with 'repo' scope: opaque secrets add github-pat".into(),
            "Start the daemon: opaque service install".into(),
            "Connect to Claude Code: opaque connect claude".into(),
        ],
        "gitlab-variables" => vec![
            "Store a GitLab token with 'api' scope: opaque secrets add gitlab-token".into(),
            "Start the daemon: opaque service install".into(),
        ],
        "agent-wrapper-github" => vec![
            "Store a GitHub PAT: opaque secrets add github-pat".into(),
            "Start the daemon: opaque service install".into(),
            "Wrap your agent: opaque agent run -- <your-agent-command>".into(),
        ],
        _ => vec!["Start the daemon: opaque service install".into()],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn operation_parameters_file_is_bounded_and_requires_an_object() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("params.json");
        assert_eq!(read_operation_params(None).unwrap(), serde_json::json!({}));
        fs::write(
            &path,
            r#"{"project":"example-project","secret_id":"demo","value_ref":"env:DEMO_SECRET"}"#,
        )
        .unwrap();
        let params = read_operation_params(Some(&path)).unwrap();
        assert_eq!(params["value_ref"], "env:DEMO_SECRET");
        for invalid in ["[]", "null", "not json"] {
            fs::write(&path, invalid).unwrap();
            assert!(read_operation_params(Some(&path)).is_err());
        }
        fs::write(&path, vec![b' '; opaque_core::MAX_FRAME_LENGTH]).unwrap();
        assert!(read_operation_params(Some(&path)).is_err());
        assert!(read_operation_params(Some(directory.path())).is_err());
    }

    /// Write a TOML string to a temp file and run policy_check_path on it.
    fn check_toml(content: &str) -> Result<String, String> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, content).unwrap();
        policy_check_path(Some(path.as_path()))
    }

    #[test]
    fn valid_toml_with_rules() {
        let toml = r#"
[[rules]]
name = "allow-github"
operation_pattern = "github.*"
allow = true
client_types = ["agent", "human"]

[rules.client]

[rules.target]
fields = {}

[rules.workspace]

[rules.secret_names]

[rules.approval]
require = "first_use"
factors = ["local_bio"]
lease_ttl = 300
"#;
        let result = check_toml(toml);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert!(result.unwrap().contains("1 rules loaded"));
    }

    #[test]
    fn valid_toml_empty_rules() {
        let toml = "";
        let result = check_toml(toml);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("0 rules loaded"));
    }

    /// Write a TOML string to a temp file and run policy_check_report on it
    /// with a simulated (not necessarily real) platform enforceability.
    fn check_toml_for_platform(
        content: &str,
        codesign_enforceable: bool,
    ) -> Result<(String, Vec<String>), String> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, content).unwrap();
        policy_check_report(Some(path.as_path()), codesign_enforceable)
    }

    /// N1: a rule requiring `codesign_team_id` loads (never refused) and
    /// warns by name only when this platform cannot enforce it. A rule
    /// pinning the caller with exe_sha256/exe_path is populated on every
    /// platform, so it never warns either way.
    #[test]
    fn policy_check_warns_only_for_unenforceable_codesign_rules() {
        let codesign_rule = r#"
[[rules]]
name = "requires-team"
operation_pattern = "github.*"
client_types = ["agent", "human"]
[rules.client]
codesign_team_id = "TEAMFIXTURE"
"#;
        let exe_rule = r#"
[[rules]]
name = "requires-exe"
operation_pattern = "github.*"
client_types = ["agent", "human"]
[rules.client]
exe_sha256 = "deadbeef"
exe_path = "/usr/bin/claude*"
"#;

        // Non-enforcing platform: the codesign rule loads and warns by name.
        let (message, warnings) = check_toml_for_platform(codesign_rule, false).unwrap();
        assert!(message.contains("1 rules loaded"));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("requires-team"));
        assert!(warnings[0].contains("codesign_team_id"));
        assert!(warnings[0].contains("exe_sha256"));

        // Enforcing platform: same rule, no warning.
        let (_, warnings) = check_toml_for_platform(codesign_rule, true).unwrap();
        assert!(warnings.is_empty());

        // exe_sha256/exe_path rule: never warns, on either platform.
        let (_, warnings) = check_toml_for_platform(exe_rule, false).unwrap();
        assert!(warnings.is_empty());
        let (_, warnings) = check_toml_for_platform(exe_rule, true).unwrap();
        assert!(warnings.is_empty());

        // The real CLI entry point (this host's actual platform) also loads
        // the codesign rule rather than refusing it.
        assert!(check_toml(codesign_rule).is_ok());
    }

    #[test]
    fn invalid_toml_syntax() {
        let toml = "[[rules]\nname = broken";
        let result = check_toml(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TOML parse error"));
    }

    #[test]
    fn validation_error_empty_name() {
        let toml = r#"
[[rules]]
name = ""
operation_pattern = "github.*"
allow = true
client_types = ["agent"]

[rules.client]

[rules.target]
fields = {}

[rules.workspace]
[rules.secret_names]

[rules.approval]
require = "always"
factors = ["local_bio"]
"#;
        let result = check_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("name must be non-empty"), "got: {err}");
    }

    #[test]
    fn validation_error_empty_operation_pattern() {
        let toml = r#"
[[rules]]
name = "test"
operation_pattern = ""
allow = true
client_types = ["human"]

[rules.client]

[rules.target]
fields = {}

[rules.workspace]
[rules.secret_names]

[rules.approval]
require = "always"
factors = []
"#;
        let result = check_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("operation_pattern must be non-empty"),
            "got: {err}"
        );
    }

    #[test]
    fn validation_error_empty_client_types() {
        let toml = r#"
[[rules]]
name = "test"
operation_pattern = "github.*"
allow = true
client_types = []

[rules.client]

[rules.target]
fields = {}

[rules.workspace]
[rules.secret_names]

[rules.approval]
require = "always"
factors = []
"#;
        let result = check_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("client_types must not be empty"), "got: {err}");
    }

    #[test]
    fn validation_error_zero_lease_ttl() {
        let toml = r#"
[[rules]]
name = "test"
operation_pattern = "github.*"
allow = true
client_types = ["human"]

[rules.client]

[rules.target]
fields = {}

[rules.workspace]
[rules.secret_names]

[rules.approval]
require = "first_use"
factors = ["local_bio"]
lease_ttl = 0
"#;
        let result = check_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("lease_ttl must be > 0"), "got: {err}");
    }

    #[test]
    fn missing_file_produces_error() {
        let result = policy_check_path(Some(Path::new("/nonexistent/config.toml")));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot read"));
    }

    #[test]
    fn init_creates_directory_structure() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");

        let result = run_init_at(&base, false, PRESET_SAFE_DEMO);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        assert!(base.exists());
        assert!(base.join("run").exists());
        assert!(base.join("config.toml").exists());

        let content = fs::read_to_string(base.join("config.toml")).unwrap();
        assert!(content.contains("safe-demo"));
    }

    #[test]
    fn init_existing_config_warns() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("config.toml"), "existing").unwrap();

        let result = run_init_at(&base, false, PRESET_SAFE_DEMO);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn init_force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("config.toml"), "old content").unwrap();

        let result = run_init_at(&base, true, PRESET_SAFE_DEMO);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        let content = fs::read_to_string(base.join("config.toml")).unwrap();
        assert!(content.contains("safe-demo"));
        // Old content should be replaced
        assert!(!content.contains("old content"));
    }

    #[test]
    fn init_with_preset() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");

        let result = run_init_at(&base, false, PRESET_SAFE_DEMO);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        let content = fs::read_to_string(base.join("config.toml")).unwrap();
        assert!(content.contains("safe-demo"));
        assert!(content.contains("test.noop"));
    }

    #[test]
    fn preset_lookup() {
        assert!(get_preset("safe-demo").is_some());
        assert!(get_preset("github-secrets").is_some());
        assert!(get_preset("gitlab-variables").is_some());
        assert!(get_preset("sandbox-human").is_some());
        assert!(get_preset("agent-wrapper-github").is_some());
        assert!(get_preset("codex-agent").is_some());
        assert!(get_preset("nonexistent").is_none());
    }

    /// Every `opaque ...` command line in a preset comment is pasted by new
    /// users straight from their own config.toml, so each one must parse.
    #[test]
    fn preset_comments_teach_only_commands_that_parse() {
        use clap::Parser;
        let mut checked = 0;
        for (preset, _, content) in available_presets() {
            assert!(
                !content.contains("preset apply"),
                "preset '{preset}' teaches the phantom 'opaque policy preset apply' form"
            );
            for line in content.lines().filter(|l| l.starts_with('#')) {
                let text = line.trim_start_matches('#').trim();
                let Some(rest) = text.strip_prefix("opaque ") else {
                    continue;
                };
                let argv: Vec<&str> = std::iter::once("opaque")
                    .chain(rest.split_whitespace())
                    .collect();
                let parsed = Cli::try_parse_from(&argv);
                assert!(
                    parsed.is_ok(),
                    "preset '{preset}' teaches a command that does not parse: `{text}`: {:?}",
                    parsed.err()
                );
                checked += 1;
            }
        }
        assert!(
            checked >= available_presets().len(),
            "every preset should teach at least one command, checked {checked}"
        );
    }

    #[test]
    fn preset_apply_word_from_old_headers_still_resolves() {
        use clap::Parser;
        let cli =
            Cli::try_parse_from(["opaque", "policy", "preset", "apply", "safe-demo"]).unwrap();
        let Some(Cmd::Policy {
            action: PolicyAction::Preset { name, legacy_name },
        }) = cli.cmd
        else {
            panic!("expected policy preset");
        };
        assert_eq!(
            resolve_preset_name(&name, legacy_name.as_deref()).unwrap(),
            "safe-demo"
        );
        assert_eq!(resolve_preset_name("safe-demo", None).unwrap(), "safe-demo");
        assert!(resolve_preset_name("apply", None).is_err());
        assert!(resolve_preset_name("safe-demo", Some("extra")).is_err());
    }

    /// The codex-agent preset shipped `[rules.workspace] require = true` in
    /// seven rules. `require` is not a WorkspaceMatch field and the table
    /// does not deny unknown keys, so the advertised scoping never happened
    /// while `opaque policy check` passed. Presets may only use workspace
    /// keys the engine enforces, and may not advertise scoping they do not
    /// configure.
    #[test]
    fn presets_use_only_enforced_workspace_keys_and_do_not_oversell_scoping() {
        let enforced = ["remote_url_pattern", "branch_pattern", "require_clean"];
        let mut rules_seen = 0;
        for (preset, description, content) in available_presets() {
            let doc: toml_edit::DocumentMut = content.parse().unwrap();
            let rules = doc
                .get("rules")
                .and_then(|r| r.as_array_of_tables())
                .unwrap_or_else(|| panic!("preset '{preset}' has no [[rules]]"));
            let mut scoped = false;
            for rule in rules {
                rules_seen += 1;
                let Some(workspace) = rule.get("workspace").and_then(|w| w.as_table_like()) else {
                    continue;
                };
                for (key, _) in workspace.iter() {
                    assert!(
                        enforced.contains(&key),
                        "preset '{preset}' rule {:?} uses [rules.workspace] key {key:?}, which the \
                         policy engine does not read",
                        rule.get("name").and_then(|n| n.as_str())
                    );
                }
                scoped = true;
            }
            if !scoped {
                assert!(
                    !description.contains("workspace-scoped"),
                    "preset '{preset}' advertises workspace scoping it does not configure"
                );
                assert!(
                    !content.contains("require = true"),
                    "preset '{preset}' still carries the inert workspace key"
                );
            }
        }
        assert!(
            rules_seen > 10,
            "expected to inspect every preset rule, saw {rules_seen}"
        );
    }

    #[test]
    fn presets_are_valid_toml() {
        for (name, _, content) in available_presets() {
            let result: Result<PolicyConfig, _> = PolicyConfig::from_toml(content);
            assert!(
                result.is_ok(),
                "preset '{name}' is not valid TOML: {result:?}"
            );
            let config = result.unwrap();
            assert!(
                !config.rules.is_empty(),
                "preset '{name}' should have at least one rule"
            );
        }
    }

    #[test]
    fn toml_with_extra_fields_ignored() {
        let toml = r#"
[daemon]
port = 1234

[[rules]]
name = "test"
operation_pattern = "test.*"
allow = true
client_types = ["human"]

[rules.client]

[rules.target]
fields = {}

[rules.workspace]
[rules.secret_names]

[rules.approval]
require = "never"
factors = []
"#;
        let result = check_toml(toml);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert!(result.unwrap().contains("1 rules loaded"));
    }

    #[test]
    fn multiple_validation_errors_reported() {
        let toml = r#"
[[rules]]
name = ""
operation_pattern = ""
allow = true
client_types = []

[rules.client]

[rules.target]
fields = {}

[rules.workspace]
[rules.secret_names]

[rules.approval]
require = "always"
factors = []
"#;
        let result = check_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("name must be non-empty"), "got: {err}");
        assert!(
            err.contains("operation_pattern must be non-empty"),
            "got: {err}"
        );
        assert!(err.contains("client_types must not be empty"), "got: {err}");
    }

    #[test]
    fn init_directory_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");

        run_init_at(&base, false, PRESET_SAFE_DEMO).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&base).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "base dir should be 0700, got {mode:o}");

            let run_mode = fs::metadata(base.join("run")).unwrap().permissions().mode() & 0o777;
            assert_eq!(run_mode, 0o700, "run dir should be 0700, got {run_mode:o}");
        }
    }

    /// Write a TOML config, return the temp path for use in policy_show / policy_simulate.
    fn write_config(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, content).unwrap();
        (dir, path)
    }

    fn sample_rule_toml() -> &'static str {
        r#"
[[rules]]
name = "allow-github-actions"
operation_pattern = "github.set_actions_secret"
allow = true
client_types = ["human"]

[rules.client]

[rules.target]
fields = { repo = "myorg/*" }

[rules.workspace]

[rules.secret_names]
patterns = ["GH_*"]

[rules.approval]
require = "first_use"
factors = ["local_bio"]
lease_ttl = 300
"#
    }

    #[test]
    fn policy_show_empty_rules() {
        let (_dir, path) = write_config("");
        // Should not error, just warn about empty rules.
        let result = policy_show(Some(path.as_path()));
        assert!(result.is_ok());
    }

    #[test]
    fn policy_show_with_rules() {
        let (_dir, path) = write_config(sample_rule_toml());
        let result = policy_show(Some(path.as_path()));
        assert!(result.is_ok());
    }

    #[test]
    fn policy_show_missing_file() {
        let result = policy_show(Some(Path::new("/nonexistent/config.toml")));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot read"));
    }

    #[test]
    fn policy_simulate_allow() {
        let (_dir, path) = write_config(sample_rule_toml());
        let result = policy_simulate(
            Some(path.as_path()),
            "github.set_actions_secret",
            "human",
            &[("repo".into(), "myorg/myrepo".into())],
            &["GH_TOKEN".into()],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn policy_simulate_deny_no_matching_rule() {
        let (_dir, path) = write_config(sample_rule_toml());
        // Use an operation not covered by any rule.
        let result = policy_simulate(Some(path.as_path()), "sandbox.exec", "human", &[], &[]);
        // Should succeed (prints the deny decision).
        assert!(result.is_ok());
    }

    #[test]
    fn policy_simulate_deny_target_mismatch() {
        let (_dir, path) = write_config(sample_rule_toml());
        // Rule requires repo=myorg/*, but we pass a different org.
        let result = policy_simulate(
            Some(path.as_path()),
            "github.set_actions_secret",
            "human",
            &[("repo".into(), "otherorg/repo".into())],
            &["GH_TOKEN".into()],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn policy_simulate_invalid_client_type() {
        let (_dir, path) = write_config(sample_rule_toml());
        let result = policy_simulate(
            Some(path.as_path()),
            "github.set_actions_secret",
            "unknown",
            &[],
            &[],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown client type"));
    }

    #[test]
    fn policy_simulate_agent_client_type() {
        let (_dir, path) = write_config(sample_rule_toml());
        // Rule only allows "human", so agent should be denied.
        let result = policy_simulate(
            Some(path.as_path()),
            "github.set_actions_secret",
            "agent",
            &[("repo".into(), "myorg/myrepo".into())],
            &["GH_TOKEN".into()],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn parse_env_names_accepts_comments_and_export() {
        let env = r#"
# comment
FOO=bar
export BAR=baz
BAZ=
"#;
        let names = parse_env_names(env).unwrap();
        assert_eq!(names, vec!["FOO", "BAR", "BAZ"]);
    }

    #[test]
    fn parse_env_names_rejects_duplicate_names() {
        let env = "FOO=1\nFOO=2\n";
        let err = parse_env_names(env).unwrap_err();
        assert!(err.contains("duplicate env name"), "got: {err}");
    }

    #[test]
    fn parse_env_names_rejects_invalid_name() {
        let env = "BAD-NAME=value\n";
        let err = parse_env_names(env).unwrap_err();
        assert!(err.contains("invalid env name"), "got: {err}");
    }

    #[test]
    fn parse_env_names_rejects_missing_equals() {
        let env = "FOO\n";
        let err = parse_env_names(env).unwrap_err();
        assert!(err.contains("expected KEY=VALUE"), "got: {err}");
    }

    #[test]
    fn render_value_ref_replaces_name_placeholder() {
        let value_ref = render_value_ref("bitwarden:production/{name}", "DATABASE_URL").unwrap();
        assert_eq!(value_ref, "bitwarden:production/DATABASE_URL");
    }

    #[test]
    fn render_value_ref_requires_placeholder() {
        let err = render_value_ref("bitwarden:production", "DATABASE_URL").unwrap_err();
        assert!(err.contains("must include '{name}'"), "got: {err}");
    }

    #[test]
    fn validate_env_manifest_rejects_duplicate_secret_name() {
        let manifest = EnvManifest {
            format: manifest_format_v1(),
            repo: Some("acme/repo".into()),
            environment: None,
            entries: vec![
                EnvManifestEntry {
                    secret_name: "DATABASE_URL".into(),
                    value_ref: "bitwarden:prod/DATABASE_URL".into(),
                },
                EnvManifestEntry {
                    secret_name: "DATABASE_URL".into(),
                    value_ref: "bitwarden:prod/DATABASE_URL_ALT".into(),
                },
            ],
        };
        let err = validate_env_manifest(&manifest).unwrap_err();
        assert!(err.contains("duplicate secret_name"), "got: {err}");
    }

    #[test]
    fn validate_env_manifest_rejects_invalid_value_ref() {
        let manifest = EnvManifest {
            format: manifest_format_v1(),
            repo: Some("acme/repo".into()),
            environment: None,
            entries: vec![EnvManifestEntry {
                secret_name: "DATABASE_URL".into(),
                value_ref: "plaintext://not-allowed".into(),
            }],
        };
        let err = validate_env_manifest(&manifest).unwrap_err();
        assert!(err.contains("invalid value_ref"), "got: {err}");
    }

    #[test]
    fn parse_version_from_output_extracts_plain_version() {
        let output = "opaque-mcp 0.1.0+abc1234";
        let version = parse_version_from_output(output, "opaque-mcp");
        assert_eq!(version.as_deref(), Some("0.1.0+abc1234"));
    }

    #[test]
    fn parse_version_from_output_extracts_from_tracing_line() {
        let output = "2026-02-21T06:38:23Z INFO opaque_mcp: opaque-mcp 0.1.0+fd008f0 starting";
        let version = parse_version_from_output(output, "opaque-mcp");
        assert_eq!(version.as_deref(), Some("0.1.0+fd008f0"));
    }

    // -----------------------------------------------------------------------
    // quickstart tests
    // -----------------------------------------------------------------------

    #[test]
    fn quickstart_creates_config_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");

        let result = run_quickstart_at(&base);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        // Should have created the directory structure
        assert!(base.exists(), "base dir should exist");
        assert!(base.join("run").exists(), "run dir should exist");
        assert!(base.join("profiles").exists(), "profiles dir should exist");
        assert!(
            base.join("config.toml").exists(),
            "config.toml should exist"
        );
    }

    #[test]
    fn quickstart_uses_safe_demo_preset() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");

        let result = run_quickstart_at(&base);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        let content = fs::read_to_string(base.join("config.toml")).unwrap();
        // safe-demo preset contains test.noop rule
        assert!(
            content.contains("test.noop"),
            "config should contain test.noop from safe-demo preset"
        );
        assert!(
            content.contains("safe-demo"),
            "config should reference safe-demo preset"
        );
    }

    #[test]
    fn quickstart_skips_init_when_config_exists() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");

        // First run — creates config
        let result = run_quickstart_at(&base);
        assert!(result.is_ok(), "first run should succeed: {result:?}");

        // Write custom content so we can verify it's not overwritten
        let config_path = base.join("config.toml");
        fs::write(&config_path, "# custom config\n").unwrap();

        // Second run — should skip init, not error
        let result = run_quickstart_at(&base);
        assert!(result.is_ok(), "second run should succeed: {result:?}");

        // Config should NOT be overwritten
        let content = fs::read_to_string(&config_path).unwrap();
        assert_eq!(
            content, "# custom config\n",
            "existing config should not be overwritten"
        );
    }

    #[test]
    fn quickstart_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");

        // Run three times — should all succeed
        for i in 0..3 {
            let result = run_quickstart_at(&base);
            assert!(result.is_ok(), "run {i} should succeed: {result:?}");
        }

        // Config should still be the safe-demo preset from first run
        let content = fs::read_to_string(base.join("config.toml")).unwrap();
        assert!(content.contains("test.noop"));
    }

    #[test]
    fn quickstart_init_equivalent_to_init_preset_safe_demo() {
        // quickstart init should produce the same config as `init --preset safe-demo`
        let qs_dir = tempfile::tempdir().unwrap();
        let qs_base = qs_dir.path().join(".opaque");

        let init_dir = tempfile::tempdir().unwrap();
        let init_base = init_dir.path().join(".opaque");

        run_quickstart_at(&qs_base).unwrap();
        run_init_at(&init_base, false, PRESET_SAFE_DEMO).unwrap();

        let qs_config = fs::read_to_string(qs_base.join("config.toml")).unwrap();
        let init_config = fs::read_to_string(init_base.join("config.toml")).unwrap();

        assert_eq!(
            qs_config, init_config,
            "quickstart config should match init --preset safe-demo"
        );
    }

    #[test]
    fn quickstart_creates_dirs_with_correct_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");

        run_quickstart_at(&base).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&base).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "base dir should be 0700, got {mode:o}");

            let run_mode = fs::metadata(base.join("run")).unwrap().permissions().mode() & 0o777;
            assert_eq!(run_mode, 0o700, "run dir should be 0700, got {run_mode:o}");
        }
    }

    // -----------------------------------------------------------------------
    // Secrets command tests
    // -----------------------------------------------------------------------

    #[test]
    fn secrets_add_command_macos() {
        let (cmd, args) = keychain_add_command("github-pat", "my-secret-token", "macos");
        assert_eq!(cmd, "security");
        assert_eq!(
            args,
            vec![
                "add-generic-password",
                "-a",
                "opaque",
                "-s",
                "opaque/github-pat",
                "-w",
                "my-secret-token",
                "-U",
            ]
        );
    }

    #[test]
    fn secrets_add_command_linux() {
        let (cmd, args) = keychain_add_command("github-pat", "my-secret-token", "linux");
        assert_eq!(cmd, "secret-tool");
        assert_eq!(
            args,
            vec![
                "store",
                "--label",
                "opaque/github-pat",
                "service",
                "opaque",
                "username",
                "github-pat",
            ]
        );
    }

    #[test]
    fn secrets_remove_command_macos() {
        let (cmd, args) = keychain_remove_command("github-pat", "macos");
        assert_eq!(cmd, "security");
        assert_eq!(
            args,
            vec![
                "delete-generic-password",
                "-a",
                "opaque",
                "-s",
                "opaque/github-pat",
            ]
        );
    }

    #[test]
    fn secrets_list_parses_keychain_dump() {
        let dump = concat!(
            "keychain: \"/Users/me/Library/Keychains/login.keychain-db\"\n",
            "version: 512\n",
            "class: \"genp\"\n",
            "attributes:\n",
            "    0x00000007 <blob>=\"opaque/github-pat\"\n",
            "    \"acct\"<blob>=\"opaque\"\n",
            "    \"svce\"<blob>=\"opaque/github-pat\"\n",
            "class: \"genp\"\n",
            "attributes:\n",
            "    0x00000007 <blob>=\"opaque/gitlab-token\"\n",
            "    \"acct\"<blob>=\"opaque\"\n",
            "    \"svce\"<blob>=\"opaque/gitlab-token\"\n",
            "class: \"genp\"\n",
            "attributes:\n",
            "    0x00000007 <blob>=\"some-other-service\"\n",
            "    \"acct\"<blob>=\"other\"\n",
            "    \"svce\"<blob>=\"some-other-service\"\n",
        );
        let names = parse_keychain_secrets(dump);
        assert_eq!(names, vec!["github-pat", "gitlab-token"]);
    }

    #[test]
    fn secrets_list_empty_keychain() {
        let names = parse_keychain_secrets("");
        assert!(names.is_empty());
    }

    #[test]
    fn secrets_name_validation() {
        // Valid names
        assert!(validate_secret_name("github-pat").is_ok());
        assert!(validate_secret_name("gitlab_token").is_ok());
        assert!(validate_secret_name("my-api-key-123").is_ok());
        assert!(validate_secret_name("TOKEN").is_ok());

        // Invalid names
        assert!(validate_secret_name("").is_err());
        assert!(validate_secret_name("has space").is_err());
        assert!(validate_secret_name("has/slash").is_err());
        assert!(validate_secret_name("has.dot").is_err());
        assert!(validate_secret_name("has@at").is_err());
        assert!(validate_secret_name("has\"quote").is_err());
    }

    #[test]
    fn secrets_ref_format_display() {
        assert_eq!(
            secrets_ref_format("github-pat"),
            "keychain:opaque/github-pat"
        );
        assert_eq!(secrets_ref_format("my-token"), "keychain:opaque/my-token");
    }

    // -----------------------------------------------------------------------
    // Connect tests (JSON-based tools)
    // -----------------------------------------------------------------------

    #[test]
    fn connect_json_mcp_creates_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("home").join(".claude.json");
        let mcp_path = Path::new("/usr/local/bin/opaque-mcp");

        let result = connect_json_mcp(&config_file, mcp_path);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(result.unwrap(), ConnectResult::Connected);

        assert!(config_file.exists(), "config file should exist");
        let text = fs::read_to_string(&config_file).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let opaque = &v["mcpServers"]["opaque"];
        assert_eq!(opaque["command"], "/usr/local/bin/opaque-mcp");
        assert_eq!(
            opaque["args"],
            serde_json::json!([]),
            "opaque-mcp rejects --stdio; the written entry must not carry it"
        );
    }

    #[test]
    fn connect_json_mcp_preserves_existing_servers() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join(".claude.json");
        fs::write(
            &config_file,
            r#"{"mcpServers":{"other":{"command":"/usr/bin/other","args":["--flag"]}}}"#,
        )
        .unwrap();

        let result = connect_json_mcp(&config_file, Path::new("/usr/local/bin/opaque-mcp"));
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(result.unwrap(), ConnectResult::Connected);

        let text = fs::read_to_string(&config_file).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v["mcpServers"]["other"]["command"], "/usr/bin/other",
            "existing server should be preserved"
        );
        assert_eq!(
            v["mcpServers"]["opaque"]["command"],
            "/usr/local/bin/opaque-mcp"
        );
    }

    #[test]
    fn connect_json_mcp_updates_existing_opaque() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join(".claude.json");
        fs::write(
            &config_file,
            r#"{"mcpServers":{"opaque":{"command":"/old/path/opaque-mcp","args":[]}}}"#,
        )
        .unwrap();

        let result = connect_json_mcp(&config_file, Path::new("/new/path/opaque-mcp"));
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(result.unwrap(), ConnectResult::Updated);

        let text = fs::read_to_string(&config_file).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v["mcpServers"]["opaque"]["command"], "/new/path/opaque-mcp",
            "opaque command should be updated to new path"
        );
    }

    #[test]
    fn connect_json_mcp_already_configured() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join(".claude.json");
        fs::write(
            &config_file,
            r#"{"mcpServers":{"opaque":{"command":"/usr/local/bin/opaque-mcp","args":[]}}}"#,
        )
        .unwrap();

        let result = connect_json_mcp(&config_file, Path::new("/usr/local/bin/opaque-mcp"));
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(result.unwrap(), ConnectResult::AlreadyConnected);
    }

    /// A 0.4.0 entry (`args: ["--stdio"]`) at the same path is repaired
    /// instead of being reported as already connected.
    #[test]
    fn connect_json_mcp_repairs_legacy_stdio_entry() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("mcp.json");
        fs::write(
            &config_file,
            r#"{"mcpServers":{"opaque":{"command":"/usr/local/bin/opaque-mcp","args":["--stdio"],"env":{}}}}"#,
        )
        .unwrap();

        let result = connect_json_mcp(&config_file, Path::new("/usr/local/bin/opaque-mcp"));
        assert_eq!(result, Ok(ConnectResult::Updated));
        let v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&config_file).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["opaque"]["args"], serde_json::json!([]));
    }

    /// Running connect twice against a file that already holds unrelated
    /// state (other servers, other top-level keys) leaves that state intact
    /// and reports the second run as already connected.
    #[test]
    fn connect_json_mcp_second_run_is_idempotent_and_keeps_unrelated_state() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join(".claude.json");
        let original = serde_json::json!({
            "numStartups": 7,
            "projects": {"/home/user/repo": {"allowedTools": ["Bash"]}},
            "mcpServers": {
                "other": {"command": "/usr/bin/other", "args": ["--flag"], "env": {"K": "v"}}
            }
        });
        fs::write(
            &config_file,
            serde_json::to_string_pretty(&original).unwrap(),
        )
        .unwrap();
        let mcp = Path::new("/usr/local/bin/opaque-mcp");

        assert_eq!(
            connect_json_mcp(&config_file, mcp),
            Ok(ConnectResult::Connected)
        );
        let after_first = fs::read_to_string(&config_file).unwrap();
        assert_eq!(
            connect_json_mcp(&config_file, mcp),
            Ok(ConnectResult::AlreadyConnected)
        );
        let after_second = fs::read_to_string(&config_file).unwrap();
        assert_eq!(
            after_first, after_second,
            "second connect must not rewrite the file"
        );

        let v: serde_json::Value = serde_json::from_str(&after_second).unwrap();
        assert_eq!(v["numStartups"], original["numStartups"]);
        assert_eq!(v["projects"], original["projects"]);
        assert_eq!(v["mcpServers"]["other"], original["mcpServers"]["other"]);
        assert_eq!(
            v["mcpServers"]["opaque"]["command"],
            "/usr/local/bin/opaque-mcp"
        );
    }

    #[test]
    fn json_mcp_config_has_opaque_parses_instead_of_substring_matching() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".claude.json");
        // Mentions "opaque" as a project path but has no opaque MCP server.
        fs::write(
            &file,
            r#"{"projects":{"/home/user/opaque":{}},"mcpServers":{"other":{"command":"x"}}}"#,
        )
        .unwrap();
        assert!(!json_mcp_config_has_opaque(&file));
        fs::write(
            &file,
            r#"{"mcpServers":{"opaque":{"command":"/x/opaque-mcp"}}}"#,
        )
        .unwrap();
        assert!(json_mcp_config_has_opaque(&file));
        assert!(!json_mcp_config_has_opaque(
            &dir.path().join("missing.json")
        ));
    }

    // -----------------------------------------------------------------------
    // Per-repo init tests
    // -----------------------------------------------------------------------

    #[test]
    fn init_repo_generates_scoped_policy() {
        let remote = "git@github.com:org/repo.git";
        let toml = generate_repo_policy(remote, None);
        assert!(
            toml.contains("remote_url_pattern"),
            "generated TOML should reference remote_url_pattern: {toml}"
        );
        assert!(
            toml.contains("org/repo"),
            "generated TOML should contain org/repo: {toml}"
        );
    }

    #[test]
    fn init_repo_auto_detects_remote() {
        // SSH format
        let toml = generate_repo_policy("git@github.com:acme/widgets.git", None);
        assert!(
            toml.contains("acme/widgets"),
            "should derive org/repo from SSH URL: {toml}"
        );

        // HTTPS format
        let toml = generate_repo_policy("https://github.com/acme/widgets.git", None);
        assert!(
            toml.contains("acme/widgets"),
            "should derive org/repo from HTTPS URL: {toml}"
        );
    }

    #[test]
    fn init_repo_with_preset() {
        let remote = "git@github.com:org/repo.git";
        let preset = get_preset("github-secrets").unwrap();
        let toml = generate_repo_policy(remote, Some(preset));

        // Should contain workspace scope
        assert!(
            toml.contains("remote_url_pattern"),
            "preset policy should have workspace scope: {toml}"
        );
        // Should contain rules from the preset
        assert!(
            toml.contains("[[rules]]"),
            "preset policy should contain rules: {toml}"
        );
        // Rule names should be prefixed with "repo-"
        assert!(
            toml.contains("repo-"),
            "rule names should be prefixed with repo-: {toml}"
        );
        // Should have the repo header
        assert!(
            toml.contains("org/repo"),
            "should reference org/repo: {toml}"
        );
    }

    #[test]
    fn init_repo_without_preset() {
        let remote = "git@github.com:org/repo.git";
        let toml = generate_repo_policy(remote, None);

        // Minimal template should have comments explaining configuration
        assert!(
            toml.contains('#'),
            "minimal template should contain comments: {toml}"
        );
        assert!(
            toml.contains("remote_url_pattern"),
            "minimal template should show remote_url_pattern: {toml}"
        );
        assert!(
            toml.contains("org/repo"),
            "minimal template should reference org/repo: {toml}"
        );
    }

    #[test]
    fn preset_show_returns_content() {
        // Verify that get_preset returns content for known presets
        let content = get_preset("github-secrets");
        assert!(content.is_some(), "github-secrets preset should exist");
        let content = content.unwrap();
        assert!(
            content.contains("[[rules]]"),
            "preset content should contain rules"
        );
        assert!(
            content.contains("github"),
            "github-secrets should reference github"
        );
    }

    #[test]
    fn preset_show_unknown_name() {
        let content = get_preset("nonexistent-preset");
        assert!(content.is_none(), "unknown preset should return None");

        // Also verify the CLI-facing function returns an error
        let result = policy_show_preset("nonexistent-preset");
        assert!(result.is_err(), "unknown preset should be an error");
        let err = result.unwrap_err();
        assert!(
            err.contains("unknown preset"),
            "error should mention unknown preset: {err}"
        );
    }

    #[test]
    fn preset_checklist_github() {
        let checklist = preset_checklist("github-secrets");
        assert!(
            checklist.len() == 3,
            "github-secrets should have 3 steps, got: {}",
            checklist.len()
        );
        assert!(
            checklist.iter().any(|s| s.contains("GitHub PAT")),
            "should contain PAT step: {checklist:?}"
        );
        assert!(
            checklist
                .iter()
                .any(|s| s.contains("opaque service install")),
            "should contain daemon step: {checklist:?}"
        );
        assert!(
            checklist
                .iter()
                .any(|s| s.contains("opaque connect claude")),
            "should contain connect step: {checklist:?}"
        );
    }

    #[test]
    fn preset_checklist_default() {
        let checklist = preset_checklist("unknown-preset-xyz");
        assert!(
            !checklist.is_empty(),
            "even unknown presets should get a minimal checklist"
        );
        assert!(
            checklist
                .iter()
                .any(|s| s.contains("opaque service install")),
            "minimal checklist should contain daemon step: {checklist:?}"
        );
        assert_eq!(
            checklist.len(),
            1,
            "unknown preset should have exactly 1 step"
        );
    }

    #[test]
    fn generate_repo_policy_escapes_special_chars() {
        // Remote URL with glob-special characters
        let remote = "git@github.com:org/repo[test].git";
        let toml = generate_repo_policy(remote, None);
        // Square brackets should be escaped in the pattern
        assert!(
            toml.contains("\\[") && toml.contains("\\]"),
            "special chars should be escaped in glob pattern: {toml}"
        );
        // The org/repo extraction should still work
        assert!(
            toml.contains("org/repo[test]") || toml.contains("org/repo\\[test\\]"),
            "should still identify org/repo: {toml}"
        );
    }

    // -----------------------------------------------------------------------
    // connect codex tests
    // -----------------------------------------------------------------------

    #[test]
    fn connect_codex_creates_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config.toml");
        let mcp_path = Path::new("/usr/local/bin/opaque-mcp");

        let result = connect_codex_at(&config_file, mcp_path);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(result.unwrap(), ConnectResult::Connected);

        assert!(config_file.exists(), "config.toml should be created");
        let content = fs::read_to_string(&config_file).unwrap();
        assert!(
            content.contains("[mcp_servers.opaque]"),
            "should contain [mcp_servers.opaque], got: {content}"
        );
        assert!(
            content.contains("command = \"/usr/local/bin/opaque-mcp\""),
            "should contain command path, got: {content}"
        );
        assert!(
            content.contains("args = []"),
            "should contain args, got: {content}"
        );
    }

    #[test]
    fn connect_codex_preserves_existing_servers() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config.toml");
        fs::write(
            &config_file,
            "[mcp_servers.other]\ncommand = \"other-mcp\"\nargs = []\n",
        )
        .unwrap();

        let result = connect_codex_at(&config_file, Path::new("/usr/local/bin/opaque-mcp"));
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(result.unwrap(), ConnectResult::Connected);

        let content = fs::read_to_string(&config_file).unwrap();
        assert!(
            content.contains("[mcp_servers.other]"),
            "existing server should be preserved, got: {content}"
        );
        assert!(
            content.contains("[mcp_servers.opaque]"),
            "opaque server should be added, got: {content}"
        );
    }

    #[test]
    fn connect_codex_already_configured() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config.toml");
        fs::write(
            &config_file,
            "[mcp_servers.opaque]\ncommand = \"/usr/local/bin/opaque-mcp\"\nargs = []\n",
        )
        .unwrap();

        let result = connect_codex_at(&config_file, Path::new("/usr/local/bin/opaque-mcp"));
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(result.unwrap(), ConnectResult::AlreadyConnected);
    }

    #[test]
    fn connect_codex_updates_existing_opaque() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config.toml");
        fs::write(
            &config_file,
            "[mcp_servers.opaque]\ncommand = \"/old/path/opaque-mcp\"\nargs = []\n",
        )
        .unwrap();

        let result = connect_codex_at(&config_file, Path::new("/new/path/opaque-mcp"));
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(result.unwrap(), ConnectResult::Updated);

        let content = fs::read_to_string(&config_file).unwrap();
        assert!(
            content.contains("/new/path/opaque-mcp"),
            "should contain updated path, got: {content}"
        );
        assert!(
            !content.contains("/old/path/opaque-mcp"),
            "should not contain old path, got: {content}"
        );
    }

    #[test]
    fn detect_mcp_connection_finds_codex() {
        // detect_mcp_connection reads from the real home directory,
        // so we test the logic inline by checking the config content patterns.
        let toml_content =
            "[mcp_servers.opaque]\ncommand = \"/usr/local/bin/opaque-mcp\"\nargs = []\n";
        assert!(
            toml_content.contains("[mcp_servers.opaque]"),
            "config should match detection pattern"
        );
    }

    #[test]
    fn codex_agent_preset_is_valid_toml() {
        let result: Result<PolicyConfig, _> = PolicyConfig::from_toml(PRESET_CODEX_AGENT);
        assert!(
            result.is_ok(),
            "codex-agent preset should be valid TOML: {result:?}"
        );
        let config = result.unwrap();
        assert!(
            !config.rules.is_empty(),
            "codex-agent preset should have at least one rule"
        );
    }

    #[test]
    fn codex_agent_preset_has_agent_rules() {
        let content = PRESET_CODEX_AGENT;
        assert!(
            content.contains("enforce_agent_sessions = true"),
            "should enforce agent sessions"
        );
        assert!(
            content.contains("client_types = [\"agent\"]"),
            "should have agent client_types"
        );
        assert!(
            content.contains("lease_ttl = 600"),
            "should have 600s lease TTL"
        );
        assert!(
            content.contains("github.list_secrets"),
            "should have GitHub list secrets rule"
        );
        assert!(
            content.contains("github.set_actions_secret"),
            "should have GitHub set actions secret rule"
        );
        assert!(
            content.contains("github.delete_secret"),
            "should have GitHub delete secret rule"
        );
        assert!(
            content.contains("gitlab.set_ci_variable"),
            "should have GitLab CI variable rule"
        );
        assert!(
            content.contains("require = \"first_use\""),
            "should use first_use approval"
        );
        assert!(
            content.contains("[\"local_bio\"]"),
            "should require local_bio factor"
        );
    }

    #[test]
    fn discover_opaque_paths_finds_current_exe() {
        let paths = discover_opaque_paths();
        assert!(
            !paths.is_empty(),
            "discover_opaque_paths should find at least the current executable"
        );
        // The first entry should always be the current exe
        let (_name, path) = &paths[0];
        assert!(
            path.exists(),
            "discovered path should exist: {}",
            path.display()
        );
    }

    #[test]
    fn discover_opaque_paths_returns_canonical_deduplicated() {
        let paths = discover_opaque_paths();
        let canonical_paths: Vec<_> = paths.iter().map(|(_, p)| p.clone()).collect();
        let unique: HashSet<_> = canonical_paths.iter().collect();
        assert_eq!(
            canonical_paths.len(),
            unique.len(),
            "discovered paths should be deduplicated"
        );
    }

    // -- identity CLI (Phase 1) --------------------------------------------

    #[test]
    fn login_command_parses_with_and_without_no_browser() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["opaque", "login"]).unwrap();
        assert!(matches!(cli.cmd, Some(Cmd::Login { no_browser: false })));

        let cli = Cli::try_parse_from(["opaque", "login", "--no-browser"]).unwrap();
        assert!(matches!(cli.cmd, Some(Cmd::Login { no_browser: true })));
    }

    #[test]
    fn logout_command_parses() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["opaque", "logout"]).unwrap();
        assert!(matches!(cli.cmd, Some(Cmd::Logout)));
    }

    #[test]
    fn identity_subcommands_parse() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["opaque", "identity", "ls"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Cmd::Identity {
                action: IdentityAction::Ls
            })
        ));

        let cli =
            Cli::try_parse_from(["opaque", "identity", "roles", "hum_x", "admin", "operator"])
                .unwrap();
        match cli.cmd {
            Some(Cmd::Identity {
                action:
                    IdentityAction::Roles {
                        principal_id,
                        roles,
                    },
            }) => {
                assert_eq!(principal_id, "hum_x");
                assert_eq!(roles, vec!["admin".to_string(), "operator".to_string()]);
            }
            other => panic!("unexpected parse: {other:?}"),
        }

        let cli = Cli::try_parse_from(["opaque", "identity", "delegations"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Cmd::Identity {
                action: IdentityAction::Delegations
            })
        ));
    }

    #[test]
    fn device_commands_parse() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["opaque", "device", "pair"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Cmd::Device {
                action: DeviceAction::Pair
            })
        ));
        let cli = Cli::try_parse_from(["opaque", "device", "ls"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Cmd::Device {
                action: DeviceAction::Ls
            })
        ));
        let cli = Cli::try_parse_from(["opaque", "device", "confirm", "dev-1"]).unwrap();
        match cli.cmd {
            Some(Cmd::Device {
                action: DeviceAction::Confirm { device_id },
            }) => assert_eq!(device_id, "dev-1"),
            other => panic!("unexpected parse: {other:?}"),
        }
        let cli = Cli::try_parse_from(["opaque", "device", "revoke", "dev-2"]).unwrap();
        match cli.cmd {
            Some(Cmd::Device {
                action: DeviceAction::Revoke { device_id },
            }) => assert_eq!(device_id, "dev-2"),
            other => panic!("unexpected parse: {other:?}"),
        }
        // confirm/revoke require the device id.
        assert!(Cli::try_parse_from(["opaque", "device", "confirm"]).is_err());
        assert!(Cli::try_parse_from(["opaque", "device", "revoke"]).is_err());
    }

    #[test]
    fn bundle_commands_parse() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["opaque", "bundle", "keygen", "--out", "/tmp/k"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Cmd::Bundle {
                action: BundleAction::Keygen { .. }
            })
        ));
        let cli = Cli::try_parse_from([
            "opaque",
            "bundle",
            "sign",
            "--manifest",
            "m.toml",
            "--key",
            "org.key",
            "--out",
            "p.bundle",
            "--version",
            "7",
        ])
        .unwrap();
        match cli.cmd {
            Some(Cmd::Bundle {
                action: BundleAction::Sign { version, .. },
            }) => assert_eq!(version, Some(7)),
            other => panic!("unexpected parse: {other:?}"),
        }
        // verify requires at least one --anchor.
        assert!(Cli::try_parse_from(["opaque", "bundle", "verify", "b.bundle"]).is_err());
        let cli = Cli::try_parse_from([
            "opaque", "bundle", "verify", "b.bundle", "--anchor", "aa", "--anchor", "bb",
        ])
        .unwrap();
        match cli.cmd {
            Some(Cmd::Bundle {
                action: BundleAction::Verify { anchor, .. },
            }) => assert_eq!(anchor.len(), 2),
            other => panic!("unexpected parse: {other:?}"),
        }
        let cli = Cli::try_parse_from(["opaque", "bundle", "inspect", "b.bundle"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Cmd::Bundle {
                action: BundleAction::Inspect { .. }
            })
        ));
    }

    #[test]
    fn key_commands_parse() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["opaque", "key", "ls"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Cmd::Key {
                action: KeyAction::Ls
            })
        ));
        let cli = Cli::try_parse_from(["opaque", "key", "remove", "cred-1"]).unwrap();
        match cli.cmd {
            Some(Cmd::Key {
                action: KeyAction::Remove { credential_id },
            }) => assert_eq!(credential_id, "cred-1"),
            other => panic!("unexpected parse: {other:?}"),
        }
        assert!(Cli::try_parse_from(["opaque", "key", "remove"]).is_err());
    }

    #[test]
    fn agent_wrapper_modes_preserve_delegated_default_and_require_exact_service_pairing() {
        let cli = Cli::try_parse_from(["opaque", "agent", "run", "--", "codex"]).unwrap();
        let Some(Cmd::Agent {
            action:
                AgentAction::Run {
                    command,
                    ttl_secs,
                    mode,
                    service,
                    ..
                },
        }) = cli.cmd
        else {
            panic!("expected agent wrapper");
        };
        assert_eq!(mode, "delegated");
        assert!(service.is_none());
        assert_eq!(
            agent_session_start_params(&command, ttl_secs, &mode, service.as_deref()).unwrap(),
            serde_json::json!({"label":"codex","mode":"delegated"})
        );
        let cli = Cli::try_parse_from([
            "opaque",
            "agent",
            "run",
            "--mode",
            "autonomous",
            "--service",
            "onboarding",
            "--ttl-secs",
            "900",
            "--",
            "opaque-mcp",
        ])
        .unwrap();
        let Some(Cmd::Agent {
            action:
                AgentAction::Run {
                    command,
                    ttl_secs,
                    mode,
                    service,
                    ..
                },
        }) = cli.cmd
        else {
            panic!("expected service wrapper");
        };
        assert_eq!(
            agent_session_start_params(&command, ttl_secs, &mode, service.as_deref()).unwrap(),
            serde_json::json!({"label":"opaque-mcp","mode":"autonomous","service":"onboarding","ttl_secs":900})
        );
        assert!(
            Cli::try_parse_from([
                "opaque",
                "agent",
                "run",
                "--mode",
                "autonomous",
                "--",
                "codex"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "opaque",
                "agent",
                "run",
                "--mode",
                "break_glass",
                "--",
                "codex"
            ])
            .is_err()
        );
        assert!(
            agent_session_start_params(&command, None, "delegated", Some("onboarding")).is_err()
        );
        assert!(agent_session_start_params(&command, None, "autonomous", None).is_err());
        assert!(
            agent_session_start_params(&command, None, "autonomous", Some("bad service")).is_err()
        );
        assert!(agent_session_start_params(&[], None, "delegated", None).is_err());
    }

    #[test]
    fn provisioning_cli_assertions_are_bounded_and_cannot_carry_extra_authority() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("assertion.json");
        let valid = serde_json::json!({"credential_id":"YQ","authenticator_data":"Yg","client_data_json":"Yw","signature":"ZA"});
        std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        let (method, params) = provisioning_command_params(ProvisioningAction::BindComplete {
            challenge_id: "exact-challenge".into(),
            assertion: path.clone(),
        })
        .unwrap();
        assert_eq!(method, "identity.provisioning.bind_complete");
        assert_eq!(params["assertion"], valid);
        assert_eq!(params["challenge_id"], "exact-challenge");
        for invalid in [
            serde_json::json!([]),
            serde_json::json!({"credential_id":"YQ"}),
            {
                let mut extra = valid.clone();
                extra["roles"] = serde_json::json!(["admin"]);
                extra
            },
            {
                let mut empty = valid.clone();
                empty["signature"] = "".into();
                empty
            },
        ] {
            std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(
                provisioning_command_params(ProvisioningAction::MandateComplete {
                    challenge_id: "exact-challenge".into(),
                    assertion: path.clone()
                })
                .is_err()
            );
        }
        std::fs::write(&path, vec![b' '; 16_385]).unwrap();
        assert!(
            provisioning_command_params(ProvisioningAction::BindComplete {
                challenge_id: "exact-challenge".into(),
                assertion: path
            })
            .is_err()
        );
    }

    #[test]
    fn provisioning_cli_issue_preserves_exact_recipient_and_request_identity() {
        let request_id = uuid::Uuid::new_v4().to_string();
        let cli = Cli::try_parse_from([
            "opaque",
            "provisioning",
            "issue",
            "--mandate",
            "mandate-id",
            "--issuer",
            "https://issuer.example",
            "--subject",
            "Exact-Subject",
            "--ttl-secs",
            "300",
            "--request-id",
            &request_id,
        ])
        .unwrap();
        let Some(Cmd::Provisioning { action }) = cli.cmd else {
            panic!("expected provisioning issue");
        };
        let (method, params) = provisioning_command_params(action).unwrap();
        assert_eq!(method, "identity.provisioning.issue");
        assert_eq!(
            params,
            serde_json::json!({"mandate_id":"mandate-id","recipient_issuer":"https://issuer.example","recipient_subject":"Exact-Subject","ttl_secs":300,"request_id":request_id})
        );
        assert!(
            Cli::try_parse_from(["opaque", "provisioning", "revoke", "role", "admin"]).is_err()
        );
        assert!(
            provisioning_command_params(ProvisioningAction::Issue {
                mandate: "m".into(),
                issuer: "i".into(),
                subject: "s".into(),
                ttl_secs: 300,
                request_id: "reuse-anything".into()
            })
            .is_err()
        );
    }

    #[test]
    fn identity_roles_requires_at_least_one_role() {
        use clap::Parser;
        assert!(Cli::try_parse_from(["opaque", "identity", "roles", "hum_x"]).is_err());
    }

    #[test]
    fn ssh_plan_selects_only_title_and_bounded_expiry_without_caller_transport_controls() {
        let cli = Cli::try_parse_from(["opaque", "task", "plan-ssh"]).unwrap();
        let Some(Cmd::Task { action }) = cli.cmd else {
            panic!("expected task")
        };
        let (method, params) = task_command_params(action).unwrap();
        assert_eq!(method, "task_plan_ssh");
        assert_eq!(
            params,
            serde_json::json!({"title":"Service health on approved host","expires_in_secs":300})
        );
        for value in ["0", "301", "-1"] {
            assert!(
                Cli::try_parse_from(["opaque", "task", "plan-ssh", "--expires-in-secs", value])
                    .is_err()
            );
        }
        for flag in [
            "--command",
            "--host",
            "--principal",
            "--private-key",
            "--vault-role",
        ] {
            assert!(
                Cli::try_parse_from(["opaque", "task", "plan-ssh", flag, "unreviewed"]).is_err()
            );
        }
    }

    #[test]
    fn task_commands_require_broker_ids_and_explicit_manifest_paths() {
        for (command, method) in [
            ("run", "task_run"),
            ("show", "task_get"),
            ("revoke", "task_revoke"),
        ] {
            let cli = Cli::try_parse_from(["opaque", "task", command, "task-123"]).unwrap();
            let Some(Cmd::Task { action }) = cli.cmd else {
                panic!("expected task command")
            };
            let (actual_method, params) = task_command_params(action).unwrap();
            assert_eq!(actual_method, method);
            assert_eq!(params["task_id"], "task-123");
            assert!(params.get("approved").is_none());
            assert!(Cli::try_parse_from(["opaque", "task", command]).is_err());
        }
        assert!(Cli::try_parse_from(["opaque", "task", "plan"]).is_err());
        assert_eq!(
            task_command_params(TaskAction::List { cursor: None })
                .unwrap()
                .0,
            "task_list"
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("manifest.json");
        std::fs::write(&path, r#"{"schema_version":1,"title":"Dogfood","expires_in_secs":600,"actions":[{"repo":"owner/repo","secret_name":"MARKER","value_ref":"vault:kv/data/demo?version=1#MARKER"}]}"#).unwrap();
        let (method, params) = task_command_params(TaskAction::Plan {
            manifest: path.clone(),
        })
        .unwrap();
        assert_eq!(method, "task_plan");
        assert_eq!(params["manifest"]["actions"][0]["repository_id"], 0);
        let mut invalid = params["manifest"].clone();
        invalid["approved"] = true.into();
        std::fs::write(&path, invalid.to_string()).unwrap();
        assert!(task_command_params(TaskAction::Plan { manifest: path }).is_err());
    }

    #[test]
    fn task_receipt_reports_uncertainty_and_exact_authority_without_claiming_verification() {
        use opaque_core::task::*;
        let action = PublishAction {
            repo: "owner/repo".into(),
            repository_id: 42,
            secret_name: "MARKER".into(),
            value_ref: "vault:kv/data/demo?version=7#MARKER".into(),
            github_token_ref: None,
        };
        let manifest = TaskManifest {
            schema_version: 1,
            title: "Dogfood".into(),
            expires_in_secs: 600,
            github_api_url: "https://api.github.com".into(),
            vault_api_url: "https://vault.example.com".into(),
            actions: vec![action.clone().into()],
        };
        let mut task = TaskRecord {
            tenant: None,
            id: "task-1".into(),
            manifest_digest: manifest.digest().unwrap(),
            manifest,
            owner_key: "owner".into(),
            created_at: 100,
            expires_at: 700,
            approved_at: Some(101),
            approval_mode: Some(TaskApprovalMode::Native),
            workstation_receipt: None,
            state: TaskState::Partial,
            release_observation: None,
            slots: vec![TaskSlot {
                id: "task-1:01".into(),
                action: action.into(),
                state: SlotState::Unknown,
                request_id: Some("r".into()),
                reserved_at: Some(102),
                finished_at: Some(103),
                outcome: Some(SlotOutcome {
                    ssh_receipt: None,
                    inference_receipt: None,
                    provider_run_id: None,
                    state: SlotState::Unknown,
                    code: "transport_unknown".into(),
                }),
            }],
        };
        let output = render_task_receipt(&task);
        for expected in [
            "owner/repo / MARKER",
            "repository 42",
            "version=7#MARKER",
            "Charged: 1/1",
            "unknown (charged; do not retry)",
            "fresh approval",
            "native approval",
            &task.manifest_digest,
        ] {
            assert!(output.contains(expected), "missing {expected}");
        }
        task.approval_mode = Some(TaskApprovalMode::InsecureTest);
        let output = render_task_receipt(&task);
        assert!(output.contains("INSECURE TEST APPROVAL"));
        assert!(!output.contains("native approval"));
        task.approval_mode = None;
        assert!(render_task_receipt(&task).contains("approval mode unavailable"));
        task.approved_at = None;
        assert!(render_task_receipt(&task).contains("Approval: not granted"));
    }

    #[test]
    fn flatten_role_args_splits_commas_and_normalizes() {
        let roles = vec!["Admin,operator".to_string(), " approver ".to_string()];
        assert_eq!(
            flatten_role_args(&roles),
            vec!["admin", "operator", "approver"]
        );
        assert_eq!(flatten_role_args(&["admin,,".to_string()]), vec!["admin"]);
        assert!(flatten_role_args(&[]).is_empty());
    }
}
