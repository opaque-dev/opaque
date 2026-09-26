//! Interactive first-run wizard for `opaque init --interactive`.
//!
//! Detects available secret providers, generates configuration, and
//! registers the MCP server with the user's AI coding tools.
//!
//! Design: All detection and generation logic is testable without I/O
//! by accepting trait objects / closures for environment access.

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Provider detection
// ---------------------------------------------------------------------------

/// Type of secret provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderType {
    GitHub,
    GitLab,
    Vault,
    OnePassword,
    Bitwarden,
    Aws,
    Gcp,
    Azure,
}

impl ProviderType {
    /// All provider types in display order.
    pub const ALL: &'static [ProviderType] = &[
        ProviderType::GitHub,
        ProviderType::GitLab,
        ProviderType::Vault,
        ProviderType::OnePassword,
        ProviderType::Bitwarden,
        ProviderType::Aws,
        ProviderType::Gcp,
        ProviderType::Azure,
    ];

    /// Human-readable name.
    pub fn label(self) -> &'static str {
        match self {
            ProviderType::GitHub => "GitHub",
            ProviderType::GitLab => "GitLab",
            ProviderType::Vault => "HashiCorp Vault",
            ProviderType::OnePassword => "1Password",
            ProviderType::Bitwarden => "Bitwarden",
            ProviderType::Aws => "AWS",
            ProviderType::Gcp => "Google Secret Manager",
            ProviderType::Azure => "Azure Key Vault",
        }
    }
}

/// How much of a provider's configuration was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionStatus {
    /// Required local configuration found; this does not verify a provider login.
    Ready,
    /// Some credentials found but others missing.
    Partial,
    /// Nothing found for this provider.
    NotFound,
}

/// A provider detected (or not) by the wizard.
#[derive(Debug, Clone)]
pub struct DetectedProvider {
    pub name: String,
    pub provider_type: ProviderType,
    pub status: DetectionStatus,
    /// Human-readable hints about what was found / missing.
    pub config_hints: Vec<String>,
}

/// Abstraction over environment access so tests can inject fake state.
pub trait Environment {
    /// Read an environment variable (like `std::env::var`).
    fn var(&self, key: &str) -> Option<String>;

    /// Check whether a CLI tool exists on PATH (like `which <name>`).
    fn has_command(&self, name: &str) -> bool;

    /// Check whether a filesystem path exists.
    fn path_exists(&self, path: &Path) -> bool;

    /// Return the user's home directory.
    fn home_dir(&self) -> PathBuf;
}

/// Real environment backed by the OS.
pub struct RealEnvironment;

impl Environment for RealEnvironment {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn has_command(&self, name: &str) -> bool {
        std::process::Command::new("which")
            .arg(name)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn home_dir(&self) -> PathBuf {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

/// Detect all known providers using the given environment.
pub fn detect_providers(env: &dyn Environment) -> Vec<DetectedProvider> {
    let mut providers = Vec::new();

    for pt in ProviderType::ALL {
        providers.push(detect_single(*pt, env));
    }

    providers
}

fn detect_single(pt: ProviderType, env: &dyn Environment) -> DetectedProvider {
    match pt {
        ProviderType::GitHub => detect_github(env),
        ProviderType::GitLab => detect_gitlab(env),
        ProviderType::Vault => detect_vault(env),
        ProviderType::OnePassword => detect_onepassword(env),
        ProviderType::Bitwarden => detect_bitwarden(env),
        ProviderType::Aws => detect_aws(env),
        ProviderType::Gcp => detect_gcp(env),
        ProviderType::Azure => detect_azure(env),
    }
}

fn detect_github(env: &dyn Environment) -> DetectedProvider {
    let gh_token = env.var("GITHUB_TOKEN").or_else(|| env.var("GH_TOKEN"));
    let has_gh_cli = env.has_command("gh");

    let mut hints = Vec::new();

    let status = if gh_token.is_some() {
        hints.push("GITHUB_TOKEN or GH_TOKEN found".into());
        DetectionStatus::Ready
    } else if has_gh_cli {
        hints.push("gh CLI found on PATH".into());
        hints.push("Set GITHUB_TOKEN for direct API access".into());
        DetectionStatus::Partial
    } else {
        hints.push("Set GITHUB_TOKEN or GH_TOKEN, or install gh CLI".into());
        DetectionStatus::NotFound
    };

    DetectedProvider {
        name: "GitHub".into(),
        provider_type: ProviderType::GitHub,
        status,
        config_hints: hints,
    }
}

fn detect_gitlab(env: &dyn Environment) -> DetectedProvider {
    let token = env
        .var("GITLAB_TOKEN")
        .or_else(|| env.var("GITLAB_PRIVATE_TOKEN"));

    let mut hints = Vec::new();

    let status = if token.is_some() {
        hints.push("GITLAB_TOKEN or GITLAB_PRIVATE_TOKEN found".into());
        DetectionStatus::Ready
    } else {
        hints.push("Set GITLAB_TOKEN or GITLAB_PRIVATE_TOKEN".into());
        DetectionStatus::NotFound
    };

    DetectedProvider {
        name: "GitLab".into(),
        provider_type: ProviderType::GitLab,
        status,
        config_hints: hints,
    }
}

fn present(env: &dyn Environment, key: &str) -> bool {
    env.var(key).is_some_and(|value| !value.is_empty())
}

/// Detection never retrieves keychain values or performs a provider login.
fn ref_available(env: &dyn Environment, reference: &str) -> bool {
    reference
        .strip_prefix("env:")
        .is_some_and(|name| !name.is_empty() && present(env, name))
}

fn detect_vault(env: &dyn Environment) -> DetectedProvider {
    let endpoint = present(env, "OPAQUE_VAULT_URL");
    let reference = env.var("OPAQUE_VAULT_TOKEN_REF");
    let credential = reference.as_deref().is_some_and(|r| ref_available(env, r));
    let status = if endpoint && credential {
        DetectionStatus::Ready
    } else if endpoint
        || reference.is_some()
        || present(env, "VAULT_ADDR")
        || present(env, "VAULT_TOKEN")
    {
        DetectionStatus::Partial
    } else {
        DetectionStatus::NotFound
    };
    DetectedProvider { name: "HashiCorp Vault".into(), provider_type: ProviderType::Vault, status,
        config_hints: vec!["Set OPAQUE_VAULT_URL and OPAQUE_VAULT_TOKEN_REF (for example env:VAULT_TOKEN); VAULT_ADDR is not loaded automatically".into(),
            "Without an explicit token ref, the broker uses keychain:opaque/vault-token; keychain contents are not inspected during setup".into(),
            "Vault is a credential resolver for authorized consumers; setup does not grant a vault.read or vault.list operation".into()] }
}

fn detect_onepassword(env: &dyn Environment) -> DetectedProvider {
    let has_op = env.has_command("op");
    let connect_token = env.var("OP_CONNECT_TOKEN");

    let mut hints = Vec::new();

    let status = if has_op {
        hints.push("op CLI found on PATH".into());
        DetectionStatus::Ready
    } else if connect_token.is_some() {
        hints.push("OP_CONNECT_TOKEN found".into());
        DetectionStatus::Ready
    } else {
        hints.push("Install op CLI or set OP_CONNECT_TOKEN".into());
        DetectionStatus::NotFound
    };

    DetectedProvider {
        name: "1Password".into(),
        provider_type: ProviderType::OnePassword,
        status,
        config_hints: hints,
    }
}

fn detect_bitwarden(env: &dyn Environment) -> DetectedProvider {
    let cli = env
        .var("OPAQUE_BITWARDEN_CLI_PATH")
        .is_some_and(|path| Path::new(&path).is_absolute() && env.path_exists(Path::new(&path)))
        || env.has_command("bws");
    let reference = env.var("OPAQUE_BITWARDEN_TOKEN_REF");
    let credential = reference.as_deref().is_some_and(|r| ref_available(env, r));
    let status = if cli && credential {
        DetectionStatus::Ready
    } else if cli || reference.is_some() || present(env, "BWS_ACCESS_TOKEN") {
        DetectionStatus::Partial
    } else {
        DetectionStatus::NotFound
    };
    DetectedProvider { name: "Bitwarden".into(), provider_type: ProviderType::Bitwarden, status,
        config_hints: vec!["Install the official bws CLI or set its absolute path in OPAQUE_BITWARDEN_CLI_PATH".into(),
            "Set OPAQUE_BITWARDEN_TOKEN_REF=env:BWS_ACCESS_TOKEN to use that environment token; the default is keychain:opaque/bitwarden-token".into(),
            "The broker verifies and binds the bws executable before authorizing an operation".into()] }
}

fn detect_aws(env: &dyn Environment) -> DetectedProvider {
    let region = present(env, "OPAQUE_AWS_REGION");
    let access = env.var("OPAQUE_AWS_ACCESS_KEY_REF");
    let secret = env.var("OPAQUE_AWS_SECRET_KEY_REF");
    let credentials = access.as_deref().is_some_and(|r| ref_available(env, r))
        && secret.as_deref().is_some_and(|r| ref_available(env, r));
    let session = env.var("OPAQUE_AWS_SESSION_TOKEN_REF");
    let session_ready = session.as_deref().is_none_or(|r| ref_available(env, r));
    let ambient = present(env, "AWS_ACCESS_KEY_ID")
        || present(env, "AWS_SECRET_ACCESS_KEY")
        || env.path_exists(&env.home_dir().join(".aws/credentials"));
    let status = if region && credentials && session_ready {
        DetectionStatus::Ready
    } else if region || access.is_some() || secret.is_some() || session.is_some() || ambient {
        DetectionStatus::Partial
    } else {
        DetectionStatus::NotFound
    };
    DetectedProvider { name: "AWS".into(), provider_type: ProviderType::Aws, status,
        config_hints: vec!["Set OPAQUE_AWS_REGION and explicit OPAQUE_AWS_ACCESS_KEY_REF / OPAQUE_AWS_SECRET_KEY_REF".into(),
            "For environment credentials, use env:AWS_ACCESS_KEY_ID and env:AWS_SECRET_ACCESS_KEY; temporary credentials also require OPAQUE_AWS_SESSION_TOKEN_REF=env:AWS_SESSION_TOKEN".into(),
            "Ambient AWS variables, AWS profiles and ~/.aws/credentials are not loaded automatically; default refs use the opaque AWS keychain entries".into()] }
}

fn detect_gcp(env: &dyn Environment) -> DetectedProvider {
    let service_ref = env
        .var("OPAQUE_GCP_SERVICE_ACCOUNT_REF")
        .filter(|value| !value.is_empty());
    let service_file = env
        .var("OPAQUE_GCP_SERVICE_ACCOUNT_KEY")
        .filter(|value| !value.is_empty());
    let token_ref = env
        .var("OPAQUE_GCP_TOKEN_REF")
        .filter(|value| !value.is_empty());
    let configured = service_ref.is_some()
        || service_file.is_some()
        || token_ref.is_some()
        || present(env, "OPAQUE_GCP_ACCESS_TOKEN");
    let available = if let Some(reference) = service_ref {
        ref_available(env, &reference)
    } else if let Some(path) = service_file {
        Path::new(&path).is_absolute() && env.path_exists(Path::new(&path))
    } else if let Some(reference) = token_ref {
        ref_available(env, &reference)
    } else {
        present(env, "OPAQUE_GCP_ACCESS_TOKEN")
    };
    DetectedProvider { name: "Google Secret Manager".into(), provider_type: ProviderType::Gcp,
        status: if available { DetectionStatus::Ready } else if configured { DetectionStatus::Partial } else { DetectionStatus::NotFound },
        config_hints: vec!["Use OPAQUE_GCP_TOKEN_REF (env: or keychain:), OPAQUE_GCP_ACCESS_TOKEN, or OPAQUE_GCP_SERVICE_ACCOUNT_REF containing service-account JSON".into(),
            "OPAQUE_GCP_SERVICE_ACCOUNT_KEY supports an absolute private key-file path; the broker verifies ownership and permissions before reading it".into(),
            "Service-account tokens refresh automatically; the endpoint is the global Google Secret Manager API. ADC and gcloud profiles are not loaded automatically".into(),
            "GCP operation project parameters and gcp: references require the canonical numeric project number, not the project ID".into()] }
}

fn detect_azure(env: &dyn Environment) -> DetectedProvider {
    let configuration = [
        "OPAQUE_AZURE_VAULT_URL",
        "OPAQUE_AZURE_TENANT_ID",
        "OPAQUE_AZURE_CLIENT_ID",
    ];
    let required = configuration.iter().all(|key| present(env, key));
    let reference = env.var("OPAQUE_AZURE_CLIENT_SECRET_REF");
    let credential = reference.as_deref().map_or_else(
        || present(env, "OPAQUE_AZURE_CLIENT_SECRET"),
        |r| ref_available(env, r),
    );
    let any = configuration.iter().any(|key| present(env, key))
        || reference.is_some()
        || present(env, "OPAQUE_AZURE_CLIENT_SECRET");
    DetectedProvider { name: "Azure Key Vault".into(), provider_type: ProviderType::Azure,
        status: if required && credential { DetectionStatus::Ready } else if any { DetectionStatus::Partial } else { DetectionStatus::NotFound },
        config_hints: vec!["Set OPAQUE_AZURE_VAULT_URL=https://<vault>.vault.azure.net, OPAQUE_AZURE_TENANT_ID and OPAQUE_AZURE_CLIENT_ID".into(),
            "Set OPAQUE_AZURE_CLIENT_SECRET_REF to an env: or keychain: ref; the default is env:OPAQUE_AZURE_CLIENT_SECRET".into(),
            "Entra client-credentials tokens refresh automatically. The resolver accepts only the configured vault".into()] }
}

// ---------------------------------------------------------------------------
// AI tool detection
// ---------------------------------------------------------------------------

/// An AI coding tool detected on the system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedAiTool {
    pub name: String,
    pub config_dir: PathBuf,
    pub kind: AiToolKind,
}

/// Known AI tool kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiToolKind {
    ClaudeCode,
    Cursor,
    Codex,
}

/// Detect AI coding tools installed on the system.
pub fn detect_ai_tools(env: &dyn Environment) -> Vec<DetectedAiTool> {
    let home = env.home_dir();
    let mut tools = Vec::new();

    let claude_dir = home.join(".claude");
    if env.path_exists(&claude_dir) {
        tools.push(DetectedAiTool {
            name: "Claude Code".into(),
            config_dir: claude_dir,
            kind: AiToolKind::ClaudeCode,
        });
    }

    let cursor_dir = home.join(".cursor");
    if env.path_exists(&cursor_dir) {
        tools.push(DetectedAiTool {
            name: "Cursor".into(),
            config_dir: cursor_dir,
            kind: AiToolKind::Cursor,
        });
    }

    let codex_dir = home.join(".codex");
    if env.path_exists(&codex_dir) {
        tools.push(DetectedAiTool {
            name: "Codex".into(),
            config_dir: codex_dir,
            kind: AiToolKind::Codex,
        });
    }

    tools
}

// ---------------------------------------------------------------------------
// MCP config generation
// ---------------------------------------------------------------------------

/// Generate the MCP server JSON configuration for a given AI tool.
///
/// Returns the JSON string that should be merged into the tool's config file.
/// `opaque-mcp` takes no arguments: it always serves MCP over stdio.
pub fn generate_mcp_config(tool: &DetectedAiTool, opaque_mcp_path: &Path) -> String {
    let path_str = opaque_mcp_path.to_string_lossy();

    match tool.kind {
        AiToolKind::ClaudeCode | AiToolKind::Cursor => serde_json::json!({
            "mcpServers": {
                "opaque": new_json_mcp_server_entry(&path_str)
            }
        })
        .to_string(),
        AiToolKind::Codex => {
            format!("[mcp_servers.opaque]\ncommand = {path_str:?}\nargs = []\n")
        }
    }
}

/// Return the config file path for MCP registration for the given AI tool.
///
/// Claude Code reads user-scope `mcpServers` from `~/.claude.json`, not from
/// `~/.claude/settings.json` (which holds settings and is never consulted for
/// MCP servers). The detected `~/.claude` directory is only the install marker.
pub fn mcp_config_path(tool: &DetectedAiTool) -> PathBuf {
    match tool.kind {
        AiToolKind::ClaudeCode => {
            claude_code_mcp_config_path(tool.config_dir.parent().unwrap_or_else(|| Path::new(".")))
        }
        AiToolKind::Cursor => tool.config_dir.join("mcp.json"),
        AiToolKind::Codex => tool.config_dir.join("config.toml"),
    }
}

/// Claude Code's user-scope MCP configuration file (`~/.claude.json`).
pub fn claude_code_mcp_config_path(home: &Path) -> PathBuf {
    home.join(".claude.json")
}

/// Argument written by `opaque connect` in releases up to 0.4.0. The shipped
/// `opaque-mcp` exited with "unknown argument: --stdio" when a client passed
/// it, so it is removed whenever an existing entry is rewritten.
const LEGACY_STDIO_ARG: &str = "--stdio";

/// Outcome of merging the `opaque` server entry into a JSON MCP config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonMcpUpsert {
    /// No `opaque` entry existed; one was added.
    Created,
    /// An `opaque` entry existed and was rewritten (new command path, or the
    /// legacy `--stdio` argument was removed).
    Updated,
    /// An `opaque` entry already pointed at this binary without the legacy
    /// argument. Nothing was changed and nothing is written.
    Unchanged,
}

fn new_json_mcp_server_entry(command: &str) -> serde_json::Value {
    serde_json::json!({
        "command": command,
        "args": [],
        "env": {}
    })
}

/// Merge the `opaque` server entry into a client's `mcpServers` JSON object.
///
/// Every other top-level key and every other server entry is preserved (the
/// same file holds unrelated client state, for example Claude Code's whole
/// `~/.claude.json`). An existing `opaque` entry keeps its `env` and any
/// custom `args`; only `command` and the legacy `--stdio` argument change.
pub fn upsert_json_mcp_server(
    config: &mut serde_json::Value,
    opaque_mcp: &Path,
) -> Result<JsonMcpUpsert, String> {
    let path_str = opaque_mcp.to_string_lossy().to_string();

    let servers = config
        .as_object_mut()
        .ok_or("config is not a JSON object")?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or("mcpServers is not a JSON object")?;

    let existing_is_object = servers.get("opaque").is_some_and(|v| v.is_object());
    if !existing_is_object {
        let replaced = servers
            .insert("opaque".into(), new_json_mcp_server_entry(&path_str))
            .is_some();
        return Ok(if replaced {
            JsonMcpUpsert::Updated
        } else {
            JsonMcpUpsert::Created
        });
    }

    let entry = servers
        .get_mut("opaque")
        .and_then(|v| v.as_object_mut())
        .expect("checked to be an object above");
    let mut changed = false;

    if entry.get("command").and_then(|v| v.as_str()) != Some(path_str.as_str()) {
        entry.insert("command".into(), serde_json::Value::String(path_str));
        changed = true;
    }

    match entry.get_mut("args") {
        Some(serde_json::Value::Array(args)) => {
            let before = args.len();
            args.retain(|arg| arg.as_str() != Some(LEGACY_STDIO_ARG));
            if args.len() != before {
                changed = true;
            }
        }
        // A non-array `args` cannot be spawned by any client; reset it.
        Some(_) => {
            entry.insert("args".into(), serde_json::json!([]));
            changed = true;
        }
        // Absent `args` is valid for every supported client; leave it alone.
        None => {}
    }

    Ok(if changed {
        JsonMcpUpsert::Updated
    } else {
        JsonMcpUpsert::Unchanged
    })
}

/// Read a JSON MCP config file, merge the `opaque` entry, and write it back
/// only when something changed. Creates the file (and its parent directory)
/// when it does not exist yet.
pub fn upsert_json_mcp_config_file(
    config_file: &Path,
    opaque_mcp: &Path,
) -> Result<JsonMcpUpsert, String> {
    if let Some(parent) = config_file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }

    let mut config: serde_json::Value = if config_file.exists() {
        let content = std::fs::read_to_string(config_file)
            .map_err(|e| format!("cannot read {}: {e}", config_file.display()))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("cannot parse {}: {e}", config_file.display()))?
    } else {
        serde_json::json!({})
    };

    let outcome = upsert_json_mcp_server(&mut config, opaque_mcp)?;
    if outcome == JsonMcpUpsert::Unchanged {
        return Ok(outcome);
    }

    let formatted = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("cannot serialize config: {e}"))?;
    std::fs::write(config_file, formatted)
        .map_err(|e| format!("cannot write {}: {e}", config_file.display()))?;

    Ok(outcome)
}

/// Return the Codex config file path (~/.codex/config.toml).
pub fn codex_config_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".codex").join("config.toml")
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

/// Options controlling wizard config generation.
#[derive(Debug, Clone)]
pub struct WizardOptions {
    /// Whether to require biometric approval.
    pub require_biometric: bool,
    /// Lease TTL in seconds (0 = no lease).
    pub lease_ttl: u64,
    /// Whether to block Reveal operations for agents.
    pub block_agent_reveal: bool,
}

impl Default for WizardOptions {
    fn default() -> Self {
        Self {
            require_biometric: true,
            lease_ttl: 300,
            block_agent_reveal: true,
        }
    }
}

/// Generate a `config.toml` from detected providers and options.
pub fn generate_config(providers: &[DetectedProvider], options: &WizardOptions) -> String {
    let mut out = String::new();

    out.push_str("# Opaque configuration file\n");
    out.push_str("# Generated by `opaque init --interactive`.\n");
    out.push_str("#\n");
    out.push_str("# Rules are evaluated in order; the first matching rule wins.\n");
    out.push_str("# Default behavior is deny-all (no rules = nothing is permitted).\n\n");

    // Known human clients: none are added by default. Client classification is
    // audit-only — an agent drives the same signed CLI a human does, so a human
    // entry only labels audit records; it grants no bypass. Operators may add
    // known-human-client entries manually if they want that labeling.
    out.push_str("# ---- Known human clients ----\n");
    out.push_str("# None by default: classification is audit-only, not a security\n");
    out.push_str("# boundary. Add a known-human-client entry only for audit labeling.\n\n");

    // Agent reveal deny rule.
    if options.block_agent_reveal {
        out.push_str("# ---- Deny agents from revealing secrets ----\n\n");
        out.push_str("[[rules]]\n");
        out.push_str("name = \"deny-agent-reveal\"\n");
        out.push_str("operation_pattern = \"*.reveal\"\n");
        out.push_str("allow = false\n");
        out.push_str("client_types = [\"agent\"]\n\n");
    }

    let approval_require = if options.require_biometric {
        "first_use"
    } else {
        "never"
    };
    let factors = if options.require_biometric {
        "[\"local_bio\"]"
    } else {
        "[]"
    };

    // Provider rules.
    for provider in providers {
        if provider.status == DetectionStatus::NotFound {
            continue;
        }

        match provider.provider_type {
            ProviderType::GitHub => {
                write_provider_section(&mut out, "GitHub");
                // MCP-safe operations (list, set, delete — no reveal).
                write_rule(
                    &mut out,
                    "allow-github-list-secrets",
                    "github.list_secrets",
                    approval_require,
                    factors,
                    options.lease_ttl,
                    &["agent", "human"],
                );
                write_rule(
                    &mut out,
                    "allow-github-set-actions-secret",
                    "github.set_actions_secret",
                    approval_require,
                    factors,
                    options.lease_ttl,
                    &["agent", "human"],
                );
                write_rule(
                    &mut out,
                    "allow-github-set-codespaces-secret",
                    "github.set_codespaces_secret",
                    approval_require,
                    factors,
                    options.lease_ttl,
                    &["agent", "human"],
                );
                write_rule(
                    &mut out,
                    "allow-github-set-dependabot-secret",
                    "github.set_dependabot_secret",
                    approval_require,
                    factors,
                    options.lease_ttl,
                    &["agent", "human"],
                );
                write_rule(
                    &mut out,
                    "allow-github-set-org-secret",
                    "github.set_org_secret",
                    approval_require,
                    factors,
                    options.lease_ttl,
                    &["agent", "human"],
                );
                write_rule(
                    &mut out,
                    "allow-github-delete-secret",
                    "github.delete_secret",
                    approval_require,
                    factors,
                    options.lease_ttl,
                    &["agent", "human"],
                );
            }
            ProviderType::GitLab => {
                write_provider_section(&mut out, "GitLab");
                write_rule(
                    &mut out,
                    "allow-gitlab-set-ci-variable",
                    "gitlab.set_ci_variable",
                    approval_require,
                    factors,
                    options.lease_ttl,
                    &["agent", "human"],
                );
            }
            ProviderType::Vault => {
                write_provider_section(&mut out, "HashiCorp Vault");
                out.push_str("# Vault refs supply credentials to authorized consumer operations.\n# Add an exact consumer operation and its secret-ref policy; no generic Vault read/list operation is granted.\n\n");
            }
            ProviderType::OnePassword => {
                write_provider_section(&mut out, "1Password");
                write_rule(
                    &mut out,
                    "allow-onepassword-list-vaults",
                    "onepassword.list_vaults",
                    approval_require,
                    factors,
                    options.lease_ttl,
                    &["agent", "human"],
                );
                write_rule(
                    &mut out,
                    "allow-onepassword-list-items",
                    "onepassword.list_items",
                    approval_require,
                    factors,
                    options.lease_ttl,
                    &["agent", "human"],
                );
                write_rule(
                    &mut out,
                    "allow-onepassword-read-field",
                    "onepassword.read_field",
                    approval_require,
                    factors,
                    options.lease_ttl,
                    &["human"],
                );
            }
            ProviderType::Bitwarden => {
                write_provider_section(&mut out, "Bitwarden");
                for operation in ["bitwarden.list_projects", "bitwarden.list_secrets"] {
                    write_rule(
                        &mut out,
                        &format!("allow-{}", operation.replace('.', "-")),
                        operation,
                        approval_require,
                        factors,
                        options.lease_ttl,
                        &["agent", "human"],
                    );
                }
            }
            ProviderType::Aws => {
                write_provider_section(&mut out, "AWS");
                for operation in ["aws.get_caller_identity", "aws.list_secrets"] {
                    write_rule(
                        &mut out,
                        &format!("allow-{}", operation.replace('.', "-")),
                        operation,
                        approval_require,
                        factors,
                        options.lease_ttl,
                        &["agent", "human"],
                    );
                }
            }
            ProviderType::Gcp => {
                write_provider_section(&mut out, "Google Secret Manager");
                for operation in ["gcp.list_secrets", "gcp.get_secret"] {
                    write_rule(
                        &mut out,
                        &format!("allow-{}", operation.replace('.', "-")),
                        operation,
                        approval_require,
                        factors,
                        options.lease_ttl,
                        &["agent", "human"],
                    );
                }
            }
            ProviderType::Azure => {
                write_provider_section(&mut out, "Azure Key Vault");
                for operation in [
                    "azure.list_secrets",
                    "azure.list_keys",
                    "azure.list_certificates",
                    "azure.get_secret",
                ] {
                    write_rule(
                        &mut out,
                        &format!("allow-{}", operation.replace('.', "-")),
                        operation,
                        approval_require,
                        factors,
                        options.lease_ttl,
                        &["agent", "human"],
                    );
                }
            }
        }
    }

    // Always include test.noop.
    out.push_str("# ---- Test operation (for onboarding) ----\n\n");
    write_rule(
        &mut out,
        "allow-test-noop",
        "test.noop",
        "first_use",
        "[\"local_bio\"]",
        300,
        &["agent", "human"],
    );

    out
}

fn write_provider_section(out: &mut String, label: &str) {
    out.push_str(&format!("# ---- {label} rules ----\n\n"));
}

fn write_rule(
    out: &mut String,
    name: &str,
    operation_pattern: &str,
    approval_require: &str,
    factors: &str,
    lease_ttl: u64,
    client_types: &[&str],
) {
    let types_str: Vec<String> = client_types.iter().map(|t| format!("\"{t}\"")).collect();
    let types_joined = types_str.join(", ");

    out.push_str("[[rules]]\n");
    out.push_str(&format!("name = {name:?}\n"));
    out.push_str(&format!("operation_pattern = {operation_pattern:?}\n"));
    out.push_str("allow = true\n");
    out.push_str(&format!("client_types = [{types_joined}]\n\n"));
    out.push_str("[rules.approval]\n");
    out.push_str(&format!("require = {approval_require:?}\n"));
    out.push_str(&format!("factors = {factors}\n"));
    if lease_ttl > 0 && approval_require != "never" {
        out.push_str(&format!("lease_ttl = {lease_ttl}\n"));
    }
    out.push('\n');
}

// ---------------------------------------------------------------------------
// Wizard orchestrator (interactive I/O)
// ---------------------------------------------------------------------------

/// Run the full interactive wizard.
///
/// This is the entry point wired to `opaque init --interactive`.
/// It performs provider detection, user selection, config generation,
/// AI tool detection, and MCP registration.
pub fn run_interactive(base_dir: &Path, force: bool) -> Result<(), String> {
    use crate::ui;

    let env = RealEnvironment;
    let total_steps = 5;

    // Banner
    ui::banner(
        "Opaque Interactive Setup",
        "Detect providers, generate config, register MCP",
    );

    // Step 0: Check for existing config.
    let config_path = base_dir.join("config.toml");
    if config_path.exists() && !force {
        return Err(format!(
            "config already exists at {} (use --force to overwrite)",
            config_path.display()
        ));
    }

    // Step 1: Detect providers.
    ui::step(1, total_steps, "Detecting secret providers...");
    println!();
    let all_providers = detect_providers(&env);
    print_detection_results(&all_providers);

    let ready_or_partial: Vec<&DetectedProvider> = all_providers
        .iter()
        .filter(|p| p.status != DetectionStatus::NotFound)
        .collect();

    if ready_or_partial.is_empty() {
        ui::warn("No providers detected. Config will contain only test.noop.");
        println!();
    }

    // Step 2: Ask which providers to configure.
    ui::step(2, total_steps, "Selecting providers...");
    let selected = if ready_or_partial.is_empty() {
        Vec::new()
    } else {
        select_providers(&ready_or_partial)?
    };

    // Step 3: Generate config.
    ui::step(3, total_steps, "Generating configuration...");
    println!();
    let options = WizardOptions::default();
    let selected_providers: Vec<DetectedProvider> = selected.into_iter().cloned().collect();
    let config_content = generate_config(&selected_providers, &options);

    // Show summary before writing.
    let summary_lines: Vec<String> = vec![
        format!(
            "Providers:  {}",
            if selected_providers.is_empty() {
                "none (test.noop only)".to_string()
            } else {
                selected_providers
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ),
        format!(
            "Biometric:  {}",
            if options.require_biometric {
                "required (first_use)"
            } else {
                "disabled"
            }
        ),
        format!("Lease TTL:  {}s", options.lease_ttl),
        format!(
            "Agent reveal: {}",
            if options.block_agent_reveal {
                "blocked"
            } else {
                "allowed"
            }
        ),
        format!("Config path: {}", config_path.display()),
    ];
    let summary_refs: Vec<&str> = summary_lines.iter().map(|s| s.as_str()).collect();
    ui::section_box("Configuration Summary", &summary_refs);
    println!();

    // Write config.
    super::create_dir_0700(base_dir)?;
    super::create_dir_0700(&base_dir.join("run"))?;
    super::create_dir_0700(&base_dir.join("profiles"))?;
    std::fs::write(&config_path, &config_content)
        .map_err(|e| format!("failed to write {}: {e}", config_path.display()))?;
    ui::success(&format!("Wrote {}", config_path.display()));

    // Step 4: Detect AI tools & MCP registration.
    ui::step(4, total_steps, "Detecting AI coding tools...");
    println!();
    let ai_tools = detect_ai_tools(&env);
    if ai_tools.is_empty() {
        println!(
            "  {}  No AI coding tools detected (Claude Code, Cursor, Codex).",
            ui::status_badge("SKIP", ui::BadgeState::Warn),
        );
    } else {
        for tool in &ai_tools {
            println!(
                "  {}  {} ({})",
                ui::status_badge("FOUND", ui::BadgeState::Ok),
                tool.name,
                console::style(tool.config_dir.display()).dim(),
            );
        }
    }
    println!();

    // Offer MCP registration.
    let opaque_mcp_path = find_opaque_mcp_binary();
    if let Some(ref mcp_path) = opaque_mcp_path {
        for tool in &ai_tools {
            print!("  Register MCP server with {}? [Y/n] ", tool.name);
            let answer = read_line_trimmed();
            if answer.is_empty() || answer.starts_with('y') || answer.starts_with('Y') {
                match register_mcp(tool, mcp_path) {
                    Ok(()) => {
                        ui::success(&format!("Registered opaque MCP with {}", tool.name));
                    }
                    Err(e) => {
                        ui::warn(&format!("Could not register with {}: {e}", tool.name));
                    }
                }
            }
        }
    } else if !ai_tools.is_empty() {
        ui::warn("opaque-mcp binary not found; skipping MCP registration.");
        println!("  Install opaque-mcp and run 'opaque init --interactive' again,");
        println!("  or manually configure the MCP server.");
    }

    // Step 5: Next steps.
    println!();
    ui::step(5, total_steps, "Setup complete!");
    println!();
    ui::divider();
    println!();
    ui::info("Next steps:");
    ui::step(
        1,
        3,
        &format!(
            "Start the daemon:  {}",
            console::style("opaque service install").cyan()
        ),
    );
    ui::step(
        2,
        3,
        &format!(
            "Seal your config:  {}",
            console::style("opaque setup --seal").cyan()
        ),
    );
    ui::step(
        3,
        3,
        &format!(
            "Test the setup:    {}",
            console::style("opaque ping").cyan()
        ),
    );
    println!();

    Ok(())
}

/// Run detection only and print results (for `opaque init --detect`).
pub fn run_detect_only() {
    use crate::ui;

    let env = RealEnvironment;

    ui::banner(
        "Opaque Environment Detection",
        "Scanning for providers and AI tools",
    );

    ui::step(1, 2, "Detecting secret providers...");
    println!();
    let providers = detect_providers(&env);
    print_detection_results(&providers);

    ui::step(2, 2, "Detecting AI coding tools...");
    let ai_tools = detect_ai_tools(&env);
    if ai_tools.is_empty() {
        println!(
            "  {}  No AI coding tools detected.",
            ui::status_badge("NONE", ui::BadgeState::Warn),
        );
    } else {
        for tool in &ai_tools {
            println!(
                "  {}  {} ({})",
                ui::status_badge("FOUND", ui::BadgeState::Ok),
                tool.name,
                console::style(tool.config_dir.display()).dim(),
            );
        }
    }
    println!();
}

fn print_detection_results(providers: &[DetectedProvider]) {
    use crate::ui;

    let mut rows: Vec<Vec<String>> = Vec::new();
    for p in providers {
        let badge = match p.status {
            DetectionStatus::Ready => ui::status_badge("CONFIGURED", ui::BadgeState::Ok),
            DetectionStatus::Partial => ui::status_badge("PARTIAL", ui::BadgeState::Warn),
            DetectionStatus::NotFound => ui::status_badge("NOT FOUND", ui::BadgeState::Info),
        };
        let hints = p.config_hints.join("; ");
        rows.push(vec![p.name.clone(), badge, hints]);
    }
    ui::table(&["PROVIDER", "STATUS", "DETAILS"], &rows);
    println!();
}

fn select_providers<'a>(
    available: &[&'a DetectedProvider],
) -> Result<Vec<&'a DetectedProvider>, String> {
    println!("  Which providers do you want to configure?");
    for (i, p) in available.iter().enumerate() {
        let status_tag = match p.status {
            DetectionStatus::Ready => "(configured)",
            DetectionStatus::Partial => "(partial)",
            DetectionStatus::NotFound => "",
        };
        println!("    [{}] {} {}", i + 1, p.name, status_tag);
    }
    println!("    [a] All");
    println!();
    print!("  Enter selection (comma-separated, or 'a' for all): ");

    let input = read_line_trimmed();
    if input.is_empty() || input == "a" || input == "A" {
        return Ok(available.to_vec());
    }

    let mut selected = Vec::new();
    for part in input.split(',') {
        let part = part.trim();
        if let Ok(idx) = part.parse::<usize>() {
            if idx >= 1 && idx <= available.len() {
                selected.push(available[idx - 1]);
            } else {
                return Err(format!("invalid selection: {idx}"));
            }
        } else {
            return Err(format!("invalid input: {part}"));
        }
    }

    Ok(selected)
}

fn read_line_trimmed() -> String {
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim().to_string()
}

fn find_opaque_mcp_binary() -> Option<PathBuf> {
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

fn register_mcp(tool: &DetectedAiTool, opaque_mcp_path: &Path) -> Result<(), String> {
    let config_file = mcp_config_path(tool);

    // Ensure parent directory exists.
    if let Some(parent) = config_file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }

    if tool.kind == AiToolKind::Codex {
        return register_mcp_codex(&config_file, opaque_mcp_path);
    }

    // JSON-based registration (Claude Code, Cursor).
    upsert_json_mcp_config_file(&config_file, opaque_mcp_path).map(|_| ())
}

/// Register the opaque MCP server in a Codex TOML config file.
fn register_mcp_codex(config_file: &Path, opaque_mcp_path: &Path) -> Result<(), String> {
    let path_str = opaque_mcp_path.to_string_lossy().to_string();

    let mut doc: toml_edit::DocumentMut = if config_file.exists() {
        let content = std::fs::read_to_string(config_file)
            .map_err(|e| format!("cannot read {}: {e}", config_file.display()))?;
        content
            .parse()
            .map_err(|e| format!("cannot parse {}: {e}", config_file.display()))?
    } else {
        toml_edit::DocumentMut::new()
    };

    // Ensure [mcp_servers] table exists.
    if !doc.contains_key("mcp_servers") {
        doc["mcp_servers"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    // Create the [mcp_servers.opaque] entry.
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

    Ok(())
}

/// Check whether config already exists (helper extracted for testability).
fn check_existing_config(config_path: &Path, force: bool) -> Result<(), String> {
    if config_path.exists() && !force {
        return Err(format!(
            "config already exists at {} (use --force to overwrite)",
            config_path.display()
        ));
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
    use std::collections::HashMap;

    /// Fake environment for testing.
    struct FakeEnv {
        vars: HashMap<String, String>,
        commands: Vec<String>,
        paths: Vec<PathBuf>,
        home: PathBuf,
    }

    impl FakeEnv {
        fn new() -> Self {
            Self {
                vars: HashMap::new(),
                commands: Vec::new(),
                paths: Vec::new(),
                home: PathBuf::from("/home/testuser"),
            }
        }

        fn with_var(mut self, key: &str, value: &str) -> Self {
            self.vars.insert(key.into(), value.into());
            self
        }

        fn with_command(mut self, name: &str) -> Self {
            self.commands.push(name.into());
            self
        }

        fn with_path(mut self, path: &str) -> Self {
            self.paths.push(PathBuf::from(path));
            self
        }
    }

    impl Environment for FakeEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned()
        }

        fn has_command(&self, name: &str) -> bool {
            self.commands.iter().any(|c| c == name)
        }

        fn path_exists(&self, path: &Path) -> bool {
            self.paths.iter().any(|p| p == path)
        }

        fn home_dir(&self) -> PathBuf {
            self.home.clone()
        }
    }

    // =======================================================================
    // Detection tests
    // =======================================================================

    #[test]
    fn test_detect_github_token() {
        let env = FakeEnv::new().with_var("GITHUB_TOKEN", "ghp_abc123");
        let result = detect_github(&env);
        assert_eq!(result.provider_type, ProviderType::GitHub);
        assert_eq!(result.status, DetectionStatus::Ready);
        assert!(
            result
                .config_hints
                .iter()
                .any(|h| h.contains("GITHUB_TOKEN"))
        );

        // Also GH_TOKEN should work.
        let env2 = FakeEnv::new().with_var("GH_TOKEN", "ghp_xyz");
        let result2 = detect_github(&env2);
        assert_eq!(result2.status, DetectionStatus::Ready);
    }

    #[test]
    fn test_detect_github_gh_cli_partial() {
        let env = FakeEnv::new().with_command("gh");
        let result = detect_github(&env);
        assert_eq!(result.status, DetectionStatus::Partial);
        assert!(result.config_hints.iter().any(|h| h.contains("gh CLI")));
    }

    #[test]
    fn test_detect_github_not_found() {
        let env = FakeEnv::new();
        let result = detect_github(&env);
        assert_eq!(result.status, DetectionStatus::NotFound);
    }

    #[test]
    fn test_detect_gitlab_token() {
        let env = FakeEnv::new().with_var("GITLAB_TOKEN", "glpat-abc");
        let result = detect_gitlab(&env);
        assert_eq!(result.provider_type, ProviderType::GitLab);
        assert_eq!(result.status, DetectionStatus::Ready);

        // Also GITLAB_PRIVATE_TOKEN.
        let env2 = FakeEnv::new().with_var("GITLAB_PRIVATE_TOKEN", "glpat-xyz");
        let result2 = detect_gitlab(&env2);
        assert_eq!(result2.status, DetectionStatus::Ready);
    }

    #[test]
    fn test_detect_gitlab_not_found() {
        let env = FakeEnv::new();
        let result = detect_gitlab(&env);
        assert_eq!(result.status, DetectionStatus::NotFound);
    }

    #[test]
    fn test_detect_vault_addr() {
        let env = FakeEnv::new()
            .with_var("OPAQUE_VAULT_URL", "https://vault.example.com")
            .with_var("OPAQUE_VAULT_TOKEN_REF", "env:VAULT_TOKEN")
            .with_var("VAULT_TOKEN", "s.abc123");
        let result = detect_vault(&env);
        assert_eq!(result.provider_type, ProviderType::Vault);
        assert_eq!(result.status, DetectionStatus::Ready);
    }

    #[test]
    fn test_detect_vault_partial_addr_only() {
        let env = FakeEnv::new().with_var("VAULT_ADDR", "https://vault.example.com");
        let result = detect_vault(&env);
        assert_eq!(result.status, DetectionStatus::Partial);
        assert!(
            result
                .config_hints
                .iter()
                .any(|h| h.contains("VAULT_TOKEN"))
        );
    }

    #[test]
    fn test_detect_vault_partial_token_only() {
        let env = FakeEnv::new().with_var("VAULT_TOKEN", "s.abc123");
        let result = detect_vault(&env);
        assert_eq!(result.status, DetectionStatus::Partial);
        assert!(result.config_hints.iter().any(|h| h.contains("VAULT_ADDR")));
    }

    #[test]
    fn test_detect_onepassword_op_cli() {
        let env = FakeEnv::new().with_command("op");
        let result = detect_onepassword(&env);
        assert_eq!(result.provider_type, ProviderType::OnePassword);
        assert_eq!(result.status, DetectionStatus::Ready);
        assert!(result.config_hints.iter().any(|h| h.contains("op CLI")));
    }

    #[test]
    fn test_detect_onepassword_connect_token() {
        let env = FakeEnv::new().with_var("OP_CONNECT_TOKEN", "abc");
        let result = detect_onepassword(&env);
        assert_eq!(result.status, DetectionStatus::Ready);
        assert!(
            result
                .config_hints
                .iter()
                .any(|h| h.contains("OP_CONNECT_TOKEN"))
        );
    }

    #[test]
    fn test_detect_onepassword_not_found() {
        let env = FakeEnv::new();
        let result = detect_onepassword(&env);
        assert_eq!(result.status, DetectionStatus::NotFound);
    }

    #[test]
    fn test_detect_bitwarden() {
        let env = FakeEnv::new()
            .with_command("bws")
            .with_var("OPAQUE_BITWARDEN_TOKEN_REF", "env:BWS_ACCESS_TOKEN")
            .with_var("BWS_ACCESS_TOKEN", "bws.abc");
        let result = detect_bitwarden(&env);
        assert_eq!(result.provider_type, ProviderType::Bitwarden);
        assert_eq!(result.status, DetectionStatus::Ready);
    }

    #[test]
    fn test_detect_bitwarden_not_found() {
        let env = FakeEnv::new();
        let result = detect_bitwarden(&env);
        assert_eq!(result.status, DetectionStatus::NotFound);
    }

    #[test]
    fn test_detect_aws_credentials_env() {
        let env = FakeEnv::new()
            .with_var("OPAQUE_AWS_REGION", "us-east-1")
            .with_var("OPAQUE_AWS_ACCESS_KEY_REF", "env:AWS_ACCESS_KEY_ID")
            .with_var("OPAQUE_AWS_SECRET_KEY_REF", "env:AWS_SECRET_ACCESS_KEY")
            .with_var("AWS_ACCESS_KEY_ID", "AKIA...")
            .with_var("AWS_SECRET_ACCESS_KEY", "synthetic");
        let result = detect_aws(&env);
        assert_eq!(result.provider_type, ProviderType::Aws);
        assert_eq!(result.status, DetectionStatus::Ready);
    }

    #[test]
    fn test_detect_aws_credentials_file() {
        let env = FakeEnv::new().with_path("/home/testuser/.aws/credentials");
        let result = detect_aws(&env);
        assert_eq!(result.status, DetectionStatus::Partial);
        assert!(
            result
                .config_hints
                .iter()
                .any(|h| h.contains(".aws/credentials"))
        );
    }

    #[test]
    fn test_detect_aws_not_found() {
        let env = FakeEnv::new();
        let result = detect_aws(&env);
        assert_eq!(result.status, DetectionStatus::NotFound);
    }

    #[test]
    fn test_detect_no_providers() {
        let env = FakeEnv::new();
        let providers = detect_providers(&env);
        assert_eq!(providers.len(), ProviderType::ALL.len());
        for p in &providers {
            assert_eq!(p.status, DetectionStatus::NotFound);
        }
    }

    #[test]
    fn test_detect_multiple_providers() {
        let env = FakeEnv::new()
            .with_var("GITHUB_TOKEN", "ghp_abc")
            .with_var("GITLAB_TOKEN", "glpat-abc")
            .with_var("OPAQUE_VAULT_URL", "https://vault.example.com")
            .with_var("OPAQUE_VAULT_TOKEN_REF", "env:VAULT_TOKEN")
            .with_var("VAULT_TOKEN", "s.abc")
            .with_command("op")
            .with_command("bws")
            .with_var("OPAQUE_BITWARDEN_TOKEN_REF", "env:BWS_ACCESS_TOKEN")
            .with_var("BWS_ACCESS_TOKEN", "bws.abc")
            .with_var("OPAQUE_AWS_REGION", "us-east-1")
            .with_var("OPAQUE_AWS_ACCESS_KEY_REF", "env:AWS_ACCESS_KEY_ID")
            .with_var("OPAQUE_AWS_SECRET_KEY_REF", "env:AWS_SECRET_ACCESS_KEY")
            .with_var("AWS_ACCESS_KEY_ID", "synthetic")
            .with_var("AWS_SECRET_ACCESS_KEY", "synthetic")
            .with_var("OPAQUE_GCP_ACCESS_TOKEN", "synthetic")
            .with_var("OPAQUE_AZURE_VAULT_URL", "https://myvault.vault.azure.net")
            .with_var("OPAQUE_AZURE_TENANT_ID", "tenant")
            .with_var("OPAQUE_AZURE_CLIENT_ID", "client")
            .with_var("OPAQUE_AZURE_CLIENT_SECRET", "synthetic");
        let providers = detect_providers(&env);

        let ready_count = providers
            .iter()
            .filter(|p| p.status == DetectionStatus::Ready)
            .count();
        assert_eq!(ready_count, ProviderType::ALL.len());
    }

    // =======================================================================
    // Config generation tests
    // =======================================================================

    #[test]
    fn test_generate_config_github_only() {
        let providers = vec![DetectedProvider {
            name: "GitHub".into(),
            provider_type: ProviderType::GitHub,
            status: DetectionStatus::Ready,
            config_hints: vec![],
        }];
        let config = generate_config(&providers, &WizardOptions::default());

        assert!(config.contains("github.list_secrets"));
        assert!(config.contains("github.set_actions_secret"));
        assert!(config.contains("github.set_codespaces_secret"));
        assert!(config.contains("github.set_dependabot_secret"));
        assert!(config.contains("github.set_org_secret"));
        assert!(config.contains("github.delete_secret"));
        assert!(config.contains("test.noop"));
    }

    #[test]
    fn test_generate_config_multi_provider() {
        let providers = vec![
            DetectedProvider {
                name: "GitHub".into(),
                provider_type: ProviderType::GitHub,
                status: DetectionStatus::Ready,
                config_hints: vec![],
            },
            DetectedProvider {
                name: "GitLab".into(),
                provider_type: ProviderType::GitLab,
                status: DetectionStatus::Ready,
                config_hints: vec![],
            },
            DetectedProvider {
                name: "1Password".into(),
                provider_type: ProviderType::OnePassword,
                status: DetectionStatus::Ready,
                config_hints: vec![],
            },
        ];
        let config = generate_config(&providers, &WizardOptions::default());

        assert!(config.contains("github.list_secrets"));
        assert!(config.contains("gitlab.set_ci_variable"));
        assert!(config.contains("onepassword.list_vaults"));
        assert!(config.contains("onepassword.list_items"));
        assert!(config.contains("onepassword.read_field"));
    }

    #[test]
    fn test_generate_config_includes_mcp_safe_ops() {
        let providers = vec![DetectedProvider {
            name: "GitHub".into(),
            provider_type: ProviderType::GitHub,
            status: DetectionStatus::Ready,
            config_hints: vec![],
        }];
        let config = generate_config(&providers, &WizardOptions::default());

        // MCP-safe operations should have client_types including "agent".
        assert!(config.contains("client_types = [\"agent\", \"human\"]"));
        // list, set, delete are MCP-safe (no reveal).
        assert!(config.contains("github.list_secrets"));
        assert!(config.contains("github.set_actions_secret"));
    }

    #[test]
    fn test_generate_config_blocks_reveal() {
        let providers = vec![];
        let options = WizardOptions {
            block_agent_reveal: true,
            ..WizardOptions::default()
        };
        let config = generate_config(&providers, &options);

        assert!(config.contains("deny-agent-reveal"));
        assert!(config.contains("operation_pattern = \"*.reveal\""));
        assert!(config.contains("allow = false"));
        assert!(config.contains("client_types = [\"agent\"]"));
    }

    #[test]
    fn test_generate_config_no_reveal_block_when_disabled() {
        let providers = vec![];
        let options = WizardOptions {
            block_agent_reveal: false,
            ..WizardOptions::default()
        };
        let config = generate_config(&providers, &options);
        assert!(!config.contains("deny-agent-reveal"));
    }

    #[test]
    fn test_generate_config_preserves_existing() {
        // This tests that run_interactive returns an error when config exists.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "existing").unwrap();

        // Calling the wizard without force should fail.
        let result = check_existing_config(&config_path, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));

        // With force it should be fine.
        let result2 = check_existing_config(&config_path, true);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_generate_config_skips_not_found_providers() {
        let providers = vec![
            DetectedProvider {
                name: "GitHub".into(),
                provider_type: ProviderType::GitHub,
                status: DetectionStatus::NotFound,
                config_hints: vec![],
            },
            DetectedProvider {
                name: "GitLab".into(),
                provider_type: ProviderType::GitLab,
                status: DetectionStatus::Ready,
                config_hints: vec![],
            },
        ];
        let config = generate_config(&providers, &WizardOptions::default());

        // GitHub NotFound => no GitHub rules.
        assert!(!config.contains("github."));
        // GitLab Ready => has GitLab rules.
        assert!(config.contains("gitlab.set_ci_variable"));
    }

    #[test]
    fn test_generate_config_parses_as_valid_toml() {
        let providers = vec![
            DetectedProvider {
                name: "GitHub".into(),
                provider_type: ProviderType::GitHub,
                status: DetectionStatus::Ready,
                config_hints: vec![],
            },
            DetectedProvider {
                name: "1Password".into(),
                provider_type: ProviderType::OnePassword,
                status: DetectionStatus::Ready,
                config_hints: vec![],
            },
        ];
        let config = generate_config(&providers, &WizardOptions::default());
        let parsed: toml_edit::DocumentMut = config
            .parse()
            .expect("generated config should be valid TOML");
        assert!(!parsed.is_empty());
    }

    #[test]
    fn test_generate_config_adds_no_auto_human_clients() {
        // Software-first: nothing is auto-classified Human; the default config must
        // not ship a [[known_human_clients]] entry (only an explanatory comment).
        let config = generate_config(&[], &WizardOptions::default());
        assert!(!config.contains("[[known_human_clients]]"));
    }

    #[test]
    fn test_generate_config_biometric_settings() {
        let options = WizardOptions {
            require_biometric: true,
            lease_ttl: 600,
            ..WizardOptions::default()
        };
        let providers = vec![DetectedProvider {
            name: "GitHub".into(),
            provider_type: ProviderType::GitHub,
            status: DetectionStatus::Ready,
            config_hints: vec![],
        }];
        let config = generate_config(&providers, &options);
        assert!(config.contains("require = \"first_use\""));
        assert!(config.contains("[\"local_bio\"]"));
        assert!(config.contains("lease_ttl = 600"));
    }

    #[test]
    fn test_generate_config_no_biometric() {
        let options = WizardOptions {
            require_biometric: false,
            lease_ttl: 0,
            ..WizardOptions::default()
        };
        let providers = vec![DetectedProvider {
            name: "GitHub".into(),
            provider_type: ProviderType::GitHub,
            status: DetectionStatus::Ready,
            config_hints: vec![],
        }];
        let config = generate_config(&providers, &options);
        // GitHub rules should have "never" approval.
        // Note: test.noop always has first_use.
        assert!(config.contains("require = \"never\""));
    }

    // =======================================================================
    // AI tool detection tests
    // =======================================================================

    #[test]
    fn test_detect_claude_code() {
        let env = FakeEnv::new().with_path("/home/testuser/.claude");
        let tools = detect_ai_tools(&env);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].kind, AiToolKind::ClaudeCode);
        assert_eq!(tools[0].name, "Claude Code");
    }

    #[test]
    fn test_detect_cursor() {
        let env = FakeEnv::new().with_path("/home/testuser/.cursor");
        let tools = detect_ai_tools(&env);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].kind, AiToolKind::Cursor);
        assert_eq!(tools[0].name, "Cursor");
    }

    #[test]
    fn test_detect_codex() {
        let env = FakeEnv::new().with_path("/home/testuser/.codex");
        let tools = detect_ai_tools(&env);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].kind, AiToolKind::Codex);
        assert_eq!(tools[0].name, "Codex");
    }

    #[test]
    fn test_detect_both_ai_tools() {
        let env = FakeEnv::new()
            .with_path("/home/testuser/.claude")
            .with_path("/home/testuser/.cursor");
        let tools = detect_ai_tools(&env);
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn test_detect_all_ai_tools() {
        let env = FakeEnv::new()
            .with_path("/home/testuser/.claude")
            .with_path("/home/testuser/.cursor")
            .with_path("/home/testuser/.codex");
        let tools = detect_ai_tools(&env);
        assert_eq!(tools.len(), 3);
    }

    #[test]
    fn test_detect_no_ai_tools() {
        let env = FakeEnv::new();
        let tools = detect_ai_tools(&env);
        assert!(tools.is_empty());
    }

    // =======================================================================
    // MCP config generation tests
    // =======================================================================

    #[test]
    fn test_generate_claude_mcp_config() {
        let tool = DetectedAiTool {
            name: "Claude Code".into(),
            config_dir: PathBuf::from("/home/user/.claude"),
            kind: AiToolKind::ClaudeCode,
        };
        let config = generate_mcp_config(&tool, Path::new("/usr/local/bin/opaque-mcp"));
        let parsed: serde_json::Value = serde_json::from_str(&config).unwrap();

        assert!(parsed.get("mcpServers").is_some());
        let opaque = &parsed["mcpServers"]["opaque"];
        assert_eq!(opaque["command"], "/usr/local/bin/opaque-mcp");
        assert_eq!(
            opaque["args"],
            serde_json::json!([]),
            "opaque-mcp takes no arguments; --stdio made it exit with code 2"
        );
    }

    #[test]
    fn test_generate_cursor_mcp_config() {
        let tool = DetectedAiTool {
            name: "Cursor".into(),
            config_dir: PathBuf::from("/home/user/.cursor"),
            kind: AiToolKind::Cursor,
        };
        let config = generate_mcp_config(&tool, Path::new("/usr/local/bin/opaque-mcp"));
        let parsed: serde_json::Value = serde_json::from_str(&config).unwrap();

        assert!(parsed.get("mcpServers").is_some());
        let opaque = &parsed["mcpServers"]["opaque"];
        assert_eq!(opaque["command"], "/usr/local/bin/opaque-mcp");
        assert_eq!(opaque["args"], serde_json::json!([]));
    }

    #[test]
    fn test_mcp_config_uses_absolute_path() {
        let tool = DetectedAiTool {
            name: "Claude Code".into(),
            config_dir: PathBuf::from("/home/user/.claude"),
            kind: AiToolKind::ClaudeCode,
        };
        let config = generate_mcp_config(&tool, Path::new("/usr/local/bin/opaque-mcp"));
        let parsed: serde_json::Value = serde_json::from_str(&config).unwrap();
        let cmd = parsed["mcpServers"]["opaque"]["command"].as_str().unwrap();
        assert!(
            cmd.starts_with('/'),
            "MCP config command should be an absolute path, got: {cmd}"
        );
    }

    #[test]
    fn test_mcp_config_path_claude() {
        let tool = DetectedAiTool {
            name: "Claude Code".into(),
            config_dir: PathBuf::from("/home/user/.claude"),
            kind: AiToolKind::ClaudeCode,
        };
        // Claude Code reads user-scope mcpServers from ~/.claude.json;
        // ~/.claude/settings.json is never consulted for MCP servers.
        assert_eq!(
            mcp_config_path(&tool),
            PathBuf::from("/home/user/.claude.json")
        );
    }

    #[test]
    fn test_mcp_config_path_cursor() {
        let tool = DetectedAiTool {
            name: "Cursor".into(),
            config_dir: PathBuf::from("/home/user/.cursor"),
            kind: AiToolKind::Cursor,
        };
        assert_eq!(
            mcp_config_path(&tool),
            PathBuf::from("/home/user/.cursor/mcp.json")
        );
    }

    #[test]
    fn test_mcp_config_path_codex() {
        let tool = DetectedAiTool {
            name: "Codex".into(),
            config_dir: PathBuf::from("/home/user/.codex"),
            kind: AiToolKind::Codex,
        };
        assert_eq!(
            mcp_config_path(&tool),
            PathBuf::from("/home/user/.codex/config.toml")
        );
    }

    #[test]
    fn test_generate_codex_mcp_config() {
        let tool = DetectedAiTool {
            name: "Codex".into(),
            config_dir: PathBuf::from("/home/user/.codex"),
            kind: AiToolKind::Codex,
        };
        let config = generate_mcp_config(&tool, Path::new("/usr/local/bin/opaque-mcp"));

        assert!(config.contains("[mcp_servers.opaque]"));
        assert!(config.contains("command = \"/usr/local/bin/opaque-mcp\""));
        assert!(config.contains("args = []"));
    }

    // =======================================================================
    // MCP registration tests
    // =======================================================================

    #[test]
    fn test_register_mcp_creates_new_config() {
        let dir = tempfile::tempdir().unwrap();
        let tool = DetectedAiTool {
            name: "Cursor".into(),
            config_dir: dir.path().to_path_buf(),
            kind: AiToolKind::Cursor,
        };
        let mcp_path = Path::new("/usr/local/bin/opaque-mcp");
        register_mcp(&tool, mcp_path).unwrap();

        let config_file = dir.path().join("mcp.json");
        assert!(config_file.exists());
        let content: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_file).unwrap()).unwrap();
        assert_eq!(
            content["mcpServers"]["opaque"]["command"],
            "/usr/local/bin/opaque-mcp"
        );
    }

    #[test]
    fn test_register_mcp_preserves_existing_servers() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("mcp.json");
        std::fs::write(
            &config_file,
            r#"{"mcpServers": {"other": {"command": "other-mcp"}}}"#,
        )
        .unwrap();

        let tool = DetectedAiTool {
            name: "Cursor".into(),
            config_dir: dir.path().to_path_buf(),
            kind: AiToolKind::Cursor,
        };
        register_mcp(&tool, Path::new("/usr/bin/opaque-mcp")).unwrap();

        let content: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_file).unwrap()).unwrap();
        // Both servers should be present.
        assert!(content["mcpServers"]["other"].is_object());
        assert!(content["mcpServers"]["opaque"].is_object());
    }

    /// A client config file holds far more than MCP servers (Claude Code's
    /// ~/.claude.json carries dozens of unrelated keys). Every one of them,
    /// and every other server entry, must survive registration with its
    /// value intact.
    #[test]
    fn upsert_preserves_unrelated_keys_and_other_servers() {
        let mut config = serde_json::json!({
            "numStartups": 42,
            "theme": "dark",
            "projects": {"/home/user/opaque": {"allowedTools": ["Bash"], "hasTrustDialogAccepted": true}},
            "mcpServers": {
                "other": {"command": "/usr/bin/other", "args": ["--flag"], "env": {"TOKEN_REF": "x"}}
            }
        });
        let before = config.clone();

        let outcome = upsert_json_mcp_server(&mut config, Path::new("/usr/local/bin/opaque-mcp"));
        assert_eq!(outcome, Ok(JsonMcpUpsert::Created));

        assert_eq!(config["numStartups"], before["numStartups"]);
        assert_eq!(config["theme"], before["theme"]);
        assert_eq!(config["projects"], before["projects"]);
        assert_eq!(config["mcpServers"]["other"], before["mcpServers"]["other"]);
        assert_eq!(
            config["mcpServers"]["opaque"],
            serde_json::json!({"command": "/usr/local/bin/opaque-mcp", "args": [], "env": {}})
        );
    }

    /// Releases up to 0.4.0 wrote `args: ["--stdio"]`, which opaque-mcp
    /// rejected. Re-running connect must repair that argument while keeping
    /// the user's own env and any other custom args.
    #[test]
    fn upsert_repairs_legacy_stdio_arg_and_keeps_custom_fields() {
        let mut config = serde_json::json!({
            "mcpServers": {
                "opaque": {
                    "command": "/usr/local/bin/opaque-mcp",
                    "args": ["--stdio", "--custom"],
                    "env": {"RUST_LOG": "debug"}
                }
            }
        });

        let outcome = upsert_json_mcp_server(&mut config, Path::new("/usr/local/bin/opaque-mcp"));
        assert_eq!(outcome, Ok(JsonMcpUpsert::Updated));
        let opaque = &config["mcpServers"]["opaque"];
        assert_eq!(opaque["args"], serde_json::json!(["--custom"]));
        assert_eq!(opaque["env"], serde_json::json!({"RUST_LOG": "debug"}));
        assert_eq!(opaque["command"], "/usr/local/bin/opaque-mcp");
    }

    #[test]
    fn upsert_updates_command_path_only() {
        let mut config = serde_json::json!({
            "mcpServers": {"opaque": {"command": "/old/opaque-mcp", "env": {"A": "b"}}}
        });
        let outcome = upsert_json_mcp_server(&mut config, Path::new("/new/opaque-mcp"));
        assert_eq!(outcome, Ok(JsonMcpUpsert::Updated));
        let opaque = &config["mcpServers"]["opaque"];
        assert_eq!(opaque["command"], "/new/opaque-mcp");
        assert_eq!(opaque["env"], serde_json::json!({"A": "b"}));
        assert!(opaque.get("args").is_none(), "absent args stay absent");
    }

    #[test]
    fn upsert_replaces_malformed_opaque_entry() {
        let mut config = serde_json::json!({"mcpServers": {"opaque": "not-an-object"}});
        let outcome = upsert_json_mcp_server(&mut config, Path::new("/usr/local/bin/opaque-mcp"));
        assert_eq!(outcome, Ok(JsonMcpUpsert::Updated));
        assert_eq!(
            config["mcpServers"]["opaque"]["command"],
            "/usr/local/bin/opaque-mcp"
        );
        assert!(upsert_json_mcp_server(&mut serde_json::json!([]), Path::new("/x")).is_err());
    }

    /// A second connect against an already-correct file changes nothing and
    /// does not rewrite the file.
    #[test]
    fn upsert_file_is_idempotent_and_skips_write_when_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("nested").join(".claude.json");
        let mcp = Path::new("/usr/local/bin/opaque-mcp");

        assert_eq!(
            upsert_json_mcp_config_file(&config_file, mcp),
            Ok(JsonMcpUpsert::Created)
        );
        let first = std::fs::read(&config_file).unwrap();
        let first_mtime = std::fs::metadata(&config_file).unwrap().modified().unwrap();

        // Make any rewrite observable regardless of filesystem timestamp granularity.
        let stale = std::time::SystemTime::now() - std::time::Duration::from_secs(120);
        std::fs::File::options()
            .write(true)
            .open(&config_file)
            .unwrap()
            .set_modified(stale)
            .unwrap();
        let stale_mtime = std::fs::metadata(&config_file).unwrap().modified().unwrap();
        assert!(stale_mtime < first_mtime);

        assert_eq!(
            upsert_json_mcp_config_file(&config_file, mcp),
            Ok(JsonMcpUpsert::Unchanged)
        );
        assert_eq!(std::fs::read(&config_file).unwrap(), first);
        assert_eq!(
            std::fs::metadata(&config_file).unwrap().modified().unwrap(),
            stale_mtime,
            "unchanged registration must not rewrite the file"
        );
    }

    // =======================================================================
    // Codex TOML registration tests
    // =======================================================================

    #[test]
    fn test_register_mcp_codex_creates_config() {
        let dir = tempfile::tempdir().unwrap();
        let tool = DetectedAiTool {
            name: "Codex".into(),
            config_dir: dir.path().to_path_buf(),
            kind: AiToolKind::Codex,
        };
        let mcp_path = Path::new("/usr/local/bin/opaque-mcp");
        register_mcp(&tool, mcp_path).unwrap();

        let config_file = dir.path().join("config.toml");
        assert!(config_file.exists());
        let content = std::fs::read_to_string(&config_file).unwrap();
        assert!(content.contains("[mcp_servers.opaque]"));
        assert!(content.contains("command = \"/usr/local/bin/opaque-mcp\""));
    }

    #[test]
    fn test_register_mcp_codex_preserves_existing_servers() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config.toml");
        std::fs::write(
            &config_file,
            "[mcp_servers.other]\ncommand = \"other-mcp\"\nargs = []\n",
        )
        .unwrap();

        let tool = DetectedAiTool {
            name: "Codex".into(),
            config_dir: dir.path().to_path_buf(),
            kind: AiToolKind::Codex,
        };
        register_mcp(&tool, Path::new("/usr/bin/opaque-mcp")).unwrap();

        let content = std::fs::read_to_string(&config_file).unwrap();
        // Both servers should be present.
        assert!(
            content.contains("[mcp_servers.other]"),
            "existing server should be preserved"
        );
        assert!(
            content.contains("[mcp_servers.opaque]"),
            "opaque server should be added"
        );
    }

    #[test]
    fn test_register_mcp_codex_updates_existing_opaque() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config.toml");
        std::fs::write(
            &config_file,
            "[mcp_servers.opaque]\ncommand = \"/old/path/opaque-mcp\"\nargs = []\n",
        )
        .unwrap();

        let tool = DetectedAiTool {
            name: "Codex".into(),
            config_dir: dir.path().to_path_buf(),
            kind: AiToolKind::Codex,
        };
        register_mcp(&tool, Path::new("/new/path/opaque-mcp")).unwrap();

        let content = std::fs::read_to_string(&config_file).unwrap();
        assert!(
            content.contains("/new/path/opaque-mcp"),
            "opaque command should be updated"
        );
        assert!(
            !content.contains("/old/path/opaque-mcp"),
            "old path should be replaced"
        );
    }

    // =======================================================================
    // Provider type tests
    // =======================================================================

    #[test]
    fn test_provider_type_labels() {
        for pt in ProviderType::ALL {
            assert!(!pt.label().is_empty());
        }
    }

    #[test]
    fn test_provider_type_all_covered() {
        assert_eq!(ProviderType::ALL.len(), 8);
    }
    #[test]
    fn aws_ambient_keys_do_not_claim_configured_provider() {
        let ambient = FakeEnv::new()
            .with_var("AWS_ACCESS_KEY_ID", "synthetic-access")
            .with_var("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
            .with_path("/home/testuser/.aws/credentials");
        assert_eq!(detect_aws(&ambient).status, DetectionStatus::Partial);
        assert!(
            detect_aws(&ambient)
                .config_hints
                .iter()
                .any(|h| h.contains("not loaded automatically"))
        );
        let incomplete = ambient
            .with_var("OPAQUE_AWS_REGION", "us-east-1")
            .with_var("OPAQUE_AWS_ACCESS_KEY_REF", "env:AWS_ACCESS_KEY_ID");
        assert_eq!(detect_aws(&incomplete).status, DetectionStatus::Partial);
    }

    #[test]
    fn bitwarden_requires_bws_and_explicit_environment_token_binding() {
        let token_only = FakeEnv::new().with_var("BWS_ACCESS_TOKEN", "synthetic");
        assert_eq!(
            detect_bitwarden(&token_only).status,
            DetectionStatus::Partial
        );
        let tool_and_token = token_only.with_command("bws");
        assert_eq!(
            detect_bitwarden(&tool_and_token).status,
            DetectionStatus::Partial
        );
        let bound = tool_and_token.with_var("OPAQUE_BITWARDEN_TOKEN_REF", "env:BWS_ACCESS_TOKEN");
        assert_eq!(detect_bitwarden(&bound).status, DetectionStatus::Ready);
    }

    #[test]
    fn gcp_detects_exact_auth_priority_without_assuming_adc() {
        let adc = FakeEnv::new()
            .with_command("gcloud")
            .with_var("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/key.json");
        assert_eq!(detect_gcp(&adc).status, DetectionStatus::NotFound);
        let direct = adc.with_var("OPAQUE_GCP_ACCESS_TOKEN", "synthetic-token");
        assert_eq!(detect_gcp(&direct).status, DetectionStatus::Ready);
        let broken_override = direct.with_var("OPAQUE_GCP_SERVICE_ACCOUNT_REF", "env:MISSING_KEY");
        assert_eq!(
            detect_gcp(&broken_override).status,
            DetectionStatus::Partial
        );
        let service = broken_override.with_var("MISSING_KEY", "synthetic-service-account-json");
        assert_eq!(detect_gcp(&service).status, DetectionStatus::Ready);
        assert!(
            detect_gcp(&service)
                .config_hints
                .iter()
                .all(|h| !h.contains("synthetic-service-account-json"))
        );
    }

    #[test]
    fn azure_needs_vault_tenant_application_and_credential() {
        let base = FakeEnv::new()
            .with_var("OPAQUE_AZURE_VAULT_URL", "https://myvault.vault.azure.net")
            .with_var("OPAQUE_AZURE_TENANT_ID", "tenant")
            .with_var("OPAQUE_AZURE_CLIENT_ID", "client");
        assert_eq!(detect_azure(&base).status, DetectionStatus::Partial);
        let configured = base.with_var("OPAQUE_AZURE_CLIENT_SECRET", "synthetic-secret");
        assert_eq!(detect_azure(&configured).status, DetectionStatus::Ready);
        let missing_ref =
            configured.with_var("OPAQUE_AZURE_CLIENT_SECRET_REF", "env:MISSING_SECRET");
        assert_eq!(detect_azure(&missing_ref).status, DetectionStatus::Partial);
    }

    #[test]
    fn selected_provider_policies_use_registered_metadata_operations_only() {
        let providers = [
            ProviderType::Vault,
            ProviderType::Bitwarden,
            ProviderType::Aws,
            ProviderType::Gcp,
            ProviderType::Azure,
        ]
        .into_iter()
        .map(|provider_type| DetectedProvider {
            name: provider_type.label().into(),
            provider_type,
            status: DetectionStatus::Ready,
            config_hints: vec![],
        })
        .collect::<Vec<_>>();
        let config = generate_config(&providers, &WizardOptions::default());
        let parsed = config.parse::<toml_edit::DocumentMut>().unwrap();
        let rules = parsed["rules"].as_array_of_tables().unwrap();
        let actual = rules
            .iter()
            .filter(|r| r["allow"].as_bool() == Some(true))
            .map(|r| r["operation_pattern"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            [
                "bitwarden.list_projects",
                "bitwarden.list_secrets",
                "aws.get_caller_identity",
                "aws.list_secrets",
                "gcp.list_secrets",
                "gcp.get_secret",
                "azure.list_secrets",
                "azure.list_keys",
                "azure.list_certificates",
                "azure.get_secret",
                "test.noop"
            ]
        );
        assert!(
            !actual
                .iter()
                .any(|operation| operation.starts_with("vault.")
                    || operation.contains("secrets_manager"))
        );
    }
}
