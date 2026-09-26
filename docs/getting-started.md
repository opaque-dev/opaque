# Getting Started (Local)

Opaque is a local secrets broker made of:

- `opaqued`: trusted local daemon (enclave, policy, approvals, audit)
- `opaque`: untrusted CLI client
- `opaque-mcp`: MCP server for Claude Code and other MCP-aware tools

Built-in operations use the enclave execution pipeline. Bounded tasks and signed
MCP routes have their own admission, review and durable consumption paths in the
broker. Provider credentials stay in custody; permitted data outputs remain
subject to each operation’s disclosure contract.

This page is the reference: install, configure, and every command. If you would
rather learn by doing, the [tutorial](tutorial.md) walks the same ground in 15
minutes, ending with a real gated operation and a verified audit chain.

## Build

For Homebrew, the shell installer, or installation from Git, start with
[install Opaque](tutorial.md#1-install). The command below assumes you already
have a source checkout and a Rust toolchain.

```bash
cargo build --locked --release
```

Binaries:

- `./target/release/opaqued`
- `./target/release/opaque`
- `./target/release/opaque-mcp`
- `./target/release/opaque-mcp-contract` (offline MCP qualification)
- `./target/release/opaque-approver` and `opaque-approve-helper` (trusted review)
- `./target/release/opaque-evidence` (offline checkpoints and verification)
- `./target/release/opaque-web` (local dashboard)

These are checkout builds. The reviewer app, MCP v2 and evidence CLI are
unreleased additions; a tagged package may omit them. See the
[reviewer installation guide](remote-approvals.md) for the separate macOS bundle.

**Existing installations:** authenticated audit heads require an
[explicit legacy upgrade](evidence-checkpoints.md#authenticated-local-head-and-older-databases)
before the new daemon can open an older audit store. Stop old writers and establish
the independently held export pin before the upgrade. `opaque init` is for setup,
not a repair or reset command for existing custody.

## Initialize Local State

`opaque init` creates:

- `~/.opaque/config.toml` (policy + daemon config)
- `~/.opaque/profiles/` (exec profiles)
- `~/.opaque/run/` (socket fallback; prefer `XDG_RUNTIME_DIR` on Linux)

```bash
./target/release/opaque init
```

Or initialize with a policy preset:

```bash
./target/release/opaque init --preset safe-demo       # test.noop only
./target/release/opaque init --preset github-secrets   # GitHub secret sync
./target/release/opaque init --preset gitlab-variables # GitLab CI variable sync
./target/release/opaque init --preset sandbox-human    # sandbox for humans only
./target/release/opaque init --preset agent-wrapper-github # wrapped-agent GitHub sync + session tokens
```

List available presets: `opaque policy presets`

## Minimal Policy (Example)

Policy is deny-by-default. Start by allowing only low-risk test operations.

```toml
[[rules]]
name = "allow-test-noop"
operation_pattern = "test.*"
allow = true
client_types = ["human", "agent"]

[rules.client]

[rules.approval]
require = "never"
factors = []
```

Validate:

```bash
./target/release/opaque policy check
```

For the full config format, see [Policy](policy.md) and `examples/policy.toml`.

## Bitwarden Secrets Manager

Opaque can resolve secrets from Bitwarden Secrets Manager using the `bitwarden:` ref scheme.

1. Install the official `bws` Secrets Manager CLI on the broker host, then
   create a machine account with read access to the required projects.
2. Store its access token through the interactive secret-entry command:
   ```bash
   opaque secrets add bitwarden-token
   ```
3. Use `bitwarden:` refs in profiles or `--value-ref` arguments:
   ```bash
   opaque github set-secret \
     --repo myorg/myrepo \
     --secret-name API_KEY \
     --value-ref bitwarden:production/API_KEY
   ```

See [Bitwarden setup](bitwarden.md) for full setup.

## HashiCorp Vault

Opaque can resolve secrets from Vault using the `vault:` ref scheme:

```text
vault:<path>#<field>
```

Example:

```bash
opaque github set-secret \
  --repo myorg/myrepo \
  --secret-name DATABASE_URL \
  --value-ref vault:secret/data/myapp#DATABASE_URL
```

Defaults:

- Vault URL: `http://127.0.0.1:8200` (override with `OPAQUE_VAULT_URL`)
- Vault token ref: `keychain:opaque/vault-token` (override with `OPAQUE_VAULT_TOKEN_REF`)
- Vault lease renew window: `30` seconds (override with `OPAQUE_VAULT_LEASE_RENEW_WINDOW_SECS`, set `0` to disable proactive renewal)
- Audit retention: `audit_retention_days = 90` (verified retention removes only an expired insertion-order prefix)

See [Vault setup](vault.md) for details.

## MCP Quickstart (Claude Code)

For Claude Code, the MCP server is the recommended integration path:

1. Add to your Claude Code MCP config:
   ```json
   {
     "mcpServers": {
       "opaque": {
         "command": "/path/to/opaque-mcp"
       }
     }
   }
   ```

2. Start `opaqued` (or install it as a service: `opaque service install`)

3. Ask Claude Code to "list my GitHub secrets for owner/repo". It will call the `opaque_github_list_secrets` tool via MCP.

See [MCP integration](mcp-integration.md) for full setup.

## Run The Daemon

In one terminal:

```bash
./target/release/opaqued
```

In another terminal:

```bash
./target/release/opaque ping
./target/release/opaque version
./target/release/opaque whoami
```

## Agent Wrapper Mode

Run an agent with a session-scoped token managed by Opaque:

```bash
./target/release/opaque agent run -- codex
```

By default, the child process receives only a baseline set of environment variables (e.g. `PATH`, `HOME`, `SHELL`) plus `OPAQUE_*` session vars. Use `--pass-env KEY` to forward additional variables, or `--inherit-env` to pass the full parent environment.

Inspect and revoke active wrapper sessions:

```bash
./target/release/opaque agent list
./target/release/opaque agent end <session-id>
./target/release/opaque agent end --all
```

With stricter daemon enforcement, enable session gating in `~/.opaque/config.toml`:

```toml
enforce_agent_sessions = true
agent_session_ttl_secs = 3600
```

Then wrapped agent clients must present `OPAQUE_SESSION_TOKEN` in the daemon handshake (the wrapper does this automatically).

## Execute Operations

### `test.noop`

```bash
./target/release/opaque execute test.noop
```

### `sandbox.exec` (Profile-Based)

1. Create a profile at `~/.opaque/profiles/dev.toml` (example: `examples/profiles/dev.toml`)
2. Run:

```bash
./target/release/opaque exec --profile dev -- echo "hello from sandbox"
```

```text
  output withheld (stdout: 19 bytes, stderr: 0 bytes)
ok  Sandbox exec succeeded (0ms)
```

The caller gets the exit code, the duration and the output byte counts. The
output content stays with the daemon: the command runs with the profile's
secrets in its environment, so anything it prints could be a secret. The two
audit events for the run name the containment that was used:

```text
sandbox.created    profile=dev argument_count=2 sandbox=bubblewrap+landlock+seccomp
sandbox.completed  profile=dev exit_code=0 sandbox=bubblewrap+landlock+seccomp
```

On Linux the daemon probes the host at startup and before every exec, then
picks the strongest strategy the host supports and logs it:

```text
INFO opaque_sandbox::linux: linux sandbox capabilities detected bubblewrap=true bubblewrap_evidence=ok landlock=true landlock_evidence=lsm=securityfs-unreadable abi=v8 seccomp=true user_namespaces=true user_namespaces_evidence=ok
INFO opaque_sandbox::linux: linux sandbox strategy selected for sandbox.exec strategy=bubblewrap+landlock+seccomp
```

Either `bwrap` (the `bubblewrap` package) or unprivileged user namespaces for
`unshare` must work on the host; otherwise every exec is refused with
`no sandbox strategy available` and nothing runs. The strategy names,
distribution notes and container requirements are in the
[deployment guide](deployment.md#sandbox-prerequisites). macOS uses Seatbelt
(`sandbox=seatbelt`). A profile with `sandbox = false` skips the platform
sandbox and is audited as `sandbox=none` (environment sanitization only).

The outputs above come from a Debian 12 container on a 7.0.12 kernel with
bubblewrap 0.8.0; `lsm=securityfs-unreadable` is what containers without a
securityfs mount report.

### GitHub Secrets

The CLI exposes multiple GitHub secret scopes via `opaque github ...`.

```bash
./target/release/opaque github set-secret \
  --repo owner/repo \
  --secret-name MY_TOKEN \
  --value-ref keychain:opaque/my-token
```

Environment-level Actions secret:

```bash
./target/release/opaque github set-secret \
  --repo owner/repo \
  --environment production \
  --secret-name MY_TOKEN \
  --value-ref keychain:opaque/my-token
```

Codespaces (user-level):

```bash
./target/release/opaque github set-codespaces-secret \
  --secret-name DOTFILES_TOKEN \
  --value-ref keychain:opaque/dotfiles-token
```

Codespaces (repo-level):

```bash
./target/release/opaque github set-codespaces-secret \
  --repo owner/repo \
  --secret-name DOTFILES_TOKEN \
  --value-ref keychain:opaque/dotfiles-token
```

Dependabot (repo-level):

```bash
./target/release/opaque github set-dependabot-secret \
  --repo owner/repo \
  --secret-name NPM_TOKEN \
  --value-ref keychain:opaque/npm-token
```

Org-level Actions secret:

```bash
./target/release/opaque github set-org-secret \
  --org myorg \
  --secret-name ORG_DEPLOY_KEY \
  --value-ref keychain:opaque/org-deploy-key
```

These operations are `SAFE`: they never return the secret value or ciphertext.

### GitLab CI Variables

Set a project CI/CD variable:

```bash
./target/release/opaque gitlab set-ci-variable \
  --project group/project \
  --key DATABASE_URL \
  --value-ref keychain:opaque/db-url
```

Optionally set scope/attributes:

```bash
./target/release/opaque gitlab set-ci-variable \
  --project group/project \
  --key DATABASE_URL \
  --value-ref bitwarden:production/DATABASE_URL \
  --environment-scope production \
  --protected \
  --masked
```

This operation is `SAFE`: it writes through to GitLab and never returns the variable value.

Build a refs-only manifest from `.env.example` (names only):

```bash
./target/release/opaque github build-manifest \
  --env-file .env.example \
  --value-ref-template 'bitwarden:production/{name}' \
  --out .opaque/env-manifest.json
```

Manually review/update refs in `.opaque/env-manifest.json`, then publish:

```bash
./target/release/opaque github publish-manifest \
  --repo owner/repo \
  --manifest-file .opaque/env-manifest.json
```

Preview publish only (no API calls):

```bash
./target/release/opaque github publish-manifest \
  --repo owner/repo \
  --manifest-file .opaque/env-manifest.json \
  --dry-run
```

Legacy one-step flow (still supported):

```bash
./target/release/opaque github publish-env \
  --repo owner/repo \
  --env-file .env.example \
  --value-ref-template 'bitwarden:production/{name}'
```

## Audit

The daemon writes a local SQLite audit DB at `~/.opaque/audit.db`.

```bash
./target/release/opaque audit tail --limit 50
./target/release/opaque audit tail --query github --limit 20
```

The log has an HMAC chain and authenticated head. Verification detects edits,
reordering and unauthorized prefix/tail changes when the attacker lacks its key.
A self-consistent older snapshot, or a writer controlling the HMAC key, needs
independently held evidence to expose it. Failure exits nonzero:

```bash
./target/release/opaque audit verify
```

For portable producer authentication and retention receipt checks without sharing
the audit HMAC key, use [evidence checkpoints](evidence-checkpoints.md).
A signed checkpoint covers its declared range; it does not prove provider effects,
global completeness or permission to restore old authorization state.

## Fleet Operations

For an org running many daemons, policy arrives as a signed bundle rather than a
local file, the audit chain streams to a SIEM, and each daemon can prove its
posture on demand:

```bash
opaque bundle keygen --out org-signing.key
opaque bundle sign --manifest policy.toml --key org-signing.key --out policy.bundle
opaque bundle verify policy.bundle --anchor <hex>
opaque attest --key <attestation key hex>
```

See [federation](federation.md) for bundle format, anti-rollback semantics,
export transports, and the key-release protocol.

## Bounded Agent Work

Beyond one-shot operations, an agent can be handed a **task**, an immutable,
fully-reviewed manifest (publish a secret, dispatch a release, run a fixed
host check) approved once as a whole and executed once, with a receipt:

```bash
opaque task plan --manifest ./release.json
opaque task run <task-id>
opaque task show <task-id>
```

See [bounded agent work](bounded-work.md) for the full lifecycle, the three
operation families, and what's production-ready today.

## Environment Variables

- `OPAQUE_CONFIG`: override daemon/CLI config path (default: `~/.opaque/config.toml`)
- `OPAQUE_SOCK`: override socket path for the CLI only (daemon ignores it)
- `OPAQUE_GITHUB_TOKEN_REF`: override default GitHub PAT secret ref used by `github.set_actions_secret`
- `OPAQUE_GITHUB_API_URL`: override GitHub API base URL (GitHub Enterprise Server or local testing)
- `OPAQUE_GITLAB_TOKEN_REF`: override default GitLab token ref used by `gitlab.set_ci_variable`
- `OPAQUE_GITLAB_API_URL`: override GitLab API base URL (GitLab.com / self-managed / local testing)
- `OPAQUE_BITWARDEN_URL`: override Bitwarden API base URL (default: `https://api.bitwarden.com`)

## Next

- [Tutorial: your first gated operation](tutorial.md)
- [Bounded agent work: plan, approve, and run a task](bounded-work.md)
- [MCP integration (Claude Code)](mcp-integration.md)
- [Identity, delegation, and approval factors](identity.md)
- [Federation: signed policy, SIEM export, attestation](federation.md)
- [AWS setup](aws.md)
- [Google Secret Manager setup](gcp.md)
- [Azure Key Vault setup](azure.md)
- [Bitwarden setup](bitwarden.md)
- [Demo recordings](demos.md)
- [Deployment & OS approval backends](deployment.md)
