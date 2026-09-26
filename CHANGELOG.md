# Changelog

All notable changes to this project will be documented in this file.

Entries are written by hand, because what changed and why it matters is not
recoverable from commit subjects. [git-cliff](https://git-cliff.org/) derives
the version number from conventional commits and generates the GitHub release
notes; `scripts/release-prep.sh` stamps the section below at release time.

## [Unreleased]

### Fixed

- Linux `sandbox.exec` works again on Landlock-capable kernels (#123). The
  daemon used to install NO_NEW_PRIVS, Landlock and seccomp on the namespace
  wrapper itself, so `bwrap` could not bind its netlink socket and `unshare`
  could not write its uid map; every sandboxed exec failed closed after about
  a millisecond with exit code 1. The wrapper now runs unrestricted and execs
  the daemon binary as the sandbox helper (`opaqued __opaque-sandbox-helper`),
  which restricts itself inside the namespaces, confirms readiness to the
  daemon over an inherited pipe, and only then execs the workload. The
  restrictions land on the workload and its descendants, never on the wrapper.
- Sandbox capability detection carries kernel evidence (#121). Landlock counts
  as available only when `landlock_create_ruleset` answers the ABI probe, and
  the securityfs LSM list is logged next to that answer. A missing layer fails
  over explicitly (`bubblewrap+seccomp`, `unshare+seccomp`, `unshare`) and the
  strategy actually used is recorded as `sandbox=<strategy>` in the
  `sandbox.created` and `sandbox.completed` audit events (`none` for
  `sandbox = false`, `seatbelt` on macOS). A host with neither `bwrap` nor
  unprivileged user namespaces is refused before anything is spawned, with the
  reason in the error instead of a workload exit code of 1. `opaqued` logs the
  probe and the selected strategy at startup.
- A namespace wrapper that dies before the workload starts is reported as a
  sandbox error carrying the wrapper's own stderr, never as the workload's
  exit code.
- Under bubblewrap a project directory below `/tmp` was hidden, read-only,
  beneath the sandbox's tmpfs; the tmpfs is now mounted before the project
  bind.
- The Landlock ruleset lets the workload use existing device nodes
  (`/dev/null`, `/dev/zero`, terminals) and `/dev/shm`. The grants were
  missing before, which never showed while every Linux exec failed closed.

## [0.5.0] - 2026-09-16

### Added

- The Harborlight quickstart, a public companion repository at
  `opaque-dev/harborlight`: four acts against the released package with no
  external accounts, verified in its own CI on Linux and macOS. The README and
  the evaluation guide link it.

### Changed

- The repositories moved to the `opaque-dev` GitHub organization, and the
  Homebrew tap moved with them: `brew install opaque-dev/tap/opaque`. Every
  workflow guard, documentation link, badge, package metadata field and the
  systemd unit `Documentation=` URL the CLI generates now name the
  organization. Release publishing had been silently skipped by the old
  owner-pinned guards after the transfer; this release is the first cut under
  the new owner.
- Release verification spans both signing eras. Certificates for tags up to
  v0.4.0 name `kcirtapfromspace/opaque`; this release and later ones name
  `opaque-dev/opaque`. `install.sh` and
  `docs/compliance/verifying-releases.md` accept exactly those two workflow
  identities, and the docs state which owner signed which versions.

### Fixed

- `install.sh` no longer aborts cosign verification of a release signed under
  the new organization; the identity check is an anchored regexp over the two
  known owners with the version still pinned.

## [0.4.0] - 2026-09-14

### Added

- macOS workstation reviewer app with reference-only notices, pinned enrollment,
  bounded queues and readback after uncertain decision delivery. Signed/notarized
  distribution and human installation qualification remain release gates.
- Signed MCP v2 contracts, offline validate/qualify/prepare commands and bounded
  typed result projections. Raw output stays withheld; projections are ephemeral
  and require current authority. Existing v1 contracts retain their wire format.
- Authenticated audit heads and portable producer-signed export checkpoints,
  with public verification of independently enrolled retention receipts.
- Per-binary CycloneDX SBOMs, cosign-signed and attached to every release, with
  a `docs/compliance/verifying-releases.md` guide to checksum, signature and
  dependency verification.

### Changed

- Existing audit stores require explicit legacy upgrade against independently
  retained export evidence. Unsupported state fails closed; this is not an
  automatic upgrade or authority restore path. See `docs/evidence-checkpoints.md`.
- Installation, review, MCP, evidence and recovery guides describe executable
  source commands and distinguish fixture validation from release qualification.
- The daemon refuses to start when the configured session factor needs local
  authentication the current session cannot provide and trust-domain enforcement
  is off. Split and out-of-band deployments (paired device, FIDO2) are
  unaffected, and the per-prompt fail-closed behavior is unchanged.
- Policy load, bundle apply and `opaque policy check` warn when a rule or a
  `known_human_clients` entry requires `codesign_team_id` on a platform that
  cannot enforce it, and name `exe_sha256` and `exe_path` as the portable
  controls. macOS enforcement is unchanged.

### Fixed

- Refuse empty legacy audit upgrades: an empty export digest cannot authenticate
  a historical sequence frontier. Preserve existing custody on refusal. Reject
  malformed singleton metadata/metadata triggers and recheck exact export bytes
  before committing a legacy upgrade.
- Refresh a pending reviewer notice after successful enrollment without approving it.
- Install `opaque-approver` and `opaque-evidence` when present in release archives;
  retain compatibility with older archives. Homebrew keeps a bundled reviewer
  under its prefix; the shell installer remains CLI-only.
- Pass the detached certificate to optional Cosign verification and bind its
  identity to the exact release workflow/tag. Missing required certificate or
  failed verification prevents installation when signature verification runs.
- Isolate Infisical mock credential tests from parallel process-environment changes.

### Security

- Close a umask race when creating the daemon socket and verify socket-directory
  custody at startup.

## [0.3.0] - 2026-09-09

### Added

- **Optional pilot contact capture** in the public demo: a visitor can
  request a pilot, stored in an isolated `LeadInbox` SQLite object (v2
  migration, own admin secret), separate from queue/task authority. Consent
  required, retention/abuse bounded, save confirmed only after durable write

### Changed

- **`opaqued` split into 7 crates**: ~65k-line monolith is now a ~23k-line
  composition root over `opaque-core`, `opaque-approval`,
  `opaque-native-approval`, `opaque-providers`, `opaque-sandbox`,
  `opaque-bounded-work`, `opaque-tenant`, `opaque-federation-runtime`.
  1900+ tests and a live-daemon smoke test verified behavior-identical
- Renamed `opaque-metrics` to `opaque-showcase` (it's demo/sales collateral,
  not telemetry) and excluded it from `default-members` — use `--workspace`
  or `-p opaque-showcase` to build it

### Fixed

- Audit retention could delete rows before chain-integrity verification, an
  acknowledged write could still be lost, a failed operation could retry
  unsafely; protocol/subprocess lifecycles are now bounded instead of able
  to stall or panic; receipt/dashboard evidence no longer races under
  concurrent access
- The hosted demo polled and wrote to storage continuously while idle,
  burning Workers usage; polling now backs off idle and writes batch

## [0.2.0] - 2026-09-03

### Added

- **Federation (Phase 2)**: central, signed control for a fleet of daemons
  - **Signed policy bundles** (`opqb1`): an org signs its policy once (rules + team rosters) and every daemon verifies the Ed25519 signature against configured trust anchors before the payload is even parsed; multiple anchors support key rotation
  - **Anti-rollback from custody**: the daemon persists `(org, version, digest)` in its custody set — older versions are refused, an equal version must be byte-identical, and a *different* bundle carrying an already-applied version is refused as a substitution; refusals are recorded as `federation.bundle_rejected`. `require_bundle = true` refuses startup until a valid bundle applies
  - **Live policy swap** from `bundle_url` and/or `bundle_path` (URL first, path as offline fallback so a network blip cannot strip policy from a fleet); expired bundles are fatal on the initial load but a warning on refresh
  - **Org tooling**: `opaque bundle keygen|sign|verify|inspect` (offline; manifests are TOML in the same rule shape as the daemon config)
  - **Team namespaces**: bundles carry team rosters, resolved daemon-side per request; `[rules.identity] teams = [...]` constrains rules by membership (ANY-of, fails closed in every direction); team membership rides into the audit chain
  - **SIEM export**: the pump tails the audit *chain*, so every exported record carries its sequence number and record hash and stays externally verifiable. Three transports — append-only JSONL spool, batched JSON webhook, and RFC 5424 syslog over TCP/TLS (RFC 6587 framing; TLS requires a CA file) — each with its own persisted cursor, so a dead SIEM never stalls the others
  - **Independent detector**: an operation that succeeded without its required approval being granted raises an Error-level `audit.alert` into the chain; the rule is derived from the chain's own evidence, not from policy
  - **Continuous attestation** (`opqa1`): periodic custody + chain re-verification recorded in the chain, plus signed posture reports bound to a caller nonce (`opaque attest --key <hex>`, verified client-side before anything is printed). Health (nothing broken) and release-eligibility (healthy *and* trust-domain enforced) are reported separately
  - **Verify before trust**: with `[attestation] key_release_url`, the daemon proves posture to a verifier — enrolled key, issued nonce, posture policy — before receiving custody key material. This is the seam where a KMS release policy or SPIFFE/SPIRE SVID exchange plugs in

- **Trust-domain hardening**: the daemon's integrity guarantees upgrade from tamper-evidence to tamper-prevention
  - `[trust_domain] enforce = true` runs the daemon as a dedicated principal that exclusively owns its custody set (audit chain + key, identity store + signing key, config + keyed seal, pairing/FIDO2 stores, approval-server TLS identity); startup verifies ownership/permissions/symlinks on every path and fails closed, with self-healing of loose modes on daemon-owned files and a `trust_domain.posture` event in the audit chain at every start
  - The cross-domain surface is exactly the socket dir (0750), socket (0660), and daemon token (0640), gated by `socket_group` (names or numeric gids); in enforce mode the peer-uid check inverts — connections from the daemon's own uid are refused
  - `run_as` privilege drop for container entrypoints (verified irreversible); deploy templates for systemd, launchd, docker-compose (with a sealed-config bootstrap + end-to-end smoke script), and Kubernetes
  - Keyed config seal (`opqs1:` HMAC, key held in daemon custody); legacy unkeyed seals still verify with a warning but are refused under enforce
- **Approval factor registry with signature-bound approvers**
  - Configured factors race; the first cryptographically verified decision (approve or deny) settles the approval, and factors that cannot run drop out — if none can decide, the approval fails closed
  - Paired second device: pairing over the (now actually started) HTTPS approval server with per-device bearer tokens, decision-bound Ed25519 signatures verified against the pairing store before anything is relayed, and a fingerprint-confirmation ceremony — a freshly paired device holds no approval authority until a human confirms its key fingerprint out-of-band. `opaque device pair|ls|confirm|revoke`
  - FIDO2 hardware keys / passkeys: daemon-side verification of challenge-bound assertions (P-256, user-presence, RP hash, counter replay floor), approval-gated registration, `opaque key ls|remove`
  - Linux polkit approvals now attribute the authenticated account (`polkit_account` approver source)
- **Sandbox layers actually enforced (C5)**: Landlock rulesets and seccomp-BPF filters are built pre-fork and applied in the exec child's `pre_exec`; a child that cannot be restricted never runs, and a capability the kernel claims but cannot deliver is a startup error, not a silent skip
- Linux verification harness (`scripts/linux-harness.sh`): kernel capability probe, full gate, root multi-uid isolation suites, and a split-daemon end-to-end test (real daemon under a dedicated uid, custody unreadable at the agent uid, operation approved by a device signature recorded in the audit chain) — wired into CI so enforcement tests can never green-skip on an incapable kernel

- **Identity substrate (Phase 1)**: a real principal model on top of the re-founded enclave
  - Principals: humans (verified OIDC `iss`+`sub`), agent workloads, config-declared service principals; roles `admin`/`approver`/`operator`/`auditor` resolved live from the identity store (revocation is immediate)
  - `opaque login` / `logout` / `whoami`: daemon-owned OIDC Authorization Code + PKCE flow against any discoverable IdP (Okta, Entra, Google) — the daemon binds the loopback redirect and exchanges the code, so the auth code and tokens never pass through the (agent-drivable) CLI; JWKS-verified RS256/ES256 ID tokens, nonce/state/PKCE bound, email-domain allowlist fails closed; first human bootstraps as admin
  - On-behalf-of delegation: `agent run` mints Ed25519-signed `opqd1` delegation tokens (RFC 8693-shaped `sub`/`act` claims) bound to the delegating human's login session; validated per request; delegated / autonomous / break-glass access modes with effective permission = agent ∩ human
  - Policy `[rules.identity]` block: `require_principal`, `principal`, `roles` (checked against the delegator), `access_modes` — any identity constraint fails closed for unidentified requests
  - Approver identity in the tamper-evident audit chain: approval events record who approved (principal, label, source) in a new HMAC-covered `approver_json` column; requester principal/role snapshots ride in `client_json`; presence-versioned canon keeps pre-existing databases verifying byte-for-byte with no backfill or re-anchor
  - `opaque identity ls|roles|delegations` for principal, role, and delegation management

- **Web dashboard (`opaque-web`)**: Localhost Axum server (port 7380) with embedded SPA for real-time monitoring and onboarding
  - Live mode: audit event streaming (SSE), policy viewer, agent session monitor, operations registry
  - Demo mode: graceful degradation with synthetic data when daemon is not running
  - Auto-detection and switching between live/demo modes
  - `--open` flag to launch browser on startup, `--port` flag for custom port
  - Dark terminal theme matching the opaque-explorer playground

### Fixed

- Every scheme-prefixed secret ref was rejected as `bad_request`: the daemon requires a `keychain:`/`env:`/`profile:`/`onepassword:`/`bitwarden:`/`vault:` prefix on a `value_ref`, then validated it against a charset that excluded `:` — so GitHub, GitLab, 1Password and Bitwarden writes were all impossible. Ref validation now strips a known scheme and checks the body, which also stops `onepassword:` reading to the secret detector as `password:<value>` (found by running the new tutorial's steps against a live daemon)
- Every GitHub secret write failed with `unexpected target key: secret_name`: the handlers put `secret_name` (and `environment`) in the operation target so rules can constrain on them, but the operation registry allowed only `repo`/`org`. All five GitHub operations now accept the keys their handlers set
- Provider responses returned `secret_name: [REDACTED]`, so a successful write printed `Set [REDACTED] on org/repo`: the field-name heuristic matched any name containing "secret". A `*_name` field identifies a secret rather than carrying one; content-based redaction still applies to its value
- `opaque audit tail` split every row of its table in half — the WHEN cell embedded a newline, and cell width is measured across the whole cell. Table cells are flattened to one line at render time
- The audit database was created with the process umask (0644) and the daemon's custody check runs *before* that file exists, so under `trust_domain.enforce` a fresh state dir left the audit log readable at the agent's uid until the next restart; the sink now sets 0600 at creation, before WAL/SHM siblings inherit the mode (found by attestation's first live posture report)
- The daemon's state directory had the same shape of gap — created by whichever subsystem got there first, with the process umask — so it is now materialized 0700 before the custody check rather than after
- The daemon never installed a process-level rustls crypto provider, so enabling the second-device approval server panicked at startup outside tests
- Unparseable configs silently fell back to defaults (enforce off, no seal requirement, no rules); a config that exists but cannot be parsed now stops the daemon
- The SQLite audit sink restarted sequence numbering at 0 on every boot, making the tamper-evident chain read as tampered after any daemon restart; sequencing now resumes across restarts
- `opaque setup --seal` sealed relative to `$HOME` while the daemon verified the seal beside the config, leaving `$OPAQUE_CONFIG` deployments with an ineffective seal
- Re-sealing over an existing (0400) seal file no longer fails with a permission error
- Landlock capability detection no longer reports support on kernels without Landlock (the best-effort ruleset builder "succeeds" as a no-op there)

## [0.1.0] - 2026-02-23

### Added

- **Core architecture**: Policy-driven enclave with Approve-then-Execute pipeline
- **Daemon (`opaqued`)**: Unix-domain-socket daemon with rate limiting, audit logging, and config seal verification
- **CLI (`opaque`)**: Full-featured client with `init`, `setup`, `doctor`, `exec`, `audit`, policy management, and agent wrapper commands
- **MCP server (`opaque-mcp`)**: Model Context Protocol integration for Claude Code and MCP-aware tools
- **GitHub provider**: Actions, Codespaces, Dependabot, and org-level secret management with NaCl sealed-box encryption
- **GitLab provider**: CI/CD variable sync (project-level, environment-scoped, protected, masked)
- **1Password provider**: Connect Server integration and `op://` ref resolution
- **Bitwarden provider**: Secrets Manager integration with `bitwarden:` ref scheme
- **HashiCorp Vault provider**: KV v2 client with lease-aware caching and automatic lease revocation
- **Secret resolution**: `keychain:`, `env:`, `vault:`, `bitwarden:`, and `op://` ref schemes
- **Policy engine**: Deny-by-default rules with glob patterns, client type filtering, and approval factors
- **Policy presets**: `safe-demo`, `github-secrets`, `gitlab-variables`, `sandbox-human`, `agent-wrapper-github`
- **Approval backends**: macOS LocalAuthentication (Touch ID / password), Linux polkit helper
- **Agent wrapper mode**: Session-scoped tokens with TTL enforcement, list, and bulk revoke
- **Sandbox execution**: Profile-based sandboxed command execution with output capture and sanitization
- **Env manifest workflow**: `build-manifest` / `publish-manifest` for `.env.example`-driven secret sync
- **Audit system**: SQLite-backed audit log with FTS5 full-text search and `audit tail` command
- **Security hardening**: `mlock()` for secret memory, `Zeroizing<Vec<u8>>` wrappers, stdout/stderr scrubbing, `[REDACTED]` in Debug/Display
- **Service management**: `opaque service install/start/stop/uninstall` for launchd (macOS) and systemd (Linux)
- **Diagnostics**: `opaque doctor` command with pass/warn/fail checks for config, daemon, service, and provider health
- **Documentation**: Architecture guide, policy reference, provider setup guides, MCP integration, deployment guide, security assessment

### Security

- Server-side `secret_ref_names` derivation to prevent policy bypass
- Sandbox stdout/stderr stripping to prevent secret leakage through `SensitiveOutput`
- Audit database sanitization to prevent plaintext secret persistence
- Config seal integrity verification at daemon startup
- HTTPS-only enforcement for all provider API URLs (with localhost exception)
