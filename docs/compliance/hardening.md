# Deployment hardening guide

How to deploy `opaqued` in its most defensible configuration. Every setting
in this guide exists in the current tree; config keys are cited to the code
or deploy artifact that reads them. For the architecture behind these
settings see [deployment](../deployment.md) and
[enterprise architecture](../enterprise-architecture.md).

The single most important decision is the deployment mode. Session mode (the
developer default, daemon under your own uid) gives tamper-evidence. The
trust-domain split (dedicated service account, `[trust_domain] enforce =
true`) gives tamper-prevention: custody files are unreadable and unwritable
at the agent's uid and the daemon fails closed at startup on any violation.
Production deployments should use the split. Reference config:
`deploy/config.trust-domain.example.toml`.

## 1. Run under a dedicated service account

Linux (from the header of `deploy/systemd/opaqued.service`, which is the
supported unit file):

```sh
sudo useradd --system --home-dir /var/lib/opaque --shell /usr/sbin/nologin opaque
sudo groupadd opaque-clients
sudo usermod -aG opaque-clients <each user or agent account that may talk to opaqued>
sudo install -d -o opaque -g opaque -m 0700 /var/lib/opaque /etc/opaque
sudo install -o opaque -g opaque -m 0600 config.toml /etc/opaque/config.toml
sudo systemctl enable --now opaqued
```

macOS uses the LaunchDaemon at `deploy/launchd/com.opaque.opaqued.plist`; its
header scripts the equivalent `_opaque` role account, `opaque-clients` group,
and 0700/0600 installs.

Do not run the daemon as root. `trust_domain.allow_root` exists for container
entrypoints that cannot set a run-as user, and is off by default because a
root daemon cannot be protected from a root agent
(`TrustDomainConfig` in `crates/opaqued/src/main.rs`).

## 2. Seal the configuration

```toml
require_seal = true
```

`require_seal` makes the daemon refuse to start when the config is not sealed
(`DaemonConfig` in `crates/opaqued/src/main.rs`). Seal it with the setup
wizard: `opaque setup --seal` (`crates/opaque/src/main.rs`). The seal is a
keyed HMAC (`opqs1`, `crates/opaque-core/src/seal.rs`); under the split, the
seal key is part of the custody set the agent uid cannot read.

## 3. Enforce the trust domain

```toml
[trust_domain]
enforce = true
socket_group = "opaque-clients"   # numeric gid accepted for containers
socket_path = "/run/opaque/opaqued.sock"
```

All three keys are read by `TrustDomainConfig`
(`crates/opaqued/src/main.rs`). With `enforce = true`:

- Startup fails closed unless every custody file (audit db and chain key,
  identity store and signing key, config and seal, pairing store) is
  exclusively owned by the daemon's uid, with no group/other bits and no
  substituted symlinks ([deployment](../deployment.md)).
- Connections from the daemon's own uid are refused; nothing legitimate runs
  as the service account except the daemon.
- The socket path comes from the sealed config; the daemon deliberately
  ignores `$OPAQUE_SOCK` in this mode.
- Every startup records a `trust_domain.posture` audit event, so enforcement
  at any past time is answerable from the log
  (`crates/opaque-core/src/audit.rs`).

`socket_group` is required in enforce mode: without it the socket keeps
owner-only permissions and no client can connect.

## 4. Socket and file permissions

The cross-domain surface in split mode is exactly three inodes, created by
the daemon ([deployment](../deployment.md), `deploy/systemd/opaqued.service`):

| Path | Mode | Owner:group |
|---|---|---|
| socket directory (`/run/opaque`) | 0750 | daemon : `socket_group` |
| socket (`opaqued.sock`) | 0660 | daemon : `socket_group` |
| daemon token | 0640 | daemon : `socket_group` |

Everything else the daemon writes is private: state directory 0700, key
files 0600 (audit chain key: `load_or_create_hmac_key` in
`crates/opaque-core/src/audit.rs`; export spool and cursor files: 0600 in
`crates/opaque-federation-runtime/src/export.rs`; tenant binding and lock:
0600 with symlink/hardlink refusal in `crates/opaque-tenant/src/tenant.rs`).
Loose modes on daemon-owned files are self-healed at startup; foreign
ownership is fatal ([deployment](../deployment.md)).

Session-mode deployments should verify the socket directory is 0700 and the
socket 0600 ([deployment](../deployment.md) checklist). The socket is created
0600 from its first instant: the daemon binds through
`bind_unix_listener_private`, which holds a `0o177` umask across `bind()`
(`crates/opaque-core/src/socket.rs`), closing the former umask race
(finding C-6, [security assessment](../security-assessment.md)).

## 5. systemd unit hardening

Use the shipped unit (`deploy/systemd/opaqued.service`) rather than writing
one. It already sets:

```ini
User=opaque
Group=opaque
SupplementaryGroups=opaque-clients
RuntimeDirectory=opaque
RuntimeDirectoryMode=0750
StateDirectory=opaque
StateDirectoryMode=0700
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/opaque
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
```

`NoNewPrivileges=true` is not optional hardening garnish: the unit's comment
notes it is required context for the seccomp/Landlock sandbox the daemon
applies to its exec children. `SupplementaryGroups=opaque-clients` is what
lets a non-root daemon chgrp the socket surface to the client group.

For session-mode developer machines, the user-service unit in
[deployment](../deployment.md) adds `LimitCORE=0` (secrets can be in process
memory) and `Requires=graphical-session.target`.

## 6. Container deployments

Compose (`deploy/docker/compose.yaml`) and Kubernetes
(`deploy/k8s/opaque.yaml`) ship the split as two containers that share only
the socket volume; custody paths do not exist inside the agent container at
all. Keep these properties when adapting them:

- Distinct uids (7381 daemon, 7382 agent) and a numeric socket gid (7999)
  granted via `group_add` / `supplementalGroups`; `socket_group = "7999"`.
- Kubernetes: separate ServiceAccounts, `automountServiceAccountToken:
  false` on the pod, `runAsNonRoot`, all capabilities dropped,
  `readOnlyRootFilesystem: true`, `seccompProfile: RuntimeDefault`, socket
  on a memory-backed `emptyDir`, custody on a PVC mounted by the daemon
  container only.
- Do not use `fsGroup` on the custody volume; it group-shares every custody
  file, which the daemon's startup check refuses (comment in
  `deploy/k8s/opaque.yaml`).
- Bootstrap (seed, chown, seal) is a one-shot root init container/service
  (`deploy/docker/bootstrap.sh`, the `init-perms` container in the k8s
  manifest); the daemon and agent never run privileged.
- `scripts/compose-smoke.sh` verifies the whole shape end to end, including
  custody invisibility from the agent and the exact 0750/0660/0640 surface
  ([deployment](../deployment.md)).

For higher key assurance, mount a KMS/CSI secret or exchange a SPIFFE/SPIRE
SVID into the daemon container only; the keyfile backend is the shipped
default (`deploy/k8s/opaque.yaml` header).

## 7. Identity (OIDC)

Configure the identity substrate so every agent operation is attributable to
a verified principal ([identity](../identity.md); keys read by
`IdentityConfig` in `crates/opaqued/src/identity/`):

```toml
[identity]
issuer = "https://your-org.okta.com"
client_id = "opaque-cli"
# audience = "opaque-cli"                  # defaults to client_id
# redirect_port = 8721                     # fixed loopback port if the IdP requires exact redirect URIs
# session_ttl_secs = 43200                 # default 12h
allowed_email_domains = ["example.com"]    # fail-closed allowlist
required = true                            # agent operations REQUIRE a valid delegation
```

Hardening notes:

- Set `required = true` in production so agents cannot operate without a
  delegation from a logged-in principal.
- `allowed_email_domains` fails closed; set it.
- Register the IdP app as a native/public client with loopback redirect URIs
  (RFC 8252); the daemon performs the code exchange itself with PKCE, and
  only RS256/ES256 tokens are accepted
  (`crates/opaqued/src/identity/oidc.rs`).
- Declare CI/service principals explicitly with the minimum roles:
  `[[identity.service_principals]]` with `roles = ["operator"]`
  ([identity](../identity.md)).
- Set `enforce_agent_sessions = true` so agent clients must present a valid
  per-session token in the handshake (`DaemonConfig` in
  `crates/opaqued/src/main.rs`).
- Tenant deployments additionally require `identity.required = true` plus an
  explicit `identity.allowed_subjects` allowlist under the configured issuer
  (the tenant boundaries design).

## 8. Approval factors

In split mode the daemon owns no GUI session, so local biometric and polkit
prompts cannot fire; configure an out-of-band factor
(`ApprovalFactorsConfig` in `crates/opaqued/src/main.rs`,
`deploy/config.trust-domain.example.toml`):

```toml
[approval]
second_device = true            # HTTPS approval server for paired phones
# server_bind = "0.0.0.0:7381"  # default 127.0.0.1:7381; LAN bind only if phones must reach it
# timeout_secs = 60
fido2 = true                    # hardware keys / passkeys as approvers
# fido2_rp_id = "opaque.local"
# session_factor = "paired_workstation"   # route agent-session creation through an enrolled workstation
```

- The approval server listens with a generated TLS certificate persisted at
  `approval_server.{key,cert}`; devices authenticate with a bearer token
  plus `X-Opaque-Device` header, and every decision requires an Ed25519
  signature over the daemon's challenge, verified against the pairing store
  before anything is relayed (`crates/opaque-approval/src/approval_server.rs`).
- Leave `server_bind` on loopback unless a phone on the LAN must reach it,
  and then expose it only to the intended network or a trusted tunnel
  (`crates/opaque-approver/README.md`).
- A newly paired device holds no approval authority until its key
  fingerprint is confirmed with `opaque device confirm <id>`
  (`deploy/config.trust-domain.example.toml`).
- Workstation approvers are allowlisted by public key in sealed config
  (`[[workstation_approvers]]`); enrollment requires an operator-verified
  broker id and TLS certificate fingerprint, never trust-on-first-use
  (`crates/opaque-approver/README.md`). Removing the key from config
  disables its credentials at next startup; revoking the paired device is
  immediate.
- Never set `approval_backend = "insecure_auto_approve"` in production. It
  exists for tests, additionally requires
  `OPAQUE_INSECURE_AUTO_APPROVE=1` in the environment, and announces itself
  with an Error-level audit event (`crates/opaqued/src/main.rs`). Leave
  `workstation_test_mode` unset for the same reason.

## 9. Policy

Policy is deny-by-default: with no matching rule, every operation is denied
(`examples/policy.toml`, `crates/opaque-core/src/policy.rs`). Hardening
practice, using the rule fields that exist in `examples/policy.toml`:

- Scope `operation_pattern`, `target.fields`, and `secret_names.patterns` as
  narrowly as the workflow allows; prefer exact operation names over broad
  globs.
- Pin clients with `rules.client` (`exe_path`, `exe_sha256`). Do not rely on
  `codesign_team_id` rules: the field is not populated from a real
  code-signature check today
  ([enterprise architecture](../enterprise-architecture.md)).
- Use `rules.workspace` (`remote_url_pattern`, `branch_pattern`,
  `require_clean`) to bind operations to the intended repository and branch.
- Require approval on sensitive rules: `approval.require = "first_use"` with
  a short `lease_ttl`, or `"always"` for one-time operations. Leases default
  to 10 minutes and are capped at 60 ([deployment](../deployment.md)).
- Add `rules.identity` constraints (`require_principal = true`, `roles`,
  `access_modes`) so agent rules fail closed without a verified delegation
  ([identity](../identity.md)).
- Keep `execve_default` restrictive and enumerate `execve_rules` explicitly
  (`DaemonConfig` in `crates/opaqued/src/main.rs`).

Central policy: distribute signed bundles and require them.

```toml
[federation]
trust_anchors = ["<hex org public key>"]
bundle_url = "https://policy.example.com/opaque/policy.bundle"
# bundle_path = "/etc/opaque/policy.bundle"  # offline fallback
require_bundle = true                        # refuse to start without policy
refresh_secs = 300
```

Keys per `deploy/config.trust-domain.example.toml`, read by
`FederationConfig` (`crates/opaque-federation-runtime/src/federation.rs`).
Trust comes from the signature, not the channel; rollback and version reuse
are refused and audited.

## 10. Sandbox execution profiles

Profiles live at `~/.opaque/profiles/<name>.toml`
(`crates/opaque-core/src/profile.rs`); `examples/profiles/dev.toml` shows
the full shape. Hardening practice:

- Keep `sandbox = true`. Setting `sandbox = false` bypasses the platform
  sandbox and falls back to environment sanitization only
  (`execute_platform_sandbox` in `crates/opaque-sandbox/src/lib.rs`).
- Leave `network.allow = []` unless the command needs egress, then list
  exact `host:port` entries. An empty list blocks network syscalls via
  seccomp on Linux (`crates/opaque-sandbox/src/linux.rs`).
- Keep `extra_read_paths` minimal; the project directory, `/tmp`, `/var/tmp`
  and `/dev/shm` are the only writable paths (existing device nodes such as
  `/dev/null` stay usable, nothing can be created under `/dev`).
- Set realistic `limits.timeout_secs` and `limits.max_output_bytes`.
- The sandbox always denies `.opaque`, `.ssh`, and `.gnupg`
  (`PROTECTED_DIRS` in `crates/opaque-sandbox/src/linux.rs`), clears the
  inherited environment, and never sets `OPAQUE_SOCK` in the child.
- Platform honesty: on Linux the daemon probes the host before each
  `sandbox.exec` (`bwrap` on PATH, the `landlock_create_ruleset` ABI answer
  next to the securityfs LSM list, seccomp, `unshare --user`) and picks the
  strongest strategy those facts support. A missing kernel layer is dropped
  explicitly and the strategy actually used is recorded as
  `sandbox=<strategy>` in the `sandbox.created` and `sandbox.completed`
  audit events; a host with no namespace wrapper at all is refused before
  anything runs. The restrictions are installed by the sandbox helper inside
  the namespaces, on the workload and never on the wrapper
  (`crates/opaque-sandbox/src/linux.rs`). Install `bwrap` and run a
  Landlock-capable kernel (5.13+) so `bubblewrap+landlock+seccomp` engages;
  prerequisites per distribution are in the
  [deployment guide](../deployment.md#sandbox-prerequisites). macOS Seatbelt
  is documented in the source as best-effort containment
  (`crates/opaque-sandbox/src/macos.rs`).
- Reference secrets by resolver (`keychain:`, `env:`, `profile:`), never
  literal values in `[env]` (`examples/profiles/dev.toml`,
  `crates/opaque-core/src/resolver.rs`).

## 11. Audit log and SIEM export

```toml
audit_retention_days = 90   # default 90 (crates/opaqued/src/main.rs)

[export]
spool_path = "/var/log/opaque/audit.jsonl"     # JSONL for a UF/filebeat tail
# webhook_url = "https://siem.example.com/ingest"
# webhook_authorization = "Bearer <token>"      # config is sealed and custody-owned
syslog_addr = "tls://siem.example.com:6514"
syslog_ca_file = "/etc/opaque/siem-ca.pem"      # REQUIRED for tls://; fails closed without it
# poll_secs = 2
# batch_size = 256
```

All keys are read by `ExportConfig`
(`crates/opaque-federation-runtime/src/export.rs`). Operational notes:

- The three transports are a spool file, an HTTPS webhook, and RFC 5424
  syslog over TCP or TLS. There are no product-specific SIEM integrations;
  point your collector at one of these.
- Exported records carry `sequence_number` and `record_hash`, so the stream
  is verifiable against the chain; delivery is at-least-once per transport,
  so configure the SIEM to deduplicate on `(sequence_number, record_hash)`.
- `tls://` syslog requires the CA file and refuses to start without it;
  there is no insecure-skip option.
- Alert on `audit.alert` events: the export pump's independent detector
  raises one when an operation succeeded without its required approval
  appearing in the chain.
- Verify the chain on a schedule and after any incident:
  `opaque audit verify` recomputes every record and detects edit,
  reordering, deletion, and truncation
  (`verify_audit_chain` in `crates/opaque-core/src/audit.rs`).

## 12. Attestation

```toml
[attestation]
interval_secs = 900
# key_release_url = "https://kms.example.com/opaque"
# key_release_authorization = "Bearer <token>"
```

Keys read by `AttestationConfig`
(`crates/opaque-federation-runtime/src/attest.rs`). The daemon re-verifies
its custody set and audit chain on the interval and records the result in
the chain; signed, nonce-bound reports (`opqa1`) are available on demand.
With `key_release_url` set, the daemon proves posture to a verifier before
receiving custody key material, and release requires the trust-domain split
to be enforced (`healthy_for_release` in `crates/opaque-core/src/attest.rs`).
Remember this is software attestation, not a hardware measurement; the
source says so and this guide repeats it.

## 13. Tenant isolation

One tenant per independently deployed broker. `[tenant] id` requires
`trust_domain.enforce = true` and refuses to open at a shared uid; the
binding is immutable, locked exclusively, and fails closed on any change,
missing marker, or adopted unbound state
(`crates/opaque-tenant/src/tenant.rs`,
the tenant boundaries design). Tenant labels are not an
isolation mechanism by themselves: the operator must provide separate OS
accounts or container/VM mounts, sockets, keys, credentials, and state
volumes per tenant.

## 14. Operational settings

- `RUST_LOG=info` in production, never `debug` or `trace`
  ([deployment](../deployment.md) checklist).
- Store provider credentials in the OS keychain or a resolver-backed source,
  never in plaintext config ([deployment](../deployment.md)).
- Back up the audit database with `sqlite3 audit.db ".backup ..."`, keep the
  tenant binding with its ledger, and encrypt backups; procedures in
  [security assessment](../security-assessment.md) section 7.4 and
  the tenant boundaries design.
- Only the latest release receives security updates (`SECURITY.md`); track
  releases and verify them before deploying, see
  [verifying releases](verifying-releases.md) for the checksum, cosign
  signature, SLSA provenance, and embedded dependency manifest checks.
