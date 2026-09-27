# Control mapping

This document maps Opaque's implemented security features to SOC 2 Trust
Services Criteria and NIST SP 800-53 rev 5 control families. It exists so an
enterprise security reviewer, an auditor, or an agency assessor can see in one
place what the product actually does, where the implementation lives, and what
it does not do.

Ground rules for this document:

- Every claim cites the code or the document that implements it. If a claim
  has no citation, treat it as an error and file an issue.
- Gaps are stated in the same table as the capabilities. A partial control is
  listed as partial, not rounded up.
- Opaque is a self-hosted product. Most organizational controls (personnel,
  physical, vendor management, business continuity) are the deploying
  customer's responsibility and are listed as such in the final section.

Snapshot: workspace version 0.3.0 (`Cargo.toml`), 2026-09-14. Re-verify
citations against the tree you deploy.

## Product summary for assessors

Opaque is a local broker daemon (`opaqued`) that sits between AI agents and
sensitive operations. Agents talk to it over a Unix domain socket; every
request passes one enforcement funnel (`crates/opaqued/src/enclave.rs`) that
applies, in order: policy evaluation, human approval, execution, response
sanitization, and audit. Supporting subsystems: OS sandboxing for command
execution (`crates/opaque-sandbox/`), OIDC-backed identity and delegation
(`crates/opaqued/src/identity/`), a tamper-evident audit chain with SIEM
export (`crates/opaque-core/src/audit.rs`,
`crates/opaque-federation-runtime/src/export.rs`), signed posture attestation
(`crates/opaque-core/src/attest.rs`), signed central policy bundles
(`crates/opaque-federation-runtime/src/federation.rs`), and tenant custody
binding (`crates/opaque-tenant/`). The architecture overview is
[enterprise architecture](../enterprise-architecture.md).

Two deployment modes matter for every row below
([deployment](../deployment.md)):

- **Session mode** (developer default, daemon shares the user's uid): audit
  and config integrity are tamper-evident, not tamper-proof.
- **Trust-domain split** (`[trust_domain] enforce = true`, dedicated service
  account): custody files are unreadable and unwritable at the agent's uid,
  verified fail-closed at startup. Rows below assume the split for the
  stronger claims and say so where it matters.

## SOC 2 Trust Services Criteria

Common Criteria only; the Availability, Processing Integrity, and Privacy
categories are addressed briefly after the table.

| Criterion | What Opaque provides | Where | Gaps and limitations |
|---|---|---|---|
| CC6.1 Logical access controls | Deny-by-default policy engine: no operation runs unless an explicit allowlist rule matches client identity, operation glob, target, workspace, and secret names. Operation safety classes (`Safe` / `SensitiveOutput` / `Reveal`); `Reveal` operations are hard-blocked for every client. | `crates/opaque-core/src/policy.rs` (module table in [enterprise architecture](../enterprise-architecture.md)), `examples/policy.toml`, safety classes in [enterprise architecture](../enterprise-architecture.md) | Policy quality is operator-defined; a permissive rule set weakens the control. |
| CC6.1 (transport gate) | Unix-socket-only IPC with peer-credential verification (uid checked against the expected uid; connections with unavailable peer creds rejected), executable path and SHA-256 captured per connection, handshake daemon token, 128 KB frame cap, bounded connection semaphore, idle timeout. | `crates/opaque-core/src/peer.rs`, `crates/opaque-federation-runtime/src/workload_attest.rs`, IPC section of [enterprise architecture](../enterprise-architecture.md) | A `codesign_team_id` field exists on `ClientIdentity` but nothing populates it from a real macOS code-signature check, so `codesign_team_id` policy rules cannot match today ([enterprise architecture](../enterprise-architecture.md)). |
| CC6.2, CC6.3 Registration, authorization, and removal of users | Human principals are established by OIDC login at the customer IdP (authorization code + PKCE, daemon-owned flow). Roles (`admin`, `approver`, `operator`, `auditor`) are assigned by admins and resolved from the identity store at request time, so revocation and role removal take effect immediately, including for in-flight agent delegations. Service principals are declared in sealed config. | `crates/opaqued/src/identity/` (`oidc.rs`, `login.rs`, `store.rs`), [identity](../identity.md) | Account lifecycle in the IdP itself (joiner/leaver, MFA policy at the IdP) is customer-operated. Identity features are off unless `[identity]` is configured; without it, access control is uid and policy only. |
| CC6.4, CC6.5 Physical access, disposal | Not provided. Self-hosted software; physical and media controls belong to the customer environment. | n/a | Customer responsibility. |
| CC6.6 External access points | The only network listeners the daemon can open are opt-in: the approval server (HTTPS with a generated TLS certificate, bearer token plus per-device header, Ed25519 signature verification before any decision is trusted) and the OIDC loopback redirect. SIEM syslog export supports TLS with a required CA file; webhook export is HTTPS. Provider base URLs require HTTPS (HTTP permitted only for localhost). | `crates/opaque-approval/src/approval_server.rs`, `crates/opaque-federation-runtime/src/export.rs`, [enterprise architecture](../enterprise-architecture.md) | The approval server certificate is self-signed and fingerprint-pinned by paired devices, not CA-issued. The APNs push relay is compiled but not wired to config (`crates/opaque-approval/src/push.rs`). |
| CC6.7 Transmission and movement of data | Plaintext secret values exist only inside `SecretValue` buffers (zeroized on drop, optional `mlock`), are injected only into sandboxed child environments, and never appear in client responses, audit rows, or error strings. `sandbox.exec` returns output lengths, never output content. Typestate-enforced response sanitization: an unsanitized response is a compile error. | `crates/opaque-core/src/secret.rs`, `crates/opaque-sandbox/src/lib.rs` (the C2 comment and its test), `crates/opaque-core/src/sanitize.rs` (module table in [enterprise architecture](../enterprise-architecture.md)) | A sandboxed child that is granted network egress can still exfiltrate a secret it was given; the profile's `network.allow` list is the control and defaults to empty. |
| CC6.8 Unauthorized software | Agent-invoked commands execute inside layered OS sandboxes: Bubblewrap mount namespaces, Landlock filesystem rules, seccomp-BPF (network syscalls blocked when no egress is allowed; ptrace and io_uring always blocked) on Linux; Seatbelt on macOS. `execve` interception maps child process launches to policy decisions. | `crates/opaque-sandbox/src/linux.rs`, `crates/opaque-sandbox/src/macos.rs`, `crates/opaque-sandbox/src/execve_hook.rs` | A Linux layer the kernel lacks is dropped explicitly and the strategy actually used is recorded as `sandbox=<strategy>` in the `sandbox.created` and `sandbox.completed` audit events; a host with no namespace wrapper is refused before anything runs. macOS `sandbox-exec` is deprecated by Apple and documented in the source as best-effort containment. Profiles can set `sandbox = false`, which drops to environment sanitization only (audited as `sandbox=none`). |
| CC7.1 Configuration monitoring | Keyed HMAC config seal (`opqs1`): the daemon refuses to start when a sealed config was modified (`require_seal = true`). Under the trust-domain split the whole custody set (audit db and chain key, identity store and signing key, config and seal, pairing store) is ownership-verified fail-closed at every startup, and the posture is recorded in the audit chain (`trust_domain.posture` event). | `crates/opaque-core/src/seal.rs` (module table), `crates/opaqued/src/main.rs` (`require_seal`, `TrustDomainConfig`), `crates/opaqued/src/trust_domain.rs`, [deployment](../deployment.md) | In session mode this is tamper-evidence only: a same-uid process can read the seal key. The split closes this; it is the recommended production mode. |
| CC7.2, CC7.3 Anomaly detection and evaluation | Structured audit events for every request, policy decision, approval, execution, secret resolution, login, delegation, and bundle change, HMAC-chained (see AU rows). An independent integrity detector replays the exported chain and raises an `audit.alert` event when an operation succeeded without its required approval being granted. Streaming export to the customer SIEM. | `crates/opaque-core/src/audit.rs`, `crates/opaque-federation-runtime/src/export.rs` (`ApprovalDetector`) | Detection beyond the built-in approval-missing invariant (thresholds, correlation, alert routing) happens in the customer's SIEM. Suggested alert rules exist only as guidance in [security assessment](../security-assessment.md) section 7.2. |
| CC7.4, CC7.5 Incident response and recovery | A vulnerability disclosure policy with private reporting, response timelines, and 90-day coordinated disclosure. Written incident response and audit-data backup/recovery procedures. | `SECURITY.md`, [security assessment](../security-assessment.md) sections 7.3 and 7.4 | These are documents, not product features. The customer's incident response program executes them. |
| CC8.1 Change management | Centrally signed policy bundles (`opqb1`, Ed25519): daemons verify signature and version before applying, refuse rollback and version reuse, and audit both apply and reject events. Config changes are gated by the seal. Release artifacts are signed in CI with Sigstore cosign and published with SHA-256 checksums. | `crates/opaque-core/src/bundle.rs` (module table), `crates/opaque-federation-runtime/src/federation.rs`, audit kinds `federation.bundle_applied` / `federation.bundle_rejected` in `crates/opaque-core/src/audit.rs`, `.github/workflows/release.yml` | No dedicated bundle-serving control plane; bundles ship by URL or file ([enterprise architecture](../enterprise-architecture.md)). Change management for the customer's own config and policy content is the customer's process. |
| CC9.x Risk mitigation, vendors | Supply-chain checks in CI: `cargo-deny` (advisories, licenses, bans, sources), GitHub dependency review, OSSF Scorecard. | `.github/workflows/ci.yml`, `.github/workflows/dependency-review.yml`, `.github/workflows/scorecard.yml`, `deny.toml` | These cover the product's own supply chain, not the customer's vendor management program. |

Other categories:

- **Availability (A1)**: largely not provided. The daemon bounds its own
  resource use (connection semaphore, rate limiting, frame caps, per-profile
  execution timeouts) but there is no HA, clustering, or failover; denial of
  service against the local daemon is explicitly out of scope in
  `SECURITY.md`.
- **Processing integrity (PI1)**: approval binding is the relevant mechanism:
  every approval is bound by SHA-256 content hash to operation, target,
  secret refs, params, client, and principal, so an approval cannot authorize
  a different action (`content_hash()` in `crates/opaque-core/src/operation.rs`,
  invariants in [deployment](../deployment.md)).
- **Confidentiality (C1)**: covered by the CC6.7 row plus central audit
  `detail` redaction and URL scrubbing in `crates/opaque-core/src/audit.rs`
  (`TargetSummary::sanitized`, `WorkspaceSummary::sanitized`).
- **Privacy (P series)**: not applicable; Opaque does not process end-user
  personal data as a product function. Audit rows contain principal
  identifiers (email labels) that the customer controls.

## NIST SP 800-53 rev 5

Selected controls in the families most relevant to a technical assessment of
the product. Controls not listed are either inherited from the customer
environment or not addressed.

### AC: access control

| Control | What Opaque provides | Where | Gaps and limitations |
|---|---|---|---|
| AC-2 Account management | Identity store with three principal kinds (`hum_`, `agt_`, `svc_`), admin-assigned roles, immediate revocation (roles resolved at request time, never embedded in tokens), audited role changes and login/logout events. | `crates/opaqued/src/identity/store.rs`, [identity](../identity.md), audit kinds `identity.*` in `crates/opaque-core/src/audit.rs` | The system of record for humans is the customer IdP; Opaque mirrors verified subjects, it does not manage IdP accounts. |
| AC-3 Access enforcement | Single enforcement funnel; deny-by-default allowlist over (client identity, operation, target, workspace, secret names, principal identity constraints). Identity constraints fail closed when a request carries no verified principal. | `crates/opaqued/src/enclave.rs`, `crates/opaque-core/src/policy.rs`, [identity](../identity.md) policy integration | Enforcement quality depends on the operator's rules. |
| AC-6 Least privilege | Effective agent permission is the intersection of the agent session and the delegating principal's roles. Safety classes deny agents value-revealing operations categorically. The trust-domain split removes custody file access from the agent uid entirely. | [identity](../identity.md), [enterprise architecture](../enterprise-architecture.md), [deployment](../deployment.md) | In session mode the daemon and agent share a uid, so least privilege between them is policy-level only. |
| AC-7 / AC-12 style session controls | Human login sessions have a TTL (`session_ttl_secs`, default 12h); logout revokes sessions; delegation expiry or revocation kills in-flight agent access; connection idle timeout. | [identity](../identity.md), IPC section of [enterprise architecture](../enterprise-architecture.md) | No lockout counter on OIDC login attempts (failed logins are audited as `identity.login.failed`, throttling is the IdP's job). |
| AC-17 Remote access | Approvals from a second device or an enrolled workstation run over pinned TLS with per-decision Ed25519 signatures; the workstation flow requires operator-verified broker id and certificate fingerprint before enrollment. | `crates/opaque-approval/src/approval_server.rs`, `crates/opaque-approver/README.md` | The daemon's own operation socket is local-only by design; there is no remote operation transport to harden. |

### AU: audit and accountability

| Control | What Opaque provides | Where | Gaps and limitations |
|---|---|---|---|
| AU-2 / AU-12 Event logging | 33 structured event kinds covering requests, policy denials, approvals (required, presented, granted, denied), execution start/success/failure, secret resolution, sandbox lifecycle, rate limiting, identity events, delegation issue/revoke, trust-domain posture, bundle apply/reject, workload attestation, and integrity alerts. | `AuditEventKind` in `crates/opaque-core/src/audit.rs` | Event selection is fixed; there is no per-kind enable/disable (which also means nothing can be quietly turned off). |
| AU-3 Content of records | Each record carries timestamp, sequence number, severity, correlation ids (`request_id`, `approval_id`, `event_id`), client summary (uid, gid, pid, exe path, truncated exe hash), principal context (`sub`, `act`, mode, delegation id, role snapshot at request time), operation, sanitized target, outcome, latency, secret names (never values), and the request content hash. | `AuditEvent`, `ClientSummary`, `PrincipalSummary` in `crates/opaque-core/src/audit.rs` | none noted |
| AU-9 Protection of audit information | HMAC-SHA256 hash chain over every persisted column, tail anchor to detect truncation, authenticated retention boundary so pruning is distinguishable from deletion, sticky flush-failure reporting, verification CLI (`opaque audit verify`). Under the trust-domain split the database and chain key are unreadable at the agent uid and ownership-verified at startup. | `crates/opaque-core/src/audit.rs` (chain, `verify_audit_chain`, retention boundary), `crates/opaque/src/main.rs` (`run_audit_verify`) | The chain key is symmetric and broker-held: at a shared uid the chain is tamper-evident, not tamper-proof, and export records are not independently verifiable with a public key (the tenant boundaries design notes this explicitly). |
| AU-10 Non-repudiation | Approver identity is persisted in its own chained column. For `paired_device`, `paired_workstation`, and `fido2` sources the identity is signature-bound: the daemon verified a cryptographic response to its own challenge before recording. | `ApproverSource`, `ApproverIdentity` in `crates/opaque-core/src/audit.rs` | `local_bio_session` and `polkit_account` sources prove presence or account authentication; the recorded name is session-bound, not signature-bound. The enum documents this per variant. |
| AU-11 Retention | Configurable retention (`audit_retention_days`, default 90) with chain-preserving pruning: surviving records keep their original authenticators. | `crates/opaqued/src/main.rs` (config field and default), retention boundary in `crates/opaque-core/src/audit.rs` | Long-term retention beyond the local database is the customer's SIEM/archive responsibility via export. |
| AU-6 Review and analysis | Full-text search index over audit rows; SIEM export for external analysis; the built-in approval-missing detector. | FTS schema in `crates/opaque-core/src/audit.rs`, `crates/opaque-federation-runtime/src/export.rs` | Reporting and correlation tooling is the customer's SIEM. |

### IA: identification and authentication

| Control | What Opaque provides | Where | Gaps and limitations |
|---|---|---|---|
| IA-2 User identification and authentication | OIDC authorization code + PKCE against the customer IdP; ID token signature, issuer, audience, expiry, and nonce verified against the IdP JWKS; RS256/ES256 only; discovery issuer match per RFC 8414; fail-closed email-domain allowlist (`allowed_email_domains`). | `crates/opaqued/src/identity/oidc.rs`, [identity](../identity.md) | MFA at login is inherited from the IdP. Opaque adds its own second factor at the approval step, not the login step. |
| IA-2(11)-style out-of-band authorization | Sensitive operations require out-of-band human approval: OS biometric/password, polkit with a separate intent dialog, paired device (Ed25519 over a decision-bound challenge), FIDO2/WebAuthn (challenge-bound, counter-checked), or enrolled workstation full review. Break-glass mode requires a distinct approver. | [deployment](../deployment.md) approval invariants, `crates/opaque-approval/`, [identity](../identity.md) | Factor availability depends on deployment mode; split mode requires an out-of-band factor since the daemon owns no GUI session. |
| IA-4 Identifier management | Stable prefixed principal ids (`hum_`, `agt_`, `svc_`), delegation session ids (`jti`), device ids in the pairing store. | [identity](../identity.md), `crates/opaque-approval/src/pairing/` | none noted |
| IA-5 Authenticator management | Delegation tokens are daemon-signed (Ed25519, `opqd1`), short-lived, and validated against store state on every request. Device pairing uses a single-use, TTL-bound nonce; tokens are stored hashed; workstation credentials are revocable and cannot rebind to another broker. | [identity](../identity.md), `crates/opaque-approval/src/approval_server.rs` (trust model comment), `crates/opaque-approver/README.md` | Provider credentials (PATs, Vault tokens) are referenced from the OS keychain or resolvers, not managed or rotated by Opaque. |
| IA-9 Service identification | Listener-bound workload attestation: peer credentials plus executable hash become a `WorkloadIdentity` before dispatch; attestation success and denial are audited. | `crates/opaque-federation-runtime/src/workload_attest.rs`, audit kinds `workload.*` | Attestation strength is peer-credential level, not cryptographic workload identity (no SPIFFE SVID verification today; the code names that as the seam). |

### SC: system and communications protection

| Control | What Opaque provides | Where | Gaps and limitations |
|---|---|---|---|
| SC-7 Boundary protection | Local Unix socket as the sole operation transport; in split mode the cross-domain surface is exactly three inodes (socket dir 0750, socket 0660, daemon token 0640) gated by a client group. Container deployments share only the socket volume between daemon and agent. | [deployment](../deployment.md), `deploy/systemd/opaqued.service`, `deploy/docker/compose.yaml`, `deploy/k8s/opaque.yaml` | The former umask race between socket `bind()` and permission tightening (finding C-6) is closed: `bind_unix_listener_private` holds a `0o177` umask across `bind()` so the socket is 0600 from birth (`crates/opaque-core/src/socket.rs`). |
| SC-8 Transmission confidentiality and integrity | rustls-based TLS for the approval server (generated Ed25519 certificate, fingerprint-pinned by devices), TLS syslog export with mandatory CA file (fails closed without one), HTTPS webhook export, HTTPS-only provider URLs, rustls-tls reqwest everywhere. | `crates/opaque-approval/src/approval_server.rs`, `crates/opaque-federation-runtime/src/export.rs` (`SyslogTarget`), `Cargo.toml` (`reqwest` with `rustls-tls`) | Spool export is a local file; its transport to the SIEM (forwarder config) is the customer's. |
| SC-12 / SC-13 Cryptographic key establishment and use | Ed25519 (delegation tokens, bundles, attestation reports, device and workstation approvals), P-256 ECDSA (FIDO2), HMAC-SHA256 (audit chain, config seal), SHA-256 (content hashes, exe hashes), X25519 sealed boxes (`crypto_box`). Keys are 0600 files inside the custody set; under the split they are ownership-verified at startup. | `Cargo.toml` workspace dependencies (`ring`, `ed25519-dalek`, `p256`, `rustls` on `ring`, `crypto_box`, `sha2`; `jsonwebtoken` on `aws_lc_rs`), `crates/opaque-core/src/attest.rs`, `crates/opaque-core/src/audit.rs` | **Not FIPS-validated.** No module in the stack runs as a FIPS 140-2/140-3 validated module in this build. See the roadmap for the FIPS-capable build assessment. Keyfile-based custody; KMS/HSM-backed keys are a documented seam, not shipped (`deploy/k8s/opaque.yaml` header). |
| SC-28 Protection at rest | State files (audit db, identity store, pairing store, cursors, keys) are created 0600/0700 and custody-verified under the split. Secret values are never persisted by Opaque; secret references resolve at use time from the OS keychain or provider. | `crates/opaque-core/src/audit.rs` (key file 0600), `crates/opaque-federation-runtime/src/export.rs` (spool and cursors 0600), `crates/opaque-tenant/src/tenant.rs` (0600/0700 checks) | No application-level encryption at rest: the audit database and identity store are plain SQLite protected by file permissions and the integrity chain. Disk encryption is the customer's platform control. |
| SC-39 Process isolation | Sandboxed execution: mount/PID/network namespaces, Landlock, seccomp (ptrace and io_uring always blocked), protected paths (`.opaque`, `.ssh`, `.gnupg`) never visible inside the sandbox, cleared environment, no daemon socket inside the sandbox. `SecretValue` zeroized on drop, optional `mlock`. | `crates/opaque-sandbox/src/linux.rs` (`PROTECTED_DIRS`, `env_clear`), `crates/opaque-sandbox/src/macos.rs`, `crates/opaque-core/src/secret.rs` | macOS containment is best-effort (deprecated `sandbox-exec`, documented in the source). Capability detection is probed from the kernel (Landlock ABI query plus the securityfs LSM list) and logged at daemon startup; a missing layer fails over to the next strategy and the audit events name the one used, so the floor is visible but not configurable per profile. |

### CM: configuration management

| Control | What Opaque provides | Where | Gaps and limitations |
|---|---|---|---|
| CM-3 / CM-5 Change control and access restrictions | Sealed config (`require_seal`, `opaque setup --seal`); under the split, config and seal are owned by the service account and unwritable at the agent uid. Central policy changes arrive only as signed bundles with anti-rollback. | `crates/opaqued/src/main.rs`, `crates/opaque/src/main.rs` (setup wizard), `crates/opaque-federation-runtime/src/federation.rs` | none beyond the session-mode caveat |
| CM-6 Configuration settings | Hardened reference configurations shipped in-tree: systemd unit with a hardening block, launchd daemon plist, compose and Kubernetes manifests with non-root users, dropped capabilities, read-only root filesystems. | `deploy/systemd/opaqued.service`, `deploy/launchd/com.opaque.opaqued.plist`, `deploy/docker/`, `deploy/k8s/opaque.yaml`, [hardening guide](hardening.md) | none noted |
| CM-7 Least functionality | Deny-by-default operation registry; MCP surface exposes `Safe` operations plus a small withheld-output set; agents cannot reach `Reveal` operations at all. | [enterprise architecture](../enterprise-architecture.md), [MCP integration](../mcp-integration.md) | Provider connectors are compiled into the shipped daemon even when feature-gated at the crate level ([enterprise architecture](../enterprise-architecture.md) notes this honestly). |
| CM-14 Signed components | Release tarballs signed with Sigstore cosign (keyless) plus SHA-256 checksums; policy bundles Ed25519-signed; per-binary CycloneDX SBOMs (`cargo cyclonedx`) generated, cosign-signed, and attached to each GitHub release. | `.github/workflows/release.yml`, `crates/opaque-core/src/bundle.rs` | Bit-for-bit reproducible builds are not implemented. Embedding each release binary's dependency manifest (`cargo auditable build`, auditable after the fact with `cargo audit bin`) and SLSA build provenance attestation are both written (`scripts/verify_auditable_binary.py`, [verifying releases](verifying-releases.md)) but not yet active in `release.yml`; see [security assessment](../security-assessment.md) finding L-7. |

### SI: system and information integrity

| Control | What Opaque provides | Where | Gaps and limitations |
|---|---|---|---|
| SI-4 Monitoring | Continuous posture attestation on an interval (`[attestation] interval_secs`, default 900): custody and chain re-verified, result recorded in the audit chain and available as a signed, nonce-bound report (`opqa1`). SIEM export streams the chain off the box. | `crates/opaque-federation-runtime/src/attest.rs`, `crates/opaque-core/src/attest.rs`, `crates/opaque-federation-runtime/src/export.rs` | Attestation is software attestation: it proves a holder of the enrolled key claims this posture, not a hardware measurement. The source states this verbatim. |
| SI-7 Software and information integrity | Config seal, custody verification, audit chain verification, signed bundles with anti-rollback, verify-before-trust key release (a verifier checks a fresh signed posture report before releasing custody material; `healthy_for_release` additionally requires the trust-domain split). | `crates/opaque-core/src/attest.rs` (`integrity_ok`, `healthy_for_release`), `crates/opaque-federation-runtime/src/attest.rs` | No hardware-rooted attestation of the running binary; the KMS/SPIRE seam is where it would attach ([enterprise architecture](../enterprise-architecture.md)). |
| SI-10 Input validation | Operation params validated against JSON schemas; length-delimited framing with a 128 KB cap; approval dialog text constructed by the daemon from verified request fields, never from client-supplied strings. | `crates/opaque-core/src/validate.rs` (module table), [deployment](../deployment.md) invariant 1 | none noted |
| SI-11 Error handling | Client-facing error messages are fixed and generic; details are logged daemon-side. Secret patterns are redacted centrally in the audit sink as a last line of defense. | [security assessment](../security-assessment.md) C-4 (resolved), `crates/opaque-core/src/audit.rs` (sanitizer in `SqliteAuditSink`) | none noted |

### IR: incident response

| Control | What Opaque provides | Where | Gaps and limitations |
|---|---|---|---|
| IR-4 / IR-6 Handling and reporting | Product-side: audit evidence (chained, exportable, verifiable), `audit.alert` events, posture events, and written containment/revocation/rotation procedures. Vendor-side: private disclosure channel, 72-hour acknowledgment target, 90-day coordinated disclosure. | [security assessment](../security-assessment.md) section 7.3, `SECURITY.md` | Opaque supplies evidence and procedures; the incident response capability itself is the customer's program. |

## Not provided / customer responsibility

Stated plainly so nobody discovers these during an audit:

- **FIPS-validated cryptography is not currently provided.** The crypto stack
  is `ring`, `ed25519-dalek`, `p256`, `crypto_box`, `sha2`/HMAC, rustls on
  the `ring` provider, and `jsonwebtoken` on `aws_lc_rs` (workspace
  `Cargo.toml`). None of these run as validated FIPS 140 modules in this
  build. Federal deployments that require FIPS-validated modules cannot meet
  that requirement with today's binaries; see the
  [certification roadmap](certification-roadmap.md) for the FIPS-capable
  build assessment.
- **Encryption at rest**: none at the application layer. Use platform disk
  encryption and the trust-domain split.
- **High availability and disaster recovery**: single-daemon architecture, no
  clustering or failover. Backup guidance exists
  ([security assessment](../security-assessment.md) section 7.4) but backup
  execution is the customer's.
- **Denial of service**: explicitly out of scope for the local daemon
  (`SECURITY.md`), though resource bounds exist.
- **Host and network security**: OS hardening, patching, firewalling,
  physical security, personnel security, security awareness training.
- **IdP operation**: account lifecycle, login MFA policy, and session
  policies at the identity provider.
- **Provider-side security**: Opaque cannot prevent compromise of GitHub,
  Vault, 1Password, or any upstream provider
  ([enterprise architecture](../enterprise-architecture.md)).
- **SIEM operation**: export delivery is at-least-once per transport;
  consumers must deduplicate on `(sequence_number, record_hash)`
  (`crates/opaque-federation-runtime/src/export.rs`). Alerting content beyond
  the built-in detector is customer-built.
- **macOS code-signature client verification**: the `codesign_team_id` policy
  field is inert today.
- **Hardware-rooted attestation**: not shipped; software attestation only.
- **Mobile push (APNs)**: compiled but not wired to configuration
  (`crates/opaque-approval/src/push.rs`); the LAN approval server is the live
  second-device transport.

## Known open findings

Tracked in [security assessment](../security-assessment.md) (status notes
dated 2026-09-09) and restated here so this document does not overclaim:

- H-8: macOS session-detection preflight at daemon startup specified but not
  implemented; screen-lock and Fast User Switching behavior untested.
- Frozen appendix data (dependency counts, file lists) in that document dates
  to 2026-02-12 and does not describe the current 16-crate workspace.

The 2026-02-14 adversarial review's six findings (P0 1-4, P1 1-2) are all
resolved; see [adversarial security review](../adversarial-security-review-2026-02-14.md).
