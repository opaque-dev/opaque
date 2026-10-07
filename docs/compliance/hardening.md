# Harden broker configuration

Apply these settings after provisioning an
[isolated broker account](../deployment.md#trust-domain-split-service-account-mode).
This guide covers public core v0.6.0 configuration on macOS and Linux. Use the
[reference config](https://github.com/opaque-dev/opaque/blob/main/deploy/config.trust-domain.example.toml)
and shipped service artifacts for your platform; a configuration example does not
qualify the deployed host.

```sh
opaque policy check
opaque doctor
opaque audit verify
```

Inspect warnings even when `policy check` exits successfully. Daemon settings
must appear above the first `[[rules]]` table. The commands use the selected
broker configuration and custody; [older stores need explicit migration](../evidence-checkpoints.md).

## Custody and transport

| Setting / artifact | Required behavior |
| --- | --- |
| `require_seal = true` | Refuse unsealed/modified configuration; seal reviewed config with `opaque setup --seal` |
| `[trust_domain] enforce = true` | Check private custody ownership/permissions and refuse broker-UID clients |
| `trust_domain.socket_group` | Limit access to the shared socket surface; grant the broker its supplementary client group |
| `trust_domain.socket_path` | Use the sealed socket path; the broker ignores `OPAQUE_SOCK` in enforced mode |
| Dedicated non-root account | Keep agents outside broker custody; do not use `allow_root` to substitute for isolation |
| Shipped systemd / launchd artifact | Preserve service-account identity, private state and applicable hardening |

The shared socket directory/socket/token are `0750`/`0660`/`0640`; other custody
stays private. Session-mode socket directory/socket are `0700`/`0600`, but the
shared UID can obtain keys. Neither mode protects against root or a compromised
broker administrator. See [deployment](../deployment.md) for installation and
container volume/group requirements.

Tenant deployments use one independently isolated broker per tenant. `[tenant]`
requires enforced custody and an immutable binding; it refuses changed, missing
or adopted unbound state. A tenant label alone supplies no OS isolation. Preserve
bindings together with their ledgers during recovery.

## Identity and approval

```toml
[identity]
issuer = "https://your-org.okta.com"
client_id = "opaque-cli"
allowed_email_domains = ["example.com"]
required = true
```

Register a native/public OIDC client with loopback redirects. Require verified
delegation and agent sessions (`enforce_agent_sessions = true`, placed at the
config top level). Tenant admission also requires explicit
`identity.allowed_subjects`; declare service principals with minimum roles.
[Identity reference](../identity.md) covers token validation, revocation and the
separate managed lifecycle contract.

Split brokers have no local GUI authentication context. Select a supported
out-of-band factor and follow [reviewer enrollment](../remote-approvals.md).
SSH health tasks and third-party MCP still require local native full review and
cannot gain headless support from an unrelated factor setting.

```toml
[approval]
second_device = true
fido2 = true
# server_bind = "127.0.0.1:7381"  # expose only to the intended review network
# session_factor = "paired_workstation"
```

`second_device` is the desktop paired-device path, not a released phone app.
Confirm its key fingerprint with `opaque device confirm <id>` before granting
approval authority. Workstation enrollment requires an operator-verified broker
ID and TLS fingerprint plus an allowlisted public key in sealed configuration;
do not use trust on first use. Removing that key takes effect at next startup;
paired-device revocation is immediate.

Keep `approval_backend = "insecure_auto_approve"` and `workstation_test_mode`
out of production configuration. Test approval evidence remains test evidence
when the backend changes.

## Policy and delegated work

Use exact operations and narrowly constrained targets, secret reference names,
workspaces and verified identity. Pin client path/hash where appropriate;
macOS `codesign_team_id` matching is platform-specific. Do not enroll an agent
adapter as a human executable. Inspect platform and ignored-key warnings.

Choose the applicable consumption contract:

- Generic operations: `always`, or a short first-use lease with `budget` or
  `one_time`. Without either, matching reuse within the TTL is unlimited.
- Bounded tasks: immutable full review and one durable attempt per action.
- Third-party MCP: signed route/schema/disclosure plus a single-use invocation
  and local native full review.
- Scoped authority: its separate finite-budget workflow and recovery contract.

Failures and uncertainty count as documented by each contract. A revocation
fence cannot undo an earlier provider effect. See [policy](../policy.md),
[bounded tasks](../bounded-work.md) and [scoped authority](../scoped-authority.md).
Keep `execve_default` restrictive and explicitly enumerate any `execve_rules`.

For multiple brokers, pin the organization signer and require its policy bundle:

```toml
[federation]
trust_anchors = ["<hex org public key>"]
bundle_url = "https://policy.example.com/opaque/policy.bundle"
require_bundle = true
refresh_secs = 300
```

Signature/version checks reject rollback and version reuse. See
[federation](../federation.md) for signing and offline bundle delivery.

## Sandbox profiles

Use [sandbox prerequisites](../deployment.md#sandbox-prerequisites) to qualify
actual namespace/layer support. Keep `sandbox = true`; `false` retains only
environment sanitization. Restrict `network.allow`, extra readable paths,
execution time and output bounds. Reference secrets through resolvers rather
than literal profile values. The [example profile](https://github.com/opaque-dev/opaque/blob/main/examples/profiles/dev.toml)
shows those fields.

The sandbox hides protected custody/SSH/GPG paths and clears inherited
environment. Actual strategy is audited. macOS Seatbelt is best-effort; Linux may
run without an unavailable layer or refuse execution without a usable wrapper.
A command given secrets can disclose them through permitted egress or metadata.

## Evidence and export

```toml
[export]
spool_path = "/var/log/opaque/audit.jsonl"
syslog_addr = "tls://siem.example.com:6514"
syslog_ca_file = "/etc/opaque/siem-ca.pem"
# webhook_url = "https://siem.example.com/ingest"
```

Export supports a local spool, HTTPS webhook and TCP/TLS syslog. TLS syslog
requires a CA file. Delivery is at-least-once per transport: receivers deduplicate
on `(sequence_number, record_hash)` and retain continuity/high-water state.
Configure retention, alert handling and protected archive custody separately.

`opaque audit verify` checks covered local integrity; a holder of the HMAC key
can forge a valid chain and an older intact snapshot can verify. Use
[signed checkpoints](../evidence-checkpoints.md) for exact-byte independent export
verification. The approval detector evaluates observed events, not omissions.

```toml
[attestation]
interval_secs = 900
```

Periodic software posture checks re-verify custody and chain health. Signed,
nonce-bound reports are available on demand. Optional verifier-gated key release
requires the documented healthy split posture; it is not hardware measurement.
See [federation](../federation.md).

Back up through a consistent storage procedure and preserve authoritative
consumption/revocation state. Do not restore an older ledger to refill authority.
Verify [release evidence](verifying-releases.md), then run the
[deployment verification workflow](../evaluation-guide.md) with disposable targets
before admitting production work.
