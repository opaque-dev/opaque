# Storage and recovery boundaries

Opaque stores authorization state, references and evidence separately from the
secret values used during an operation. This page describes the current source
implementation; it is not a proposed database schema or a backend migration plan.

## Durable authority

The broker uses SQLite for existing local ledgers. Task and MCP invocation stores
persist reservations before dispatch, consumption, expiry/revocation state and
receipts. An interrupted attempt can have an unknown provider effect. Restarting
the broker must preserve that charge and prevent replay; asking for approval
again does not make the old attempt safe to repeat.

Identity, pairing, federation replay state, tenant bindings and configuration
seals also belong to trusted custody. Their precise files and migrations are
owned by the corresponding components. Audit events are evidence about these
systems, not a replacement for their authoritative state.

See [bounded work](bounded-work.md), [qualified MCP tools](mcp-qualified-tools.md),
[identity](identity.md) and [deployment](deployment.md). Public wire contracts do
not expose a database driver. A different storage implementation must preserve
atomic admission, revocation ordering, replay tombstones and crash recovery.
Analytics or graph projections must not become authorization sources.

## Keys, configuration and secret values

Provider credentials remain in the configured provider or credential backend.
Secret values fetched for an operation are not an audit or metadata payload.
Do not persist raw authenticated request/response bodies, credentials or injected
process environments in application logs.

Do not assume every signing key is in an OS credential store. The audit HMAC key
and several broker keys use protected key files. The workstation reviewer also
uses file-backed private custody; enrollment stores pinned public identities.
See [reviewer setup](remote-approvals.md) for its ownership and permission checks.

Configuration and profiles contain policy, references and provider metadata.
Those references can themselves be sensitive. Protect the entire custody set,
including SQLite WAL/SHM siblings, keys and backups. The dedicated service-account
or container setup in [deployment](deployment.md) separates these files from the
agent. An attacker who can read the HMAC key can forge a locally valid audit
history; file permissions under the same compromised user do not prevent that.

## Audit persistence and export

The default session-mode audit path is `~/.opaque/audit.db`; service deployments
use their configured state directory. The current writer authenticates both rows
and the retained chain head, including empty state. Retention removes only a
verified expired prefix in insertion order and preserves the authenticated
frontier. Unsupported older stores fail closed until explicitly upgraded.

Follow [the audit upgrade procedure](evidence-checkpoints.md#authenticated-local-head-and-older-databases)
before starting this writer against an existing installation. A newly computed
hash of a suspect database is not an independently retained historical pin.
Never reset or delete custody just to bypass an upgrade refusal.

[Portable checkpoints](evidence-checkpoints.md) bind exact export bytes to an
enrolled producer, generation and sequence range. They can be verified without
SQLite or the broker HMAC key. A retained external receipt or high-water mark is
needed to detect replay of an older intact snapshot. A signature alone proves
neither completeness, provider effects nor independence of the signer.

[Audit inspection](audit-analytics.md) explains local reads, SIEM structural checks
and the signed custody boundary.

## Backup and recovery

Use a consistent database snapshot or stop all writers before copying custody;
copying only a live SQLite main file can omit committed WAL contents. Keep keys,
configuration and independent evidence under separately controlled access.
Verify archive integrity offline and retain the original evidence.

A valid audit archive is suitable for inspection, not automatic restoration of
execution authority. Restoring old task, identity, revocation or replay ledgers
can resurrect consumed or revoked work even when every file passes integrity
checks. Recovery needs admission closed, old writers fenced, unresolved effects
preserved, and a reviewed generation/re-enrollment procedure. There is no generic
safe “restore a database and restart” command in the current product.
