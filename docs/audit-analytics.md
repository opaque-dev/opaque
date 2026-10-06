# Inspect audit evidence

Read recent events and verify the local chain from a reviewed source checkout:

```sh
cargo build --locked -p opaque --bins
OPAQUE="${CARGO_TARGET_DIR:-target}/debug/opaque"
"$OPAQUE" audit tail --limit 50
"$OPAQUE" audit tail --query github --since 1h
"$OPAQUE" audit verify
```

These commands read the configured local audit database; session mode defaults to
`~/.opaque/audit.db`. Event metadata can contain repository names, secret references
and human identities. Keep the database and exports under their custody controls.
The durability contract below describes current source; check installed release
availability before applying its [offline upgrade procedure](evidence-checkpoints.md#authenticated-local-head-and-older-databases).

## Choose the inspection boundary

`audit tail` filters recorded events by kind, operation, time, request ID, outcome
or full-text query. Request IDs correlate records; they do not authorize retries.
The [local dashboard](web-dashboard.md) reads broker audit state. The
[SIEM export pump and detector](federation.md#audit-export-to-siem) maintain their
own cursors and report observed lifecycle contradictions and delivery gaps.
Findings describe the records seen by the detector, not independently witnessed
provider effects.

For an independently obtained `opaque.audit.v1` SIEM JSONL file, the source-only
structural verifier handles bounded input and exact duplicate deliveries:

```sh
python3 -B scripts/verify_audit_evidence.py verify /received/audit.jsonl
```

It reports structural validity, duplicates and observed gaps. It does not
verify the audit HMAC or producer identity. Its optional externally pinned
unsigned checkpoint compares one exact file to a separately held digest; it
cannot authenticate a producer or establish global completeness.

For portable custody, use [signed evidence checkpoints](evidence-checkpoints.md).
`opaque-evidence create` signs an authenticated database snapshot under a dedicated
producer key. `verify` requires separately enrolled producer trust;
`verify-receipt` additionally checks an independently enrolled custodian signature
and retention interval. Receiving an enrollment or digest beside the same package
does not establish its provenance. A replaying SIEM spool is not interchangeable
with the exact snapshot named by a signed checkpoint.

## Durability and retention

The daemon records audit events in SQLite with a keyed hash chain. Startup and retention verify existing history before maintenance; corruption stops startup rather than being signed again. Retention removes only an expired insertion-order prefix and authenticates its boundary without changing surviving record hashes. A clock regression can therefore keep an old-timestamp event beyond the retention period until the preceding live events expire. Export cursors remain monotonic even after the table is fully pruned.

Registered operation execution waits for audit durability before dispatch and before returning a successful payload. Bounded task execution also keeps its independent durable reservation and receipt ledger. An audit failure after an external effect cannot undo that effect: the caller receives an uncertain outcome and must inspect its receipt or audit evidence before acting again. Denials and diagnostic events remain asynchronous; they cannot authorize an effect. Persistence failures and queue losses remain visible for the lifetime of the sink; restarting requires investigating the missing evidence and underlying storage fault first.

CLI retries cover connection establishment only. Neither CLI nor MCP automatically replays a dispatched operation after a lost response or deadline. A request ID correlates evidence; it is not a general provider idempotency guarantee.

The chain depends on custody of its key and database. A process that controls the audit HMAC key can forge history; a storage writer can also restore an older intact database and authentic head. The local verifier cannot detect that rollback alone. Preserve a consistent database, any WAL/SHM state, and the matching sibling `.hmac` key when investigating integrity errors; do not edit rows or remove the key to force startup. Keep backups and exports under the same access controls as audit metadata, with independent checkpoint/receipt references outside the producer's administration.

The local tail head is now versioned and authenticated. Older unversioned heads require an explicit offline upgrade against independently trusted export bytes; startup does not silently bless them. [Signed evidence checkpoints](evidence-checkpoints.md) documents the upgrade, dedicated producer-key enrollment, transactional snapshot signing, public verification and retention receipts. These authenticate declared ranges and custody commitments; they do not establish global completeness or safe authorization-state recovery.

The migration guide requires an independently archived export of the exact retained
range in the expected JSONL framing. An arbitrary SIEM export or today's locally
calculated digest is not an upgrade anchor. Empty legacy exports are refused because
their digest cannot bind the historical sequence frontier. Preserve consumed authority and
revocation history separately: audit exports neither reconstruct grants nor prove
whether an external effect completed.

## Earlier unsigned report bundles

The source cleanup after v0.6.0 retires `evidence_package.py`, `approval_metrics.py`
and `audit_anomalies.py`, including their descriptive review signals and unsigned
control-report bundle. Their report formats are not signed checkpoint formats.
Preserve existing exports and independent reference hashes when investigating
historical bundles; the structural verifier can inspect their `audit.jsonl`.
For new custody evidence, follow the producer enrollment and authenticated snapshot
workflow above. Attaching a new signature or locally calculated hash to an old
bundle cannot establish its historical authenticity.
