# Inspect and export audit records

Read instrumented decisions and outcomes, check local chain integrity, and export
evidence for another recipient. Core v0.6.0 includes the local audit store, query
commands and SIEM export.

```sh
opaque audit tail --limit 50
opaque audit tail --query github --limit 20
opaque audit verify
```

A request ID correlates records; it does not make a provider call idempotent.
For an unresolved task, inspect its receipt with `opaque task show <task-id>` and
use `opaque task reconcile <task-id>` to read evidence without dispatching again.

## Durability and retention

The SQLite audit store uses a keyed hash chain and authenticated head. Startup
and retention verify existing history; corruption stops startup. Retention removes
only an expired insertion-order prefix and authenticates the boundary without
changing surviving hashes. A clock regression can keep an old-timestamp event
until preceding live events expire. Export cursors remain monotonic after pruning.

Registered operations wait for audit durability before dispatch and before
returning successful payloads. Tasks also maintain an independent durable
reservation and receipt ledger. An audit failure after an external effect cannot
undo it: the caller receives an uncertain outcome. Denials and diagnostic events
are asynchronous and cannot authorize an effect. Persistence failures and queue
losses remain visible for the sink's lifetime.

CLI retries cover connection establishment. CLI and MCP do not automatically
replay a dispatched operation after a lost response or deadline. Consumed task
and MCP attempts remain spent when their outcomes are unknown.

## Independent evidence

A process holding the HMAC key can forge locally valid history. An older intact
snapshot can also verify locally. Keep checkpoints and high-water references
outside the producer's administration to detect covered rollback or discontinuity.

[Signed evidence checkpoints](evidence-checkpoints.md) authenticate exact export
bytes, an enrolled producer and a declared range without sharing the HMAC key.
They do not prove unobserved effects, global completeness or restored authority.
Older audit heads require the guide's explicit offline upgrade against an
independently archived exact export; startup does not silently migrate them.

When investigating failures, preserve the database, any WAL/SHM state and matching
`.hmac` key. Do not edit rows or remove keys to force startup. Audit exports cannot
reconstruct consumed authority or revocation history; follow
[storage and recovery boundaries](storage.md).

## Collection and analysis

| Surface | Current behavior |
| --- | --- |
| [Local dashboard](web-dashboard.md) | Authenticated read-only queries and a resumable audit stream |
| [SIEM export](federation.md#audit-export-to-siem) | Spool, HTTPS webhook or TLS syslog, each with a durable cursor; at-least-once delivery |
| Approval detector | Checks recorded required approval against granted approval or a lease before recorded operation success; emits `audit.alert` on a violation |

The detector evaluates recorded events, not omitted actions or independent provider
completion. Protect exports as sensitive metadata: principal labels, targets and
secret references can disclose context even when values are omitted.

Build additional analysis as a derived view of authenticated exports; it must
not become an authorization source.
