# Inspect retained scope accounting offline

**Availability: unreleased, on the scoped-authority development branch.** Export
one broker's complete retained scope ledger, then verify its signature and
accounting without access to the broker database or private enterprise source.

```sh
cargo build --locked -p opaque --bin opaque-evidence
target/debug/opaque-evidence verify \
  --enrollment producer.json \
  --checkpoint snapshot/checkpoint.json \
  --export snapshot/scope.json \
  --expected-checkpoint-sha256 "$RETAINED_CHECKPOINT_SHA256"
```

Obtain the producer enrollment and checkpoint reference through your established
trust process. A key or digest delivered only alongside an export does not
establish independent trust or freshness. The command checks a retained
reference; it does not contact the producer to find its newest state.

## Create an export in broker custody

Use a dedicated evidence signing key and enroll its public key for the exact
tenant, broker and authority generation. The [checkpoint guide](evidence-checkpoints.md)
describes `keygen` and `enroll`. Choose a separate stream ID such as `scope-ledger`;
an existing audit stream cannot change formats.

Stop the broker cleanly before running this command as its custody account:

```sh
target/debug/opaque-evidence create-scope \
  --database /private/broker/scopes.db \
  --private-key /private/evidence/producer.key \
  --enrollment /private/evidence/producer.json \
  --build-identity "$SOURCE_REVISION" \
  --output /private/evidence/snapshot-1
```

The database, its existing writer-lock file and its direct directory must belong
to the custody account, with no group or other permissions. The command refuses
a live writer, file aliases and missing databases. It opens SQLite read-only;
it does not perform startup recovery. If a process crashed with unfinished
attempts, restart the broker to record their `unknown` outcomes, then stop it
before exporting. Do not copy a running database to bypass the writer lock.

The new output directory contains `scope.json`, `checkpoint.json`, and
`retention-request.json`. Output files are private and created exclusively.
Failure can leave a partial directory for inspection; existing files are never
overwritten. Exports contain resource identifiers and action metadata: distribute
them only to intended evaluators or custodians.

For a later checkpoint, supply both prior artifacts:

```sh
target/debug/opaque-evidence create-scope \
  --database /private/broker/scopes.db \
  --private-key /private/evidence/producer.key \
  --enrollment /private/evidence/producer.json \
  --previous /private/evidence/snapshot-1/checkpoint.json \
  --previous-export /private/evidence/snapshot-1/scope.json \
  --build-identity "$SOURCE_REVISION" \
  --output /private/evidence/snapshot-2
```

This verifies the old signature and exact bytes, checks the new ledger extends
the retained history, and links the new checkpoint to its predecessor. Preserve
the trusted latest checkpoint reference outside the producer's custody boundary.

## What verification establishes

The checkpoint authenticates the enrolled producer and exact export bytes.
Storage-independent validation checks:

- Canonical grants and prepared-action digests, owner binding and narrowing ancestry.
- Every retained charge against all applicable ancestor budgets and resource sets.
- Contiguous event history, valid lifecycle ordering and revocation before subsequent admissions or claims.
- Retained dispatch and outcome timestamps, including interrupted attempts whose actual interruption time is unknown.

A successor must retain prior events and immutable authority/action bindings.
Terminal outcomes, including `unknown`, cannot be rewritten. A complete export
contains all retained scopes, actions and events; it fails above 64 MiB instead
of silently truncating. This bound applies to export, not to ledger admission.

Checkpoint schema version 2 identifies this scope JSON format and has a distinct
signature domain. Version 1 audit JSONL remains unchanged. `record_count` and
sequence bounds count scope events, not the number of JSON objects or business
operations. A custodian needs version-2 support before accepting this format.

## Limits

This is a producer-attested record of one retained ledger. A compromised producer
can sign a false but internally consistent first snapshot. Deleted history cannot
be discovered without a separately retained reference. Signatures do not prove
unobserved actions, current authorization, independent administration or business
completion. `api_accepted` records an API response; it is not proof that the
downstream business operation completed.

This export contains approval **digests**, not the signed review receipts.
Retain the [trusted scope-review receipts](scoped-authority.md) separately as a
JSON array. `verify-scope-reviews` accepts the same enrollment, checkpoint, export
and optional retained pin, plus `--receipts` and an independently enrolled
`--broker-public-key`. It verifies the historical reviewer and broker signatures
and matches issuance/exact-action receipts to the exported grants and charges.
It does not prove human presence or current enrollment. The
[synthetic recovery example](scope-recovery.md) shows this command end to end.
The export cannot restore authority, clear unknown outcomes, refund attempts or
authorize retries.
