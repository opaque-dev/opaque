# Build with Opaque core

Opaque's local applications and separately packaged management services consume
the same public libraries and protocols. A local installation builds and runs
without private source, organization services or enterprise credentials.

| Surface | Responsibility | Consumer requirement |
| --- | --- | --- |
| `opaque-core` | Canonical operation and identity types, policy evaluation, signed policy/report contracts and evidence primitives | Obtain trusted identity; policy evaluation alone is not a complete execution authorization |
| `opaque-bounded-work` | Task manifests, consumption ledger and bounded executors | Preserve durable reservation before dispatch, current authority and consumed unknown outcomes |
| `opaque-approval` | Trusted review binding, enrolled signatures and durable decisions | Preserve full review and current reviewer/requester verification |
| `opaque-federation-runtime` | Signed policy application, attestation, audit export and broker reporting | Retain tenant/broker binding and consumer-owned replay state where specified |
| `opaque-web` | Local dashboard application and trusted view composition | Route private data through protected APIs; honor lock, cancellation and response generations |

The [independent policy example](https://github.com/opaque-dev/opaque/tree/main/examples/embedded-policy) is a
separate Cargo project. It demonstrates library consumption without private
dependencies. Fleet wire verification also has a standalone example under
`crates/opaque-federation-runtime/examples/`.

These are Rust source interfaces, not a stable C ABI or a promise that every
crate supports every operating system. Pin a reviewed Git revision and run
integration tests when upgrading. The public core uses Apache-2.0; see [licensing](licensing.md) for documentation
and third-party terms. These interfaces are not published packages.

## Compose a dashboard

`opaque_web::run_dashboard(DashboardOptions, DashboardExtension)` runs the local
application. `application_with_extension` exposes the router for applications
that own their listener. An extension supplies compile-time tab/panel/style/script
fragments and an Axum router. All extension routes require the owner token,
including paths outside `/api/`, and retain the local Host/Origin checks.

Client code registers a view with `registerDashboardView(id, {load, clear})`.
Use `apiJson` for protected reads and capture `auth.generation`; check
`currentAuth(generation)` before changing the page after any asynchronous work.
`clear` must remove the view's private state when the dashboard locks. The same
design assets, navigation and locked shell serve every consumer.

Extensions are trusted application code, not an untrusted plugin mechanism.
Shell fragments must never contain credentials or runtime private records.
Keep provider execution and trusted approval outside browser view handlers.

## Verify portable evidence

`opaque_core::evidence_checkpoint` contains the public producer/checkpoint and
retention-receipt contracts; `opaque_core::audit::checkpoint` provides local
verified snapshots and explicit legacy upgrades. The `opaque-evidence` binary in
the `opaque` package can verify exact export bytes against independently supplied producer and
custodian trust pins without running a broker or opening its database. Follow
[the executable examples](evidence-checkpoints.md) to build it from the reviewed
checkout and check declared coverage and explicit reference pins. Single-checkpoint
CLI verification reports history as unchecked; the consuming service must enforce
predecessor continuity and retain its own high-water reference.

This is an evidence boundary: a receipt cannot restore authority, prove provider
effects or establish that its signer has independent custody. Consumers must
retain their high-water state, reject gaps/substitutions as appropriate and keep
administrative enrollment assertions distinct from measured facts.

## Storage boundaries

Public identity lifecycle and signed-report contracts do not expose a database
driver. Existing local persistence implementations still use SQLite. Backend
replacement requires migration and crash/replay/revocation acceptance; choosing
another engine does not remove those guarantees. Analytics and graph projections
must not silently become authoritative authorization state.
