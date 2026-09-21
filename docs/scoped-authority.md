# Scoped authority foundation

This is an unreleased library foundation for bounded agent work. It is not yet
connected to the daemon, CLI, MCP server, trusted approval ceremony, or provider
connectors. Existing task approval and execution behavior is unchanged.

The product direction is to let people approve a finite scope of work, let agents
operate within that scope, and bring exceptions back for a contextual decision.
Deterministic checks establish authority. Evaluators supply evidence for review;
they cannot expand a scope or issue permission.

## Contracts and ownership

`opaque_core::scope` defines versioned scope grants, prepared actions, review
bindings, and admission evidence. A grant names one tenant, owning broker and
generation, issuer and subject, operation, provider profile, finite resource and
field allowlists, validity interval, delegation depth, charged-attempt limit,
distinct-resource limit, and required policy, approval and evaluator bindings.

Children can only narrow a parent grant. Every ancestor remains relevant to
admission, revocation and shared budgets. A child does not receive an independent
copy of the root's capacity. Changing a grant or prepared action changes its
canonical digest and invalidates evidence bound to the old digest.

`opaque_bounded_work::scope_store` owns durable scope and action state in a local
SQLite ledger. The first implementation has one writer and one owning broker per
scope root. It does not provide cross-broker leases, leader election, replication
or failover. Independent roots do not establish a shared tenant-wide budget.

The embedding broker implements `AuthorityGuard`. That trusted host must verify
issuance authority and current authenticated identity, policy and approval or
evaluator receipts. Structurally valid JSON and matching hashes alone are not
authorization. There is no production accept-all guard in this library.
The host must hold its identity and policy change fence across the entire
reservation or dispatch-claim call, and supply independently verified delegation
context. Releasing that fence inside a callback would leave a race before the
ledger commits. Callbacks cannot reenter the same ledger.

## Admission and execution

1. Prepare an exact action, including its target resource version and evidence
   digest. Typed connectors must define and validate operation semantics.
2. Check current scope, all ancestors, authenticated authority and required
   evidence. Reserve capacity atomically against every ancestor before dispatch.
3. Recheck current authority at the final dispatch claim. A revocation before
   that claim blocks the action even if it has already consumed an attempt.
4. Dispatch at most once through the connector and record the observed outcome.
   A crash or uncertain provider response remains `UNKNOWN`; it is never an
   instruction to retry or refund capacity.

The dispatch claim is the ordering boundary. Revocation cannot recall a provider
request already sent. A connector must carry the exact prepared action across
that boundary and independently verify its resource preconditions. Local durable
admission cannot by itself promise exactly-once external effects.

## Human supervision and evidence

Durable enterprise cases will organize work awaiting attention. A case is not an
approval, and a historical receipt is not current authority. An action, scope,
policy, evidence or reviewer eligibility change requires a fresh applicable
review. Timeout and lack of a reviewer do not become approval.

Model checks may identify intent mismatch, missing evidence or suspicious source
instructions. Required evaluation failures hold the work. Shadow evaluations are
observational. Successful evaluation still requires every deterministic authority
check and any required human decision.

The library event history supports local inspection. Connecting these events to
Opaque's portable, independently verified evidence export is follow-up work; the
new ledger does not yet establish that export boundary.

## Remaining integration

Before enabling this path for real operations, implement one typed connector,
authenticated broker endpoints, the scope-bound trusted review protocol, current
identity and policy verification, evidence export, and restart/dispatch fault
acceptance against that connector. Enterprise orchestration must use the broker's
authenticated interfaces rather than open or edit its database.

Keep existing credential custody and task paths supported. New developer
password-broker workflow expansion is deferred while scoped authority, exception
review and fleet evidence are developed.
