# Understand broker authorization { #architecture }

An approval binds captured work to a requester, target and lifetime. Current
policy, identity and revocation still apply when the broker dispatches it.
For a configured staging-release manifest:

```sh
opaque task plan --manifest ./release.json
opaque task run <task-id>
opaque task show <task-id>
```

Inspect dispatch and workflow evidence separately: API acceptance is not deployment
success. Choose the [custody/topology pattern](enterprise-architecture.md) before
admitting untrusted agents.

The generic/task/MCP source references below are pinned to
[83e7924](https://github.com/opaque-dev/opaque/tree/83e7924960f809e87379a54996317dbe1422fe70).
Check the selected release and each workflow's qualification requirements.

<a id="1-design-goals"></a>
<a id="3-crates"></a>

## Request flow

The daemon prepares the effective target, parameters and credential references
before policy or review. Generic execution uses that captured action; values are
resolved after authorization. Task manifests pin their complete planned scope.
CLI and MCP are adapters; the broker owns enforcement. See
[operation contracts](operations.md) and [core boundaries](reusable-core.md).

<a id="6-approval"></a>
<a id="8-bounded-agent-work"></a>

## What approval authorizes

| Path | Scope and consumption |
| --- | --- |
| [Generic operation](operations.md) | Prepared action bound to client, target, references, parameters and verified delegation. Policy and operation minimums set the gate. A first-use lease can permit repeated matching operations until expiry, with an optional attempt budget. |
| [Bounded task](bounded-work.md) | Immutable manifest reviewed in full locally or, for supported families, by a paired workstation. Each action consumes a durable attempt before dispatch. |
| [Third-party MCP](mcp-qualified-tools.md) | Single-use invocation under a signed route, pinned schemas and finite arguments. Requires local native full review and its own durable attempt ledger. |
| [Scoped authority](scoped-authority.md) | Separate v0.6.0 `opaque scope` path: finite resources/values, expiry and attempt budget, with per-action review by default. Its stores and executor are separate from the paths above. |

Changed work requires applicable new authorization. Task/MCP failures and unknown
outcomes do not refund attempts; inspect or reconcile before proposing replacement
work. Revocation before the final fence blocks dispatch, but cannot undo an earlier
provider effect. An unsupported approval factor fails closed. A workstation task
receipt does not authorize third-party MCP.

<a id="2-threat-model"></a>
<a id="4-trust-boundaries"></a>
<a id="5-identity-and-policy"></a>

## Trust boundaries

The broker, its administrators, credential stores and enrolled approval keys are
trusted; agent workloads are not. Enforce [separate broker custody](deployment.md)
to keep agent accounts away from configuration, keys and authoritative state.
Shared-account processes that obtain keys can compromise controls and forge
locally valid history. Root and broker administrators remain trusted in split mode.

Opaque governs broker-routed work. Other readable credentials or provider access
can bypass it. OS peer/executable identity does not prove human presence: an agent
can invoke the CLI. [Verified delegation](identity.md) and [policy](policy.md)
supply the additional authority checks.

<a id="7-sandboxed-execution"></a>

## Output and execution limits

Provider inputs can stay in broker custody through credential references; allowed
outputs follow the operation contract. Sanitization is enforced, but pattern
scrubbing does not prove every output harmless. MCP v2 may disclose signed
selections of bounded integer/status fields under current authority. These remain
untrusted provider claims; arbitrary upstream text is withheld.

`opaque exec` gives profile secrets to a child. Its Linux/macOS sandbox is a
compatibility control, not confidentiality from an agent-selected command.
Permitted egress and status/length metadata remain disclosure paths.

<a id="10-audit"></a>

## What the evidence supports

HMAC chaining and authenticated heads detect covered tampering without the key.
[Signed checkpoints](evidence-checkpoints.md) bind an enrolled producer to exact
export bytes and a declared range without sharing that key. Intact old snapshots
can verify; receivers must retain continuity/high-water state.

Receipts describe observations. A charged attempt does not prove a write; a
signature proves neither an honest producer, independent custody nor globally
complete history. Older stores require the linked explicit migration procedure.

<a id="9-federation"></a>
<a id="11-providers"></a>
<a id="12-platforms"></a>
<a id="deferred"></a>

## Inspect and qualify

Start with these source and test anchors at the revision above:

- [Generic enforcement](https://github.com/opaque-dev/opaque/blob/83e7924960f809e87379a54996317dbe1422fe70/crates/opaqued/src/enclave.rs): preparation, approval leases and dispatch checks.
- [GitHub secret-write fixture](https://github.com/opaque-dev/opaque/blob/83e7924960f809e87379a54996317dbe1422fe70/crates/opaqued/tests/provider_e2e.rs): broker dispatch to a mocked GitHub endpoint and checks that the response omits the secret and token.
- [Task ledger tests](https://github.com/opaque-dev/opaque/blob/83e7924960f809e87379a54996317dbe1422fe70/crates/opaque-bounded-work/src/task_store.rs): concurrent consumption, revocation and interrupted-attempt recovery.
- [MCP integration tests](https://github.com/opaque-dev/opaque/blob/83e7924960f809e87379a54996317dbe1422fe70/crates/opaqued/tests/mcp_gateway_e2e.rs): mocked effects, denied dispatch, restart replay rejection and withheld disclosure.
- [Audit regression tests](https://github.com/opaque-dev/opaque/blob/83e7924960f809e87379a54996317dbe1422fe70/crates/opaque-core/src/audit/regression_tests.rs): tampered storage, retention and durability faults.

These are implementation evidence, not an independent security audit or customer
production validation. Qualify actual credentials, provider behavior, reviewer
installation, custody and bypass paths for the chosen workflow. Platform packaging
and source tests do not qualify every feature on every platform.

For broader configuration, continue to [operations](operations.md),
[federation](federation.md) or [deferred capabilities](roadmap-deferred.md).
