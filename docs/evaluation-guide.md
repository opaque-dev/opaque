# Verify a deployment's controls

Select one agent action and verify its authorization, review, effect and evidence
against the exact release you intend to deploy. Start with core v0.6.0's
[request paths](architecture.md) and [deployment patterns](enterprise-architecture.md).

## Define the boundary

Record the operation, target, credential, agent identity, approver and expected
provider readback. Run the broker under a separate OS identity for custody
isolation. Identify any direct access the agent retains outside Opaque.

| Check | Expected behavior | Reference |
| --- | --- | --- |
| Admission | Unmatched operations and out-of-scope targets are denied | [Policy](policy.md) |
| Review | Approval binds the applicable prepared action, task manifest or MCP invocation | [Architecture](architecture.md#what-approval-authorizes) |
| Current authority | Expiry, logout, role removal and revocation are checked at the applicable dispatch/disclosure boundary | [Identity](identity.md) |
| Consumption | Task/MCP failures, restarts and unknown outcomes do not restore a durable attempt | [Bounded tasks](bounded-work.md), [MCP qualification](mcp-qualified-tools.md) |
| Evidence | Receipts report observed outcomes; checkpoints authenticate declared export ranges | [Evidence verification](evidence-checkpoints.md) |

Generic first-use leases and [scoped authority budgets](scoped-authority.md) have
their own consumption rules. Do not apply task semantics to every interface.

## Run and inspect

1. Verify the archive's checksum and published signature using
   [release verification](compliance/verifying-releases.md).
2. Run the [first-operation tutorial](tutorial.md) with disposable credentials and
   data, then inspect `opaque audit tail` and `opaque audit verify`.
3. Qualify the selected provider's effect with independent readback. API acceptance
   is not deployment success, stored-value verification or service health.
4. Test scope changes, replay, revocation and interruption in isolated fixtures.
   [Scope recovery](scope-recovery.md) supplies a reproducible interrupted-budget
   example; architecture source links identify task/MCP and audit tests.

Tests and mock providers validate mechanisms. Qualify native reviewer installation,
actual provider behavior, custody and bypass paths for the chosen deployment.
Do not alter a live audit database to test tamper detection.

## Interpret the result

A local HMAC verifier cannot identify a key holder's forgery or a complete older
snapshot. Independently held checkpoints and high-water state are separate
requirements. Signed software posture reports authenticate claims from an enrolled
key holder; they do not measure hardware integrity.

SCIM integrations, collaboration delivery, fleet collectors and management views
are separate enterprise components. A successful core test does not qualify them.

For an assessment, use the [control mapping](compliance/control-mapping.md),
[hardening reference](compliance/hardening.md) and
[cryptographic build assessment](compliance/fips-assessment.md).
These documents and source tests are inspection material, not a certification or
an independent audit.
