# Map broker controls to an assessment

Use this mapping to identify implementation evidence for selected SOC 2 Common
Criteria and NIST SP 800-53 Rev. 5 controls. It does not establish compliance,
certification or customer operating effectiveness. Check the source and installed
release for the deployment under review; the workflows linked here describe
public core v0.6.0 on macOS and Linux.

Start by recording the broker version, permitted operation, approval path and
[custody boundary](../deployment.md). Different request paths have different
approval and consumption contracts. The [architecture overview](../architecture.md)
explains those boundaries; the [deployment verification guide](../evaluation-guide.md)
provides a short inspection workflow.

## Access and approval

| Assessment references | Implemented behavior and evidence | Scope and limits |
| --- | --- | --- |
| CC6.1; AC-3, AC-6 | Ordered, deny-by-default rules match operation, client, target, workspace, secret reference names and verified identity. Identity constraints fail closed without a principal. See [policy](../policy.md) and [policy implementation](https://github.com/opaque-dev/opaque/blob/main/crates/opaque-core/src/policy.rs). | Operators choose the rules. Direct provider credentials or another access path can bypass the broker. `Reveal` operations are blocked; `Safe` does not mean side-effect-free. |
| CC6.1; SC-7, IA-9 | The local operation socket authenticates OS peers, records executable identity and checks a daemon token. [Workload attestation](../workload-attestation.md) supplies typed observations. | Peer credentials and executable hashes do not prove human presence or a hardware-rooted workload identity. macOS Team ID matching is platform-specific; inspect `opaque policy check` warnings on other platforms. |
| CC6.2, CC6.3; AC-2, AC-7, AC-12, IA-2, IA-4 | OIDC login verifies issuer, audience, signature, nonce and expiry; daemon-owned code exchange uses PKCE. Roles and session state are read from the identity store at request time. See [identity](../identity.md). | Login MFA and IdP account administration belong to the customer. Without identity configuration, there is no verified human delegation. Managed lifecycle requires its explicit sealed admission configuration. |
| CC6.1; IA-2, IA-5, AC-17 | Prepared-action approvals bind reviewed work to the requester. Paired devices and workstations use enrolled keys and decision-bound signatures; delegation tokens are signed and checked against current store state. See [approval contracts](../architecture.md#what-approval-authorizes), [workstation review](../remote-approvals.md) and [identity](../identity.md). | Factor support depends on the operation and deployment. SSH health tasks and third-party MCP currently require local native full review. Local biometric attribution differs from signature-bound approver identity. No shipped iOS workflow is implied by the `ios_faceid` wire name. |
| PI1; AC-3, SI-10 | Generic first-use leases bind the prepared action and can carry an attempt budget. Bounded tasks and MCP invocations durably consume an attempt before dispatch. See [policy leases](../policy.md#approval-configuration), [bounded work](../bounded-work.md) and [MCP qualification](../mcp-qualified-tools.md). | These are separate contracts. Changed work needs applicable new authorization. Failed and unknown task/MCP attempts stay consumed; revocation cannot undo a provider effect already dispatched. |

## Custody and data protection

| Assessment references | Implemented behavior and evidence | Scope and limits |
| --- | --- | --- |
| CC7.1; CM-3, CM-5, SC-28 | A keyed configuration seal detects covered modification. Enforced trust-domain separation checks ownership, permissions and substituted paths at startup; agent accounts cannot access broker custody. See [deployment](../deployment.md) and [hardening](hardening.md). | Same-account session mode lets a process that obtains the keys forge locally valid state. Root and broker administrators remain trusted. SQLite state has no application-level encryption at rest. |
| CC6.7, C1; SC-39, SI-11 | Brokered operations resolve credentials after authorization and sanitize responses. `sandbox.exec` withholds stdout/stderr content in CLI and MCP responses. Secret buffers are zeroized on drop. See [operation contracts](../operations.md), [agent integration](../llm-harness.md) and [secret handling](https://github.com/opaque-dev/opaque/blob/main/crates/opaque-core/src/secret.rs). | A sandboxed child receives its configured secrets. Permitted egress, lengths and predictable status values can disclose information. Sanitization does not prove every allowed output harmless. |
| CC6.8; SC-39 | Linux execution chooses a probed namespace strategy with available Landlock/seccomp layers; macOS uses Seatbelt. Actual strategy is recorded in sandbox audit events. See [sandbox prerequisites](../deployment.md#sandbox-prerequisites). | No usable namespace wrapper on Linux means refusal. Missing layers reduce containment. `sandbox = false` retains environment sanitization only. Agent-selected commands with secrets are not a confidentiality boundary. |
| CC6.6, CC6.7; SC-8 | Approval transport uses pinned TLS and signed decisions. Export supports HTTPS webhook and TLS syslog with a required CA file. See [workstation review](../remote-approvals.md) and [federation](../federation.md). | The operation socket stays local. File-spool forwarding, network exposure and receiver administration are customer controls. Enrolling a key or receiving a notification does not approve work. |
| SC-12, SC-13 | Signed decisions, bundles, checkpoints and posture reports use their documented cryptographic formats; local audit and seals use HMAC. See [evidence checkpoints](../evidence-checkpoints.md), [federation](../federation.md) and [FIPS assessment](fips-assessment.md). | Public release binaries are not a FIPS-validated product build. Software-signed posture is not hardware measurement. KMS/HSM-backed custody is not established by a configuration example. |

## Evidence, monitoring and change control

| Assessment references | Implemented behavior and evidence | Scope and limits |
| --- | --- | --- |
| CC7.2, CC7.3; AU-2, AU-3, AU-12 | Structured records cover identity, policy, approval, execution and posture events. Task and MCP ledgers preserve their own control state and receipts. See [audit inspection](../audit-analytics.md) and [audit implementation](https://github.com/opaque-dev/opaque/blob/main/crates/opaque-core/src/audit.rs). | Available records describe broker observations, not globally complete history. An accepted API call does not prove business success. A consumed attempt does not prove a write occurred. |
| AU-9, AU-10 | HMAC chaining, authenticated heads and retention boundaries protect covered records. Signed checkpoints bind exact export bytes to an enrolled producer and declared range. Approval records preserve factor provenance. See [evidence verification](../evidence-checkpoints.md). | A holder of the HMAC key can forge a valid local chain. An intact old snapshot can verify. Receivers must retain continuity/high-water state. Signatures do not prove an honest producer or independent custody. |
| AU-6, AU-11; SI-4 | Read-only query/stream interfaces and at-least-once SIEM export support review. The approval detector evaluates observed events. Posture reports recheck custody and chain health. See [audit inspection](../audit-analytics.md) and [federation](../federation.md). | Retention, receiver deduplication, alert routing and investigation are customer-operated. The detector cannot establish omitted activity. Software posture reports assert the enrolled producer's observations. |
| CC8.1; CM-3, CM-5, SI-7 | Ed25519-signed policy bundles pin trust anchors and reject rollback/version reuse. See [federation](../federation.md). | Bundle content, signer custody and rollout approval remain operator responsibilities. There is no public enterprise fleet control plane in core. |
| CC8.1, CC9.x; CM-14 | The release workflow publishes checksums, cosign signatures and signed per-binary CycloneDX SBOMs. CI runs dependency/advisory checks. See [release verification](verifying-releases.md), [release workflow](https://github.com/opaque-dev/opaque/blob/main/.github/workflows/release.yml) and [CI](https://github.com/opaque-dev/opaque/blob/main/.github/workflows/ci.yml). | Verify the selected artifact. Reproducible builds, embedded dependency manifests and SLSA provenance must not be assumed from helper scripts or proposed procedures. |
| CC7.4, CC7.5; IR-4, IR-6 | Evidence inspection, revocation and the [vulnerability disclosure policy](https://github.com/opaque-dev/opaque/blob/main/SECURITY.md) support response. | Written procedures are documentation evidence. The deploying organization executes containment, credential rotation, restoration and incident reporting. |

## Customer responsibilities

The deploying organization provides:

- Host, network, disk encryption, physical/media, personnel and vendor controls
  (including CC6.4, CC6.5 and organizational CC9 requirements).
- IdP lifecycle and MFA; least-privilege provider credentials; isolated broker,
  reviewer and signer custody; closure of direct-access bypasses.
- SIEM deduplication, continuity tracking, retention, alerts and privacy handling
  for principal identifiers and other permitted audit metadata.
- Backup and recovery that preserve custody bindings and consumption ledgers;
  availability and disaster recovery. Core does not provide broker clustering
  or failover. Resource bounds do not establish an A1 availability program.
- Assessment scope, operating evidence and any required certification. This
  repository supplies no SOC 2 report, ISO certificate, FedRAMP authorization
  or validated FIPS product build; see [certification status](certification-roadmap.md).

## Historical findings

The [February 12 assessment](../security-assessment.md) and
[February 14 review](../adversarial-security-review-2026-02-14.md) retain their
original findings and dated status notes. They are historical evidence. Recheck
applicable findings against the deployed revision rather than treating those
reports as current qualification.
