# Second-device approval status

Core v0.6.0 includes paired desktop approval factors. An iOS application, Face ID
gate, QR onboarding and mobile push workflow are design proposals; no iOS app
ships with the public core.

## Select a supported review path

| Factor | Supported use | Setup |
| --- | --- | --- |
| `paired_workstation` | Complete secret-publish, staging-release or fixed-inference task review on an enrolled trusted workstation | [Workstation review](remote-approvals.md) |
| `ios_faceid` | Shipped paired second-device Ed25519 approval; the wire name does not establish iOS or Face ID support | `opaque device pair`, `ls`, `confirm`, `revoke`; [identity](identity.md) |
| `fido2` | Challenge-bound security-key or passkey approval where the operation permits that factor | [Policy factors](policy.md#approval-configuration) |

Keep the review device and its signing key outside the agent-controlled account.
Enroll the expected broker identity and TLS fingerprint through a trusted channel.
A received notice, device enrollment or old decision receipt does not approve new
work. The broker must verify the current reviewer and exact decision binding.

SSH health tasks and third-party MCP invocations currently require native local
full review. A paired-workstation task approval does not authorize those paths;
see [task review](bounded-work.md#reviewing-and-approving).

## Requirements for a future mobile client

A mobile implementation would need trusted broker enrollment, a device-held signing
key, complete scope display, decision-bound challenges, expiry and revocation
checks, durable decision receipts and independent transport qualification.
Biometric key use would require platform enforcement and evidence of that ceremony;
a signature alone does not prove a Face ID event.

These requirements describe future design work. Use the supported desktop reviewer
for current deployments and consult [deferred capabilities](roadmap-deferred.md).
