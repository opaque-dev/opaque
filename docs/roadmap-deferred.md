# Deferred capabilities

These capabilities are outside the public core release. They describe remaining
work, not scheduled availability.

## Developer password-broker expansion

Password filling and password-broker onboarding are deprioritized. Current work
focuses on gated actions, bounded authority, trusted review and inspectable evidence.
Credential integrations remain enforcement dependencies.

## iOS second-device approvals (Face ID)

No iOS app ships. The `ios_faceid` wire factor is desktop pairing;
[second-device status](mobile-approvals.md) distinguishes current review from the
mobile design.

## General-purpose tenant operator

A general-purpose workload operator needs separately qualified isolation and
resource contracts. Kubernetes operator implementation belongs to the private
enterprise repository; public tenant binding is not workload isolation.

## Hardware attestation and confidential compute

Current posture reports are software claims signed by an enrolled key holder.
Hardware measurement, confidential-runtime attestation and measurement-gated key
release require a measured runtime and verifier policy.

## Isolation for co-resident sibling agents

Separate broker custody isolates the agent account from the broker, not agents
from each other when they share an account. Host administrators remain trusted.
No microVM/vsock isolation is provided.

## External, witnessed transparency

[Signed checkpoints](evidence-checkpoints.md) authenticate declared audit ranges.
Externally witnessed logs and third-party Merkle proofs are separate work; receiving
a valid checkpoint does not establish global completeness.
