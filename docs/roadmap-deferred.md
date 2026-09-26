# Deferred

Out of scope for the current release, not "coming soon": each needs its own
threat model, evidence, or customer pull before it's worth building.

## Developer password-broker expansion

New password-filling workflows and developer password-broker onboarding are
deprioritized. Product work focuses on bounded authority, trusted human review,
and inspectable execution evidence. Existing credential integrations remain
supported enforcement dependencies; custody does not by itself authorize work.
See the [scoped authority foundation](scoped-authority.md) for implemented library
boundaries and the integration work still required.

## iOS second-device approvals (Face ID)

Design only; see [mobile approvals](mobile-approvals.md). No iOS app ships.
The paired-second-device factor that does ship is desktop-to-desktop
(Ed25519), not mobile.

## General-purpose tenant operator

Tenant support (see [enterprise architecture](enterprise-architecture.md))
is scoped to validated operation families. A general-purpose operator for
arbitrary workloads needs its own isolation model.

## Hardware attestation and confidential compute

Posture attestation today is software-only (custody + audit-chain
integrity). Hardware measurement, confidential VM/enclave attestation, and
key release gated on it need a real measured runtime and verifier policy.

## Isolation for co-resident sibling agents

Trust-domain enforcement separates the daemon's uid from the agent's, not
multiple agents sharing a host from each other, and not from a host
administrator who already has root. No microVM/vsock isolation exists.

## External, witnessed transparency

Signed audit exports verify independently at the receiving SIEM. Publicly
witnessed transparency (signed checkpoints, third-party-checkable Merkle
proofs) needs a named relying party before it's worth building.
