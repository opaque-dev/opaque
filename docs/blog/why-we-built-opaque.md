# Why broker agent authority

An agent can propose useful work without receiving unrestricted authority to
perform it. Opaque puts the decision at a broker boundary: the agent requests an
action, policy decides whether it is permitted, a trusted reviewer approves the
required scope, and the broker records the observed result.

Credential custody supports this boundary. For a brokered provider operation, the
agent selects permitted work while the broker resolves the credential and calls
the provider. The agent receives only the operation's allowed result.

## Approval needs a fixed scope

A review must identify the target, parameters, lifetime and allowed attempts.
An immutable task pins that manifest for complete review. Current policy,
requester identity, expiry and revocation still apply when it runs. A changed
build or destination needs new work and review.

```sh
opaque task plan --manifest ./release.json
opaque task run <task-id>
opaque task show <task-id>
```

These commands require a configured workflow, policy and reviewer. Each task action
consumes an attempt before dispatch. A lost response can leave the effect unknown;
restarting or approving again does not restore that attempt.

## Evidence needs its own boundary

A receipt distinguishes what the broker observed from what a provider ultimately
completed. An accepted workflow dispatch does not establish deployment success.
Signed checkpoints authenticate exported records and declared ranges; independent
receivers must retain continuity state.

The broker's keys and state also need custody outside the agent's OS identity.
The default same-user setup demonstrates the workflow but does not establish that
separation. Other credentials and direct access remain outside Opaque's controls.

Core v0.6.0 includes local enforcement, CLI/MCP interfaces, trusted review and
portable evidence. Multiple brokers can consume signed policies and export to a
SIEM; fleet management is separate enterprise software.

Use the [architecture](../architecture.md) to choose an execution contract,
[deployment patterns](../enterprise-architecture.md) to choose custody, and the
[tutorial](../tutorial.md) to run a first gated operation.
