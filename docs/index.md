---
template: home.html
hide:
  - toc
---

# Opaque

**Gate and audit agents at scale.**

Opaque gives platform and security teams control over AI agent actions.
Define permitted operations, require human approval, and record what happened.

[Try the demo](https://demo.opaque.info/) · [Set up locally](tutorial.md)

Open-source core · macOS and Linux · [v0.6.0 and installation](getting-started.md)

Hosted demo uses fictional data. [Demo guide](hosted-demo.md).

## A gated staging release { #approve-one-staging-release }

Configure the release workflow and policy, then prepare a manifest.
Example commands; replace `<task-id>`:

```sh
opaque task plan --manifest ./release.json
opaque task run <task-id>
opaque task show <task-id>
```

Approval covers one build, one destination, and one dispatch attempt.
A timeout can leave the result unknown; the attempt stays consumed.
Dispatch acceptance is not deployment success.
[Task setup and revocation](bounded-work.md).

## Gate access { #set-the-permitted-scope }

Deny by default. Limit operations by identity and target,
and require human approval before sensitive execution. [Policy rules](policy.md).

## Bound the work { #bound-agent-work }

Give tasks an exact scope and expiry. Revoke future dispatches;
an approval cannot expand the reviewed task. [Task limits](bounded-work.md).

## Audit actions { #audit-agent-actions }

Inspect decisions, approvals, and observed outcomes.
Verify exported audit ranges with independently held checkpoints.
[Evidence verification](evidence-checkpoints.md).

## Manage policy across brokers { #policy-across-brokers }

Public core v0.6.0 includes signed policy distribution and SIEM export.
Fleet management is separate enterprise software.
[Signed policies and audit export](federation.md).

## Protect the broker { #know-the-boundary }

Route agent actions through Opaque and run the broker under a separate OS identity.
Same-user installs do not isolate custody; direct agent access remains outside the gate.
[Deployment boundaries and evidence](architecture.md).
