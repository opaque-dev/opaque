# Evaluating Opaque

This guide is for the person who signs off on what an AI agent may touch:
a security architect, a platform lead, a CISO. It orders the documentation
into a review you can finish in about an hour. Thirty minutes of reading,
fifteen minutes running the broker on one laptop, and the rest spent
checking our claims against source and signatures.

Opaque is not another secrets manager or agent framework. It decides what
may pass between the two you already have, and proves what did. The agent
receives operations and constrained results. Plaintext stays with the
broker. Every privileged action carries policy, required human approval,
and a tamper-evident record.

## Start with the adversary

The agent is the adversary. Its model, its dependencies, its prompt
context and every command it emits are untrusted, including in the moments
it is being helpful. The broker, its administrators, the credential stores
and enrolled approval keys remain trusted. Opaque does not prevent an
agent from using credentials it can already read through another path.

[Architecture](architecture.md) states the boundary precisely.
[Security assessment](security-assessment.md) is the threat model we wrote
against ourselves, findings included, and
[the adversarial review](adversarial-security-review-2026-02-14.md) is the
follow-up pass we published rather than filed away.

## Five invariants, with enforcement points

| Invariant | Enforced where | Check it yourself |
| --- | --- | --- |
| Plaintext never reaches the agent | Response sanitization is a type state in `opaque-core`; returning an unsanitized response does not compile | `rg 'SanitizedResponse' crates/opaque-core/src` |
| Approval arrives out of band | The agent cannot approve through the interface it drives; a missing approval factor fails closed, and the daemon refuses to start when its local factor cannot authenticate | Disable the factor and watch the request refuse |
| The broker derives the target | Wire parameters that contradict the derived target are rejected before policy, approval or provider dispatch | Substitution tests in `crates/opaqued/tests` |
| Delegated authority is an intersection | An agent working under human delegation holds agent ∩ human; logout or expiry invalidates in-flight operations | [Identity](identity.md) |
| Evidence is a keyed chain | HMAC hash chain over the audit log, anchored in the database, verified at startup and on demand, exportable with per-record hashes | `opaque audit verify` |

## What the evidence proves, and when

Read this section before quoting us. In the default single-account
install, audit history is tamper-evident: edits, reordering, deletion and
truncation are detected, and a process holding the daemon's keys could
still forge locally valid history. Under enforced trust-domain custody,
with configuration, keys and authoritative state owned by a separate
service account, the same chain hardens into a boundary the agent's
account cannot cross. The daemon checks custody at startup and reports the
posture it is running in. [Deployment](deployment.md) is the boundary to
follow; a separate directory under the same account is insufficient.

## Compliance posture

Opaque holds no certifications today. What exists is inspection material:
a [control mapping](compliance/control-mapping.md) to SOC 2 and NIST SP
800-53 rev 5 with file citations and open findings listed, a
[FIPS assessment](compliance/fips-assessment.md) documenting a working
build against a FIPS-validated cryptographic module and naming the two
paths that do not yet have one, and
[release verification](compliance/verifying-releases.md) for the
cosign-signed tarballs and per-binary CycloneDX SBOMs every release ships.

## What Opaque does not do

- No SCIM or IdP group sync. Roles resolve inside the daemon.
- No Slack or Teams approval routing. Approval is local native review or a
  paired workstation.
- No fleet dashboard across many daemons.
- No SOC 2 report, no FedRAMP authorization.
- No control over credentials the agent obtains outside the broker.

If one of these is disqualifying, the trial below will not change that,
and we would rather you know now.

## Falsify it in fifteen minutes

1. **Verify the download.** Checksum first, then cosign against the
   release workflow identity, following
   [verifying releases](compliance/verifying-releases.md). The signature
   is keyless and checks against this repository's release workflow.
2. **Run one gated operation.** The [tutorial](tutorial.md) installs the
   broker, gates one real secret publish behind your approval, and shows
   you the receipt. The secret value never appears in the agent's
   transcript.
3. **Try to break the chain.** Stop the daemon, edit any row in the audit
   database, run `opaque audit verify`. It exits non-zero and names where
   the chain broke.
4. **Read the source at the pinned commit.** The architecture pages cite
   the exact commit they describe, so what you read is what you audit.

Steps 2 and 3 are scripted, with no external accounts, in the
[Harborlight quickstart](https://github.com/opaque-dev/harborlight).
Its CI runs the same falsification weekly against the released package.

## Where to go next

[Bounded work](bounded-work.md) covers immutable task manifests and
durable attempts. [MCP qualification](mcp-qualified-tools.md) covers the
gate for third-party MCP tools: signed routes, pinned upstream schemas,
one approval per invocation. [Federation](federation.md) covers signed
policy bundles and SIEM export for the day one laptop becomes a fleet.
