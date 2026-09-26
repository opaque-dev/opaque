# Why an uncertain agent write stays charged

Run a process that shares four authorized attempts among sixteen concurrent
requests, kill it after dispatch, and inspect what survives:

```sh
cargo run --locked -p opaque --example scope-recovery -- /tmp/opaque-recovery-run
```

This public-core example is part of the unreleased
[scope-evidence change](https://github.com/opaque-dev/opaque/pull/132).
Use a new absolute output directory on Linux or macOS. Its identities, reviewer
signatures and local provider effects are synthetic. The process termination,
transactional accounting and offline signature checks execute real code. The
[reproduction guide](scope-recovery.md) includes the build and verification steps.

## A missing response leaves an unresolved effect

An agent can send a write just before its process dies. The provider might have
applied the write, rejected it, or never received it. A missing acknowledgment
does not distinguish those cases.

Returning the attempt to the available budget would let another request spend
the same authorization. Automatically resending could repeat an external effect.
Opaque therefore retains the consumed attempt and records `unknown` when recovery
cannot establish a terminal outcome. That uncertainty remains visible to the
operator and to later evidence inspection.

The budget measures attempts. It does not promise a number of successful business
outcomes. Provider idempotency and reconciliation are separate requirements.

## Four reservations, three uncertain outcomes

The example admits four requests and rejects twelve because the shared budget
is exhausted. It records these four cases before terminating the producer:

| State at the crash boundary | Retained after restart | Attempt remains charged |
| --- | --- | --- |
| Synthetic provider acknowledgment recorded | `api_accepted` | Yes |
| Synthetic effect written, acknowledgment treated as lost | `unknown` | Yes |
| Dispatch claimed, process killed before recording its outcome | `unknown` | Yes |
| Reserved, then prevented from dispatching by scope revocation | `unknown` | Yes |

The final reservation illustrates a conservative recovery boundary. The stopped
process knew that its dispatch claim failed; the ledger did not record a terminal
result. Restart preserves that distinction instead of inventing a successful
reconciliation. Inspect the retained action and event records to see which
requests had a dispatch claim.

## Revocation orders future dispatch

Revoking the scope prevents a later dispatch claim, including one for an existing
reservation. It cannot recall an external request already sent under a prior
claim. An in-flight action can still report its outcome after revocation.

A supervision interface must preserve those states. A task disappearing from a
runtime, a reviewer queue becoming empty, or a worker restarting does not establish
that its external effects stopped. Recovery starts by reading retained outcomes.
It needs explicit reconciliation before anyone considers replacement work.

The [scope workflow](scoped-authority.md) exposes authenticated outcome
reads and scope revocation. Its broker checks current authority before dispatch;
the external provider must enforce the documented resource-version precondition.

## Keep evidence that another process can inspect

The example exports the complete scope ledger, signs linked checkpoints, and
verifies historical reviewer signatures. The public `opaque-evidence` CLI can
inspect those files without the broker database or producer private key.

The [scope-evidence contract](scope-evidence.md) checks that charged attempts agree
with retained actions and events. Comparing successive snapshots also rejects
removed history, cleared revocation and changed terminal outcomes. A previously
retained `unknown` cannot quietly become `api_accepted` in a later producer claim.

An independently retained checkpoint gives an inspector a reference for detecting
changed history. A valid signature by itself does not prove the producer told the
truth, captured every external action, or supplied the latest snapshot. In this
example, both checkpoints are signed after reproduction; the run does not
demonstrate independently retained evidence before the crash.

## What remains to qualify

This example exercises one local authority owner and one shared budget. It does
not establish a distributed budget, broker failover, real human presence, live
provider behavior, independently administered custody, or production capacity.
An API acknowledgment also does not prove downstream business completion.

Use the reproduction to evaluate the accounting behavior, then qualify the
intended deployment's identity, native review, connector and retention boundaries.
Keep unresolved effects visible throughout that evaluation.
