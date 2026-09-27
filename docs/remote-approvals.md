# Remote reviews and independent notification adapters

Opaque core owns the review challenge, current reviewer eligibility, signed
decision and final authorization check. A separately enrolled workstation fetches
the full review over pinned TLS and signs the exact challenge. The broker verifies
that signature and retains the decision before acknowledging it. Notification
adapters cannot approve work or replace the native review ceremony.

The macOS release archives include `Opaque Reviewer.app` and the standalone
reviewer (verified in the published v0.5.0 `aarch64-apple-darwin` archive, which
also carries `opaque-approver`). The shell installer installs CLI binaries only.
The Homebrew formula tracks the latest published release and preserves the
included app at `$(brew --prefix opaque)/Opaque Reviewer.app` without opening or
registering it; the release archive also supports manual installation.
Its native URL handler accepts opaque references only, queues a bounded set of
notices and resolves them against explicitly selected local enrollment. Opening
a notice does not approve it. A reviewer chooses to open the full immutable
document, confirms review and authenticates natively before an approval is signed.
Rejecting native review can submit a signed rejection; dismissing the notice
locally sends no decision. See the [installation and enrollment guide](https://github.com/opaque-dev/opaque/blob/main/crates/opaque-approver/README.md).
The app displays expiry and separates decision acceptance from execution. A
missing acknowledgment triggers a read-only receipt lookup, never another POST
or an operation retry. Signed/notarized distribution and fresh-user native testing
remain distinct from local packaging and inert launcher tests.
Native review lasts at most 90 seconds and authentication at most 60 seconds,
each bounded by the remaining challenge deadline. An accepted rejection is still
a decision acknowledgment, not permission to execute. Retained receipt lookup is
for current-authority v2 remote tasks and still requires eligible device/human
access; it does not recover authority from an expired or revoked round.

A host can use the public `opaque-approval` runtime without an enterprise service.
`RemoteApprovals` accepts host-owned reviewer resolution and authority guards;
the host keeps revocation checks held through the irreversible ledger transition.
The same configured device, principal, required role, authority epoch and exact
requester must remain eligible when a decision is accepted and used.

## Configuring the current remote reviewer

Workstation enrollment alone does not enable v2 remote tasks. Add these fields to
an already provisioned broker's trusted configuration:

```toml
[[workstation_approvers]]
name = "Trusted reviewer"
public_key_hex = "<workstation Ed25519 public key>"
principal_id = "<existing enabled human principal ID>"

[remote_approvals]
reviewer_public_key_hex = "<same workstation Ed25519 public key>"
required_role = "operator"
# Optional: omit this field for review without a notification adapter.
notice_token_file = "/absolute/broker-custody/notice.token"
```

The daemon requires native approval backend, `enable_task_grants = true`,
`require_seal = true`, enforced isolated custody, an isolated tenant binding, and
`identity.required = true`. The named reviewer must remain enabled, admitted and
hold `required_role`. The task and its child actions must require the single
`paired_workstation` factor. Apply changes through the trusted sealing/startup
process. See [deployment](deployment.md), [identity](identity.md) and
[policy](policy.md). Distinct-approver policy remains in force when configured;
a second key for the requester does not provide a different human reviewer.

The workstation needs the broker HTTPS origin, its `opq-...` pairing ID and the
full certificate SHA-256 through trusted operator provisioning before enrollment.
Startup's shortened certificate fingerprint is insufficient. No current dedicated
read-only operator CLI exports this complete enrollment handoff; notices and
unverified discovery responses must not become its trust source.

## Configuring the optional notice feed

The optional token is a dedicated read credential, not a paired-device token.
Its file must be an owned mode-0600 regular file directly inside the same custody
directory as the remote decision ledger. Use 32–128 random URL-safe characters,
with no whitespace, and distribute it only to the intended adapter through
private custody. The broker hashes the credential at startup; credential rotation
requires an intentional restart, which cancels unfinished approval rounds.
Omitting the token disables the feed while preserving trusted workstation review.
Legacy `slack` configuration is rejected, so a migration cannot silently leave
notification delivery enabled inside the broker.

`GET /notifications/pending` on the existing HTTPS approval server requires the
single `Authorization: Bearer <notice-token>` header. Browser-origin requests are
rejected. The response has `Cache-Control: no-store` and this v1 shape:

```json
{
  "schema_version": 1,
  "broker_id": "opq-example",
  "notices": [
    {
      "approval_id": "00000000-0000-4000-8000-000000000001",
      "broker_id": "opq-example",
      "expires_at": 2000000000
    }
  ]
}
```

The response contains at most the 64 live workstation rounds and filters each
against current reviewer eligibility and expiry. It contains no review text,
requester, task details, signing keys or transport credentials. Polling does not
consume a round or write delivery status. A notice token cannot fetch workstation
review documents or submit decisions. Public wire structs are
`remote::notices::{ApprovalNotice, PendingNoticeFeed}`.

## Implementing an adapter

Pin the broker's certificate and identity through a trusted channel before
sending credentials. Disable redirects and ambient proxies, bound requests and
responses, validate the feed version and broker ID, and never derive endpoints
or credentials from notice contents. Use `opaque_core::workstation::notice_link`
to create the opaque reference; only the enrolled approver resolves it against
its own pinned broker configuration.

An adapter owns its delivery deduplication, retry budget and transport credentials
separately from broker state. Recheck that a notice is still pending immediately
before delivery. Cancellation can race a message already in transit; the message
still carries no authority, and the workstation/broker check the current review.
A delivery failure or unknown outcome must never become an approval or retry of
an agent operation. Snapshot or transport availability is not proof of approval.

Core retains the existing decision ledger schema for historical signed receipts.
Old notification columns remain inert for compatibility; new rounds do not store
transport attempts there. Restart cancels unfinished rounds and cannot resume
work from either historical receipts or notification state.

Current remote task approval uses one configured reviewer. It does not authorize
MCP invocations, provide approval quorum or imply a completed production pilot.
