# Run a bounded support-case workflow

The opt-in scope workflow lets a person approve a finite set of support cases,
allowed statuses, expiry and attempt budget. The broker prepares each status
change against the provider's current resource version, checks current authority,
and records one dispatch attempt. The default also requires a separate human
review for each exact change.

This workflow is unreleased. The connector implements the fixed REST contract
below; it is not a Zendesk or Salesforce adapter. Automated tests use a synthetic
provider and synthetic reviewer signatures. They do not certify a live provider,
native human presence, or production capacity.

## Prerequisites

Use an isolated tenant broker with sealed configuration, enforced service-account
custody, required identity, and native approval. The requester must have the
operator role. Configure a distinct human approver with the approver role and an
enrolled workstation whose public key and principal match the workflow config.

The provider credential belongs to the broker account in a private regular file.
The agent must not have that credential or an alternate write path. Enroll the
workstation using the existing pinned-TLS `opaque-approver enroll` flow before
requesting a scope. Run the approver on that trusted workstation outside delegated
agent sessions.

Add a configuration section to the broker's trusted configuration, then seal it
using the deployment's normal configuration process:

```toml
[scope_workflow]
reviewer_id = "human:YOUR_ENROLLED_PRINCIPAL"
reviewer_public_key = "YOUR_64_CHARACTER_PUBLIC_KEY"
generation = 1
max_scope_seconds = 3600
max_attempts = 100
max_resources = 100
exact_action = true
allowed_statuses = ["open", "resolved", "closed"]

[scope_workflow.profile]
endpoint = "https://support-api.example.com/v1/"
token_file = "/var/lib/opaque/support-api.token"
```

Use actual principal identifiers from the deployment. The example public key and
principal are placeholders, not runnable credentials. The endpoint must be HTTPS,
end in `/`, and have no credentials, query or fragment. Proxy use, redirects and
transport retries are disabled. The token file must be owned by the broker, have
no group/other permissions, and not be a symbolic link or multiply linked file.

## Provider contract

`GET {endpoint}cases/{id}` returns exactly an object with `id`, `status` and
`version`. Status is `open`, `resolved` or `closed`. IDs and versions are at most
128 ASCII alphanumeric, hyphen or underscore characters. Reads are bounded to
16 KiB and eight seconds.

The only write is `PATCH {endpoint}cases/{id}` with `{"status":"resolved"}`,
`If-Match: "version"`, and an `Idempotency-Key` equal to the broker action ID.
The API must enforce the version precondition atomically. Its `409` and `412`
responses must mean that no change was applied. A successful HTTP response is
recorded as `api_accepted`; it does not establish downstream completion. All other
write responses and transport uncertainty become `unknown`.

A production adapter must qualify this contract against its selected API before
live use. No caller can select an arbitrary URL, method, header or request body.

## Review and execute

Run the `opaque scope` commands inside the authenticated delegation. Create a
scope manifest, for example:

```json
{"resources":["case-101","case-102"],"statuses":["resolved"],"expires_in_secs":900,"max_attempts":2}
```

1. Run `opaque --json scope plan --manifest scope.json`. Save the returned
   `document.round_id`.
2. On the enrolled workstation, run `opaque-approver scope-review --state-dir
   /path/to/workstation-state --round-id ROUND_ID`. The native prompt shows the
   complete signed scope. Approval and rejection both produce signed decisions.
3. Run `opaque --json scope activate ROUND_ID`. Save the scope ID. Activation
   issues authority and does not send a provider write.
4. Prepare a change using `opaque --json scope prepare --manifest action.json`:

    ```json
    {"scope_id":"SCOPE_ID","issuance_round_id":"ISSUANCE_ROUND_ID","resource":"case-101","status":"resolved","request_id":"case-101-resolution-1"}
    ```

5. Review that returned round on the enrolled workstation using the same
   `scope-review` command. The signed document binds the before state, requested
   status, resource version, scope, policy, reviewer, device and deadline.
6. Run `opaque --json scope execute --round-id ACTION_ROUND_ID
   --issuance-round-id ISSUANCE_ROUND_ID` once. Inspect the returned action record.

Rounds last at most five minutes. A stale, rejected or missing decision never
becomes approval. The approver sends one decision POST; uncertain acknowledgment
is resolved with a receipt read, never another submission. `scope-list` returns
at most one complete pending document per call; known round IDs remain directly
addressable. `scope-receipt` retrieves a retained signed decision and does not
claim execution occurred.

If the operator deliberately sets `exact_action = false`, the approved issuance
permits `opaque scope run --manifest action.json` within the same fixed limits.
The broker still reads the case version, checks identity and enrollment, charges
capacity and claims dispatch. This setting is an explicit policy choice, not a
model recommendation. Required model-evaluator contracts are not accepted by this
initial workflow.

## Inspect and stop work

`opaque --json scope show SCOPE_ID` returns the retained grant and charged budget.
`opaque --json scope outcome --scope-id SCOPE_ID --request-id REQUEST_ID` reads a
charged request's outcome. `opaque scope revoke SCOPE_ID` blocks subsequent
claims, including when the original reviewer is no longer eligible. An already
claimed provider request may still finish.

Attempts are never refunded. Replaying a consumed action cannot cause another
send. A crash turns unfinished reservations or claims into `unknown`; startup
cancels pending review rounds. Recovery uses retained outcomes, not automatic
provider retries. Local dispatch accounting alone cannot promise exactly-once
external effects.

`opaque --json scope snapshot` requires an auditor or admin delegation. It returns
bounded, tenant-owned historical projections and total counts; a partial window
cannot establish that an omitted action was never attempted. Enterprise consumers
use this authenticated RPC and do not open the broker database.

The first runtime supports one owner, one reviewer, one fixed connector and root
grants with no child delegation. The underlying library supports narrowing and
shared ancestor budgets, but those delegation routes are not exposed here. There
is no cross-broker budget, failover, quorum, automatic retry, or complete portable
audit export for this workflow. Keep existing credential custody supported;
new developer password-broker expansion remains deferred.
