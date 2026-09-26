# Keep an AX action attached to its retained outcome

**Availability: unreleased external example.** This helper maps a logical Google
AX task action to an Opaque request ID, then verifies and reads its historical
scope evidence. Unknown or missing outcomes stay on hold. The helper never
approves an action, sends a provider request, or authorizes a retry.

## Run against AX's local task runner

Use macOS or Linux, Python 3.12 or newer, the repository's Rust toolchain, and
Go 1.27.1 or newer. From the Opaque repository root:

```sh
python3 -m venv /tmp/opaque-ax-venv
/tmp/opaque-ax-venv/bin/pip install -r examples/ax-scope/requirements.txt
git clone https://github.com/google/ax.git /tmp/opaque-ax-source
git -C /tmp/opaque-ax-source checkout --detach f009cc81c9a571073bc1dd58cd2ed934bf2d5b1c
/tmp/opaque-ax-venv/bin/python -B examples/ax-scope/check_runtime.py \
  --ax-source /tmp/opaque-ax-source \
  --output /tmp/opaque-ax-run
```

Choose unused paths. The output directory must be new, absolute, and outside Git.
It contains generated keys and runtime records; retain it privately. Builds need
access to dependency registries. The execution makes no model or provider API
calls and needs no enterprise source or credentials.

The checker builds the pinned official `ax-task-runner` source and launches a
synthetic Task with an empty local workspace. At link time it sets AX's
`internal/workspace.AXDir` test variable to the private output directory, so the
runner's workspace markers stay there instead of `/ax`. This qualifies a local
runner binary with that override, not the default container image or Kubernetes
substrate.

The pinned runner listens on all host interfaces. Use an isolated development
host; the fixture enables no debug services and supplies only synthetic task
metadata, but that metadata includes local workspace and executable paths.

The runner starts the actual helper process. That process reads AX's YAML
metadata endpoint, persists one logical run UUID, and supplies 16 derived request
IDs to the public [scope recovery example](../../docs/scope-recovery.md). The
example performs concurrent reservations, revokes the scope, kills its producer
with `SIGKILL`, and reopens the real ledger. The helper invokes the public
`opaque-evidence` binary for each inspection.

Expected checks:

- Four charged attempts, including three retained `unknown` outcomes and one
  `api_accepted`; twelve proposed requests have no charged action in this export.
- Every inspection records historical revocation and `retry_authorized: false`.
- Changed effect content and altered export bytes are rejected.
- Historical synthetic review signatures verify through the public CLI.
- Stopping and restarting AX's runner reuses the same run and request IDs, reads
  identical action evidence, and does not invoke the producer again.

Read `report.json` for the individual outcomes and limitations, and
`qualification.json` for source identity, restart checks, and file hashes. A dirty
Opaque checkout is identified as such. If the example started but its result was
not retained, recovery stops; it does not repeat the experiment automatically.

The reviewer, requester, policy and provider effects in this run are synthetic.
No native human ceremony, authenticated broker RPC, live provider, cross-broker
budget, or independently administered custody is exercised. The checkpoint pin
comes from this same synthetic run. This is author-run integration evidence,
not an independent evaluation or an AX endorsement.

## Bind a proposed action in an enrolled deployment

First complete the broker, requester and trusted human workstation prerequisites
in the [scoped support workflow](../../docs/scoped-authority.md). Obtain a
human-approved scope and its issuance round. Persist one UUID per logical run and
one action key per intended change; reuse both after AX restarts or retries.
Do not derive a new run UUID from a new container or mutable AX status.

Inside the AX task, using your deployment's actual values:

```sh
python3 examples/ax-scope/adapter.py bind \
  --deployment-id "$AX_DEPLOYMENT_ID" --run-id "$LOGICAL_RUN_UUID" \
  --action-key "resolve-case-101" --requester-id "$OPAQUE_REQUESTER_ID" \
  --scope-id "$SCOPE_ID" --issuance-round-id "$ISSUANCE_ROUND_ID" \
  --resource case-101 --status resolved \
  --tenant-id "$TENANT_ID" --broker-id "$BROKER_ID" --generation "$GENERATION" \
  --output /private/new-action-context
opaque --json scope prepare --manifest /private/new-action-context/action.json
```

`bind` reads `AX_METADATA_URL` supplied by the runner. For offline mapping, use
`--task-file task.yaml`. It retains only selected identity fields; it does not
copy environment variables, command text or mutable Task status. The generated
manifest is a proposal. Preparation and execution still go through Opaque's
authenticated broker and configured review policy.

On the enrolled human workstation, review the exact returned action round using
`opaque-approver scope-review --state-dir WORKSTATION_STATE --round-id ACTION_ROUND_ID`.
After that approval, the authenticated requester can call
`opaque --json scope execute --round-id ACTION_ROUND_ID --issuance-round-id ISSUANCE_ROUND_ID`
once. Use `opaque scope outcome` to resolve uncertainty. These deployment steps
are not exercised by the synthetic checker above.

AX metadata is an untrusted correlation label. Deployment, owner, requester and
scope identifiers are caller inputs, not identity enrollment. Only the broker's
authenticated request and signed authority establish permission. Changing the
resource or desired status under the same logical action preserves its request
ID; it does not create another attempt identity.

## Inspect a retained checkpoint

Export and retain the complete ledger following the
[scope evidence guide](../../docs/scope-evidence.md). Enroll the producer key and
retain the expected checkpoint digest through your relying party's trust process.
Then run:

```sh
python3 examples/ax-scope/adapter.py inspect \
  --context /private/new-action-context/correlation.json \
  --enrollment /private/evidence/producer.json \
  --checkpoint /private/evidence/checkpoint.json \
  --export /private/evidence/scope.json \
  --checkpoint-pin "$RETAINED_CHECKPOINT_SHA256" \
  --evidence-binary target/debug/opaque-evidence
```

The helper verifies a bounded private copy of the export, then reads those exact
bytes. It checks the owner, scope, requester, request ID and effect content before
reporting a retained action.

| Retained state | Reported disposition |
| --- | --- |
| `unknown`, `reserved`, `dispatch_claimed` | Hold for reconciliation |
| No matching action | `not_observed`; hold for reconciliation |
| `api_accepted` | Inspect provider completion; API acceptance is not completion |
| `rejected` | Consumed rejection; no refund or retry authorization |
| Invalid signature, reference, owner or effect binding | Error and hold |

A single historical checkpoint establishes neither current authority nor complete
history or present freshness. A missing action does not prove it never happened.
`historical_revocation` refers to the selected checkpoint; AX cancellation or
suspension is not interpreted as authority revocation. Review signatures require
the separate `verify-scope-reviews` command documented in the evidence guide.

Run the focused mapping tests with
`python3 -B -m unittest discover -s examples/ax-scope -v`.
