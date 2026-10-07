# Bounded agent work

Beyond one-shot operations (`opaque execute`, `opaque github set-secret`),
Opaque can bind an agent's work to a **task**: an immutable manifest reviewed as a
whole, with at most one attempt per action and an inspectable receipt.
This task path is available from v0.6.0 on macOS and Linux; factor and provider
qualification remain specific to the chosen family.

A content hash pins the planned manifest. Planning does not grant execution
authority: approval, current policy, requester identity, expiry and revocation
must still permit each dispatch. A changed manifest requires a new task and review.

---

## Choose an operation family

| Family | What it does | Action type | Enforcement |
|---|---|---|---|
| Repository & release work | Publish a fixed set of GitHub secrets, or dispatch one reviewed staging-release workflow | `PublishSecret`, `StagingRelease` | Pinned repo/workflow/branch/image digest; atomic single-use slot; provider reconciliation |
| Application evidence | Run three fixed public-source completions against the tenant's configured model profile | `Inference` | Tenant binding, fixed source/prompt and model/profile hashes, bounded requested output, current-authority recheck before source disclosure |
| Host operations | Run one fixed command against one host over a Vault-signed, short-lived SSH certificate | `SshHealth` | Exact host key + principal + command binding, session deadline, host-side revocation check |

Every family uses `opaque_core::task::TaskManifest`, with `schema_version`, `title`,
`expires_in_secs`, typed `actions` and daemon-bound provider origin fields. Schema
version 1 permits secret publishing, version 2 exactly one staging release, version
3 three fixed inference requests, and version 4 one fixed SSH health check. Action
families cannot be mixed. The overall maximum is 32 actions and one hour; a selected
family can impose tighter action and lifetime limits.

## Planning a task

```sh
# Resolve exact repositories/refs and pin a manifest for review
opaque task plan --manifest ./release.json

# Plan a fixed host health check via the tenant's Vault SSH signer
opaque task plan-ssh --title "Service health on approved host" --expires-in-secs 300

# Plan three fixed public-source completions in the authenticated tenant
opaque task plan-inference --title "Tenant public data inference" --expires-in-secs 600
```

Planning resolves the selected family's repository/workflow or trusted profile
bindings and pins them for review. Execution revalidates the applicable repository,
workflow, source/profile and authority constraints before dispatch; planning is not
a promise that the external resource will remain unchanged.

## Reviewing and approving

A planned task is reviewed as a whole. The task and every action must require the
same single complete-review factor: `local_bio` or `paired_workstation`. Unsupported
or mixed factors fail closed. Local review uses the broker host's native helper.
The current workstation protocol supports secret-publish, staging-release and fixed
inference manifests. SSH health manifests require local native review; selecting a
paired-workstation policy does not add that operation to the remote protocol.

Set `factors = ["paired_workstation"]` in the applicable approval policies to use
the [trusted workstation reviewer](https://github.com/opaque-dev/opaque/blob/main/crates/opaque-approver/README.md).
It fetches the complete broker-generated review over pinned TLS, verifies its hash
and deadline, displays it for native review/authentication, rechecks the unchanged
round and signs the exact decision. Run its custody and application in a trusted
account/device the agent cannot control. A separate directory under the same
agent-controlled account does not establish that boundary.

The broker requires current reviewer eligibility when accepting and using the
decision, including the enrolled device, principal, role and authority binding.
Opening a notification or receiving a delivery acknowledgment grants no authority.
A reviewer decision receipt proves the signed decision, not a biometric sensor
event or completion of the provider operation. An ambiguous decision acknowledgment
uses a read-only receipt lookup; the reviewer does not resend the decision or work.

```sh
opaque task run <task-id>       # request approval, then execute once
opaque task show <task-id>      # exact scope, charged slots, provider outcomes
opaque task reconcile <task-id> # re-read correlated evidence without re-dispatching
opaque task revoke <task-id>    # block future writes on this task
opaque task list                # tasks owned by the authenticated caller
```

## Lifecycle

```
Planned --run--> Running --> Completed
                         \--> Partial   (inspect each slot's state)
   \--revoke------------------> Revoked
   \--expire (deadline passes)-> Expired
```

A slot charges **atomically before dispatch**. A charged slot can still be denied
by a later fence before any provider effect; charge is consumption, not proof of a
write. Errors, restart and ambiguous responses never refund the slot. A closed run
cannot resume pending slots. Reserved slots found after interruption become unknown.

`Completed` means every slot reached its action-specific `api_accepted` state.
`Partial` can include unattempted, rejected or unknown slots; it does not mean every
action was dispatched or every result is ambiguous. Inspect each slot and its
action-specific receipt. GitHub API acceptance does not establish workflow success,
deployment or service health. `reconcile` reads correlated provider evidence without
dispatching again or restoring allowance. Revocation ordered before the final
dispatch fence blocks that dispatch; it cannot recall an already authorized effect.

## Relationship to third-party MCP

The stdio MCP adapter exposes task planning and execution through `opaque_task_*`
tools. Separately enrolled `opaque_mcp_tool_*` routes use their own signed registry,
invocation UUID, approval and durable single-attempt ledger. They are not a new
`TaskManifest` action family, and these schema version numbers are unrelated to MCP
registry versions.

Third-party MCP currently requires local native full review. A paired-workstation
task receipt cannot authorize it. Registry v2 separates the upstream schema pin
from admitted input and can disclose bounded integer/status fields selected by a
signed projection; the values are not separately signed evidence. It does not permit
arbitrary output passthrough. See [MCP integration](mcp-integration.md)
and [qualifying one tool](mcp-qualified-tools.md) for input, disclosure and unknown
effect semantics.

## Maturity

Repository/release manifests, durable consumption, native/paired-workstation gates
and provider reconciliation have implemented runtime paths and isolated tests.
Automated mock-provider and disposable fixtures validate mechanisms; they do not
qualify a live repository's credentials, workflow protections, artifact, reviewer
installation or business outcome. Qualify those controls for the selected deployment
before treating a successful API response as evidence that the task achieved its goal.

Host operations (`SshHealth`) implement pinned certificate/host/profile checks and
authenticated host evidence for one fixed health contract. Unit tests cover those
bindings; the opt-in live Vault/SSH test needs separately provisioned disposable
services. `opaque task plan-ssh` does not provision a host, configure its guard,
install Vault or establish a successful native review ceremony.

Application-evidence (`Inference`) supports a broker-captured sample of public
GitHub workflow results, or the legacy explicit synthetic source. The configured
repository, workflow and branch select up to three typed observations; the exact
snapshot and three prompts are bound to the reviewed manifest. See
[GitHub CI inference](github-ci-inference.md) for configuration and evidence limits.
Private repositories, arbitrary queries, repository text and CI logs are not
accepted by this source adapter.

[Signed evidence checkpoints](evidence-checkpoints.md) let another recipient verify
the producer and exact exported audit range without the audit HMAC key. They do not
prove unobserved provider effects, restore task/MCP authority, recover lost revocation
history or refund consumed unknown attempts. Retained high-water references and
fenced authority recovery remain separate responsibilities.

## Related docs

- [Identity](identity.md): the delegation token an agent session presents when planning a task on a human's behalf
- [Trusted workstation approvals](https://github.com/opaque-dev/opaque/blob/main/crates/opaque-approver/README.md): installation, enrollment and the `paired_workstation` full-manifest review flow
- [HashiCorp Vault](vault.md): the SSH certificate signer for `SshHealth` actions
- [Deployment patterns](enterprise-architecture.md): broker custody and multi-broker topology
