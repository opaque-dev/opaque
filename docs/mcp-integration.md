# Connect an agent through MCP

Public core v0.6.0 includes `opaque-mcp`, a stdio adapter for built-in broker
operations, bounded tasks and separately qualified HTTPS MCP routes on macOS and
Linux. The daemon owns identity, policy, credentials, approvals and durable
outcomes. The adapter cannot enroll a route or approve its own calls.

```text
Agent --stdio--> opaque-mcp --authenticated Unix socket--> opaqued
                                                           |
                                                   signed HTTPS route
                                                           |
                                                      MCP provider
```

## Setup

[Install core](getting-started.md), initialize policy and start `opaqued`.
Keep the native review helper beside the daemon for workflows that require it.
Then register the adapter:

```sh
opaque connect codex
opaque ping
```

| Command | Client configuration |
| --- | --- |
| `opaque connect codex` | `~/.codex/config.toml` |
| `opaque connect claude` | `~/.claude.json` |
| `opaque connect cursor` | `~/.cursor/mcp.json` |
| `opaque connect auto` | Detected supported clients |

Registration preserves unrelated configuration and an existing entry's extra
arguments/environment. For another client, use its stdio configuration format;
for clients with an `mcpServers` object:

```json
{
  "mcpServers": {
    "opaque": {"command": "/absolute/path/to/opaque-mcp", "args": []}
  }
}
```

The adapter takes no arguments; `--stdio` is accepted as a compatibility no-op.
It needs an enrolled agent session when the broker enforces sessions. See
[agent integration](llm-harness.md) and [identity](identity.md). Registration does
not provision the custody split, sealed tenant, signed registry or reviewer
required for [third-party MCP qualification](mcp-qualified-tools.md).

### Verify discovery { #4-verify-discovery }

Refresh the client's tool list. On every `tools/list`, the adapter requests the
caller's catalog from the authenticated broker. Built-in discovery does not grant
execution permission. Signed `opaque_mcp_tool_*` routes appear only when current
discovery policy admits them.

From v0.6.0, invocation inspection/revocation tools appear only when
`gateway.availability` is `enabled` or `fixture_only`. Missing availability,
`disabled` or another value hides all `opaque_mcp_*` tools while leaving built-in
tools visible. Packages through v0.5.0 listed invocation tools unconditionally.

## Call behavior

Arguments are checked against published schemas before IPC. The adapter admits
up to eight concurrent calls; listing, ping and cancellation remain responsive.
Cancellation closes that call's IPC connection and stops waiting. It cannot undo
an already dispatched effect.

| Request | Adapter deadline |
| --- | --- |
| Broker status / receipt reads | 30 seconds |
| Ordinary operations / sandbox | 5 minutes |
| Bounded task execution | 61 minutes |

A timeout after dispatch reports uncertainty and never automatically replays work.
The daemon independently validates and authorizes calls, including direct IPC.
Keep the adapter classified as `agent`: executable classification comes from
trusted configuration and verified process identity, not tool arguments.

## Available tools

`Safe` is an operation classification, not a promise of no side effects or
non-sensitive metadata. Value-revealing `Reveal` operations are excluded.
Local profile tools are the exception to broker dispatch: they read metadata from
the adapter account and never resolve secret values.

### Enrolled third-party tools

| Tool | Broker method | Behavior |
| --- | --- | --- |
| `opaque_mcp_tool_<alias>` | `mcp_call` | Invoke a signed route after local native full review |
| `opaque_mcp_invocation_get` | `mcp_get` | Read owned control state; no replay or redisclosure |
| `opaque_mcp_invocation_revoke` | `mcp_revoke` | Block dispatch before its final fence; block new disclosure when current authority is removed |

The signed registry fixes endpoint, credential binding, schemas and disclosure.
Calls supply a single-use invocation UUID, expiry of 1–300 seconds and bounded
arguments; they cannot override those controls. Both adapter and broker refresh
or revalidate current authority.

V1 uses one finite schema and withholds raw results, but response hash/length
metadata can reveal predictable values. V2 separately pins upstream/admitted
schemas, omits raw hashes/sizes and may disclose only the signed selection of
bounded integers and enumerated statuses. Those are untrusted provider claims.
See the [qualification and disclosure contract](mcp-qualified-tools.md).

`accepted` means a valid MCP result was observed. It does not establish business
success or useful disclosure. Errors and unknown outcomes remain consumed;
read back effects before proposing a new invocation and approval. Whole-task
workstation approvals do not authorize these calls.

### Bounded Tasks

These tools use the [bounded task contract](bounded-work.md): full review of an
immutable manifest and at most one durable attempt per action. Secret publishing,
staging release and fixed inference support configured paired-workstation review;
SSH health tasks require local native full review.

| Tool | Daemon method | Description |
|------|-----------|-------------|
| `opaque_task_plan_ssh` | `task_plan_ssh` | Plan one fixed SSH host-health check on the tenant's trusted host/command profile |
| `opaque_task_plan_inference` | `task_plan_inference` | Plan three fixed public-source completions in the authenticated tenant |
| `opaque_task_plan` | `task_plan` | Plan a secret-publish or staging-release manifest for review |
| `opaque_task_run` | `task_run` | Request complete trusted review and at most one attempt per planned action |
| `opaque_task_get` | `task_get` | Inspect a task's exact scope, approval state, and receipt (maps to `opaque task show` in the CLI) |
| `opaque_task_list` | `task_list` | List a page of tasks owned by the authenticated caller |
| `opaque_task_revoke` | `task_revoke` | Block future provider actions on a task; already-dispatched work may still complete |
| `opaque_task_reconcile` | `task_reconcile` | Re-read correlated provider evidence without re-dispatching |

### GitHub

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_github_set_actions_secret` | `github.set_actions_secret` | Set a repo or environment Actions secret |
| `opaque_github_set_codespaces_secret` | `github.set_codespaces_secret` | Set a user or repo Codespaces secret |
| `opaque_github_set_dependabot_secret` | `github.set_dependabot_secret` | Set a Dependabot repo secret |
| `opaque_github_set_org_secret` | `github.set_org_secret` | Set an org-level Actions secret |
| `opaque_github_list_secrets` | `github.list_secrets` | List secret names (no values) |
| `opaque_github_delete_secret` | `github.delete_secret` | Delete a secret |

### GitLab

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_gitlab_set_ci_variable` | `gitlab.set_ci_variable` | Set a project CI/CD variable (write-only) |

### 1Password

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_onepassword_list_vaults` | `onepassword.list_vaults` | List vault names and descriptions |
| `opaque_onepassword_list_items` | `onepassword.list_items` | List item titles in a vault |

### Bitwarden

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_bitwarden_list_projects` | `bitwarden.list_projects` | List Bitwarden projects |
| `opaque_bitwarden_list_secrets` | `bitwarden.list_secrets` | List secret names in a project |

### Sandbox

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_sandbox_exec` | `sandbox.exec` | Run a command in the sandbox with profile-scoped secrets injected |
| `opaque_sandbox_list_profiles` | *(client-side)* | List available `~/.opaque/profiles/*.toml` names; reads local files directly, never calls the daemon |

`sandbox.exec` is `SENSITIVE_OUTPUT` and needs an explicit policy rule
for `agent` clients. The model receives execution status and stdout/stderr
**byte lengths**, not their content. These metadata can still reveal information
about a predictable command; withholding content is not a general non-disclosure
guarantee. `opaque exec` also withholds output content. A command receiving secrets can
still disclose them through permitted egress; see [agent integration](llm-harness.md).

### Utility

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_secrets_status` | *(client-side)* | List a profile's secret ref names and schemes (never resolves values); reads the profile TOML directly, never calls the daemon |

### Not Exposed

These operations are intentionally excluded from MCP entirely:

- `onepassword.read_field`: `REVEAL` (returns plaintext secret values)
- `bitwarden.read_secret`: `REVEAL` (returns plaintext secret values)
- `test.noop`: test-only, not useful for agents

## Troubleshooting

| Symptom | Next check |
| --- | --- |
| Tool absent | Adapter path/configuration, refreshed tool list, signed route and discovery policy |
| Connection failed | `opaque ping`, then `opaque doctor` for socket/permissions |
| Policy denied | `opaque policy show`; confirm agent classification and applicable identity/target rules |
| Approval prompt absent | Required native helper/GUI or enrolled workstation for the supported task family |

A schema rejection returns JSON-RPC `-32602` with a field pointer and constraint.
For example, the documented `opaque_secrets_status` call with `{}` reports
`missing required field "/profile"`. At most three failures are reported; messages
do not quote supplied values. Correct the arguments before retrying. No broker
request was sent for this adapter validation failure.

```sh
opaque policy simulate --operation github.set_actions_secret --client-type agent
opaque audit tail --limit 20
```

The adapter logs to stderr; stdout is reserved for MCP. Broker audit and durable
receipts distinguish denied requests from dispatched or uncertain work.
