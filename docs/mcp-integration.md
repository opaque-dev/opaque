# MCP Integration

Opaque ships a stdio MCP server (`opaque-mcp`) that exposes broker operations to
MCP-aware assistants. It includes built-in tools and can discover separately
enrolled third-party tools through the broker's signed HTTPS MCP gateway.

## Architecture

```
MCP client  --MCP/stdio-->  opaque-mcp  --Unix socket-->  opaqued
                                                        |
                                        signed route --HTTPS--> MCP provider
```

`opaque-mcp` translates MCP JSON-RPC messages into Opaque IPC requests. The daemon
authenticates the caller and owns policy, approval, credentials and durable outcome
state. The adapter cannot enroll a route, select an upstream credential or authorize
an action. Local profile inspection tools are the documented exception to daemon
dispatch; they read metadata from the adapter's own account.

The adapter validates tool arguments against its published schemas and admits up to eight concurrent tool calls. Ping, tool listing, and cancellation remain responsive while calls wait on the broker. Cancellation stops waiting and closes that call's IPC connection; it does not promise to undo work already dispatched. Broker status and task receipt reads have a 30-second deadline, ordinary operations and sandbox execution five minutes, and bounded task execution 61 minutes. A timeout after dispatch reports an uncertain outcome and never triggers an automatic replay.

## Setup

### 1. Build

```bash
cargo build --locked --release -p opaqued -p opaque -p opaque-mcp -p opaque-approve-helper
```

Binaries:

- `./target/release/opaqued` (daemon)
- `./target/release/opaque` (CLI)
- `./target/release/opaque-mcp` (MCP server)
- `./target/release/opaque-approve-helper` (native full-review helper; keep beside the daemon)

### 2. Configure the MCP client

`opaque connect <tool>` writes the entry and preserves everything else in the
client's file (other servers, unrelated keys, and the `env` or extra `args` of
an existing `opaque` entry). `opaque connect auto` registers with every tool it
detects.

| Command | File written |
| --- | --- |
| `opaque connect claude` | `~/.claude.json` (Claude Code user scope) |
| `opaque connect cursor` | `~/.cursor/mcp.json` |
| `opaque connect codex` | `~/.codex/config.toml` |

```sh
opaque connect codex
cat ~/.codex/config.toml
```

```text
✔  Registered opaque MCP server with Codex
```

```toml
[mcp_servers]

[mcp_servers.opaque]
command = "/opt/homebrew/bin/opaque-mcp"
args = []
```

`opaque-mcp` takes no arguments; it always serves MCP over stdio. It accepts
`--stdio` as a no-op for clients that pass a transport flag (releases up to
0.4.0 wrote that argument, and the server of that release rejected it).

For any other client that uses an `mcpServers` JSON object, configure a stdio
server with the absolute path to `opaque-mcp`:

```json
{
  "mcpServers": {
    "opaque": {
      "command": "/path/to/opaque-mcp",
      "args": []
    }
  }
}
```

Place this entry in the configuration location supported by your client. The
adapter communicates over stdin/stdout and connects through the configured Opaque
Unix socket. It must have the enrolled agent session when the broker enforces
sessions; see [identity](identity.md) and [getting started](getting-started.md).

### 3. Start the daemon

```bash
opaqued
```

For an already configured local installation, the service manager is another option:

```bash
opaque service install
```

These commands do not provision the separate broker custody, sealed tenant,
delegated identity, signed registry or native reviewer required by the HTTPS MCP
gateway. Follow [qualifying one MCP tool](mcp-qualified-tools.md) before enabling it.

### 4. Verify discovery

Use the client's tool list to confirm the built-in `opaque_*` tools are present.
Discovery alone does not grant execution authority. Signed `opaque_mcp_tool_*`
routes appear only when returned by the authenticated broker and allowed by its
current discovery policy. An unavailable gateway can leave built-in tools visible
while omitting the enrolled third-party routes.

## Available Tools

Signed third-party tool routes are covered in [qualifying one MCP tool](mcp-qualified-tools.md).
That guide explains separate upstream/admitted schemas, offline catalog qualification,
bounded typed result disclosure, current authority checks and the supported transport.

The built-in catalog includes selected operations classified `SAFE` and sandbox
execution (`SENSITIVE_OUTPUT`) with output content withheld; see
[Sandbox](#sandbox). `SAFE` is a broker classification, not a promise that an
operation has no side effects or that every provider field is non-sensitive.
Operations classified `REVEAL`, which return plaintext secret values, are excluded.

### Enrolled third-party MCP tools

| Tool | Daemon method | Description |
|------|-----------|-------------|
| `opaque_mcp_tool_<alias>` | `mcp_call` | Invoke one signed route under its admitted input and output contract after native full review |
| `opaque_mcp_invocation_get` | `mcp_get` | Read owned invocation control state; never replay work or redisclose prior typed output |
| `opaque_mcp_invocation_revoke` | `mcp_revoke` | Block dispatch if revocation precedes its final fence; withhold newly observed output when authority is removed before disclosure |

The broker chooses the endpoint, tool, credential binding and schemas from its
signed registry. Dynamic tool inputs include a single-use invocation UUID, an expiry
of 1–300 seconds and bounded arguments; they cannot override routing, approval or
projection fields.
The adapter refreshes the broker catalog before calling a dynamic route, and the
broker independently revalidates the call and current authority.

Registry v1 pins the same finite schema used for admission and withholds raw results;
its authorized response hash/length metadata can reveal predictable values. V2 pins
the advertised schema separately, validates each call against both schemas and
omits raw response hashes/sizes. A v2 route may disclose bounded integer IDs and
enumerated statuses selected by its signed projection. The returned values are
untrusted provider claims, not separately signed effect evidence. See the
[full qualification and disclosure contract](mcp-qualified-tools.md).

Receipt `accepted` means a valid MCP result was observed. A call may be charged
without an effect, or a provider may return an error after an effect. Check dispatch
state and disclosure status separately; a successful protocol response does not
establish useful output or business success. Unknown outcomes are never retried or
refunded automatically. A new invocation needs new approval and appropriate effect
readback. Remote whole-task approval receipts do not authorize these MCP calls.

### Bounded Tasks

An immutable manifest defines secret publishing, one release dispatch, a fixed host
check or fixed public-source inference. A complete review permits at most one
attempt per action while current authority remains valid. See
[bounded agent work](bounded-work.md) for the lifecycle and receipt semantics.

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
guarantee. The CLI path
(`opaque exec`) differs: it prints raw output to the terminal; treat that
as sensitive, per [LLM harness](llm-harness.md).

### Utility

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_secrets_status` | *(client-side)* | List a profile's secret ref names and schemes (never resolves values); reads the profile TOML directly, never calls the daemon |

### Not Exposed

These operations are intentionally excluded from MCP entirely:

- `onepassword.read_field`: `REVEAL` (returns plaintext secret values)
- `bitwarden.read_secret`: `REVEAL` (returns plaintext secret values)
- `test.noop`: test-only, not useful for agents

## Safety Model

1. **Catalog admission**: Built-in tools have a fixed allowlist. Dynamic tools must match the current authenticated broker catalog and signed registry. Unknown tools and malformed arguments fail before upstream dispatch; the daemon remains the authority even when its IPC is called directly.

2. **Daemon enforcement**: Ordinary operations, bounded tasks, sandbox execution and third-party MCP use their respective broker handlers and authority checks. They do not all call one execution method. The two local profile tools read metadata directly and never reach the daemon.

3. **Explicit disclosure**: `REVEAL` operations are excluded and sandbox content is withheld. Third-party v2 disclosure is restricted to the exact signed typed projection under current authority; arbitrary provider text is withheld. Names, statuses, lengths and identifiers can still be sensitive, so choose policies and projections for the receiving principal.

4. **Authenticated classification**: The daemon derives client type from verified process identity and trusted client configuration, not caller-supplied fields. Keep `opaque-mcp` classified as an agent; do not enroll its executable as a human client. Human-only policy rules then do not authorize its requests.

5. **Approval scope**: Secret-publish, staging-release and fixed inference tasks permit complete local or paired-workstation review as configured. SSH health tasks and third-party MCP currently require native local full review. Notification delivery, enrollment, catalog qualification and historical receipts cannot substitute for an applicable current approval.

## Troubleshooting

### "Tool not found"

- Verify `opaque-mcp` is in your client's MCP config and the path is correct.
- Refresh the tool list or restart the client after changing its configuration.
- For a dynamic route, inspect the signed registry and discovery policy at the broker. Its absence is not evidence that the upstream provider removed the tool.

### "Connection failed"

- Check that `opaqued` is running: `opaque ping`
- Inspect `opaque doctor` for the configured socket and permission checks.

### "Policy denied"

- The daemon denied the operation. Check your policy:
  ```bash
  opaque policy show
  opaque policy simulate --operation github.set_actions_secret --client-type agent
  ```
- Ensure the intended rules include `client_types = ["agent"]` and the broker has classified the adapter correctly. For third-party tools, check the signed route and required tenant/session/delegation configuration too.

### "Approval required" but no prompt appears

- The MCP adapter cannot approve or show its own trusted review prompt.
- A native local policy requires the supported review/authentication helper on the broker host (macOS LocalAuthentication or Linux desktop review/polkit).
- A bounded task using `paired_workstation` requires its separately enrolled trusted reviewer to open the full review; see [remote reviews](remote-approvals.md). That factor is not supported for third-party MCP invocations.

### Viewing MCP logs

`opaque-mcp` logs to stderr (stdout is reserved for the MCP transport). To capture logs:

```bash
RUST_LOG=debug opaque-mcp 2>/tmp/opaque-mcp.log
```

Or check the daemon audit log:

```bash
opaque audit tail --limit 20
```
