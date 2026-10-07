# Route agent work through Opaque

Connect an agent through MCP or the CLI, then let the broker enforce policy,
required review and result disclosure. These interfaces are available in core
v0.6.0. Provider credentials stay with the broker; agent-readable credentials
outside that boundary remain usable independently.

## Connect and delegate

For an MCP client, register the installed adapter and confirm its tool list:

```sh
opaque connect codex
```

`opaque connect claude` and `opaque connect cursor` configure those clients.
Follow [MCP setup](mcp-integration.md#setup) for paths, sessions and discovery.
CLI commands reach the same broker through its Unix socket.

To launch an agent with a broker-managed session:

```sh
opaque agent run -- codex
opaque agent list
opaque agent end <session-id>
```

With OIDC configured, the wrapper uses the verified human's delegation. Configure
`enforce_agent_sessions = true` to reject non-session agent calls. A reduced child
environment removes most inherited variables; it does not isolate files,
`SSH_AUTH_SOCK`, another credential path or co-resident processes.

Use `--pass-env KEY` for selected variables; `--inherit-env` passes the full parent
environment. The wrapper revokes its session on ordinary exit, launch failure or
handled interruption. Failed or unacknowledged revocation exits nonzero. After an
abrupt kill or connection loss, inspect and end remaining sessions explicitly.
Ctrl-C reaches the interactive agent; a signal sent directly to the wrapper
cancels its process group, with five seconds for cleanup before forced termination.

See [identity and delegation](identity.md) and [broker custody](deployment.md).

## Choose the execution contract

| Work | Interface | Limit |
| --- | --- | --- |
| One registered operation | `opaque execute` or a built-in MCP tool | Prepared action and policy-specific approval; a first-use lease can cover repeated matching operations |
| One immutable task | `opaque task plan`, `run`, `show` | Full-manifest review and one durable attempt per action; action families cannot be mixed |
| A qualified third-party tool | Signed `opaque_mcp_tool_*` route | Pinned schema, bounded arguments, local full review and a separate durable attempt |
| Finite delegated budget | `opaque scope` | Separate scope store, approval and executor; see [scoped authority](scoped-authority.md) |

Changing reviewed work requires the applicable new review. Revocation blocks future
dispatch at its final fence; it cannot recall an external effect. Inspect unknown
outcomes before proposing replacement work. See [tasks](bounded-work.md) and
[MCP qualification](mcp-qualified-tools.md).

## Credential inputs and outputs

Use configured references such as `keychain:opaque/github-pat`,
`vault:secret/data/app#token` or `bitwarden:production/API_KEY`. Keep names and
reference mappings in profiles; do not put plaintext in agent prompts or arguments.
`env:` reads the broker's environment, not the agent's.

Both `opaque exec` and `opaque_sandbox_exec` withhold stdout/stderr content and
return status and byte lengths. A child still receives its profile's secrets;
permitted egress and predictable output lengths can disclose information. Review
the command and [sandbox prerequisites](deployment.md#sandbox-prerequisites).
`REVEAL` operations are blocked for every client.

Approval factors have operation-specific support. Native review, paired-workstation
review and second-device factors are not interchangeable; a notification or catalog
entry grants no authority. Follow the [approval configuration](policy.md#approval-configuration)
for the selected path.
