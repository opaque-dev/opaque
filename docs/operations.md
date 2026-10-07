# Operation contracts

Call a registered operation through the CLI or a built-in MCP tool. The broker
checks policy, required approval and the captured action before provider dispatch.
For example, with a configured test repository and credential references:

```sh
opaque github set-secret --repo myorg/test-repo \
  --secret-name TEST_TOKEN --value-ref keychain:opaque/test-token
```

Generic operations use local Unix-socket transport. Tasks, scoped authority and
qualified third-party MCP use [separate request contracts](architecture.md#what-approval-authorizes).
Check the selected broker's [operation catalog](web-dashboard.md): registered,
enabled and policy-permitted are different states. This reference describes the
current source; provider guides state implementation availability and qualification
requirements.

## Prepared action contract

The daemon parses each generic operation once before policy, human approval or
credential resolution. Policy, review, leases and audit use the same captured
action that execution consumes. Targets include effective scope, options and
configured destination. Credential selectors are resolved once during preparation;
secret values are resolved only after authorization.

For the low-level `execute` RPC, `target` is an optional consistency assertion.
Omit redundant fields or supply values that exactly match the operation's
parameters and defaults. Contradictory, unknown or malformed target assertions
fail before approval. Caller-supplied `secret_ref_names` are ignored: the daemon
derives effective credential and accessed-resource references. Restrictive
`secret_names` rules must allow both. Unknown provider parameters and malformed
optional values are rejected instead of silently selecting defaults.

Review includes every target and reference without truncation. Commands use a
JSON argv array so empty arguments, spaces and control characters remain distinct.
Generic actions whose review fields exceed 32 KiB are rejected. Local native
approval first opens the complete review in the installed trusted helper, then
requests authentication bound to that review's fingerprint.

Sandbox execution captures a validated profile once and binds its digest, including
literal environment configuration, without placing those literal values in audit
metadata. Changing a profile file after preparation does not change that action.
Secret references still select their current values; this is not secret-version
or executable-binary attestation.

Bounded task manifests use their dedicated task transport. Their parent and
internal task-operation names cannot be invoked through generic `execute`.
Upgrading requires a daemon restart, which clears old in-memory generic leases;
persistent task allowances and audit history retain their existing semantics.

## Safety classes

| Class | Contract |
| --- | --- |
| `SAFE` | Use credentials internally and omit their values from the operation result; still requires policy and applicable approval |
| `SENSITIVE_OUTPUT` | Potentially sensitive output; explicit policy and out-of-band approval. Withholding is operation-specific |
| `REVEAL` | Plaintext-secret operation; broker hard-blocks every client |

A class name does not prove harmless metadata or absence of side effects.
Response sanitization is enforced, but pattern scrubbing is not a general
confidentiality guarantee. In particular, STS AssumeRole is sensitive output,
while sandbox stdout/stderr are withheld by that operation's contract.

## Secret references

Base references are `env:NAME`, `keychain:service/account` and
`profile:<name>:<key>`. Provider references include:

| Provider | Reference | Configuration |
| --- | --- | --- |
| 1Password | `onepassword:<vault>/<item>/<field>` | Configured Connect or trusted `op` backend |
| Bitwarden | `bitwarden:<project>/<key>` or `bitwarden:<secret-id>` | [Secrets Manager](bitwarden.md) |
| Vault | `vault:<path>#<field>` | [Vault resolver and leases](vault.md) |
| AWS | `aws:<secret-name>` or `aws:ssm:<parameter>` | [Region and signing credentials](aws.md) |
| Google Cloud | `gcp:<project-number>/<secret>[/version]` | [Secret Manager](gcp.md) |
| Azure | `azure:<vault-name>/<secret-name>[/version]` | [Key Vault](azure.md) |

References select values for an authorized consumer; they do not make a reveal
operation available. `env:` reads the broker environment.

## Local operations

### `test.noop` (`SAFE`)

No inputs; result contract is `{ "status": "ok" }`. Use it to test local policy
and approval without a provider effect.

### `sandbox.exec` (`SENSITIVE_OUTPUT`)

```sh
opaque exec --profile dev -- command argument
```

Inputs are `profile` and a JSON argv `command` array. The prepared profile/digest
binds its effective configuration. Results contain `exit_code` (i32),
`duration_ms`, `stdout_length`, `stderr_length` (u64) and `truncated` (bool).
CLI and MCP return lengths/status, never captured stdout/stderr content.
The child still receives configured secrets; permitted egress and metadata can
disclose them. See [sandbox prerequisites](deployment.md#sandbox-prerequisites).

## Repository operations

GitHub/GitLab write results omit secret values and ciphertext. GitHub writes return
`status` (`created`/`updated`), resource identifiers and secret name; these are API
outcomes, not verification of a stored value or deployment success.

| Operation (`SAFE`) | Required inputs | Optional inputs / scope |
| --- | --- | --- |
| `github.set_actions_secret` | `repo`, `secret_name`, `value_ref` | `environment` selects environment scope; `github_token_ref` |
| `github.set_codespaces_secret` | `secret_name`, `value_ref` | `repo` selects repository scope, otherwise user; `selected_repository_ids` for user scope; `github_token_ref` |
| `github.set_dependabot_secret` | `repo`, `secret_name`, `value_ref` | `github_token_ref` |
| `github.set_org_secret` | `org`, `secret_name`, `value_ref` | `visibility` defaults to `private`; `selected_repository_ids` required only for `selected`; `github_token_ref` |
| `gitlab.set_ci_variable` | `project`, `key`, `value_ref` | `environment_scope`, `protected`, `masked`, `raw`, `variable_type`, `gitlab_token_ref` |

GitHub token references default to `keychain:opaque/github-pat`; GitLab defaults
to `keychain:opaque/gitlab-pat`. Codespaces results distinguish user/repository
scope. GitLab updates match the exact environment scope (default `*`); omitted
`variable_type` preserves an existing value or uses the creation default. Its
result includes applicable scope/options and never the variable value.

Trusted broker environment can select `OPAQUE_GITHUB_API_URL` or
`OPAQUE_GITLAB_API_URL` for alternate API hosts. Those destinations participate in
prepared authorization. Read [GitHub inventory](github-secret-inventory.md) for
list/delete operations, and [bounded work](bounded-work.md) for staging releases.

## Credential-store metadata

| Operation (`SAFE`) | Input | Result contract |
| --- | --- | --- |
| `onepassword.list_vaults` | None | `vaults`: names/descriptions |
| `onepassword.list_items` | `vault` | Vault and item titles/categories |
| `bitwarden.list_projects` | None | `projects`: names/IDs |
| `bitwarden.list_secrets` | Optional `project` filter | `secrets`: keys/IDs/projects |

Metadata can be sensitive; admitting a list operation is still a policy decision.
`onepassword.read_field` and `bitwarden.read_secret` are registered `REVEAL`
operations and are blocked for human and agent clients, not interactive escape
hatches.

## Cloud operations

### AWS

The current client uses regional AWS Signature V4 and real STS, Secrets Manager
and SSM protocols. Older mock-only builds cannot contact AWS. Configure explicit
Region/credential references and independently qualify the target account; see
[AWS setup and protocol evidence](aws.md).

| Operation | Class | Input |
| --- | --- | --- |
| `aws.get_caller_identity` | `SAFE` | None; returns account, ARN and user ID |
| `aws.assume_role` | `SENSITIVE_OUTPUT` | `role_arn`, optional `session_name`; temporary credential fields |
| `aws.list_secrets` | `SAFE` | None; secret names |
| `aws.create_secret` | `SAFE` | `name`, `value`, optional `description` |
| `aws.put_secret_value` | `SAFE` | `secret_id`, `value` |
| `aws.delete_secret` | `SAFE` | `secret_id`; schedules recovery-capable deletion |
| `aws.put_parameter` | `SAFE` | `name`, `value`, optional `type`, `overwrite` |
| `aws.get_parameters_by_path` | `SAFE` | `path`, optional `with_decryption`; handler returns metadata only |
| `aws.delete_parameter` | `SAFE` | `name` |
| `aws.get_secret_value`, `aws.get_parameter` | `REVEAL` | Blocked for all clients |

Collection bounds fail explicitly rather than returning incomplete lists as
complete. Lost/invalid write acknowledgments can mean an unknown effect. The
client does not automatically retry; read back the resource before new authority.
Loopback fixtures use fixed synthetic credentials and do not qualify live AWS.

### Google Cloud and Azure

Current source registers and wires Google Secret Manager and Azure Key Vault
handlers; they are enabled only with valid provider configuration. See
[GCP operation/credential contracts](gcp.md) and
[Azure operation/credential contracts](azure.md) for the exact metadata/write
operations, admitted inputs, supported authentication and response limits.
Source or fixture support does not establish a live deployment's qualification.
Doppler/Infisical scaffolding does not establish registered broker operations.

## Deferred operation names

`k8s.set_secret`, `k8s.apply_manifest` and `http.request_with_auth` are design
placeholders, not supported generic operations. Keep proposed contracts separate
from the selected broker's live catalog.
