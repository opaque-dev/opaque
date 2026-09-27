# Tutorial: your first gated operation

Publish a disposable secret to a test GitHub repository, approve the request,
and inspect the broker's audit record. The operation returns status without
returning the secret value through Opaque.

This is a **local learning exercise**: agent and daemon share your user account.
It does not isolate credentials from other processes with that account's access.
Use a throwaway value and test repository, not production credentials or data.

Steps 1–4 need macOS or a Linux graphical desktop with
[native approval configured](linux-polkit.md). Step 5 also needs access to a test
repository and a disposable GitHub token authorized to manage its Actions secrets.

## What you are about to build

```text
Agent → opaque-mcp → opaqued → GitHub
CLI   ────────────→    ↑
                human approval
```

The broker checks policy, requests approval, resolves a credential reference,
and calls GitHub. The CLI exercises the same broker before you connect an agent.

## 1. Install

This tutorial covers the baseline broker flow. The reviewer app, signed MCP v2
projections and portable checkpoints are unreleased source capabilities; see
[getting started](getting-started.md) for their build paths. Before upgrading an
existing installation to the current source writer, follow the
[audit migration guide](evidence-checkpoints.md#authenticated-local-head-and-older-databases).

=== "macOS (Homebrew)"

    ```sh
    brew install opaque-dev/tap/opaque
    ```

=== "Linux / macOS (script)"

    ```sh
    curl -sSfL https://raw.githubusercontent.com/opaque-dev/opaque/main/install.sh | sh
    ```

=== "From source"

    ```sh
    cargo install --locked --git https://github.com/opaque-dev/opaque.git opaque opaqued opaque-mcp opaque-approve-helper
    ```

Check the installed version and binary paths:

```sh
opaque --version
command -v opaqued opaque-mcp opaque-approve-helper
```

## 2. Start from a policy you can read

For a fresh installation:

```sh
opaque init --preset github-secrets
```

Open `~/.opaque/config.toml`. If a configuration already exists, review it instead
of overwriting it. These instructions assume the unchanged `github-secrets` preset.
Its Actions-secret rule is:

```toml
[[rules]]
name = "allow-github-actions-secret"
operation_pattern = "github.set_actions_secret"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "always"
factors = ["local_bio"]
```

The preset also permits other GitHub secret operations, including deletion;
it is not restricted to your test repository. Writes and deletions require
approval each time. Listing and `test.noop` use first-use approval with a
five-minute lease. Unmatched operations are denied. For narrower repository
and secret-name rules, see [policy](policy.md).

## 3. Run the daemon

In a second terminal, start the broker and leave it running:

```sh
opaqued
```

Back in the first terminal:

```sh
opaque ping
```

A successful ping confirms connectivity. Read startup errors before proceeding;
ordinary session-mode startup does not establish separate credential custody.

## 4. Run your first gated operation

```sh
opaque execute test.noop
```

Review the operation in the native prompt, then approve using the configured
native authentication. Linux requires an intent dialog followed by polkit.
If review cannot open, fix that prerequisite before continuing.

A successful no-op checks the local request and approval path without contacting
a provider. Repeating the same request within its valid lease can skip another
approval. That lease does not apply to the GitHub write below.

## 5. Give the daemon your secrets

Store two values interactively: the disposable GitHub token and a throwaway
value. These commands match the resolver's `keychain:service/account` format.
Do not put values in command arguments or agent messages.

=== "macOS"

    ```sh
    security add-generic-password -s opaque -a github-pat -w
    security add-generic-password -s opaque -a tutorial-value -w
    ```

=== "Linux (secret-tool)"

    ```sh
    secret-tool store --label="opaque github pat" service opaque account github-pat
    secret-tool store --label="opaque tutorial value" service opaque account tutorial-value
    ```

Enter the token at the first prompt and the throwaway value at the second.
The references are `keychain:opaque/github-pat` and
`keychain:opaque/tutorial-value`. An existing entry may need separate review;
do not replace credentials belonging to another installation.

## 6. Publish the disposable secret { #6-push-a-secret-you-never-see }

Replace the repository placeholder with your test repository. This creates or
replaces its `TUTORIAL_KEY` Actions secret:

```sh
opaque github set-secret \
  --repo YOUR_ORG/YOUR_REPO \
  --secret-name TUTORIAL_KEY \
  --value-ref keychain:opaque/tutorial-value
```

Confirm the repository and secret name in the approval prompt. Success means
GitHub accepted the write; it does not establish what a workflow later did
with the value. Opaque's response omits the value. A process with independent
keychain access or control of a consuming workflow has a different access path.

With the unchanged preset, this GitLab operation should be denied before
provider execution:

```sh
opaque gitlab set-ci-variable \
  --project tutorial/denied \
  --key TUTORIAL_KEY \
  --value-ref keychain:opaque/tutorial-value
```

Expect `policy_denied`; no GitLab token is needed. If your result differs,
inspect the active policy before proceeding.

## 7. Read the audit trail

```sh
opaque audit tail --limit 10
opaque audit verify
```

Inspect recorded operation, approval, provider and denial events. Increase
`--limit` if the relevant events are outside the displayed window. Results and
event counts depend on your run; a provider error is not a successful write.

Verification checks local audit integrity under its custody assumptions.
Someone holding the audit HMAC key can forge records; verification cannot
establish that a compromised broker reported truthfully. Whole-state rollback
also needs an independently retained reference to detect. See
[signed evidence checkpoints](evidence-checkpoints.md) for authenticated heads,
retained references and verification limits.

## 8. Point your agent at it

For Claude Code, Cursor or Codex, let the CLI write the entry:

```sh
opaque connect claude    # or: cursor, codex, auto
```

```text
✔  Registered opaque MCP server with Claude Code
```

For any other MCP client using an `mcpServers` configuration, add:

```json
{
  "mcpServers": {
    "opaque": {
      "command": "/absolute/path/to/opaque-mcp"
    }
  }
}
```

Use the path from `command -v opaque-mcp` and your client's supported configuration
location. Restart or reconnect the client, then confirm it lists
`opaque_github_set_actions_secret`. See [MCP integration](mcp-integration.md).

Ask it to set `TUTORIAL_KEY` in your test repository using
`keychain:opaque/tutorial-value`. Review the resulting request before approval.
This built-in tool returns operation status without exposing the secret value
through its result. It does not restrict the agent's independent tools or account.

## Review your results { #what-you-just-proved }

Check your own outcomes: no-op completed, GitHub accepted the write, GitLab was
denied, and audit verification passed. Record failures as failures. This exercise
is not a production security assessment or evidence of customer deployment.

Afterward, remove the test secret through GitHub and revoke the disposable token.

## Where to go next

- [Deployment](deployment.md): separate broker custody and its trust assumptions.
- [Bounded agent work](bounded-work.md): exact task manifests, durable consumption
  and outcome receipts beyond this single-operation flow.
- [Identity](identity.md) and [policy](policy.md): attributed access and narrower rules.

## Troubleshooting

**Daemon unreachable:** inspect the foreground broker's startup error.

**Linux prompt missing:** check the graphical session, dialog helper and polkit
setup in [Linux native approvals](linux-polkit.md).

**Unsealed configuration:** review [deployment](deployment.md) before sealing.
A seal does not protect against someone who can replace its key.

**Unexpected denial:** inspect `opaque policy show` and `opaque audit tail`.
