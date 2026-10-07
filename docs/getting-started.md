# Install and operate the local broker

Install core v0.6.0, configure a broker, connect an agent and inspect its evidence.
Use the [tutorial](tutorial.md) for the first gated operation and
[deployment](deployment.md) for separate broker custody.

## Install or build { #build }

For macOS Homebrew:

```sh
brew install opaque-dev/tap/opaque
```

For Linux or other installation paths, follow [installation](tutorial.md#1-install).
From a source checkout with a Rust toolchain:

```sh
cargo build --locked --release
```

Source binaries are in `target/release`; use those paths in place of the installed
commands below. A v0.6.0 archive contains eight tools:

| Tool | Purpose |
| --- | --- |
| `opaqued` | Broker enforcement, provider dispatch and audit |
| `opaque` | CLI |
| `opaque-mcp` | Stdio MCP adapter |
| `opaque-mcp-contract` | Offline MCP qualification |
| `opaque-approve-helper`, `opaque-approver` | Native and workstation review |
| `opaque-evidence` | Offline evidence verification |
| `opaque-web` | Local dashboard |

Archives also include `opaque-release.json`, `LICENSE`, `LICENSE-DOCS` and `NOTICE`;
macOS adds `Opaque Reviewer.app`. Scope and authority-policy commands are available
from v0.6.0. Follow [archive verification](installable-releases.md) before use.

**Upgrades:** older audit heads need the
[explicit offline migration](evidence-checkpoints.md#authenticated-local-head-and-older-databases).
Stop old writers and retain the independent exact-export pin. `opaque init` is
fresh setup, not a custody repair or reset command.

## Initialize and check policy { #initialize-local-state }

For a fresh installation:

```sh
opaque policy presets
opaque init --preset safe-demo
opaque policy show
opaque policy check
```

Initialization creates `~/.opaque/config.toml`, `profiles/` and a `run/` socket
fallback. Presets include `safe-demo`, `github-secrets`, `gitlab-variables`,
`sandbox-human` and `agent-wrapper-github`; review the selected rules before use.
Native approval requires the supported macOS or Linux graphical-session setup.

Daemon settings belong above the first `[[rules]]` table. The checker warns about
ignored keys but can still exit zero; read the warnings. See
[policy schema and approval limits](policy.md).

## Run the broker { #run-the-daemon }

Start the configured broker in one terminal:

```sh
opaqued
```

In another:

```sh
opaque ping
opaque version
opaque whoami
opaque execute test.noop
```

`opaque service install` installs the local user service. Neither this command nor
a successful no-op establishes separate custody; use the
[service-account deployment](deployment.md#trust-domain-split-service-account-mode).

## Connect an agent { #mcp-quickstart-claude-code }

```sh
opaque connect codex
```

Use `claude`, `cursor` or `auto` for other supported clients. The command registers
`opaque-mcp` from `PATH`; [MCP configuration](mcp-integration.md#setup) documents
client files, discovery and the qualified third-party gateway.

To run with a broker-managed session:

```sh
opaque agent run -- codex
opaque agent list
opaque agent end <session-id>
opaque agent end --all
```

Enable `enforce_agent_sessions = true` and set `agent_session_ttl_secs` in reviewed
broker configuration to require agent sessions. `--pass-env KEY` forwards selected
variables; `--inherit-env` passes the full parent environment. The wrapper is not
file or host isolation. See [agent integration](llm-harness.md) and
[identity/delegation](identity.md).

## Choose work { #execute-operations }

| Work | Reference |
| --- | --- |
| Registered provider operation | [Operation inputs and result contracts](operations.md) |
| Immutable release, secret-publish, host or inference task | [Plan, review, run and reconcile](bounded-work.md) |
| Qualified third-party MCP invocation | [Signed route and disclosure contract](mcp-qualified-tools.md) |
| Finite authority budget | [Scoped authority workflow](scoped-authority.md) |
| Sandboxed command with injected profile credentials | [Containment prerequisites](deployment.md#sandbox-prerequisites) |

A configured profile can run a command:

```sh
opaque exec --profile dev -- echo "hello from sandbox"
```

Both CLI and MCP return status and stdout/stderr byte lengths, with content
withheld. Inspect the recorded `sandbox` strategy; `sandbox = false` disables
platform containment. A child with permitted egress can still disclose injected
credentials.

For a configured test repository and credential reference:

```sh
opaque github set-secret --repo owner/repo --secret-name API_KEY \
  --value-ref keychain:opaque/api-key
```

Use [Bitwarden](bitwarden.md), [Vault](vault.md), [AWS](aws.md),
[Google Secret Manager](gcp.md) or [Azure Key Vault](azure.md) for provider setup.
Provider-specific fields and secret scopes belong in [operation reference](operations.md).

## Inspect evidence { #audit }

```sh
opaque audit tail --limit 50
opaque audit tail --query github --limit 20
opaque audit verify
```

Verification detects covered tampering when the attacker lacks the HMAC key.
An intact older snapshot or key-holder forgery needs independently held evidence.
Use [audit and export](audit-analytics.md) and
[portable checkpoints](evidence-checkpoints.md) for the exact limits.

For a configured release manifest:

```sh
opaque task plan --manifest ./release.json
opaque task run <task-id>
opaque task show <task-id>
opaque task reconcile <task-id>
opaque task revoke <task-id>
```

Task actions consume attempts durably before dispatch. Unknown outcomes stay spent;
reconciliation reads evidence without dispatching again. Revocation blocks future
work at its dispatch fence and cannot recall an external effect.

## Apply policy across brokers { #fleet-operations }

```sh
opaque bundle verify policy.bundle --anchor <policy-key-hex>
opaque attest --key <broker-attestation-key-hex>
```

Public core provides signed policy distribution, audit export and software posture
reports. Follow [federation configuration](federation.md). Fleet management is
separate enterprise software; a valid posture signature authenticates its signer's
claims, not hardware integrity.

## Environment variables

| Variable | Use |
| --- | --- |
| `OPAQUE_CONFIG` | Config path; defaults to `~/.opaque/config.toml` |
| `OPAQUE_SOCK` | CLI socket override; the daemon ignores it |
| `OPAQUE_GITHUB_TOKEN_REF`, `OPAQUE_GITLAB_TOKEN_REF` | Default provider credential references |
| `OPAQUE_GITHUB_API_URL`, `OPAQUE_GITLAB_API_URL` | Provider API endpoints |
| `OPAQUE_BITWARDEN_URL` | Bitwarden API endpoint; defaults to `https://api.bitwarden.com` |

Provider guides document additional settings. Profile references can contain
sensitive metadata even when they contain no credential values.
