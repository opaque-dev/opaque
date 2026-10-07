# Deploy a broker with isolated custody

Choose where the broker's authority lives before connecting agents. Public core
v0.6.0 provides local brokers on macOS and Linux; it does not provide an enterprise
fleet control plane. For the overall topology, see
[deployment patterns](enterprise-architecture.md).

## Two deployment modes

| | Session mode | Trust-domain split |
| --- | --- | --- |
| Broker account | Your user account | Dedicated non-root service account |
| Custody | Shared account can obtain broker keys and forge locally valid history | Agent account cannot read/write broker custody; startup verifies ownership and permissions |
| Native approval | Requires the user's active GUI session | Broker has no GUI session; choose an applicable out-of-band factor |
| Service | LaunchAgent / systemd user service | LaunchDaemon / systemd system service |
| Configuration | `~/.opaque/config.toml` | Sealed service-account configuration, typically `/etc/opaque/config.toml` |

Session mode is useful for local workflow evaluation. It does not separate the
agent from broker keys. Split mode still trusts the host, root and broker
administrator, and cannot close unrelated provider access paths.

## Trust-domain split (service-account mode)

Start from the [reference configuration](https://github.com/opaque-dev/opaque/blob/main/deploy/config.trust-domain.example.toml).
Provision the dedicated account, client group and private state as described in the
[systemd unit](https://github.com/opaque-dev/opaque/blob/main/deploy/systemd/opaqued.service)
or [LaunchDaemon plist](https://github.com/opaque-dev/opaque/blob/main/deploy/launchd/com.opaque.opaqued.plist).
Their headers contain the installation commands; adapt paths and account names
before installing them.

```toml
# Daemon settings must precede the first [[rules]] table.
require_seal = true

[trust_domain]
enforce = true
socket_group = "opaque-clients"
socket_path = "/run/opaque/opaqued.sock"
```

With enforcement enabled:

- Existing custody files must belong exclusively to the broker UID, with no
  group/other permission bits or substituted symlinks. Foreign ownership is
  fatal; loose modes on broker-owned files are tightened at startup.
- The broker refuses connections from its own UID. Keep agent workloads out of
  the service account.
- Client-group access opens the transport boundary; identity and policy still
  decide request authority. Every startup records `trust_domain.posture`.

| Shared transport path | Mode | Owner/group |
| --- | --- | --- |
| Socket directory | `0750` | Broker / client group |
| Operation socket | `0660` | Broker / client group |
| Daemon handshake token | `0640` | Broker / client group |

Configuration, seals, audit/identity/task state, keys, pairing state and profiles
remain private. The broker needs the client group in its own supplementary group
set to change transport ownership. `socket_group` also accepts a numeric GID.

When no per-user socket exists, CLI/MCP clients try `/run/opaque/opaqued.sock`
and check socket ownership, world access and directory permissions before
connecting. Follow [hardening](compliance/hardening.md) for identity, policy,
reviewer enrollment and export settings.

### Containers and Kubernetes

The [Compose reference](https://github.com/opaque-dev/opaque/blob/main/deploy/docker/compose.yaml)
and [Kubernetes manifest](https://github.com/opaque-dev/opaque/blob/main/deploy/k8s/opaque.yaml)
run broker and agent under distinct UIDs (7381/7382), sharing only a socket volume.
Custody is mounted only in the broker container. A one-shot bootstrap initializes
ownership and seals configuration; the running broker and agent stay non-root.

Keep the numeric socket GID (7999) in the required supplementary groups. The
Kubernetes reference disables automatic API tokens, drops capabilities, uses
read-only root filesystems and separates custody storage from the memory-backed
socket volume. Do not use `fsGroup` to group-share custody files: startup refuses
those permissions.

```sh
# Isolated fixture: builds and checks the Compose custody/transport boundary.
scripts/compose-smoke.sh
```

This test is fixture evidence, not qualification of an adapted deployment. The
reference uses file-based keys. KMS/CSI delivery, SPIFFE identity and hardware
attestation need separately implemented and qualified integration. The Kubernetes
operator belongs to the private enterprise package; the public manifest is a
static deployment example.

## Approval placement

Approval support follows the request contract, not just the platform:

| Work | Supported review path |
| --- | --- |
| Generic operations | Applicable native, paired-device or FIDO2 factor selected by policy |
| Secret publishing, staging release, fixed inference tasks | Full native review or configured paired-workstation review |
| SSH health tasks and third-party MCP invocations | Local native full review |

See [bounded tasks](bounded-work.md), [workstation review](remote-approvals.md) and
[MCP qualification](mcp-qualified-tools.md) for exact prerequisites. A headless
split broker cannot perform a workflow that currently requires local native
review. `ios_faceid` names the desktop paired-device wire factor; no iOS client
is released.

### macOS session mode

```sh
opaque service install
opaque service status
opaque service logs
```

The installed LaunchAgent is scoped to an Aqua session. LocalAuthentication needs
the user's GUI/keychain context; a LaunchDaemon does not supply that context.
Current source checks local authentication capability at startup when the session
factor is `local_bio` and trust-domain enforcement is off. Each prompt also fails
closed when authentication is unavailable. That preflight does not qualify
screen-lock, clamshell, remote-desktop or Fast User Switching behavior; test the
chosen host and factor.

Release archives and the separate reviewer application are described in
[installable releases](installable-releases.md). A proposed daemon `.pkg` or
SMAppService installer is not the current installation workflow.

### Linux session mode

The native flow presents reviewed intent, then requests polkit authentication.
Install the [polkit action](linux-polkit.md), provide `zenity` or `kdialog` and a
running graphical-session authentication agent. Missing approval prerequisites
cause denial; they do not authorize skipping review.

```sh
opaque service install
opaque service status
opaque service logs
```

The CLI installs a user service; it does not provision split custody. Inspect the
generated unit before relying on graphical-session dependencies or additional
hardening. For a dedicated broker use the shipped system unit, including its
supplementary client group and `NoNewPrivileges` setting.

## Sandbox prerequisites

Linux `sandbox.exec` requires a usable namespace wrapper. The broker probes the
actual namespace shape, kernel Landlock ABI and seccomp capability at startup and
before execution; installing a binary alone is insufficient.

| Recorded strategy | Requirement |
| --- | --- |
| `bubblewrap+landlock+seccomp` | Working `bwrap`, Landlock and seccomp |
| `bubblewrap+seccomp` | Working `bwrap`; Landlock unavailable |
| `unshare+landlock+seccomp` | Working `unshare` fallback, Landlock and seccomp |
| `unshare+seccomp` | Working `unshare`; Landlock unavailable |
| Refused | Neither namespace wrapper can establish the required shape |

Missing layers produce warnings; `sandbox.created` and `sandbox.completed` record
the strategy actually used. A failed probe refuses execution before spawning the
workload. The namespace wrapper performs setup, then
`opaqued __opaque-sandbox-helper` installs the supported restrictions before
executing the command. Keep the daemon binary outside `.opaque`, `.ssh` and
`.gnupg`, which are hidden in the sandbox.

```sh
# Debian/Ubuntu package; use your distribution's equivalent elsewhere.
sudo apt-get install bubblewrap
opaque service logs
opaque exec --profile dev -- echo "sandbox probe"
opaque audit tail --limit 20
```

The final two commands require a configured `dev` profile, policy and approval
factor. Inspect status and strategy; CLI/MCP withhold child stdout/stderr content.
On Ubuntu or in containers, host AppArmor, capabilities and seccomp policies may
prevent namespace creation. Qualify the required namespace permissions in the
chosen host policy rather than disabling confinement globally. A broker may start
while refusing `sandbox.exec`; provider operations do not require that sandbox.

macOS execution uses Seatbelt via the deprecated `sandbox-exec` facility and is
best-effort containment. `sandbox = false` provides environment sanitization only.
Neither platform makes secrets confidential from an agent-selected command that
receives them; permitted egress and output metadata remain disclosure paths.
See [profiles and agent integration](llm-harness.md).

## Upgrading existing custody

Before replacing a running binary, close admission, reconcile in-flight work and
stop/fence every writer. The current writer requires an authenticated retained
audit head and refuses unsupported older stores. Follow the explicit
[audit-store upgrade](evidence-checkpoints.md#authenticated-local-head-and-older-databases),
which requires independently retained evidence. Hashing a suspect store is not a
substitute; preserve original custody when migration is refused.

Do not restore task, identity, revocation or replay ledgers to an older state to
recover service. An intact old snapshot can verify and still resurrect authority.
See [storage and recovery](storage.md).

## Verify the deployed boundary

1. Verify the selected [release artifact](compliance/verifying-releases.md) and
   record its version. Inspect the active config, `opaque policy check` warnings,
   custody ownership and startup posture.
2. Test permitted and denied work with a disposable target and real reviewer.
   Test replay/revocation in isolated fixtures, and inspect interrupted outcomes.
3. Confirm the agent cannot read custody or access the provider through an
   unrelated credential. Match approval provenance to the intended factor.
4. Export and independently retain evidence with receiver continuity state.
   Preserve custody bindings and consumption ledgers in recovery procedures.

[Deployment verification](evaluation-guide.md) gives the inspection steps;
[hardening](compliance/hardening.md) gives configuration fields. Approval, current
authority, durable consumption and provider success are separate checks.
