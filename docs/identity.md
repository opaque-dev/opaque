# Identify and delegate agent work

Configure OIDC identity to bind agent work to a verified human or a declared
service principal. Public core v0.6.0 supports this local broker workflow on
macOS and Linux. Process classification alone cannot identify a human: an agent
can invoke the same CLI.

```sh
opaque login
opaque whoami
opaque agent run -- codex
opaque logout
```

The daemon owns login and token validation. Agent-session creation requires its
configured approval factor; login alone does not approve an operation. See
[agent integration](llm-harness.md) for session setup and
[deployment patterns](enterprise-architecture.md) for custody requirements.

## Principals and roles

| Kind | Established by | ID prefix | Authority |
| --- | --- | --- | --- |
| Human | Verified OIDC issuer and subject | `hum_` | Admin-assigned roles; first human bootstraps admin/approver/operator outside managed mode |
| Agent | Workload identity | `agt_` | No independent principal authority |
| Service | `[[identity.service_principals]]` in daemon configuration | `svc_` | Explicit roles and autonomous policy |

Roles are `admin` (identity administration), `approver` (approval), `operator`
(operations) and `auditor` (read-only inspection). The broker reads current roles
and session state from its store; tokens do not preserve revoked roles. Client
classification is a separate [policy matcher](policy.md#client-type-human-vs-agent).
Neither classification nor roles replace an operation's approval requirements.

## Access modes

| Mode | Subject | Approval |
| --- | --- | --- |
| `delegated` | Authenticated human | Required out-of-band approval |
| `autonomous` | Config-declared service principal | Applicable operation and policy requirements |
| `break_glass` | Authenticated human | A distinct approver; fails closed without a supported factor |

## Configuration

Register a native/public IdP client with loopback redirect URIs. The daemon binds
the listener, exchanges the code with PKCE and validates the ID token's signature,
issuer, audience, nonce and expiry. The CLI displays the login URL; it does not
receive the authorization code. Login assurance still depends on the IdP and
browser environment.

```toml
[identity]
issuer = "https://your-org.okta.com"
client_id = "opaque-cli"
allowed_email_domains = ["example.com"]
required = true
# audience = "opaque-cli"      # defaults to client_id
# redirect_port = 8721         # if the IdP requires an exact redirect URI
# session_ttl_secs = 43200     # default 12 hours

[[identity.service_principals]]
name = "ci"
roles = ["operator"]
```

`required = true` requires verified delegation for agent operations. Put daemon
settings above the first `[[rules]]` table and inspect `opaque policy check`
warnings. Managed tenant admission additionally requires an explicit
`identity.allowed_subjects` list.

## Managed identity lifecycle

A provider-neutral adapter can submit membership observations through the public
[lifecycle contract](https://github.com/opaque-dev/opaque/blob/main/crates/opaque-core/src/identity_lifecycle.rs). The broker
owns admission, role mapping, authority epochs and revocation. An adapter never
opens its identity database or submits roles directly.

Enable managed lifecycle only with sealed configuration, enforced tenant custody,
a tenant binding, `identity.required = true`, and explicit
`identity.allowed_subjects`. Add these settings to the reviewed configuration:

```toml
[lifecycle]
socket_path = "/run/opaque/identity-lifecycle.sock"
allowed_adapter_uids = [7383]
socket_gid = 7999
token_file = "/var/lib/opaque/.opaque/identity-lifecycle.token"

[lifecycle.group_roles]
reviewers = ["approver", "operator"]
```

The example assumes broker UID 7381 and a separately isolated adapter UID 7383.
Preprovision the socket parent as broker-owned, group 7999, mode 0750; grant the
adapter only traversal and socket access. Every ancestor must be broker/root
controlled without untrusted writes; root-owned sticky temporary directories are
permitted. The socket is broker-owned mode 0660. Store a separate random
32–128-character URL-safe credential without whitespace in owner-only
`identity-lifecycle.token` directly inside broker custody. Give the adapter its
own private copy of only that credential. Keep task, approval, provider and
lifecycle credentials distinct. Same-UID processes share a trust boundary.

The wire format is one big-endian `u32` length followed by one JSON
`LifecycleRequest`, then one similarly framed `LifecycleResponse`. The public
`identity_lifecycle::deliver(socket, broker_uid, credential, batch)` client checks
path custody, socket ownership and the connected OS peer UID **before sending any
credential or mutation bytes**. The broker separately checks the adapter peer UID
against `allowed_adapter_uids` and authenticates the dedicated credential. There
is no TCP or HTTP fallback. Frames are bounded, connections have a 10-second
deadline, and at most 32 requests are handled concurrently.

Each version-1 batch carries the exact tenant/broker binding, configured issuer,
strictly sequential source revision starting at one, and at most 4,096 subject
updates within 2 MiB. Each subject must be explicitly admitted and may carry at
most 128 group identifiers. Core maps those identifiers through the sealed role
mapping. Unprovisioned humans cannot bootstrap admin or log in under managed
mode. Deleted subjects remain tombstoned; terminal `suspend` batches revoke human
authority and cannot be remotely cleared.

A successful receipt binds tenant, issuer, revision and the SHA-256 digest of the
serialized batch. Adapters must verify all those values before acknowledging a
source update, retain pending deliveries durably, and retry the exact batch after
an uncertain result. Only exact replay of the most recent committed revision is
acknowledged again. Updating authority and final task dispatch share the identity
writer lock; removal/regrant does not restore old sessions, delegations or
reviewer authority. A receipt cannot recall an already completed external effect.

The broker holds a lifetime endpoint writer lock. On restart it retires only an
owned stale socket after observing connection refusal; active sockets and
unrelated files remain untouched. Managed state cannot be silently disabled by
removing its configuration. Legacy `[scim]` configuration and persisted legacy
managed identity state fail closed with an explicit offline-migration requirement.
No automatic migration, authority reset, remote transport or retention pruning is
provided by this contract.

## Delegation and policy

With identity configured, `opaque agent run` mints an Ed25519-signed `opqd1`
delegation binding subject (`sub`), acting workload (`act`), access mode and
session ID (`jti`). Delegated mode also requires an unexpired human login.
Every request checks signature, expiry and current store state. Approval hashes
include this context, so two principals' approvals are not interchangeable.

Constrain operations with the verified delegator's roles and mode:

```toml
[[rules]]
name = "agents-for-operators-only"
operation_pattern = "github.*"
allow = true
client_types = ["agent"]

[rules.identity]
require_principal = true
roles = ["operator"]
access_modes = ["delegated"]
```

All listed roles must belong to `sub`. Any identity constraint fails closed
without a verified principal. Add the target, workspace and approval constraints
required by your workflow; this example shows only identity matching.

```sh
opaque identity ls
opaque identity roles <id> <roles…>
opaque identity delegations
```

Listing requires admin/auditor authority; assigning roles requires admin authority.

## Attribution and limits

Operation records carry the verified principal context and role snapshot.
Approval records distinguish session-bound presence (`local_bio_session`),
polkit account authentication, and signature-bound device/workstation/FIDO2
responses. Login, logout, role and delegation changes are audited. The
`trust_domain.posture` startup record reports observed custody enforcement.
Use [audit inspection](audit-analytics.md) and the explicit
[older-store migration procedure](evidence-checkpoints.md).

Same-account processes that obtain broker keys can forge locally valid history.
An [enforced custody split](deployment.md#trust-domain-split-service-account-mode)
prevents agent-account access to those files; it still trusts the host, root and
broker administrator. Attribution does not establish globally complete evidence
or prove an external effect.

Bounded task requests carry the same verified delegation. Logout, delegation
revocation or role removal blocks further authorized access; a final dispatch
fence cannot recall work already dispatched. Read the
[task lifecycle](bounded-work.md) before retrying an interrupted request.
