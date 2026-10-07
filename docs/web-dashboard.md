# Inspect a local broker in the dashboard

`opaque-web` provides read-only task receipts, audit, policy, sessions and operation
availability. Public core v0.6.0 includes it on macOS and Linux. It binds only to
`127.0.0.1`; start the selected broker separately.

```sh
opaque-web --data-dir /tmp/opaque-example --open
```

This example requires an existing isolated installation at that path. The default
URL is `http://127.0.0.1:7380`. The dashboard cannot create the daemon, change
policy, approve work or dispatch writes. **Check workflow** refreshes evidence
through a provider read. Use the CLI/agent and trusted reviewer to execute tasks.

## Select inputs and unlock

`--data-dir DIR` selects `DIR/config.toml`, `DIR/audit.db`, `DIR/web.token` and
`DIR/run/opaqued.sock`; explicit `--config` and `--socket` override those paths.
Without it, `~/.opaque` defaults and `OPAQUE_CONFIG` / `OPAQUE_SOCK` apply.
An explicit isolated directory ignores those environment overrides.

```sh
opaque-web --data-dir /tmp/opaque-example \
  --config /tmp/opaque-example/config.toml \
  --socket /tmp/opaque-example/run/opaqued.sock --port 8080
```

The page starts **LOCKED**. Read the selected directory's `web.token` (`0600`),
enter **Owner token**, and select **Unlock dashboard**. The bearer stays in page
memory/request headers, never URLs or browser storage. All `/api/*` routes,
including streaming and reconciliation, require it.

**Lock dashboard** clears private views, receipts, token, stream cursor and timers,
and cancels outstanding requests. Reload, another tab and browser-history
restoration require unlock again. A server restart rotates the token. Locking a
page cannot revoke a token copied elsewhere; owner-account processes, root and
privileged browser extensions remain outside this boundary.

Host/Origin validation accepts only localhost/127.0.0.1 at the bound port.
Responses disable caching and framing; no cross-origin access is granted. The
page itself is static and credential-free. Daemon authorization governs task
visibility; there is no direct task-database read or generic RPC proxy.

## Read connection state

| State | Meaning |
| --- | --- |
| **LIVE** | Daemon health check answered; individual data sources can still fail |
| **TEST APPROVAL** | Live broker uses insecure auto-approval or workstation test mode; the banner identifies its socket |
| **DISCONNECTED** | Broker unavailable; readable persisted audit/policy can remain visible, tasks/sessions report errors |
| **ERROR** | Web API unavailable; an authentication rejection locks the page |
| **DEMO** | Explicit synthetic examples; no daemon connection or live task receipts |

```sh
opaque-web --demo --data-dir /tmp/opaque-demo --port 7381 --open
```

Demo mode uses its own unlock token. Missing or failed live data never turns into
synthetic activity. Unlocked pages poll broker status and resume audit streaming
after disconnection; locked pages perform no protected reads or reconciliation.

## Inspect the five views

| View | What to inspect | Limit |
| --- | --- | --- |
| **Tasks** (default) | Scoped, paginated manifests, approval times/digest and per-action receipts; use **Older receipts** / **Newest receipts** | No secret values; only tasks returned by the broker's `task_list` |
| **Audit** | Read-only SQLite filters and resumable sequence stream | Pause buffers up to 200 events; **Clear view** clears display only |
| **Policy** | Selected configuration and seal-file presence | Presence is labelled unverified; it does not prove active policy or a valid seal |
| **Sessions** | Visible IDs, labels and expiry | No session tokens |
| **Operations** | Broker registry/handlers with enabled, disabled or fixture-only availability | Catalog membership and default approval do not grant request permission |

Approval provenance belongs to each receipt: native, paired workstation,
insecure test, or unavailable for legacy records. Changing the current backend
does not relabel historical test approvals.

Task slots distinguish not-started, in-flight, rejected, API-accepted and unknown
outcomes. **API accepted** does not verify the stored secret or deployment success.
**Unknown** may include a provider effect; its allowance remains consumed.

### Staging-release evidence

Expand a release task to inspect repository/workflow IDs, reviewed workflow hash,
commit, image digest and destination. Dispatch authority and receipt are separate
from pending/running/succeeded/failed/ambiguous workflow observations, run ID,
attempt, check time and correlation source.

**Check workflow** is an owner-scoped provider read: no approval, dispatch or
retry. Failed checks preserve earlier evidence with an error. Workflow success
establishes no health beyond that workflow's checks. See [bounded work](bounded-work.md).

### Tenant inference receipts

A dashboard started inside a delegated agent wrapper may inherit
`OPAQUE_SESSION_TOKEN`. It captures that token at startup for daemon handshakes;
HTTP callers cannot replace it. The broker resolves current principal/tenant on
each task request. Restart the dashboard after renewing delegation.

Schema 3 receipts show tenant/broker, fixed public source, model, reserved/observed
tokens and bounded model output as plain text. Reservation consumes the allowance;
observed usage does not refill it. Completion evidence proves neither GPU time,
server cancellation nor hardware isolation.

Organization fleet views belong to a separate management console; core has no
collector credential or `/api/fleet`. See [dashboard composition](reusable-core.md#compose-a-dashboard).

## Keyboard controls

Use arrow keys on view tabs; **Home** selects Tasks, **End** Operations. In Audit,
**Enter** applies a filter; **Enter/Space** expands an event. New events retain
focus where possible. **Paper theme** / **Dark theme** switch appearance in page
memory; reload resets the choice. Navigation becomes a horizontal tab bar on
narrow screens.

## API routes

| Route | Method | Description |
|---|---|---|
| `/` | GET | Credential-free, initially locked dashboard |
| `/api/status` | GET | Selected daemon health and data paths |
| `/api/tasks` | GET | Scoped task list through daemon IPC; optional `cursor` |
| `/api/tasks/{id}` | GET | Scoped task receipt through daemon IPC |
| `/api/tasks/{id}/reconcile` | POST | Refresh workflow evidence through read-only provider reconciliation; no dispatch |
| `/api/audit` | GET | Audit query with filters; limit capped at 500 |
| `/api/audit/stream` | GET | SSE over authenticated fetch; optional `Last-Event-ID` |
| `/api/policy` | GET | Selected config and seal-file presence |
| `/api/sessions` | GET | Visible session metadata through IPC |
| `/api/operations` | GET | Selected daemon's operation catalog and handler availability; synthetic in demo mode |

Unavailable data returns an explicit non-2xx JSON error. Status returns the disconnected state as a successful health response so the page can explain it. Demo responses always carry `mode: "demo"`.

## Verify dashboard behavior

```sh
cargo test -p opaque-web
node --test crates/opaque-web/tests/dashboard.test.cjs
```

The source tests cover bearer/Origin protection, unlock/lock and stale-response
handling, explicit demo/disconnection states, input paths, audit stream resumption,
scoped task/session IPC and reconciliation without dispatch. These are test
evidence; qualify the selected deployment separately.
