# Web dashboard (`opaque-web`)

A read-only localhost dashboard for bounded tasks, provider receipts, audit events, policy files, and agent sessions. It binds only to `127.0.0.1`.

## Run against an isolated installation

```bash
cargo build -p opaque-web

# Matches a daemon configured with this data directory and run/opaqued.sock.
# This does not read or write ~/.opaque.
./target/debug/opaque-web --data-dir /tmp/opaque-example --open

# Override individual inputs when your daemon uses other paths.
./target/debug/opaque-web \
  --data-dir /tmp/opaque-example \
  --config /tmp/opaque-example/config.toml \
  --socket /tmp/opaque-example/run/opaqued.sock \
  --port 8080
```

The default URL is `http://127.0.0.1:7380`. Start the daemon separately with matching paths. The dashboard does not create a daemon, change policy, approve work, or execute writes. Task approval uses the trusted local or paired workstation approver; execution uses the CLI or agent tools. The dashboard can refresh correlated workflow evidence without dispatching work.

`--data-dir DIR` selects `DIR/config.toml`, `DIR/audit.db`, `DIR/web.token`, and `DIR/run/opaqued.sock`. Explicit `--config` and `--socket` take precedence. Without `--data-dir`, the existing `~/.opaque` defaults and `OPAQUE_CONFIG` / `OPAQUE_SOCK` overrides apply. An isolated data directory deliberately ignores those environment overrides.

## Unlock and lock

The page opens **LOCKED**. Read the token from the selected data directory's
`web.token` file, enter it in **Owner token**, then select **Unlock dashboard**.
The file is owner-readable (`0600`); the URL and page source contain no bearer.

The token stays in this page's memory and authenticated request headers. It is
never saved in browser storage. **Lock dashboard** clears the token, displayed
private data, cached receipts, stream cursor and timers, and cancels outstanding
requests. Reloading or opening another tab requires token entry again. A browser
history restoration also returns to the locked state. A dashboard restart rotates
the token: read the new file and unlock again.

Locking this page does not revoke a token copied elsewhere. The owner, other
processes running as the owner, root and privileged browser extensions remain
outside this file-possession boundary.

## Appearance and keyboard navigation

The dashboard shares the website's warm charcoal and paper colors, amber accent,
redaction mark, and Archivo / IBM Plex Mono typography. Fonts are served locally;
the page does not need a font CDN. It opens in the dark appearance. Select
**Paper theme** to switch, or **Dark theme** to return. The choice stays in this
page's memory and resets on reload; it does not change authentication.

Navigation sits beside the content on wide screens and becomes a horizontal tab
bar on narrow screens. Focus a tab and use the arrow keys to move between views;
**Home** selects Tasks and **End** selects Operations. In Audit, press **Enter** in a
filter field or select **Apply filters** to apply the query. Audit rows are
keyboard-accessible disclosure buttons: **Enter** or **Space** expands or closes
their evidence. New events preserve the focused row when it remains in the view.
**Clear view** clears only the displayed audit events; it does not delete the
audit database or stop new events from arriving.

## Connection states

- **LIVE:** the selected daemon answered a version/health check. An insecure auto-approval backend or workstation test mode adds a conspicuous **TEST APPROVAL** banner, even though the broker connection is live. The banner identifies its socket. Individual data sources can still report an error.
- **DISCONNECTED:** the daemon is unavailable. Persisted audit history and readable policy remain inspectable. Sessions and tasks show an actionable error.
- **ERROR:** the web API cannot be reached. An authentication rejection locks the dashboard; enter the current owner token to reconnect.

The dashboard never turns missing data, daemon failures, or API authentication errors into synthetic activity. After successful unlock, it polls daemon status every ten seconds and resumes the audit stream after disconnections. Locked pages perform no protected reads or reconciliation.

The live operation catalog comes from the selected daemon's registry and configured handlers. Availability distinguishes enabled, disabled, and fixture-only operations. Approval labels describe defaults; policy permission is evaluated for each request. A disconnected daemon cannot supply a live catalog. Audit catch-up drains bounded pages immediately and polls every 500 ms after reaching the tail; dashboard refreshes are coalesced and rendering is batched per animation frame.

## Views

**Tasks** is the default. Large histories are paginated; use **Older receipts** and **Newest receipts** to move between pages. It lists only the tasks returned by the daemon's scoped `task_list` API. Expand a task to inspect its manifest digest, creation/expiry/approval times, each exact repository and secret name, pinned source references, and per-slot receipt. No secret values are displayed. Each approved task records its own **Native approval**, **Paired workstation approval**, or **INSECURE TEST APPROVAL** provenance; switching the current daemon backend does not relabel historical test receipts. Legacy receipts without provenance say **Approval mode unavailable**. The view distinguishes:

- Slots not started and writes in flight.
- **API accepted:** GitHub accepted the write. This does not prove a deployment succeeded or verify the stored value.
- **Rejected:** the broker has a terminal rejection receipt.
- **Unknown:** a write may have happened; its allowance remains consumed and must not be silently retried.

**Staging releases** display dispatch authority separately from workflow evidence. Expand the task to inspect its exact repository/workflow IDs, reviewed workflow SHA-256, commit, image repository/digest, and staging destination. **Dispatch recorded** and **Dispatch API accepted** describe the dispatch receipt. A separate panel shows pending, running, succeeded, failed, or ambiguous workflow observations, including the run ID, attempt, check time, and correlation source. **Check workflow** performs an owner-scoped provider read; it cannot approve, dispatch, or retry. Failed checks retain prior evidence with an error. Workflow success does not establish service health beyond the reviewed workflow's checks.

**Audit** queries the selected SQLite database read-only. Kind, operation, outcome, and full-text filters apply to the displayed events. New events stream over an authenticated fetch connection, which resumes with a sequence cursor after connection loss. Pause buffers up to 200 events; **Clear view** clears the local view only.

**Policy** displays the selected config file. A seal file's existence is labeled as “Seal file present (not verified)”; the dashboard does not claim cryptographic validation or that this file is the daemon's active policy.

**Sessions** lists the daemon's visible session IDs, labels, and expiration times. Session tokens are not returned. **Operations** shows the selected daemon's actual operation catalog, including enabled, disabled and fixture-only availability. Catalog membership and default approval labels do not grant permission to execute an operation.

Organization fleet views are composed by a separately packaged management
console. The local dashboard contains five views and has no collector credential
or `/api/fleet` route. See [dashboard composition](reusable-core.md#compose-a-dashboard).

## Security

Every `/api/*` route, including the audit stream, requires `Authorization: Bearer <token>`. The served page is static and credential-free. The owner supplies the per-launch token through the unlock form; the page uses it only in request headers, never query strings or browser storage. API clients may read `DIR/web.token`, created atomically with `0600` permissions. Do not log or share this token.

Host and Origin validation accepts only `127.0.0.1` or `localhost` at the actual bound port. There is no cross-origin access grant. Responses use `Cache-Control: no-store`, a same-origin connection policy, and frame blocking. A browser refresh clears local authentication and requires explicit unlock.

This is a local read-only client of the existing daemon trust model. The daemon enforces task visibility and authorization; the dashboard does not bypass it by reading a task database or exposing a generic RPC proxy.

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
| `/api/operations` | GET | Selected daemon's operation catalog and handler availability |

Unavailable data returns an explicit non-2xx JSON error. Status returns the disconnected state as a successful health response so the page can explain it.

## Verification

```bash
cargo test -p opaque-web
node --test crates/opaque-web/tests/dashboard.test.cjs
```

The tests exercise the real router, bearer protection on all API routes and the stream, configurable-port Origin/Host validation, credential-free HTML, explicit unlock/lock and stale-response suppression, disconnected behavior, isolated path resolution, live SQLite query/stream resumption, daemon IPC response shapes for sessions and tasks, reconciliation authentication and method isolation, and dispatch/workflow wording with preserved approval provenance.

### Tenant inference receipts

A dashboard launched inside a delegated agent wrapper can inherit `OPAQUE_SESSION_TOKEN`. The token is captured at process startup and presented only in the daemon handshake; HTTP callers cannot replace it. The daemon resolves its principal and tenant on every task request. Renewing the wrapper delegation requires restarting that dashboard process.

Schema 3 receipts show the tenant and broker binding, fixed public source snapshot, model identity, reserved and observed token counts, and bounded model output as plain text. The three-request allowance is charged by reservation, never by observed usage. Provider completion evidence does not establish GPU time, server cancellation, or hardware isolation.
