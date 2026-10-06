# Adversarial Security Review (2026-02-14)

**Date:** 2026-02-14  
**Scope:** `crates/` + `docs/` + demo scripts  
**Goal:** Verify the core invariant: **no plaintext secrets should reach agent/LLM-visible channels**.

> ## Current status (2026-09-09)
>
> All six findings (P0 #1-#4, P1 #1-#2) are **RESOLVED**. Historical record,
> kept for context; see the status line under each finding for what changed.

## Executive Summary

The current implementation has multiple **P0 / CRITICAL** issues that violate the invariant above. In particular:

1. `onepassword.read_field` returns plaintext in the `"value"` field and the CLI prints it.
2. `sandbox.exec` returns captured stdout/stderr (and the CLI prints it). Any secret printed by the sandboxed command is leaked.
3. The "secret transporter" control (`secret_ref_names` + `[rules.secret_names]`) is bypassable because requests are not reliably populated with secret names.
4. Audit persistence stores `AuditEvent.detail` verbatim; some detail strings are constructed from user-controlled / secret-adjacent data (e.g., command argv).

## Findings

### P0: `onepassword.read_field` returns plaintext secrets (misclassified as `SAFE`)

**Impact:** Breaks the v1 rule "LLMs get operations, not values". Any agent client can be configured to receive plaintext secrets.

**Evidence:**

- Plaintext returned in response:
  - `crates/opaqued/src/onepassword/mod.rs` (response includes `"value": value`)
- Operation registered as `SAFE`:
  - `crates/opaqued/src/main.rs` (`onepassword.read_field` → `OperationSafety::Safe`)
- CLI prints plaintext:
  - `crates/opaque/src/ui.rs` (`read_field` prints `value`)

**Recommendations:**

- Reclassify `onepassword.read_field` as `REVEAL` (and ensure v1 hard-block applies), or remove it from v1 entirely.
- If a human-only "reveal" feature is ever needed, make it an explicit, high-friction workflow that is **not** accessible to agents and is cryptographically bound to user intent.

**Status: RESOLVED.** `onepassword.read_field` is registered
`OperationSafety::Reveal` (`crates/opaqued/src/main.rs`), which is
hard-blocked for every client, agent or human.

### P0: `sandbox.exec` leaks secrets via captured stdout/stderr

**Impact:** Any secret that reaches command output becomes agent-visible. This is a direct, high-probability exfil path because many tools print secrets accidentally (debug logs, env dumps, stack traces, CLI prompts).

**Evidence:**

- Response includes captured output:
  - `crates/opaqued/src/sandbox/mod.rs` (returns `"stdout"` and `"stderr"`)
- Sandbox injects secrets into env:
  - `crates/opaqued/src/sandbox/macos.rs` + `crates/opaqued/src/sandbox/linux.rs` (inject `config.env`)
- CLI prints output:
  - `crates/opaque/src/ui.rs` (`sandbox.exec returns stdout/stderr + exit code`)
- Operation registered as `SAFE`:
  - `crates/opaqued/src/main.rs` (`sandbox.exec` → `OperationSafety::Safe`)

**Recommendations:**

- Treat `sandbox.exec` as `SENSITIVE_OUTPUT` (or stronger) and deny-by-default for agent clients.
- Remove stdout/stderr content from daemon responses (return lengths + exit code only), or provide an opt-in, human-only output view.
- Consider enforcing output redaction at the daemon boundary, but note: pattern-based redaction is not sufficient as the primary control.

**Status: RESOLVED.** `sandbox.exec` is registered
`OperationSafety::SensitiveOutput`, and the response carries only
`stdout_length`/`stderr_length`, never captured output content
(`crates/opaque-sandbox/src/lib.rs`, with a regression test asserting the
response object has no `stdout`/`stderr` keys).

### P0: Secret transporter defense is bypassable (`secret_ref_names` is not reliable)

**Impact:** Policies that attempt to constrain which secrets a client can reference (`[rules.secret_names]`) can be bypassed by omitting or emptying `secret_ref_names`.

**Evidence:**

- Wrapper requests set `secret_ref_names: vec![]`:
  - `crates/opaqued/src/main.rs` (`exec`, `github`, `onepassword` convenience wrappers)
- Policy matching is vacuously true on empty lists:
  - `crates/opaque-core/src/policy.rs` (`SecretNameMatch::matches` uses `iter().all(...)`)

**Recommendations:**

- Derive secret names server-side from operation params and profile contents (do not trust client-supplied `secret_ref_names`).
- Fail closed: if `[rules.secret_names].patterns` is non-empty and derived secret names are empty/unknown, deny.
- Emit derived secret names into audit (`event.secret_names`) for forensic integrity.

**Status: RESOLVED.** `secret_ref_names` is now derived server-side from
the profile's secret declarations or the vault/item/field path
(`crates/opaqued/src/rpc_wrappers.rs`), and `SecretNameMatch::matches`
fails closed when patterns are configured but the derived list is empty
(`crates/opaque-core/src/policy.rs`).

### P0: Audit DB can persist secrets (`AuditEvent.detail` stored verbatim)

**Impact:** Even if response sanitization works, secrets can be written to disk in the audit DB via unsafe `detail` strings (and later leak via audit queries or backups).

**Evidence:**

- Sandbox audit includes full command argv via debug formatting:
  - `crates/opaqued/src/sandbox/mod.rs` (SandboxCreated detail includes `command={:?}`)
- SQLite sink stores `event.detail` as-is:
  - `crates/opaque-core/src/audit.rs` (insert uses `event.detail` directly)

**Recommendations:**

- Enforce sanitization centrally inside the audit sink (last line of defense).
- Avoid free-form `detail` strings for secret-adjacent fields; prefer structured fields with conservative truncation/redaction.

**Status: RESOLVED.** `SqliteAuditSink::emit` redacts every event's
`detail` text through the sanitizer before it is queued for persistence
(`crates/opaque-core/src/audit.rs`): exactly the "last line of defense"
recommended here, applied to all events including sandbox command detail.

### P1: Approvals and leases are not bound to operation params

**Impact:** Approval prompts (and `FirstUse` leases) can apply to a broader set of actions than intended, because the binding hash excludes `params`, and the approval UI does not display params.

**Evidence:**

- `OperationRequest::content_hash()` excludes `params`:
  - `crates/opaque-core/src/operation.rs`
- Approval UI description includes only `target` + `secret_ref_names`:
  - `crates/opaqued/src/enclave.rs`

**Recommendations:**

- Introduce explicit, per-operation approval bindings (a canonical subset of params) included in the content hash and shown to the user.
- Promote critical params into `target` where appropriate (e.g., `secret_name`, `environment`, `command` summary).

**Status: RESOLVED.** `OperationRequest::content_hash()` now includes a
canonical JSON serialization of `params` (in addition to operation,
target, secret_ref_names, client identity, and principal context):
`crates/opaque-core/src/operation.rs`.

### P1: Provider base URLs accept insecure schemes (footgun)

**Impact:** A misconfigured environment can downgrade to plaintext HTTP or enable unintended routing (SSRF-like behavior), especially in test/dev contexts.

**Evidence:**

- GitHub base URL comes from `OPAQUE_GITHUB_API_URL` with no scheme validation:
  - `crates/opaqued/src/github/client.rs`
- 1Password Connect base URL comes from `OPAQUE_1PASSWORD_CONNECT_URL` with no scheme validation:
  - `crates/opaqued/src/onepassword/client.rs`

**Recommendations:**

- Require `https://` by default; allow `http://` only behind an explicit "insecure" flag/config.

**Status: RESOLVED.** Both clients validate the scheme and reject
`http://` outside of localhost/127.0.0.1
(`crates/opaque-providers/src/github/client.rs`,
`crates/opaque-providers/src/onepassword/client.rs`).
