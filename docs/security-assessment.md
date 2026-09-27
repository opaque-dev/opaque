# Opaque Security Assessment

> NOTE: This is a historical assessment, not a current deployment checklist. A later historical review is [Adversarial security review](adversarial-security-review-2026-02-14.md). Current custody and migration instructions are in [deployment](deployment.md), [storage](storage.md) and [evidence checkpoints](evidence-checkpoints.md).

**Date:** 2026-02-12
**Assessor:** Security Engineering Review
**Scope:** Full source tree (`crates/`), documentation (`docs/`), PRD, configuration, and dependency analysis
**Codebase Version:** 0.1.0 (pre-release)

> ## Current status (2026-09-09)
>
> Reviewed codebase: 0.1.0, 3 crates, pre-approval-flow. Now 14 crates; the
> existing DONE/PARTIALLY-DONE annotations (§4.1.2, §4.2.1, §8.1, §8.2)
> still hold per-finding, but these have moved further:
>
> - **TA-3 / §3.5 same-uid attacker**: closed under `[trust_domain]
>   enforce = true`: custody files unreadable/unwritable at the agent's
>   uid, startup fails closed. See [deployment](deployment.md).
> - **§3.5 request authentication**: `opqd1` Ed25519 delegation tokens now
>   bind each request to a verified principal, checked live, revoked
>   immediately. See [identity](identity.md).
> - **Approver attribution** (Findings 2.1/2.4): cryptographic for
>   `paired_device`/`fido2`: a signature over a decision-bound challenge,
>   not just a session name.
> - **§8.1 C-6** (umask race before `bind()`): CLOSED 2026-09-14. The daemon
>   now binds through `bind_unix_listener_private` (a 0o177 umask guard in
>   `../crates/opaque-core/src/socket.rs`), so the socket file is 0600 from
>   its first instant. A regression test asserts the mode at birth under a
>   fully permissive umask.
> - Central policy, SIEM export, posture attestation: shipped, see
>   [federation](federation.md).
>
> **Verification pass (2026-09-14):** every finding below was re-verified
> against the current code; per-finding status notes were added or updated
> in place. Fixed in that pass: C-6 (umask race), H-5 (socket directory
> custody check), L-3 (`SAFETY` documentation on the unsafe FFI blocks),
> L-4 (double-invocation warning in the LocalAuthentication callback).
> Still open, with recommendations inline: H-8 startup session preflight,
> screen-lock and Fast User Switching testing (§4.1.2), APNs relay wiring
> (compiled but deliberately unwired), L-2, L-6, L-7, L-9, L-10, and the
> polkit policy-file integrity check (§4.2.2).
>
> Appendix A/B file lists and dependency counts are frozen at 2026-02-12.
>
> September 11 source update: authenticated audit heads, explicit legacy upgrade
> and independently verifiable checkpoints are implemented, and `opaque-evidence`
> ships in the v0.6.0 release archives. The scoped authority foundation
> (`opaque scope`, signed scope checkpoints) is available from v0.6.0; it landed
> after the 2026-09-14 verification pass and is not covered by the findings below.
> Local verification cannot detect a forged history when the attacker holds the
> HMAC key, or establish freshness of an older intact snapshot. The recovery
> instructions below have been corrected; the historical findings elsewhere
> have not been reclassified by this documentation update.

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Code-Level Findings (Current Implementation)](#2-code-level-findings-current-implementation)
3. [Protocol Security](#3-protocol-security)
4. [Approval Flow Security](#4-approval-flow-security)
5. [Filesystem Security](#5-filesystem-security)
6. [Supply Chain](#6-supply-chain)
7. [Operational Security Guide](#7-operational-security-guide)
8. [Security Roadmap](#8-security-roadmap)

---

## 1. Threat Model

### 1.1 Threat Actors

| Actor | Description | Capability | Motivation |
|-------|-------------|------------|------------|
| **TA-1: Malicious LLM Agent** | An AI coding tool (Codex, Claude Code) that has been jailbroken, compromised, or is behaving adversarially. | Can invoke any RPC exposed over the UDS socket. Can send arbitrary JSON payloads. Can run arbitrary commands on the user's machine if the tool runtime permits. Can read any file the user can read. | Exfiltrate secrets, escalate privileges, perform unauthorized operations against SaaS targets. |
| **TA-2: Compromised Dependency** | A crate in the supply chain (e.g., `zbus`, `objc2`, or a transitive dep) that has been backdoored via a supply chain attack. | Full code execution within `opaqued` or `opaque` process at build time (proc macros) or runtime. Access to all in-memory secrets, the UDS socket, and OS credentials. | Exfiltrate secrets, install persistent backdoors, pivot to cloud resources. |
| **TA-3: Same-User Attacker** | A malicious process running under the same Unix UID as the Opaque user. This could be malware, a compromised npm package, a hostile VS Code extension, etc. | Can connect to the UDS socket (same UID), read/write files in the user's home directory, attach debuggers (on some configurations), read `/proc/<pid>/mem` (Linux). | Trigger unauthorized approval prompts (approval spam/fatigue), invoke privileged operations, read audit data, denial of service. |
| **TA-4: Network-Adjacent Attacker** | An attacker on the same LAN, relevant when the iOS mobile pairing HTTPS server is active. | Network traffic interception, mDNS spoofing, ARP spoofing. | Intercept pairing QR data, man-in-the-middle the mobile approval channel, steal device pairing keys. |
| **TA-5: Malicious MCP Server** | A rogue or compromised MCP server that relays requests from LLM tools to Opaque. | Can craft arbitrary operation requests, replay requests, attempt to extract sensitive information from responses or error messages. | Exfiltrate secrets through error message side channels, abuse approval leases, trigger operations against unauthorized targets. |
| **TA-6: Insider / Malicious Developer** | A developer with commit access to the Opaque repository or access to the build pipeline. | Can introduce backdoors in code, weaken policy defaults, add exfiltration paths. | Long-term persistent access to secrets across all deployments. |

### 1.2 Attack Surface Map

| Surface | Components | Exposed To | Notes |
|---------|-----------|------------|-------|
| **UDS Socket** | `opaqued` listener at `$XDG_RUNTIME_DIR/opaque/opaqued.sock` or `~/.opaque/run/opaqued.sock` | TA-1, TA-3, TA-5 | Primary attack surface. All operations flow through this socket. |
| **Approval UI (macOS)** | `LocalAuthentication` framework, Touch ID / password dialog | TA-1 (indirect via spam), TA-3 | User-facing. Social engineering vector. |
| **Approval UI (Linux)** | polkit `CheckAuthorization`, system auth agent | TA-1 (indirect via spam), TA-3 | User-facing. Intent visibility depends on auth agent. |
| **Provider Connectors** | 1Password CLI/API, HashiCorp Vault API, AWS SDK, GitHub/GitLab APIs | TA-2, TA-6 | Credentials for these are the crown jewels. |
| **Audit Log** | SQLite database, Parquet exports, LanceDB embeddings | TA-1, TA-3, TA-5 | If readable by agents, becomes an exfiltration channel for target names, operation metadata. |
| **Semantic Search Pipeline** | LanceDB vector index, embedding computation | TA-1, TA-3 | Embedding text must be sanitized. If not, secret refs leak into the vector store. |
| **Mobile Pairing (iOS)** | HTTPS server on LAN, QR code payload, Secure Enclave challenge-response | TA-4 | Network-level attacks during pairing window. |
| **HTTP Proxy** | `http.request_with_auth` operation (planned) | TA-1, TA-5 | Authenticated HTTP requests on behalf of agents. Response body is an exfiltration vector. |
| **Configuration Files** | TOML policy files, profile mappings | TA-3 | If writable by attacker, policy can be weakened. |
| **Process Memory** | In-memory plaintext secrets during operation execution | TA-2, TA-3 (via ptrace/debugger) | Secrets exist in broker memory during operation execution. |

### 1.3 Threat-Risk Matrix

| Threat | Likelihood | Impact | Risk Rating | Rationale |
|--------|-----------|--------|-------------|-----------|
| TA-1: LLM agent approval spam | **High** | **Medium** | **HIGH** | `approval.prompt` is currently exposed as a generic RPC with no authorization. Any connected client can trigger unlimited approval popups. |
| TA-1: LLM agent triggers unintended operation | **High** | **High** | **CRITICAL** | No policy engine exists yet. Once operations are implemented, any client can invoke any operation. |
| TA-3: Same-user process connects to socket | **High** | **High** | **HIGH** | Socket permissions (0600) are correct but same-UID processes can connect. No client identity verification beyond peer creds is implemented. |
| TA-3: Same-user process reads audit DB | **Medium** | **Medium** | **MEDIUM** | Audit DB will contain target metadata. File permissions must be strict. |
| TA-2: Compromised proc-macro crate | **Low** | **Critical** | **MEDIUM** | Many proc-macro crates in the dependency tree execute at build time with full access. |
| TA-4: MitM during mobile pairing | **Low** | **High** | **MEDIUM** | Pairing is a one-time event, but a successful MitM compromises the entire approval channel. |
| TA-5: Error message leaks secret | **Medium** | **High** | **HIGH** | Current error handling passes upstream error strings directly to clients. |
| TA-6: Insider backdoor | **Low** | **Critical** | **MEDIUM** | Mitigated by code review practices and small codebase. |

---

## 2. Code-Level Findings (Current Implementation)

### Finding 2.1: CRITICAL -- Generic `approval.prompt` RPC Exposed Without Authorization

**File:** `../crates/opaqued/src/main.rs`, lines 174-188
**File:** `../crates/opaque/src/main.rs`, lines 47-53

**Description:**
The `approval.prompt` method is directly callable by any process that can connect to the UDS socket. There is no client identity verification, no policy check, and no operation binding. The `reason` string is entirely client-controlled and displayed directly to the user in the OS authentication dialog.

**Code:**
```rust
// opaqued/src/main.rs:174-188
"approval.prompt" => {
    let reason = req
        .params
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let Ok(_permit) = state.approval_gate.acquire().await else {
        return Response::err(Some(req.id), "internal", "approval gate closed");
    };

    match approval::prompt(reason).await {
        Ok(approved) => Response::ok(req.id, serde_json::json!({ "approved": approved })),
        Err(e) => Response::err(Some(req.id), "approval_failed", e.to_string()),
    }
}
```

**Attack Scenario:**
1. A malicious LLM agent (TA-1) or same-user process (TA-3) connects to the UDS socket.
2. It sends: `{"id":1,"method":"approval.prompt","params":{"reason":"Install critical security update - approve now"}}`.
3. The macOS Touch ID or Linux polkit dialog appears with attacker-controlled text.
4. The user, seeing what appears to be a system prompt, approves.
5. The attacker receives `{"approved": true}` but this approval is not bound to any operation -- it is a free-floating "yes" that currently does nothing, but could be used to condition the user into approving future operation-bound prompts.

**Proof of Concept:**
```bash
# From any process running as the same user:
echo '{"id":1,"method":"approval.prompt","params":{"reason":"URGENT: Approve to prevent data loss"}}' | \
  socat - UNIX-CONNECT:$HOME/.opaque/run/opaqued.sock
```

**Impact:** Social engineering via approval prompt spoofing. Approval fatigue attack (repeated prompts until user blindly approves).

**Recommended Fix:**
- Remove the generic `approval.prompt` RPC endpoint entirely for external clients (as specified in PRD US-001/FR-4).
- Approvals should only be triggered internally by the daemon during operation execution, never by client request.
- If a debug mode is needed, gate it behind a compile-time feature flag or a separate debug socket.

---

### Finding 2.2: CRITICAL -- No Client Identity Verification or Authorization

**File:** `../crates/opaqued/src/main.rs`, lines 122-168

**Description:**
The `handle_conn` function retrieves peer credentials (`uid`, `gid`, `pid`) but only logs them. No authorization decision is made. Every connected client has full access to all RPC methods.

**Code:**
```rust
// opaqued/src/main.rs:122-134
async fn handle_conn(state: Arc<AppState>, stream: UnixStream) -> std::io::Result<()> {
    let fd = stream.as_raw_fd();
    let peer = peer_info_from_fd(fd).ok();

    if let Some(peer) = peer {
        info!(
            "client connected uid={} gid={} pid={:?}",
            peer.uid, peer.gid, peer.pid
        );
    } else {
        info!("client connected (peer creds unavailable)");
    }
    // ... proceeds to handle requests with no authorization check
```

**Attack Scenario:**
A malicious npm postinstall script (TA-3) running under the same UID connects to the socket and invokes `approval.prompt` or any future operation RPC. There is no allowlist, no executable hash verification, no policy evaluation.

**Recommended Fix:**
- Implement FR-2: Compute client identity from UDS peer creds + `/proc/<pid>/exe` readlink (Linux) or `proc_pidpath` (macOS) + SHA-256 of the executable.
- Implement FR-3: Evaluate every request against a policy allowlist keyed on (client identity, operation, target).
- Reject requests from unrecognized clients by default (deny-all policy).

---

### Finding 2.3: HIGH -- Approval Error Leaks LocalAuthentication Details

**File:** `../crates/opaqued/src/approval.rs`, lines 59-63

**Description:**
When LocalAuthentication is unavailable, the error includes the full `localizedDescription()` from `NSError`, which may contain system-internal details about the authentication configuration.

**Code:**
```rust
// approval.rs:59-63
if let Err(e) = unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) } {
    return Err(ApprovalError::Failed(format!(
        "LocalAuthentication unavailable: {}",
        e.localizedDescription()
    )));
}
```

This error propagates to the client via:
```rust
// main.rs:187
Err(e) => Response::err(Some(req.id), "approval_failed", e.to_string()),
```

**Attack Scenario:**
An LLM agent probes the `approval.prompt` endpoint. If LocalAuthentication is not available (daemon running headless, no Secure Enclave, etc.), the error response contains internal system details that reveal the security configuration of the machine.

**Recommended Fix:**
- Return a fixed, stable error message to the client: `"approval_unavailable"`.
- Log the full `NSError` details locally at debug level only.
- Apply this pattern to all error paths per FR-8.

---

### Finding 2.4: HIGH -- Client-Controlled Reason String Displayed in OS Auth Dialog

**File:** `../crates/opaqued/src/approval.rs`, lines 68-85
**File:** `../crates/opaqued/src/approval.rs`, lines 120-122

**Description:**
The `reason` parameter from the client is passed directly to:
- macOS: `evaluatePolicy_localizedReason_reply` (line 80-85) -- displayed in the Touch ID dialog.
- Linux: polkit `details` HashMap (line 121-122) -- may be shown in the auth agent dialog.

There is no sanitization, length limit, or content validation beyond `trim()` and empty check.

**Attack Scenario:**
An attacker sends a reason string designed to deceive the user:
- `"System update requires authentication"` (impersonating the OS)
- A very long string that causes UI overflow or hides the true source
- Unicode control characters or RTL override characters that alter the visual presentation
- Newlines that push important context off-screen

**Recommended Fix:**
- In the target architecture, the reason string should be derived server-side from the `OperationRequest` (operation + target + client identity), never from client-supplied text.
- As an interim fix: limit length to 200 characters, strip control characters and RTL overrides, prefix with `"Opaque: "` to distinguish from system prompts.

---

### Finding 2.5: HIGH -- Unsafe Code Review in `peer.rs`

**File:** `../crates/opaque-core/src/peer.rs`, lines 20-28 and 77-88

**Description:**
There are three `unsafe` blocks in `peer.rs`. All involve FFI calls to `libc` functions (`getsockopt`, `getpeereid`).

**Block 1 (Linux, lines 20-28):**
```rust
let rc = unsafe {
    libc::getsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_PEERCRED,
        std::ptr::addr_of_mut!(ucred).cast(),
        &mut len,
    )
};
```

**Analysis:** This is correctly structured. The `ucred` struct is stack-allocated and zero-initialized. The `len` parameter is correctly set to `size_of::<ucred>()`. The `addr_of_mut!` macro is used instead of raw pointer arithmetic, which is the modern recommended pattern. The return code is checked. **No memory safety issue found.**

**Block 2 (macOS, line 43):**
```rust
let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
```

**Analysis:** Straightforward FFI call with stack-allocated output parameters. Return code is checked. **No memory safety issue found.**

**Block 3 (macOS, lines 77-85):**
```rust
let rc = unsafe {
    libc::getsockopt(
        fd,
        SOL_LOCAL,
        LOCAL_PEERPID,
        std::ptr::addr_of_mut!(pid).cast(),
        &mut len,
    )
};
```

**Analysis:** Same pattern as Block 1. The hardcoded constants `LOCAL_PEERPID = 0x002` and `SOL_LOCAL = 0` are documented as stable on macOS. However, there is a concern:

**Concern:** The `RawFd` parameter is never validated. If the caller passes an invalid or already-closed file descriptor, `getsockopt` will return an error but the behavior is defined by the OS (returns `EBADF`). This is not a memory safety issue but could cause confusing error messages. The caller in `main.rs` line 123-124 uses `stream.as_raw_fd()` on a live `UnixStream`, so the fd is valid at point of call.

**Recommended Fix:**
- No immediate memory safety fix needed. These `unsafe` blocks are sound.
- Consider adding `# Safety` documentation comments to each `unsafe` block explaining the preconditions.
- Consider using the `rustix` crate (already in the dependency tree via `zbus`) which provides safe wrappers for `getpeereid` and `getsockopt`.

**Status (RESOLVED, 2026-09-14):** All three blocks in
`../crates/opaque-core/src/peer.rs` now carry `SAFETY` comments stating
their preconditions (L-3). The `rustix` migration (L-9) remains tracked but
optional; the raw `libc` calls are sound as reviewed.

---

### Finding 2.6: HIGH -- Unsafe Code Review in `approval.rs`

**File:** `../crates/opaqued/src/approval.rs`, lines 57-85

**Description:**
There are three `unsafe` blocks in `approval.rs`, all related to Objective-C interop via the `objc2` crate.

**Block 1 (line 57):**
```rust
let ctx = unsafe { LAContext::new() };
```

**Analysis:** `LAContext::new()` allocates and initializes an Objective-C object. The `objc2` crate handles retain/release semantics automatically via `Retained<T>`. This is the standard pattern. **No issue found.**

**Block 2 (line 59):**
```rust
if let Err(e) = unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) } {
```

**Analysis:** This is a method call that takes an `NSError**` out-parameter internally. The `objc2` crate translates this into a `Result`. **No issue found.**

**Block 3 (lines 79-85):**
```rust
unsafe {
    ctx.evaluatePolicy_localizedReason_reply(
        LAPolicy::DeviceOwnerAuthentication,
        &reason_ns,
        &reply,
    );
}
```

**Analysis:** This dispatches an asynchronous evaluation. The `reply` block is an `RcBlock` that captures a clone of the `Arc<Mutex<Option<Sender>>>`. The block may be called on an arbitrary dispatch queue.

**Concern:** The `reply` closure captures `tx2` which is `Arc<Mutex<Option<Sender<bool>>>>`. If the block is called more than once (which LocalAuthentication should not do, but is not formally guaranteed by Apple's documentation), the second call would find `tx.take()` returns `None` and silently drop the result. This is safe but could mask bugs.

**Concern:** If `opaqued` is terminated while an approval is pending, the `reply` block may be called after the `rx` receiver has been dropped. The `tx.send()` will return `Err` and the result is silently dropped via `let _ = tx.send(ok)`. This is safe.

**Recommended Fix:**
- No immediate memory safety fix needed. These `unsafe` blocks are sound.
- Add `# Safety` documentation.
- Consider adding a log warning if `tx.take()` returns `None` (indicates the callback was invoked more than once).

**Status (RESOLVED, 2026-09-14):** This code now lives in
`../crates/opaque-native-approval/src/lib.rs`. All `unsafe` blocks carry
`SAFETY` comments, and the reply block logs a warning when the callback is
invoked more than once instead of dropping the second result silently (L-4).

---

### Finding 2.7: MEDIUM -- Denial of Service via Approval Semaphore Starvation

**File:** `../crates/opaqued/src/main.rs`, lines 63, 181-183

**Description:**
The `approval_gate` is a `Semaphore::new(1)`, which correctly ensures only one approval dialog is active at a time. However, the semaphore is held for the entire duration of the approval (up to 120 seconds on macOS). During this time, all other approval requests block.

**Code:**
```rust
// main.rs:63
approval_gate: tokio::sync::Semaphore::new(1),

// main.rs:181-183
let Ok(_permit) = state.approval_gate.acquire().await else {
    return Response::err(Some(req.id), "internal", "approval gate closed");
};
```

**Attack Scenario:**
A malicious process (TA-3) sends an `approval.prompt` request. The approval dialog appears and the semaphore is acquired. While the user is deciding (up to 120 seconds), the attacker holds the gate. All legitimate operations that require approval are blocked. The attacker can repeat this indefinitely.

Even without a malicious actor, a legitimate but slow approval (user steps away) blocks all other operations.

**Recommended Fix:**
- Add a per-client request timeout shorter than the approval timeout (e.g., if the requester disconnects, cancel the approval and release the semaphore).
- Implement a queue with a maximum depth (e.g., 3 pending approvals). Reject additional requests with a `"approval_busy"` error code.
- When client identity is implemented, rate-limit approval requests per client identity.

**Status (RESOLVED):** The approval semaphore now lives in the enclave
(`../crates/opaqued/src/enclave.rs`) and is released when the requesting
client disconnects (the in-flight request future is dropped when the
connection splits detect EOF, see `handle_conn` in
`../crates/opaqued/src/main.rs`). An `ApprovalRateLimiter` keyed on
(pid, operation) rejects rapid-fire prompts, and the native prompt timeout
is 60 seconds (see Finding 4.1.4).

---

### Finding 2.8: MEDIUM -- Unbounded Connection Spawning

**File:** `../crates/opaqued/src/main.rs`, lines 81-89

**Description:**
Every incoming connection spawns a new Tokio task with no limit on concurrent connections.

**Code:**
```rust
// main.rs:81-89
res = listener.accept() => {
    let (stream, _addr) = res?;
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_conn(state, stream).await {
            warn!("connection error: {e}");
        }
    });
}
```

**Attack Scenario:**
A malicious process opens thousands of connections to the UDS socket. Each connection spawns a Tokio task and allocates a `LengthDelimitedCodec` with a 1MB max frame buffer. This can exhaust memory (thousands of tasks x codec buffer allocations) or file descriptors.

**Recommended Fix:**
- Add a connection semaphore limiting concurrent connections (e.g., `Semaphore::new(64)`).
- Add per-client-IP (per-PID where available) connection limits.
- Set a connection idle timeout (e.g., drop connections that haven't sent a request in 30 seconds).

**Status (RESOLVED):** A `connection_semaphore` capped at 64 concurrent
connections and a 30-second idle timeout are implemented in
`../crates/opaqued/src/main.rs` (`DaemonState.connection_semaphore`,
`handle_conn`). Per-PID limits were not added; the global cap plus the
per-connection rate limiter (Finding 2.13) bound the resource cost.

---

### Finding 2.9: MEDIUM -- Connection Error Leaks Frame Parsing Details

**File:** `../crates/opaqued/src/main.rs`, lines 141-158

**Description:**
Frame parsing errors and JSON deserialization errors are sent back to the client with the full `e.to_string()` error message.

**Code:**
```rust
// main.rs:144
let resp = Response::err(None, "bad_frame", e.to_string());

// main.rs:154
let resp = Response::err(None, "bad_json", e.to_string());
```

**Attack Scenario:**
A malicious client sends malformed data to probe the internal codec implementation. The error messages reveal:
- tokio-util `LengthDelimitedCodec` version-specific error strings
- serde_json deserialization details (expected types, byte positions)

This information assists in fingerprinting the server implementation.

**Recommended Fix:**
- Return fixed error messages: `"invalid frame"` and `"invalid request"`.
- Log the detailed errors server-side at debug level.

**Status (RESOLVED):** Clients now receive the fixed strings
`"malformed frame"` and `"invalid JSON request"`
(`../crates/opaqued/src/main.rs`, `handle_conn`); details stay server-side.

---

### Finding 2.10: MEDIUM -- Peer Credentials Not Verified Against UID

**File:** `../crates/opaqued/src/main.rs`, lines 122-134

**Description:**
The daemon retrieves peer credentials but does not verify that the connecting process's UID matches the daemon's UID. While socket permissions (0600) should prevent cross-user connections, the daemon should defensively verify this.

**Code:**
```rust
let peer = peer_info_from_fd(fd).ok();
// peer is only used for logging, never for authorization
```

**Attack Scenario:**
If socket permissions are misconfigured (e.g., the directory is world-readable due to a race condition), a process from a different UID could connect. The daemon would log the foreign UID but proceed to handle requests normally.

**Recommended Fix:**
- After obtaining peer credentials, verify `peer.uid == current_uid`. Reject connections from different UIDs.
- If peer credentials are unavailable (the `.ok()` path), reject the connection rather than proceeding.

**Status (RESOLVED):** `trust_domain::peer_uid_allowed` gates every
connection in `handle_conn` (`../crates/opaqued/src/main.rs`), mode-aware:
shared-uid mode admits only the daemon's own uid, and the enforced split
refuses exactly that uid while gating everyone else by socket group plus
the daemon token handshake. Connections whose workload attestation is
unavailable (including missing peer credentials) are rejected in
`attest_connection`.

---

### Finding 2.11: LOW -- `whoami` Endpoint Not Implemented

**File:** `../crates/opaqued/src/main.rs`, lines 190-193

**Description:**
The `whoami` endpoint returns `{"note": "not implemented"}`. When implemented, it should return the server-observed client identity. If the implementation returns too much detail, it could be used for fingerprinting.

**Code:**
```rust
"whoami" => {
    Response::ok(req.id, serde_json::json!({ "note": "not implemented" }))
}
```

**Recommended Fix:**
- When implemented, return only the information the policy allows the client to see about itself.
- Do not return the executable hash or codesign info to the client -- that information is for the daemon's policy engine, not for the client.

**Status (RESOLVED):** `whoami` is implemented with disclosure scoped by
client type: agent clients get minimal fields to prevent reconnaissance,
human clients get the debugging view plus the logged-in principal
(`../crates/opaqued/src/main.rs`, the `"whoami"` arm of `handle_request`).

---

### Finding 2.12: LOW -- Request ID Type Is Not Cryptographically Random

**File:** `../crates/opaque-core/src/proto.rs`, line 5

**Description:**
The `Request.id` field is a `u64`, and the client CLI hardcodes it to `1`. When operation requests are implemented, the `request_id` should be a cryptographically random UUID to prevent prediction and replay.

**Recommended Fix:**
- Use UUID v4 (or v7 for time-ordered) for request identifiers.
- The daemon should generate the canonical `request_id` for audit, not trust a client-supplied one.

**Status (RESOLVED):** `OperationRequest.request_id` is a UUID v4 generated
server-side (`../crates/opaque-core/src/operation.rs`); the wire-level
`Request.id` remains a per-connection `u64` correlation id only, never used
for audit identity.

---

### Finding 2.13: LOW -- No Rate Limiting on Any Endpoint

**File:** `../crates/opaqued/src/main.rs`, lines 170-196

**Description:**
There is no rate limiting on RPC calls. A malicious client can send thousands of `ping` or `version` requests per second, or spam `approval.prompt` requests.

**Recommended Fix:**
- Implement per-connection rate limiting (e.g., token bucket: 10 requests/second burst, 2 requests/second sustained).
- Implement per-method rate limiting for sensitive endpoints (approval: 1 per 5 seconds).

**Status (RESOLVED):** `ConnectionRateLimiter` (burst 10, sustained 2/s)
runs per connection in `handle_conn`, and the enclave's
`ApprovalRateLimiter` additionally windows approval prompts per
(pid, operation) (`../crates/opaqued/src/main.rs`,
`../crates/opaqued/src/enclave.rs`).

---

## 3. Protocol Security

### 3.1 JSON Deserialization

**File:** `../crates/opaqued/src/main.rs`, line 151
**File:** `../crates/opaque-core/src/proto.rs`, lines 1-9

**Analysis:**
The protocol uses `serde_json::from_slice` to deserialize incoming frames into the `Request` struct. The `params` field is `serde_json::Value`, which means arbitrary JSON is accepted.

**Risk: JSON Injection**
- The `params` field accepts any JSON value, including deeply nested objects. `serde_json` has a default recursion limit (`serde_json` default is 128 levels), which mitigates stack overflow attacks.
- The `method` field is a `String` with no validation beyond the `match` in `handle_request`. Unknown methods correctly return an error.
- The `id` field is `u64`, which is not susceptible to injection.

**Risk: Deserialization of Untrusted Data**
- `serde_json` is well-audited and widely used. No known deserialization vulnerabilities in the current version (1.0.149).
- The `params: serde_json::Value` type means the daemon will allocate memory proportional to the input. Combined with the 1MB frame limit, a single request can allocate up to ~1MB of heap memory for the parsed JSON tree.

**Recommendation:**
- Add a depth limit for `params` parsing if serde_json's default is insufficient for your threat model.
- Consider defining typed param structs per method instead of accepting `serde_json::Value`.

### 3.2 Frame Smuggling via Length-Delimited Codec

**File:** `../crates/opaqued/src/main.rs`, lines 135-137
**File:** `../crates/opaque/src/main.rs`, lines 78-80

**Analysis:**
Both client and server use `LengthDelimitedCodec` with a 1MB max frame length. This codec prepends a 4-byte big-endian length header to each frame.

**Risk: Frame Boundary Manipulation**
- The codec handles frame boundaries correctly. A malicious client cannot inject data into another client's connection because each connection has its own codec instance and TCP-like stream ordering is guaranteed by the kernel for UDS.
- Since each client gets its own connection, there is no risk of cross-client frame smuggling.

**Risk: Large Frame Allocation**
- A client can send a frame header claiming a frame of exactly 1,048,576 bytes. The codec will attempt to allocate this buffer before receiving the full frame data. This is bounded by the `max_frame_length` setting.
- With many concurrent connections (see Finding 2.8), this becomes a memory exhaustion vector: 1000 connections x 1MB = 1GB.

**Recommendation:**
- Reduce `max_frame_length` to 64KB or 128KB unless there is a specific need for larger frames. Current RPC payloads are tiny (< 1KB).
- Combine with the connection limit from Finding 2.8.

**Status (RESOLVED):** `opaque_core::MAX_FRAME_LENGTH` is 128KB
(`../crates/opaque-core/src/lib.rs`) and every codec in the daemon and
clients uses it; combined with the 64-connection cap, worst-case buffer
allocation is bounded at 8MB.

### 3.3 Replay Attacks

**Analysis:**
The current protocol has no authentication, no nonces, and no request signing. Any request can be replayed by a process that observed it.

However, since the transport is a UDS (not network), replay requires the attacker to have already connected to the socket, which requires same-UID access. If the attacker has same-UID access, they can craft new requests anyway -- replay adds no additional capability.

**For the mobile pairing channel (future):** Replay attacks are a real concern. The challenge construction (`H(server_id || request_id || sha256(request_summary_json) || expires_at)`) includes a `request_id` (random) and `expires_at` (TTL), which prevents replay if implemented correctly.

**Recommendation:**
- For UDS: replay protection is not needed beyond same-UID access control.
- For mobile pairing: ensure `request_id` values are never reused and that the daemon rejects signatures on expired challenges.

### 3.4 Resource Exhaustion Summary

| Vector | Limit | Risk |
|--------|-------|------|
| Frame size | 1MB | Medium -- should be reduced |
| Concurrent connections | Unbounded | High -- needs a limit |
| Requests per connection | Unbounded | Medium -- needs rate limiting |
| Pending approvals | 1 (semaphore) | Medium -- blocks all other approvals |
| JSON depth | 128 (serde default) | Low |

### 3.5 Lack of Request Authentication/Signing

**Analysis:**
Requests are not signed or authenticated. The daemon relies entirely on socket-level access control (file permissions + peer credentials). This is a reasonable model for a single-user local daemon, but it means:
- Any process that can connect to the socket is fully trusted.
- There is no way to distinguish between different clients once connected.
- Approval decisions cannot be cryptographically bound to the requesting client.

**Recommendation:**
- Implement client identity as described in the PRD (peer creds + executable hash + optional codesign).
- Bind approval decisions to the verified client identity.
- Consider a per-session challenge-response if you want to prevent pid-reuse attacks (a short-lived process could connect, disconnect, and another process could reuse the PID).

---

## 4. Approval Flow Security

### 4.1 macOS LocalAuthentication

#### 4.1.1 Prompt Spoofing

**File:** `../crates/opaqued/src/approval.rs`, lines 68-85

**Analysis:**
The `localizedReason` string is the only context the user sees in the Touch ID dialog. macOS displays this as: `"opaqued" is trying to [reason]`. The application name comes from the process name, not the reason string.

**Risk:** A malicious client can set the reason to anything (see Finding 2.4). The user sees `"opaqued" is trying to "Install critical security update"` and may approve without understanding what operation is actually being authorized.

**Mitigation (current):** None. The reason is fully client-controlled.

**Mitigation (target):** The daemon should construct the reason string from the verified `OperationRequest`, never from client input. Example: `"Allow Claude Code to set GitHub secret JWT for org/repo"`.

#### 4.1.2 Daemon Losing UI Session

**Analysis:**
If `opaqued` is started as a LaunchDaemon (runs as root, no GUI session) instead of a LaunchAgent (runs in user session), `LocalAuthentication` will fail because there is no UI session to display the dialog.

The code at line 59 calls `canEvaluatePolicy_error` which should detect this and return an error. However, there are edge cases:
- If the daemon starts with a UI session but the user locks the screen, the behavior of `evaluatePolicy` is unclear (Apple documentation does not specify).
- If the daemon is started via SSH, there is no UI session.

**Mitigation (current):** The `canEvaluatePolicy_error` preflight check provides some protection.

**Recommendation:**
- Document the supported deployment model (LaunchAgent only, never LaunchDaemon).
- Test behavior when the screen is locked.
- Consider detecting `IOServiceGetMatchingService(kIOMainPortDefault, ...)` for display sleep state.

**Status (PARTIALLY RESOLVED, re-verified 2026-09-14):** The deployment
model (LaunchAgent only, `LimitLoadToSessionType: Aqua`) is documented in
[Deployment](deployment.md). A per-prompt `canEvaluatePolicy` preflight is
implemented (`../crates/opaque-native-approval/src/lib.rs`,
`prompt_macos_blocking`): an unusable session yields a fixed
`approval_unavailable` error at prompt time, so the failure mode is
fail-closed, not undefined.

Still open, with the blocking decision spelled out:

- *Startup session preflight (H-8).* [Deployment](deployment.md) specifies
  refusing to start when `canEvaluatePolicy` fails at startup. Implementing
  that unconditionally would break two supported shapes: split deployments
  (the daemon deliberately owns no GUI session and uses out-of-band factors
  such as paired device or FIDO2) and session-mode configs whose factors do
  not include `local_bio`. The decision needed: preflight only when the
  effective factor set includes `local_bio` AND trust-domain enforcement is
  off, and choose whether failure is fatal (exit non-zero per the spec) or
  a startup warning plus the existing per-prompt fail-closed behavior. The
  implementation is then a ~20-line check next to the config validation in
  `../crates/opaqued/src/main.rs`, calling a small
  `session_supports_local_authentication()` helper exported from
  `opaque-native-approval`.
- *Screen lock and Fast User Switching.* Cannot be verified in an automated
  environment; needs a manual pass on hardware: (1) trigger an approval with
  the screen locked, expect the dialog on the lock screen; (2) trigger an
  approval while a second user owns the console, expect either a dialog on
  the daemon owner's session or a clean `approval_unavailable`, never an
  approval surfaced to the wrong user. Record the results in the
  [Deployment](deployment.md) macOS edge-case table, whose FUS row is
  explicitly marked "Needs testing".

#### 4.1.3 Process Interaction with Prompt

**Analysis:**
The macOS LocalAuthentication dialog is system-owned and runs in the WindowServer's trust domain. A malicious process cannot:
- Programmatically dismiss the dialog
- Click the "Allow" button
- Inject events into the dialog

However, a malicious process *can*:
- Create a fake overlay window that looks like the Touch ID prompt (UI spoofing)
- Use accessibility APIs (if granted) to interact with the dialog

**Recommendation:**
- Include the process name and a unique operation ID in the reason string so the user can verify authenticity.
- Consider using `LAPolicyDeviceOwnerAuthenticationWithBiometrics` instead of `LAPolicyDeviceOwnerAuthentication` to require biometrics (prevents password fallback, which is more susceptible to shoulder surfing).

#### 4.1.4 120-Second Timeout as DoS Vector

**File:** `../crates/opaqued/src/approval.rs`, line 88

**Analysis:**
The 120-second timeout on `rx.recv_timeout(Duration::from_secs(120))` means the approval gate semaphore is held for up to 2 minutes per approval request.

**Risk:** Combined with Finding 2.7, an attacker can block all operations for 2 minutes at a time by triggering an approval that the user ignores.

**Recommendation:**
- Reduce the timeout to 60 seconds.
- Add a mechanism for the user to cancel the approval from the daemon side (e.g., via the CLI: `opaque cancel`).
- Release the semaphore when the requesting connection is dropped.

**Status (RESOLVED):** The timeout is 60 seconds
(`../crates/opaque-native-approval/src/lib.rs`, `prompt_macos_blocking`),
and the approval semaphore is released when the requesting client
disconnects (future cancellation in `handle_conn`, see Finding 2.7).

### 4.2 Linux polkit

#### 4.2.1 `auth_self` Policy Analysis

**File:** `../assets/linux/polkit/com.opaque.approve.policy`, lines 9-13

**Policy:**
```xml
<defaults>
    <allow_any>no</allow_any>
    <allow_inactive>no</allow_inactive>
    <allow_active>auth_self</allow_active>
</defaults>
```

**Analysis:**
- `allow_any=no`: Correctly denies requests from non-local sessions.
- `allow_inactive=no`: Correctly denies requests from inactive sessions (e.g., SSH).
- `allow_active=auth_self`: Requires the user to authenticate with their own password.

**Risk Assessment:**
`auth_self` is the correct choice for this use case. It requires proof-of-life without requiring root privileges. However:
- Some polkit auth agents (particularly CLI-based `pkttyagent`) do not show the `details` HashMap, so the user cannot see *what* they are approving.
- GNOME's polkit agent shows the `message` field but not individual `details` entries.
- KDE's polkit agent shows details in some versions.

This means on many Linux setups, the user sees: `"Authentication is required to approve an Opaque operation."` with no indication of which operation or target.

**Recommendation:**
- Test specific auth agents (gnome-shell, kde, mate, pkttyagent) and document which ones display intent.
- As specified in the PRD (US-006/FR-6): if the environment cannot display intent, fail closed with `approval_unavailable`.
- Consider implementing a dedicated Opaque approval UI helper for Linux that shows full operation details, using polkit only for the authentication step.

**Status (RESOLVED):** A two-step approval flow has been implemented in the Linux approval helper (`../crates/opaque-approve-helper/src/main.rs`). Step 1 shows an intent dialog via `zenity --question` or `kdialog --yesno` with full operation details. Step 2 performs the polkit authentication. This separates intent visibility (our code, always works) from authentication (polkit, always requires password). If no intent dialog UI is available (no zenity, no kdialog, no TTY), approval fails closed. Supported desktop tiers are documented in [Deployment](deployment.md).

#### 4.2.2 Action ID Hijacking

**Analysis:**
The polkit action ID `com.opaque.approve` is a reverse-DNS identifier. A malicious actor would need root access to install a competing policy file at `/usr/share/polkit-1/actions/com.opaque.approve.policy`. If they have root, they can bypass polkit entirely.

**Risk:** Low. Polkit action IDs cannot be hijacked without root access.

**Recommendation:**
- Verify the policy file integrity at daemon startup (hash check).
- Consider namespacing operations into separate action IDs (e.g., `com.opaque.approve.github`, `com.opaque.approve.k8s`) for more granular policy in the future.

**Status (OPEN, low):** Neither the startup hash check nor action-ID
namespacing is implemented. Risk remains low (modifying the policy file
requires root, and root bypasses polkit anyway); track as hardening, not a
vulnerability.

### 4.3 Mobile (iOS) Pairing

#### 4.3.1 QR Pairing Crypto Protocol Weaknesses

**File:** `mobile-approvals.md`, Section 2

**Analysis:**
The pairing protocol described in the documentation includes:
- `server_pubkey`: Daemon's public key for identity pinning
- `pairing_code`: One-time high-entropy secret with 5-minute TTL
- `endpoint`: HTTPS URL with pinned cert fingerprint

**Weakness 1: QR Code Shoulder Surfing**
The QR code contains the `server_pubkey` and `pairing_code` in plaintext. If an attacker photographs the QR code within the 5-minute TTL, they can pair their own device.

**Weakness 2: No Key Confirmation**
The protocol does not include a key confirmation step. After pairing, neither side verifies that the channel is not being MitM'd. The daemon stores the device's public key on receipt of the `pairing_code`, but there is no mutual authentication beyond the one-time code.

**Weakness 3: Pairing Code Entropy**
The documentation says "high-entropy" but does not specify the length or character set. If too short, it is brute-forceable within the TTL window.

**Recommendation:**
- Require a key confirmation step: after pairing, display a short verification code (derived from both public keys) on both devices for the user to compare (similar to Signal safety numbers).
- Specify minimum pairing code entropy: at least 128 bits (e.g., 32 hex characters or 22 base64 characters).
- Rate-limit pairing attempts to prevent brute-force (max 5 attempts per pairing session).
- Add device listing: `opaque devices list` should show paired devices with their last-seen timestamp.

**Status (RESOLVED):** Implemented in
`../crates/opaque-approval/src/pairing/`: freshly paired devices are
quarantined (`confirmed: false`) and no token they hold works until a human
confirms the key fingerprint through the confirmation ceremony
(`store.rs`); the pairing nonce is 32 random bytes with a session TTL and
sessions are one-shot (`consumed` flag in `mod.rs`), which removes the
brute-force window a per-attempt rate limit was meant to bound; device
bearer tokens are 256-bit and stored only as SHA-256 digests.

#### 4.3.2 MitM Prevention During Pairing

**Analysis:**
The QR code includes either a pinned self-signed cert fingerprint or the server's public key. This provides a trust anchor for the phone-to-daemon connection.

**Risk:** If the attacker can intercept the QR code AND sit on the network path between phone and daemon, they can present their own certificate. However, the phone has the server's pinned cert/pubkey from the QR, so the TLS connection would fail unless the attacker also obtained the QR contents.

**Risk:** If the local network uses mDNS for discovery (v1), an attacker could respond to mDNS queries first and present a rogue endpoint. The cert pinning from the QR mitigates this.

**Recommendation:**
- Always pin the server certificate using the pubkey from the QR code.
- Use certificate-based mutual TLS after pairing (the device presents its Secure Enclave-backed certificate).
- Never fall back to unpinned TLS.

**Status (RESOLVED for the LAN server):** The approval server persists its
TLS identity so paired devices can pin the certificate across restarts
(`../crates/opaque-approval/src/approval_server.rs`,
`load_or_create_tls_identity`); there is no unpinned fallback path.

**Note (2026-09-14):** The APNs push relay
(`../crates/opaque-approval/src/push.rs`) is compiled and unit-tested but
deliberately NOT wired: the LAN approval server is the live second-device
transport, and the relay activates only when an `[approval.apns]` config
surface lands, since it is unusable without Apple credentials. Wiring it is
a product decision (credential provisioning, fallback ordering between LAN
and push, and notification content policy), not a code gap; leaving it dark
adds no attack surface.

#### 4.3.3 Challenge Construction Security

**Documentation states:**
```
challenge = H(server_id || request_id || sha256(request_summary_json) || expires_at)
```

**Analysis:**
- Including `server_id` prevents cross-server replay.
- Including `request_id` (random) prevents same-server replay.
- Including `sha256(request_summary_json)` binds the approval to the exact operation intent.
- Including `expires_at` prevents approval after expiry.

**Weakness:** The concatenation `||` operator is ambiguous. If the fields are simply concatenated as strings without a delimiter, an attacker could shift bytes between fields (concatenation collision). For example, `server_id="ab" || request_id="cd"` equals `server_id="abc" || request_id="d"`.

**Recommendation:**
- Use a structured encoding before hashing (e.g., `canonical_json({server_id, request_id, summary_hash, expires_at})`) or use length-prefixed encoding.
- Alternatively, use HMAC-SHA256 with the device's shared secret as the key, and include the structured fields as the message.
- Specify the hash algorithm explicitly (SHA-256 recommended).

**Status (RESOLVED):** Implemented with length-prefixed encoding (4-byte LE
length per field) hashed with SHA-256, and the approve/reject decision is
bound into the signed bytes so a relayed signed rejection can never be
replayed as an approval
(`../crates/opaque-approval/src/pairing/challenge.rs`, with tests).

---

## 5. Filesystem Security

### 5.1 Socket Path Permissions

**File:** `../crates/opaque-core/src/socket.rs`, lines 24-39
**File:** `../crates/opaqued/src/main.rs`, lines 96-104

**Analysis:**
The socket creation follows these steps:
1. `ensure_socket_parent_dir` creates the directory with `0o700` permissions (line 35).
2. `UnixListener::bind` creates the socket file (line 55).
3. `lock_down_socket_path` sets socket permissions to `0o600` (line 101).

**Risk: Race Condition Between Steps 2 and 3**
Between `bind()` and `set_permissions()`, there is a window where the socket may have default permissions (typically `0o755` minus umask). If the attacker can connect during this window, they gain access.

**Recommended Fix:**
- Set the process umask to `0o077` before calling `bind()`:
```rust
let old_umask = unsafe { libc::umask(0o077) };
let listener = UnixListener::bind(&socket)?;
unsafe { libc::umask(old_umask) };
```
- This ensures the socket is created with restrictive permissions from the start.

**Status (FIXED, 2026-09-14):** The daemon binds through
`bind_unix_listener_private` in `../crates/opaque-core/src/socket.rs`,
which swaps in a `0o177` umask for the duration of the `bind()` (RAII
guard, restored even on error), so the socket file is exactly 0600 from
its first instant; `lock_down_socket_path` remains as normalization. The
regression test
`bind_unix_listener_private_is_0600_from_birth_and_restores_umask` binds
under a fully permissive umask and asserts the mode at birth plus umask
restoration. This closes roadmap item C-6.

### 5.2 Directory Permission Race Conditions

**File:** `../crates/opaque-core/src/socket.rs`, lines 24-39

**Analysis:**
`create_dir_all` followed by `set_permissions` has a TOCTOU race: another process could create the directory (or a symlink) between the check and the permission set.

**Risk:** If `$XDG_RUNTIME_DIR/opaque/` does not exist, `create_dir_all` creates it. But `$XDG_RUNTIME_DIR` itself is typically user-owned (created by `pam_systemd` with correct permissions). The risk is low in practice.

**Higher risk path:** `~/.opaque/run/` under the HOME fallback. If `~/.opaque/` already exists and is a symlink to an attacker-controlled location, `create_dir_all` will follow the symlink and create `run/` in the attacker's directory.

**Recommended Fix:**
- After `create_dir_all`, verify that the resulting path is owned by the current user and is not a symlink:
```rust
let meta = std::fs::symlink_metadata(parent)?;
if meta.file_type().is_symlink() {
    return Err(io::Error::new(io::ErrorKind::Other, "socket directory is a symlink"));
}
if meta.uid() != current_uid {
    return Err(io::Error::new(io::ErrorKind::Other, "socket directory not owned by current user"));
}
```

**Status (FIXED, 2026-09-14):** `ensure_socket_parent_dir` now verifies the
directory it adopts: `check_socket_dir_custody` in
`../crates/opaque-core/src/socket.rs` refuses a symlinked parent and any
owner other than the daemon's effective uid or root (root pre-creates
`/run/opaque` in split deployments; a root daemon may adopt any directory).
Symlinks deeper in the chain are rejected by `validate_path_chain`, which
the daemon now runs before writing the pid file (see 5.4). Covered by
`socket_dir_custody_rules` and
`ensure_socket_parent_dir_rejects_symlinked_parent` tests. This closes
roadmap item H-5.

### 5.3 Stale Socket File Handling (TOCTOU)

**File:** `../crates/opaqued/src/main.rs`, lines 40-53

**Code:**
```rust
if socket.exists() {
    match UnixStream::connect(&socket).await {
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("socket already in use: {}", socket.display()),
            ));
        }
        Err(_) => {
            // Stale socket file.
            tokio::fs::remove_file(&socket).await?;
        }
    }
}
```

**Analysis:**
This has a TOCTOU race: between the `exists()` check (or the failed `connect()`) and the `remove_file()`, another instance of `opaqued` could start, create its socket, and then this instance removes the other's socket.

Additionally, between `remove_file()` and `bind()`, another process could create a file (or symlink) at the socket path.

**Risk:** Low in practice (daemon startup is infrequent), but could cause confusing behavior with systemd socket activation or rapid restart scenarios.

**Recommended Fix:**
- Use `flock()` or a PID file with advisory locking to ensure single-instance operation:
```rust
let lockfile = socket.with_extension("lock");
let lock = std::fs::File::create(&lockfile)?;
if flock(lock.as_raw_fd(), FlockArg::LockExclusiveNonblock).is_err() {
    return Err("another instance is running");
}
```
- This eliminates the race entirely.

**Status (RESOLVED):** `PidFileGuard` in `../crates/opaqued/src/main.rs`
takes a non-blocking exclusive `flock` on `<socket_dir>/opaqued.pid` before
the stale-socket check, so two daemons can no longer race on stale-socket
removal. This closes roadmap item H-6.

### 5.4 Symlink Attacks on Socket Path

**File:** `../crates/opaque-core/src/socket.rs`, lines 6-22

**Analysis:**
The `OPAQUE_SOCK` environment variable allows the user to specify an arbitrary socket path. If the daemon runs as the user, and the path points to a symlink, `UnixListener::bind` will follow the symlink.

**Attack Scenario (TA-3):**
1. Attacker creates a symlink: `ln -s /tmp/shared_socket ~/.opaque/run/opaqued.sock`
2. When the daemon starts, it binds to `/tmp/shared_socket` (which may be world-accessible).
3. The attacker can now connect to the socket from any user.

**Recommended Fix:**
- Before binding, check that the socket path is not a symlink:
```rust
if socket.symlink_metadata()?.file_type().is_symlink() {
    return Err("socket path is a symlink, refusing to bind");
}
```
- Combine with the directory ownership check from 5.2.

**Status (RESOLVED):** The daemon never trusts `OPAQUE_SOCK` from the
environment (`socket_path_for_client(false)` in
`../crates/opaque-core/src/socket.rs`) and runs `validate_path_chain`,
which rejects a symlink at any component of the socket path, before the
pid file is written and before `bind()` (`../crates/opaqued/src/main.rs`).
Clients independently refuse symlinked or mis-permissioned sockets via
`verify_socket_safety`. This closes roadmap item M-4.

---

## 6. Supply Chain

### 6.1 Dependency Overview

The project has 3 crates and the following key dependency categories:

| Category | Crates | Risk Level |
|----------|--------|------------|
| **Async runtime** | tokio, tokio-util, futures-util, mio | Low -- widely audited, maintained by Tokio team |
| **Serialization** | serde, serde_json, serde_derive | Low -- ubiquitous, heavily audited |
| **CLI** | clap, clap_derive | Low |
| **macOS Obj-C interop** | objc2, objc2-foundation, objc2-local-authentication, block2, dispatch2 | **Medium** -- FFI boundary, less widely audited than core Rust ecosystem |
| **Linux D-Bus/polkit** | zbus, zbus_polkit, zvariant, zbus_macros | **Medium** -- complex protocol implementation, IPC boundary |
| **Proc macros** | syn, proc-macro2, quote, serde_derive, clap_derive, async-trait, async-recursion, zbus_macros, zvariant_derive | **Medium** -- execute at build time with full access |
| **WASM** | wasm-bindgen, wit-bindgen, wasmparser (transitive via zbus->uuid) | Low -- not used at runtime on macOS/Linux |
| **Logging** | tracing, tracing-subscriber | Low |

### 6.2 High-Risk Dependencies

#### `objc2` Ecosystem (macOS)

**Crates:** `objc2` 0.6.3, `objc2-foundation` 0.3.2, `objc2-local-authentication` 0.3.2, `block2` 0.6.2

**Risk:** These crates provide Rust bindings to Objective-C frameworks via FFI. They are inherently `unsafe` at the boundary. A supply chain compromise of these crates could:
- Bypass LocalAuthentication entirely (always return `true`)
- Exfiltrate secrets from process memory
- Execute arbitrary code at the Obj-C runtime level

**Mitigation:**
- Pin exact versions in `Cargo.lock` (already done).
- Monitor for security advisories via `cargo audit`.
- Consider vendoring these crates for production builds.
- The maintainer (madsmtm) is a known, active contributor in the Rust community.

#### `zbus` Ecosystem (Linux)

**Crates:** `zbus` 5.13.2, `zbus_polkit` 5.0.0, `zvariant` 5.9.2

**Risk:** `zbus` implements the D-Bus wire protocol and connects to the system bus. A vulnerability in `zvariant` deserialization could be triggered by a malicious D-Bus message. `zbus_polkit` trusts the polkit daemon's responses; if the D-Bus session is compromised, polkit responses could be forged.

**Mitigation:**
- Pin exact versions.
- Monitor `zbus` security advisories.
- The zbus project is maintained by the GNOME/freedesktop community.

#### Proc-Macro Crates

**Crates:** `syn`, `proc-macro2`, `quote`, `serde_derive`, `clap_derive`, `zbus_macros`, `zvariant_derive`, `async-trait`, `async-recursion`, `enumflags2_derive`, `thiserror-impl`, `tokio-macros`

**Risk:** These crates execute arbitrary Rust code at build time during `cargo build`. A compromised proc-macro crate could:
- Read environment variables (API keys, CI tokens)
- Write files (backdoor the compiled binary)
- Phone home (exfiltrate build metadata)

**Mitigation:**
- Use `cargo vet` or `cargo crev` to verify trusted publishers.
- Build in a sandboxed environment without network access.
- Audit `Cargo.lock` changes in PRs.

### 6.3 Compromised Dependency Impact

If a runtime dependency is compromised:

| Dependency | Impact |
|-----------|--------|
| `serde_json` | Can intercept and exfiltrate all deserialized request data. Can forge responses. |
| `tokio` | Full control over async runtime. Can intercept all I/O. |
| `objc2-local-authentication` | Can bypass biometric approval. Can always return `approved = true`. |
| `zbus` | Can intercept polkit communication. Can forge authorization responses. |
| `tracing` | Can exfiltrate all logged data (which currently excludes params, but includes peer info). |

**Recommendation:**
- Run `cargo audit` in CI to check for known vulnerabilities.
- Consider `cargo supply-chain` to analyze maintainer trust chains.
- For production deployments, vendor dependencies and build from a verified source tree.
- Implement reproducible builds to verify binary integrity.

---

## 7. Operational Security Guide

### 7.1 Hardening Checklist

#### Filesystem

- [ ] Socket directory (`$XDG_RUNTIME_DIR/opaque/` or `~/.opaque/run/`) has permissions `0700`, owned by the daemon user.
- [ ] Socket file has permissions `0600`.
- [ ] No symlinks exist in the socket path chain.
- [ ] SQLite database directory (when implemented) has permissions `0700`.
- [ ] TOML policy files have permissions `0600` and are owned by the daemon user.
- [ ] Verify `$XDG_RUNTIME_DIR` is mounted as `tmpfs` (Linux) -- prevents socket persistence across reboots.
- [ ] On macOS, verify `~/.opaque/` is excluded from Time Machine and Spotlight indexing.

#### Process Isolation

- [ ] `opaqued` runs as a LaunchAgent (macOS) or systemd user service (Linux), never as root.
- [ ] On Linux, create a systemd unit with:
  ```ini
  [Service]
  NoNewPrivileges=true
  ProtectSystem=strict
  ProtectHome=read-only
  PrivateTmp=true
  ReadWritePaths=%h/.opaque
  ```
- [ ] On macOS, if using a signed app bundle, the binary should have hardened runtime enabled.
- [ ] Disable core dumps for the daemon process (`ulimit -c 0` or `prctl(PR_SET_DUMPABLE, 0)` on Linux).
- [ ] On Linux, set `kernel.yama.ptrace_scope=1` (or higher) to prevent ptrace from other same-UID processes.

#### Network

- [ ] The daemon's UDS socket must never be exposed over TCP or any network transport.
- [ ] When the mobile pairing HTTPS server is active (future), bind it to the LAN interface only, never `0.0.0.0`.
- [ ] Use a firewall to restrict outbound connections from `opaqued` to only the required provider endpoints (1Password, Vault, GitHub API, GitLab API, AWS endpoints).

#### Secrets Management

- [ ] Provider credentials (PATs, Vault tokens) must be stored in the OS keychain, never in plaintext config files.
- [ ] Rotate provider credentials regularly (quarterly at minimum).
- [ ] Use short-lived credentials where possible (Vault dynamic secrets, AWS STS, GitHub App installation tokens).
- [ ] Never store plaintext secret values in the SQLite database.

#### Logging

- [ ] Set `RUST_LOG=info` for production (never `debug` or `trace` in production -- these may log sensitive details).
- [ ] Rotate log files. Do not let logs grow unbounded.
- [ ] Ensure log files have permissions `0600`.
- [ ] Never log request params (the current code already avoids this -- see `main.rs:161`).

### 7.2 Monitoring Recommendations

#### Daemon Health

- Monitor daemon process uptime (systemd `is-active` or launchctl print).
- Alert if the daemon crashes and restarts more than 3 times in 5 minutes (indicates a potential DoS or exploit attempt).
- Monitor socket file existence and permissions (alert if permissions change from `0600`).

#### Security Events (When Audit Log Is Implemented)

- **Alert on:** More than 5 approval denials in 10 minutes (possible approval fatigue attack).
- **Alert on:** Approval requests from unrecognized client identities.
- **Alert on:** Operations targeting production resources outside business hours.
- **Alert on:** Rapid succession of approval requests (more than 3 per minute).
- **Alert on:** Failed provider authentication (credentials may be expired or stolen).

#### Resource Usage

- Monitor file descriptor count for `opaqued` (alert if > 100).
- Monitor memory usage (alert if > 256MB -- indicates possible memory exhaustion attack or leak).
- Monitor CPU usage (alert if sustained > 50% -- possible DoS).

### 7.3 Incident Response Procedures

#### Suspected Compromise of Opaque Daemon

1. **Contain:** Kill the `opaqued` process immediately: `kill -9 $(pgrep opaqued)`.
2. **Preserve:** Copy the audit log (SQLite DB) and log files to a secure location before they are modified.
3. **Revoke:** Revoke all provider credentials (PATs, Vault tokens, AWS keys) that were configured in Opaque.
4. **Rotate:** Rotate all secrets that were managed through Opaque operations (GitHub secrets, GitLab CI variables, Kubernetes secrets).
5. **Investigate:** Review the audit log for unauthorized operations. Check for operations against unexpected targets or from unrecognized client identities.
6. **Rebuild:** Reinstall Opaque from a verified source. Do not reuse the old binary or configuration.
7. **Re-pair:** If iOS device pairing was in use, revoke all paired devices and re-pair.

#### Suspected Approval Prompt Spoofing / Social Engineering

1. **Do not approve** any pending prompts.
2. **Check** `opaque devices list` (when implemented) for unauthorized paired devices.
3. **Review** the audit log for any operations that were approved during the suspicious time window.
4. **Revoke** approval leases if any are active.
5. **Investigate** which process triggered the suspicious approval (check daemon logs for client PID/exe).

#### Provider Credential Leak

1. **Revoke** the leaked credential immediately at the provider (GitHub, GitLab, AWS, Vault, 1Password).
2. **Audit** the provider's access logs for unauthorized usage during the exposure window.
3. **Rotate** any downstream secrets that were accessible via the leaked credential.
4. **Update** the Opaque configuration with the new credential.

### 7.4 Backup and Recovery for Audit Data

The original proposed paths, Parquet/embedding backups and “restore then restart”
recipe are superseded. Use [current storage boundaries](storage.md) and
[evidence checkpoints](evidence-checkpoints.md) for supported paths and commands.

Preserve a consistent snapshot of custody and keep independently retained export
pins/checkpoints under separate control. Inspect archived evidence offline;
SQLite integrity alone is not a cryptographic or freshness check. The current
writer rejects older audit schemas pending explicit, pinned migration.

Do not replace live authority stores with an old backup and restart. Task/MCP
consumption, revocation and replay state are durable; rolling them back can
resurrect already consumed or revoked work. Safe recovery requires closed
admission, fenced old writers, preserved unknown effects and a reviewed
new-generation/re-enrollment procedure. The product has no generic authority
restore command. See [deployment](deployment.md#upgrading-existing-custody).

---

## 8. Security Roadmap

### 8.1 Critical -- Do Before Any Deployment

| ID | Finding | Action | Effort |
|----|---------|--------|--------|
| C-1 | Finding 2.1 | ~~Remove `approval.prompt` as a client-callable RPC.~~ **DONE:** Removed in hardening pass. Approvals are triggered internally by `Enclave::handle_approval()` only. | Small |
| C-2 | Finding 2.2 | ~~Implement client identity verification (peer creds + exe path + hash).~~ **DONE:** `ClientIdentity` with uid/gid/pid/exe_path/exe_sha256 implemented. Policy engine evaluates against client identity. | Medium |
| C-3 | Finding 2.4 | ~~Never pass client-supplied strings to OS approval dialogs.~~ **DONE:** Approval description is constructed by the enclave from verified `OperationRequest` fields, never from client-supplied reason text. | Small |
| C-4 | Finding 2.3 | ~~Sanitize all error messages returned to clients.~~ **DONE:** Error messages scrubbed in hardening pass. `bad_frame` -> `"malformed frame"`, `bad_json` -> `"invalid JSON request"`, workspace errors -> generic message. Details logged server-side only. | Small |
| C-5 | Finding 2.10 | ~~Verify peer UID matches daemon UID.~~ **DONE:** `verify_peer_uid()` implemented. Connections from different UIDs or with unavailable peer creds are silently rejected. | Small |
| C-6 | Section 5.1 | ~~Set umask to `0o077` before `bind()` to eliminate the socket permission race window.~~ **DONE (2026-09-14):** `bind_unix_listener_private` (0o177 umask guard in `opaque-core/src/socket.rs`) makes the socket 0600 from birth; regression-tested. | Small |

### 8.2 High Priority -- Do Before v1 Release

| ID | Finding | Action | Effort |
|----|---------|--------|--------|
| H-1 | Finding 2.8 | ~~Add a connection semaphore (max 64 concurrent connections).~~ **DONE:** `connection_semaphore` (64) in `opaqued/src/main.rs`, plus a 30s idle timeout. | Small |
| H-2 | Finding 2.7 | ~~Add per-client approval rate limiting. Release semaphore when client disconnects.~~ **DONE:** `ApprovalRateLimiter` per (pid, operation) in `opaqued/src/enclave.rs`; disconnect cancels the in-flight request and releases the semaphore. | Medium |
| H-3 | Section 3.2 | ~~Reduce `max_frame_length` from 1MB to 128KB.~~ **DONE:** `MAX_FRAME_LENGTH = 128 * 1024` in `opaque-core/src/lib.rs`, used by every codec. | Small |
| H-4 | Finding 2.13 | ~~Implement per-connection rate limiting (token bucket).~~ **DONE:** `ConnectionRateLimiter` (burst 10, sustained 2/s) in `opaqued/src/main.rs`. | Medium |
| H-5 | Section 5.2 | ~~Add symlink and ownership checks on socket directory.~~ **DONE (2026-09-14):** `check_socket_dir_custody` in `opaque-core/src/socket.rs` (symlink + ownership), with `validate_path_chain` covering the full path before the pid file and bind. | Small |
| H-6 | Section 5.3 | ~~Add PID file with advisory locking for single-instance protection.~~ **DONE:** `PidFileGuard` (`flock` LOCK_EX\|LOCK_NB) in `opaqued/src/main.rs`. | Small |
| H-7 | Section 4.2.1 | ~~Implement polkit intent visibility detection. Fail closed when the auth agent cannot show operation details.~~ **DONE:** Two-step approval flow (intent dialog + polkit auth) implemented. Supported desktops documented in [Deployment](deployment.md). | Medium |
| H-8 | Section 4.1.2 | ~~Document supported macOS deployment models (LaunchAgent only).~~ **PARTIALLY DONE:** Documented in [Deployment](deployment.md); per-prompt `canEvaluatePolicy` preflight fails closed. Startup session detection still open; the gating decision and implementation sketch are written out in the 4.1.2 status note. | Medium |
| H-9 | Section 6.3 | ~~Add `cargo audit` to CI pipeline. Pin all dependency versions.~~ **DONE:** `cargo-deny` (with `[advisories]` in `deny.toml`) runs in `ci.yml`; `dependency-review.yml` and OSSF `scorecard.yml` also run; versions pinned via `Cargo.lock`. | Small |
| H-10 | -- | ~~Implement the `OperationRequest` envelope (PRD US-002) with versioning, binding approvals to specific operations.~~ **DONE:** `OperationRequest` in `opaque-core/src/operation.rs`; approvals bind to the canonical request hash (params included, request_id excluded). | Large |

### 8.3 Medium Priority -- Address in v1 Lifecycle

| ID | Finding | Action | Effort |
|----|---------|--------|--------|
| M-1 | Section 4.3.1 | ~~Implement key confirmation step for mobile pairing.~~ **DONE:** confirmation ceremony with key fingerprint; unconfirmed devices are quarantined (`opaque-approval/src/pairing/store.rs`). | Medium |
| M-2 | Section 4.3.3 | ~~Use structured encoding (canonical JSON or length-prefixed) for challenge construction.~~ **DONE:** length-prefixed SHA-256 encoding with decision binding (`opaque-approval/src/pairing/challenge.rs`). | Small |
| M-3 | Finding 2.12 | ~~Use UUID v4/v7 for request identifiers. Generate canonical IDs server-side.~~ **DONE:** `OperationRequest.request_id` is a server-generated UUID v4. | Small |
| M-4 | Section 5.4 | ~~Add symlink check before binding to socket path (especially when `OPAQUE_SOCK` is set).~~ **DONE:** `validate_path_chain` before bind; the daemon ignores `OPAQUE_SOCK` entirely. | Small |
| M-5 | Section 3.5 | ~~Implement per-session challenge-response to prevent PID reuse attacks.~~ **DONE (different mechanism):** the first frame of every connection must present the daemon token (0600 file beside the socket), sessions carry their own tokens, and `opqd1` Ed25519 delegation tokens bind requests to a verified principal; identity no longer rests on the PID alone. | Medium |
| M-6 | -- | ~~Implement audit log with redaction levels (human vs. agent feed).~~ **DONE:** hash-chained SQLite audit sink with sanitized summaries (`opaque-core/src/audit.rs`, `sanitize.rs`). | Large |
| M-7 | -- | ~~Implement approval leases with scoped TTL (PRD US-004).~~ **DONE:** lease cache keyed on (client, operation, target, secrets, params hash) in `opaqued/src/enclave.rs`. | Medium |
| M-8 | -- | ~~Add client executable hash verification on macOS (codesign) and Linux (/proc/pid/exe).~~ **DONE:** `ClientIdentity` carries `exe_path`, `exe_sha256`, `codesign_team_id` (`opaque-core/src/operation.rs`); policy matches on them. | Medium |
| M-9 | Section 7.1 | ~~Implement core dump prevention (`prctl(PR_SET_DUMPABLE, 0)` on Linux).~~ **DONE:** `PR_SET_DUMPABLE=0` on Linux and `RLIMIT_CORE=0` on macOS at startup (`opaqued/src/main.rs`). | Small |
| M-10 | -- | ~~Implement connection idle timeout (30 seconds without a request).~~ **DONE:** 30s idle timeout in `handle_conn`. | Small |

### 8.4 Low Priority -- Track for Future

| ID | Finding | Action | Effort |
|----|---------|--------|--------|
| L-1 | Finding 2.11 | ~~Implement `whoami` with appropriate information disclosure controls.~~ **DONE:** agent clients get minimal fields, human clients the debugging view (`opaqued/src/main.rs`). | Small |
| L-2 | Section 3.1 | Define typed param structs per RPC method instead of `serde_json::Value`. **OPEN (partial):** the wrapper methods parse into typed `OperationRequest`s with validation (`opaqued/src/rpc_wrappers.rs`), but top-level `params` remains `serde_json::Value`. Acceptable; revisit if the method surface grows. | Medium |
| L-3 | Finding 2.5 | ~~Add `# Safety` documentation to all `unsafe` blocks.~~ **DONE (2026-09-14):** `SAFETY` comments on the FFI blocks in `opaque-core/src/peer.rs`, `opaque-core/src/socket.rs`, and `opaque-native-approval/src/lib.rs`. | Small |
| L-4 | Finding 2.6 | ~~Add logging for unexpected double-invocation of the LA callback.~~ **DONE (2026-09-14):** the reply block warns instead of silently dropping a second result (`opaque-native-approval/src/lib.rs`). | Small |
| L-5 | Section 4.3.1 | ~~Specify minimum pairing code entropy (128 bits). Rate-limit pairing attempts.~~ **DONE:** 256-bit one-shot pairing nonce with TTL; 256-bit bearer tokens stored as SHA-256; quarantine until fingerprint confirmation. | Small |
| L-6 | Section 6.2 | Consider vendoring `objc2` and `zbus` ecosystems for production builds. **OPEN:** not vendored; mitigated by `Cargo.lock` pinning, `cargo-deny` advisories, and dependency review in CI. | Medium |
| L-7 | -- | Implement reproducible builds for binary verification. **PARTIALLY DONE:** the SBOM step landed. Dependency-manifest embedding (`cargo auditable build`, verified in CI by `scripts/verify_auditable_binary.py`) and SLSA build provenance (`actions/attest-build-provenance`) are both written, along with downstream verification instructions ([verifying releases](compliance/verifying-releases.md)), but neither is active yet: both require a `.github/workflows/release.yml` change that has not been rolled in. Bit-for-bit reproducible builds remain out of scope. | Large |
| L-8 | -- | Add integration tests that verify error messages never contain secret values. **PARTIALLY DONE:** `opaque-core/src/sanitize.rs` unit tests cover scrubbing, and `opaqued/tests/provider_e2e.rs` drives a live daemon asserting the agent feed never sees the secret; a dedicated error-path secret-leak sweep is still worth adding. | Medium |
| L-9 | -- | Consider `rustix` safe wrappers for peer credential lookups instead of raw `libc` FFI. **OPEN:** still raw `libc`, now with `SAFETY` documentation; migration is optional hardening. | Medium |
| L-10 | Section 4.1.3 | Consider requiring biometrics-only policy (`LAPolicyDeviceOwnerAuthenticationWithBiometrics`) to prevent password fallback. **OPEN (deliberate):** `DeviceOwnerAuthentication` retains the password fallback so Macs without biometric hardware keep working ([Deployment](deployment.md) edge cases). Recommend an opt-in config knob for biometrics-only rather than a default change. | Small |

---

## Appendix A: Files Reviewed

| File | Lines | Purpose |
|------|-------|---------|
| `../crates/opaque-core/src/lib.rs` | 6 | Core library root, API version constant |
| `../crates/opaque-core/src/proto.rs` | 46 | JSON-RPC Request/Response types |
| `../crates/opaque-core/src/socket.rs` | 40 | Socket path resolution and directory setup |
| `../crates/opaque-core/src/peer.rs` | 91 | UDS peer credential extraction (unsafe FFI) |
| `../crates/opaque/src/main.rs` | 103 | CLI client |
| `../crates/opaqued/src/main.rs` | 200 | Daemon: listener, connection handler, request dispatch |
| `../crates/opaqued/src/approval.rs` | 137 | macOS LocalAuthentication and Linux polkit approval flows |
| `../assets/linux/polkit/com.opaque.approve.policy` | 16 | polkit policy XML |
| `../Cargo.toml` | 21 | Workspace configuration |
| `../Cargo.lock` | 1489 | Full dependency tree |
| `architecture.md` | 381 | System architecture |
| `operations.md` | 163 | Operation contract definitions |
| `policy.md` | 115 | Policy model |
| `llm-harness.md` | 137 | LLM integration safety model |
| `mobile-approvals.md` | 107 | Mobile pairing and approval protocol |
| `storage.md` | 206 | Storage and data model |
| `audit-analytics.md` | 228 | Audit, live feed, and analytics design |
| `linux-polkit.md` | 23 | Linux polkit setup instructions |
| `../tasks/prd-secure-approval-and-audit-hardening.md` | 165 | PRD for security hardening |
| `../README.md` | 24 | Project overview |
| `../AGENTS.md` | 25 | LLM tool guidance |

## Appendix B: Dependency Count Summary

- **Direct dependencies** (across all workspace crates): 21
- **Total transitive dependencies** (from Cargo.lock): 93
- **Proc-macro crates** (build-time code execution): 12
- **Crates with `unsafe` code** (estimated): `libc`, `objc2`, `block2`, `mio`, `socket2`, `tokio`, `rustix`, plus the project's own `peer.rs` and `approval.rs`

## Appendix C: Severity Definitions

| Severity | Definition |
|----------|-----------|
| **CRITICAL** | Exploitable vulnerability that could lead to secret disclosure, unauthorized operations, or complete bypass of security controls. Must be fixed before any deployment. |
| **HIGH** | Significant weakness that could be exploited under realistic conditions. Should be fixed before production use. |
| **MEDIUM** | Vulnerability that requires specific conditions to exploit or has limited impact. Should be addressed in the v1 lifecycle. |
| **LOW** | Code quality issue, missing defense-in-depth measure, or future risk that does not currently pose an exploitable threat. Track and address opportunistically. |
