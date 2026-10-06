# FIPS 140-3 feasibility assessment

Written 2026-09-14. This is the record of a feasibility spike: a full
inventory of cryptography in the workspace, a classification of each usage
against the aws-lc-rs migration path, and the results of two time-boxed build
attempts (the aws-lc-rs provider swap, then the FIPS build). All spike
changes were reverted; the default build is untouched. The known Rust path to
FIPS 140-3 validated crypto is the aws-lc-rs provider for rustls, where
aws-lc-fips-sys carries the CMVP validation.

Bottom line: the TLS layer swaps to aws-lc-rs with a one-line feature change
plus seven mechanical source lines, and the FIPS build (aws-lc-fips-sys
0.14.2) compiles the entire workspace green on the first attempt. The real
migration cost is not TLS; it is the direct RustCrypto usage (ed25519-dalek,
sha2, hmac, p256) that signs identities, chains the audit log, and verifies
approvals, plus two usages with no FIPS path (GitHub sealed boxes, the
ssh-key crate backend).

## Classification key

- (a) covered by swapping the rustls crypto provider or a dependency feature
  flag; no algorithm-level source changes.
- (b) needs source migration to aws-lc-rs APIs; the algorithm itself is
  FIPS approved.
- (c) no FIPS path without redesign or scoping the usage out of the
  cryptographic module boundary.

## Inventory

### TLS and certificates

| Crate | File | Primitive | Protects | Class |
|---|---|---|---|---|
| opaqued | `crates/opaqued/src/main.rs:759` | rustls ring provider, process default | All daemon TLS (installed once at startup) | a |
| opaque-approver | `crates/opaque-approver/src/client.rs:94,191` (also 42, 56) | rustls ring provider, TLS 1.2/1.3 signature verification | Pinned TLS client to the approval server | a |
| opaque-approval | `crates/opaque-approval/src/approval_server.rs:421` | tokio-rustls `TlsAcceptor` | Approval HTTPS server (mobile device pairing and decisions) | a |
| opaque-approval | `crates/opaque-approval/src/approval_server.rs:256` | rcgen `PKCS_ED25519` keygen and self-signed certificate | Approval server TLS identity | a (rcgen 0.14 has an `aws_lc_rs` backend feature) |
| opaque-federation-runtime | `crates/opaque-federation-runtime/src/export.rs:388-455` | tokio-rustls TLS client, custom roots | SIEM export streams | a |
| HTTPS clients | `reqwest` with `rustls-tls` (workspace `Cargo.toml:83`) | rustls via hyper-rustls | Outbound HTTPS: OIDC, cloud providers, federation fetch | a, with the graph caveat below |
| opaque-core (indirect) | `jsonschema` 0.45 pulls `reqwest` 0.13 | second rustls consumer | Schema reference fetching | a, same caveat |
| test harnesses | `crates/opaque-approval/src/approval_server.rs:759`, `approval_server/workstation.rs:426`, `factors.rs:912,987` | rustls ring provider installs | Test TLS setup | a |
| opaqued | `crates/opaqued/Cargo.toml:43` | direct `ring` dependency | Nothing: no `ring::` usage exists in the crate | a (delete it) |

Graph caveat for reqwest: `rustls` features are additive across the
dependency graph. reqwest's `rustls-tls` feature enables hyper-rustls's
`ring` feature, which re-enables `rustls/ring` even after the workspace
declaration changes. The runtime provider is still whatever
`install_default()` selects, but ring stays linked into the binary. Removing
it from the graph requires switching reqwest to `rustls-tls-no-provider`
(reqwest then uses the installed process default) and declaring tokio-rustls
with `default-features = false`. Auditors read `cargo tree`; budget for this
trim even though it does not change runtime behavior. Both reqwest versions
(0.12 direct, 0.13 via jsonschema) need the same treatment.

### Signatures

| Crate | File | Primitive | Protects | Class |
|---|---|---|---|---|
| opaque-core | `crates/opaque-core/src/identity.rs:27` | ed25519-dalek sign/verify | Delegation identity: role assertions over Ed25519 signatures | b |
| opaque-core | `crates/opaque-core/src/attest.rs:19` | ed25519-dalek sign/verify | Attestation signatures | b |
| opaque-core | `crates/opaque-core/src/bundle.rs:22` | ed25519-dalek sign/verify | Federation trust bundles (`opqd1` delegation tokens, trust anchors) | b |
| opaque-core | `crates/opaque-core/src/workstation.rs:8` | ed25519-dalek verify | Workstation approval decisions | b |
| opaqued | `crates/opaqued/src/identity/keys.rs:12-32` | ed25519-dalek keygen from a `getrandom` seed | Daemon identity signing key (`identity.key`, mode 0600) | b |
| opaque-approval | `crates/opaque-approval/src/pairing/` (`mod.rs:15`, `challenge.rs:9`, `store.rs:11`) | ed25519-dalek sign/verify | Device pairing, approval decision signatures, paired-device store | b |
| opaque-approver | `crates/opaque-approver/src/custody.rs:7`, `src/main.rs:5` | ed25519-dalek signing | Approver device key custody | b |
| opaque-federation-runtime | `crates/opaque-federation-runtime/src/attest.rs:28`, `src/federation.rs:52,180` | ed25519-dalek sign/verify | Federation bundle signatures and trust anchors | b |
| opaque | `crates/opaque/src/main.rs:5149,5333` | Ed25519 key parsing | CLI trust anchors and attestation keys | b |
| opaque-approval | `crates/opaque-approval/src/fido2.rs:20-21` | p256 ECDSA P-256 verify | WebAuthn/FIDO2 ES256 assertion verification (human approval factor) | b |
| opaque-bounded-work | `crates/opaque-bounded-work/src/ssh.rs:12,92` | ed25519-dalek via the `ssh-key` crate | Broker task-grant SSH certificates (issue and verify) | c (see below) |
| opaque-core | `crates/opaque-core/src/evidence_checkpoint.rs:5,366,413` | ed25519-dalek sign/verify | Evidence checkpoint and retention receipts (bounded-work inference evidence chain) | b |

Ed25519 is approved in FIPS 186-5, and aws-lc-rs provides Ed25519 including
under the FIPS feature, so the ed25519-dalek rows are migrations, not
redesigns. Two mechanical concerns: keys are stored as raw 32-byte seeds
(`crates/opaqued/src/identity/keys.rs`), so the migration needs
seed-compatible construction on the aws-lc-rs side, and key generation must
move from `getrandom` into the module's DRBG. Before a federal commitment,
verify that the CMVP certificate revision matching aws-lc-fips-sys 0.14.x
lists Ed25519 as approved; the aws-lc-rs FIPS documentation maps crate
versions to module certificates.

The ssh-key row is class (c) because ssh-key 0.6 hardwires its Ed25519
backend to ed25519-dalek; there is no aws-lc-rs backend. Options, in rough
order of preference: keep ssh-key for OpenSSH encoding only and drive the
signature bytes through aws-lc-rs via custom signer plumbing, contribute a
backend upstream, or accept the deviation and document SSH grant signing as
outside the validated boundary in the interim.

### Hashing and MACs

| Crate | File | Primitive | Protects | Class |
|---|---|---|---|---|
| opaque-core | `crates/opaque-core/src/audit.rs:14,1004` | hmac + sha2 (HMAC-SHA-256) | Tamper-evident audit chain | b |
| opaque-core | `crates/opaque-core/src/seal.rs:24,108` | HMAC-SHA-256 | Sealed state integrity | b |
| opaque-core | `crates/opaque-core/src/resource_auth.rs:1051-1063` | HMAC-SHA-256 | Resource authority token integrity | b |
| opaque-core | `crates/opaque-core/src/keyfile.rs:33` | `getrandom` key generation | HMAC key files (`audit.hmac`, store keys) | b (module DRBG for key material) |
| opaque-approval | `crates/opaque-approval/src/fido2.rs:320-323` | HMAC-SHA-256 | FIDO2 credential store integrity | b |
| opaque-approval | `crates/opaque-approval/src/fido2.rs:538,752,771` | SHA-256 | WebAuthn rpIdHash and clientDataHash verification | b |
| opaque-approval | `crates/opaque-approval/src/pairing/challenge.rs:69-111`, `pairing/store.rs:76` | SHA-256 | Pairing challenge derivation, key fingerprints | b |
| opaqued | `crates/opaqued/src/enclave.rs:297,334` | SHA-256 | Lease keys: client fingerprint and canonical parameter hash (anti param-swapping) | b |
| opaqued | `crates/opaqued/src/identity/persona.rs:157`, `identity/provisioning.rs:340,537` | SHA-256 | Identity and provisioning fingerprints | b |
| opaqued | `crates/opaqued/src/identity/oidc.rs:403` | SHA-256 | OIDC PKCE challenge | b |
| opaque-approver | `crates/opaque-approver/src/client.rs:28,180` | SHA-256 | TLS certificate pinning fingerprint | b |
| opaque-native-approval | `crates/opaque-native-approval/src/lib.rs:173-181` | SHA-256 | Display digest of the approval reason (UI only) | b (low priority) |
| opaque-core | `crates/opaque-core/src/inference.rs:31` | SHA-256 (`sha256`/`prompt_sha256` helpers) | Bounded-work inference receipt digests: profile, prompt, output, and source-snapshot hashes | b |
| opaque-sandbox | `crates/opaque-sandbox/src/lib.rs:151` | SHA-256 | Sandbox profile fingerprint (`profile_sha256` in execution evidence) | b |

All of these are SHA-256 or HMAC-SHA-256 through RustCrypto crates. The
algorithms are approved; the implementations are not validated. The
migration to `aws_lc_rs::digest` and `aws_lc_rs::hmac` is mechanical but
wide. Beyond the rows above, the same SHA-256 helper appears in several more
`opaque-core` digest sites that a complete migration must sweep:
`mcp.rs:457` (registry document hash), `policy.rs:675`, `task.rs:621`,
`operation.rs:450`, `identity_lifecycle.rs:185`, and
`crates/opaque-bounded-work/src/mcp/transport.rs:355` (MCP response digest).
All class (b), same treatment.

PR #87 widened this surface. `opaque-providers` is a default workspace
member, so its connectors compile into the shipped daemon; SHA-256 now
appears there in `aws/action.rs:35`, `aws/client.rs:61` (SigV4 canonical
payload hash), `azure/client.rs:338`, `bitwarden/client.rs:147`,
`vault/resolve.rs:189`, and `github/release.rs:281` (workflow hash check).
It also appears in `opaque-approval` at `remote/mod.rs:341` and
`remote/notices.rs:57`, in `opaque-federation-runtime` at `fleet/mod.rs:58`
and `export/detector.rs:45`, and in `opaqued` at `identity/lifecycle.rs:138`
(token, credential, and batch digests). All class (b).

Separately, AWS request signing uses AWS Signature V4 (HMAC-SHA-256) through
the `aws-sigv4` 1.5.1 crate (`crates/opaque-providers/src/aws/client.rs`,
`sign::v4`), whose signing crypto is the AWS SDK's own backend rather than
the RustCrypto stack; the canonical payload hash next to it is RustCrypto
`sha2`. The algorithm is approved, so this is class (a) if `aws-sigv4` can be
pointed at aws-lc-rs and class (b) otherwise; either way, budget the
aws-sigv4 backend as a distinct FIPS-scope item alongside the rustls
provider swap.

### JWT (already on the aws-lc-rs backend)

The workspace declares `jsonwebtoken = { version = "10", features =
["aws_lc_rs", "use_pem"] }` (workspace `Cargo.toml:90`), so these sites
already run on aws-lc-rs, and cargo feature unification means the FIPS build
recompiles them against the FIPS module with no source change:

| Crate | File | Algorithm | Protects |
|---|---|---|---|
| opaqued | `crates/opaqued/src/identity/oidc.rs:269-298` | RS256 verify | OIDC id_token validation |
| opaque-core | `crates/opaque-core/src/resource_auth.rs:24` | RS256 verify | Resource authority JWTs |
| opaque-providers | `crates/opaque-providers/src/gcp/client.rs:648-650` | RS256 sign | GCP service account tokens |

All class (a).

### No FIPS path

| Crate | File | Primitive | Protects | Class |
|---|---|---|---|---|
| opaque-providers | `crates/opaque-providers/src/github/crypto.rs` | crypto_box sealed box (X25519 + XSalsa20-Poly1305) | GitHub Actions secret upload | c |

The wire format is mandated by the GitHub API: secrets must be encrypted to
the repository's Curve25519 public key as a libsodium sealed box. Neither
X25519 key agreement in this construction nor XSalsa20-Poly1305 is FIPS
approved, and the format cannot change unilaterally. Treatment: document it
as an external-service interoperability requirement outside the module
boundary (the plaintext is a secret destined for GitHub, encrypted with
GitHub's key, transported inside FIPS TLS). Deployments that cannot accept
the deviation must disable the GitHub secrets feature.

### Non-issues

`zeroize` is memory hygiene, not cryptography. `getrandom` uses for
non-key material (session tokens at `crates/opaque-web/src/security.rs:114`,
daemon auth tokens at `crates/opaqued/src/main.rs:1078`, PKCE verifiers) are
acceptable as-is, though routing them through the module DRBG is cheap once
it is in place. The `p256` usages in `crates/opaque-approval/src/factors.rs`
and `crates/opaqued/src/provisioning_api_tests.rs` are test-side signing
only. No argon2, bcrypt, pbkdf2, or direct AES usage exists anywhere in the
workspace.

### Classification totals

- (a) provider or feature-flag swap: 9 clusters (all TLS, rcgen, JWT, the
  unused ring dependency).
- (b) source migration to aws-lc-rs, approved algorithms: 5 clusters
  (ed25519-dalek, p256 WebAuthn verify, sha2, hmac, key-generation RNG).
- (c) no FIPS path without redesign or scoping: 2 clusters (GitHub sealed
  boxes, ssh-key Ed25519 backend).

## Toolchain findings

The dev machine (macOS arm64) meets every aws-lc-fips-sys build
requirement:

| Tool | Version | Path |
|---|---|---|
| cmake | 4.4.3 | /opt/homebrew/bin/cmake |
| go | 1.27.0 | /opt/homebrew/bin/go |
| perl | 5.34.1 | /usr/bin/perl |
| rustc | 1.95.0 | (rustup) |

The FIPS build also compiled `clang-sys`/bindgen locally, so libclang is a
de facto requirement on macOS hosts (Linux x86_64/aarch64 targets ship
pregenerated bindings).

## Build attempts

All at `cargo check` level, on a warm cache. Baseline first: the untouched
tree checks green in 28s.

Attempt 1, feature-only swap. Changed workspace `Cargo.toml:101` from
`rustls = { version = "0.23.45", features = ["ring"] }` to
`features = ["aws-lc-rs"]`. Result: green, zero errors, but inert. The
`rustls::crypto::ring` call sites still compiled because reqwest and
hyper-rustls re-enable `rustls/ring` additively (`cargo tree` shows rustls
0.23.43 with both `aws_lc_rs` and `ring` features), and the runtime provider
is still selected by the explicit `install_default()` calls.

Attempt 2, real provider swap. Additionally changed the seven
`rustls::crypto::ring::default_provider()` references to
`rustls::crypto::aws_lc_rs::default_provider()` (`crates/opaqued/src/main.rs:759`,
`crates/opaque-approver/src/client.rs:94,191`, plus four test-harness sites
in opaque-approval). Result: `cargo check --workspace --all-targets` green,
zero errors. The entire non-FIPS swap is one feature flag and seven lines.

Attempt 3, FIPS. Changed the feature list to `["aws-lc-rs", "fips"]`. Cargo
resolved aws-lc-rs 1.18.1 with its `fips` feature and aws-lc-fips-sys
0.14.2, ran the full CMake and Go build of the FIPS module, and the whole
workspace checked green in 30.75s, including `--all-targets`. No errors of
any kind. jsonwebtoken 10.4.0 recompiled against the FIPS-enabled aws-lc-rs
in the same pass, confirming feature unification carries the JWT paths onto
the module.

Reverted everything afterward (the feature line and the seven source
lines); `cargo check --workspace` is green on the reverted tree and
`Cargo.lock` returned to byte-identical (cargo prunes the FIPS packages on
re-resolve).

Caveats on what this proves: compile-level compatibility only. No runtime
TLS handshake was exercised under the FIPS provider, and no `cargo test` run
was made against the FIPS build. Given this project's track record of
compile-green bugs surfacing only against a live daemon, the first migration
PR should include a live handshake and approval-flow test under the FIPS
provider. Separately, a FIPS 140-3 certificate covers specific operating
environments; the macOS arm64 build demonstrated here is developer
convenience, not a validated OE. Deployment claims should name the module
certificate and its listed environments (Linux x86_64/aarch64 are the
relevant ones for the daemon).

## Migration plan, ordered by effort

1. Delete the unused direct `ring` dependency from
   `crates/opaqued/Cargo.toml:43`. Minutes.
2. Provider swap: workspace feature `ring` to `aws-lc-rs` plus the seven
   call sites, exactly as in attempt 2. Hours, already proven green.
3. rcgen backend: switch the workspace rcgen declaration to its
   `aws_lc_rs` feature so approval-server certificate generation uses the
   same stack. Hours.
4. Graph trim: reqwest to `rustls-tls-no-provider` (both the 0.12
   declaration and the jsonschema-pulled 0.13), tokio-rustls to
   `default-features = false` with explicit features, then verify
   `cargo tree | grep ring` is empty. A day including verification, because
   reqwest then depends on the process-default provider being installed
   before any client is built, which needs an ordering audit around
   `crates/opaqued/src/main.rs:759`.
5. FIPS build variant: a `fips` cargo feature on opaqued (and the other
   binaries) forwarding to `rustls/fips`, default off, plus a startup
   assertion (`aws_lc_rs::try_fips_mode()`) so a FIPS-built daemon refuses
   to run outside FIPS mode silently. A day with tests.
6. sha2 and hmac migration to `aws_lc_rs::digest` / `aws_lc_rs::hmac`.
   Mechanical but touches roughly a dozen files across five crates; the
   audit-chain and seal code (`crates/opaque-core/src/audit.rs`,
   `seal.rs`) needs golden-value tests proving identical output before and
   after. Days.
7. p256 WebAuthn verification to aws-lc-rs ECDSA P-256
   (`crates/opaque-approval/src/fido2.rs`). A day with the existing FIDO2
   test vectors.
8. ed25519-dalek migration to aws-lc-rs Ed25519 across seven crates,
   preserving the 32-byte seed storage format and moving keygen onto the
   module DRBG. The widest item; existing signatures and stored keys must
   verify unchanged. A week-scale item with compatibility tests.
9. ssh-key backend decision (class c): custom signer plumbing, upstream
   contribution, or documented deviation. Unbounded until scoped.
10. GitHub sealed-box documentation (class c): a paragraph in the control
    mapping scoping it outside the module boundary, plus a config switch to
    disable the feature for deployments that require it. Hours.

Items 1 through 5 produce a credible "FIPS-capable TLS" story. Items 6
through 8 are what makes the product's own security claims (audit chain,
approvals, identity) run on validated crypto, and they are where the real
effort lives.

## CI implications

The FIPS build is a build variant, not the default. The default build stays
on the current stack until the migration lands; nothing in this assessment
changes the shipped artifacts.

- A `fips` variant job needs cmake, go, and perl on the runner.
  ubuntu-latest images carry all three; pin and print their versions in the
  job so CMVP-relevant toolchain drift is visible in logs.
- The aws-lc-fips-sys cold build adds several minutes of CMake and Go
  compilation; cache the cargo build directory keyed on the aws-lc-fips-sys
  version.
- macOS FIPS-variant jobs additionally need libclang for bindgen. Linux
  x86_64/aarch64 use pregenerated bindings and do not.
- The variant job should run `cargo check --workspace --all-targets
  --features fips` at minimum, and the live-daemon handshake test once item
  5 of the migration plan exists.
- Release artifacts for the FIPS variant are a separate matrix entry with
  distinct names; a FIPS binary and a default binary must never be
  interchangeable in the release pipeline, because the claim attaches to
  the artifact.
