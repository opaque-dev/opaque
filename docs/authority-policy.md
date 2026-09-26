# Validate a versioned authority policy

The unreleased `AuthorityPolicy` v1alpha1 format describes finite support-case
status authority. Validation and compilation run offline and create no grants,
approvals, seals, credentials or ledger records.

```sh
opaque authority-policy validate examples/authority-policy/support.yaml --json
opaque authority-policy compile examples/authority-policy/support.yaml --json
opaque authority-policy schema
```

The example at `examples/authority-policy/support.yaml` selects named tenant,
connector and reviewer references. Its `support.case.setStatus` operation maps
to the existing `support.case.set_status` broker operation. A manifest cannot
supply an endpoint, credential, principal or signing key.

`approval.scope: Required` is mandatory. `approval.action` defaults to
`EveryAction`; `WithinApprovedScope` explicitly permits automatic dispatch only
inside a separately human-approved, finite scope. A policy is never that
approval. `spec.mode` supports only `Enforce`; `Shadow` and nonempty
`spec.evaluators` fail validation. This version does not invoke Jev.

## Parsing and compiler contract

The parser accepts one UTF-8 YAML or JSON document, at most 64 KiB, 16 nested
levels and 4,096 values/keys. Duplicate keys, YAML aliases, anchors, explicit
tags, merge keys, complex keys and unknown fields are rejected. YAML plain
scalars use JSON boolean/number/null interpretation; quote references that look
like those values. Names, namespaces and references are lowercase DNS labels,
at most 63 bytes. Allowed statuses are `open`, `resolved` and `closed`;
duplicates are rejected. Resource limits are 1–100 and attempts 1–10,000.
`maxDuration` accepts a positive whole `s`, `m` or `h` duration up to 24 hours.

The compiler fills defaults, sorts statuses and normalizes duration to seconds.
Its lowercase hex digest is SHA-256 over `opaque.authority-policy.v1`, one NUL
byte, then compact UTF-8 JSON of the canonical `policy` with every object's keys
sorted lexicographically and no whitespace. There are no floating-point policy
fields. Name, namespace, references, approval requirements and bounds are
included. Comments, property order and equivalent durations do not change it.
`compile` returns `{schemaVersion: 1, digest, identity, policy}`; `validate`
returns `{schemaVersion: 1, valid: true, digest, identity}`. Errors exit 2 with no
successful JSON result. Recompiling the returned `policy` yields the same
digest; hashing the pretty-printed output does not.

## Bind a policy at broker startup

In the isolated broker's operator-controlled, sealed `config.toml`, pin the exact
compiler digest and identity. References must match the manifest and
`tenant_ref` must also match the broker's configured tenant ID:

```toml
[authority_policy]
path = "/etc/opaque/authority-policy/authority-policy.json"
digest = "REPLACE_WITH_COMPILER_DIGEST"
name = "support-status"
namespace = "support"
tenant_ref = "example"
connector_ref = "support-api"
reviewer_ref = "support-approver"
reviewer_id = "REPLACE_WITH_ENROLLED_HUMAN_PRINCIPAL"
reviewer_public_key = "REPLACE_WITH_ENROLLED_PUBLIC_KEY"
generation = 1

[authority_policy.profile]
endpoint = "https://support.example.invalid/v1/"
token_file = "/var/lib/opaque/private/support.token"
```

The local profile and enrolled reviewer remain trusted configuration, bound into
the runtime policy digest. Startup still requires native approval, required
identity, sealed configuration and enforced custody/tenant isolation. Setting
both `[authority_policy]` and `[scope_workflow]` is rejected. Manifest identity
and digest checks precede opening scope ledgers. Bounded regular-file reads
reject FIFOs without blocking. Policy content is nonsecret: root-owned read-only
files and Kubernetes projected-volume symlinks work. Credential custody checks
remain separate.

Activation occurs only on operator-controlled restart after the ordinary seal
process. These commands never seal or activate automatically. File changes do
not alter a running broker; a changed file with an old pin fails startup. The
read-only `opaque scope snapshot` reports `authority_policy.digest` and
`authority_policy.identity` for the running broker. A staged file alone does not
prove activation.

Keep the same tenant, `generation` and private custody directory across policy
edits, removal and reapplication. Generation identifies the ledger owner, not a
policy revision; changing it against existing custody is unsupported. Never
delete a ledger or create fresh custody to activate an update. Consumed attempts,
revoked scopes and `UNKNOWN` outcomes survive restart and rollback. Semantic
changes make old grants/reviews fail current policy checks. An exact rollback
can make otherwise-valid unused authority match again; use explicit scope
revocation for permanent retirement. Neither rollback nor redeployment restores
consumed or revoked authority. New scopes still require human approval.
Historical outcome queries can still return the retained result; that never
authorizes another dispatch.

## Migrate existing TOML without changing the broker

```sh
opaque authority-policy migrate --config /path/to/config.toml \
  --name support-status --namespace support --tenant-ref example \
  --connector-ref support-api --reviewer-ref support-approver > policy.json
opaque authority-policy validate policy.json --json
```

Migration preserves `[scope_workflow]` limits, explicit `exact_action` and omitted
legacy defaults. It emits manifest JSON only on stdout. It does not read the
credential, copy endpoint/key material, edit configuration, change generation,
contact a broker or issue authority. Review the result, retain the existing local
connector/reviewer/custody bindings, replace the selected configuration section,
then use the ordinary operator seal/restart procedure. Existing TOML and its
runtime digest remain unchanged when no manifest is selected. Switching to a
manifest deliberately requires newly reviewed scopes.

## Kubernetes adapters

Core supplies a portable schema and compiler, without a Kubernetes controller.
A staging controller can embed the schema's strict `spec` subtree and invoke
the compiler. Kubernetes owns metadata such as UID, resourceVersion, generation,
creationTimestamp and managedFields, plus status. An adapter must remove only
its documented API-server metadata/status before passing authored
name/namespace/spec to the strict compiler. Reject unknown spec fields before
pruning, or preserve them for compiler rejection; never silently discard them
into a valid policy. The standalone parser rejects extra metadata.

An immutable ConfigMap is staged content, not activation or a grant. Mounting or
deleting it cannot reset budgets, mint approvals or prove a broker loaded it.
Broker-side sealed digest and identity checks remain authoritative.
