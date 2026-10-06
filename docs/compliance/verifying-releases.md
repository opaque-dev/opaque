# Verifying a release

Tagged releases publish platform archives with checksums, Sigstore signatures
and signed SBOMs. The unreleased workflow also embeds dependency manifests in
each Rust binary and checks their presence after packaging. This does not change
previously published archives. SLSA provenance attestation remains proposed and
is not wired into the current release workflow.

These checks identify the downloaded bytes, the signing workflow and linked
Rust dependencies. They do not replace source review or deployment qualification.

Commands below use `opaque-0.3.0-x86_64-unknown-linux-gnu.tar.gz` as the
example artifact. Substitute the file for the platform and version you
downloaded, and run every command from the directory holding the downloaded
files.

## 1. Checksum

```sh
shasum -a 256 -c opaque-0.3.0-x86_64-unknown-linux-gnu.tar.gz.sha256
```

This only proves the download was not corrupted or truncated in transit. A
checksum published next to the file it checks proves nothing about who
produced the file; treat a checksum mismatch as a hard stop, and treat a
match as step one, not as verification on its own.

## 2. Sigstore signature (tarball and SBOM)

Releases are signed keylessly with [cosign](https://docs.sigstore.dev/cosign/overview/),
using the GitHub Actions OIDC identity of the `release.yml` workflow rather
than a long-lived private key. Verify the tarball:

```sh
cosign verify-blob \
  --certificate opaque-0.3.0-x86_64-unknown-linux-gnu.tar.gz.pem \
  --signature   opaque-0.3.0-x86_64-unknown-linux-gnu.tar.gz.sig \
  --certificate-identity-regexp 'https://github\.com/(kcirtapfromspace|opaque-dev)/opaque/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  opaque-0.3.0-x86_64-unknown-linux-gnu.tar.gz
```

Releases up to and including v0.4.0 were signed before the repository moved
to the `opaque-dev` organization, so their certificates name
`kcirtapfromspace/opaque`; later releases name `opaque-dev/opaque`. The
pattern above accepts exactly those two owners and nothing else.

Verify the CycloneDX SBOM the same way, pointing at its own `.sig`/`.pem`
pair:

```sh
cosign verify-blob \
  --certificate opaque-0.3.0-opaque.cdx.json.pem \
  --signature   opaque-0.3.0-opaque.cdx.json.sig \
  --certificate-identity-regexp 'https://github\.com/(kcirtapfromspace|opaque-dev)/opaque/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  opaque-0.3.0-opaque.cdx.json
```

`cosign` prints `Verified OK` and echoes the certificate's transparency-log
entry on success. This proves the file matches exactly what a run of the
named workflow, in this repository, signed at build time; it does not by
itself prove which commit or which inputs that run used, which is what the
next section adds. Confirm current flag names with `cosign verify-blob
--help` if a `cosign` upgrade changes them.

## 3. SLSA build provenance

*Proposed; the current release workflow does not emit this attestation.*

A future release workflow could attest each release tarball with
[`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance),
which records the source repository, commit, and workflow run that produced
it as a signed, transparency-logged statement. The GitHub CLI verifies this
directly:

```sh
gh attestation verify opaque-0.3.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo opaque-dev/opaque
```

This checks a `https://slsa.dev/provenance/v1` predicate by default and
confirms both the artifact's digest and the identity of the workflow that
built it, giving you the commit-level linkage the signature check alone
does not. It requires `gh` to reach the GitHub API (`gh auth status` should
already be set up, or use `--owner opaque-dev` in place of `--repo` if
you would rather not pin the exact repository name); offline verification
against a locally downloaded attestation bundle is also available, see `gh
attestation verify --help`.

## 4. Embedded dependency manifest

*Wired in unreleased source. Use release notes to confirm availability for a tagged archive.*

Each release binary (`opaqued`, `opaque`, `opaque-mcp`,
`opaque-approve-helper`, `opaque-approver`, `opaque-web`, and the two
auxiliary binaries `opaque-mcp-contract` and `opaque-evidence`) is built
with `cargo auditable build`, which links the exact dependency tree,
including versions, into the compiled binary itself: a `Cargo.lock` handed
to you separately from the binary could always have been tampered with
independently of it, but data linked into the binary you already checksummed
and signature-verified above cannot be swapped out on its own. Extract and
audit it with
[`cargo-audit`](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
after installing it (`cargo install cargo-audit`):

```sh
tar xzf opaque-0.3.0-x86_64-unknown-linux-gnu.tar.gz opaque
cargo audit bin opaque
```

This reports the full dependency list `cargo-audit` extracted from the
binary and cross-references it against the RustSec advisory database,
independent of whatever CI produced the binary. The unreleased release gate
(`scripts/verify_auditable_binary.py`) uses bounded, offline
[`rust-audit-info`](https://github.com/rust-secure-code/cargo-auditable/tree/master/rust-audit-info)
extraction on all eight standalone Rust binaries and both Rust copies in the
macOS reviewer app after signing and notarization. It rejects missing data;
it does not consult an advisory database. `cargo audit bin` can also guess
partial dependencies in binaries without embedded data, so a parseable audit
report alone does not prove a complete embedded manifest exists. A clean `cargo audit bin` result reports the
dependency list with no forced network fetch of the binary's own build
inputs: everything it verifies came from the binary you already downloaded
and checksummed above.

## Putting it together

Each layer answers a different question:

| Check | Answers |
|---|---|
| Checksum | Did the download arrive intact? |
| Cosign signature | Did this exact repository's release workflow produce this exact file? |
| SLSA provenance (proposed) | Which commit, and which workflow run, built this file? |
| `cargo audit bin` | What did that build actually link in, and is any of it known-vulnerable? |

None of the four is a substitute for the others: a matching checksum says
nothing about authorship, a valid signature says nothing about which source
commit was built, and a clean dependency audit says nothing about whether
the archive you have was tampered with after signing. Run the available checks together for
a release you are about to deploy, especially into an environment where
`trust_domain.enforce = true` ([hardening guide](hardening.md)) makes the
binary itself part of the trust boundary.
