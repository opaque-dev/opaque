# Verify a release artifact

Download the selected platform archive, its `.sha256`, `.sig` and `.pem` files,
and the signed SBOMs from the same [release](https://github.com/opaque-dev/opaque/releases).
The checked-in [release workflow](https://github.com/opaque-dev/opaque/blob/main/.github/workflows/release.yml)
builds archives, publishes checksums, and signs archives and per-binary CycloneDX
SBOMs with cosign. Check the workflow at the selected tag before assuming a
historical release has the same evidence.

Examples below use the v0.6.0 Linux x86-64 archive. Run them in the download
directory, substituting your exact version/platform filenames.

## 1. Checksum

```sh
shasum -a 256 -c opaque-0.6.0-x86_64-unknown-linux-gnu.tar.gz.sha256
```

A match checks file integrity against the published digest. It does not identify
the producer. Stop on a mismatch.

## 2. Sigstore signature (tarball and SBOM)

Releases are signed keylessly with [cosign](https://docs.sigstore.dev/cosign/overview/),
using the GitHub Actions OIDC identity of the `release.yml` workflow rather
than a long-lived private key. Verify the tarball:

```sh
cosign verify-blob \
  --certificate opaque-0.6.0-x86_64-unknown-linux-gnu.tar.gz.pem \
  --signature   opaque-0.6.0-x86_64-unknown-linux-gnu.tar.gz.sig \
  --certificate-identity-regexp 'https://github\.com/(kcirtapfromspace|opaque-dev)/opaque/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  opaque-0.6.0-x86_64-unknown-linux-gnu.tar.gz
```

Releases up to and including v0.4.0 were signed before the repository moved
to the `opaque-dev` organization, so their certificates name
`kcirtapfromspace/opaque`; later releases name `opaque-dev/opaque`. The
pattern above accepts exactly those two owners and nothing else.

Verify the CycloneDX SBOM the same way, pointing at its own `.sig`/`.pem`
pair:

```sh
cosign verify-blob \
  --certificate opaque-0.6.0-opaque.cdx.json.pem \
  --signature   opaque-0.6.0-opaque.cdx.json.sig \
  --certificate-identity-regexp 'https://github\.com/(kcirtapfromspace|opaque-dev)/opaque/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  opaque-0.6.0-opaque.cdx.json
```

A valid signature binds the bytes to the accepted workflow identity. Inspect the
certificate identity and expected release tag; it does not establish safe code
or complete build-input provenance. See the
[Sigstore verification reference](https://docs.sigstore.dev/cosign/verifying/verify/)
for certificate/signature and bundle formats.

## Evidence not supplied by the current workflow

The checked-in workflow uses `cargo build`, not `cargo auditable build`, and has
no `actions/attest-build-provenance` step. Helper scripts and proposed procedures
do not establish an embedded dependency manifest or SLSA provenance for an
existing binary. Do not treat absent evidence as successful verification.

| Evidence | What to inspect |
| --- | --- |
| Checksum | Download bytes match the published digest |
| Cosign signature | Bytes match an accepted repository/workflow signing identity |
| Signed SBOM | The signer supplied this dependency inventory; compare it with the selected build |
| Source and tests | Implementation and test evidence for the chosen operation |

These checks do not establish reproducible builds, a trustworthy runtime host,
regulatory certification or customer operating effectiveness. Continue with
[deployment verification](../evaluation-guide.md) before granting broker custody.
