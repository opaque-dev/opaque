# Build and verify an installable release

Use a release archive whose tools, source revision and version are verified
together. Source-only integration changes remain unavailable through an older
archive. The Homebrew formula must continue pointing at published artifacts
until the new release and its checksums exist.

The release workflow tests the tagged workspace on Linux and macOS before
building. Each archive must contain all eight tools: `opaqued`, `opaque`,
`opaque-mcp`, `opaque-mcp-contract`, `opaque-approve-helper`, `opaque-approver`,
`opaque-evidence`, and `opaque-web`. From v0.6.0 every archive also carries the
`LICENSE`, `LICENSE-DOCS` and `NOTICE` files, and the manifest gate refuses a
payload without them. macOS archives also require the reviewer app.

`opaque-release.json` records the workspace version, exact source revision,
source tree digest and every payload file's hash, size and executable mode.
The gate rejects missing tools, altered files, unexpected payloads, duplicate or
escaping paths, links and privileged file modes. A manifest identifies a build
candidate; it does not claim a signed or live-qualified release. Verify the
archive's published signature and checksum separately.

After the release build and platform packaging steps, run:

```sh
release_revision=$(git rev-parse HEAD)
release_target=$(rustc -vV | sed -n 's/^host: //p')
release_version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')
python3 scripts/release_artifacts.py manifest \
  --binary-dir "target/$release_target/release" \
  --target "$release_target" --version "$release_version" \
  --revision "$release_revision"
```

Include that manifest in the archive with the tools, the three license files
and, on macOS, the complete reviewer app. Then verify the exact archive:

```sh
python3 scripts/release_artifacts.py verify \
  --archive "opaque-$release_version-$release_target.tar.gz" \
  --target "$release_target" --version "$release_version" \
  --revision "$release_revision" --smoke
```

The smoke option executes trusted archive CLIs in an isolated temporary home,
checks command availability and checks the CLI/daemon version. It does not start
a broker, request native approval, contact providers or install globally.
CI smokes binaries where the build runner matches the target; cross-built
archives still need execution on the target architecture.

For a local working-tree candidate, both commands accept `--allow-dirty` and
record its complete source digest. Such a candidate fails the default release
gate. This option is never used by the publishing workflow.

Before publishing, retain acceptance for the exact archive on a fresh supported
host: verified installation, native reviewer enrollment and approval, one useful
provider effect with independent readback, and replay/revocation/restart denial.
For macOS distribution, the existing workflow signs the binaries and app,
submits them to Apple, and staples/verifies the app ticket. Local ad-hoc packaging
does not satisfy that gate. Publish only after these deployment-specific checks
are complete, then update the formula from the downloaded release archives with
`scripts/update-tap.sh`.
