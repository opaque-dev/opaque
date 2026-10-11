# opaque, opaqued and opaque-mcp for Linux machine tests.
#
# Built with the toolchain pinned in rust-toolchain.toml. This is not the
# release artifact: release.yml builds those with cargo-auditable and LTO.
# LTO is off here so the test loop stays short.
{
  lib,
  craneLib,
  revision ? null,
}:
let
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
      # opaque-web embeds the brand allowlist via #[path].
      ../assets/brand
      # opaque-core tests include reviewed fuzz seeds.
      ../fuzz/corpus
    ];
  };

  commonArgs = {
    inherit src;
    pname = "opaque";
    version = (lib.importTOML ../Cargo.toml).workspace.package.version;
    strictDeps = true;
    cargoExtraArgs = "--locked -p opaque -p opaqued -p opaque-mcp";
    CARGO_PROFILE_RELEASE_LTO = "false";
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "16";
    doCheck = false;
  }
  # build.rs falls back to "unknown" without .git; a clean flake supplies the
  # full commit, which build.rs requires to be 40 lowercase hex characters.
  // lib.optionalAttrs (revision != null) { OPAQUE_BUILD_REVISION = revision; };
in
craneLib.buildPackage (
  commonArgs
  // {
    # Nothing here runs clippy, so skip crane's extra `cargo check` pass.
    cargoArtifacts = craneLib.buildDepsOnly (commonArgs // { cargoCheckCommand = "true"; });
    meta = {
      description = "Opaque broker daemon, CLI and MCP adapter";
      homepage = "https://github.com/opaque-dev/opaque";
      license = lib.licenses.asl20;
      mainProgram = "opaque";
      platforms = lib.platforms.linux;
    };
  }
)
