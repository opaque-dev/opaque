{
  description = "Opaque on NixOS: package, opaqued module and machine tests";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      rust-overlay,
    }:
    let
      # Linux only: the macOS build needs Apple frameworks this flake does not
      # model. Release archives still come from release.yml, not from here.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            }
          )
        );
    in
    {
      packages = forSystems (pkgs: rec {
        opaque = pkgs.callPackage ./nix/package.nix {
          craneLib = (crane.mkLib pkgs).overrideToolchain (
            p: p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml
          );
          revision = self.rev or null;
        };
        default = opaque;
      });

      nixosModules.opaqued = import ./nix/module.nix;
      nixosModules.default = self.nixosModules.opaqued;

      checks = forSystems (pkgs: {
        power-cut = pkgs.testers.runNixOSTest (
          import ./nix/tests/power-cut.nix {
            module = self.nixosModules.opaqued;
            opaque = self.packages.${pkgs.stdenv.hostPlatform.system}.opaque;
          }
        );
      });
    };
}
