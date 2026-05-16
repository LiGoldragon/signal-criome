{
  description = "signal-criome - Signal contract for Criome trust and attestation records";

  inputs = {
    nixpkgs.url = "github:LiGoldragon/nixpkgs?ref=main";

    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";

    crane.url = "github:ipetkov/crane";
  };

  outputs =
    { self, nixpkgs, fenix, crane }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forSystems = function: nixpkgs.lib.genAttrs systems (system: function system);

      mkContext =
        system:
      let
        pkgs = import nixpkgs { inherit system; };
        toolchain = fenix.packages.${system}.stable.withComponents [
          "cargo"
          "rustc"
          "rustfmt"
          "clippy"
          "rust-src"
        ];
        craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
        # Include `examples/` so canonical NOTA examples files are present
        # at build time for `include_str!` in `tests/canonical_examples.rs`.
        examplesFilter = path: _type: builtins.match ".*/examples(/.*)?$" path != null;
        sourceFilter = path: type:
          (craneLib.filterCargoSources path type) || (examplesFilter path type);
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = sourceFilter;
          name = "source";
        };
        cargoVendorDir = craneLib.vendorCargoDeps { inherit src; };
        commonArgs = {
          inherit src cargoVendorDir;
          strictDeps = true;
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
      in
      {
        inherit pkgs toolchain craneLib src commonArgs cargoArtifacts;
      };
    in
    {
      packages = forSystems (
        system:
        let
          context = mkContext system;
        in
        {
          default = context.craneLib.buildPackage (
            context.commonArgs
            // {
              inherit (context) cargoArtifacts;
            }
          );
        }
      );

      checks = forSystems (
        system:
        let
          context = mkContext system;
        in
        {
          build = context.craneLib.cargoBuild (context.commonArgs // { inherit (context) cargoArtifacts; });
          test = context.craneLib.cargoTest (context.commonArgs // { inherit (context) cargoArtifacts; });
          test-round-trip = context.craneLib.cargoTest (
            context.commonArgs
            // {
              inherit (context) cargoArtifacts;
              cargoTestExtraArgs = "--test round_trip";
            }
          );
          test-doc = context.craneLib.cargoTest (
            context.commonArgs
            // {
              inherit (context) cargoArtifacts;
              cargoTestExtraArgs = "--doc";
            }
          );
          doc = context.craneLib.cargoDoc (
            context.commonArgs
            // {
              inherit (context) cargoArtifacts;
              RUSTDOCFLAGS = "-D warnings";
            }
          );
          fmt = context.craneLib.cargoFmt { inherit (context) src; };
          clippy = context.craneLib.cargoClippy (
            context.commonArgs
            // {
              inherit (context) cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- -D warnings";
            }
          );
          rkyv-feature-discipline = context.pkgs.runCommand "signal-criome-rkyv-feature-discipline" { } ''
            ${context.pkgs.gnugrep}/bin/grep -F \
              'rkyv        = { version = "0.8", default-features = false, features = ["std", "bytecheck", "little_endian", "pointer_width_32", "unaligned"] }' \
              ${./Cargo.toml} > /dev/null
            touch $out
          '';
          contract-crate-carries-no-runtime = context.pkgs.runCommand "signal-criome-no-runtime" { } ''
            ! ${context.pkgs.gnugrep}/bin/grep -R -E '(^|[^[:alnum:]_])(kameo|tokio|redb|sema|ractor)([^[:alnum:]_]|$)' ${./Cargo.toml} ${./src}
            touch $out
          '';
        }
      );

      devShells = forSystems (
        system:
        let
          context = mkContext system;
        in
        {
          default = context.pkgs.mkShell {
            name = "signal-criome";
            packages = [
              context.pkgs.jujutsu
              context.pkgs.pkg-config
              context.toolchain
            ];
          };
        }
      );
    };
}
