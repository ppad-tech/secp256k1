{
  description = "ppad-secp256k1";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "ppad-secp256k1";

        pkgs = import nixpkgs { inherit system; };
        hlib = pkgs.haskell.lib;

        hpkgs = pkgs.haskell.packages.ghc964;
        # hpkgs = pkgs.haskell.packages.ghc964.override {
        #   overrides = new: old: {
        #     ${lib} = old.callCabal2nix lib ./. {};
        #   };
        # };

        ghc   = hpkgs.ghc;
        cabal = hpkgs.cabal-install;
      in
        {
          # packages.${lib} = hpkgs.${lib};

          # defaultPackage = self.packages.${system}.${lib};

          devShells.default = hpkgs.shellFor {
            packages = p: [
            ];

            buildInputs = [
              cabal
            ];

            inputsFrom = builtins.attrValues self.packages.${system};

            shellHook = ''
              PS1="[${lib}] \w$ "
              echo "entering ${system} shell, using"
              echo "ghc:   $(${ghc}/bin/ghc --version)"
              echo "cabal: $(${cabal}/bin/cabal --version)"
            '';
          };
        }
      );
}

