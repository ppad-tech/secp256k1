{
  description = "ppad-secp256k1";

  inputs = {
    nixpkgs = {
      follows = "ppad-sha256/nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    ppad-sha256 = {
      type = "git";
      url  = "git://git.ppad.tech/sha256.git";
      ref  = "v0.1.0";
    };
  };

  outputs = { self, nixpkgs, flake-utils, ppad-sha256 }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "ppad-secp256k1";

        pkgs = import nixpkgs { inherit system; };
        hlib = pkgs.haskell.lib;

        hpkgs = pkgs.haskell.packages.ghc964.override {
          overrides = new: old: {
            ppad-sha256 = ppad-sha256.packages.${system}.ppad-sha256;
            ${lib} = new.callCabal2nix lib ./. { };
          };
        };

        cc    = pkgs.stdenv.cc;
        ghc   = hpkgs.ghc;
        cabal = hpkgs.cabal-install;
      in
        {
          packages.${lib} = hpkgs.${lib};

          packages.default = self.packages.${system}.${lib};

          devShells.default = hpkgs.shellFor {
            packages = p: [
              (hlib.doBenchmark p.${lib})
            ];

            buildInputs = [
              cabal
              cc
            ];

            inputsFrom = builtins.attrValues self.packages.${system};

            doBenchmark = true;

            shellHook = ''
              PS1="[${lib}] \w$ "
              echo "entering ${system} shell, using"
              echo "cc:    $(${cc}/bin/cc --version)"
              echo "ghc:   $(${ghc}/bin/ghc --version)"
              echo "cabal: $(${cabal}/bin/cabal --version)"
            '';
          };
        }
      );
}

