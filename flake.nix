{
  description = "Pure Haskell cryptographic primitives on secp256k1";

  inputs = {
    ppad-sha256 = {
      type = "git";
      url  = "git://git.ppad.tech/sha256.git";
      ref  = "master";
    };
    ppad-hmac-drbg = {
      type = "git";
      url  = "git://git.ppad.tech/hmac-drbg.git";
      ref  = "master";
    };
    flake-utils.follows = "ppad-sha256/flake-utils";
    nixpkgs.follows = "ppad-sha256/nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, ppad-sha256, ppad-hmac-drbg }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "ppad-secp256k1";

        pkgs = import nixpkgs { inherit system; };
        hlib = pkgs.haskell.lib;

        sha256 = ppad-sha256.packages.${system}.default;
        hmac-drbg = ppad-hmac-drbg.packages.${system}.default;

        hpkgs = pkgs.haskell.packages.ghc981.extend (new: old: {
          ppad-sha256 = sha256;
          ppad-hmac-drbg = hmac-drbg;
          ${lib} = new.callCabal2nix lib ./. {
            ppad-sha256 = new.ppad-sha256;
            ppad-hmac-drbg = new.ppad-hmac-drbg;
          };
        });

        cc    = pkgs.stdenv.cc;
        ghc   = hpkgs.ghc;
        cabal = hpkgs.cabal-install;
      in
        {
          packages.default = hpkgs.${lib};

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

