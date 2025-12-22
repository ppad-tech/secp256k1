{
  description = "Pure Haskell Schnorr, ECDSA on secp256k1";

  inputs = {
    ppad-nixpkgs = {
      type = "git";
      url  = "git://git.ppad.tech/nixpkgs.git";
      ref  = "master";
    };
    ppad-base16 = {
      type = "git";
      url  = "git://git.ppad.tech/base16.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    ppad-sha256 = {
      type = "git";
      url  = "git://git.ppad.tech/sha256.git";
      ref  = "master";
      inputs.ppad-base16.follows = "ppad-base16";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    # transitive dependency via ppad-hmac-drbg
    ppad-sha512 = {
      type = "git";
      url  = "git://git.ppad.tech/sha512.git";
      ref  = "master";
      inputs.ppad-base16.follows = "ppad-base16";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    ppad-hmac-drbg = {
      type = "git";
      url  = "git://git.ppad.tech/hmac-drbg.git";
      ref  = "master";
      inputs.ppad-base16.follows = "ppad-base16";
      inputs.ppad-sha256.follows = "ppad-sha256";
      inputs.ppad-sha512.follows = "ppad-sha512";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    ppad-fixed = {
      type = "git";
      url  = "git://git.ppad.tech/fixed.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    flake-utils.follows = "ppad-nixpkgs/flake-utils";
    nixpkgs.follows = "ppad-nixpkgs/nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, ppad-nixpkgs
            , ppad-base16
            , ppad-sha256, ppad-sha512
            , ppad-hmac-drbg
            , ppad-fixed
            }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "ppad-secp256k1";

        pkgs = import nixpkgs { inherit system; };
        hlib = pkgs.haskell.lib;
        llvm  = pkgs.llvmPackages_15.llvm;

        base16 = ppad-base16.packages.${system}.default;

        fixed = ppad-fixed.packages.${system}.default;
        fixed-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag fixed "llvm")
            [ llvm ];

        sha256 = ppad-sha256.packages.${system}.default;
        sha256-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag sha256 "llvm")
            [ llvm ];

        hmac-drbg = ppad-hmac-drbg.packages.${system}.default;
        hmac-drbg-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag hmac-drbg "llvm")
            [ llvm ];

        hpkgs = pkgs.haskell.packages.ghc981.extend (new: old: {
          ppad-base16 = base16;
          ppad-sha256 = sha256-llvm;
          ppad-hmac-drbg = hmac-drbg-llvm;
          ppad-fixed = fixed-llvm;
          ${lib} = new.callCabal2nix lib ./. {
            ppad-base16 = new.ppad-base16;
            ppad-sha256 = new.ppad-sha256;
            ppad-hmac-drbg = new.ppad-hmac-drbg;
            ppad-fixed = new.ppad-fixed;
          };
        });

        cabal = hpkgs.cabal-install;
        cc    = pkgs.stdenv.cc;
        ghc   = hpkgs.ghc;
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
              llvm
            ];

            doBenchmark = true;

            shellHook = ''
              PS1="[${lib}] \w$ "
              echo "entering ${system} shell, using"
              echo "cabal: $(${cabal}/bin/cabal --version)"
              echo "cc:    $(${cc}/bin/cc --version)"
              echo "ghc:   $(${ghc}/bin/ghc --version)"
              echo "llc:   $(${llvm}/bin/llc --version | head -2 | tail -1)"
            '';
          };
        }
      );
}

