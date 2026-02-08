# secp256k1

[![](https://img.shields.io/hackage/v/ppad-secp256k1?color=blue)](https://hackage.haskell.org/package/ppad-secp256k1)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-secp256k1-lightblue)](https://docs.ppad.tech/secp256k1)

A pure Haskell implementation of [BIP0340][bp340] Schnorr signatures,
deterministic [RFC6979][r6979] ECDSA (with [BIP0146][bp146]-style
"low-S" signatures), ECDH, and various primitives on the elliptic curve
secp256k1.

(See also [ppad-csecp256k1][csecp] for FFI bindings to
bitcoin-core/secp256k1.)

## Usage

A sample GHCi session:

```
  > -- pragmas and b16 import for illustration only; not required
  > :set -XOverloadedStrings
  > :set -XBangPatterns
  > import qualified Data.ByteString.Base16 as B16
  >
  > -- import qualified
  > import qualified Crypto.Curve.Secp256k1 as Secp256k1
  >
  > -- secret, public keys
  > let sec = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
  :{
  ghci| let Just pub = Secp256k1.parse_point . B16.decodeLenient $
  ghci|       "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
  ghci| :}
  >
  > let msg = "i approve of this message"
  >
  > -- create and verify a schnorr signature for the message
  > let Just sig0 = Secp256k1.sign_schnorr sec msg mempty
  > Secp256k1.verify_schnorr msg pub sig0
  True
  >
  > -- create and verify a low-S ECDSA signature for the message
  > let Just sig1 = Secp256k1.sign_ecdsa sec msg
  > Secp256k1.verify_ecdsa msg pub sig1
  True
  >
  > -- for faster signs (especially w/ECDSA) and verifies, use a context
  > let !tex = Secp256k1.precompute
  > Secp256k1.verify_schnorr' tex msg pub sig0
  True
```

## Documentation

Haddocks (API documentation, etc.) are hosted at
[docs.ppad.tech/secp256k1][hadoc].

## Performance

The aim is best-in-class performance for pure Haskell code.

Current benchmark figures on an M4 MacBook Air look like (use `cabal
bench` to run the benchmark suite):

```
  benchmarking schnorr/sign_schnorr' (large)
  time                 76.57 μs   (76.46 μs .. 76.73 μs)
                       1.000 R²   (0.999 R² .. 1.000 R²)
  mean                 77.81 μs   (77.23 μs .. 79.13 μs)
  std dev              2.732 μs   (1.296 μs .. 5.251 μs)

  benchmarking schnorr/verify_schnorr'
  time                 112.8 μs   (112.4 μs .. 113.1 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 112.4 μs   (112.0 μs .. 112.8 μs)
  std dev              1.246 μs   (1.023 μs .. 1.554 μs)

  benchmarking ecdsa/sign_ecdsa' (large)
  time                 44.02 μs   (44.00 μs .. 44.03 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 43.99 μs   (43.97 μs .. 44.01 μs)
  std dev              58.86 ns   (46.66 ns .. 72.16 ns)

  benchmarking ecdsa/verify_ecdsa'
  time                 105.1 μs   (104.8 μs .. 105.4 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 104.8 μs   (104.4 μs .. 105.8 μs)
  std dev              2.037 μs   (1.170 μs .. 3.692 μs)

  benchmarking ecdh/ecdh (large)
  time                 138.5 μs   (137.8 μs .. 139.4 μs)
                       1.000 R²   (0.999 R² .. 1.000 R²)
  mean                 137.8 μs   (137.4 μs .. 138.4 μs)
  std dev              1.584 μs   (1.119 μs .. 2.541 μs)
```

Ensure you compile with the 'llvm' flag (and that [ppad-fixed][fixed]
and [ppad-sha256][sha256] have been compiled with the 'llvm' flag) for
maximum performance.

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be [challenging to achieve][const].

The Schnorr implementation within has been tested against the [official
BIP0340 vectors][ut340], and ECDSA and ECDH have been tested against the
relevant [Wycheproof vectors][wyche] (with the former also being tested
against [noble-secp256k1's][noble] vectors), so their implementations
are likely to be accurate and safe from attacks targeting e.g.
faulty nonce generation or malicious inputs for signature or public
key parameters.

Timing-sensitive operations, e.g. elliptic curve scalar multiplication,
have been explicitly written so as to execute in time constant with
respect to secret data. Moreover, fixed-size (256-bit) wide words with
constant-time operations provided by [ppad-fixed][fixed] are used
exclusively internally, avoiding timing variations incurred by use of
GHC's variable-size Integer type.

Criterion benchmarks attest that any timing variation between cases with
differing inputs is attributable to noise:

```
  benchmarking derive_pub/wnaf, sk = 2
  time                 29.67 μs   (29.64 μs .. 29.71 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 29.68 μs   (29.64 μs .. 29.71 μs)
  std dev              121.1 ns   (83.80 ns .. 177.2 ns)

  benchmarking derive_pub/wnaf, sk = 2 ^ 255 - 19
  time                 29.68 μs   (29.65 μs .. 29.72 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 29.71 μs   (29.68 μs .. 29.75 μs)
  std dev              106.7 ns   (71.74 ns .. 174.7 ns)

  benchmarking schnorr/sign_schnorr' (small)
  time                 76.27 μs   (76.21 μs .. 76.32 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 76.44 μs   (76.40 μs .. 76.50 μs)
  std dev              162.3 ns   (123.1 ns .. 246.7 ns)

  benchmarking schnorr/sign_schnorr' (large)
  time                 76.35 μs   (76.31 μs .. 76.38 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 76.37 μs   (76.35 μs .. 76.40 μs)
  std dev              84.10 ns   (67.03 ns .. 112.7 ns)

  benchmarking ecdsa/sign_ecdsa' (small)
  time                 43.95 μs   (43.89 μs .. 44.02 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 44.04 μs   (43.96 μs .. 44.15 μs)
  std dev              310.2 ns   (259.9 ns .. 384.6 ns)

  benchmarking ecdsa/sign_ecdsa' (large)
  time                 44.02 μs   (44.00 μs .. 44.03 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 43.99 μs   (43.97 μs .. 44.01 μs)
  std dev              58.86 ns   (46.66 ns .. 72.16 ns)

  benchmarking ecdh/ecdh (small)
  time                 143.6 μs   (143.4 μs .. 143.7 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 143.7 μs   (143.3 μs .. 144.6 μs)
  std dev              2.022 μs   (846.9 ns .. 3.402 μs)

  benchmarking ecdh/ecdh (large)
  time                 143.8 μs   (143.7 μs .. 143.9 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 143.8 μs   (143.7 μs .. 143.9 μs)
  std dev              385.2 ns   (265.9 ns .. 544.5 ns)
```

Note also that care has been taken to ensure that allocation is held
constant across input sizes for all sensitive operations:

```
  derive_pub

    Case                     Allocated  GCs
    wnaf, sk = 2                   312    0
    wnaf, sk = 2 ^ 255 - 19        312    0

  schnorr

    Case                   Allocated  GCs
    sign_schnorr' (small)     14,416    0
    sign_schnorr' (large)     14,416    0

  ecdsa

    Case                   Allocated  GCs
    sign_ecdsa' (small)      1,560    0
    sign_ecdsa' (large)      1,560    0

  ecdh

    Case          Allocated  GCs
    ecdh (small)        616    0
    ecdh (large)        616    0

```

Though constant-resource execution is enforced rigorously, take
reasonable security precautions as appropriate. You shouldn't deploy the
implementations within in any situation where they could easily be used
as an oracle to construct a [timing attack][timea], and you shouldn't
give sophisticated malicious actors [access to your computer][flurl].

If you discover any vulnerabilities, please disclose them via
security@ppad.tech.

## Development

You'll require [Nix][nixos] with [flake][flake] support enabled. Enter a
development shell with:

```
$ nix develop
```

Then do e.g.:

```
$ cabal repl ppad-secp256k1
```

to get a REPL for the main library.

[bp340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[ut340]: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
[bp146]: https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
[r6979]: https://www.rfc-editor.org/rfc/rfc6979
[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/secp256k1
[wyche]: https://github.com/C2SP/wycheproof
[timea]: https://en.wikipedia.org/wiki/Timing_attack
[flurl]: https://eprint.iacr.org/2014/140.pdf
[const]: https://www.chosenplaintext.ca/articles/beginners-guide-constant-time-cryptography.html
[csecp]: https://git.ppad.tech/csecp256k1
[noble]: https://github.com/paulmillr/noble-secp256k1
[fixed]: https://git.ppad.tech/fixed
[sha256]: https://git.ppad.tech/sha256
