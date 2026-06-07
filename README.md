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
  time                 42.04 μs   (42.00 μs .. 42.11 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 42.08 μs   (42.05 μs .. 42.13 μs)
  std dev              139.4 ns   (100.1 ns .. 198.1 ns)

  benchmarking schnorr/verify_schnorr'
  time                 88.88 μs   (88.69 μs .. 89.17 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 88.85 μs   (88.70 μs .. 89.25 μs)
  std dev              747.4 ns   (346.3 ns .. 1.409 μs)

  benchmarking ecdsa/sign_ecdsa' (large)
  time                 25.76 μs   (25.73 μs .. 25.80 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 25.76 μs   (25.74 μs .. 25.81 μs)
  std dev              105.5 ns   (49.05 ns .. 205.4 ns)

  benchmarking ecdsa/verify_ecdsa'
  time                 85.66 μs   (85.60 μs .. 85.72 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 85.65 μs   (85.59 μs .. 85.71 μs)
  std dev              190.2 ns   (155.3 ns .. 247.4 ns)

  benchmarking ecdh/ecdh (large)
  time                 88.01 μs   (87.80 μs .. 88.30 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 87.94 μs   (87.81 μs .. 88.13 μs)
  std dev              492.2 ns   (361.8 ns .. 701.2 ns)
```

Ensure you compile with the 'llvm' flag (and that [ppad-fixed][fixed]
and [ppad-sha256][sha256] have been compiled with the 'llvm' flag) for
maximum performance.

## Security

(See both a [security analysis](https://ppad.tech/security-analysis-secp256k1)
and follow-up [assembly analysis](https://ppad.tech/static-assembly-analysis)
of the library at [ppad.tech](https://ppad.tech).)

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
  time                 16.63 μs   (16.58 μs .. 16.67 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 16.54 μs   (16.50 μs .. 16.58 μs)
  std dev              138.3 ns   (123.6 ns .. 156.4 ns)

  benchmarking derive_pub/wnaf, sk = 2 ^ 255 - 19
  time                 16.63 μs   (16.61 μs .. 16.66 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 16.63 μs   (16.60 μs .. 16.65 μs)
  std dev              75.03 ns   (59.63 ns .. 101.5 ns)

  benchmarking schnorr/sign_schnorr' (small)
  time                 42.12 μs   (42.06 μs .. 42.22 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 42.13 μs   (42.08 μs .. 42.22 μs)
  std dev              245.3 ns   (120.9 ns .. 390.8 ns)

  benchmarking schnorr/sign_schnorr' (large)
  time                 42.04 μs   (42.00 μs .. 42.11 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 42.08 μs   (42.05 μs .. 42.13 μs)
  std dev              139.4 ns   (100.1 ns .. 198.1 ns)

  benchmarking ecdsa/sign_ecdsa' (small)
  time                 25.76 μs   (25.74 μs .. 25.77 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 25.75 μs   (25.74 μs .. 25.77 μs)
  std dev              52.46 ns   (42.15 ns .. 68.26 ns)

  benchmarking ecdsa/sign_ecdsa' (large)
  time                 25.76 μs   (25.73 μs .. 25.80 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 25.76 μs   (25.74 μs .. 25.81 μs)
  std dev              105.5 ns   (49.05 ns .. 205.4 ns)

  benchmarking ecdh/ecdh (small)
  time                 87.40 μs   (87.33 μs .. 87.49 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 87.41 μs   (87.34 μs .. 87.48 μs)
  std dev              218.7 ns   (176.6 ns .. 274.3 ns)

  benchmarking ecdh/ecdh (large)
  time                 88.01 μs   (87.80 μs .. 88.30 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 87.94 μs   (87.81 μs .. 88.13 μs)
  std dev              492.2 ns   (361.8 ns .. 701.2 ns)
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
