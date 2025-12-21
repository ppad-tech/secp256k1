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
  time                 77.54 μs   (77.14 μs .. 78.16 μs)
                       1.000 R²   (0.999 R² .. 1.000 R²)
  mean                 77.27 μs   (77.11 μs .. 77.63 μs)
  std dev              802.7 ns   (166.4 ns .. 1.331 μs)

  benchmarking schnorr/verify_schnorr'
  time                 161.1 μs   (160.9 μs .. 161.3 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 160.9 μs   (160.6 μs .. 161.0 μs)
  std dev              618.3 ns   (374.1 ns .. 1.070 μs)

  benchmarking ecdsa/sign_ecdsa' (large)
  time                 72.37 μs   (72.32 μs .. 72.43 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 72.50 μs   (72.43 μs .. 72.60 μs)
  std dev              268.5 ns   (167.6 ns .. 413.0 ns)

  benchmarking ecdsa/verify_ecdsa'
  time                 151.8 μs   (151.6 μs .. 152.0 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 152.0 μs   (151.8 μs .. 152.3 μs)
  std dev              781.7 ns   (421.4 ns .. 1.175 μs)
```

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
  time                 27.08 μs   (27.07 μs .. 27.10 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 27.10 μs   (27.09 μs .. 27.12 μs)
  std dev              60.01 ns   (41.51 ns .. 98.05 ns)

  benchmarking derive_pub/wnaf, sk = 2 ^ 255 - 19
  time                 27.09 μs   (27.07 μs .. 27.11 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 27.09 μs   (27.08 μs .. 27.12 μs)
  std dev              61.41 ns   (34.20 ns .. 116.9 ns)

  benchmarking schnorr/sign_schnorr' (small)
  time                 77.40 μs   (77.11 μs .. 77.87 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 77.32 μs   (77.25 μs .. 77.53 μs)
  std dev              366.0 ns   (197.5 ns .. 704.2 ns)

  benchmarking schnorr/sign_schnorr' (large)
  time                 77.39 μs   (77.33 μs .. 77.45 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 77.36 μs   (77.31 μs .. 77.42 μs)
  std dev              178.8 ns   (147.8 ns .. 222.9 ns)

  benchmarking ecdsa/sign_ecdsa' (small)
  time                 72.32 μs   (72.24 μs .. 72.42 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 72.42 μs   (72.38 μs .. 72.50 μs)
  std dev              199.4 ns   (151.0 ns .. 298.5 ns)

  benchmarking ecdsa/sign_ecdsa' (large)
  time                 72.42 μs   (72.31 μs .. 72.56 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 72.41 μs   (72.37 μs .. 72.49 μs)
  std dev              199.9 ns   (141.9 ns .. 344.1 ns)

  benchmarking ecdh/ecdh (small)
  time                 257.2 μs   (256.9 μs .. 257.5 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 257.0 μs   (256.8 μs .. 257.2 μs)
  std dev              667.5 ns   (480.7 ns .. 973.1 ns)

  benchmarking ecdh/ecdh (large)
  time                 256.9 μs   (256.7 μs .. 257.0 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 256.9 μs   (256.7 μs .. 257.0 μs)
  std dev              369.9 ns   (278.8 ns .. 570.4 ns)
```

Note also that care has been taken to ensure that allocation is held
constant across input sizes for all sensitive operations:

```
  derive_pub

    Case                     Allocated  GCs
    wnaf, sk = 2                   304    0
    wnaf, sk = 2 ^ 255 - 19        304    0

  schnorr

    Case                   Allocated  GCs
    sign_schnorr' (small)     27,104    0
    sign_schnorr' (large)     27,104    0

  ecdsa

    Case                 Allocated  GCs
    sign_ecdsa' (small)     61,624    0
    sign_ecdsa' (large)     61,624    0

  ecdh

    Case          Allocated  GCs
    ecdh (small)      1,880    0
    ecdh (large)      1,880    0
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
