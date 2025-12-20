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

The aim is best-in-class performance for pure, highly-auditable Haskell
code.

Current benchmark figures on an M4 MacBook Air look like (use `cabal
bench` to run the benchmark suite):

```
  benchmarking schnorr/sign_schnorr' (large)
  time                 48.00 μs   (47.93 μs .. 48.09 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 48.01 μs   (47.96 μs .. 48.10 μs)
  std dev              219.6 ns   (121.9 ns .. 407.9 ns)

  benchmarking schnorr/verify_schnorr'
  time                 131.0 μs   (130.7 μs .. 131.4 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 132.0 μs   (131.4 μs .. 133.0 μs)
  std dev              2.521 μs   (1.745 μs .. 3.350 μs)
  variance introduced by outliers: 13% (moderately inflated)

  benchmarking ecdsa/sign_ecdsa' (large)
  time                 58.25 μs   (58.14 μs .. 58.44 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 58.27 μs   (58.19 μs .. 58.44 μs)
  std dev              383.9 ns   (192.0 ns .. 687.1 ns)

  benchmarking ecdsa/verify_ecdsa'
  time                 135.3 μs   (135.2 μs .. 135.5 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 135.5 μs   (135.4 μs .. 135.7 μs)
  std dev              384.2 ns   (271.7 ns .. 558.1 ns)
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
key parameters. Timing-sensitive operations, e.g. elliptic curve
scalar multiplication, have been explicitly written so as to execute
*algorithmically* in time constant with respect to secret data, and
evidence from benchmarks supports this:

```
  benchmarking derive_pub/wnaf, sk = 2
  time                 76.20 μs   (75.62 μs .. 77.33 μs)
                       0.999 R²   (0.998 R² .. 1.000 R²)
  mean                 75.87 μs   (75.61 μs .. 76.48 μs)
  std dev              1.218 μs   (614.3 ns .. 2.291 μs)
  variance introduced by outliers: 11% (moderately inflated)

  benchmarking derive_pub/wnaf, sk = 2 ^ 255 - 19
  time                 76.50 μs   (75.88 μs .. 77.37 μs)
                       0.999 R²   (0.998 R² .. 1.000 R²)
  mean                 76.26 μs   (75.99 μs .. 76.93 μs)
  std dev              1.317 μs   (570.7 ns .. 2.583 μs)
  variance introduced by outliers: 12% (moderately inflated)

  benchmarking schnorr/sign_schnorr' (small)
  time                 1.430 ms   (1.424 ms .. 1.438 ms)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 1.429 ms   (1.425 ms .. 1.433 ms)
  std dev              13.71 μs   (10.48 μs .. 18.85 μs)

  benchmarking schnorr/sign_schnorr' (large)
  time                 1.400 ms   (1.399 ms .. 1.402 ms)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 1.406 ms   (1.404 ms .. 1.408 ms)
  std dev              5.989 μs   (5.225 μs .. 7.317 μs)

  benchmarking ecdsa/sign_ecdsa' (small)
  time                 114.5 μs   (114.0 μs .. 115.3 μs)
                       1.000 R²   (0.999 R² .. 1.000 R²)
  mean                 115.2 μs   (114.8 μs .. 115.8 μs)
  std dev              1.650 μs   (1.338 μs .. 2.062 μs)

  benchmarking ecdsa/sign_ecdsa' (large)
  time                 115.3 μs   (115.1 μs .. 115.7 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 116.0 μs   (115.6 μs .. 116.4 μs)
  std dev              1.367 μs   (1.039 μs .. 1.839 μs)

  benchmarking ecdh/ecdh (small)
  time                 907.0 μs   (902.8 μs .. 912.0 μs)
                       1.000 R²   (0.999 R² .. 1.000 R²)
  mean                 909.5 μs   (907.0 μs .. 913.0 μs)
  std dev              10.05 μs   (6.943 μs .. 17.11 μs)

  benchmarking ecdh/ecdh (large)
  time                 922.9 μs   (911.0 μs .. 937.4 μs)
                       0.999 R²   (0.998 R² .. 1.000 R²)
  mean                 915.8 μs   (911.9 μs .. 922.5 μs)
  std dev              16.84 μs   (9.830 μs .. 26.48 μs)
```

Due to the use of arbitrary-precision integers, integer division modulo
the elliptic curve group order does display persistent substantial
timing differences on the order of 1-2 nanoseconds when the inputs
differ dramatically in size (here 2 bits vs 255 bits):

```
  benchmarking remQ (remainder modulo _CURVE_Q)/remQ 2
  time                 11.13 ns   (11.12 ns .. 11.14 ns)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 11.10 ns   (11.09 ns .. 11.11 ns)
  std dev              33.75 ps   (30.27 ps .. 38.31 ps)

  benchmarking remQ (remainder modulo _CURVE_Q)/remQ (2 ^ 255 - 19)
  time                 12.50 ns   (12.49 ns .. 12.51 ns)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 12.51 ns   (12.51 ns .. 12.52 ns)
  std dev              26.72 ps   (14.45 ps .. 45.87 ps)
```

This represents the worst-case scenario (real-world private keys will
never differ so extraordinarily) and is likely to be well within
acceptable limits for all but the most extreme security requirements.
But because we don't make "hard" guarantees of constant-time execution,
take reasonable security precautions as appropriate. You shouldn't
deploy the implementations within in any situation where they could
easily be used as an oracle to construct a [timing attack][timea],
and you shouldn't give sophisticated malicious actors [access to your
computer][flurl].

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
