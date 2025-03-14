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
  > let sig0 = Secp256k1.sign_schnorr sec msg mempty
  > Secp256k1.verify_schnorr msg pub sig0
  True
  >
  > -- create and verify a low-S ECDSA signature for the message
  > let sig1 = Secp256k1.sign_ecdsa sec msg
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

Current benchmark figures on a relatively-beefy NixOS VPS look like
(use `cabal bench` to run the benchmark suite):

```
  benchmarking schnorr/sign_schnorr'
  time                 2.584 ms   (2.491 ms .. 2.646 ms)
                       0.994 R²   (0.991 R² .. 0.997 R²)
  mean                 2.459 ms   (2.426 ms .. 2.492 ms)
  std dev              114.5 μs   (95.32 μs .. 142.8 μs)

  benchmarking schnorr/verify_schnorr'
  time                 1.283 ms   (1.263 ms .. 1.301 ms)
                       0.999 R²   (0.998 R² .. 0.999 R²)
  mean                 1.273 ms   (1.260 ms .. 1.284 ms)
  std dev              41.56 μs   (31.12 μs .. 54.35 μs)

  benchmarking ecdsa/sign_ecdsa'
  time                 222.6 μs   (219.9 μs .. 224.9 μs)
                       0.999 R²   (0.999 R² .. 1.000 R²)
  mean                 219.1 μs   (217.8 μs .. 220.5 μs)
  std dev              4.523 μs   (3.525 μs .. 6.158 μs)

  benchmarking ecdsa/verify_ecdsa'
  time                 1.267 ms   (1.260 ms .. 1.276 ms)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 1.278 ms   (1.273 ms .. 1.286 ms)
  std dev              21.32 μs   (15.43 μs .. 30.82 μs)
```

In terms of allocations, we get:

```
schnorr

  Case                   Allocated  GCs
  sign_schnorr'          3,273,824    0
  verify_schnorr'        1,667,360    0

ecdsa

  Case                 Allocated  GCs
  sign_ecdsa'            324,672    0
  verify_ecdsa'        3,796,328    0

ecdh

  Case          Allocated  GCs
  ecdh (small)  2,141,736    0
  ecdh (large)  2,145,464    0
```

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be [challenging to achieve][const].

The Schnorr implementation within has been tested against the [official
BIP0340 vectors][ut340], and ECDSA and ECDH have been tested against
the relevant [Wycheproof vectors][wyche], so their implementations
are likely to be accurate and safe from attacks targeting e.g. faulty
nonce generation or malicious inputs for signature or public key
parameters. Timing-sensitive operations, e.g. elliptic curve scalar
multiplication, have been explicitly written so as to execute
*algorithmically* in time constant with respect to secret data, and
evidence from benchmarks supports this:

```
  benchmarking derive_pub/sk = 2
  time                 1.513 ms   (1.468 ms .. 1.565 ms)
                       0.994 R²   (0.991 R² .. 0.997 R²)
  mean                 1.579 ms   (1.557 ms .. 1.600 ms)
  std dev              74.25 μs   (60.33 μs .. 93.80 μs)

  benchmarking derive_pub/sk = 2 ^ 255 - 19
  time                 1.571 ms   (1.530 ms .. 1.599 ms)
                       0.997 R²   (0.995 R² .. 0.998 R²)
  mean                 1.574 ms   (1.553 ms .. 1.589 ms)
  std dev              57.72 μs   (45.29 μs .. 71.48 μs)

  benchmarking schnorr/sign_schnorr' (small)
  time                 2.436 ms   (2.357 ms .. 2.516 ms)
                       0.995 R²   (0.994 R² .. 0.998 R²)
  mean                 2.563 ms   (2.532 ms .. 2.588 ms)
  std dev              95.87 μs   (71.98 μs .. 127.2 μs)

  benchmarking schnorr/sign_schnorr' (large)
  time                 2.470 ms   (2.372 ms .. 2.543 ms)
                       0.993 R²   (0.989 R² .. 0.997 R²)
  mean                 2.407 ms   (2.374 ms .. 2.443 ms)
  std dev              123.7 μs   (110.7 μs .. 144.9 μs)

  benchmarking ecdsa/sign_ecdsa' (small)
  time                 206.9 μs   (202.7 μs .. 211.8 μs)
                       0.997 R²   (0.996 R² .. 0.999 R²)
  mean                 213.8 μs   (211.5 μs .. 215.9 μs)
  std dev              7.476 μs   (5.572 μs .. 9.698 μs)

  benchmarking ecdsa/sign_ecdsa' (large)
  time                 216.7 μs   (211.6 μs .. 221.7 μs)
                       0.997 R²   (0.995 R² .. 0.999 R²)
  mean                 221.8 μs   (219.5 μs .. 224.1 μs)
  std dev              7.673 μs   (6.124 μs .. 10.69 μs)

  benchmarking ecdh/ecdh (small)
  time                 1.623 ms   (1.605 ms .. 1.639 ms)
                       0.999 R²   (0.998 R² .. 1.000 R²)
  mean                 1.617 ms   (1.603 ms .. 1.624 ms)
  std dev              32.52 μs   (20.66 μs .. 55.97 μs)

  benchmarking ecdh/ecdh (large)
  time                 1.623 ms   (1.580 ms .. 1.661 ms)
                       0.996 R²   (0.992 R² .. 0.998 R²)
  mean                 1.625 ms   (1.606 ms .. 1.641 ms)
  std dev              58.38 μs   (44.31 μs .. 78.23 μs)
```

Due to the use of arbitrary-precision integers, integer division modulo
the elliptic curve group order does display persistent substantial
timing differences on the order of 2 nanoseconds when the inputs differ
dramatically in size (here 2 bits vs 255 bits):

```
  benchmarking remQ (remainder modulo _CURVE_Q)/remQ 2
  time                 27.44 ns   (27.19 ns .. 27.72 ns)
                       1.000 R²   (0.999 R² .. 1.000 R²)
  mean                 27.23 ns   (27.03 ns .. 27.43 ns)
  std dev              669.1 ps   (539.9 ps .. 860.2 ps)

  benchmarking remQ (remainder modulo _CURVE_Q)/remQ (2 ^ 255 - 19)
  time                 29.11 ns   (28.87 ns .. 29.33 ns)
                       0.999 R²   (0.999 R² .. 1.000 R²)
  mean                 29.04 ns   (28.82 ns .. 29.40 ns)
  std dev              882.9 ps   (647.8 ps .. 1.317 ns)
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
