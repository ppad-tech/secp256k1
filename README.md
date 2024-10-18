# ppad-secp256k1

A pure Haskell implementation of [BIP0340][bp340] Schnorr signatures
and deterministic [RFC6979][r6979] ECDSA (with [BIP0146][bp146]-style
"low-S" signatures) on the elliptic curve secp256k1.

## Usage

A sample GHCi session:

```
  > :set -XOverloadedStrings
  >
  > -- import qualified
  > import qualified Crypto.Curve.Secp256k1 as Secp256k1
  >
  > -- secret, public keys
  > let sec = Secp256k1.parse_int256 "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
  > let Just pub = Secp256k1.parse_point "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
  >
  > let msg = "i approve of this message"
  >
  > -- create and verify a schnorr signature for the message
  > let sig0 = Secp256k1.sign_schnorr sec msg mempty
  > Secp256k1.verify_schnorr msg pub sig0
  True
  >
  > -- create a low-S ECDSA signature for the message
  > let sig1 = Secp256k1.sign_ecdsa sec msg
  >
  > -- verify it
  > Secp256k1.verify_ecdsa msg pub sig1
  > True
```

## Documentation

Haddocks (API documentation, etc.) are hosted at
[docs.ppad.tech/secp256k1][hadoc].

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be [challenging to achieve][const].

The Schnorr implementation within has been tested against the [official
BIP0340 vectors][ut340], and ECDSA has been tested against the relevant
[Wycheproof vectors][wyche], so their implementations are likely to be
accurate and safe from attacks targeting e.g. faulty nonce generation or
malicious inputs for signature parameters. Timing-sensitive operations,
e.g. elliptic curve scalar multiplication, have been explicitly written
so as to execute algorithmically in time constant with respect to secret
data:

```
  benchmarking derive_public/sk = 2
  time                 1.703 ms   (1.680 ms .. 1.728 ms)
                       0.997 R²   (0.995 R² .. 0.999 R²)
  mean                 1.704 ms   (1.684 ms .. 1.730 ms)
  std dev              81.99 μs   (67.86 μs .. 98.34 μs)

  benchmarking derive_public/sk = 2 ^ 255 - 19
  time                 1.686 ms   (1.654 ms .. 1.730 ms)
                       0.998 R²   (0.997 R² .. 0.999 R²)
  mean                 1.658 ms   (1.645 ms .. 1.673 ms)
  std dev              44.75 μs   (34.84 μs .. 59.81 μs)

  benchmarking schnorr/sign_schnorr (small secret)
  time                 5.388 ms   (5.345 ms .. 5.438 ms)
                       1.000 R²   (0.999 R² .. 1.000 R²)
  mean                 5.429 ms   (5.410 ms .. 5.449 ms)
  std dev              58.14 μs   (48.93 μs .. 68.69 μs)

  benchmarking schnorr/sign_schnorr (large secret)
  time                 5.364 ms   (5.324 ms .. 5.410 ms)
                       0.999 R²   (0.999 R² .. 1.000 R²)
  mean                 5.443 ms   (5.414 ms .. 5.486 ms)
  std dev              102.1 μs   (74.16 μs .. 146.4 μs)

  benchmarking ecdsa/sign_ecdsa (small secret)
  time                 1.740 ms   (1.726 ms .. 1.753 ms)
                       1.000 R²   (0.999 R² .. 1.000 R²)
  mean                 1.752 ms   (1.744 ms .. 1.761 ms)
  std dev              32.33 μs   (26.12 μs .. 43.34 μs)

  benchmarking ecdsa/sign_ecdsa (large secret)
  time                 1.748 ms   (1.731 ms .. 1.766 ms)
                       0.999 R²   (0.998 R² .. 0.999 R²)
  mean                 1.756 ms   (1.743 ms .. 1.771 ms)
  std dev              48.99 μs   (40.83 μs .. 62.77 μs)
```

Despite all that, take reasonable security precautions as appropriate.
You probably shouldn't deploy the implementations within in any
situation where they could easily be used as an oracle to construct a
[timing attack][timea], and you shouldn't give sophisticated malicious
actors [access to your computer][flurl].

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
