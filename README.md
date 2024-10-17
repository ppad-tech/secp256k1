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
  > let sec = Secp256k1.parse_integer "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
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

This library is in a **pre-release** state. It ultimately aims at the
maximum security achievable in a garbage-collected language under an
optimizing compiler such as GHC, in which strict constant-timeness can
be challenging to achieve, but we're not there quite yet.

The Schnorr implementation within has been tested against the [official
BIP0340 vectors][ut340], and ECDSA has been tested against the relevant
[Wycheproof vectors][wyche], so their implementations are likely to be
accurate and safe from attacks targeting e.g. faulty nonce generation or
malicious inputs for signature parameters.

However, the signature schemes are **not** implemented so as to be
constant-time (or constant-allocation) with respect to secrets, and no
effort has yet been made to quantify the degree to which they deviate
from that. Perhaps obviously: you shouldn't deploy the implementations
within in any situation where they can easily be used as an oracle to
construct a [timing attack][timea], and you shouldn't give sophisticated
malicious actors [access to your computer][flurl].

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
