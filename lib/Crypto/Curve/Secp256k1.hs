{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module: Crypto.Curve.Secp256k1
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Pure [BIP0340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
-- Schnorr signatures, deterministic
-- [RFC6979](https://www.rfc-editor.org/rfc/rfc6979) ECDSA (with
-- [BIP0146](https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki)-style
-- "low-S" signatures), and ECDH shared secret computation
--  on the elliptic curve secp256k1.

module Crypto.Curve.Secp256k1 (
  -- * Field and group parameters
    _CURVE_Q
  , _CURVE_P
  , modQ

  -- * secp256k1 points
  , Pub
  , derive_pub
  , derive_pub'
  , _CURVE_G
  , _CURVE_ZERO

  -- * Parsing
  , parse_int256
  , parse_point
  , parse_sig

  -- * Serializing
  , serialize_point

  -- * ECDH
  , ecdh

  -- * BIP0340 Schnorr signatures
  , sign_schnorr
  , verify_schnorr

  -- * RFC6979 ECDSA
  , ECDSA(..)
  , SigType(..)
  , sign_ecdsa
  , sign_ecdsa_unrestricted
  , verify_ecdsa
  , verify_ecdsa_unrestricted

  -- * Fast variants
  , Context
  , precompute
  , sign_schnorr'
  , verify_schnorr'
  , sign_ecdsa'
  , sign_ecdsa_unrestricted'
  , verify_ecdsa'
  , verify_ecdsa_unrestricted'

  -- Elliptic curve group operations
  , neg
  , add
  , double
  , mul
  , mul_unsafe
  , mul_wnaf

  -- Coordinate systems and transformations
  , Affine(..)
  , Projective(..)
  , affine
  , projective
  , valid

  -- for testing/benchmarking
  , _sign_ecdsa_no_hash
  , _sign_ecdsa_no_hash'
  ) where

import Control.Monad (guard)
import Control.Monad.ST
import qualified Crypto.DRBG.HMAC as DRBG
import qualified Crypto.Hash.SHA256 as SHA256
import Data.Bits ((.&.))
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import qualified Data.Choice as CT
import qualified Data.Maybe as M
import qualified Data.Primitive.Array as A
import Data.STRef
import Data.Word (Word8)
import Data.Word.Limb (Limb(..))
import qualified Data.Word.Limb as L
import Data.Word.Wider (Wider(..))
import qualified Data.Word.Wider as W
import qualified Foreign.Storable as Storable (pokeByteOff)
import qualified GHC.Exts as Exts
import GHC.Generics
import qualified GHC.Int (Int(..))
import qualified GHC.Word (Word(..), Word8(..))
import qualified Numeric.Montgomery.Secp256k1.Curve as C
import qualified Numeric.Montgomery.Secp256k1.Scalar as S
import Prelude hiding (sqrt)

-- utilities ------------------------------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- dumb strict pair
data Pair a b = Pair !a !b

-- convenience pattern
pattern Zero :: Wider
pattern Zero = Wider (# Limb 0##, Limb 0##, Limb 0##, Limb 0## #)

-- convert a Word8 to a Limb
limb :: Word8 -> Limb
limb (GHC.Word.W8# (Exts.word8ToWord# -> w)) = Limb w
{-# INLINABLE limb #-}

-- convert a Limb to a Word8
word8 :: Limb -> Word8
word8 (Limb w) = GHC.Word.W8# (Exts.wordToWord8# w)
{-# INLINABLE word8 #-}

-- convert a Limb to a Word8 after right-shifting
word8s :: Limb -> Exts.Int# -> Word8
word8s l s =
  let !(Limb w) = L.shr# l s
  in  GHC.Word.W8# (Exts.wordToWord8# w)
{-# INLINABLE word8s #-}

-- convert a Word8 to a Wider
word8_to_wider :: Word8 -> Wider
word8_to_wider w = Wider (# limb w, Limb 0##, Limb 0##, Limb 0## #)
{-# INLINABLE word8_to_wider #-}

wider_to_int :: Wider -> Int
wider_to_int (Wider (# Limb l, _, _, _ #)) = GHC.Int.I# (Exts.word2Int# l)
{-# INLINABLE wider_to_int #-}

-- unsafely extract the first 64-bit word from a big-endian-encoded bytestring
unsafe_word0 :: BS.ByteString -> Limb
unsafe_word0 bs =
          (limb (BU.unsafeIndex bs 00) `L.shl#` 56#)
  `L.or#` (limb (BU.unsafeIndex bs 01) `L.shl#` 48#)
  `L.or#` (limb (BU.unsafeIndex bs 02) `L.shl#` 40#)
  `L.or#` (limb (BU.unsafeIndex bs 03) `L.shl#` 32#)
  `L.or#` (limb (BU.unsafeIndex bs 04) `L.shl#` 24#)
  `L.or#` (limb (BU.unsafeIndex bs 05) `L.shl#` 16#)
  `L.or#` (limb (BU.unsafeIndex bs 06) `L.shl#` 08#)
  `L.or#` (limb (BU.unsafeIndex bs 07))
{-# INLINABLE unsafe_word0 #-}

-- unsafely extract the second 64-bit word from a big-endian-encoded bytestring
unsafe_word1 :: BS.ByteString -> Limb
unsafe_word1 bs =
          (limb (BU.unsafeIndex bs 08) `L.shl#` 56#)
  `L.or#` (limb (BU.unsafeIndex bs 09) `L.shl#` 48#)
  `L.or#` (limb (BU.unsafeIndex bs 10) `L.shl#` 40#)
  `L.or#` (limb (BU.unsafeIndex bs 11) `L.shl#` 32#)
  `L.or#` (limb (BU.unsafeIndex bs 12) `L.shl#` 24#)
  `L.or#` (limb (BU.unsafeIndex bs 13) `L.shl#` 16#)
  `L.or#` (limb (BU.unsafeIndex bs 14) `L.shl#` 08#)
  `L.or#` (limb (BU.unsafeIndex bs 15))
{-# INLINABLE unsafe_word1 #-}

-- unsafely extract the third 64-bit word from a big-endian-encoded bytestring
unsafe_word2 :: BS.ByteString -> Limb
unsafe_word2 bs =
          (limb (BU.unsafeIndex bs 16) `L.shl#` 56#)
  `L.or#` (limb (BU.unsafeIndex bs 17) `L.shl#` 48#)
  `L.or#` (limb (BU.unsafeIndex bs 18) `L.shl#` 40#)
  `L.or#` (limb (BU.unsafeIndex bs 19) `L.shl#` 32#)
  `L.or#` (limb (BU.unsafeIndex bs 20) `L.shl#` 24#)
  `L.or#` (limb (BU.unsafeIndex bs 21) `L.shl#` 16#)
  `L.or#` (limb (BU.unsafeIndex bs 22) `L.shl#` 08#)
  `L.or#` (limb (BU.unsafeIndex bs 23))
{-# INLINABLE unsafe_word2 #-}

-- unsafely extract the fourth 64-bit word from a big-endian-encoded bytestring
unsafe_word3 :: BS.ByteString -> Limb
unsafe_word3 bs =
          (limb (BU.unsafeIndex bs 24) `L.shl#` 56#)
  `L.or#` (limb (BU.unsafeIndex bs 25) `L.shl#` 48#)
  `L.or#` (limb (BU.unsafeIndex bs 26) `L.shl#` 40#)
  `L.or#` (limb (BU.unsafeIndex bs 27) `L.shl#` 32#)
  `L.or#` (limb (BU.unsafeIndex bs 28) `L.shl#` 24#)
  `L.or#` (limb (BU.unsafeIndex bs 29) `L.shl#` 16#)
  `L.or#` (limb (BU.unsafeIndex bs 30) `L.shl#` 08#)
  `L.or#` (limb (BU.unsafeIndex bs 31))
{-# INLINABLE unsafe_word3 #-}

-- 256-bit big-endian bytestring decoding. the input size is not checked!
unsafe_roll32 :: BS.ByteString -> Wider
unsafe_roll32 bs =
  let !w0 = unsafe_word0 bs
      !w1 = unsafe_word1 bs
      !w2 = unsafe_word2 bs
      !w3 = unsafe_word3 bs
  in  Wider (# w3, w2, w1, w0 #)
{-# INLINABLE unsafe_roll32 #-}

-- arbitrary-size big-endian bytestring decoding
roll :: BS.ByteString -> Wider
roll = BS.foldl' alg 0 where
  alg !a (word8_to_wider -> !b) = (a `W.shl_limb` 8) `W.or` b
{-# INLINABLE roll #-}

-- 256-bit big-endian bytestring encoding
unroll32 :: Wider -> BS.ByteString
unroll32 (Wider (# w0, w1, w2, w3 #)) =
  BI.unsafeCreate 32 $ \ptr -> do
    -- w0
    Storable.pokeByteOff ptr 00 (word8s w3 56#)
    Storable.pokeByteOff ptr 01 (word8s w3 48#)
    Storable.pokeByteOff ptr 02 (word8s w3 40#)
    Storable.pokeByteOff ptr 03 (word8s w3 32#)
    Storable.pokeByteOff ptr 04 (word8s w3 24#)
    Storable.pokeByteOff ptr 05 (word8s w3 16#)
    Storable.pokeByteOff ptr 06 (word8s w3 08#)
    Storable.pokeByteOff ptr 07 (word8 w3)
    -- w1
    Storable.pokeByteOff ptr 08 (word8s w2 56#)
    Storable.pokeByteOff ptr 09 (word8s w2 48#)
    Storable.pokeByteOff ptr 10 (word8s w2 40#)
    Storable.pokeByteOff ptr 11 (word8s w2 32#)
    Storable.pokeByteOff ptr 12 (word8s w2 24#)
    Storable.pokeByteOff ptr 13 (word8s w2 16#)
    Storable.pokeByteOff ptr 14 (word8s w2 08#)
    Storable.pokeByteOff ptr 15 (word8 w2)
    -- w2
    Storable.pokeByteOff ptr 16 (word8s w1 56#)
    Storable.pokeByteOff ptr 17 (word8s w1 48#)
    Storable.pokeByteOff ptr 18 (word8s w1 40#)
    Storable.pokeByteOff ptr 19 (word8s w1 32#)
    Storable.pokeByteOff ptr 20 (word8s w1 24#)
    Storable.pokeByteOff ptr 21 (word8s w1 16#)
    Storable.pokeByteOff ptr 22 (word8s w1 08#)
    Storable.pokeByteOff ptr 23 (word8 w1)
    -- w3
    Storable.pokeByteOff ptr 24 (word8s w0 56#)
    Storable.pokeByteOff ptr 25 (word8s w0 48#)
    Storable.pokeByteOff ptr 26 (word8s w0 40#)
    Storable.pokeByteOff ptr 27 (word8s w0 32#)
    Storable.pokeByteOff ptr 28 (word8s w0 24#)
    Storable.pokeByteOff ptr 29 (word8s w0 16#)
    Storable.pokeByteOff ptr 30 (word8s w0 08#)
    Storable.pokeByteOff ptr 31 (word8 w0)
{-# INLINABLE unroll32 #-}

-- cheeky montgomery-assisted modQ
modQ :: Wider -> Wider
modQ = S.from . S.to
{-# INLINABLE modQ #-}

-- bytewise xor
xor :: BS.ByteString -> BS.ByteString -> BS.ByteString
xor = BS.packZipWith B.xor

-- constants ------------------------------------------------------------------

-- | secp256k1 field prime.
_CURVE_P :: Wider
_CURVE_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

-- | secp256k1 group order.
_CURVE_Q :: Wider
_CURVE_Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

-- | half of the secp256k1 group order.
_CURVE_QH :: Wider
_CURVE_QH = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0

-- bitlength of group order
--
-- = smallest integer such that _CURVE_Q < 2 ^ _CURVE_Q_BITS
_CURVE_Q_BITS :: Int
_CURVE_Q_BITS = 256

-- bytelength of _CURVE_Q
--
-- = _CURVE_Q_BITS / 8
_CURVE_Q_BYTES :: Int
_CURVE_Q_BYTES = 32

-- secp256k1 weierstrass form, /b/ coefficient
_CURVE_B :: Wider
_CURVE_B = 7

-- secp256k1 weierstrass form, /b/ coefficient, montgomery form
_CURVE_Bm :: C.Montgomery
_CURVE_Bm = 7

-- _CURVE_Bm * 3
_CURVE_Bm3 :: C.Montgomery
_CURVE_Bm3 = 21

-- Is field element?
fe :: Wider -> Bool
fe n = case W.cmp n _CURVE_P of
  LT -> True
  _  -> False
{-# INLINE fe #-}

-- Is group element?
ge :: Wider -> Bool
ge n = case W.cmp n _CURVE_Q of
  LT -> True
  _  -> False
{-# INLINE ge #-}

-- curve points ---------------------------------------------------------------

-- curve point, affine coordinates
data Affine = Affine !C.Montgomery !C.Montgomery
  deriving stock (Show, Generic)

-- curve point, projective coordinates
data Projective = Projective {
    px :: !C.Montgomery
  , py :: !C.Montgomery
  , pz :: !C.Montgomery
  }
  deriving stock (Show, Generic)

instance Eq Projective where
  Projective ax ay az == Projective bx by bz =
    let !x1z2 = ax * bz
        !x2z1 = bx * az
        !y1z2 = ay * bz
        !y2z1 = by * az
    in  CT.decide (CT.and# (C.eq x1z2 x2z1) (C.eq y1z2 y2z1))

-- | An ECC-flavoured alias for a secp256k1 point.
type Pub = Projective

-- Convert to affine coordinates.
affine :: Projective -> Affine
affine = \case
  Projective 0 1 0 -> Affine 0 0
  Projective x y 1 -> Affine x y
  Projective x y z ->
    let !iz = C.inv z
    in  Affine (x * iz) (y * iz)
{-# INLINABLE affine #-}

-- Convert to projective coordinates.
projective :: Affine -> Projective
projective = \case
  Affine 0 0 -> _CURVE_ZERO
  Affine x y -> Projective x y 1

-- | secp256k1 generator point.
_CURVE_G :: Projective
_CURVE_G = Projective x y C.one where
  !x = C.Montgomery
    (# Limb 15507633332195041431##, Limb  2530505477788034779##
    ,  Limb 10925531211367256732##, Limb 11061375339145502536## #)
  !y = C.Montgomery
    (# Limb 12780836216951778274##, Limb 10231155108014310989##
    ,  Limb 8121878653926228278##,  Limb 14933801261141951190## #)

-- | secp256k1 zero point, point at infinity, or monoidal identity.
_CURVE_ZERO :: Projective
_CURVE_ZERO = Projective 0 1 0

-- secp256k1 zero point, point at infinity, or monoidal identity
_ZERO :: Projective
_ZERO = Projective 0 1 0
{-# DEPRECATED _ZERO "use _CURVE_ZERO instead" #-}

-- secp256k1 in short weierstrass form (y ^ 2 = x ^ 3 + 7)
weierstrass :: C.Montgomery -> C.Montgomery
weierstrass x = C.sqr x * x + _CURVE_Bm
{-# INLINE weierstrass #-}

-- Point is valid
valid :: Projective -> Bool
valid p = case affine p of
  Affine x y
    | C.sqr y /= weierstrass x -> False
    | otherwise -> True

-- (bip0340) return point with x coordinate == x and with even y coordinate
--
-- conceptually:
--   y ^ 2 = x ^ 3 + 7
--   y     = "+-" sqrt (x ^ 3 + 7)
--     (n.b. for solution y, p - y is also a solution)
--   y + (p - y) = p (odd)
--     (n.b. sum is odd, so one of y and p - y must be odd, and the other even)
--   if y even, return (x, y)
--   else,      return (x, p - y)
lift_vartime :: C.Montgomery -> Maybe Affine
lift_vartime x = do
  let !c = weierstrass x
  !y <- C.sqrt c
  let !y_e | C.odd y   = negate y
           | otherwise = y
  guard (C.sqr y_e == c)
  pure $! Affine x y_e

even_y_vartime :: Projective -> Projective
even_y_vartime p = case affine p of
  Affine _ (C.retr -> y)
    | W.odd y  -> neg p
    | otherwise -> p

-- ec arithmetic --------------------------------------------------------------

-- Negate secp256k1 point.
neg :: Projective -> Projective
neg (Projective x y z) = Projective x (negate y) z

-- Elliptic curve addition on secp256k1.
add :: Projective -> Projective -> Projective
add p q@(Projective _ _ z)
  | z == 1 = add_mixed p q   -- algo 8
  | otherwise = add_proj p q -- algo 7

-- algo 7, "complete addition formulas for prime order elliptic curves,"
-- renes et al, 2015
--
-- https://eprint.iacr.org/2015/1060.pdf
add_proj :: Projective -> Projective -> Projective
add_proj (Projective x1 y1 z1) (Projective x2 y2 z2) = runST $ do
  x3 <- newSTRef 0
  y3 <- newSTRef 0
  z3 <- newSTRef 0
  t0 <- newSTRef (x1 * x2) -- 1
  t1 <- newSTRef (y1 * y2)
  t2 <- newSTRef (z1 * z2)
  t3 <- newSTRef (x1 + y1) -- 4
  t4 <- newSTRef (x2 + y2)
  readSTRef t4 >>= \r4 ->
    modifySTRef' t3 (\r3 -> r3 * r4)
  readSTRef t0 >>= \r0 ->
    readSTRef t1 >>= \r1 ->
    writeSTRef t4 (r0 + r1)
  readSTRef t4 >>= \r4 ->
    modifySTRef' t3 (\r3 -> r3 - r4) -- 8
  writeSTRef t4 (y1 + z1)
  writeSTRef x3 (y2 + z2)
  readSTRef x3 >>= \rx3 ->
    modifySTRef' t4 (\r4 -> r4 * rx3)
  readSTRef t1 >>= \r1 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef x3 (r1 + r2) -- 12
  readSTRef x3 >>= \rx3 ->
    modifySTRef' t4 (\r4 -> r4 - rx3)
  writeSTRef x3 (x1 + z1)
  writeSTRef y3 (x2 + z2)
  readSTRef y3 >>= \ry3 ->
    modifySTRef' x3 (\rx3 -> rx3 * ry3) -- 16
  readSTRef t0 >>= \r0 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef y3 (r0 + r2)
  readSTRef x3 >>= \rx3 ->
    modifySTRef' y3 (\ry3 -> rx3 - ry3)
  readSTRef t0 >>= \r0 ->
    writeSTRef x3 (r0 + r0)
  readSTRef x3 >>= \rx3 ->
    modifySTRef t0 (\r0 -> rx3 + r0) -- 20
  modifySTRef' t2 (\r2 -> _CURVE_Bm3 * r2)
  readSTRef t1 >>= \r1 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef z3 (r1 + r2)
  readSTRef t2 >>= \r2 ->
    modifySTRef' t1 (\r1 -> r1 - r2)
  modifySTRef' y3 (\ry3 -> _CURVE_Bm3 * ry3) -- 24
  readSTRef t4 >>= \r4 ->
    readSTRef y3 >>= \ry3 ->
    writeSTRef x3 (r4 * ry3)
  readSTRef t3 >>= \r3 ->
    readSTRef t1 >>= \r1 ->
    writeSTRef t2 (r3 * r1)
  readSTRef t2 >>= \r2 ->
    modifySTRef' x3 (\rx3 -> r2 - rx3)
  readSTRef t0 >>= \r0 ->
    modifySTRef' y3 (\ry3 -> ry3 * r0) -- 28
  readSTRef z3 >>= \rz3 ->
    modifySTRef' t1 (\r1 -> r1 * rz3)
  readSTRef t1 >>= \r1 ->
    modifySTRef' y3 (\ry3 -> r1 + ry3)
  readSTRef t3 >>= \r3 ->
    modifySTRef' t0 (\r0 -> r0 * r3)
  readSTRef t4 >>= \r4 ->
    modifySTRef' z3 (\rz3 -> rz3 * r4) -- 32
  readSTRef t0 >>= \r0 ->
    modifySTRef' z3 (\rz3 -> rz3 + r0)
  Projective <$> readSTRef x3 <*> readSTRef y3 <*> readSTRef z3

-- algo 8, renes et al, 2015
add_mixed :: Projective -> Projective -> Projective
add_mixed (Projective x1 y1 z1) (Projective x2 y2 z2)
  | z2 /= 1   = error "ppad-secp256k1 (add_mixed): internal error"
  | otherwise = runST $ do
      x3 <- newSTRef 0
      y3 <- newSTRef 0
      z3 <- newSTRef 0
      t0 <- newSTRef (x1 * x2) -- 1
      t1 <- newSTRef (y1 * y2)
      t3 <- newSTRef (x2 + y2)
      t4 <- newSTRef (x1 + y1) -- 4
      readSTRef t4 >>= \r4 ->
        modifySTRef' t3 (\r3 -> r3 * r4)
      readSTRef t0 >>= \r0 ->
        readSTRef t1 >>= \r1 ->
        writeSTRef t4 (r0 + r1)
      readSTRef t4 >>= \r4 ->
        modifySTRef' t3 (\r3 -> r3 - r4) -- 7
      writeSTRef t4 (y2 * z1)
      modifySTRef' t4 (\r4 -> r4 + y1)
      writeSTRef y3 (x2 * z1) -- 10
      modifySTRef' y3 (\ry3 -> ry3 + x1)
      readSTRef t0 >>= \r0 ->
        writeSTRef x3 (r0 + r0)
      readSTRef x3 >>= \rx3 ->
        modifySTRef' t0 (\r0 -> rx3 + r0) -- 13
      t2 <- newSTRef (_CURVE_Bm3 * z1)
      readSTRef t1 >>= \r1 ->
        readSTRef t2 >>= \r2 ->
        writeSTRef z3 (r1 + r2)
      readSTRef t2 >>= \r2 ->
        modifySTRef' t1 (\r1 -> r1 - r2) -- 16
      modifySTRef' y3 (\ry3 -> _CURVE_Bm3 * ry3)
      readSTRef t4 >>= \r4 ->
        readSTRef y3 >>= \ry3 ->
        writeSTRef x3 (r4 * ry3)
      readSTRef t3 >>= \r3 ->
        readSTRef t1 >>= \r1 ->
        writeSTRef t2 (r3 * r1) -- 19
      readSTRef t2 >>= \r2 ->
        modifySTRef' x3 (\rx3 -> r2 - rx3)
      readSTRef t0 >>= \r0 ->
        modifySTRef' y3 (\ry3 -> ry3 * r0)
      readSTRef z3 >>= \rz3 ->
        modifySTRef' t1 (\r1 -> r1 * rz3) -- 22
      readSTRef t1 >>= \r1 ->
        modifySTRef' y3 (\ry3 -> r1 + ry3)
      readSTRef t3 >>= \r3 ->
        modifySTRef' t0 (\r0 -> r0 * r3)
      readSTRef t4 >>= \r4 ->
        modifySTRef' z3 (\rz3 -> rz3 * r4) -- 25
      readSTRef t0 >>= \r0 ->
        modifySTRef' z3 (\rz3 -> rz3 + r0)
      Projective <$> readSTRef x3 <*> readSTRef y3 <*> readSTRef z3

-- algo 9, renes et al, 2015
double :: Projective -> Projective
double (Projective x y z) = runST $ do
  x3 <- newSTRef 0
  y3 <- newSTRef 0
  z3 <- newSTRef 0
  t0 <- newSTRef (y * y) -- 1
  readSTRef t0 >>= \r0 ->
    writeSTRef z3 (r0 + r0)
  modifySTRef' z3 (\rz3 -> rz3 + rz3)
  modifySTRef' z3 (\rz3 -> rz3 + rz3) -- 4
  t1 <- newSTRef (y * z)
  t2 <- newSTRef (z * z)
  modifySTRef t2 (\r2 -> _CURVE_Bm3 * r2) -- 7
  readSTRef z3 >>= \rz3 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef x3 (r2 * rz3)
  readSTRef t0 >>= \r0 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef y3 (r0 + r2)
  readSTRef t1 >>= \r1 ->
    modifySTRef' z3 (\rz3 -> r1 * rz3) -- 10
  readSTRef t2 >>= \r2 ->
    writeSTRef t1 (r2 + r2)
  readSTRef t1 >>= \r1 ->
    modifySTRef' t2 (\r2 -> r1 + r2)
  readSTRef t2 >>= \r2 ->
    modifySTRef' t0 (\r0 -> r0 - r2) -- 13
  readSTRef t0 >>= \r0 ->
    modifySTRef' y3 (\ry3 -> r0 * ry3)
  readSTRef x3 >>= \rx3 ->
    modifySTRef' y3 (\ry3 -> rx3 + ry3)
  writeSTRef t1 (x * y) -- 16
  readSTRef t0 >>= \r0 ->
    readSTRef t1 >>= \r1 ->
    writeSTRef x3 (r0 * r1)
  modifySTRef' x3 (\rx3 -> rx3 + rx3)
  Projective <$> readSTRef x3 <*> readSTRef y3 <*> readSTRef z3

-- Timing-safe scalar multiplication of secp256k1 points.
mul :: Projective -> Wider -> Maybe Projective
mul p sec = do
    guard (ge sec)
    pure $! loop (0 :: Int) _CURVE_ZERO _CURVE_G p sec
  where
    loop !j !acc !f !d !_SECRET
      | j == _CURVE_Q_BITS = acc
      | otherwise =
          let !nd = double d
              !(!nm, !lsb_set) = W.shr1_c _SECRET -- constant-time shift
          in  if   lsb_set
              then loop (succ j) (add acc d) f nd nm
              else loop (succ j) acc (add f d) nd nm
{-# INLINE mul #-}

-- Timing-unsafe scalar multiplication of secp256k1 points.
--
-- Don't use this function if the scalar could potentially be a secret.
mul_unsafe :: Projective -> Wider -> Maybe Projective
mul_unsafe p = \case
    Zero -> pure _CURVE_ZERO
    n | not (ge n) -> Nothing
      | otherwise  -> pure $! loop _CURVE_ZERO p n
  where
    loop !r !d = \case
      Zero -> r
      m ->
        let !nd = double d
            !(!nm, !lsb_set) = W.shr1_c m
            !nr = if lsb_set then add r d else r
        in  loop nr nd nm

-- | Precomputed multiples of the secp256k1 base or generator point.
data Context = Context {
    ctxW     :: {-# UNPACK #-} !Int
  , ctxArray :: !(A.Array Projective)
  } deriving Generic

instance Show Context where
  show Context {} = "<secp256k1 context>"

-- | Create a secp256k1 context by precomputing multiples of the curve's
--   generator point.
--
--   This should be used once to create a 'Context' to be reused
--   repeatedly afterwards.
--
--   >>> let !tex = precompute
--   >>> sign_ecdsa' tex sec msg
--   >>> sign_schnorr' tex sec msg aux
precompute :: Context
precompute = _precompute 8

-- translation of noble-secp256k1's 'precompute'
_precompute :: Int -> Context
_precompute ctxW = Context {..} where
  ctxArray = A.arrayFromListN size (loop_w mempty _CURVE_G 0)
  capJ = (2 :: Int) ^ (ctxW - 1)
  ws = 256 `quot` ctxW + 1
  size = ws * capJ

  loop_w !acc !p !w
    | w == ws = reverse acc
    | otherwise =
        let b = p
            !(Pair nacc nb) = loop_j p (b : acc) b 1
            np = double nb
        in  loop_w nacc np (succ w)

  loop_j !p !acc !b !j
    | j == capJ = Pair acc b
    | otherwise =
        let nb = add b p
        in  loop_j p (nb : acc) nb (succ j)

-- Timing-safe wNAF (w-ary non-adjacent form) scalar multiplication of
-- secp256k1 points.
mul_wnaf :: Context -> Wider -> Maybe Projective
mul_wnaf Context {..} _SECRET = do
    guard (ge _SECRET)
    pure $! loop 0 _CURVE_ZERO _CURVE_G _SECRET
  where
    wins = 256 `quot` ctxW + 1
    wsize = 2 ^ (ctxW - 1)
    mask = 2 ^ ctxW - 1
    mnum = 2 ^ ctxW

    loop !w !acc !f !n
      | w == wins = acc
      | otherwise =
          let !off0 = w * wsize

              !b0 = wider_to_int n .&. mask
              !n0 = n `W.shr_limb` ctxW

              !(Pair b1 n1) | b0 > wsize = Pair (b0 - mnum) (n0 + 1)
                            | otherwise  = Pair b0 n0

              !c0 = B.testBit w 0
              !c1 = b1 < 0

              !off1 = off0 + fi (abs b1) - 1

          in  if   b1 == 0
              then let !pr = A.indexArray ctxArray off0
                       !pt | c0 = neg pr
                           | otherwise = pr
                   in  loop (w + 1) acc (add f pt) n1
              else let !pr = A.indexArray ctxArray off1
                       !pt | c1 = neg pr
                           | otherwise = pr
                   in  loop (w + 1) (add acc pt) f n1
{-# INLINE mul_wnaf #-}

-- | Derive a public key (i.e., a secp256k1 point) from the provided
--   secret.
--
--   >>> import qualified System.Entropy as E
--   >>> sk <- fmap parse_int256 (E.getEntropy 32)
--   >>> derive_pub sk
--   Just "<secp256k1 point>"
derive_pub :: Wider -> Maybe Pub
derive_pub = mul _CURVE_G
{-# NOINLINE derive_pub #-}

-- | The same as 'derive_pub', except uses a 'Context' to optimise
--   internal calculations.
--
--   >>> import qualified System.Entropy as E
--   >>> sk <- fmap parse_int256 (E.getEntropy 32)
--   >>> let !tex = precompute
--   >>> derive_pub' tex sk
--   Just "<secp256k1 point>"
derive_pub' :: Context -> Wider -> Maybe Pub
derive_pub' = mul_wnaf
{-# NOINLINE derive_pub' #-}

-- parsing --------------------------------------------------------------------

-- | Parse a 'Wider', /e.g./ a Schnorr or ECDSA secret key.
--
--   >>> import qualified Data.ByteString as BS
--   >>> parse_int256 (BS.replicate 32 0xFF)
--   Just <2^256 - 1>
parse_int256 :: BS.ByteString -> Maybe Wider
parse_int256 bs = do
  guard (BS.length bs == 32)
  pure $! unsafe_roll32 bs

-- | Parse compressed secp256k1 point (33 bytes), uncompressed point (65
--   bytes), or BIP0340-style point (32 bytes).
--
--   >>> parse_point <33-byte compressed point>
--   Just <Pub>
--   >>> parse_point <65-byte uncompressed point>
--   Just <Pub>
--   >>> parse_point <32-byte bip0340 public key>
--   Just <Pub>
--   >>> parse_point <anything else>
--   Nothing
parse_point :: BS.ByteString -> Maybe Projective
parse_point bs
    | len == 32 = _parse_bip0340 bs
    | len == 33 = _parse_compressed h t
    | len == 65 = _parse_uncompressed h t
    | otherwise = Nothing
  where
    len = BS.length bs
    h = BU.unsafeIndex bs 0 -- lazy
    t = BS.drop 1 bs

-- input is guaranteed to be 32B in length
_parse_bip0340 :: BS.ByteString -> Maybe Projective
_parse_bip0340 = fmap projective . lift_vartime . C.to . unsafe_roll32

-- bytestring input is guaranteed to be 32B in length
_parse_compressed :: Word8 -> BS.ByteString -> Maybe Projective
_parse_compressed h (unsafe_roll32 -> x)
  | h /= 0x02 && h /= 0x03 = Nothing
  | not (fe x) = Nothing
  | otherwise = do
      let !mx = C.to x
      !my <- C.sqrt (weierstrass mx)
      let !(W.Wider (# Limb w, _, _, _ #)) = C.retr my
          !yodd = B.testBit (GHC.Word.W# w) 0
          !hodd = B.testBit h 0
      pure $!
        if   hodd /= yodd
        then Projective mx (negate my) 1
        else Projective mx my 1

-- bytestring input is guaranteed to be 64B in length
_parse_uncompressed :: Word8 -> BS.ByteString -> Maybe Projective
_parse_uncompressed h bs = do
  let (unsafe_roll32 -> x, unsafe_roll32 -> y) = BS.splitAt _CURVE_Q_BYTES bs
  guard (h /= 0x04)
  let !p = Projective (C.to x) (C.to y) 1
  guard (valid p)
  pure $! p

-- | Parse an ECDSA signature encoded in 64-byte "compact" form.
--
--   >>> parse_sig <64-byte compact signature>
--   Just "<ecdsa signature>"
parse_sig :: BS.ByteString -> Maybe ECDSA
parse_sig bs
  | BS.length bs /= 64 = Nothing
  | otherwise = pure $
      let (roll -> r, roll -> s) = BS.splitAt 32 bs
      in  ECDSA r s

-- serializing ----------------------------------------------------------------

-- | Serialize a secp256k1 point in 33-byte compressed form.
--
--   >>> serialize_point pub
--   "<33-byte compressed point>"
serialize_point :: Projective -> BS.ByteString
serialize_point (affine -> Affine (C.from -> x) (C.from -> y)) =
  let !(Wider (# Limb w, _, _, _ #)) = y
      !b | B.testBit (GHC.Word.W# w) 0 = 0x03
         | otherwise = 0x02
  in  BS.cons b (unroll32 x)

-- ecdh -----------------------------------------------------------------------

-- SEC1-v2 3.3.1, plus SHA256 hash

-- | Compute a shared secret, given a secret key and public secp256k1 point,
--   via Elliptic Curve Diffie-Hellman (ECDH).
--
--   The shared secret is the SHA256 hash of the x-coordinate of the
--   point obtained by scalar multiplication.
--
--   >>> let sec_alice = 0x03
--   >>> let sec_bob   = 2 ^ 128 - 1
--   >>> let Just pub_alice = derive_pub sec_alice
--   >>> let Just pub_bob   = derive_pub sec_bob
--   >>> let secret_as_computed_by_alice = ecdh pub_bob sec_alice
--   >>> let secret_as_computed_by_bob   = ecdh pub_alice sec_bob
--   >>> secret_as_computed_by_alice == secret_as_computed_by_bob
--   True
ecdh
  :: Projective          -- ^ public key
  -> Wider               -- ^ secret key
  -> Maybe BS.ByteString -- ^ shared secret
ecdh pub _SECRET = do
  pt <- mul pub _SECRET
  guard (pt /= _CURVE_ZERO)
  case affine pt of
    Affine (C.retr -> x) _ -> pure $! SHA256.hash (unroll32 x)

-- schnorr --------------------------------------------------------------------
-- see https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

-- | Create a 64-byte Schnorr signature for the provided message, using
--   the provided secret key.
--
--   BIP0340 recommends that 32 bytes of fresh auxiliary entropy be
--   generated and added at signing time as additional protection
--   against side-channel attacks (namely, to thwart so-called "fault
--   injection" attacks). This entropy is /supplemental/ to security,
--   and the cryptographic security of the signature scheme itself does
--   not rely on it, so it is not strictly required; 32 zero bytes can
--   be used in its stead (and can be supplied via 'mempty').
--
--   >>> import qualified System.Entropy as E
--   >>> aux <- E.getEntropy 32
--   >>> sign_schnorr sec msg aux
--   Just "<64-byte schnorr signature>"
sign_schnorr
  :: Wider          -- ^ secret key
  -> BS.ByteString  -- ^ message
  -> BS.ByteString  -- ^ 32 bytes of auxilliary random data
  -> Maybe BS.ByteString  -- ^ 64-byte Schnorr signature
sign_schnorr = _sign_schnorr (mul _CURVE_G)

-- | The same as 'sign_schnorr', except uses a 'Context' to optimise
--   internal calculations.
--
--   You can expect about a 2x performance increase when using this
--   function, compared to 'sign_schnorr'.
--
--   >>> import qualified System.Entropy as E
--   >>> aux <- E.getEntropy 32
--   >>> let !tex = precompute
--   >>> sign_schnorr' tex sec msg aux
--   Just "<64-byte schnorr signature>"
sign_schnorr'
  :: Context        -- ^ secp256k1 context
  -> Wider          -- ^ secret key
  -> BS.ByteString  -- ^ message
  -> BS.ByteString  -- ^ 32 bytes of auxilliary random data
  -> Maybe BS.ByteString  -- ^ 64-byte Schnorr signature
sign_schnorr' tex = _sign_schnorr (mul_wnaf tex)

_sign_schnorr
  :: (Wider -> Maybe Projective)  -- partially-applied multiplication function
  -> Wider                        -- secret key
  -> BS.ByteString                -- message
  -> BS.ByteString                -- 32 bytes of auxilliary random data
  -> Maybe BS.ByteString
_sign_schnorr _mul _SECRET m a = do
  p <- _mul _SECRET
  let Affine (C.retr -> x_p) (C.retr -> y_p) = affine p
      s = S.to _SECRET
      d | W.odd y_p = negate s
        | otherwise = s
      bytes_d = unroll32 (S.retr d)
      bytes_p = unroll32 x_p
      t       = xor bytes_d (hash_aux a)
      rand    = hash_nonce (t <> bytes_p <> m)
      k'      = S.to (unsafe_roll32 rand)
  guard (k' /= 0) -- negligible probability
  pt <- _mul (S.retr k')
  let Affine (C.retr -> x_r) (C.retr -> y_r) = affine pt
      k | W.odd y_r = negate k'
        | otherwise = k'
      bytes_r   = unroll32 x_r
      rand'     = hash_challenge (bytes_r <> bytes_p <> m)
      e         = S.to (unsafe_roll32 rand')
      bytes_ked = unroll32 (S.retr (k + e * d))
      sig       = bytes_r <> bytes_ked
  guard (verify_schnorr m p sig)
  pure $! sig
{-# INLINE _sign_schnorr #-}

-- | Verify a 64-byte Schnorr signature for the provided message with
--   the supplied public key.
--
--   >>> verify_schnorr msg pub <valid signature>
--   True
--   >>> verify_schnorr msg pub <invalid signature>
--   False
verify_schnorr
  :: BS.ByteString  -- ^ message
  -> Pub            -- ^ public key
  -> BS.ByteString  -- ^ 64-byte Schnorr signature
  -> Bool
verify_schnorr = _verify_schnorr (mul_unsafe _CURVE_G)

-- | The same as 'verify_schnorr', except uses a 'Context' to optimise
--   internal calculations.
--
--   You can expect about a 1.5x performance increase when using this
--   function, compared to 'verify_schnorr'.
--
--   >>> let !tex = precompute
--   >>> verify_schnorr' tex msg pub <valid signature>
--   True
--   >>> verify_schnorr' tex msg pub <invalid signature>
--   False
verify_schnorr'
  :: Context        -- ^ secp256k1 context
  -> BS.ByteString  -- ^ message
  -> Pub            -- ^ public key
  -> BS.ByteString  -- ^ 64-byte Schnorr signature
  -> Bool
verify_schnorr' tex = _verify_schnorr (mul_wnaf tex)

_verify_schnorr
  :: (Wider -> Maybe Projective) -- partially-applied multiplication function
  -> BS.ByteString
  -> Pub
  -> BS.ByteString
  -> Bool
_verify_schnorr _mul m p sig
  | BS.length sig /= 64 = False
  | otherwise = M.isJust $ do
      let capP = even_y_vartime p
          (unsafe_roll32 -> r, unsafe_roll32 -> s) = BS.splitAt 32 sig
      guard (fe r && ge s)
      let Affine (C.retr -> x_P) _ = affine capP
          e = modQ . unsafe_roll32 $
            hash_challenge (unroll32 r <> unroll32 x_P <> m)
      pt0 <- _mul s
      pt1 <- mul_unsafe capP e
      let dif = add pt0 (neg pt1)
      guard (dif /= _CURVE_ZERO)
      let Affine (C.from -> x_R) (C.from -> y_R) = affine dif
      guard $ not (W.odd y_R || x_R /= r)
{-# INLINE _verify_schnorr #-}

-- hardcoded tag of BIP0340/aux
--
-- \x -> let h = SHA256.hash "BIP0340/aux"
--       in  SHA256.hash (h <> h <> x)
hash_aux :: BS.ByteString -> BS.ByteString
hash_aux x = SHA256.hash $
  "\241\239N^\192c\202\218m\148\202\250\157\152~\160i&X9\236\193\US\151-w\165.\216\193\204\144\241\239N^\192c\202\218m\148\202\250\157\152~\160i&X9\236\193\US\151-w\165.\216\193\204\144" <> x
{-# INLINE hash_aux #-}

-- hardcoded tag of BIP0340/nonce
hash_nonce :: BS.ByteString -> BS.ByteString
hash_nonce x = SHA256.hash $
  "\aIw4\167\155\203\&5[\155\140}\ETXO\DC2\FS\244\&4\215>\247-\218\EM\135\NULa\251R\191\235/\aIw4\167\155\203\&5[\155\140}\ETXO\DC2\FS\244\&4\215>\247-\218\EM\135\NULa\251R\191\235/" <> x
{-# INLINE hash_nonce #-}

-- hardcoded tag of BIP0340/challenge
hash_challenge :: BS.ByteString -> BS.ByteString
hash_challenge x = SHA256.hash $
  "{\181-z\159\239X2>\177\191z@}\179\130\210\243\242\216\ESC\177\"OI\254Q\143mH\211|{\181-z\159\239X2>\177\191z@}\179\130\210\243\242\216\ESC\177\"OI\254Q\143mH\211|" <> x
{-# INLINE hash_challenge #-}

-- ecdsa ----------------------------------------------------------------------
-- see https://www.rfc-editor.org/rfc/rfc6979, https://secg.org/sec1-v2.pdf

-- RFC6979 2.3.2
bits2int :: BS.ByteString -> Wider
bits2int = unsafe_roll32
{-# INLINABLE bits2int #-}

-- RFC6979 2.3.3
int2octets :: Wider -> BS.ByteString
int2octets = unroll32
{-# INLINABLE int2octets #-}

-- RFC6979 2.3.4
bits2octets :: BS.ByteString -> BS.ByteString
bits2octets bs =
  let z1 = bits2int bs
      z2 = modQ z1
  in  int2octets z2

-- | An ECDSA signature.
data ECDSA = ECDSA {
    ecdsa_r :: !Wider
  , ecdsa_s :: !Wider
  }
  deriving (Eq, Generic)

instance Show ECDSA where
  show _ = "<ecdsa signature>"

-- ECDSA signature type.
data SigType =
    LowS
  | Unrestricted
  deriving Show

-- Indicates whether to hash the message or assume it has already been
-- hashed.
data HashFlag =
    Hash
  | NoHash
  deriving Show

-- Convert an ECDSA signature to low-S form.
low :: ECDSA -> ECDSA
low (ECDSA r s) = ECDSA r ms where
  ms | s > _CURVE_QH = _CURVE_Q - s
     | otherwise = s
{-# INLINE low #-}

-- | Produce an ECDSA signature for the provided message, using the
--   provided private key.
--
--   'sign_ecdsa' produces a "low-s" signature, as is commonly required
--   in applications using secp256k1. If you need a generic ECDSA
--   signature, use 'sign_ecdsa_unrestricted'.
--
--   >>> sign_ecdsa sec msg
--   Just "<ecdsa signature>"
sign_ecdsa
  :: Wider         -- ^ secret key
  -> BS.ByteString -- ^ message
  -> Maybe ECDSA
sign_ecdsa = _sign_ecdsa (mul _CURVE_G) LowS Hash

-- | The same as 'sign_ecdsa', except uses a 'Context' to optimise internal
--   calculations.
--
--   You can expect about a 10x performance increase when using this
--   function, compared to 'sign_ecdsa'.
--
--   >>> let !tex = precompute
--   >>> sign_ecdsa' tex sec msg
--   Just "<ecdsa signature>"
sign_ecdsa'
  :: Context       -- ^ secp256k1 context
  -> Wider         -- ^ secret key
  -> BS.ByteString -- ^ message
  -> Maybe ECDSA
sign_ecdsa' tex = _sign_ecdsa (mul_wnaf tex) LowS Hash

-- | Produce an ECDSA signature for the provided message, using the
--   provided private key.
--
--   'sign_ecdsa_unrestricted' produces an unrestricted ECDSA signature,
--   which is less common in applications using secp256k1 due to the
--   signature's inherent malleability. If you need a conventional
--   "low-s" signature, use 'sign_ecdsa'.
--
--   >>> sign_ecdsa_unrestricted sec msg
--   Just "<ecdsa signature>"
sign_ecdsa_unrestricted
  :: Wider         -- ^ secret key
  -> BS.ByteString -- ^ message
  -> Maybe ECDSA
sign_ecdsa_unrestricted = _sign_ecdsa (mul _CURVE_G) Unrestricted Hash

-- | The same as 'sign_ecdsa_unrestricted', except uses a 'Context' to
--   optimise internal calculations.
--
--   You can expect about a 10x performance increase when using this
--   function, compared to 'sign_ecdsa_unrestricted'.
--
--   >>> let !tex = precompute
--   >>> sign_ecdsa_unrestricted' tex sec msg
--   Just "<ecdsa signature>"
sign_ecdsa_unrestricted'
  :: Context       -- ^ secp256k1 context
  -> Wider         -- ^ secret key
  -> BS.ByteString -- ^ message
  -> Maybe ECDSA
sign_ecdsa_unrestricted' tex = _sign_ecdsa (mul_wnaf tex) Unrestricted Hash

-- Produce a "low-s" ECDSA signature for the provided message, using
-- the provided private key. Assumes that the message has already been
-- pre-hashed.
--
-- (Useful for testing against noble-secp256k1's suite, in which messages
-- in the test vectors have already been hashed.)
_sign_ecdsa_no_hash
  :: Wider         -- ^ secret key
  -> BS.ByteString -- ^ message digest
  -> Maybe ECDSA
_sign_ecdsa_no_hash = _sign_ecdsa (mul _CURVE_G) LowS NoHash

_sign_ecdsa_no_hash'
  :: Context
  -> Wider
  -> BS.ByteString
  -> Maybe ECDSA
_sign_ecdsa_no_hash' tex = _sign_ecdsa (mul_wnaf tex) LowS NoHash

_sign_ecdsa
  :: (Wider -> Maybe Projective) -- partially-applied multiplication function
  -> SigType
  -> HashFlag
  -> Wider
  -> BS.ByteString
  -> Maybe ECDSA
_sign_ecdsa _mul ty hf _SECRET m = runST $ do
    -- RFC6979 sec 3.3a
    let entropy = int2octets _SECRET
        nonce   = bits2octets h
    drbg <- DRBG.new SHA256.hmac entropy nonce mempty
    -- RFC6979 sec 2.4
    sign_loop drbg
  where
    d  = S.to _SECRET
    hm = S.to (bits2int h)
    h  = case hf of
      Hash -> SHA256.hash m
      NoHash -> m

    sign_loop g = do
      k <- gen_k g
      let mpair = do
            kg <- _mul k
            let Affine (S.to . C.retr -> r) _ = affine kg
                ki = S.inv (S.to k)
                s  = (hm + d * r) * ki
            pure $! (S.retr r, S.retr s)
      case mpair of
        Nothing -> pure Nothing
        Just (r, s)
          | r == 0 -> sign_loop g -- negligible probability
          | otherwise ->
              let !sig = Just $! ECDSA r s
              in  case ty of
                    Unrestricted -> pure sig
                    LowS -> pure (fmap low sig)
{-# INLINE _sign_ecdsa #-}

-- RFC6979 sec 3.3b
gen_k :: DRBG.DRBG s -> ST s Wider
gen_k g = loop g where
  loop drbg = do
    bytes <- DRBG.gen mempty (fi _CURVE_Q_BYTES) drbg
    let can = bits2int bytes
    if   can >= _CURVE_Q
    then loop drbg
    else pure can
{-# INLINE gen_k #-}

-- | Verify a "low-s" ECDSA signature for the provided message and
--   public key,
--
--   Fails to verify otherwise-valid "high-s" signatures. If you need to
--   verify generic ECDSA signatures, use 'verify_ecdsa_unrestricted'.
--
--   >>> verify_ecdsa msg pub valid_sig
--   True
--   >>> verify_ecdsa msg pub invalid_sig
--   False
verify_ecdsa
  :: BS.ByteString -- ^ message
  -> Pub           -- ^ public key
  -> ECDSA         -- ^ signature
  -> Bool
verify_ecdsa m p sig@(ECDSA _ s)
  | s > _CURVE_QH = False
  | otherwise = verify_ecdsa_unrestricted m p sig

-- | The same as 'verify_ecdsa', except uses a 'Context' to optimise
--   internal calculations.
--
--   You can expect about a 2x performance increase when using this
--   function, compared to 'verify_ecdsa'.
--
--   >>> let !tex = precompute
--   >>> verify_ecdsa' tex msg pub valid_sig
--   True
--   >>> verify_ecdsa' tex msg pub invalid_sig
--   False
verify_ecdsa'
  :: Context       -- ^ secp256k1 context
  -> BS.ByteString -- ^ message
  -> Pub           -- ^ public key
  -> ECDSA         -- ^ signature
  -> Bool
verify_ecdsa' tex m p sig@(ECDSA _ s)
  | s > _CURVE_QH = False
  | otherwise = verify_ecdsa_unrestricted' tex m p sig

-- | Verify an unrestricted ECDSA signature for the provided message and
--   public key.
--
--   >>> verify_ecdsa_unrestricted msg pub valid_sig
--   True
--   >>> verify_ecdsa_unrestricted msg pub invalid_sig
--   False
verify_ecdsa_unrestricted
  :: BS.ByteString -- ^ message
  -> Pub           -- ^ public key
  -> ECDSA         -- ^ signature
  -> Bool
verify_ecdsa_unrestricted = _verify_ecdsa_unrestricted (mul_unsafe _CURVE_G)

-- | The same as 'verify_ecdsa_unrestricted', except uses a 'Context' to
--   optimise internal calculations.
--
--   You can expect about a 2x performance increase when using this
--   function, compared to 'verify_ecdsa_unrestricted'.
--
--   >>> let !tex = precompute
--   >>> verify_ecdsa_unrestricted' tex msg pub valid_sig
--   True
--   >>> verify_ecdsa_unrestricted' tex msg pub invalid_sig
--   False
verify_ecdsa_unrestricted'
  :: Context       -- ^ secp256k1 context
  -> BS.ByteString -- ^ message
  -> Pub           -- ^ public key
  -> ECDSA         -- ^ signature
  -> Bool
verify_ecdsa_unrestricted' tex = _verify_ecdsa_unrestricted (mul_wnaf tex)

_verify_ecdsa_unrestricted
  :: (Wider -> Maybe Projective) -- partially-applied multiplication function
  -> BS.ByteString
  -> Pub
  -> ECDSA
  -> Bool
_verify_ecdsa_unrestricted _mul m p (ECDSA r0 s0) = M.isJust $ do
  -- SEC1-v2 4.1.4
  let h = SHA256.hash m
  guard (ge r0 && ge s0)
  let r  = S.to r0
      s  = S.to s0
      e  = S.to (bits2int h)
      si = S.inv s
      u1 = S.retr (e * si)
      u2 = S.retr (r * si)
  pt0 <- _mul u1
  pt1 <- mul_unsafe p u2
  let capR = add pt0 pt1
  guard (capR /= _CURVE_ZERO)
  let Affine (S.to . C.retr -> v) _ = affine capR
  guard (v == r)
{-# INLINE _verify_ecdsa_unrestricted #-}

