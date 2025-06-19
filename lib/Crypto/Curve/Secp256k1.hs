{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE UnboxedSums #-}
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
  , remQ
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

import Control.Monad (guard, when)
import Control.Monad.ST
import qualified Crypto.DRBG.HMAC as DRBG
import qualified Crypto.Hash.SHA256 as SHA256
import Data.Bits ((.|.))
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BU
import qualified Data.Maybe as M (isJust)
import qualified Data.Primitive.Array as A
import Data.STRef
import Data.Word (Word8, Word64)
import GHC.Generics
import GHC.Natural
import qualified GHC.Num.Integer as I

-- note the use of GHC.Num.Integer-qualified functions throughout this
-- module; in some cases explicit use of these functions (especially
-- I.integerPowMod# and I.integerRecipMod#) yields tremendous speedups
-- compared to more general versions

-- keystroke savers & other utilities -----------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- generic modular exponentiation
-- b ^ e mod m
modexp :: Integer -> Natural -> Natural -> Integer
modexp b (fi -> e) m = case I.integerPowMod# b e m of
  (# fi -> n | #) -> n
  (# | _ #) -> error "ppad-secp256k1 (modexp): internal error"
{-# INLINE modexp #-}

-- generic modular inverse
-- for a, m return x such that ax = 1 mod m
modinv :: Integer -> Natural -> Maybe Integer
modinv a m = case I.integerRecipMod# a m of
  (# fi -> n | #) -> Just $! n
  (# | _ #) -> Nothing
{-# INLINE modinv #-}

-- bytewise xor
xor :: BS.ByteString -> BS.ByteString -> BS.ByteString
xor = BS.packZipWith B.xor

-- arbitrary-size big-endian bytestring decoding
roll :: BS.ByteString -> Integer
roll = BS.foldl' alg 0 where
  alg !a (fi -> !b) = (a `I.integerShiftL` 8) `I.integerOr` b

-- /Note:/ there can be substantial differences in execution time
-- when this function is called with "extreme" inputs. For example: a
-- bytestring consisting entirely of 0x00 bytes will parse more quickly
-- than one consisting of entirely 0xFF bytes. For appropriately-random
-- inputs, timings should be indistinguishable.
--
-- 256-bit big-endian bytestring decoding. the input size is not checked!
roll32 :: BS.ByteString -> Integer
roll32 bs = go (0 :: Word64) (0 :: Word64) (0 :: Word64) (0 :: Word64) 0 where
  go !acc0 !acc1 !acc2 !acc3 !j
    | j == 32  =
            (fi acc0 `B.unsafeShiftL` 192)
        .|. (fi acc1 `B.unsafeShiftL` 128)
        .|. (fi acc2 `B.unsafeShiftL` 64)
        .|. fi acc3
    | j < 8    =
        let b = fi (BU.unsafeIndex bs j)
        in  go ((acc0 `B.unsafeShiftL` 8) .|. b) acc1 acc2 acc3 (j + 1)
    | j < 16   =
        let b = fi (BU.unsafeIndex bs j)
        in go acc0 ((acc1 `B.unsafeShiftL` 8) .|. b) acc2 acc3 (j + 1)
    | j < 24   =
        let b = fi (BU.unsafeIndex bs j)
        in go acc0 acc1 ((acc2 `B.unsafeShiftL` 8) .|. b) acc3 (j + 1)
    | otherwise =
        let b = fi (BU.unsafeIndex bs j)
        in go acc0 acc1 acc2 ((acc3 `B.unsafeShiftL` 8) .|. b) (j + 1)
{-# INLINE roll32 #-}

-- this "looks" inefficient due to the call to reverse, but it's
-- actually really fast

-- big-endian bytestring encoding
unroll :: Integer -> BS.ByteString
unroll i = case i of
    0 -> BS.singleton 0
    _ -> BS.reverse $ BS.unfoldr step i
  where
    step 0 = Nothing
    step m = Just (fi m, m `I.integerShiftR` 8)

-- big-endian bytestring encoding for 256-bit ints, left-padding with
-- zeros if necessary. the size of the integer is not checked.
unroll32 :: Integer -> BS.ByteString
unroll32 (unroll -> u)
    | l < 32 = BS.replicate (32 - l) 0 <> u
    | otherwise = u
  where
    l = BS.length u

-- (bip0340) return point with x coordinate == x and with even y coordinate
lift :: Integer -> Maybe Affine
lift x = do
  guard (fe x)
  let c = remP (modexp x 3 (fi _CURVE_P) + 7) -- modexp always nonnegative
      e = (_CURVE_P + 1) `I.integerQuot` 4
      y = modexp c (fi e) (fi _CURVE_P)
      y_p | B.testBit y 0 = _CURVE_P - y
          | otherwise = y
  guard (c == modexp y 2 (fi _CURVE_P))
  pure $! Affine x y_p

-- coordinate systems & transformations ---------------------------------------

-- curve point, affine coordinates
data Affine = Affine !Integer !Integer
  deriving stock (Show, Generic)

instance Eq Affine where
  Affine x1 y1 == Affine x2 y2 =
    modP x1 == modP x2 && modP y1 == modP y2

-- curve point, projective coordinates
data Projective = Projective {
    px :: !Integer
  , py :: !Integer
  , pz :: !Integer
  }
  deriving stock (Show, Generic)

instance Eq Projective where
  Projective ax ay az == Projective bx by bz =
    let x1z2 = modP (ax * bz)
        x2z1 = modP (bx * az)
        y1z2 = modP (ay * bz)
        y2z1 = modP (by * az)
    in  x1z2 == x2z1 && y1z2 == y2z1

-- | A Schnorr and ECDSA-flavoured alias for a secp256k1 point.
type Pub = Projective

-- Convert to affine coordinates.
affine :: Projective -> Affine
affine p@(Projective x y z)
  | p == _CURVE_ZERO = Affine 0 0
  | z == 1     = Affine x y
  | otherwise  = case modinv z (fi _CURVE_P) of
      Nothing -> error "ppad-secp256k1 (affine): internal error"
      Just iz -> Affine (modP (x * iz)) (modP (y * iz))

-- Convert to projective coordinates.
projective :: Affine -> Projective
projective (Affine x y)
  | x == 0 && y == 0 = _CURVE_ZERO
  | otherwise = Projective x y 1

-- Point is valid
valid :: Projective -> Bool
valid p = case affine p of
  Affine x y
    | not (fe x) || not (fe y) -> False
    | modP (y * y) /= weierstrass x -> False
    | otherwise -> True

-- curve parameters -----------------------------------------------------------
-- see https://www.secg.org/sec2-v2.pdf for parameter specs

-- ~ 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1

-- | secp256k1 field prime.
_CURVE_P :: Integer
_CURVE_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

-- | secp256k1 group order.
_CURVE_Q :: Integer
_CURVE_Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

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

-- secp256k1 short weierstrass form, /a/ coefficient
_CURVE_A :: Integer
_CURVE_A = 0

-- secp256k1 weierstrass form, /b/ coefficient
_CURVE_B :: Integer
_CURVE_B = 7

-- ~ parse_point . B16.decode $
--     "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"

-- | secp256k1 generator point.
_CURVE_G :: Projective
_CURVE_G = Projective x y 1 where
  x = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

-- | secp256k1 zero point, point at infinity, or monoidal identity.
_CURVE_ZERO :: Projective
_CURVE_ZERO = Projective 0 1 0

-- secp256k1 zero point, point at infinity, or monoidal identity
_ZERO :: Projective
_ZERO = Projective 0 1 0
{-# DEPRECATED _ZERO "use _CURVE_ZERO instead" #-}

-- secp256k1 in prime order j-invariant 0 form (i.e. a == 0).
weierstrass :: Integer -> Integer
weierstrass x = remP (remP (x * x) * x + _CURVE_B)
{-# INLINE weierstrass #-}

-- field, group operations ----------------------------------------------------

-- Division modulo secp256k1 field prime.
modP :: Integer -> Integer
modP a = I.integerMod a _CURVE_P
{-# INLINE modP #-}

-- Division modulo secp256k1 field prime, when argument is nonnegative.
-- (more efficient than modP)
remP :: Integer -> Integer
remP a = I.integerRem a _CURVE_P
{-# INLINE remP #-}

-- | Division modulo secp256k1 group order.
modQ :: Integer -> Integer
modQ a = I.integerMod a _CURVE_Q
{-# INLINE modQ #-}

-- | Division modulo secp256k1 group order, when argument is nonnegative.
remQ :: Integer -> Integer
remQ a = I.integerRem a _CURVE_Q
{-# INLINE remQ #-}

-- Is field element?
fe :: Integer -> Bool
fe n = 0 < n && n < _CURVE_P
{-# INLINE fe #-}

-- Is group element?
ge :: Integer -> Bool
ge n = 0 < n && n < _CURVE_Q
{-# INLINE ge #-}

-- Square root (Shanks-Tonelli) modulo secp256k1 field prime.
--
-- For a, return x such that a = x x mod _CURVE_P.
modsqrtP :: Integer -> Maybe Integer
modsqrtP n = runST $ do
  r   <- newSTRef 1
  num <- newSTRef n
  e   <- newSTRef ((_CURVE_P + 1) `I.integerQuot` 4)

  let loop = do
        ev <- readSTRef e
        when (ev > 0) $ do
          when (I.integerTestBit ev 0) $ do
            numv <- readSTRef num
            modifySTRef' r (\rv -> remP (rv * numv))
          modifySTRef' num (\numv -> remP (numv * numv))
          modifySTRef' e (`I.integerShiftR` 1)
          loop

  loop
  rv  <- readSTRef r

  pure $ do
    guard (remP (rv * rv) == n)
    Just $! rv

-- ec point operations --------------------------------------------------------

-- Negate secp256k1 point.
neg :: Projective -> Projective
neg (Projective x y z) = Projective x (modP (negate y)) z

-- Elliptic curve addition on secp256k1.
add :: Projective -> Projective -> Projective
add p q@(Projective _ _ z)
  | p == q = double p        -- algo 9
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
  let b3 = remP (_CURVE_B * 3)
  t0 <- newSTRef (modP (x1 * x2)) -- 1
  t1 <- newSTRef (modP (y1 * y2))
  t2 <- newSTRef (modP (z1 * z2))
  t3 <- newSTRef (modP (x1 + y1)) -- 4
  t4 <- newSTRef (modP (x2 + y2))
  readSTRef t4 >>= \r4 ->
    modifySTRef' t3 (\r3 -> modP (r3 * r4))
  readSTRef t0 >>= \r0 ->
    readSTRef t1 >>= \r1 ->
    writeSTRef t4 (modP (r0 + r1))
  readSTRef t4 >>= \r4 ->
    modifySTRef' t3 (\r3 -> modP (r3 - r4)) -- 8
  writeSTRef t4 (modP (y1 + z1))
  writeSTRef x3 (modP (y2 + z2))
  readSTRef x3 >>= \rx3 ->
    modifySTRef' t4 (\r4 -> modP (r4 * rx3))
  readSTRef t1 >>= \r1 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef x3 (modP (r1 + r2)) -- 12
  readSTRef x3 >>= \rx3 ->
    modifySTRef' t4 (\r4 -> modP (r4 - rx3))
  writeSTRef x3 (modP (x1 + z1))
  writeSTRef y3 (modP (x2 + z2))
  readSTRef y3 >>= \ry3 ->
    modifySTRef' x3 (\rx3 -> modP (rx3 * ry3)) -- 16
  readSTRef t0 >>= \r0 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef y3 (modP (r0 + r2))
  readSTRef x3 >>= \rx3 ->
    modifySTRef' y3 (\ry3 -> modP (rx3 - ry3))
  readSTRef t0 >>= \r0 ->
    writeSTRef x3 (modP (r0 + r0))
  readSTRef x3 >>= \rx3 ->
    modifySTRef t0 (\r0 -> modP (rx3 + r0)) -- 20
  modifySTRef' t2 (\r2 -> modP (b3 * r2))
  readSTRef t1 >>= \r1 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef z3 (modP (r1 + r2))
  readSTRef t2 >>= \r2 ->
    modifySTRef' t1 (\r1 -> modP (r1 - r2))
  modifySTRef' y3 (\ry3 -> modP (b3 * ry3)) -- 24
  readSTRef t4 >>= \r4 ->
    readSTRef y3 >>= \ry3 ->
    writeSTRef x3 (modP (r4 * ry3))
  readSTRef t3 >>= \r3 ->
    readSTRef t1 >>= \r1 ->
    writeSTRef t2 (modP (r3 * r1))
  readSTRef t2 >>= \r2 ->
    modifySTRef' x3 (\rx3 -> modP (r2 - rx3))
  readSTRef t0 >>= \r0 ->
    modifySTRef' y3 (\ry3 -> modP (ry3 * r0)) -- 28
  readSTRef z3 >>= \rz3 ->
    modifySTRef' t1 (\r1 -> modP (r1 * rz3))
  readSTRef t1 >>= \r1 ->
    modifySTRef' y3 (\ry3 -> modP (r1 + ry3))
  readSTRef t3 >>= \r3 ->
    modifySTRef' t0 (\r0 -> modP (r0 * r3))
  readSTRef t4 >>= \r4 ->
    modifySTRef' z3 (\rz3 -> modP (rz3 * r4)) -- 32
  readSTRef t0 >>= \r0 ->
    modifySTRef' z3 (\rz3 -> modP (rz3 + r0))
  Projective <$> readSTRef x3 <*> readSTRef y3 <*> readSTRef z3

-- algo 8, renes et al, 2015
add_mixed :: Projective -> Projective -> Projective
add_mixed (Projective x1 y1 z1) (Projective x2 y2 z2)
  | z2 /= 1   = error "ppad-secp256k1 (add_mixed): internal error"
  | otherwise = runST $ do
      x3 <- newSTRef 0
      y3 <- newSTRef 0
      z3 <- newSTRef 0
      let b3 = remP (_CURVE_B * 3)
      t0 <- newSTRef (modP (x1 * x2)) -- 1
      t1 <- newSTRef (modP (y1 * y2))
      t3 <- newSTRef (modP (x2 + y2))
      t4 <- newSTRef (modP (x1 + y1)) -- 4
      readSTRef t4 >>= \r4 ->
        modifySTRef' t3 (\r3 -> modP (r3 * r4))
      readSTRef t0 >>= \r0 ->
        readSTRef t1 >>= \r1 ->
        writeSTRef t4 (modP (r0 + r1))
      readSTRef t4 >>= \r4 ->
        modifySTRef' t3 (\r3 -> modP (r3 - r4)) -- 7
      writeSTRef t4 (modP (y2 * z1))
      modifySTRef' t4 (\r4 -> modP (r4 + y1))
      writeSTRef y3 (modP (x2 * z1)) -- 10
      modifySTRef' y3 (\ry3 -> modP (ry3 + x1))
      readSTRef t0 >>= \r0 ->
        writeSTRef x3 (modP (r0 + r0))
      readSTRef x3 >>= \rx3 ->
        modifySTRef' t0 (\r0 -> modP (rx3 + r0)) -- 13
      t2 <- newSTRef (modP (b3 * z1))
      readSTRef t1 >>= \r1 ->
        readSTRef t2 >>= \r2 ->
        writeSTRef z3 (modP (r1 + r2))
      readSTRef t2 >>= \r2 ->
        modifySTRef' t1 (\r1 -> modP (r1 - r2)) -- 16
      modifySTRef' y3 (\ry3 -> modP (b3 * ry3))
      readSTRef t4 >>= \r4 ->
        readSTRef y3 >>= \ry3 ->
        writeSTRef x3 (modP (r4 * ry3))
      readSTRef t3 >>= \r3 ->
        readSTRef t1 >>= \r1 ->
        writeSTRef t2 (modP (r3 * r1)) -- 19
      readSTRef t2 >>= \r2 ->
        modifySTRef' x3 (\rx3 -> modP (r2 - rx3))
      readSTRef t0 >>= \r0 ->
        modifySTRef' y3 (\ry3 -> modP (ry3 * r0))
      readSTRef z3 >>= \rz3 ->
        modifySTRef' t1 (\r1 -> modP (r1 * rz3)) -- 22
      readSTRef t1 >>= \r1 ->
        modifySTRef' y3 (\ry3 -> modP (r1 + ry3))
      readSTRef t3 >>= \r3 ->
        modifySTRef' t0 (\r0 -> modP (r0 * r3))
      readSTRef t4 >>= \r4 ->
        modifySTRef' z3 (\rz3 -> modP (rz3 * r4)) -- 25
      readSTRef t0 >>= \r0 ->
        modifySTRef' z3 (\rz3 -> modP (rz3 + r0))
      Projective <$> readSTRef x3 <*> readSTRef y3 <*> readSTRef z3

-- algo 9, renes et al, 2015
double :: Projective -> Projective
double (Projective x y z) = runST $ do
  x3 <- newSTRef 0
  y3 <- newSTRef 0
  z3 <- newSTRef 0
  let b3 = remP (_CURVE_B * 3)
  t0 <- newSTRef (modP (y * y)) -- 1
  readSTRef t0 >>= \r0 ->
    writeSTRef z3 (modP (r0 + r0))
  modifySTRef' z3 (\rz3 -> modP (rz3 + rz3))
  modifySTRef' z3 (\rz3 -> modP (rz3 + rz3)) -- 4
  t1 <- newSTRef (modP (y * z))
  t2 <- newSTRef (modP (z * z))
  modifySTRef t2 (\r2 -> modP (b3 * r2)) -- 7
  readSTRef z3 >>= \rz3 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef x3 (modP (r2 * rz3))
  readSTRef t0 >>= \r0 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef y3 (modP (r0 + r2))
  readSTRef t1 >>= \r1 ->
    modifySTRef' z3 (\rz3 -> modP (r1 * rz3)) -- 10
  readSTRef t2 >>= \r2 ->
    writeSTRef t1 (modP (r2 + r2))
  readSTRef t1 >>= \r1 ->
    modifySTRef' t2 (\r2 -> modP (r1 + r2))
  readSTRef t2 >>= \r2 ->
    modifySTRef' t0 (\r0 -> modP (r0 - r2)) -- 13
  readSTRef t0 >>= \r0 ->
    modifySTRef' y3 (\ry3 -> modP (r0 * ry3))
  readSTRef x3 >>= \rx3 ->
    modifySTRef' y3 (\ry3 -> modP (rx3 + ry3))
  writeSTRef t1 (modP (x * y)) -- 16
  readSTRef t0 >>= \r0 ->
    readSTRef t1 >>= \r1 ->
    writeSTRef x3 (modP (r0 * r1))
  modifySTRef' x3 (\rx3 -> modP (rx3 + rx3))
  Projective <$> readSTRef x3 <*> readSTRef y3 <*> readSTRef z3

-- Timing-safe scalar multiplication of secp256k1 points.
mul :: Projective -> Integer -> Maybe Projective
mul p _SECRET = do
    guard (ge _SECRET)
    pure $! loop (0 :: Int) _CURVE_ZERO _CURVE_G p _SECRET
  where
    loop !j !acc !f !d !m
      | j == _CURVE_Q_BITS = acc
      | otherwise =
          let nd = double d
              nm = I.integerShiftR m 1
          in  if   I.integerTestBit m 0
              then loop (succ j) (add acc d) f nd nm
              else loop (succ j) acc (add f d) nd nm
{-# INLINE mul #-}

-- Timing-unsafe scalar multiplication of secp256k1 points.
--
-- Don't use this function if the scalar could potentially be a secret.
mul_unsafe :: Projective -> Integer -> Maybe Projective
mul_unsafe p n
    | n == 0 = pure $! _CURVE_ZERO
    | not (ge n) = Nothing
    | otherwise  = pure $! loop _CURVE_ZERO p n
  where
    loop !r !d m
      | m <= 0 = r
      | otherwise =
          let nd = double d
              nm = I.integerShiftR m 1
              nr = if I.integerTestBit m 0 then add r d else r
          in  loop nr nd nm

-- | Precomputed multiples of the secp256k1 base or generator point.
data Context = Context {
    ctxW     :: {-# UNPACK #-} !Int
  , ctxArray :: !(A.Array Projective)
  } deriving (Eq, Generic)

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

-- dumb strict pair
data Pair a b = Pair !a !b

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
mul_wnaf :: Context -> Integer -> Maybe Projective
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
          let !off0 = w * fi wsize

              !b0 = n `I.integerAnd` mask
              !n0 = n `I.integerShiftR` fi ctxW

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
derive_pub :: Integer -> Maybe Pub
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
derive_pub' :: Context -> Integer -> Maybe Pub
derive_pub' = mul_wnaf
{-# NOINLINE derive_pub' #-}

-- parsing --------------------------------------------------------------------

-- | Parse a positive 256-bit 'Integer', /e.g./ a Schnorr or ECDSA
--   secret key.
--
--   >>> import qualified Data.ByteString as BS
--   >>> parse_int256 (BS.replicate 32 0xFF)
--   Just <2^256 - 1>
parse_int256 :: BS.ByteString -> Maybe Integer
parse_int256 bs = do
  guard (BS.length bs == 32)
  pure $! roll32 bs

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
_parse_bip0340 = fmap projective . lift . roll32

-- bytestring input is guaranteed to be 32B in length
_parse_compressed :: Word8 -> BS.ByteString -> Maybe Projective
_parse_compressed h (roll32 -> x)
  | h /= 0x02 && h /= 0x03 = Nothing
  | not (fe x) = Nothing
  | otherwise = do
      y <- modsqrtP (weierstrass x)
      let yodd = I.integerTestBit y 0
          hodd = B.testBit h 0
      pure $!
        if   hodd /= yodd
        then Projective x (modP (negate y)) 1
        else Projective x y 1

-- bytestring input is guaranteed to be 64B in length
_parse_uncompressed :: Word8 -> BS.ByteString -> Maybe Projective
_parse_uncompressed h (BS.splitAt _CURVE_Q_BYTES -> (roll32 -> x, roll32 -> y))
  | h /= 0x04 = Nothing
  | otherwise = do
      let p = Projective x y 1
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
serialize_point (affine -> Affine x y) = BS.cons b (unroll32 x) where
  b | I.integerTestBit y 0 = 0x03
    | otherwise = 0x02

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
  :: Integer        -- ^ secret key
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
  -> Integer        -- ^ secret key
  -> BS.ByteString  -- ^ message
  -> BS.ByteString  -- ^ 32 bytes of auxilliary random data
  -> Maybe BS.ByteString  -- ^ 64-byte Schnorr signature
sign_schnorr' tex = _sign_schnorr (mul_wnaf tex)

_sign_schnorr
  :: (Integer -> Maybe Projective)  -- partially-applied multiplication function
  -> Integer                  -- secret key
  -> BS.ByteString            -- message
  -> BS.ByteString            -- 32 bytes of auxilliary random data
  -> Maybe BS.ByteString
_sign_schnorr _mul _SECRET m a = do
  p_proj <- _mul _SECRET
  let Affine x_p y_p = affine p_proj
      d | I.integerTestBit y_p 0 = _CURVE_Q - _SECRET
        | otherwise = _SECRET

      bytes_d = unroll32 d
      h_a = hash_aux a
      t = xor bytes_d h_a

      bytes_p = unroll32 x_p
      rand = hash_nonce (t <> bytes_p <> m)

      k' = modQ (roll32 rand)

  if   k' == 0 -- negligible probability
  then Nothing -- XX handle me
  else do
    pt <- _mul k'
    let Affine x_r y_r = affine pt
        k | I.integerTestBit y_r 0 = _CURVE_Q - k'
          | otherwise = k'

        bytes_r = unroll32 x_r
        e = modQ . roll32 . hash_challenge
          $ bytes_r <> bytes_p <> m

        bytes_ked = unroll32 (modQ (k + e * d))

        sig = bytes_r <> bytes_ked

    guard (verify_schnorr m p_proj sig)
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
  :: (Integer -> Maybe Projective) -- partially-applied multiplication function
  -> BS.ByteString
  -> Pub
  -> BS.ByteString
  -> Bool
_verify_schnorr _mul m (affine -> Affine x_p _) sig
  | BS.length sig /= 64 = False
  | otherwise = M.isJust $ do
      capP@(Affine x_P _) <- lift x_p
      let (roll32 -> r, roll32 -> s) = BS.splitAt 32 sig
      guard (r < _CURVE_P && s < _CURVE_Q)
      let e = modQ . roll32 $ hash_challenge
                (unroll32 r <> unroll32 x_P <> m)
      pt0 <- _mul s
      pt1 <- mul_unsafe (projective capP) e
      let dif = add pt0 (neg pt1)
      guard (dif /= _CURVE_ZERO)
      let Affine x_R y_R = affine dif
      guard $ not (I.integerTestBit y_R 0 || x_R /= r)
      pure ()
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
bits2int :: BS.ByteString -> Integer
bits2int bs =
  let (fi -> blen) = BS.length bs * 8
      (fi -> qlen) = _CURVE_Q_BITS
      del = blen - qlen
  in  if   del > 0
      then roll bs `I.integerShiftR` del
      else roll bs

-- RFC6979 2.3.3
int2octets :: Integer -> BS.ByteString
int2octets i = pad (unroll i) where
  pad bs
    | BS.length bs < _CURVE_Q_BYTES = pad (BS.cons 0 bs)
    | otherwise = bs

-- RFC6979 2.3.4
bits2octets :: BS.ByteString -> BS.ByteString
bits2octets bs =
  let z1 = bits2int bs
      z2 = modQ z1
  in  int2octets z2

-- | An ECDSA signature.
data ECDSA = ECDSA {
    ecdsa_r :: !Integer
  , ecdsa_s :: !Integer
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
  :: Integer         -- ^ secret key
  -> BS.ByteString   -- ^ message
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
  :: Context         -- ^ secp256k1 context
  -> Integer         -- ^ secret key
  -> BS.ByteString   -- ^ message
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
  :: Integer        -- ^ secret key
  -> BS.ByteString  -- ^ message
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
  :: Context        -- ^ secp256k1 context
  -> Integer        -- ^ secret key
  -> BS.ByteString  -- ^ message
  -> Maybe ECDSA
sign_ecdsa_unrestricted' tex = _sign_ecdsa (mul_wnaf tex) Unrestricted Hash

-- Produce a "low-s" ECDSA signature for the provided message, using
-- the provided private key. Assumes that the message has already been
-- pre-hashed.
--
-- (Useful for testing against noble-secp256k1's suite, in which messages
-- in the test vectors have already been hashed.)
_sign_ecdsa_no_hash
  :: Integer        -- ^ secret key
  -> BS.ByteString  -- ^ message digest
  -> Maybe ECDSA
_sign_ecdsa_no_hash = _sign_ecdsa (mul _CURVE_G) LowS NoHash

_sign_ecdsa_no_hash'
  :: Context
  -> Integer
  -> BS.ByteString
  -> Maybe ECDSA
_sign_ecdsa_no_hash' tex = _sign_ecdsa (mul_wnaf tex) LowS NoHash

_sign_ecdsa
  :: (Integer -> Maybe Projective) -- partially-applied multiplication function
  -> SigType
  -> HashFlag
  -> Integer
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
    h = case hf of
      Hash -> SHA256.hash m
      NoHash -> m

    h_modQ = remQ (bits2int h) -- bits2int yields nonnegative

    sign_loop g = do
      k <- gen_k g
      let mpair = do
            kg <- _mul k
            let Affine (modQ -> r) _ = affine kg
            kinv <- modinv k (fi _CURVE_Q)
            let s = remQ (remQ (h_modQ + remQ (_SECRET * r)) * kinv)
            pure $! (r, s)
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
gen_k :: DRBG.DRBG s -> ST s Integer
gen_k g = loop g where
  loop drbg = do
    bytes <- DRBG.gen mempty (fi _CURVE_Q_BYTES) drbg
    let can = bits2int bytes
    if   can >= _CURVE_Q
    then loop drbg
    else pure can
{-# INLINE gen_k #-}

-- Convert an ECDSA signature to low-S form.
low :: ECDSA -> ECDSA
low (ECDSA r s) = ECDSA r ms where
  ms
    | s > B.unsafeShiftR _CURVE_Q 1 = modQ (negate s)
    | otherwise = s
{-# INLINE low #-}

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
  | s > B.unsafeShiftR _CURVE_Q 1 = False
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
  | s > B.unsafeShiftR _CURVE_Q 1 = False
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
  :: (Integer -> Maybe Projective) -- partially-applied multiplication function
  -> BS.ByteString
  -> Pub
  -> ECDSA
  -> Bool
_verify_ecdsa_unrestricted _mul (SHA256.hash -> h) p (ECDSA r s) = M.isJust $ do
  -- SEC1-v2 4.1.4
  guard (ge r && ge s)
  let e = remQ (bits2int h)
  s_inv <- modinv s (fi _CURVE_Q)
  let u1 = remQ (e * s_inv)
      u2 = remQ (r * s_inv)
  pt0 <- _mul u1
  pt1 <- mul_unsafe p u2
  let capR = add pt0 pt1
  guard (capR /= _CURVE_ZERO)
  let Affine (modQ -> v) _ = affine capR
  guard (v == r)
  pure ()
{-# INLINE _verify_ecdsa_unrestricted #-}

-- ecdh -----------------------------------------------------------------------

-- SEC1-v2 3.3.1, plus SHA256 hash

-- | Compute a shared secret, given a secret key and public secp256k1 point,
--   via Elliptic Curve Diffie-Hellman (ECDH).
--
--   The shared secret is the SHA256 hash of the x-coordinate of the
--   point obtained by scalar multiplication.
--
--   >>> let sec_alice = 0x03                   -- contrived
--   >>> let sec_bob   = 2 ^ 128 - 1            -- contrived
--   >>> let Just pub_alice = derive_pub sec_alice
--   >>> let Just pub_bob   = derive_pub sec_bob
--   >>> let secret_as_computed_by_alice = ecdh pub_bob sec_alice
--   >>> let secret_as_computed_by_bob   = ecdh pub_alice sec_bob
--   >>> secret_as_computed_by_alice == secret_as_computed_by_bob
--   True
ecdh
  :: Projective    -- ^ public key
  -> Integer       -- ^ secret key
  -> Maybe BS.ByteString -- ^ shared secret
ecdh pub _SECRET = do
  pt <- mul pub _SECRET
  guard (pt /= _CURVE_ZERO)
  let Affine x _ = affine pt
  pure $! SHA256.hash (unroll32 x)

