{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UnboxedSums #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.Curve.Secp256k1 (
  -- * Coordinate systems and transformations
    Affine(..)
  , Projective(..)
  , affine
  , projective
  , valid

  -- * Elliptic curve group operations
  , neg
  , add
  , double
  , mul
  , mul_safe

  -- * Point parsing
  , parse_point

  -- * ECDSA
  , ECDSA(..)
  , SigType(..)
  , sign
  , sign_unrestricted
  , verify
  , verify_unrestricted

    -- for testing
  , _sign_no_hash
  ) where

import Control.Monad (when)
import Control.Monad.ST
import qualified Crypto.DRBG.HMAC as DRBG
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16 -- XX kill this dep
import Data.Int (Int64)
import Data.STRef
import GHC.Generics
import GHC.Natural
import qualified GHC.Num.Integer as I
import Prelude hiding (mod)

-- XX RFC 6979 uses Q whereas SEC1-v2 uses N for group order

-- keystroke savers & other utilities -----------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- generic modular inverse
-- for a, m return x such that ax = 1 mod m
modinv :: Integer -> Natural -> Maybe Integer
modinv a m = case I.integerRecipMod# a m of
  (# fi -> n | #) -> Just $! n
  (# | _ #) -> Nothing
{-# INLINE modinv #-}

-- coordinate systems ---------------------------------------------------------

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

-- | Convert to affine coordinates.
affine :: Projective -> Affine
affine p@(Projective x y z)
  | p == _ZERO = Affine 0 0
  | z == 1     = Affine x y
  | otherwise  = case modinv z (fi _CURVE_P) of
      Nothing -> error "ppad-secp256k1 (affine): impossible point"
      Just iz -> Affine (modP (x * iz)) (modP (y * iz))

-- | Convert to projective coordinates.
projective :: Affine -> Projective
projective (Affine x y)
  | x == 0 && y == 0 = _ZERO
  | otherwise = Projective x y 1

-- | Point is valid
valid :: Projective -> Bool
valid p = case affine p of
  Affine x y
    | not (fe x) || not (fe y) -> False
    | modP (y * y) /= weierstrass x -> False
    | otherwise -> True

-- curve parameters -----------------------------------------------------------
-- see https://www.secg.org/sec2-v2.pdf for parameter specs

-- secp256k1 field prime
--
-- = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
_CURVE_P :: Integer
_CURVE_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

-- XX can i make this abstract and use SPECIALIZE pragmas?

-- secp256k1 group order
_CURVE_Q :: Integer
_CURVE_Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

-- bitlength of group order
--
-- = smallest integer such that _CURVE_Q < 2 ^ _CURVE_Q_BITS
_CURVE_Q_BITS :: Int64
_CURVE_Q_BITS = 256

-- bytelength of _CURVE_Q
--
-- = _CURVE_Q_BITS / 8
_CURVE_Q_BYTES :: Int64
_CURVE_Q_BYTES = 32

-- secp256k1 short weierstrass form, /a/ coefficient
_CURVE_A :: Integer
_CURVE_A = 0

-- secp256k1 weierstrass form, /b/ coefficient
_CURVE_B :: Integer
_CURVE_B = 7

-- secp256k1 generator
--
-- = parse_point
--     "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
_CURVE_G :: Projective
_CURVE_G = Projective x y 1 where
  x = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

-- secp256k1 zero point
_ZERO :: Projective
_ZERO = Projective 0 1 0

-- | secp256k1 in prime order j-invariant 0 form (i.e. a == 0).
weierstrass :: Integer -> Integer
weierstrass x = modP (modP (x * x) * x + _CURVE_B)

-- field, group operations ----------------------------------------------------

-- | Division modulo secp256k1 field prime.
modP :: Integer -> Integer
modP a = I.integerMod a _CURVE_P
{-# INLINE modP #-}

-- | Division modulo secp256k1 group order.
modQ :: Integer -> Integer
modQ a = I.integerMod a _CURVE_Q
{-# INLINE modQ #-}

-- | Is field element?
fe :: Integer -> Bool
fe n = 0 < n && n < _CURVE_P

-- | Is group element?
ge :: Integer -> Bool
ge n = 0 < n && n < _CURVE_Q

-- | Square root (Shanks-Tonelli) modulo secp256k1 field prime.
--
--   For a, return x such that a = x x mod _CURVE_P.
modsqrt :: Integer -> Maybe Integer
modsqrt n = runST $ do
    r   <- newSTRef 1
    num <- newSTRef n
    e   <- newSTRef ((_CURVE_P + 1) `div` 4)
    loop r num e
    rr  <- readSTRef r
    pure $
      if   modP (rr * rr) == n
      then Just $! rr
      else Nothing
  where
    loop sr snum se = do
      e <- readSTRef se
      when (e > 0) $ do
        when (I.integerTestBit e 0) $ do
          num <- readSTRef snum
          modifySTRef' sr (\lr -> (lr * num) `rem` _CURVE_P)
        modifySTRef' snum (\ln -> (ln * ln) `rem` _CURVE_P)
        modifySTRef' se (`I.integerShiftR` 1)
        loop sr snum se

-- ec point operations --------------------------------------------------------

-- | Negate secp256k1 point.
neg :: Projective -> Projective
neg (Projective x y z) = Projective x (modP (negate y)) z

-- XX check implications on timing safety by special-casing algos below

-- | Elliptic curve addition on secp256k1.
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
  let b3 = modP (_CURVE_B * 3)
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
  | z2 /= 1   = error "ppad-secp256k1: internal error"
  | otherwise = runST $ do
      x3 <- newSTRef 0
      y3 <- newSTRef 0
      z3 <- newSTRef 0
      let b3 = modP (_CURVE_B * 3)
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
  let b3 = modP (_CURVE_B * 3)
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

-- | Scalar multiplication of secp256k1 points.
mul :: Projective -> Integer -> Projective
mul p n
    | n == 0 = _ZERO
    | not (ge n) = error "ppad-secp256k1 (mul): scalar not in group"
    | otherwise  = loop _ZERO p n
  where
    loop !r !d m
      | m <= 0 = r
      | otherwise =
          let nd = double d
              nm = I.integerShiftR m 1
              nr = if I.integerTestBit m 0 then add r d else r
          in  loop nr nd nm

-- | Safe scalar multiplication of secp256k1 points.
mul_safe :: Projective -> Integer -> Projective
mul_safe p n
    | not (ge n) = error "ppad-secp256k1 (mul_safe): scalar not in group"
    | otherwise  = loop _ZERO _CURVE_G p n
  where
    loop !r !f !d m
      | m <= 0 = r
      | otherwise =
          let nd = double d
              nm = I.integerShiftR m 1
          in  if   I.integerTestBit m 0
              then loop (add r d) f nd nm
              else loop r (add f d) nd nm

-- parsing --------------------------------------------------------------------

-- | Parse hex-encoded compressed or uncompressed point.
parse_point :: BS.ByteString -> Maybe Projective
parse_point (B16.decode -> ebs) = case ebs of
  Left _   -> Nothing
  Right bs -> case BS.uncons bs of
    Nothing -> Nothing
    Just (fi -> h, t) ->
      let (roll -> x, etc) = BS.splitAt (fi _CURVE_Q_BYTES) t
          len = BS.length bs
      in  if   len == 33 && (h == 0x02 || h == 0x03)  -- compressed
          then if   not (fe x)
               then Nothing
               else do
                 y <- modsqrt (weierstrass x)
                 let yodd = I.integerTestBit y 0
                     hodd = I.integerTestBit h 0
                 pure $
                   if   hodd /= yodd
                   then Projective x (modP (negate y)) 1
                   else Projective x y 1
          else
               if   len == 65 && h == 0x04  -- uncompressed
               then let (roll -> y, _) = BS.splitAt (fi _CURVE_Q_BYTES) etc
                        p = Projective x y 1
                    in  if   valid p
                        then Just p
                        else Nothing
               else Nothing

-- big-endian bytestring decoding
roll :: BS.ByteString -> Integer
roll = BS.foldl' alg 0 where
  alg a (fi -> b) = (a `I.integerShiftL` 8) `I.integerOr` b

-- big-endian bytestring encoding
unroll :: Integer -> BS.ByteString
unroll i = case i of
    0 -> BS.singleton 0
    _ -> BS.reverse $ BS.unfoldr step i -- XX looks slow
  where
    step 0 = Nothing
    step m = Just (fi m, m `I.integerShiftR` 8)

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
  pad !bs
    | BS.length bs < fi _CURVE_Q_BYTES = pad (BS.cons 0 bs)
    | otherwise = bs

-- RFC6979 2.3.4
bits2octets :: BS.ByteString -> BS.ByteString
bits2octets bs =
  let z1 = bits2int bs
      z2 = modQ z1
  in  int2octets z2

data ECDSA = ECDSA {
    ecdsa_r :: !Integer
  , ecdsa_s :: !Integer
  }
  deriving (Eq, Show, Generic)

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
--   'sign' produces a "low-s" signature, as is commonly required
--   in applications. If you need a generic ECDSA signature, use
--   'sign_unrestricted'.
sign
  :: Integer         -- ^ secret key
  -> BS.ByteString   -- ^ message
  -> ECDSA
sign = _sign LowS Hash

-- | Produce an ECDSA signature for the provided message, using the
--   provided private key.
--
--   'sign_unrestricted' produces an unrestricted ECDSA signature, which
--   is less common in applications. If you need a conventional "low-s"
--   signature, use 'sign'.
sign_unrestricted
  :: Integer        -- ^ secret key
  -> BS.ByteString  -- ^ message
  -> ECDSA
sign_unrestricted = _sign Unrestricted Hash

_sign :: SigType -> HashFlag -> Integer -> BS.ByteString -> ECDSA
_sign ty hf x m
  | not (ge x) = error "ppad-secp256k1 (sign): invalid secret key"
  | otherwise  = runST $ do
      -- RFC6979 sec 3.3a
      let entropy = int2octets x
          nonce   = bits2octets h
      drbg <- DRBG.new SHA256.hmac entropy nonce mempty
      -- RFC6979 sec 2.4
      sign_loop drbg
    where
      h = case hf of
        Hash -> SHA256.hash m
        NoHash -> m

      h_modQ = modQ (bits2int h)

      sign_loop g = do
        k <- gen_k g
        let kg = mul _CURVE_G k
            Affine (modQ -> r) _ = affine kg
            s = case modinv k (fi _CURVE_Q) of
              Nothing   -> error "ppad-secp256k1 (sign): bad k value"
              -- XX check timing implications of mod division of secret by Q
              Just kinv -> modQ (modQ (h_modQ + modQ (x * r)) * kinv)
        if   r == 0 -- negligible probability
        then sign_loop g
        else let !sig = ECDSA r s
             in  case ty of
                   Unrestricted -> pure sig
                   LowS -> pure (low sig)

-- Produce a "low-s" ECDSA signature for the provided message, using
-- the provided private key.
--
-- Assumes that the message has already been pre-hashed.
--
-- Useful for testing against noble-secp256k1's suite, in which messages
-- have already been hashed.
_sign_no_hash
  :: Integer        -- ^ secret key
  -> BS.ByteString  -- ^ message digest
  -> ECDSA
_sign_no_hash = _sign LowS NoHash

-- RFC6979 sec 3.3b
gen_k :: DRBG.DRBG s -> ST s Integer
gen_k g = loop g where
  loop drbg = do
    bytes <- DRBG.gen mempty (fi _CURVE_Q_BYTES) drbg
    let !can = bits2int bytes
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

-- | Verify an unrestricted ECDSA signature for the provided message and
--   public key.
verify_unrestricted
  :: BS.ByteString -- ^ message
  -> Projective    -- ^ public key
  -> ECDSA         -- ^ signature
  -> Bool
verify_unrestricted (SHA256.hash -> h) p (ECDSA r s)
  -- SEC1-v2 4.1.4
  | not (ge r) || not (ge s) = False
  | otherwise =
      let e     = modQ (bits2int h)
          s_inv = case modinv s (fi _CURVE_Q) of
            -- 'ge s' assures existence of inverse
            Nothing -> error "ppad-secp256k1 (verify): no inverse"
            Just si -> si
          u1   = modQ (e * s_inv)
          u2   = modQ (r * s_inv)
          capR = add (mul _CURVE_G u1) (mul p u2)
      in  if   capR == _ZERO
          then False
          else let Affine (modQ -> v) _ = affine capR
               in  v == r

-- | Verify a "low-s" ECDSA signature for the provided message and
--   public key.
verify
  :: BS.ByteString -- ^ message
  -> Projective    -- ^ public key
  -> ECDSA         -- ^ signature
  -> Bool
verify m p sig@(ECDSA _ s)
  | s > B.unsafeShiftR _CURVE_Q 1 = False
  | otherwise = verify_unrestricted m p sig

