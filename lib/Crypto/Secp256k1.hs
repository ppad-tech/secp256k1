{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.Secp256k1 where

import Control.Monad (when)
import Control.Monad.ST
import Data.Bits (Bits, (.&.), (.|.))
import qualified Data.Bits as B (shiftL, shiftR)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.STRef
import GHC.Generics

-- XX could stand some reorganization; lots of stuff 'baked in', e.g. in mods
--
-- XX seems Point should have a reference to the curve it's on; probably a lazy
--    one. otherwise hard to implement Eq.
--
--    then again, we're exclusively concerned with a single curve here, so
--    who cares. bake everything in.
--
--    only counterargument is that we may want to reuse the same skeleton for
--    other libraries after the fact. so we have a single library implementing
--    modular arithmetic, curves, etc., and then implement other stuff on top
--    of that
--
--    i think i like the idea of abstracting quickly and baking types and utils
--    and such into an internal library, e.g. secp256k1-sys; later extract that

-- modular arithmetic utilities

-- XX be aware of non-constant-timeness in these; i should understand this
--    issue *precisely*

-- modular division
moddiv :: Integral a => a -> a -> a
moddiv a b
    | r < 0     = b + r
    | otherwise = r
  where
    r = a `mod` b

-- modular division by secp256k1 group order
mods :: Integral a => a -> a
mods a = moddiv a (curve_p secp256k1)

-- is field element (i.e., is invertible)
fe :: Integral a => a -> Bool
fe n = 0 < n && n < (curve_p secp256k1)

-- is group element
ge :: Integral a => a -> Bool
ge n = 0 < n && n < (curve_n secp256k1)

data Triple a = Triple !a !a !a
  deriving stock Generic

-- for a, b, return x, y, g such that ax + by = g for g = gcd(a, b)
egcd :: Integral a => a -> a -> Triple a
egcd a 0 = Triple 1 0 a
egcd a b =
  let (q, r) = a `quotRem` b
      Triple s t g = egcd b r
  in  Triple t (s - q * t) g

-- for a, m return x such that ax = 1 mod m
modinv :: Integral a => a -> a -> Maybe a
modinv a m
    | g == 1    = Just (pos i)
    | otherwise = Nothing
  where
    Triple i _ g = egcd a m
    pos x
      | x < 0     = x + m
      | otherwise = x

-- partial modinv
modinv' :: Integral a => a -> a -> a
modinv' a m = case modinv a m of
  Just x  -> x
  Nothing -> error "modinv': no modular inverse"

-- elliptic curve

data Curve a = Curve {
    curve_p  :: a -- ^ field prime
  , curve_n  :: a -- ^ group order
  , curve_a  :: a -- ^ /a/ coefficient, weierstrass form
  , curve_b  :: a -- ^ /b/ coefficient, weierstrass form
  , curve_gx :: a -- ^ base point x
  , curve_gy :: a -- ^ base point y
  }
  deriving stock (Show, Generic)

secp256k1 :: Integral a => Curve a
secp256k1 = Curve p n 0 7 gx gy where
  b256 = 2 ^ (256 :: Integer)
  p    = b256 - 0x1000003d1
  n    = b256 - 0x14551231950b75fc4402da1732fc9bebf
  gx   = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  gy   = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

-- XX not general weierstrass; only for j-invariant 0 (i.e. a == 0)
weierstrass :: Integral a => a -> a
weierstrass x = mods (mods (x * x) * x + curve_b secp256k1)

-- modular square root
modsqrt :: (Integral a, Bits a) => a -> Maybe a
modsqrt n = runST $ do
    r   <- newSTRef 1
    num <- newSTRef n
    e   <- newSTRef ((p + 1) `div` 4)
    loop r num e
    rr  <- readSTRef r
    pure $
      if   mods (rr * rr) == n
      then Just rr
      else Nothing
  where
    p = curve_p secp256k1
    loop sr snum se = do
      e <- readSTRef se
      when (e > 0) $ do
        when (e .&. 1 == 1) $ do
          num <- readSTRef snum
          modifySTRef' sr (\lr -> (lr * num) `rem` p)
        modifySTRef' snum (\ln -> (ln * ln) `rem` p)
        modifySTRef' se (`B.shiftR` 1)
        loop sr snum se

-- group bytelength
_GROUP_BYTELENGTH :: Integral a => a
_GROUP_BYTELENGTH = 32

-- curve point

data Affine a = Affine !a !a
  deriving stock (Show, Generic)

instance Integral a => Eq (Affine a) where
  Affine x1 y1 == Affine x2 y2 =
    mods x1 == mods x2 && mods y1 == mods y2

data Projective a = Projective {
    px :: !a
  , py :: !a
  , pz :: !a
  }
  deriving stock (Show, Generic)

instance Integral a => Eq (Projective a) where
  Projective ax ay az == Projective bx by bz =
    let x1z2 = mods (ax * bz)
        x2z1 = mods (bx * az)
        y1z2 = mods (ay * bz)
        y2z1 = mods (by * az)
    in  x1z2 == x2z1 && y1z2 == y2z1

_ZERO :: Integral a => Projective a
_ZERO = Projective 0 1 0

_BASE :: Integral a => Projective a
_BASE = Projective (curve_gx secp256k1) (curve_gy secp256k1) 1

-- negate point
neg :: (Integral a, Num a) => Projective a -> Projective a
neg (Projective x y z) = Projective x (mods (negate y)) z

-- XX correct?
add_affine :: (Integral a, Num a) => Affine a -> Affine a -> Maybe (Affine a)
add_affine p@(Affine x1 y1) q@(Affine x2 y2)
    | p == q && (p == azero || q == azero) = pure azero
    | p == q = do
        i <- modinv (mods (2 * y1)) (curve_p secp256k1)
        let s = mods (mods (3 * mods (x1 * x1)) * i)
            x = mods (mods (s * s) - mods (2 * x1))
            y = mods (mods (s * mods (x1 - x)) - y1)
        pure (Affine x y)
    | x1 == 0 && y1 == 0 = pure q
    | x2 == 0 && y2 == 0 = pure p
    | x1 == x2 = pure azero
    | otherwise = do
        i <- modinv (mods (x1 - x2)) (curve_p secp256k1)
        let s = mods (mods (y1 - y2) * i)
            x3 = mods (mods (s * s) - x1 - x2)
            y3 = mods (mods (s * mods (x1 - x3)) - y1)
        pure (Affine x3 y3)
  where
    azero = Affine 0 0

-- algo 1, "complete addition formulas for prime order elliptic curves,"
-- renes et al, 2015
add :: (Integral a, Num a) => Projective a -> Projective a -> Projective a
add (Projective x1 y1 z1) (Projective x2 y2 z2) = runST $ do
  let a = curve_a secp256k1
      b = curve_b secp256k1
  x3 <- newSTRef 0
  y3 <- newSTRef 0
  z3 <- newSTRef 0
  let b3 = mods (b * 3)
  t0 <- newSTRef (mods (x1 * x2))
  t1 <- newSTRef (mods (y1 * y2))
  t2 <- newSTRef (mods (z1 * z2))
  t3 <- newSTRef (mods (x1 + y1))
  t4 <- newSTRef (mods (x2 + y2))
  readSTRef t4 >>= \r4 ->
    modifySTRef' t3 (\r3 -> mods (r3 * r4))
  readSTRef t0 >>= \r0 ->
    readSTRef t1 >>= \r1 ->
    writeSTRef t4 (mods (r0 + r1))
  readSTRef t4 >>= \r4 ->
    modifySTRef' t3 (\r3 -> mods (r3 - r4))
  writeSTRef t4 (mods (x1 + z1))
  t5 <- newSTRef (mods (x2 + z2))
  readSTRef t5 >>= \r5 ->
    modifySTRef' t4 (\r4 -> mods (r4 * r5))
  readSTRef t0 >>= \r0 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef t5 (mods (r0 + r2))
  readSTRef t5 >>= \r5 ->
    modifySTRef' t4 (\r4 -> mods (r4 - r5))
  writeSTRef t5 (mods (y1 + z1))
  writeSTRef x3 (mods (y2 + z2))
  readSTRef x3 >>= \rx3 ->
    modifySTRef' t5 (\r5 -> mods (r5 * rx3))
  readSTRef t1 >>= \r1 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef x3 (mods (r1 + r2))
  readSTRef x3 >>= \rx3 ->
    modifySTRef' t5 (\r5 -> mods (r5 - rx3))
  readSTRef t4 >>= \r4 ->
    writeSTRef z3 (mods (a * r4))
  readSTRef t2 >>= \r2 ->
    writeSTRef x3 (mods (b3 * r2))
  readSTRef x3 >>= \rx3 ->
    modifySTRef' z3 (\rz3 -> mods (rx3 + rz3))
  readSTRef t1 >>= \r1 ->
    readSTRef z3 >>= \rz3 ->
    writeSTRef x3 (mods (r1 - rz3))
  readSTRef t1 >>= \r1 ->
    modifySTRef' z3 (\rz3 -> mods (r1 + rz3))
  readSTRef x3 >>= \rx3 ->
    readSTRef z3 >>= \rz3 ->
    writeSTRef y3 (mods (rx3 * rz3))
  readSTRef t0 >>= \r0 ->
    writeSTRef t1 (mods (r0 + r0))
  readSTRef t0 >>= \r0 ->
    modifySTRef' t1 (\r1 -> mods (r1 + r0))
  modifySTRef' t2 (\r2 -> mods (a * r2))
  modifySTRef' t4 (\r4 -> mods (b3 * r4))
  readSTRef t2 >>= \r2 ->
    modifySTRef' t1 (\r1 -> mods (r1 + r2))
  readSTRef t0 >>= \r0 ->
    modifySTRef' t2 (\r2 -> mods (r0 - r2))
  modifySTRef' t2 (\r2 -> mods (a * r2))
  readSTRef t2 >>= \r2 ->
    modifySTRef' t4 (\r4 -> mods (r4 + r2))
  readSTRef t1 >>= \r1 ->
    readSTRef t4 >>= \r4 ->
    writeSTRef t0 (mods (r1 * r4))
  readSTRef t0 >>= \r0 ->
    modifySTRef' y3 (\ry3 -> mods (ry3 + r0))
  readSTRef t5 >>= \r5 ->
    readSTRef t4 >>= \r4 ->
    writeSTRef t0 (mods (r5 * r4))
  readSTRef t3 >>= \r3 ->
    modifySTRef' x3 (\rx3 -> mods (r3 * rx3))
  readSTRef t0 >>= \r0 ->
    modifySTRef' x3 (\rx3 -> mods (rx3 - r0))
  readSTRef t1 >>= \r1 ->
    readSTRef t3 >>= \r3 ->
    writeSTRef t0 (mods (r3 * r1))
  readSTRef t5 >>= \r5 ->
    modifySTRef' z3 (\rz3 -> mods (r5 * rz3))
  readSTRef t0 >>= \r0 ->
    modifySTRef' z3 (\rz3 -> mods (rz3 + r0))
  Projective <$> readSTRef x3 <*> readSTRef y3 <*> readSTRef z3

add_pure :: (Integral a, Num a) => Projective a -> Projective a -> Projective a
add_pure (Projective x1 y1 z1) (Projective x2 y2 z2) =
  let a = curve_a secp256k1
      b = curve_b secp256k1
      b3 = mods (b * 3)
      t0 = mods (x1 * x2)
      t1 = mods (y1 * y2)
      t2 = mods (z1 * z2)
      t3 = mods (x1 + y1)
      t4 = mods (x2 + y2)
      t30 = mods (t3 * t4)
      t40 = mods (t0 + t1)
      t300 = mods (t30 - t40)
      t400 = mods (x1 + z1)
      t5 = mods (x2 + z2)
      t4000 = mods (t400 * t5)
      t50 = mods (t0 + t2)
      t40000 = mods (t4000 - t50)
      t500 = mods (y1 + z1)
      x3 = mods (y2 + z2)
      t5000 = mods (t500 * x3)
      x30 = mods (t1 + t2)
      t50000 = mods (t5000 - x30)
      z3 = mods (a * t40000)
      x300 = mods (b3 * t2)
      z30 = mods (x300 + z3)
      x3000 = mods (t1 - z30)
      z300 = mods (t1 + z30)
      y3 = mods (x3000 * z300)
      t10 = mods (t0 + t0)
      t100 = mods (t10 + t0)
      t20 = mods (a * t2)
      t400000 = mods (b3 * t40000)
      t1000 = mods (t100 + t20)
      t200 = mods (t0 - t20)
      t2000 = mods (a * t200)
      t4000000 = mods (t400000 + t2000)
      t00 = mods (t1000 * t4000000)
      y30 = mods (y3 + t00)
      t000 = mods (t50000 * t4000000)
      x30000 = mods (t300 * x3000)
      x300000 = mods (x30000 - t000)
      t0000 = mods (t300 * t1000)
      z3000 = mods (t50000 * z300)
      z30000 = mods (z3000 + t0000)
  in  Projective x300000 y30 z30000

-- algo 7, "complete addition formulas for prime order elliptic curves,"
-- renes et al, 2015
add' :: (Integral a, Num a) => Projective a -> Projective a -> Projective a
add' (Projective x1 y1 z1) (Projective x2 y2 z2) = runST $ do
  let b = curve_b secp256k1
  x3 <- newSTRef 0
  y3 <- newSTRef 0
  z3 <- newSTRef 0
  let b3 = mods (b * 3)
  t0 <- newSTRef (mods (x1 * x2)) -- 1
  t1 <- newSTRef (mods (y1 * y2))
  t2 <- newSTRef (mods (z1 * z2))
  t3 <- newSTRef (mods (x1 + y1)) -- 4
  t4 <- newSTRef (mods (x2 + y2))
  readSTRef t4 >>= \r4 ->
    modifySTRef' t3 (\r3 -> mods (r3 * r4))
  readSTRef t0 >>= \r0 ->
    readSTRef t1 >>= \r1 ->
    writeSTRef t4 (mods (r0 + r1))
  readSTRef t4 >>= \r4 ->
    modifySTRef' t3 (\r3 -> mods (r3 - r4)) -- 8
  writeSTRef t4 (mods (y1 + z1))
  writeSTRef x3 (mods (y2 + z2))
  readSTRef x3 >>= \rx3 ->
    modifySTRef' t4 (\r4 -> mods (r4 * rx3))
  readSTRef t1 >>= \r1 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef x3 (mods (r1 + r2)) -- 12
  readSTRef x3 >>= \rx3 ->
    modifySTRef' t4 (\r4 -> mods (r4 - rx3))
  writeSTRef x3 (mods (x1 + z1))
  writeSTRef y3 (mods (x2 + z2))
  readSTRef y3 >>= \ry3 ->
    modifySTRef' x3 (\rx3 -> mods (rx3 * ry3)) -- 16
  readSTRef t0 >>= \r0 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef y3 (mods (r0 + r2))
  readSTRef x3 >>= \rx3 ->
    modifySTRef' y3 (\ry3 -> mods (rx3 - ry3))
  readSTRef t0 >>= \r0 ->
    writeSTRef x3 (mods (r0 + r0))
  readSTRef x3 >>= \rx3 ->
    modifySTRef t0 (\r0 -> mods (rx3 + r0)) -- 20
  modifySTRef' t2 (\r2 -> mods (b3 * r2))
  readSTRef t1 >>= \r1 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef z3 (mods (r1 + r2))
  readSTRef t2 >>= \r2 ->
    modifySTRef' t1 (\r1 -> mods (r1 - r2))
  modifySTRef' y3 (\ry3 -> mods (b3 * ry3)) -- 24
  readSTRef t4 >>= \r4 ->
    readSTRef y3 >>= \ry3 ->
    writeSTRef x3 (mods (r4 * ry3))
  readSTRef t3 >>= \r3 ->
    readSTRef t1 >>= \r1 ->
    writeSTRef t2 (mods (r3 * r1))
  readSTRef t2 >>= \r2 ->
    modifySTRef' x3 (\rx3 -> mods (r2 - rx3))
  readSTRef t0 >>= \r0 ->
    modifySTRef' y3 (\ry3 -> mods (ry3 * r0)) -- 28
  readSTRef z3 >>= \rz3 ->
    modifySTRef' t1 (\r1 -> mods (r1 * rz3))
  readSTRef t1 >>= \r1 ->
    modifySTRef' y3 (\ry3 -> mods (r1 + ry3))
  readSTRef t3 >>= \r3 ->
    modifySTRef' t0 (\r0 -> mods (r0 * r3))
  readSTRef t4 >>= \r4 ->
    modifySTRef' z3 (\rz3 -> mods (rz3 * r4)) -- 32
  readSTRef t0 >>= \r0 ->
    modifySTRef' z3 (\rz3 -> mods (rz3 + r0))
  Projective <$> readSTRef x3 <*> readSTRef y3 <*> readSTRef z3

-- double a point
double :: (Integral a, Num a) => Projective a -> Projective a
double p = add p p

-- to affine coordinates
affine :: Integral a => Projective a -> Maybe (Affine a)
affine p@(Projective x y z)
  | p == _ZERO = pure (Affine 0 0)
  | z == 1     = pure (Affine x y)
  | otherwise  = do
      iz <- modinv z (curve_p secp256k1)
      if   mods (z * iz) /= 1
      then Nothing
      else pure (Affine (mods (x * iz)) (mods (y * iz)))

-- partial affine
affine' :: Integral a => Projective a -> Affine a
affine' p = case affine p of
  Nothing -> error "bang"
  Just x  -> x

-- to projective coordinates
projective :: Integral a => Affine a -> Projective a
projective (Affine x y)
  | x == 0 && y == 0 = _ZERO
  | otherwise = Projective x y 1

-- point is valid
valid :: Integral a => Projective a -> Bool
valid p = case affine p of
  Nothing -> False
  Just (Affine x y)
    | not (fe x) || not (fe y) -> False
    | mods (y * y) /= weierstrass x -> False
    | otherwise -> True

-- parse hex-encoded
parse_point :: (Bits a, Integral a) => BS.ByteString -> Maybe (Projective a)
parse_point (B16.decode -> ebs) = case ebs of
  Left _   -> Nothing
  Right bs -> case BS.uncons bs of
    Nothing -> Nothing
    Just (h, t) ->
      let (roll -> x, etc) = BS.splitAt _GROUP_BYTELENGTH t
          len = BS.length bs
      in  if   len == 33 && (h == 0x02 || h == 0x03) -- compressed
          then if   not (fe x)
               then Nothing
               else do
                 y <- modsqrt (weierstrass x)
                 let yodd = y .&. 1 == 1
                     hodd = h .&. 1 == 1
                 pure $
                   if   hodd /= yodd
                   then Projective x (mods (negate y)) 1
                   else Projective x y 1
          else if   len == 65 && h == 0x04 -- uncompressed
               then let (roll -> y, _) = BS.splitAt _GROUP_BYTELENGTH etc
                        p = Projective x y 1
                    in  if   valid p
                        then Just p
                        else Nothing
               else Nothing

-- big-endian bytestring decoding
roll :: (Bits a, Integral a) => BS.ByteString -> a
roll = BS.foldl' unstep 0 where
  unstep a b = a `B.shiftL` 8 .|. fromIntegral b

