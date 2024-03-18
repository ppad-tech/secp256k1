{-# LANGUAGE ViewPatterns #-}

module Crypto.Secp256k1 where

import Control.Monad (when)
import Control.Monad.ST
import Data.Bits (Bits, (.&.), (.|.))
import qualified Data.Bits as B (shiftL, shiftR)
import qualified Data.ByteString as BS
import Data.STRef

-- XX seems like this should be easy to abstract

-- modular arithmetic utilities
-- XX be aware of non-constant-timeness in these; i should understand this
--    exactly

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
    curve_p  :: !a -- ^ field prime
  , curve_n  :: !a -- ^ group order
  , curve_a  :: !a -- ^ /a/ coefficient, weierstrass form
  , curve_b  :: !a -- ^ /b/ coefficient, weierstrass form
  , curve_gx :: !a -- ^ base point x
  , curve_gy :: !a -- ^ base point y
  }
  deriving Show

secp256k1 :: Integral a => Curve a
secp256k1 = Curve p n 0 7 gx gy where
  b256 = 2 ^ (256 :: Integer)
  p    = b256 - 0x1000003d1
  n    = b256 - 0x14551231950b75fc4402da1732fc9bebf
  gx   = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  gy   = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

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

data Point a = Point {
    px :: !a
  , py :: !a
  , pz :: !a
  }
  deriving Show

instance Integral a => Eq (Point a) where
  Point ax ay az == Point bx by bz =
    let x1z2 = mods (ax * bz)
        x2z1 = mods (bx * az)
        y1z2 = mods (ay * bz)
        y2z1 = mods (by * az)
    in  x1z2 == x2z1 && y1z2 == y2z1

_ZERO :: Integral a => Point a
_ZERO = Point 0 1 0

_BASE :: Integral a => Point a
_BASE = Point (curve_gx secp256k1) (curve_gy secp256k1) 1

neg :: (Integral a, Num a) => Point a -> Point a
neg (Point x y z) = Point x (mods (negate y)) z

add :: (Integral a, Num a) => Point a -> Point a -> Point a
add (Point x1 y1 z1) (Point x2 y2 z2) = runST $ do
  let a = curve_a secp256k1
      b = curve_b secp256k1
  x3 <- newSTRef 0
  y3 <- newSTRef 0
  z3 <- newSTRef 0
  let b3 = mods (b * 3)
  t0 <- newSTRef (mods (x1 * x2))
  t1 <- newSTRef (mods (y1 * y2))
  t2 <- newSTRef (mods (z2 * z2))
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
    modifySTRef' t4 (\r4 -> mods (r4 + r5))
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
  Point <$> readSTRef x3 <*> readSTRef y3 <*> readSTRef z3

double :: (Integral a, Num a) => Point a -> Point a
double p = add p p

-- XX assumes we're dealing with hex; need to decode
parse_point :: (Bits a, Integral a) => BS.ByteString -> Maybe (Point a)
parse_point bs = case BS.uncons bs of
  Nothing -> Nothing
  Just (h, t) ->
    let (roll -> x, etc) = BS.splitAt _GROUP_BYTELENGTH t
        len = BS.length bs
    in  if   len == 33 && (h == 0x02 || h == 0x03) -- compressed
        then if   not (fe x) -- x must be converted to num
             then Nothing
             else do
               y <- modsqrt (weierstrass x)
               let yodd = y .&. 1 == 1
                   hodd = h .&. 1 == 1
               pure $
                 if   hodd /= yodd
                 then Point x (mods (negate y)) 1
                 else Point x y 1
        else if   len == 65 && h == 0x04        -- uncompressed
             then let (roll -> y, _) = BS.splitAt _GROUP_BYTELENGTH etc
                  in  Just (Point x y 1) -- XX check validity
             else Nothing

-- big-endian bytestring decoding
roll :: (Bits a, Integral a) => BS.ByteString -> a
roll = BS.foldl' unstep 0 where
  unstep a b = a `B.shiftL` 8 .|. fromIntegral b

