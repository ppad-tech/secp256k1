{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedSums #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.Secp256k1 where

import Control.Monad (when)
import Control.Monad.ST
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.STRef
import GHC.Generics
import GHC.Natural
import qualified GHC.Num.Integer as I

_B256 :: Integer
_B256 = 2 ^ (256 :: Integer)

-- secp256k1 field prime
_CURVE_P :: Integer
_CURVE_P = _B256 - 0x1000003d1

-- secp256k1 group order
_CURVE_N :: Integer
_CURVE_N = _B256 - 0x14551231950b75fc4402da1732fc9bebf

-- secp256k1 short weierstrass form, /a/ coefficient
_CURVE_A :: Integer
_CURVE_A = 0

-- secp256k1 weierstrass form, /b/ coefficient
_CURVE_B :: Integer
_CURVE_B = 7

-- secp256k1 base point, x coordinate
_CURVE_GX :: Integer
_CURVE_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

-- secp256k1 base point, y coordinate
_CURVE_GY :: Integer
_CURVE_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

-- modular division by secp256k1 group order
mods :: Integer -> Integer
mods a = I.integerMod a _CURVE_P

-- is field element (i.e., is invertible)
fe :: Integer -> Bool
fe n = 0 < n && n < _CURVE_P

-- is group element
ge :: Integer -> Bool
ge n = 0 < n && n < _CURVE_N

-- for a, m return x such that ax = 1 mod m
modinv :: Integer -> Natural -> Maybe Integer
modinv a m = case I.integerRecipMod# a m of
  (# n | #) -> Just (fromIntegral n)
  (# | _ #) -> Nothing

-- modular square root (shanks-tonelli)
modsqrt :: Integer -> Maybe Integer
modsqrt n = runST $ do
    r   <- newSTRef 1
    num <- newSTRef n
    e   <- newSTRef ((_CURVE_P + 1) `div` 4)
    loop r num e
    rr  <- readSTRef r
    pure $
      if   mods (rr * rr) == n
      then Just rr
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

-- prime order j-invariant 0 (i.e. a == 0)
weierstrass :: Integer -> Integer
weierstrass x = mods (mods (x * x) * x + _CURVE_B)

data Affine = Affine Integer Integer
  deriving stock (Show, Generic)

instance Eq Affine where
  Affine x1 y1 == Affine x2 y2 =
    mods x1 == mods x2 && mods y1 == mods y2

data Projective = Projective {
    px :: Integer
  , py :: Integer
  , pz :: Integer
  }
  deriving stock (Show, Generic)

instance Eq Projective where
  Projective ax ay az == Projective bx by bz =
    let x1z2 = mods (ax * bz)
        x2z1 = mods (bx * az)
        y1z2 = mods (ay * bz)
        y2z1 = mods (by * az)
    in  x1z2 == x2z1 && y1z2 == y2z1

_ZERO :: Projective
_ZERO = Projective 0 1 0

_BASE :: Projective
_BASE = Projective _CURVE_GX _CURVE_GY 1

-- negate point
neg :: Projective -> Projective
neg (Projective x y z) = Projective x (mods (negate y)) z

-- general ec addition
add :: Projective -> Projective -> Projective
add p q@(Projective _ _ z)
  | p == q = double p        -- algo 9
  | z == 1 = add_mixed p q   -- algo 8
  | otherwise = add_proj p q -- algo 7

-- algo 7, "complete addition formulas for prime order elliptic curves,"
-- renes et al, 2015
add_proj :: Projective -> Projective -> Projective
add_proj (Projective x1 y1 z1) (Projective x2 y2 z2) = runST $ do
  x3 <- newSTRef 0
  y3 <- newSTRef 0
  z3 <- newSTRef 0
  let b3 = mods (_CURVE_B * 3)
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

-- algo 8, renes et al, 2015
add_mixed :: Projective -> Projective -> Projective
add_mixed (Projective x1 y1 z1) (Projective x2 y2 z2)
  | z2 /= 1   = error "secp256k1: internal error"
  | otherwise = runST $ do
      x3 <- newSTRef 0
      y3 <- newSTRef 0
      z3 <- newSTRef 0
      let b3 = mods (_CURVE_B * 3)
      t0 <- newSTRef (mods (x1 * x2)) -- 1
      t1 <- newSTRef (mods (y1 * y2))
      t3 <- newSTRef (mods (x2 + y2))
      t4 <- newSTRef (mods (x1 + y1)) -- 4
      readSTRef t4 >>= \r4 ->
        modifySTRef' t3 (\r3 -> mods (r3 * r4))
      readSTRef t0 >>= \r0 ->
        readSTRef t1 >>= \r1 ->
        writeSTRef t4 (mods (r0 + r1))
      readSTRef t4 >>= \r4 ->
        modifySTRef' t3 (\r3 -> mods (r3 - r4)) -- 7
      writeSTRef t4 (mods (y2 * z1))
      modifySTRef' t4 (\r4 -> mods (r4 + y1))
      writeSTRef y3 (mods (x2 * z1)) -- 10
      modifySTRef' y3 (\ry3 -> mods (ry3 + x1))
      readSTRef t0 >>= \r0 ->
        writeSTRef x3 (mods (r0 + r0))
      readSTRef x3 >>= \rx3 ->
        modifySTRef' t0 (\r0 -> mods (rx3 + r0)) -- 13
      t2 <- newSTRef (mods (b3 * z1))
      readSTRef t1 >>= \r1 ->
        readSTRef t2 >>= \r2 ->
        writeSTRef z3 (mods (r1 + r2))
      readSTRef t2 >>= \r2 ->
        modifySTRef' t1 (\r1 -> mods (r1 - r2)) -- 16
      modifySTRef' y3 (\ry3 -> mods (b3 * ry3))
      readSTRef t4 >>= \r4 ->
        readSTRef y3 >>= \ry3 ->
        writeSTRef x3 (mods (r4 * ry3))
      readSTRef t3 >>= \r3 ->
        readSTRef t1 >>= \r1 ->
        writeSTRef t2 (mods (r3 * r1)) -- 19
      readSTRef t2 >>= \r2 ->
        modifySTRef' x3 (\rx3 -> mods (r2 - rx3))
      readSTRef t0 >>= \r0 ->
        modifySTRef' y3 (\ry3 -> mods (ry3 * r0))
      readSTRef z3 >>= \rz3 ->
        modifySTRef' t1 (\r1 -> mods (r1 * rz3)) -- 22
      readSTRef t1 >>= \r1 ->
        modifySTRef' y3 (\ry3 -> mods (r1 + ry3))
      readSTRef t3 >>= \r3 ->
        modifySTRef' t0 (\r0 -> mods (r0 * r3))
      readSTRef t4 >>= \r4 ->
        modifySTRef' z3 (\rz3 -> mods (rz3 * r4)) -- 25
      readSTRef t0 >>= \r0 ->
        modifySTRef' z3 (\rz3 -> mods (rz3 + r0))
      Projective <$> readSTRef x3 <*> readSTRef y3 <*> readSTRef z3

-- algo 9, renes et al, 2015
double :: Projective -> Projective
double (Projective x y z) = runST $ do
  x3 <- newSTRef 0
  y3 <- newSTRef 0
  z3 <- newSTRef 0
  let b3 = mods (_CURVE_B * 3)
  t0 <- newSTRef (mods (y * y)) -- 1
  readSTRef t0 >>= \r0 ->
    writeSTRef z3 (mods (r0 + r0))
  modifySTRef' z3 (\rz3 -> mods (rz3 + rz3))
  modifySTRef' z3 (\rz3 -> mods (rz3 + rz3)) -- 4
  t1 <- newSTRef (mods (y * z))
  t2 <- newSTRef (mods (z * z))
  modifySTRef t2 (\r2 -> mods (b3 * r2)) -- 7
  readSTRef z3 >>= \rz3 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef x3 (mods (r2 * rz3))
  readSTRef t0 >>= \r0 ->
    readSTRef t2 >>= \r2 ->
    writeSTRef y3 (mods (r0 + r2))
  readSTRef t1 >>= \r1 ->
    modifySTRef' z3 (\rz3 -> mods (r1 * rz3)) -- 10
  readSTRef t2 >>= \r2 ->
    writeSTRef t1 (mods (r2 + r2))
  readSTRef t1 >>= \r1 ->
    modifySTRef' t2 (\r2 -> mods (r1 + r2))
  readSTRef t2 >>= \r2 ->
    modifySTRef' t0 (\r0 -> mods (r0 - r2)) -- 13
  readSTRef t0 >>= \r0 ->
    modifySTRef' y3 (\ry3 -> mods (r0 * ry3))
  readSTRef x3 >>= \rx3 ->
    modifySTRef' y3 (\ry3 -> mods (rx3 + ry3))
  writeSTRef t1 (mods (x * y)) -- 16
  readSTRef t0 >>= \r0 ->
    readSTRef t1 >>= \r1 ->
    writeSTRef x3 (mods (r0 * r1))
  modifySTRef' x3 (\rx3 -> mods (rx3 + rx3))
  Projective <$> readSTRef x3 <*> readSTRef y3 <*> readSTRef z3



--    mul(n, safe = true) {
--        if (!safe && n === 0n)
--            return I; // in unsafe mode, allow zero
--        if (!ge(n))
--            err('invalid scalar'); // must be 0 < n < CURVE.n
--        if (this.equals(G))
--            return wNAF(n).p; // use precomputes for base point
--        let p = I, f = G; // init result point & fake point
--        for (let d = this; n > 0n; d = d.double(), n >>= 1n) { // double-and-add ladder
--            if (n & 1n)
--                p = p.add(d); // if bit is present, add to point
--            else if (safe)
--                f = f.add(d); // if not, add to fake for timing safety
--        }
--        return p;
--    }


-- to affine coordinates
affine :: Projective -> Maybe Affine
affine p@(Projective x y z)
  | p == _ZERO = pure (Affine 0 0)
  | z == 1     = pure (Affine x y)
  | otherwise  = do
      iz <- modinv z (fromIntegral _CURVE_P)
      if   mods (z * iz) /= 1
      then Nothing
      else pure (Affine (mods (x * iz)) (mods (y * iz)))

-- to projective coordinates
projective :: Affine -> Projective
projective (Affine x y)
  | x == 0 && y == 0 = _ZERO
  | otherwise = Projective x y 1

-- point is valid
valid :: Projective -> Bool
valid p = case affine p of
  Nothing -> False
  Just (Affine x y)
    | not (fe x) || not (fe y) -> False
    | mods (y * y) /= weierstrass x -> False
    | otherwise -> True

-- parse hex-encoded point
parse :: BS.ByteString -> Maybe Projective
parse (B16.decode -> ebs) = case ebs of
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
                   let yodd = I.integerTestBit y 0
                       hodd = I.integerTestBit (fromIntegral h) 0
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
  where
    _GROUP_BYTELENGTH :: Int
    _GROUP_BYTELENGTH = 32

-- big-endian bytestring decoding
roll :: BS.ByteString -> Integer
roll = BS.foldl' unstep 0 where
  unstep a b = (a `I.integerShiftL` 8) `I.integerOr` fromIntegral b

