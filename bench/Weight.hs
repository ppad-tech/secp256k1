{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- XX need to make sure arguments aren't allocating in the benchmarks

module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Word.Wider (Wider(..))
import Control.DeepSeq
import qualified Crypto.Curve.Secp256k1 as S
import qualified Weigh as W

instance NFData S.Projective
instance NFData S.Affine
instance NFData S.ECDSA
instance NFData S.Context

decodeLenient :: BS.ByteString -> BS.ByteString
decodeLenient bs = case B16.decode bs of
  Nothing -> error "bang"
  Just b -> b

parse_int :: BS.ByteString -> Wider
parse_int bs = case S.parse_int256 bs of
  Nothing -> error "bang"
  Just v -> v

big :: Wider
big = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed

tex :: S.Context
tex = S.precompute

-- note that 'weigh' doesn't work properly in a repl
main :: IO ()
main = W.mainWith $ do
  parse_int256
  add
  mul
  mul_unsafe
  mul_wnaf
  derive_pub
  schnorr
  ecdsa
  ecdh

parse_int256 :: W.Weigh ()
parse_int256 =
  let !a = BS.replicate 32 0x00
      !b = BS.replicate 32 0xFF
  in  W.wgroup "parse_int256" $ do
        W.func' "parse_int (small)" parse_int a
        W.func' "parse_int (big)" parse_int b

add :: W.Weigh ()
add =
  let !pl = p
      !rl = r
      !ql = q
      !sl = s
  in  W.wgroup " add" $ do
        W.func "2 p (double, trivial projective point)" (S.add pl) pl
        W.func "2 r (double, nontrivial projective point)" (S.add rl) rl
        W.func "p + q (trivial projective points)" (S.add pl) ql
        W.func "p + s (nontrivial mixed points)" (S.add pl) sl
        W.func "s + r (nontrivial projective points)" (S.add sl) rl

mul :: W.Weigh ()
mul =
  let !g = S._CURVE_G
      !t = 2
      !bigl = big
  in  W.wgroup "mul" $ do
        W.func "2 G" (S.mul g) t
        W.func "(2 ^ 255 - 19) G" (S.mul g) bigl

mul_unsafe :: W.Weigh ()
mul_unsafe =
  let !g = S._CURVE_G
      !t = 2
      !bigl = big
  in  W.wgroup "mul_unsafe" $ do
        W.func "2 G" (S.mul_unsafe g) t
        W.func "(2 ^ 255 - 19) G" (S.mul_unsafe g) bigl

mul_wnaf :: W.Weigh ()
mul_wnaf =
  let !t = 2
      !bigl = big
      !con = tex
  in  W.wgroup "mul_wnaf" $ do
        W.value "precompute" S.precompute -- XX ?
        W.func "2 G" (S.mul_wnaf con) t
        W.func "(2 ^ 255 - 19) G" (S.mul_wnaf con) bigl

derive_pub :: W.Weigh ()
derive_pub =
  let !t = 2
      !bigl = big
      !con = tex
  in  W.wgroup "derive_pub" $ do
        W.func "sk = 2" S.derive_pub t
        W.func "sk = 2 ^ 255 - 19" S.derive_pub bigl
        W.func "wnaf, sk = 2" (S.derive_pub' con) t
        W.func "wnaf, sk = 2 ^ 255 - 19" (S.derive_pub' con) bigl

schnorr :: W.Weigh ()
schnorr =
  let !t = 2
      !s_msgl = s_msg
      !s_auxl = s_aux
      !s_sigl = s_sig
      !s_pkl  = s_pk
      !con    = tex
      !bigl   = big
  in  W.wgroup "schnorr" $ do
        W.func "sign_schnorr (small)" (S.sign_schnorr t s_msgl) s_auxl
        W.func "sign_schnorr (large)" (S.sign_schnorr bigl s_msgl) s_auxl
        W.func "sign_schnorr' (small)" (S.sign_schnorr' con t s_msgl) s_auxl
        W.func "sign_schnorr' (large)" (S.sign_schnorr' con big s_msgl) s_auxl
        W.func "verify_schnorr" (S.verify_schnorr s_msgl s_pkl) s_sigl
        W.func "verify_schnorr'" (S.verify_schnorr' con s_msgl s_pkl) s_sigl

ecdsa :: W.Weigh ()
ecdsa =
  let !t = 2
      !s_msgl = s_msg
      !con    = tex
      !bigl   = big
      !msg = "i approve of this message"
      Just !pub = S.derive_pub bigl
      Just !sig = S.sign_ecdsa bigl s_msgl
  in   W.wgroup "ecdsa" $ do
         W.func "sign_ecdsa (small)" (S.sign_ecdsa t) s_msgl
         W.func "sign_ecdsa (large)" (S.sign_ecdsa bigl) s_msgl
         W.func "sign_ecdsa' (small)" (S.sign_ecdsa' con t) s_msgl
         W.func "sign_ecdsa' (large)" (S.sign_ecdsa' con bigl) s_msgl
         W.func "verify_ecdsa" (S.verify_ecdsa msg pub) sig
         W.func "verify_ecdsa'" (S.verify_ecdsa' tex msg pub) sig

ecdh :: W.Weigh ()
ecdh = W.wgroup "ecdh" $ do
    W.func "ecdh (small)" (S.ecdh pub) 2
    W.func "ecdh (large)" (S.ecdh pub) b
  where
    !b = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
    Just !pub = S.parse_point . decodeLenient $
      "bd02b9dfc8ef760708950bd972f2dc244893b61b6b46c3b19be1b2da7b034ac5"

s_sk :: Wider
s_sk = parse_int . decodeLenient $
  "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"

s_sig :: BS.ByteString
s_sig = decodeLenient "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"

s_pk_raw :: BS.ByteString
s_pk_raw = decodeLenient
  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"

s_pk :: S.Projective
s_pk = case S.parse_point s_pk_raw of
  Nothing -> error "bang"
  Just !pt -> pt

s_msg :: BS.ByteString
s_msg = decodeLenient
  "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"

s_aux :: BS.ByteString
s_aux = decodeLenient
  "0000000000000000000000000000000000000000000000000000000000000001"

p_bs :: BS.ByteString
p_bs = decodeLenient
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

p :: S.Projective
p = case S.parse_point p_bs of
  Nothing -> error "bang"
  Just !pt -> pt

q_bs :: BS.ByteString
q_bs = decodeLenient
  "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

q :: S.Projective
q = case S.parse_point q_bs of
  Nothing -> error "bang"
  Just !pt -> pt

r_bs :: BS.ByteString
r_bs = decodeLenient
  "03a2113cf152585d96791a42cdd78782757fbfb5c6b2c11b59857eb4f7fda0b0e8"

r :: S.Projective
r = case S.parse_point r_bs of
  Nothing -> error "bang"
  Just !pt -> pt

s_bs :: BS.ByteString
s_bs = decodeLenient
  "0306413898a49c93cccf3db6e9078c1b6a8e62568e4a4770e0d7d96792d1c580ad"

s :: S.Projective
s = case S.parse_point s_bs of
  Nothing -> error "bang"
  Just !pt -> pt

