{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Maybe (fromJust)
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

-- note that 'weigh' doesn't work properly in a repl
main :: IO ()
main = W.mainWith $ do
  parse_int256
  ge
  add
  double
  mul
  mul_unsafe
  mul_wnaf
  derive_pub
  schnorr
  ecdsa
  ecdh

ge :: W.Weigh ()
ge =
  let !t = 2
      !b = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
  in  W.wgroup "ge" $ do
        W.func' "small" S.ge t
        W.func' "large" S.ge b

parse_int256 :: W.Weigh ()
parse_int256 =
  let !a = BS.replicate 32 0x00
      !b = BS.replicate 32 0xFF
  in  W.wgroup "parse_int256" $ do
        W.func' "parse_int (small)" parse_int a
        W.func' "parse_int (big)" parse_int b

add :: W.Weigh ()
add =
  let !p = fromJust . S.parse_point . decodeLenient $
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      !r = fromJust . S.parse_point . decodeLenient $
        "03a2113cf152585d96791a42cdd78782757fbfb5c6b2c11b59857eb4f7fda0b0e8"
      !q = fromJust . S.parse_point . decodeLenient $
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      !s = fromJust . S.parse_point . decodeLenient $
        "0306413898a49c93cccf3db6e9078c1b6a8e62568e4a4770e0d7d96792d1c580ad"
  in  W.wgroup "add" $ do
        W.func' "p + q (trivial projective points)" (S.add p) q
        W.func' "s + p (nontrivial mixed points)" (S.add s) p
        W.func' "r + s (nontrivial projective points)" (S.add r) s

double :: W.Weigh ()
double =
  let !p = fromJust . S.parse_point . decodeLenient $
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      !r = fromJust . S.parse_point . decodeLenient $
        "03a2113cf152585d96791a42cdd78782757fbfb5c6b2c11b59857eb4f7fda0b0e8"
  in  W.wgroup "double" $ do
        W.func' "2 p (double, trivial projective point)" S.double p
        W.func' "2 r (double, nontrivial projective point)" S.double r

mul :: W.Weigh ()
mul =
  let !g = S._CURVE_G
      !t = 2
      !b = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
  in  W.wgroup "mul" $ do
        W.func' "2 G" (S.mul g) t
        W.func' "(2 ^ 255 - 19) G" (S.mul g) b

mul_unsafe :: W.Weigh ()
mul_unsafe =
  let !g = S._CURVE_G
      !t = 2
      !b = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
  in  W.wgroup "mul_unsafe" $ do
        W.func' "2 G" (S.mul_unsafe g) t
        W.func' "(2 ^ 255 - 19) G" (S.mul_unsafe g) b

mul_wnaf :: W.Weigh ()
mul_wnaf =
  let !t = 2
      !b = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
      !con = S.precompute
  in  W.wgroup "mul_wnaf" $ do
        W.func' "precompute" S._precompute (8 :: Int)
        W.func' "2 G" (S.mul_wnaf con) t
        W.func' "(2 ^ 255 - 19) G" (S.mul_wnaf con) b

derive_pub :: W.Weigh ()
derive_pub =
  let !t = 2
      !b = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
      !con = S.precompute
  in  W.wgroup "derive_pub" $ do
        W.func' "sk = 2" S.derive_pub t
        W.func' "sk = 2 ^ 255 - 19" S.derive_pub b
        W.func' "wnaf, sk = 2" (S.derive_pub' con) t
        W.func' "wnaf, sk = 2 ^ 255 - 19" (S.derive_pub' con) b

schnorr :: W.Weigh ()
schnorr =
  let !t = 2
      !b = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
      !con   = S.precompute
      !s_msg = decodeLenient
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
      !s_aux = decodeLenient
        "0000000000000000000000000000000000000000000000000000000000000001"
      !s_sig = decodeLenient
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"
      !(Just !s_pk) = S.parse_point . decodeLenient $
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
  in  W.wgroup "schnorr" $ do
        W.func "sign_schnorr (small)" (S.sign_schnorr t s_msg) s_aux
        W.func "sign_schnorr (large)" (S.sign_schnorr b s_msg) s_aux
        W.func "sign_schnorr' (small)" (S.sign_schnorr' con t s_msg) s_aux
        W.func "sign_schnorr' (large)" (S.sign_schnorr' con b s_msg) s_aux
        W.func "verify_schnorr" (S.verify_schnorr s_msg s_pk) s_sig
        W.func "verify_schnorr'" (S.verify_schnorr' con s_msg s_pk) s_sig

ecdsa :: W.Weigh ()
ecdsa =
  let !t = 2
      !b = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
      !con   = S.precompute
      !msg   = "i approve of this message"
      !s_msg = decodeLenient
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
      !(Just !pub) = S.derive_pub b
      !(Just !sig) = S.sign_ecdsa b s_msg
  in   W.wgroup "ecdsa" $ do
         W.func "sign_ecdsa (small)" (S.sign_ecdsa t) s_msg
         W.func "sign_ecdsa (large)" (S.sign_ecdsa b) s_msg
         W.func "sign_ecdsa' (small)" (S.sign_ecdsa' con t) s_msg
         W.func "sign_ecdsa' (large)" (S.sign_ecdsa' con b) s_msg
         W.func "verify_ecdsa" (S.verify_ecdsa msg pub) sig
         W.func "verify_ecdsa'" (S.verify_ecdsa' con msg pub) sig

ecdh :: W.Weigh ()
ecdh =
  let !b = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
      !(Just !pub) = S.parse_point . decodeLenient $
        "bd02b9dfc8ef760708950bd972f2dc244893b61b6b46c3b19be1b2da7b034ac5"
  in  W.wgroup "ecdh" $ do
        W.func "ecdh (small)" (S.ecdh pub) 2
        W.func "ecdh (large)" (S.ecdh pub) b

