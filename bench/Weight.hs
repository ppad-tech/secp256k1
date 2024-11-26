{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Control.DeepSeq
import qualified Crypto.Curve.Secp256k1 as S
import qualified Weigh as W

instance NFData S.Projective
instance NFData S.Affine
instance NFData S.ECDSA
instance NFData S.Context

big :: Integer
big = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed

tex :: S.Context
tex = S.precompute

-- note that 'weigh' doesn't work properly in a repl
main :: IO ()
main = W.mainWith $ do
  remQ
  parse_int256
  mul
  mul_wnaf
  derive_pub
  schnorr
  ecdsa

remQ :: W.Weigh ()
remQ = W.wgroup "remQ" $ do
  W.func "remQ 2" S.remQ 2
  W.func "remQ (2 ^ 255 - 19)" S.remQ big

parse_int256 :: W.Weigh ()
parse_int256 = W.wgroup "parse_int256" $ do
  W.func' "parse_int256 (small)" S.parse_int256 (BS.replicate 32 0x00)
  W.func' "parse_int256 (big)" S.parse_int256 (BS.replicate 32 0xFF)

mul :: W.Weigh ()
mul = W.wgroup "mul" $ do
  W.func "2 G" (S.mul S._CURVE_G) 2
  W.func "(2 ^ 255 - 19) G" (S.mul S._CURVE_G) big

mul_wnaf :: W.Weigh ()
mul_wnaf = W.wgroup "mul_wnaf" $ do
  W.value "precompute" S.precompute
  W.func "2 G" (S.mul_wnaf tex) 2
  W.func "(2 ^ 255 - 19) G" (S.mul_wnaf tex) big

derive_pub :: W.Weigh ()
derive_pub = W.wgroup "derive_pub" $ do
  W.func "sk = 2" S.derive_pub 2
  W.func "sk = 2 ^ 255 - 19" S.derive_pub big
  W.func "wnaf, sk = 2" (S.derive_pub' tex) 2
  W.func "wnaf, sk = 2 ^ 255 - 19" (S.derive_pub' tex) big

schnorr :: W.Weigh ()
schnorr = W.wgroup "schnorr" $ do
  W.func "sign_schnorr (small)" (S.sign_schnorr 2 s_msg) s_aux
  W.func "sign_schnorr (large)" (S.sign_schnorr big s_msg) s_aux
  W.func "sign_schnorr' (small)" (S.sign_schnorr' tex 2 s_msg) s_aux
  W.func "sign_schnorr' (large)" (S.sign_schnorr' tex big s_msg) s_aux
  W.func "verify_schnorr" (S.verify_schnorr s_msg s_pk) s_sig
  W.func "verify_schnorr'" (S.verify_schnorr' tex s_msg s_pk) s_sig

ecdsa :: W.Weigh ()
ecdsa = W.wgroup "ecdsa" $ do
    W.func "sign_ecdsa (small)" (S.sign_ecdsa 2) s_msg
    W.func "sign_ecdsa (large)" (S.sign_ecdsa big) s_msg
    W.func "sign_ecdsa' (small)" (S.sign_ecdsa' tex 2) s_msg
    W.func "sign_ecdsa' (large)" (S.sign_ecdsa' tex big) s_msg
    W.func "verify_ecdsa" (S.verify_ecdsa msg pub) sig
    W.func "verify_ecdsa'" (S.verify_ecdsa' tex msg pub) sig
  where
    pub = S.derive_pub big
    msg = "i approve of this message"
    sig = S.sign_ecdsa big s_msg

s_sk :: Integer
s_sk = S.parse_int256 . B16.decodeLenient $
  "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"

s_sig :: BS.ByteString
s_sig = B16.decodeLenient "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"

s_pk_raw :: BS.ByteString
s_pk_raw = B16.decodeLenient
  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"

s_pk :: S.Projective
s_pk = case S.parse_point s_pk_raw of
  Nothing -> error "bang"
  Just !pt -> pt

s_msg :: BS.ByteString
s_msg = B16.decodeLenient
  "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"

s_aux :: BS.ByteString
s_aux = B16.decodeLenient
  "0000000000000000000000000000000000000000000000000000000000000001"

