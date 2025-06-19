{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Control.DeepSeq
import Criterion.Main
import qualified Crypto.Curve.Secp256k1 as S

instance NFData S.Projective
instance NFData S.Affine
instance NFData S.ECDSA
instance NFData S.Context

main :: IO ()
main = defaultMain [
    parse_point
  , add
  , mul
  , precompute
  , mul_wnaf
  , derive_pub
  , schnorr
  , ecdsa
  , ecdh
  ]

parse_int256 :: BS.ByteString -> Integer
parse_int256 bs = case S.parse_int256 bs of
  Nothing -> error "bang"
  Just v -> v

remQ :: Benchmark
remQ = env setup $ \x ->
    bgroup "remQ (remainder modulo _CURVE_Q)" [
      bench "remQ 2 " $ nf S.remQ 2
    , bench "remQ (2 ^ 255 - 19)" $ nf S.remQ x
    ]
  where
    setup = pure . parse_int256 $ B16.decodeLenient
      "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"

parse_point :: Benchmark
parse_point = bgroup "parse_point" [
    bench "compressed" $ nf S.parse_point p_bs
  , bench "uncompressed" $ nf S.parse_point t_bs
  , bench "bip0340" $ nf S.parse_point (BS.drop 1 p_bs)
  ]

parse_integer :: Benchmark
parse_integer = env setup $ \ ~(small, big) ->
    bgroup "parse_int256" [
      bench "parse_int256 (small)" $ nf parse_int256 small
    , bench "parse_int256 (big)" $ nf parse_int256 big
    ]
  where
    setup = do
      let small = BS.replicate 32 0x00
          big   = BS.replicate 32 0xFF
      pure (small, big)

add :: Benchmark
add = bgroup "add" [
    bench "2 p (double, trivial projective point)" $ nf (S.add p) p
  , bench "2 r (double, nontrivial projective point)" $ nf (S.add r) r
  , bench "p + q (trivial projective points)" $ nf (S.add p) q
  , bench "p + s (nontrivial mixed points)" $ nf (S.add p) s
  , bench "s + r (nontrivial projective points)" $ nf (S.add s) r
  ]

mul :: Benchmark
mul = env setup $ \x ->
    bgroup "mul" [
      bench "2 G" $ nf (S.mul S._CURVE_G) 2
    , bench "(2 ^ 255 - 19) G" $ nf (S.mul S._CURVE_G) x
    ]
  where
    setup = pure . parse_int256 $ B16.decodeLenient
      "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"

precompute :: Benchmark
precompute = bench "precompute" $ nfIO (pure S.precompute)

mul_wnaf :: Benchmark
mul_wnaf = env setup $ \ ~(tex, x) ->
    bgroup "mul_wnaf" [
      bench "2 G" $ nf (S.mul_wnaf tex) 2
    , bench "(2 ^ 255 - 19) G" $ nf (S.mul_wnaf tex) x
    ]
  where
    setup = do
      let !tex = S.precompute
          !int = parse_int256 $ B16.decodeLenient
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
      pure (tex, int)

derive_pub :: Benchmark
derive_pub = env setup $ \ ~(tex, x) ->
    bgroup "derive_pub" [
      bench "sk = 2" $ nf S.derive_pub 2
    , bench "sk = 2 ^ 255 - 19" $ nf S.derive_pub x
    , bench "wnaf, sk = 2" $ nf (S.derive_pub' tex) 2
    , bench "wnaf, sk = 2 ^ 255 - 19" $ nf (S.derive_pub' tex) x
    ]
  where
    setup = do
      let !tex = S.precompute
          !int = parse_int256 $ B16.decodeLenient
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
      pure (tex, int)

schnorr :: Benchmark
schnorr = env setup $ \ ~(tex, big) ->
    bgroup "schnorr" [
      bench "sign_schnorr (small)" $ nf (S.sign_schnorr 2 s_msg) s_aux
    , bench "sign_schnorr (large)" $ nf (S.sign_schnorr big s_msg) s_aux
    , bench "sign_schnorr' (small)" $ nf (S.sign_schnorr' tex 2 s_msg) s_aux
    , bench "sign_schnorr' (large)" $ nf (S.sign_schnorr' tex big s_msg) s_aux
    , bench "verify_schnorr" $ nf (S.verify_schnorr s_msg s_pk) s_sig
    , bench "verify_schnorr'" $ nf (S.verify_schnorr' tex s_msg s_pk) s_sig
    ]
  where
    setup = do
      let !tex = S.precompute
          !int = parse_int256 $ B16.decodeLenient
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
      pure (tex, int)

ecdsa :: Benchmark
ecdsa = env setup $ \ ~(tex, big, pub, msg, sig) ->
    bgroup "ecdsa" [
      bench "sign_ecdsa (small)" $ nf (S.sign_ecdsa 2) s_msg
    , bench "sign_ecdsa (large)" $ nf (S.sign_ecdsa big) s_msg
    , bench "sign_ecdsa' (small)" $ nf (S.sign_ecdsa' tex 2) s_msg
    , bench "sign_ecdsa' (large)" $ nf (S.sign_ecdsa' tex big) s_msg
    , bench "verify_ecdsa" $ nf (S.verify_ecdsa msg pub) sig
    , bench "verify_ecdsa'" $ nf (S.verify_ecdsa' tex msg pub) sig
    ]
  where
    setup = do
      let !tex = S.precompute
          big = parse_int256 $ B16.decodeLenient
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
          Just pub = S.derive_pub big
          msg = "i approve of this message"
          Just sig = S.sign_ecdsa big s_msg
      pure (tex, big, pub, msg, sig)

ecdh :: Benchmark
ecdh = env setup $ \ ~(big, pub) ->
    bgroup "ecdh" [
      bench "ecdh (small)" $ nf (S.ecdh pub) 2
    , bench "ecdh (large)" $ nf (S.ecdh pub) big
    ]
  where
    setup = do
      let !big =
            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
          !(Just !pub) = S.parse_point . B16.decodeLenient $
            "bd02b9dfc8ef760708950bd972f2dc244893b61b6b46c3b19be1b2da7b034ac5"
      pure (big, pub)

p_bs :: BS.ByteString
p_bs = B16.decodeLenient
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

p :: S.Projective
p = case S.parse_point p_bs of
  Nothing -> error "bang"
  Just !pt -> pt

q_bs :: BS.ByteString
q_bs = B16.decodeLenient
  "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

q :: S.Projective
q = case S.parse_point q_bs of
  Nothing -> error "bang"
  Just !pt -> pt

r_bs :: BS.ByteString
r_bs = B16.decodeLenient
  "03a2113cf152585d96791a42cdd78782757fbfb5c6b2c11b59857eb4f7fda0b0e8"

r :: S.Projective
r = case S.parse_point r_bs of
  Nothing -> error "bang"
  Just !pt -> pt

s_bs :: BS.ByteString
s_bs = B16.decodeLenient
  "0306413898a49c93cccf3db6e9078c1b6a8e62568e4a4770e0d7d96792d1c580ad"

s :: S.Projective
s = case S.parse_point s_bs of
  Nothing -> error "bang"
  Just !pt -> pt

t_bs :: BS.ByteString
t_bs = B16.decodeLenient "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"

t :: S.Projective
t = case S.parse_point t_bs of
  Nothing -> error "bang"
  Just !pt -> pt

s_sk :: Integer
s_sk = parse_int256 . B16.decodeLenient $
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

-- e_msg = B16.decodeLenient "313233343030"
-- e_sig = B16.decodeLenient "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba"

