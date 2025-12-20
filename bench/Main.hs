{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns -fno-warn-type-defaults #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Word.Wider as W
import Control.DeepSeq
import Criterion.Main
import qualified Crypto.Curve.Secp256k1 as S

import qualified Numeric.Montgomery.Secp256k1.Curve as C

instance NFData S.Projective
instance NFData S.Affine
instance NFData S.ECDSA
instance NFData S.Context

decodeLenient :: BS.ByteString -> BS.ByteString
decodeLenient bs = case B16.decode bs of
  Nothing -> error "bang"
  Just b -> b

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

parse_int256 :: BS.ByteString -> W.Wider
parse_int256 bs = case S.parse_int256 bs of
  Nothing -> error "bang"
  Just v -> v

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

mul_fixed :: Benchmark
mul_fixed = bgroup "mul_fixed" [
    bench "curve:  M(2) * M(2)" $ nf (C.mul 2) 2
  , bench "curve:  M(2) * M(2 ^ 255 - 19)" $ nf (C.mul 2) (2 ^ 255 - 19)
  ]

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
    setup = pure . parse_int256 $ decodeLenient
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
          !int = parse_int256 $ decodeLenient
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
          !int = parse_int256 $ decodeLenient
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
          !int = parse_int256 $ decodeLenient
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
          big = parse_int256 $ decodeLenient
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
          !(Just !pub) = S.parse_point . decodeLenient $
            "bd02b9dfc8ef760708950bd972f2dc244893b61b6b46c3b19be1b2da7b034ac5"
      pure (big, pub)


p :: S.Projective
p = S.Projective
  55066263022277343669578718895168534326250603453777594175500187360389116729240
  32670510020758816978083085130507043184471273380659243275938904335757337482424
  1

q :: S.Projective
q = S.Projective
  112711660439710606056748659173929673102114977341539408544630613555209775888121
  25583027980570883691656905877401976406448868254816295069919888960541586679410
  1

r :: S.Projective
r = S.Projective
  73305138481390301074068425511419969342201196102229546346478796034582161436904
  77311080844824646227678701997218206005272179480834599837053144390237051080427
  1

p_bs :: BS.ByteString
p_bs = decodeLenient
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

q_bs :: BS.ByteString
q_bs = decodeLenient
  "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

r_bs :: BS.ByteString
r_bs = decodeLenient
  "03a2113cf152585d96791a42cdd78782757fbfb5c6b2c11b59857eb4f7fda0b0e8"

s_bs :: BS.ByteString
s_bs = decodeLenient
  "0306413898a49c93cccf3db6e9078c1b6a8e62568e4a4770e0d7d96792d1c580ad"

s :: S.Projective
s = case S.parse_point s_bs of
  Nothing -> error "bang"
  Just !pt -> pt

t_bs :: BS.ByteString
t_bs = decodeLenient "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6ff0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"

t :: S.Projective
t = case S.parse_point t_bs of
  Nothing -> error "bang"
  Just !pt -> pt

s_sk :: W.Wider
s_sk = parse_int256 . decodeLenient $
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

