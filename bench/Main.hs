{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString.Base16 as B16
import Control.DeepSeq
import Criterion.Main
import qualified Crypto.Curve.Secp256k1 as S

instance NFData S.Projective
instance NFData S.Affine

main :: IO ()
main = defaultMain [
    secp256k1
  ]

-- to benchmark
--
--    parse_point
--    parse_integer
--
--    add_proj, add_mixed, double
--    mul, neg
--
--    schnorr sign/verify
--    ecdsa sign/verify

secp256k1 :: Benchmark
secp256k1 = env setup $ \ ~(p_raw, p, q, r, s) ->
    bgroup "secp256k1" [
      bgroup "parse_point" [
        bench "p" $ nf S.parse_point p_raw
      ]
      -- , bgroup "add" [
      --     bench "2 p (double, trivial projective point)" $ nf (S.add p) p
      --   , bench "p + q (trivial projective points)" $ nf (S.add p) q
      --   , bench "2 r (double, nontrivial projective point)" $ nf (S.add r) r
      --   , bench "p + s (nontrivial mixed points)" $ nf (S.add p) s
      --   , bench "s + r (nontrivial projective points)" $ nf (S.add s) r
      -- ]
      -- , bgroup "mul" [
      --     bench "3 p (trivial projective point)" $ nf (S.mul p) 3
      --   , bench "3 r (nontrivial projective point)" $ nf (S.mul r) 3
      --   , bench "<large group element> p" $
      --       nf (S.mul p) (S._CURVE_Q - 0xFFFFFFFFFFFFFFFFFFFFFFFF)
      -- ]
    ]
  where
    setup = do
      let p_raw = B16.decodeLenient
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
          q_raw = B16.decodeLenient
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
          r_raw = B16.decodeLenient
            "03a2113cf152585d96791a42cdd78782757fbfb5c6b2c11b59857eb4f7fda0b0e8"
          s_raw = B16.decodeLenient
            "0306413898a49c93cccf3db6e9078c1b6a8e62568e4a4770e0d7d96792d1c580ad"
          -- all points w/proj_z = 1
          p = case S.parse_point p_raw of
                Nothing -> error "bang"
                Just !pt -> pt
          q = case S.parse_point q_raw of
                Nothing -> error "bang"
                Just !pt -> pt
          r = case S.parse_point r_raw of
                Nothing -> error "bang"
                Just !pt -> pt
          s = case S.parse_point s_raw of
                Nothing -> error "bang"
                Just !pt -> pt
          -- p + q, r + s are nontrivial projective points
      pure (p_raw, p, q, S.add p q, S.add r s)

    -- baz :: S.Projective
    -- baz = case S.parse_point (B16.decodeLenient r) of
    --   Nothing -> error "bang"
    --   Just !pa -> pa

    -- qux :: S.Projective
    -- qux = case S.parse_point s of
    --   Nothing -> error "bang"
    --   Just !pa -> pa

