{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as BS
import Control.DeepSeq
import Criterion.Main
import qualified Crypto.Secp256k1 as S

instance NFData S.Projective
instance NFData S.Affine
instance NFData S.Curve

main :: IO ()
main = defaultMain [
    secp256k1
  ]

secp256k1 :: Benchmark
secp256k1 = bgroup "secp256k1" [
      bgroup "parse" [
        bench "foo" $ nf bparse p
      , bench "bar" $ nf bparse q
      , bench "baz" $ nf bparse r
      , bench "qux" $ nf bparse s
      ]
    , bgroup "add" [
        bench "foo bar" $ nf (S.add foo) bar
      , bench "foo baz" $ nf (S.add foo) baz
      , bench "foo qux" $ nf (S.add foo) qux
      , bench "bar baz" $ nf (S.add bar) baz
      , bench "bar qux" $ nf (S.add bar) qux
      , bench "baz qux" $ nf (S.add baz) qux
      ]
    ]
  where
    p = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    q = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    r = "03a2113cf152585d96791a42cdd78782757fbfb5c6b2c11b59857eb4f7fda0b0e8"
    s = "0306413898a49c93cccf3db6e9078c1b6a8e62568e4a4770e0d7d96792d1c580ad"

    bparse :: BS.ByteString -> S.Projective
    bparse bs = case S.parse bs of
      Nothing -> error "bang"
      Just v -> v

    foo :: S.Projective
    foo = case S.parse p of
      Nothing -> error "boom"
      Just !pa -> pa

    bar :: S.Projective
    bar = case S.parse q of
      Nothing -> error "bang"
      Just !pa -> pa

    baz :: S.Projective
    baz = case S.parse r of
      Nothing -> error "bang"
      Just !pa -> pa

    qux :: S.Projective
    qux = case S.parse s of
      Nothing -> error "bang"
      Just !pa -> pa

