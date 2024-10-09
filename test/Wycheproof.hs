{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Wycheproof where

import Crypto.Curve.Secp256k1
import qualified Data.Bits as B
import qualified Data.Attoparsec.ByteString as A
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

parse_DER :: A.Parser ECDSA
parse_DER = do
  _ <- A.word8 0x30
  _ <- A.takeTill (== 0x02)
  _ <- A.word8 0x02
  r_len <- fmap fi A.anyWord8
  bs_r <- A.take r_len
  _ <- A.word8 0x02
  s_len <- fmap fi A.anyWord8
  bs_s <- A.take s_len
  let r = fi (parse_integer_be bs_r)
      s = fi (parse_integer_be bs_s)
  pure (ECDSA r s)

-- dumb integer parser
parse_integer_be :: BS.ByteString -> Integer
parse_integer_be = BS.foldl' alg 0 where
  alg !acc b = B.shiftL acc 8 + fromIntegral b
{-# INLINE parse_integer_be #-}

-- XX delete me when done

test_pub :: BS.ByteString
test_pub = "04782c8ed17e3b2a783b5464f33b09652a71c678e05ec51e84e2bcfc663a3de963af9acb4280b8c7f7c42f4ef9aba6245ec1ec1712fd38a0fa96418d8cd6aa6152"

pub =
  let Just p = parse_point test_pub
  in  p

test_msg :: BS.ByteString
test_msg = mempty

test_sig :: BS.ByteString
test_sig = "3046022100f80ae4f96cdbc9d853f83d47aae225bf407d51c56b7776cd67d0dc195d99a9dc022100b303e26be1f73465315221f0b331528807a1a9b6eb068ede6eebeaaa49af8a36"

sig =
  let Right s = A.parseOnly parse_DER (B16.decodeLenient test_sig)
  in  s
