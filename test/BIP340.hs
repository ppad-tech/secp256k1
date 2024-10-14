{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module BIP340 (
    cases
  , execute
  ) where

import Control.Applicative
import Crypto.Curve.Secp256k1
import qualified Data.Attoparsec.ByteString.Char8 as AT
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified GHC.Num.Integer as I
import Test.Tasty
import Test.Tasty.HUnit

-- XX make a test prelude instead of copying/pasting these things everywhere

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

roll :: BS.ByteString -> Integer
roll = BS.foldl' unstep 0 where
  unstep a (fi -> b) = (a `I.integerShiftL` 8) `I.integerOr` b

data Case = Case {
    c_index   :: !Int
  , c_sk      :: !BS.ByteString
  , c_pk      :: !BS.ByteString
  , c_aux     :: !BS.ByteString
  , c_msg     :: !BS.ByteString
  , c_sig     :: !BS.ByteString
  , c_res     :: !Bool
  , c_comment :: !BS.ByteString
  } deriving Show

execute :: Case -> TestTree
execute Case {..} = testCase ("bip0340 " <> show c_index) $
  case parse_point c_pk of
    Nothing -> assertBool mempty (not c_res)
    Just (affine -> pk) -> do
      if   c_sk == mempty
      then do -- no signature; test verification
        let ver = verify_schnorr c_msg pk c_sig
        if   c_res
        then assertBool mempty ver
        else assertBool mempty (not ver)
      -- XX test pubkey derivation from sk
      else do -- signature present; test sig too
        let sk = roll c_sk
            sig = sign_schnorr sk c_msg c_aux
            ver = verify_schnorr c_msg pk sig
        assertEqual mempty c_sig sig
        if   c_res
        then assertBool mempty ver
        else assertBool mempty (not ver)

header :: AT.Parser ()
header = do
  _ <- AT.string "index,secret key,public key,aux_rand,message,signature,verification result,comment"
  AT.endOfLine

test_case :: AT.Parser Case
test_case = do
  c_index <- AT.decimal AT.<?> "index"
  _ <- AT.char ','
  c_sk <- fmap B16.decodeLenient (AT.takeWhile (/= ',') AT.<?> "sk")
  _ <- AT.char ','
  c_pk <- AT.takeWhile1 (/= ',') AT.<?> "pk"
  _ <- AT.char ','
  c_aux <- fmap B16.decodeLenient (AT.takeWhile (/= ',') AT.<?> "aux")
  _ <- AT.char ','
  c_msg <- fmap B16.decodeLenient (AT.takeWhile (/= ',') AT.<?> "msg")
  _ <- AT.char ','
  c_sig <- fmap B16.decodeLenient (AT.takeWhile1 (/= ',') AT.<?> "sig")
  _ <- AT.char ','
  c_res <- (AT.string "TRUE" *> pure True) <|> (AT.string "FALSE" *> pure False)
            AT.<?> "res"
  _ <- AT.char ','
  c_comment <- AT.takeWhile (/= '\n') AT.<?> "comment"
  AT.endOfLine
  pure Case {..}

cases :: AT.Parser [Case]
cases = header *> AT.many1 test_case

