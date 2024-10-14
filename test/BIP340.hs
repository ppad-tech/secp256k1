{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module BIP340 where

import Control.Applicative
import qualified Data.Attoparsec.ByteString.Char as AT
import qualified Data.ByteString as BS

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

header :: AT.Parser ()
header = do
  _ <- AT.string "index,secret key,public key,aux_rand,message,signature,verification result,comment"
  AT.endOfLine

test_case :: AT.Parser Case
test_case = do
  c_index <- AT.decimal
  _ <- AT.char ','
  c_sk <- AT.takeWhile1 (/= ',')
  _ <- AT.char ','
  c_pk <- AT.takeWhile1 (/= ',')
  _ <- char ','
  c_aux <- AT.takeWhile1 (/= ',')
  _ <- char ','
  c_msg <- AT.takeWhile1 (/= ',')
  _ <- char ','
  c_sig <- AT.takeWhile1 (/= ',')
  _ <- char ','
  c_res <- (AT.string "TRUE" *> pure True) <|> (AT.string "FALSE" *> pure False)
  _ <- AT.char ','
  c_comment <- AT.takeWhile1 (/= '\n')
  AT.endOfLine
  pure Case {..}

cases :: AT.Parser [Case]
cases = header *> AT.many1 test_case

