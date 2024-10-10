{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module Noble (
    Ecdsa(..)
  , execute_ecdsa
  , execute_valid

  , parse_compact
  , roll -- uh
  ) where

import Crypto.Curve.Secp256k1
import Data.Aeson ((.:))
import qualified Data.Aeson as A
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified GHC.Num.Integer as I
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

toBS :: T.Text -> BS.ByteString
toBS = B16.decodeLenient . TE.encodeUtf8

toSecKey :: T.Text -> Integer
toSecKey = roll . toBS

data Ecdsa = Ecdsa {
    ec_valid   :: ![(Int, ValidTest)]
  , ec_invalid :: !InvalidTest
  } deriving Show

instance A.FromJSON Ecdsa where
  parseJSON = A.withObject "Ecdsa" $ \m -> Ecdsa
    <$> fmap (zip [0..]) (m .: "valid")
    <*> m .: "invalid"

-- XX run noble's invalid suites
execute_ecdsa :: Ecdsa -> TestTree
execute_ecdsa Ecdsa {..} = testGroup "noble_ecdsa" [
    testGroup "valid" (fmap execute_valid ec_valid)
  ]

data ValidTest = ValidTest {
    vt_d           :: !Integer
  , vt_m           :: !BS.ByteString
  , vt_signature   :: !BS.ByteString
  } deriving Show

instance A.FromJSON ValidTest where
  parseJSON = A.withObject "ValidTest" $ \m -> ValidTest
    <$> fmap toSecKey (m .: "d")
    <*> fmap toBS (m .: "m")
    <*> fmap toBS (m .: "signature")

-- big-endian bytestring decoding
roll :: BS.ByteString -> Integer
roll = BS.foldl' unstep 0 where
  unstep a (fi -> b) = (a `I.integerShiftL` 8) `I.integerOr` b

parse_compact :: BS.ByteString -> ECDSA
parse_compact bs =
  let (roll -> r, roll -> s) = BS.splitAt 32 bs
  in  ECDSA r s

execute_valid :: (Int, ValidTest) -> TestTree
execute_valid (label, ValidTest {..}) =
  testCase ("noble-secp256k1, valid (" <> show label <> ")") $ do
    let msg = vt_m
        x   = vt_d
        pec = parse_compact vt_signature
        sig = _sign_no_hash x msg
    assertEqual mempty pec sig

data InvalidTest = InvalidTest {
    iv_sign   :: ![InvalidSignTest]
  , iv_verify :: ![InvalidVerifyTest]
  } deriving Show

instance A.FromJSON InvalidTest where
  parseJSON = A.withObject "InvalidTest" $ \m -> InvalidTest
    <$> m .: "sign"
    <*> m .: "verify"

data InvalidSignTest = InvalidSignTest {
    ivs_d           :: !Integer
  , ivs_m           :: !BS.ByteString
  } deriving Show

instance A.FromJSON InvalidSignTest where
  parseJSON = A.withObject "InvalidSignTest" $ \m -> InvalidSignTest
    <$> fmap toSecKey (m .: "d")
    <*> fmap toBS (m .: "m")

data InvalidVerifyTest = InvalidVerifyTest {
    ivv_Q           :: !T.Text        -- XX check noble pubkey encoding
  , ivv_m           :: !BS.ByteString
  , ivv_signature   :: !BS.ByteString -- XX to sig (from compact?)
  } deriving Show

instance A.FromJSON InvalidVerifyTest where
  parseJSON = A.withObject "InvalidVerifyTest" $ \m -> InvalidVerifyTest
    <$> m .: "Q"
    <*> fmap toBS (m .: "m")
    <*> fmap toBS (m .: "signature")

