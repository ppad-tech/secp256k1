{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module Noble (
    Ecdsa(..)
  , execute_ecdsa
  ) where

import Control.Exception
import Crypto.Curve.Secp256k1
import Data.Aeson ((.:))
import qualified Data.Aeson as A
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified GHC.Num.Integer as I
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertBool, assertFailure, testCase)

data Ecdsa = Ecdsa {
    ec_valid   :: ![(Int, ValidTest)]
  , ec_invalid :: !InvalidTest
  } deriving Show

execute_ecdsa :: Context -> Ecdsa -> TestTree
execute_ecdsa tex Ecdsa {..} = testGroup "noble_ecdsa" [
      testGroup "valid" (fmap (execute_valid tex) ec_valid)
    , testGroup "invalid (sign)" (fmap (execute_invalid_sign tex) iv_sign)
    , testGroup "invalid (verify)" (fmap (execute_invalid_verify tex) iv_verify)
    ]
  where
    InvalidTest {..} = ec_invalid

execute_valid :: Context -> (Int, ValidTest) -> TestTree
execute_valid tex (label, ValidTest {..}) =
  testCase ("noble-secp256k1, valid (" <> show label <> ")") $ do
    let msg = vt_m
        x   = vt_d
        pec = parse_compact vt_signature
        sig = _sign_ecdsa_no_hash x msg
        sig' = _sign_ecdsa_no_hash' tex x msg
    assertEqual mempty sig sig'
    assertEqual mempty pec sig

execute_invalid_sign :: Context -> (Int, InvalidSignTest) -> TestTree
execute_invalid_sign tex (label, InvalidSignTest {..}) =
    testCase ("noble-secp256k1, invalid sign (" <> show label <> ")") $ do
      let x   = ivs_d
          m   = ivs_m
      err <- catch (pure (_sign_ecdsa_no_hash x m) >> pure False) handler
      err' <- catch (pure (_sign_ecdsa_no_hash' tex x m) >> pure False) handler
      if   err || err'
      then assertFailure "expected error not caught"
      else pure ()
  where
    handler :: ErrorCall -> IO Bool
    handler _ = pure True

execute_invalid_verify :: Context -> (Int, InvalidVerifyTest) -> TestTree
execute_invalid_verify tex (label, InvalidVerifyTest {..}) =
  testCase ("noble-secp256k1, invalid verify (" <> show label <> ")") $
    case parse_point (B16.decodeLenient ivv_Q) of
      Nothing -> assertBool "no parse" True
      Just pub -> do
        let sig = parse_compact ivv_signature
            ver = verify_ecdsa ivv_m pub sig
            ver' = verify_ecdsa' tex ivv_m pub sig
        assertBool mempty (not ver)
        assertBool mempty (not ver')

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- parser helper
toBS :: T.Text -> BS.ByteString
toBS = B16.decodeLenient . TE.encodeUtf8

-- parser helper
toSecKey :: T.Text -> Integer
toSecKey = roll . toBS

-- big-endian bytestring decoding
roll :: BS.ByteString -> Integer
roll = BS.foldl' unstep 0 where
  unstep a (fi -> b) = (a `I.integerShiftL` 8) `I.integerOr` b

instance A.FromJSON Ecdsa where
  parseJSON = A.withObject "Ecdsa" $ \m -> Ecdsa
    <$> fmap (zip [0..]) (m .: "valid")
    <*> m .: "invalid"

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

parse_compact :: BS.ByteString -> ECDSA
parse_compact bs = case parse_sig bs of
  Nothing -> error "bang"
  Just s -> s

data InvalidTest = InvalidTest {
    iv_sign   :: ![(Int, InvalidSignTest)]
  , iv_verify :: ![(Int, InvalidVerifyTest)]
  } deriving Show

instance A.FromJSON InvalidTest where
  parseJSON = A.withObject "InvalidTest" $ \m -> InvalidTest
    <$> fmap (zip [0..]) (m .: "sign")
    <*> fmap (zip [0..]) (m .: "verify")

data InvalidSignTest = InvalidSignTest {
    ivs_d           :: !Integer
  , ivs_m           :: !BS.ByteString
  } deriving Show

instance A.FromJSON InvalidSignTest where
  parseJSON = A.withObject "InvalidSignTest" $ \m -> InvalidSignTest
    <$> fmap toSecKey (m .: "d")
    <*> fmap toBS (m .: "m")

data InvalidVerifyTest = InvalidVerifyTest {
    ivv_Q           :: !BS.ByteString
  , ivv_m           :: !BS.ByteString
  , ivv_signature   :: !BS.ByteString
  } deriving Show

instance A.FromJSON InvalidVerifyTest where
  parseJSON = A.withObject "InvalidVerifyTest" $ \m -> InvalidVerifyTest
    <$> fmap TE.encodeUtf8 (m .: "Q")
    <*> fmap toBS (m .: "m")
    <*> fmap toBS (m .: "signature")

