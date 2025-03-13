{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module WycheproofEcdh (
    Wycheproof(..)
  , execute_group
  ) where

import Crypto.Curve.Secp256k1
import Data.Aeson ((.:))
import qualified Data.Aeson as A
import qualified Data.Attoparsec.ByteString as AT
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified GHC.Num.Integer as I
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, testCase)

execute_group = undefined

data Wycheproof = Wycheproof {
    wp_testGroups :: ![EcdhTestGroup]
  } deriving Show

instance A.FromJSON Wycheproof where
  parseJSON = A.withObject "Wycheproof" $ \m -> Wycheproof
    <$> m .: "testGroups"

data EcdhTestGroup = EcdhTestGroup {
    etg_tests     :: ![EcdhTest]
  } deriving Show

instance A.FromJSON EcdhTestGroup where
  parseJSON = A.withObject "EcdhTestGroup" $ \m -> EcdhTestGroup
    <$> m .: "tests"

data PublicKey = PublicKey {
    pk_type         :: !T.Text
  , pk_curve        :: !T.Text
  , pk_keySize      :: !Int
  , pk_uncompressed :: !Projective
  } deriving Show

toProjective :: T.Text -> Projective
toProjective (B16.decodeLenient . TE.encodeUtf8 -> bs) = case parse_point bs of
  Nothing -> error "wycheproof: couldn't parse pubkey"
  Just p -> p

instance A.FromJSON PublicKey where
  parseJSON = A.withObject "PublicKey" $ \m -> PublicKey
    <$> m .: "type"
    <*> m .: "curve"
    <*> m .: "keySize"
    <*> fmap toProjective (m .: "uncompressed")

data EcdhTest = EcdhTest {
    t_tcId    :: !Int
  , t_public  :: !T.Text
  , t_private :: !T.Text
  , t_shared  :: !T.Text
  , t_result  :: !T.Text
  } deriving Show

instance A.FromJSON EcdhTest where
  parseJSON = A.withObject "EcdhTest" $ \m -> EcdhTest
    <$> m .: "tcId"
    <*> m .: "public"
    <*> m .: "private"
    <*> m .: "shared"
    <*> m .: "result"


