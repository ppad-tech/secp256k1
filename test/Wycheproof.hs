{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module Wycheproof (
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

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- big-endian bytestring decoding
roll :: BS.ByteString -> Integer
roll = BS.foldl' unstep 0 where
  unstep a (fi -> b) = (a `I.integerShiftL` 8) `I.integerOr` b

execute_group :: SigType -> EcdsaTestGroup -> TestTree
execute_group ty EcdsaTestGroup {..} =
    testGroup msg (fmap (execute ty pk_uncompressed) etg_tests)
  where
    msg = "wycheproof (" <> T.unpack etg_type <> ", " <> T.unpack etg_sha <> ")"
    PublicKey {..} = etg_publicKey

execute :: SigType -> Projective -> EcdsaVerifyTest -> TestTree
execute ty pub EcdsaVerifyTest {..} = testCase report $ do
    let msg = B16.decodeLenient (TE.encodeUtf8 t_msg)
        sig = toEcdsa t_sig
    case sig of
      Left _  -> assertBool mempty (t_result == "invalid")
      Right s -> do
        let ver = case ty of
              LowS -> verify_ecdsa msg pub s
              Unrestricted -> verify_ecdsa_unrestricted msg pub s
        if   t_result == "invalid"
        then assertBool mempty (not ver)
        else assertBool mempty ver
  where
    report = "wycheproof (" <> show ty <> ") " <> show t_tcId

parse_der_sig :: AT.Parser ECDSA
parse_der_sig = do
    _ <- AT.word8 0x30
    len <- fmap fi AT.anyWord8
    content <- AT.take len
    etc <- AT.takeByteString
    if   BS.length content /= len || etc /= mempty
    then fail "invalid content"
    else case AT.parseOnly (meat len) content of
      Left _  -> fail "invalid content"
      Right v -> pure v
  where
    meat len = do
      (lr, bs_r) <- parseAsnInt
      (ls, bs_s) <- parseAsnInt
      let r = fi (roll bs_r)
          s = fi (roll bs_s)
          checks = lr + ls == len
      rest <- AT.takeByteString
      if   rest == mempty && checks
      then pure (ECDSA r s)
      else fail "input remaining or length mismatch"

parseAsnInt :: AT.Parser (Int, BS.ByteString)
parseAsnInt = do
  _       <- AT.word8 0x02
  len     <- fmap fi AT.anyWord8
  content <- AT.take len
  if   BS.length content /= len
  then fail "invalid length"
  else if   len == 1
       then pure (len + 2, content) -- + tag byt + len byt
       else case BS.uncons content of
         Nothing -> fail "invalid content"
         Just (h0, t0)
           | B.testBit h0 7 -> fail "negative value"
           | otherwise -> case BS.uncons t0 of
               Nothing -> fail "invalid content"
               Just (h1, _)
                 | h0 == 0x00 && not (B.testBit h1 7) -> fail "invalid padding"
                 | otherwise -> case BS.unsnoc content of
                     Nothing -> fail "invalid content"
                     Just (_, tn)
                       | tn == 0x00 -> fail "invalid padding"
                       | otherwise  -> pure (len + 2, content)

data Wycheproof = Wycheproof {
    wp_algorithm        :: !T.Text
  , wp_generatorVersion :: !T.Text
  , wp_numberOfTests    :: !Int
  , wp_testGroups       :: ![EcdsaTestGroup]
  } deriving Show

instance A.FromJSON Wycheproof where
  parseJSON = A.withObject "Wycheproof" $ \m -> Wycheproof
    <$> m .: "algorithm"
    <*> m .: "generatorVersion"
    <*> m .: "numberOfTests"
    <*> m .: "testGroups"

data EcdsaTestGroup = EcdsaTestGroup {
    etg_type      :: !T.Text
  , etg_publicKey :: !PublicKey
  , etg_sha       :: !T.Text
  , etg_tests     :: ![EcdsaVerifyTest]
  } deriving Show

instance A.FromJSON EcdsaTestGroup where
  parseJSON = A.withObject "EcdsaTestGroup" $ \m -> EcdsaTestGroup
    <$> m .: "type"
    <*> m .: "publicKey"
    <*> m .: "sha"
    <*> m .: "tests"

data PublicKey = PublicKey {
    pk_type         :: !T.Text
  , pk_curve        :: !T.Text
  , pk_keySize      :: !Int
  , pk_uncompressed :: !Projective
  } deriving Show

toProjective :: T.Text -> Projective
toProjective (TE.encodeUtf8 -> bs) = case parse_point bs of
  Nothing -> error "wycheproof: couldn't parse pubkey"
  Just p -> p

instance A.FromJSON PublicKey where
  parseJSON = A.withObject "PublicKey" $ \m -> PublicKey
    <$> m .: "type"
    <*> m .: "curve"
    <*> m .: "keySize"
    <*> fmap toProjective (m .: "uncompressed")

toEcdsa :: T.Text -> Either String ECDSA
toEcdsa (B16.decodeLenient . TE.encodeUtf8 -> bs) =
  AT.parseOnly parse_der_sig bs

data EcdsaVerifyTest = EcdsaVerifyTest {
    t_tcId    :: !Int
  , t_comment :: !T.Text
  , t_msg     :: !T.Text
  , t_sig     :: !T.Text
  , t_result  :: !T.Text
  } deriving Show

instance A.FromJSON EcdsaVerifyTest where
  parseJSON = A.withObject "EcdsaVerifyTest" $ \m -> EcdsaVerifyTest
    <$> m .: "tcId"
    <*> m .: "comment"
    <*> m .: "msg"
    <*> m .: "sig"
    <*> m .: "result"

