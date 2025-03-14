{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module WycheproofEcdh (
    Wycheproof(..)
  , execute_group
  ) where

import Crypto.Curve.Secp256k1
import qualified Crypto.Hash.SHA256 as SHA256
import Data.Aeson ((.:))
import qualified Data.Aeson as A
import qualified Data.Attoparsec.ByteString as AT
import Data.Bits ((.<<.), (.>>.), (.|.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Test.Tasty (TestTree, testGroup)
import qualified Test.Tasty.HUnit as H (assertBool, assertEqual, testCase)

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

execute_group :: EcdhTestGroup -> TestTree
execute_group EcdhTestGroup {..} =
    testGroup msg (fmap execute etg_tests)
  where
    msg = "wycheproof ecdh"

execute :: EcdhTest -> TestTree
execute EcdhTest {..} = H.testCase report $ do
    case der_to_pub t_public of
      Left _ ->
        -- 'acceptable' in wycheproof-speak means that a public key
        -- contains a parameter that, whilst invalid, doesn't actually
        -- affect the ECDH computation. we work only with valid
        -- secp256k1 points, so rule these out as invalid as well.
        --
        H.assertBool "invalid" (t_result `elem` ["invalid", "acceptable"])
      Right pub -> do
        let sec   = parse_bigint t_private
            sar   = parse_bigint t_shared
            h_sar = SHA256.hash (unroll32 sar)
            out   = ecdh pub sec
        H.assertEqual mempty h_sar out
  where
    report = "wycheproof ecdh " <> show t_tcId

-- RFC 5280 ASN.1
--   SubjectPublicKeyInfo  ::=  SEQUENCE  {
--     algorithm         AlgorithmIdentifier,
--     subjectPublicKey  BIT STRING
--   }
--   AlgorithmIdentifier  ::=  SEQUENCE  {
--     algorithm   OBJECT IDENTIFIER,
--     parameters  ANY DEFINED BY algorithm OPTIONAL
--   }
parse_der_pub :: AT.Parser Projective
parse_der_pub = do
  _ <- AT.word8 0x30 -- SEQUENCE
  _ <- AT.anyWord8
  _ <- parse_der_algo
  parse_der_subjectpubkey

parse_der_algo :: AT.Parser ()
parse_der_algo = do
  _ <- AT.word8 0x30 -- SEQUENCE
  _ <- AT.anyWord8
  _ <- parse_der_ecpubkey
  _ <- parse_der_secp256k1
  pure ()

-- RFC 5480 2.1.1
--   id-ecPublicKey OBJECT IDENTIFIER ::= {
--      iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
--
--   DER encoded -> 06 07 2A 86 48 CE 3D 02 01
parse_der_ecpubkey :: AT.Parser ()
parse_der_ecpubkey = do
  _ <- AT.word8 0x06
  _ <- AT.word8 0x07
  _ <- AT.word8 0x2a
  _ <- AT.word8 0x86
  _ <- AT.word8 0x48
  _ <- AT.word8 0xce
  _ <- AT.word8 0x3d
  _ <- AT.word8 0x02
  _ <- AT.word8 0x01
  pure ()

-- SEC1-v2 A.2
--   certicom-arc OBJECT IDENTIFIER ::= {
--     iso(1) identified-organization(3) certicom(132)
--   }
--
--   ellipticCurve OBJECT IDENTIFIER ::= { certicom-arc curve(0) }
--
--   secp256k1 OBJECT IDENTIFIER ::= { ellipticCurve 10 }
--
--   (i.e., 1.3.132.0.10)
--
--   DER encoded -> 06 05 2B 81 04 00 0A
parse_der_secp256k1 :: AT.Parser ()
parse_der_secp256k1 = do
  _ <- AT.word8 0x06
  _ <- AT.word8 0x05
  _ <- AT.word8 0x2b
  _ <- AT.word8 0x81
  _ <- AT.word8 0x04
  _ <- AT.word8 0x00
  _ <- AT.word8 0x0a
  pure ()

parse_der_subjectpubkey :: AT.Parser Projective
parse_der_subjectpubkey = do
  _ <- AT.word8 0x03 -- BIT STRING
  len <- fmap fi AT.anyWord8
  _ <- AT.word8 0x00 -- extra bits (always 0x00 for DER)
  content <- AT.take (len - 1) -- len counts 'extra bits' field
  etc <- AT.takeByteString
  if   BS.length content /= len - 1 || etc /= mempty
  then fail "invalid content"
  else case parse_point content of
        Nothing -> fail "invalid content"
        Just pt -> pure pt

der_to_pub :: T.Text -> Either String Projective
der_to_pub (B16.decodeLenient . TE.encodeUtf8 -> bs) =
  AT.parseOnly parse_der_pub bs

parse_bigint :: T.Text -> Integer
parse_bigint (B16.decodeLenient . TE.encodeUtf8 -> bs) = roll bs where
  roll :: BS.ByteString -> Integer
  roll = BS.foldl' alg 0 where
    alg !a (fi -> !b) = (a .<<. 8) .|. b

-- big-endian bytestring encoding
unroll :: Integer -> BS.ByteString
unroll i = case i of
    0 -> BS.singleton 0
    _ -> BS.reverse $ BS.unfoldr step i
  where
    step 0 = Nothing
    step m = Just (fi m, m .>>. 8)

-- big-endian bytestring encoding for 256-bit ints, left-padding with
-- zeros if necessary. the size of the integer is not checked.
unroll32 :: Integer -> BS.ByteString
unroll32 (unroll -> u)
    | l < 32 = BS.replicate (32 - l) 0 <> u
    | otherwise = u
  where
    l = BS.length u

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

