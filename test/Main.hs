{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as BS
import Crypto.Curve.Secp256k1
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain units

units :: TestTree
units = testGroup "unit tests" [
    parse_point_tests
  , add_tests
  , dub_tests
  ]

parse_point_tests :: TestTree
parse_point_tests = testGroup "parse_point tests" [
    parse_point_test_p
  , parse_point_test_q
  , parse_point_test_r
  ]

render :: Show a => a -> String
render = filter (`notElem` ("\"" :: String)) . show

-- XX replace these with something non-stupid
parse_point_test_p :: TestTree
parse_point_test_p = testCase (render p_hex) $ case parse_point p_hex of
  Nothing -> assertFailure "bad parse"
  Just p  -> assertEqual mempty p_pro p

parse_point_test_q :: TestTree
parse_point_test_q = testCase (render q_hex) $ case parse_point q_hex of
  Nothing -> assertFailure "bad parse"
  Just q  -> assertEqual mempty q_pro q

parse_point_test_r :: TestTree
parse_point_test_r = testCase (render r_hex) $ case parse_point r_hex of
  Nothing -> assertFailure "bad parse"
  Just r  -> assertEqual mempty r_pro r

-- XX also make less dumb
add_tests :: TestTree
add_tests = testGroup "ec addition" [
    add_test_pq
  , add_test_pr
  , add_test_qr
  ]

add_test_pq :: TestTree
add_test_pq = testCase "p + q" $
  assertEqual mempty pq_pro (p_pro `add` q_pro)

add_test_pr :: TestTree
add_test_pr = testCase "p + r" $
  assertEqual mempty pr_pro (p_pro `add` r_pro)

add_test_qr :: TestTree
add_test_qr = testCase "q + r" $
  assertEqual mempty qr_pro (q_pro `add` r_pro)

dub_tests :: TestTree
dub_tests = testGroup "ec doubling" [
    dub_test_p
  , dub_test_q
  , dub_test_r
  ]

dub_test_p :: TestTree
dub_test_p = testCase "2p" $
  assertEqual mempty (p_pro `add` p_pro) (double p_pro)

dub_test_q :: TestTree
dub_test_q = testCase "2q" $
  assertEqual mempty (q_pro `add` q_pro) (double q_pro)

dub_test_r :: TestTree
dub_test_r = testCase "2r" $
  assertEqual mempty (r_pro `add` r_pro) (double r_pro)

p_hex :: BS.ByteString
p_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

p_pro :: Projective
p_pro = Projective {
    px = 55066263022277343669578718895168534326250603453777594175500187360389116729240
  , py = 32670510020758816978083085130507043184471273380659243275938904335757337482424
  , pz = 1
  }

q_hex :: BS.ByteString
q_hex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

q_pro :: Projective
q_pro = Projective {
    px = 112711660439710606056748659173929673102114977341539408544630613555209775888121
  , py = 25583027980570883691656905877401976406448868254816295069919888960541586679410
  , pz = 1
  }

r_hex :: BS.ByteString
r_hex = "03a2113cf152585d96791a42cdd78782757fbfb5c6b2c11b59857eb4f7fda0b0e8"

r_pro :: Projective
r_pro = Projective {
    px = 73305138481390301074068425511419969342201196102229546346478796034582161436904
  , py = 77311080844824646227678701997218206005272179480834599837053144390237051080427
  , pz = 1
  }

pq_pro :: Projective
pq_pro = Projective {
    px = 52396973184413144605737087313078368553350360735730295164507742012595395307648
  , py = 81222895265056120475581324527268307707868393868711445371362592923687074369515
  , pz = 57410578768022213246260942140297839801661445014943088692963835122150180187279
  }

pr_pro :: Projective
pr_pro = Projective {
    px = 1348700846815225554023000535566992225745844759459188830982575724903956130228
  , py = 36170035245379023681754688218456726199360176620640420471087552839246039945572
  , pz = 92262311556350124501370727779827867637071338628440636251794554773617634796873
  }

qr_pro :: Projective
qr_pro = Projective {
    px = 98601662106226486891738184090788320295235665172235527697419658886981126285906
  , py = 18578813777775793862159229516827464252856752093683109113431170463916250542461
  , pz = 56555634785712334774735413904899958905472439323190450522613637299635410127585
  }

