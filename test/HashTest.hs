{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
module HashTest (hashSpec) where

import Test.Hspec.QuickCheck
import Test.Hspec
import Test.QuickCheck.Arbitrary
import Test.QuickCheck.Property

import Crypto.Lithium.Hash as S
import Crypto.Lithium.Unsafe.Hash as U
import Crypto.Lithium.Unsafe.Types


import Control.Monad.IO.Class
import Data.ByteArray (Bytes)
import qualified Data.ByteArray as B
import qualified Data.ByteArray.Encoding as B
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Maybe (fromJust)

import TestUtils

instance (Between MinKeyBytes MaxKeyBytes l) => Arbitrary (U.Key l) where
  arbitrary = U.Key <$> arbitrary

type Digest32 = U.Digest 32
type Key32 = U.Key 32

hashSpec :: Spec
hashSpec = parallel $ do
  describe "Hash" $ do

    describe "hash" $ do

      prop "hashes different messages to different digests" $
        \(Message msg1) (Message msg2) -> msg1 /= msg2 ==>
        hash msg1 `shouldNotBe` hash msg2

      prop "hashes the same message with and without key to different digests" $
        \(Message msg) key ->
          hash msg `shouldNotBe` keyedHash key msg

      prop "hashes the same message with different keys to different digests" $
        \(Message msg) key1 key2 -> key1 /= key2 ==>
        keyedHash key1 msg `shouldNotBe` keyedHash key2 msg

    describe "longHash" $ do

      it "matches empty test vector" $
        fromLongDigest (keyedLongHash testKey testIn0) `shouldBe` testOut0

      it "matches test vector 1" $
        fromLongDigest (keyedLongHash testKey testIn1) `shouldBe` testOut1

      it "matches test vector 2" $
        fromLongDigest (keyedLongHash testKey testIn2) `shouldBe` testOut2

      it "matches test vector 3" $
        fromLongDigest (keyedLongHash testKey testIn3) `shouldBe` testOut3

      it "matches test vector 4" $
        fromLongDigest (keyedLongHash testKey testIn4) `shouldBe` testOut4

      prop "a shorter digest is not the prefix of a longer digest" $
        \(Message msg) ->
          let shortDigest = hash msg
              longDigest = longHash msg
          in S.fromDigest shortDigest `shouldNotBe` BS.take digestSize (fromLongDigest longDigest)

    describe "streamingHash" $

      prop "is equivalent to hashing the data directly" $
        \chunks ->
          let streamDigest = S.streamingHash Nothing chunks
              directDigest = S.hash (BS.concat chunks)
          in S.fromDigest streamDigest `shouldBe` (S.fromDigest directDigest :: ByteString)

  describe "byte sizes" $

    it "has matching type-level and value-level sizes" $ do
      theNat @DigestBytes `shouldBe` digestSize
      theNat @LongDigestBytes `shouldBe` longDigestSize
      theNat @KeyBytes `shouldBe` keySize
      theNat @LongKeyBytes `shouldBe` longKeySize

      theNat @MinDigestBytes `shouldBe` minDigestSize
      theNat @MaxDigestBytes `shouldBe` maxDigestSize
      theNat @MinKeyBytes `shouldBe` minKeySize
      theNat @MaxKeyBytes `shouldBe` maxKeySize
      theNat @StateBytes `shouldBe` stateSize


from16 :: ByteString -> Bytes
from16 = either (const B.empty) id . B.convertFromBase B.Base16

testKey :: LongKey
testKey = fromJust . U.asKey @LongKeyBytes $ from16 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"

testIn0, testIn1, testIn2, testIn3, testIn4 :: Bytes
testOut0, testOut1, testOut2, testOut3, testOut4 :: Bytes

testIn0 = from16 ""
testOut0 = from16 "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"

testIn1 = from16 "000102030405060708090a0b0c0d0e0f"
testOut1 = from16 "a0c65bddde8adef57282b04b11e7bc8aab105b99231b750c021f4a735cb1bcfab87553bba3abb0c3e64a0b6955285185a0bd35fb8cfde557329bebb1f629ee93"

testIn2 = from16 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
testOut2 = from16 "86221f3ada52037b72224f105d7999231c5e5534d03da9d9c0a12acb68460cd375daf8e24386286f9668f72326dbf99ba094392437d398e95bb8161d717f8991"

testIn3 = from16 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
testOut3 = from16 "41daa6adcfdb69f1440c37b596440165c15ada596813e2e22f060fcd551f24dee8e04ba6890387886ceec4a7a0d7fc6b44506392ec3822c0d8c1acfc7d5aebe8"

testIn4 = from16 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe"
testOut4 = from16 "142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e92484be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461"
