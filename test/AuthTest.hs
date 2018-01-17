{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
module AuthTest (authSpec) where

import Test.Hspec.QuickCheck
import Test.Hspec
import Test.QuickCheck.Arbitrary
import Test.QuickCheck.Property

import Crypto.Lithium.Auth as S
import Crypto.Lithium.Unsafe.Auth as U
import Crypto.Lithium.Unsafe.OnetimeAuth as O
import Crypto.Lithium.Unsafe.Types


import Control.Monad.IO.Class
import Data.ByteArray (Bytes)
import qualified Data.ByteArray as B
import qualified Data.ByteArray.Encoding as B
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import TestUtils

instance Arbitrary U.Key where
  arbitrary = U.Key <$> arbitrary

instance Arbitrary O.Key where
  arbitrary = O.Key <$> arbitrary

authSpec :: Spec
authSpec = parallel $ do
  describe "Auth" $ do

    describe "auth" $ do

      prop "authes different messages to different digests" $
        \(Message msg1) (Message msg2) key -> msg1 /= msg2 ==>
        S.auth key msg1 `shouldNotBe` S.auth key msg2

      prop "authes the same message with different keys to different digests" $
        \(Message msg) key1 key2 -> key1 /= key2 ==>
        S.auth key1 msg `shouldNotBe` S.auth key2 msg

    describe "verify" $ do

      prop "verifies" $
        \key (Message msg) ->
          S.verify key (S.auth key msg) msg `shouldBe` True

      prop "doesn't verify when mac perturbed" $
        \key (Message msg) p ->
          let mac = S.auth key msg
              perturbed = S.makeMac $ perturbN p $ S.unMac mac
          in S.verify key perturbed msg `shouldBe` False

      prop "doesn't verify when message perturbed" $
        \key (Message msg) p -> perturb p msg /= msg ==>
          let mac = S.auth key msg
              perturbed = perturb p msg
          in S.verify key mac perturbed `shouldBe` False

  describe "Unsafe.OnetimeAuth" $ do

    describe "auth" $ do

      prop "authes different messages to different digests" $
        \(Message msg1) (Message msg2) key -> msg1 /= msg2 ==>
        O.auth key msg1 `shouldNotBe` O.auth key msg2

      prop "authes the same message with different keys to different digests" $
        \(Message msg) key1 key2 -> key1 /= key2 ==>
        O.auth key1 msg `shouldNotBe` O.auth key2 msg

    describe "verify" $ do

      prop "verifies" $
        \key (Message msg) ->
          O.verify key (O.auth key msg) msg `shouldBe` True

      prop "doesn't verify when mac perturbed" $
        \key (Message msg) p ->
          let mac = O.auth key msg
              perturbed = O.Mac $ perturbN p $ O.unMac mac
          in O.verify key perturbed msg `shouldBe` False

      prop "doesn't verify when message perturbed" $
        \key (Message msg) p -> perturb p msg /= msg ==>
          let mac = O.auth key msg
              perturbed = perturb p msg
          in O.verify key mac perturbed `shouldBe` False

    describe "streamingAuth" $ do

      prop "is equivalent to authenticating the data directly" $
        \chunks key ->
          let streamMac = O.streamingAuth key chunks
              directMac = O.auth key (BS.concat chunks)
          in streamMac `shouldBe` directMac

  describe "byte sizes" $ do

    it "has matching type-level and value-level sizes" $ do
      (fromIntegral . natVal) S.macBytes `shouldBe` S.macSize
      (fromIntegral . natVal) S.keyBytes `shouldBe` S.keySize

      (fromIntegral . natVal) O.macBytes `shouldBe` O.macSize
      (fromIntegral . natVal) O.keyBytes `shouldBe` O.keySize
      (fromIntegral . natVal) O.stateBytes `shouldBe` O.stateSize
