{-# LANGUAGE OverloadedStrings #-}
module SecretBoxTest (secretBoxSpec) where

import Test.Hspec.QuickCheck
import Test.Tasty.Hspec
import Test.QuickCheck.Arbitrary
import Test.QuickCheck.Property

import Crypto.Lithium.Random
import Crypto.Lithium.SecretBox as S
import Crypto.Lithium.Unsafe.SecretBox as U
import Crypto.Lithium.Unsafe.Types

import Control.Monad.IO.Class
import Data.ByteArray as B
import Data.ByteString.Base16
import Data.ByteString (ByteString)

secretBoxSpec :: Spec
secretBoxSpec = parallel $ do
  describe "secretBox" $ do

    it "initializes" $ do
      x <- S.newKey
      y <- randomSecretN
      fromKey x `shouldNotBe` y

    it "works" $ do
      alice <- S.newKey
      let message = "hello Lithium"
      ciphertext <- S.secretBox alice message
      let result = S.openSecretBox alice (ciphertext :: SecretBox ScrubbedBytes ByteString)
      result `shouldBe` Just message

  describe "Unsafe.secretBox" $ do

    it "works" $ do
      alice <- U.newKey
      nonce <- U.newNonce
      let message = "hello unsafe Lithium" :: ByteString
      let ciphertext = U.secretBox alice nonce message
      let result = U.openSecretBox alice nonce (ciphertext :: Bytes)
      result `shouldBe` Just message

  describe "Unsafe.secretBoxDetached" $ do

    it "works" $ do
      alice <- U.newKey
      nonce <- U.newNonce
      let message = "hello Lithium" :: ByteString
      let (ciphertext, tag) = U.secretBoxDetached alice nonce message
      let result = U.openSecretBoxDetached alice nonce tag (ciphertext :: Bytes)
      result `shouldBe` Just message

  describe "constants" $ do

    it "has matching type-level and value-level sizes" $ do
      asNum keyBytes   `shouldBe` keySize
      asNum macBytes   `shouldBe` macSize
      asNum nonceBytes `shouldBe` nonceSize
      asNum tagBytes   `shouldBe` tagSize
