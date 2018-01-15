{-# LANGUAGE OverloadedStrings #-}
module SecretBoxTest (secretBoxSpec) where

import Test.Hspec.QuickCheck
import Test.Tasty.Hspec
import Test.QuickCheck.Arbitrary
import Test.QuickCheck.Property

import Crypto.Lithium.SecretBox as S
import Crypto.Lithium.Unsafe.SecretBox as U
import Crypto.Lithium.Unsafe.Types


import Control.Monad.IO.Class
import Data.ByteArray (Bytes)
import qualified Data.ByteArray as B
import Data.ByteString.Base16
import Data.ByteString (ByteString)

import TestUtils

instance Arbitrary Key where
  arbitrary = U.Key <$> arbitrary

instance Arbitrary Nonce where
  arbitrary = U.Nonce <$> arbitrary

secretBoxSpec :: Spec
secretBoxSpec = parallel $ do

  describe "SecretBox" $ do

    describe "secretBox" $ do

      prop "decrypts" $
        \key (Message msg) -> do
          ciphertext <- S.secretBox key msg
          let decrypted = S.openSecretBox key ciphertext
          decrypted `shouldBe` Just msg

      prop "doesn't decrypt when ciphertext perturbed" $
        \key (Message msg) p -> do
          ciphertext <- S.secretBox key msg
          let perturbed = SecretBox $ perturb p $ getCiphertext ciphertext
              decrypted = S.openSecretBox key perturbed
          decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong key" $
        \key1 key2 (Message msg) -> do
          ciphertext <- S.secretBox key1 msg
          let decrypted = S.openSecretBox key2 ciphertext
          decrypted `shouldBe` (Nothing :: Maybe ByteString)


  describe "Unsafe.SecretBox" $ do

    describe "secretBox" $ do

      prop "decrypts" $
        \key nonce (Message msg) ->
          let ciphertext = U.secretBox key nonce msg :: ByteString
              decrypted = U.openSecretBox key nonce ciphertext
          in decrypted `shouldBe` Just msg

      prop "doesn't decrypt when ciphertext perturbed" $
        \key nonce (Message msg) p ->
          let ciphertext = U.secretBox key nonce msg :: ByteString
              perturbed = perturb p ciphertext
              decrypted = U.openSecretBox key nonce perturbed
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong recipient" $
        \key1 key2 nonce (Message msg) ->
          let ciphertext = U.secretBox key1 nonce msg :: ByteString
              decrypted = U.openSecretBox key2 nonce ciphertext
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong nonce" $
        \key nonce1 nonce2 (Message msg) ->
          let ciphertext = U.secretBox key nonce1 msg :: ByteString
              decrypted = U.openSecretBox key nonce2 ciphertext
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "DANGER! is vulnerable to nonce reuse" $
        \key nonce (Message msg1) (Message msg2) ->
          msg1 /= msg2 ==>
          let ct1 = U.secretBox key nonce msg1 :: ByteString
              ct2 = U.secretBox key nonce msg2 :: ByteString
              xoredCiphertexts = B.drop macSize (B.xor ct1 ct2) :: ByteString
          in xoredCiphertexts `shouldBe` B.xor msg1 msg2


    describe "secretBoxDetached" $ do

      prop "decrypts" $
        \key nonce (Message msg) ->
          let (ciphertext, mac) = U.secretBoxDetached key nonce msg
              decrypted = U.openSecretBoxDetached key
                nonce mac (ciphertext :: ByteString)
          in decrypted `shouldBe` Just msg

      prop "doesn't decrypt when ciphertext perturbed" $
        \key nonce (Message msg) p ->
          perturb p msg /= msg ==>
          let (ciphertext, mac) = U.secretBoxDetached key nonce msg
              decrypted = U.openSecretBoxDetached key nonce mac
                (perturb p (ciphertext :: ByteString))
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt when mac perturbed" $
        \key nonce (Message msg) p ->
          let (ciphertext, mac) = U.secretBoxDetached key nonce msg
              decrypted = U.openSecretBoxDetached key nonce
                (U.Mac $ perturbN p $ U.unMac mac)
                (ciphertext :: ByteString)
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong key" $
        \key1 key2 nonce (Message msg) ->
          let (ciphertext, mac) = U.secretBoxDetached key1 nonce msg
              decrypted = U.openSecretBoxDetached key2
                nonce mac (ciphertext :: ByteString)
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong nonce" $
        \key nonce1 nonce2 (Message msg) ->
          let (ciphertext, mac) = U.secretBoxDetached key nonce1 msg
              decrypted = U.openSecretBoxDetached key
                nonce2 mac (ciphertext :: ByteString)
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "DANGER! is vulnerable to nonce reuse" $
        \key nonce (Message msg1) (Message msg2)->
          msg1 /= msg2 ==>
          let (ct1, mac1) = U.secretBoxDetached key nonce msg1
              (ct2, mac2) = U.secretBoxDetached key nonce msg2
              xoredCiphertexts = B.xor (ct1 :: ByteString) (ct2 :: ByteString)
          in xoredCiphertexts `shouldBe` (B.xor msg1 msg2 :: ByteString)

  describe "byte sizes" $ do

    it "has matching type-level and value-level sizes" $ do
      asNum keyBytes   `shouldBe` (keySize :: Int)
      asNum macBytes   `shouldBe` (macSize :: Int)
      asNum nonceBytes `shouldBe` (nonceSize :: Int)
      asNum tagBytes   `shouldBe` (tagSize :: Int)
