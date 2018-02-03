{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DataKinds #-}
module AeadTest (aeadSpec) where

import Test.Hspec.QuickCheck
import Test.Hspec
import Test.QuickCheck.Arbitrary
import Test.QuickCheck.Property

import Crypto.Lithium.Aead as S
import Crypto.Lithium.Unsafe.Aead as U
import Crypto.Lithium.Unsafe.Types


import Control.Monad.IO.Class
import Data.ByteArray (Bytes)
import qualified Data.ByteArray as B
import qualified Data.ByteArray.Sized as Sized
import Data.ByteString (ByteString)

import TestUtils

instance Arbitrary Key where
  arbitrary = U.asKey <$> arbitrary

instance Arbitrary Nonce where
  arbitrary = U.asNonce <$> arbitrary

aeadSpec :: Spec
aeadSpec = parallel $ do

  describe "Aead" $

    describe "aead" $ do

      prop "decrypts" $
        \key (Message msg) (Message aad) -> do
          ciphertext <- S.aead key msg aad
          let decrypted = S.openAead key ciphertext aad
          decrypted `shouldBe` Just msg

      prop "doesn't decrypt when ciphertext perturbed" $
        \key (Message msg) (Message aad) p -> do
          ciphertext <- S.aead key msg aad
          let perturbed = AeadBox $ perturb p $ getCiphertext ciphertext
              decrypted = S.openAead key perturbed aad
          decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt when associated data perturbed" $
        \key (Message msg) (Message aad) p -> perturb p aad /= aad ==> do
          ciphertext <- S.aead key msg aad
          let perturbed = perturb p aad
              decrypted = S.openAead key ciphertext perturbed
          decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong key" $
        \key1 key2 (Message msg) (Message aad) -> do
          ciphertext <- S.aead key1 msg aad
          let decrypted = S.openAead key2 ciphertext aad
          decrypted `shouldBe` (Nothing :: Maybe ByteString)


  describe "Unsafe.Aead" $ do

    describe "aead" $ do

      prop "decrypts" $
        \key nonce (Message msg) (Message aad) ->
          let ciphertext = U.aead key nonce msg aad :: ByteString
              decrypted = U.openAead key nonce ciphertext aad
          in decrypted `shouldBe` Just msg

      prop "doesn't decrypt when ciphertext perturbed" $
        \key nonce (Message msg) (Message aad) p ->
          let ciphertext = U.aead key nonce msg aad :: ByteString
              perturbed = perturb p ciphertext
              decrypted = U.openAead key nonce perturbed aad
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt when aad perturbed" $
        \key nonce (Message msg) (Message aad) p ->
          perturb p aad /= aad ==>
          let ciphertext = U.aead key nonce msg aad :: ByteString
              perturbed = perturb p aad
              decrypted = U.openAead key nonce ciphertext perturbed
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong recipient" $
        \key1 key2 nonce (Message msg) (Message aad) ->
          let ciphertext = U.aead key1 nonce msg aad :: ByteString
              decrypted = U.openAead key2 nonce ciphertext aad
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong nonce" $
        \key nonce1 nonce2 (Message msg) (Message aad) ->
          let ciphertext = U.aead key nonce1 msg aad :: ByteString
              decrypted = U.openAead key nonce2 ciphertext aad
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "DANGER! is vulnerable to nonce reuse" $
        \key nonce (Message msg1) (Message msg2) (Message aad) ->
          msg1 /= msg2 ==>
          let ct1 = U.aead key nonce msg1 aad :: ByteString
              ct2 = U.aead key nonce msg2 aad :: ByteString
              xoredCiphertexts = B.take
                (min (B.length msg1) (B.length msg2))
                (B.xor ct1 ct2) :: ByteString
          in xoredCiphertexts `shouldBe` B.xor msg1 msg2


    describe "aeadDetached" $ do

      prop "decrypts" $
        \key nonce (Message msg) (Message aad) ->
          let (ciphertext, mac) = U.aeadDetached key nonce msg aad
              decrypted = U.openAeadDetached key
                nonce mac (ciphertext :: ByteString) aad
          in decrypted `shouldBe` Just msg

      prop "doesn't decrypt when ciphertext perturbed" $
        \key nonce (Message msg) (Message aad) p ->
          perturb p msg /= msg ==>
          let (ciphertext, mac) = U.aeadDetached key nonce msg aad
              decrypted = U.openAeadDetached key nonce mac
                (perturb p (ciphertext :: ByteString)) aad
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt when mac perturbed" $
        \key nonce (Message msg) (Message aad) p ->
          let (ciphertext, mac) = U.aeadDetached key nonce msg aad
              decrypted = U.openAeadDetached key nonce
                (U.asMac $ perturbN p $ U.fromMac mac)
                (ciphertext :: ByteString) aad
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong key" $
        \key1 key2 nonce (Message msg) (Message aad) ->
          let (ciphertext, mac) = U.aeadDetached key1 nonce msg aad
              decrypted = U.openAeadDetached key2
                nonce mac (ciphertext :: ByteString) aad
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong nonce" $
        \key nonce1 nonce2 (Message msg) (Message aad) ->
          let (ciphertext, mac) = U.aeadDetached key nonce1 msg aad
              decrypted = U.openAeadDetached key
                nonce2 mac (ciphertext :: ByteString) aad
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "DANGER! is vulnerable to nonce reuse" $
        \key nonce (Message msg1) (Message msg2) (Message aad1) (Message aad2)->
          msg1 /= msg2 ==>
          let (ct1, mac1) = U.aeadDetached key nonce msg1 aad1
              (ct2, mac2) = U.aeadDetached key nonce msg2 aad2
              xoredCiphertexts = B.xor (ct1 :: ByteString) (ct2 :: ByteString)
          in xoredCiphertexts `shouldBe` (B.xor msg1 msg2 :: ByteString)

    describe "aeadN" $ do

      prop "decrypts" $
        \key nonce (SecretMessageN msg) (MessageN aad) ->
          let ciphertext = U.aeadN key nonce msg aad
              decrypted = U.openAeadN key nonce ciphertext aad
          in decrypted `shouldBe` Just msg

      prop "doesn't decrypt when ciphertext perturbed" $
        \key nonce (SecretMessageN msg) (MessageN aad) p ->
          let ciphertext = U.aeadN key nonce msg aad
              perturbed = perturbN p ciphertext
              decrypted = U.openAeadN key nonce perturbed aad
          in decrypted `shouldBe` Nothing

      prop "doesn't decrypt when aad perturbed" $
        \key nonce (SecretMessageN msg) (MessageN aad) p ->
          perturbN p aad /= aad ==>
          let ciphertext = U.aeadN key nonce msg aad
              perturbed = perturbN p aad
              decrypted = U.openAeadN key nonce ciphertext perturbed
          in decrypted `shouldBe` Nothing

      prop "doesn't decrypt with wrong recipient" $
        \key1 key2 nonce (SecretMessageN msg) (MessageN aad) ->
          let ciphertext = U.aeadN key1 nonce msg aad
              decrypted = U.openAeadN key2 nonce ciphertext aad
          in decrypted `shouldBe` Nothing

      prop "doesn't decrypt with wrong nonce" $
        \key nonce1 nonce2 (SecretMessageN msg) (MessageN aad) ->
          let ciphertext = U.aeadN key nonce1 msg aad
              decrypted = U.openAeadN key nonce2 ciphertext aad
          in decrypted `shouldBe` Nothing

      prop "DANGER! is vulnerable to nonce reuse" $
        \key nonce (SecretMessageN msg1) (SecretMessageN msg2) (MessageN aad) ->
          msg1 /= msg2 ==>
          let ct1 = U.aeadN key nonce msg1 aad
              ct2 = U.aeadN key nonce msg2 aad
              xoredCiphertexts = Sized.xor ct1 ct2
          in Sized.take xoredCiphertexts `shouldBe` Sized.convert (Sized.xor (reveal msg1) (reveal msg2))


    describe "aeadDetachedN" $ do

      prop "decrypts" $
        \key nonce (SecretMessageN msg) (MessageN aad) ->
          let (ciphertext, mac) = U.aeadDetachedN key nonce msg aad
              decrypted = U.openAeadDetachedN key
                nonce mac ciphertext aad
          in decrypted `shouldBe` Just msg

      prop "doesn't decrypt when ciphertext perturbed" $
        \key nonce (SecretMessageN msg) (MessageN aad) p ->
          (perturbN p <$> msg) /= msg ==>
          let (ciphertext, mac) = U.aeadDetachedN key nonce msg aad
              decrypted = U.openAeadDetachedN key nonce mac
                (perturbN p ciphertext) aad
          in decrypted `shouldBe` Nothing

      prop "doesn't decrypt when mac perturbed" $
        \key nonce (SecretMessageN msg) (MessageN aad) p ->
          let (ciphertext, mac) = U.aeadDetachedN key nonce msg aad
              decrypted = U.openAeadDetachedN key nonce
                (U.asMac $ perturbN p $ U.fromMac mac)
                ciphertext aad
          in decrypted `shouldBe` Nothing

      prop "doesn't decrypt with wrong key" $
        \key1 key2 nonce (SecretMessageN msg) (MessageN aad) ->
          let (ciphertext, mac) = U.aeadDetachedN key1 nonce msg aad
              decrypted = U.openAeadDetachedN key2
                nonce mac ciphertext aad
          in decrypted `shouldBe` Nothing

      prop "doesn't decrypt with wrong nonce" $
        \key nonce1 nonce2 (SecretMessageN msg) (MessageN aad) ->
          let (ciphertext, mac) = U.aeadDetachedN key nonce1 msg aad
              decrypted = U.openAeadDetachedN key
                nonce2 mac ciphertext aad
          in decrypted `shouldBe` Nothing

      prop "DANGER! is vulnerable to nonce reuse" $
        \key nonce (SecretMessageN msg1) (SecretMessageN msg2) (MessageN aad1) (MessageN aad2)->
          msg1 /= msg2 ==>
          let (ct1, mac1) = U.aeadDetachedN key nonce msg1 aad1
              (ct2, mac2) = U.aeadDetachedN key nonce msg2 aad2
              xoredCiphertexts = Sized.convert $ Sized.xor ct1 ct2
          in xoredCiphertexts `shouldBe` Sized.xor (reveal msg1) (reveal msg2)

  describe "byte sizes" $

    it "has matching type-level and value-level sizes" $ do
      theNat @KeyBytes   `shouldBe` keySize
      theNat @MacBytes   `shouldBe` macSize
      theNat @NonceBytes `shouldBe` nonceSize
      theNat @TagBytes   `shouldBe` tagSize
