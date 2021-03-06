{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module BoxTest (boxSpec) where

import Test.Hspec.QuickCheck
import Test.Hspec
import Test.QuickCheck.Arbitrary
import Test.QuickCheck.Property

import Crypto.Lithium.Box as S
import Crypto.Lithium.Unsafe.Box as U
import Crypto.Lithium.Unsafe.Types


import Control.Monad.IO.Class
import Data.ByteArray (Bytes)
import qualified Data.ByteArray as B
import Data.ByteString (ByteString)

import TestUtils

instance Arbitrary Keypair where
  arbitrary = U.seedKeypair <$> arbitrary

instance Arbitrary PublicKey where
  arbitrary = publicKey <$> arbitrary

instance Arbitrary SecretKey where
  arbitrary = secretKey <$> arbitrary

instance Arbitrary Nonce where
  arbitrary = U.Nonce <$> arbitrary

instance Arbitrary Seed where
  arbitrary = U.Seed <$> arbitrary

boxSpec :: Spec
boxSpec = parallel $ do

  describe "Box" $ do

    describe "box" $ do

      prop "decrypts" $
        \alice bob (Message msg) -> do
          ciphertext <- S.box (publicKey bob) (secretKey alice) msg
          let decrypted = S.openBox (publicKey alice) (secretKey bob) ciphertext
          decrypted `shouldBe` Just msg

      prop "doesn't decrypt when perturbed" $
        \alice bob (Message msg) p -> do
          ciphertext <- S.box (publicKey bob) (secretKey alice) msg
          let perturbed = Box $ perturb p $ unBox ciphertext
              decrypted = S.openBox (publicKey alice) (secretKey bob) perturbed
          decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong recipient" $
        \alice bob charlie (Message msg) -> do
          ciphertext <- S.box (publicKey bob) (secretKey alice) msg
          let decrypted = S.openBox (publicKey alice) (secretKey charlie) ciphertext
          decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong sender" $
        \alice bob charlie (Message msg) -> do
          ciphertext <- S.box (publicKey bob) (secretKey alice) msg
          let decrypted = S.openBox (publicKey charlie) (secretKey bob) ciphertext
          decrypted `shouldBe` (Nothing :: Maybe ByteString)

    describe "precalculate" $ do

      prop "symmetric" $
        \alice bob -> do
          let bobs = precalculate (publicKey alice) (secretKey bob)
          let alices = precalculate (publicKey bob) (secretKey alice)
          bobs `shouldBe` alices

      prop "interchangeable when sending" $
        \alice bob (Message msg) -> do
          let bobs = precalculate (publicKey alice) (secretKey bob)
          ciphertext <- S.box' bobs msg
          let decrypted = S.openBox (publicKey bob) (secretKey alice) ciphertext
          decrypted `shouldBe` Just msg

      prop "interchangeable when receiving" $
        \alice bob (Message msg) -> do
          ciphertext <- S.box (publicKey alice) (secretKey bob) msg
          let alices = precalculate (publicKey bob) (secretKey alice)
          let decrypted = S.openBox' alices ciphertext
          decrypted `shouldBe` Just msg

    describe "sealBox" $

      prop "roundtrips" $
        \alice (Message msg) -> do
          ciphertext <- S.sealBox (publicKey alice) msg
          let decrypted = S.openSealedBox alice ciphertext
          decrypted `shouldBe` Just msg


  describe "Unsafe.Box" $ do

    describe "box" $ do

      prop "decrypts" $
        \alice bob nonce (Message msg) ->
          let ciphertext = U.box (publicKey bob) (secretKey alice) nonce msg :: ByteString
              decrypted = U.openBox (publicKey alice) (secretKey bob) nonce ciphertext
          in decrypted `shouldBe` Just msg

      prop "doesn't decrypt when perturbed" $
        \alice bob nonce (Message msg) p ->
          let ciphertext = U.box (publicKey bob) (secretKey alice) nonce msg :: ByteString
              perturbed = perturb p ciphertext
              decrypted = U.openBox (publicKey alice) (secretKey bob) nonce perturbed
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong recipient" $
        \alice bob charlie nonce (Message msg) ->
          let ciphertext = U.box (publicKey bob) (secretKey alice) nonce msg :: ByteString
              decrypted = U.openBox (publicKey alice) (secretKey charlie) nonce ciphertext
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong sender" $
        \alice bob charlie nonce (Message msg) ->
          let ciphertext = U.box (publicKey bob) (secretKey alice) nonce msg :: ByteString
              decrypted = U.openBox (publicKey charlie) (secretKey bob) nonce ciphertext
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong nonce" $
        \alice bob nonce1 nonce2 (Message msg) ->
          let ciphertext = U.box (publicKey bob) (secretKey alice) nonce1 msg :: ByteString
              decrypted = U.openBox (publicKey alice) (secretKey bob) nonce2 ciphertext
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "DANGER! is vulnerable to nonce reuse" $
        \alice bob nonce (Message msg1) (Message msg2) ->
          msg1 /= msg2 ==>
          let ct1 = U.box (publicKey bob) (secretKey alice) nonce msg1 :: ByteString
              ct2 = U.box (publicKey bob) (secretKey alice) nonce msg2 :: ByteString
              xoredCiphertexts = B.xor (B.drop macSize ct1) (B.drop macSize ct2) :: ByteString
          in xoredCiphertexts `shouldBe` B.xor msg1 msg2


    describe "detachedBox" $ do

      prop "decrypts" $
        \alice bob nonce (Message msg) ->
          let (ciphertext, mac) = U.detachedBox (publicKey bob) (secretKey alice) nonce msg
              decrypted = U.openDetachedBox (publicKey alice) (secretKey bob)
                nonce mac (ciphertext :: ByteString)
          in decrypted `shouldBe` Just msg

      prop "doesn't decrypt when ciphertext perturbed" $
        \alice bob nonce (Message msg) p ->
          perturb p msg /= msg ==>
          let (ciphertext, mac) = U.detachedBox (publicKey bob) (secretKey alice) nonce msg
              decrypted = U.openDetachedBox (publicKey alice) (secretKey bob)
                nonce mac $ perturb p (ciphertext :: ByteString)
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt when mac perturbed" $
        \alice bob nonce (Message msg) p ->
          let (ciphertext, mac) = U.detachedBox (publicKey bob) (secretKey alice) nonce msg
              decrypted = U.openDetachedBox (publicKey alice) (secretKey bob)
                nonce (U.Mac $ perturbN p $ U.unMac mac) (ciphertext :: ByteString)
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong recipient" $
        \alice bob charlie nonce (Message msg) ->
          let (ciphertext, mac) = U.detachedBox (publicKey bob) (secretKey alice) nonce msg
              decrypted = U.openDetachedBox (publicKey alice) (secretKey charlie)
                nonce mac (ciphertext :: ByteString)
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong sender" $
        \alice bob charlie nonce (Message msg) ->
          let (ciphertext, mac) = U.detachedBox (publicKey bob) (secretKey alice) nonce msg
              decrypted = U.openDetachedBox (publicKey charlie) (secretKey bob)
                nonce mac (ciphertext :: ByteString)
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't decrypt with wrong nonce" $
        \alice bob nonce1 nonce2 (Message msg) ->
          let (ciphertext, mac) = U.detachedBox (publicKey bob) (secretKey alice) nonce1 msg
              decrypted = U.openDetachedBox (publicKey alice) (secretKey bob)
                nonce2 mac (ciphertext :: ByteString)
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "DANGER! is vulnerable to nonce reuse" $
        \alice bob nonce (Message msg1) (Message msg2) ->
          msg1 /= msg2 ==>
          let (ct1, mac1) = U.detachedBox (publicKey bob) (secretKey alice) nonce msg1
              (ct2, mac2) = U.detachedBox (publicKey bob) (secretKey alice) nonce msg2
              xoredCiphertexts = B.xor (ct1 :: ByteString) (ct2 :: ByteString)
          in xoredCiphertexts `shouldBe` (B.xor msg1 msg2 :: ByteString)

    describe "conversions" $ do

      encodingRoundtrips "Seed" asSeed fromSeed
      encodingRoundtrips "Nonce" asNonce fromNonce
      encodingRoundtrips "Keypair" asKeypair fromKeypair
      encodingRoundtrips "PublicKey" asPublicKey fromPublicKey
      encodingRoundtrips "SecretKey" asSecretKey fromSecretKey

  describe "byte sizes" $

    it "has matching type-level and value-level sizes" $ do
      theNat @PublicKeyBytes `shouldBe` publicKeySize
      theNat @SecretKeyBytes `shouldBe` secretKeySize
      theNat @MacBytes       `shouldBe` macSize
      theNat @NonceBytes     `shouldBe` nonceSize
      theNat @SeedBytes      `shouldBe` seedSize
      theNat @SharedKeyBytes `shouldBe` sharedKeySize
      theNat @TagBytes       `shouldBe` tagSize
