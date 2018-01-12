{-# LANGUAGE OverloadedStrings #-}
module SignTest (signSpec) where

import Test.Hspec.QuickCheck
import Test.Tasty.Hspec
import Test.QuickCheck.Arbitrary
import Test.QuickCheck.Property

import Crypto.Lithium.Sign as S
import Crypto.Lithium.Unsafe.Sign as U
import Crypto.Lithium.Unsafe.Types


import Control.Monad.IO.Class
import Data.ByteArray (Bytes)
import qualified Data.ByteArray as B
import Data.ByteString.Base16
import Data.ByteString (ByteString)

import TestUtils

instance Arbitrary Keypair where
  arbitrary = U.seedKeypair <$> arbitrary

instance Arbitrary Seed where
  arbitrary = U.asSeed <$> arbitrary

signSpec :: Spec
signSpec = parallel $ do

  describe "Sign" $ do

    describe "sign'" $ do

      prop "opens signed" $
        \alice (Message msg) ->
          let signed = S.sign' (secretKey alice) msg
              decrypted = S.openSigned (publicKey alice) signed
          in decrypted `shouldBe` Just msg

      prop "doesn't open when perturbed" $
        \alice (Message msg) p ->
          let signed = S.sign' (secretKey alice) msg
              perturbed = S.asSigned $ perturb p $ S.fromSigned signed
              decrypted = S.openSigned (publicKey alice) perturbed
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

      prop "doesn't open with wrong public key" $
        \alice bob (Message msg) ->
          let signed = S.sign' (secretKey alice) msg
              decrypted = S.openSigned (publicKey bob) signed
          in decrypted `shouldBe` (Nothing :: Maybe ByteString)

    describe "sign" $ do

      prop "verifies" $
        \alice (Message msg) ->
          let signature = S.sign (secretKey alice) msg
              isValid = S.verify (publicKey alice)
                msg signature
          in isValid `shouldBe` True

      prop "doesn't verify when message perturbed" $
        \alice (Message msg) p ->
          perturb p msg /= msg ==>
          let signature = S.sign (secretKey alice) msg
              isValid = S.verify (publicKey alice)
                (perturb p msg) signature
          in isValid `shouldBe` False

      prop "doesn't verify when signature perturbed" $
        \alice (Message msg) p ->
          let signature = S.sign (secretKey alice) msg
              isValid = S.verify (publicKey alice) msg
                (S.asSignature $ perturbN p $ S.fromSignature signature)
          in isValid `shouldBe` False

      prop "doesn't verify with wrong public key" $
        \alice bob (Message msg) ->
          let signature = S.sign (secretKey alice) msg
              isValid = S.verify (publicKey bob) msg signature
          in isValid `shouldBe` False

  describe "byte sizes" $ do

    it "has matching type-level and value-level sizes" $ do
      asNum publicKeyBytes `shouldBe` (publicKeySize :: Int)
      asNum secretKeyBytes `shouldBe` (secretKeySize :: Int)
      asNum keypairBytes   `shouldBe` (keypairSize :: Int)
      asNum signatureBytes `shouldBe` (signatureSize :: Int)
      asNum seedBytes      `shouldBe` (seedSize :: Int)
