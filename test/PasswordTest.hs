{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeApplications #-}
module PasswordTest (passwordSpec) where

import Test.Hspec.QuickCheck
import Test.Hspec
import Test.QuickCheck.Arbitrary
import Test.QuickCheck.Gen
import Test.QuickCheck.Property

import Crypto.Lithium.Random
import Crypto.Lithium.Password as S
import Crypto.Lithium.Unsafe.Password as U
import Crypto.Lithium.Unsafe.Types

import Control.Monad.IO.Class
import Data.ByteArray (Bytes, ScrubbedBytes)
import qualified Data.ByteArray as B
import Data.ByteString (ByteString)

import Data.Maybe (fromJust)

import TestUtils

instance Arbitrary Policy where
  arbitrary = Policy <$> arbitrary <*> arbitrary <*> pure defaultAlgorithm

instance Arbitrary Opslimit where
  arbitrary = fromJust . opslimit <$> choose (getOpslimit minOpslimit, getOpslimit maxOpslimit)

instance Arbitrary Memlimit where
  arbitrary = fromJust . memlimit <$> choose (getMemlimit minMemlimit, getMemlimit maxMemlimit)

instance Arbitrary Salt where
  arbitrary = Salt <$> arbitrary

passwordSpec :: Spec
passwordSpec = parallel $ do
  describe "Password" $ do

    context "Password storage" $ do

      describe "storePassword" $ do

        it "stores passwords" $ do
          str1 <- S.storePassword interactivePolicy (Password "hunter2")
          str2 <- S.storePassword interactivePolicy (Password "password")

          str1 `shouldNotBe` str2

        it "generates random salts" $ do
          str1 <- S.storePassword interactivePolicy (Password "hunter2")
          str2 <- S.storePassword interactivePolicy (Password "hunter2")

          str1 `shouldNotBe` str2

      describe "verifyPassword" $ do

        it "accepts the correct password" $ do
          pwstr <- S.storePassword interactivePolicy (Password "hunter2")
          S.verifyPassword pwstr (Password "hunter2") `shouldBe` True

        it "rejects incorrect passwords" $ do
          pwstr <- S.storePassword interactivePolicy (Password "hunter2")
          S.verifyPassword pwstr (Password "password") `shouldBe` False

      describe "needsRehash" $ do

        it "checks if password string needs rehashing" $ do
          let oldPolicy = interactivePolicy
          oldstr <- S.storePassword oldPolicy (Password "hunter2")
          let newPolicy = interactivePolicy
                { memPolicy = memlimitModerate }
          newstr <- S.storePassword newPolicy (Password "password")
          S.needsRehash newPolicy oldstr `shouldBe` True
          S.needsRehash newPolicy newstr `shouldBe` False

  describe "Unsafe.Password" $ do

    context "Password protection" $ do

      prop "packing roundtrips" $
        \(Message secret) salt policy ->
          unpackProtected (packProtected secret salt policy)
          `shouldBe` Just (secret, salt, policy)

      it "protects secrets of unknown length" $ do
        let mysecret = "this should be kept secret too" :: ByteString
        let mypassword = "hunter2" :: ScrubbedBytes

        protected <- passwordProtect interactivePolicy mypassword mysecret
        passwordOpen mypassword protected `shouldBe` Just mysecret

      it "protects in a house" $ do
        let mysecret = B.convert ("in this house we use good passwords" :: ByteString)
        let mypassword = "correct horse battery staple" :: ScrubbedBytes

        protected <- passwordProtect sensitivePolicy mypassword (mysecret :: Bytes)
        passwordOpen mypassword protected `shouldBe` Just mysecret

      it "protects with a mouse" $ do
        let mysecret = "squeak" :: ByteString
        let mypassword = "a mouse" :: ScrubbedBytes

        protected <- passwordProtect moderatePolicy mypassword mysecret
        passwordOpen mypassword protected `shouldBe` Just mysecret

      it "rejects invalid passwords" $ do
        let mysecret = "you will never see this again" :: ByteString
        let mypassword = "foo" :: ScrubbedBytes
        let falseGuess = "bar" :: ScrubbedBytes

        protected <- passwordProtect interactivePolicy mypassword mysecret
        passwordOpen falseGuess protected `shouldBe` Nothing

  describe "byte sizes" $ do

    it "has matching type-level and value-level sizes" $ do
      (fromIntegral . natVal) saltBytes `shouldBe` saltSize
      (fromIntegral . natVal) U.tagBytes `shouldBe` U.tagSize
      theNat @PasswordStringBytes `shouldBe` passwordStringSize
