{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module PasswordTest (passwordSpec) where

import Test.Hspec.QuickCheck
import Test.Tasty.Hspec
import Test.QuickCheck.Arbitrary
import Test.QuickCheck.Property

import Crypto.Lithium.Random
import Crypto.Lithium.SecretBox as S
import Crypto.Lithium.Password
import Crypto.Lithium.Unsafe.Types

import Control.Monad.IO.Class
import Data.ByteArray (Bytes, ScrubbedBytes)
import qualified Data.ByteArray as B
import Data.ByteString.Base16
import Data.ByteString (ByteString)

passwordSpec :: Spec
passwordSpec = parallel $ do
  describe "Password" $ do

    context "Password storage" $ do

      describe "storePassword" $ do

        it "stores passwords" $ do
          str1 <- storePassword interactivePolicy (Password "hunter2")
          str2 <- storePassword interactivePolicy (Password "password")

          str1 `shouldNotBe` str2

        it "generates random salts" $ do
          str1 <- storePassword interactivePolicy (Password "hunter2")
          str2 <- storePassword interactivePolicy (Password "hunter2")

          str1 `shouldNotBe` str2

      describe "verifyPassword" $ do

        it "accepts the correct password" $ do
          pwstr <- storePassword interactivePolicy (Password "hunter2")
          verifyPassword pwstr (Password "hunter2") `shouldBe` True

        it "rejects incorrect passwords" $ do
          pwstr <- storePassword interactivePolicy (Password "hunter2")
          verifyPassword pwstr (Password "password") `shouldBe` False

      describe "needsRehash" $ do

        it "checks if password string needs rehashing" $ do
          let oldPolicy = interactivePolicy
          oldstr <- storePassword oldPolicy (Password "hunter2")
          let newPolicy = interactivePolicy
                { memPolicy = memlimitModerate }
          newstr <- storePassword newPolicy (Password "password")
          needsRehash newPolicy oldstr `shouldBe` True
          needsRehash newPolicy newstr `shouldBe` False

    -- it "protects secrets of known length" $ do
    --   let mysecret = "very sensitive material!" :: ScrubbedBytes
    --   let mysecretN = conceal $ coerceToN mysecret
    --   let mypassword = Password "password"

    --   protected <- protectWithN interactivePolicy mypassword (mysecretN :: SecretN 24)

    --   openWithN mypassword protected `shouldBe` Just mysecretN

    -- it "protects secrets of unknown length" $ do
    --   let mysecret = Conceal "this should be kept secret too" :: Secret ScrubbedBytes
    --   let mypassword = Password "hunter2"

    --   protected <- protectWith interactivePolicy mypassword mysecret
    --   openWith mypassword protected `shouldBe` Just mysecret

    -- it "protects in a house" $ do
    --   let mysecret = B.convert ("in this house we use good passwords" :: ByteString)
    --   let mypassword = Password "correct horse battery staple"

    --   protected <- protectWith sensitivePolicy mypassword (mysecret :: Bytes)
    --   openWith mypassword protected `shouldBe` Just mysecret

    -- it "protects with a mouse" $ do
    --   let mysecret = "squeak" :: ByteString
    --   let mypassword = Password "a mouse"

    --   protected <- protectWith moderatePolicy mypassword mysecret
    --   openWith mypassword protected `shouldBe` Just mysecret

    -- it "rejects invalid passwords" $ do
    --   let mysecret = Conceal "you will never see this again" :: Secret ByteString
    --   let mypassword = Password "foo"
    --   let falseGuess = Password "bar"

    --   protected <- protectWith interactivePolicy mypassword mysecret
    --   openWith falseGuess protected `shouldBe` Nothing
