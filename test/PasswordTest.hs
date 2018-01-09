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
import Crypto.Lithium.Unsafe.Password as U
import Crypto.Lithium.Unsafe.Types


import Control.Monad.IO.Class
import Data.ByteArray (Bytes, ScrubbedBytes)
import qualified Data.ByteArray as B
import Data.ByteString.Base16
import Data.ByteString (ByteString)

-- instance PasswordProtectable Secret where
--   protect = passwordProtect
--   open = passwordOpen

passwordSpec :: Spec
passwordSpec = parallel $ do
  describe "password" $ do

    it "protects secrets of known length" $ do
      let mysecret = "very sensitive material!" :: ScrubbedBytes
      let mysecretN = conceal $ coerceToN mysecret
      let mypassword = Password "password"

      protected <- protectWithN interactivePolicy mypassword (mysecretN :: SecretN 24)

      openWithN mypassword protected `shouldBe` Just mysecretN

    it "protects secrets of unknown length" $ do
      let mysecret = Conceal "this should be kept secret too" :: Secret ScrubbedBytes
      let mypassword = Password "hunter2"

      protected <- protectWith interactivePolicy mypassword mysecret
      openWith mypassword protected `shouldBe` Just mysecret

    it "protects in a house" $ do
      let mysecret = B.convert ("in this house we use good passwords" :: ByteString)
      let mypassword = Password "correct horse battery staple"

      protected <- protectWith sensitivePolicy mypassword (mysecret :: Bytes)
      openWith mypassword protected `shouldBe` Just mysecret

    it "protects with a mouse" $ do
      let mysecret = "squeak" :: ByteString
      let mypassword = Password "a mouse"

      protected <- protectWith moderatePolicy mypassword mysecret
      openWith mypassword protected `shouldBe` Just mysecret
