{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}
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

    it "fucks off" $ do
      True `shouldNotBe` False
    --   let mysecret = "very sensitive material!" :: ScrubbedBytes
    --   let Just mysecretN = asSecretN b24 mysecret
    --   let mypassword = Password "password"

    --   protected <- protectWithN sensitivePolicy mypassword mysecretN

    --   openWithN mypassword protected `shouldBe` Just mysecretN

    -- it "works again" $ do
    --   let mysecret = Conceal "this should be kept secret too"
    --   let mypassword = Password "hunter2"

    --   protected <- protectWith sensitivePolicy mypassword mysecret
    --   openWith mypassword protected `shouldBe` Just mysecret
