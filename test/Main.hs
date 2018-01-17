{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DataKinds #-}
-- {-# LANGUAGE NoImplicitPrelude #-}
-- import Foundation
import Test.Hspec
import Test.Hspec.QuickCheck

import AeadTest
import AuthTest
import BoxTest
import HashTest
import PasswordTest
import SecretBoxTest
import SignTest

main :: IO ()
main = do
  hspec spec

spec :: Spec
spec = parallel $ modifyMaxSuccess (const 1000) $ do
  describe "Aead" aeadSpec
  describe "Auth" authSpec
  describe "Box" boxSpec
  describe "Hash" hashSpec
  describe "Password" passwordSpec
  describe "SecretBox" secretBoxSpec
  describe "Sign" signSpec
