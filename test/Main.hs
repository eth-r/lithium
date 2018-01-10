{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DataKinds #-}
-- {-# LANGUAGE NoImplicitPrelude #-}
-- import Foundation
-- Tasty makes it easy to test your code. It is a test framework that can
-- combine many different types of tests into one suite. See its website for
-- help: <http://documentup.com/feuerbach/tasty>.
import qualified Test.Tasty
-- Hspec is one of the providers for Tasty. It provides a nice syntax for
-- writing tests. Its website has more info: <https://hspec.github.io>.
import Test.Tasty.Hspec
import Test.Hspec.QuickCheck

import AeadTest
import BoxTest
import HashTest
import PasswordTest
import SecretBoxTest
import SignTest

main :: IO ()
main = do
  test <- testSpec "lithium" spec
  Test.Tasty.defaultMain test

spec :: Spec
spec = parallel $ modifyMaxSuccess (const 1000) $ do
  describe "Aead" aeadSpec
  describe "Box" boxSpec
  -- describe "Hash" hashSpec
  describe "Password" passwordSpec
  describe "SecretBox" secretBoxSpec
  describe "Sign" signSpec
