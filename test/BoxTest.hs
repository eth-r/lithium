{-# LANGUAGE OverloadedStrings #-}
module BoxTest (boxSpec) where

import Test.Hspec.QuickCheck
import Test.Tasty.Hspec
import Test.QuickCheck.Arbitrary
import Test.QuickCheck.Property

import Crypto.Lithium.Box as S
import Crypto.Lithium.Unsafe.Box as U
import Crypto.Lithium.Unsafe.Types


import Control.Monad.IO.Class
import Data.ByteArray (Bytes)
import qualified Data.ByteArray as B
import Data.ByteString.Base16
import Data.ByteString (ByteString)

boxSpec :: Spec
boxSpec = parallel $ do
  describe "box" $ do

    it "initializes" $ do
      x <- S.newKeypair
      y <- S.newKeypair
      publicKey x `shouldNotBe` publicKey y

    it "works" $ do
      alice <- S.newKeypair
      bob <- S.newKeypair
      let message = "hello Lithium" :: ByteString
      ciphertext <- S.box (publicKey bob) (secretKey alice) message
      let result = S.openBox (publicKey alice) (secretKey bob)
            (ciphertext :: S.Box ByteString ByteString)
      result `shouldBe` Just message

    it "has matching type-level and value-level sizes" $ do
      asNum publicKeyBytes `shouldBe` (publicKeySize :: Int)
      asNum secretKeyBytes `shouldBe` (secretKeySize :: Int)
      asNum macBytes       `shouldBe` (macSize :: Int)
      asNum nonceBytes     `shouldBe` (nonceSize :: Int)
      asNum seedBytes      `shouldBe` (seedSize :: Int)
      asNum sharedKeyBytes `shouldBe` (sharedKeySize :: Int)
      asNum tagBytes       `shouldBe` (tagSize :: Int)
