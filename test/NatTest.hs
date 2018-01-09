{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
module NatTest (natSpec) where


import Test.Tasty.Hspec

import Data.ByteArray
import Data.ByteString

import Crypto.Lithium.Unsafe.Types


natSpec :: Spec
natSpec = parallel $ do
  let myBytes = "01234567" :: ByteString

  it "works" $ do

    let myNonSecret8 :: Maybe (N 8 ByteString)
        myNonSecret8 = maybeToN myBytes
    (fromN <$> myNonSecret8) `shouldBe` Just myBytes

  it "works again" $ do
    let my4bytes = Data.ByteArray.take 4 myBytes
    let myNonSecret4 = maybeToN my4bytes
    let accept4 :: N 4 ByteString -> ByteString
        accept4 = fromN
    (accept4 <$> myNonSecret4) `shouldBe` Just my4bytes
