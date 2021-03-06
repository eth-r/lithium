{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module TestUtils where

import Crypto.Lithium.Unsafe.Types
import Data.ByteArray.Sized as Sized

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Data.ByteArray as B
import Data.ByteString as BS

import           Control.Monad           (replicateM)

instance Arbitrary ByteString where
  arbitrary = BS.pack <$> arbitrary

instance (KnownNat l, ByteArray b) => Arbitrary (Sized l b) where
  arbitrary = Sized.coerce . B.pack <$> vector (theNat @l)

instance Arbitrary a => Arbitrary (Secret a) where
  arbitrary = Conceal <$> arbitrary

newtype Perturb = Perturb ByteString deriving (Eq, Show, Ord, Monoid, ByteArray, ByteArrayAccess)

newtype PerturbN l = PerturbN (Sized l ByteString) deriving (Eq, Show, Ord)

newtype Message = Message ByteString deriving (Eq, Show, Ord, Monoid)
newtype MessageN = MessageN (BytesN 32) deriving (Eq, Show, Ord)
newtype SecretMessageN = SecretMessageN (SecretN 32) deriving (Eq, Show, Ord)

instance Arbitrary Message where
  arbitrary = Message . BS.cons 1 <$> arbitrary

instance Arbitrary MessageN where
  arbitrary = MessageN <$> arbitrary

instance Arbitrary SecretMessageN where
  arbitrary = SecretMessageN <$> arbitrary

valueOf :: KnownNat n => proxy n -> Int
valueOf = fromIntegral . natVal

perturb :: forall a. ByteArray a => Perturb -> a -> a
perturb (Perturb with) target =
  let diff = B.length target - BS.length with
      padded = B.append with $ B.replicate diff 0
  in B.xor target (B.convert padded :: a)

perturbN :: forall a l. (KnownNat l, ByteArray a) => PerturbN l -> Sized l a -> Sized l a
perturbN (PerturbN with) target = Sized.xor target $ Sized.convert with

instance Arbitrary Perturb where
  arbitrary = do
    base <- arbitrary
    let res = if B.all (== 0) base
          then BS.cons 1 base
          else base
    pure $ Perturb res

instance (KnownNat l) => Arbitrary (PerturbN l) where
  arbitrary = do
    base <- arbitrary
    let res = if Sized.allZeros base
          then Sized.coerce $ B.cons 1 $ B.drop 1 $ unSized base
          else base
    pure $ PerturbN res

noCollisions :: (Show a, Eq a) => (ByteString -> a) -> Property
noCollisions f =
  property $ \b1 b2 -> b1 /= b2 ==>
  f b1 `shouldNotBe` f b2


roundtrips :: (Eq a, Show a, Arbitrary a) => String -> (b -> Maybe a) -> (a -> b) -> Spec
roundtrips name f g =
  prop (name ++ " roundtrips") $ \m -> f (g m) `shouldBe` Just m

encodingRoundtrips :: (Eq a, Show a, Arbitrary a) => String -> (ByteString -> Maybe a) -> (a -> ByteString) -> Spec
encodingRoundtrips name f g =
  prop ("(as" ++ name ++ " . from" ++ name ++ ") roundtrips") $ \m -> f (g m) `shouldBe` Just m

noPerturbedRoundtrip :: (Eq a, Show a, ByteArray b) => (a -> b) -> (b -> Maybe a) -> a -> Perturb -> Expectation
noPerturbedRoundtrip f g m p =
  g (perturb p $ f m) `shouldBe` Nothing
