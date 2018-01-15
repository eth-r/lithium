{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Util.Secret
Description : Sized byte arrays
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Util.Secret
  ( Secret(..)
  , conceal

  , Plaintext(..)

  , BytesN

  , SecretN
  , concealN
  , revealN

  , maybeConcealN
  , coerceConcealN

  , emptySecretN
  , allocSecretN
  , copySecretN
  , copySecretN'
  , withSecret
  , secretLengthN

  , splitSecretN
  ) where

import Foundation
import Basement.Compat.Base
import Control.DeepSeq

import Data.ByteArray as B
import Data.ByteString as BS

import Crypto.Lithium.Util.Nat
import Crypto.Lithium.Util.Sized


{-|
Opaque type for secrets

Used to prevent secret data from being handled insecurely
-}
newtype Secret a = Conceal { reveal :: a } deriving (Eq, Ord, NFData)

conceal :: a -> Secret a
conceal = Conceal

instance Show (Secret a) where
  show _ = "<secret>"

instance Functor Secret where
  fmap f (Conceal a) = Conceal (f a)

instance Applicative Secret where
  pure = Conceal
  (Conceal f) <*> (Conceal a) = Conceal $ f a

instance Monad Secret where
  (Conceal a) >>= f = f a

instance Monoid a => Monoid (Secret a) where
  mempty = Conceal mempty
  mappend (Conceal a) (Conceal b) = Conceal $ a <> b

-- newtype SecretT m a = SecretT { runSecretT :: m (Secret a) }

-- instance Functor m => Functor (SecretT m) where
--   fmap f = SecretT . fmap (fmap f) . runSecretT

-- instance Applicative m => Applicative (SecretT m) where
--   pure = SecretT . pure . Conceal
--   f <*> x = SecretT $ liftA2 (<*>) (runSecretT f) (runSecretT x)

-- instance Monad m => Monad (SecretT m) where
--   return = SecretT . return . Conceal
--   x >>= f = SecretT $ do x' <- runSecretT x
--                          runSecretT $ f $ reveal x'

-- instance MonadIO m => MonadIO (SecretT m) where
--   liftIO = SecretT . fmap Conceal . liftIO

-- instance MonadTrans SecretT where
--   lift = SecretT . liftM Secret

{-|
Class representing types that can be encoded and decoded for use in
cryptographic operations

Many operations store the type of the plaintext as a phantom type, and
encode and decode transparently for maximum convenience
-}
class Plaintext p where
  toPlaintext :: ByteArrayAccess a => a -> Maybe p
  default toPlaintext :: (ByteOp a p) => a -> Maybe p
  toPlaintext = Just . B.convert

  fromPlaintext :: ByteArray a => p -> a
  default fromPlaintext :: ByteOp p a => p -> a
  fromPlaintext = B.convert

  withPlaintext :: p -> (Ptr p' -> IO e) -> IO e
  default withPlaintext :: ByteArrayAccess p => p -> (Ptr p' -> IO e) -> IO e
  withPlaintext = B.withByteArray

  plaintextLength :: p -> Int
  default plaintextLength :: ByteArrayAccess p => p -> Int
  plaintextLength = B.length

instance Plaintext Bytes

instance Plaintext ScrubbedBytes

instance Plaintext ByteString

instance (ByteArray b, Plaintext b, KnownNat n) => Plaintext (N n b) where
  toPlaintext = maybeToN . B.convert
  fromPlaintext = B.convert . fromN


type SecretN (n :: Nat) = Secret (N n ScrubbedBytes)
type BytesN (n :: Nat) = N n Bytes


{-|
Empty secret sized byte array
-}
emptySecretN :: SecretN 0
emptySecretN = Conceal $ emptyN

{-|
Allocate and initialize a sized secret byte array
-}
allocSecretN :: forall l p e. KnownNat l => (Ptr p -> IO e) -> IO (e, SecretN l)
allocSecretN f = do
  (e, ns) <- allocRetN f
  return (e, Conceal ns)

copySecretN :: KnownNat l => SecretN l -> (Ptr p -> IO ()) -> IO (SecretN l)
copySecretN (Conceal bs) f = Conceal <$> copyN bs f

copySecretN' :: KnownNat l => SecretN l -> (Ptr p -> IO e) -> IO (e, SecretN l)
copySecretN' (Conceal bs) f = do
  (e, bs') <- copyN' bs f
  return (e, Conceal bs')

secretLengthN :: forall l. SecretN l -> Int
secretLengthN (Conceal s) = B.length s

{-|
Use the contents of a secret like 'withByteArray'
-}
-- NOTE: exposes contents
withSecret :: ByteArrayAccess ba => Secret ba -> (Ptr a -> IO x) -> IO x
withSecret (Conceal bs) = withByteArray bs

{-|
Expose the contents of a secret byte array
-}
-- NOTE: exposes contents
revealN :: forall ba n. (ByteArray ba, KnownNat n) => SecretN n -> N n ba
revealN = convertN . reveal

{-|
Make a sized byte array secret
-}
concealN :: forall ba n. (ByteArrayAccess ba, KnownNat n) => N n ba -> SecretN n
concealN = Conceal . convertN

{-|
Try converting an unsized byte array into a sized secret byte array
-}
maybeConcealN :: forall n. (KnownNat n) => ScrubbedBytes -> Maybe (SecretN n)
maybeConcealN bs = do
  n <- maybeToN bs
  return $ Conceal n

{-|
Coerce an unsized byte array into a secret sized byte array

Like 'coerceToN', will truncate longer arrays and expand shorter arrays
-}
coerceConcealN :: forall n. (KnownNat n) => ScrubbedBytes -> SecretN n
coerceConcealN = Conceal . coerceToN

{-|
Split a secret byte array to two secret byte arrays
-}
splitSecretN :: KnownNats x y => SecretN (x + y) -> (SecretN x, SecretN y)
splitSecretN (Conceal a) =
  let (b, c) = splitN a
  in (Conceal b, Conceal c)
