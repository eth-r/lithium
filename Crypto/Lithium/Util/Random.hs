{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module Crypto.Lithium.Util.Random
  ( randomBytes
  , randomBytesN
  , randomSecretN
  , randomNumber
  ) where

import Data.ByteArray as B
import Data.ByteArray.Sized as Sized
import Foundation

import Crypto.Lithium.Unsafe.Types

import Crypto.Lithium.Internal.Random

{-|
Use Libsodium to generate random byte array
-}
randomBytes :: ByteArray ba
            => Int -> IO ba
randomBytes n = do
  (_err, ptr) <- B.allocRet n $ \p ->
    sodium_randombytes p (fromIntegral n)
  return ptr

randomNumber :: Word32 -> IO Word32
randomNumber upto = do
  number <- sodium_randomnumber $ fromIntegral upto
  return $ fromIntegral number

randomSecretN :: forall n. KnownNat n => IO (SecretN n)
randomSecretN = do
  bs <- randomBytes (theNat @n) :: IO ScrubbedBytes
  return $ coerceConcealN bs

randomBytesN :: forall n. KnownNat n => IO (BytesN n)
randomBytesN = Sized.coerce <$> randomBytes (theNat @n)
