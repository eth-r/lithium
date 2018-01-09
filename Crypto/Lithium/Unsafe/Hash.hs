{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.Hash
Description : Cryptographic hashing made easy
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Hash
  ( Key
  , asKey
  , fromKey

  , Digest
  , asDigest
  , fromDigest

  , newKey
  , genericHash

  , MinDigestBytes
  , minDigestBytes
  , minDigestSize

  , MaxDigestBytes
  , maxDigestBytes
  , maxDigestSize

  , DigestBytes
  , digestBytes
  , digestSize

  , MinKeyBytes
  , minKeyBytes
  , minKeySize

  , MaxKeyBytes
  , maxKeyBytes
  , maxKeySize

  , KeyBytes
  , keyBytes
  , keySize
  ) where

import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Internal.Hash as I
import Crypto.Lithium.Unsafe.Types

import Foundation
import Control.DeepSeq
import Data.ByteArray as B


newtype Key (n :: Nat) = Key (SecretN n) deriving (Eq, Show, NFData)

asKey :: Between MinKeyBytes MaxKeyBytes n
      => SecretN n -> Key n
asKey = Key

fromKey :: Between MinKeyBytes MaxKeyBytes n
        => Key n -> SecretN n
fromKey (Key k) = k


newtype Digest (n :: Nat) = Digest (BytesN n) deriving (Eq, Show, NFData)

asDigest :: Between MinDigestBytes MaxDigestBytes n
         => BytesN n -> Digest n
asDigest = Digest

fromDigest :: Between MinDigestBytes MaxDigestBytes n
           => Digest n -> BytesN n
fromDigest (Digest d) = d


newKey :: forall n.
          ( Between MinKeyBytes MaxKeyBytes n )
       => IO (Key n)
newKey = withLithium $ Key <$> randomSecretN

{-

-}
genericHash :: forall a n k.
               ( ByteArrayAccess a
               , Between MinDigestBytes MaxDigestBytes n
               , KnownNat k
               )
            => Maybe (Key k) -> a -> Digest n
genericHash key m = withLithium $
  let len = ByteSize :: ByteSize n
      hashLength = asNum len
  in case key of

    Nothing ->
      let (_e, result) = unsafePerformIO $
            allocRetN $ \ph ->
            withByteArray m $ \pm ->
            sodium_generichash ph hashLength
                               pm (fromIntegral $ B.length m)
                               nullPtr 0
      in Digest result

    Just (Key k) ->
      let (_e, result) = unsafePerformIO $
            allocRetN $ \ph ->
            withSecret k $ \pk ->
            withByteArray m $ \pm ->
            sodium_generichash ph hashLength
                               pm (fromIntegral $ B.length m)
                               pk (fromIntegral $ secretLengthN k)
      in Digest result

-- hashSaltPersonal :: forall a n k.
--                     ( ByteArrayAccess a
--                     , Between MinDigestBytes MaxDigestBytes n
--                     )
--                  => a -> Maybe (Key k) -> Maybe a -> Maybe a -> Digest n

type MinDigestBytes = 16
minDigestBytes :: ByteSize MinDigestBytes
minDigestBytes = ByteSize

minDigestSize :: Int
minDigestSize = fromIntegral sodium_generichash_bytes_min

type MaxDigestBytes = 64
maxDigestBytes :: ByteSize MaxDigestBytes
maxDigestBytes = ByteSize

maxDigestSize :: Int
maxDigestSize = fromIntegral sodium_generichash_bytes_max

type DigestBytes = 32
digestBytes :: ByteSize DigestBytes
digestBytes = ByteSize

digestSize :: Int
digestSize = fromIntegral sodium_generichash_bytes

type MinKeyBytes = 16
minKeyBytes :: ByteSize MinKeyBytes
minKeyBytes = ByteSize

minKeySize :: Int
minKeySize = fromIntegral sodium_generichash_keybytes_min

type MaxKeyBytes = 64
maxKeyBytes :: ByteSize MaxKeyBytes
maxKeyBytes = ByteSize

maxKeySize :: Int
maxKeySize = fromIntegral sodium_generichash_keybytes_max

type KeyBytes = 32
keyBytes :: ByteSize KeyBytes
keyBytes = ByteSize

keySize :: Int
keySize = fromIntegral sodium_generichash_keybytes
