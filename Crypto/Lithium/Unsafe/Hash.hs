{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.Hash
Description : Blake2b hash
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Hash
  ( KeySized
  , Key(..)
  , asKey
  , fromKey

  , DigestSized
  , Digest(..)
  , asDigest
  , fromDigest

  , newKey

  , genericHash

  , genericHashInit
  , genericHashUpdate
  , genericHashFinal

  , streamingHash

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

  , StateBytes
  , stateBytes
  , stateSize
  ) where

import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Internal.Hash as I
import Crypto.Lithium.Unsafe.Types

import Foundation hiding (Foldable)
import Control.DeepSeq
import Data.ByteArray as B
import Data.ByteArray.Sized as Sized
import Data.Foldable as F

type KeySized n = Between MinKeyBytes MaxKeyBytes n

newtype Key (n :: Nat) = Key
  { unKey :: SecretN n } deriving (Eq, Show, NFData)

asKey :: KeySized n => Decoder (Key n)
asKey = decodeSecret Key

fromKey :: KeySized n => Encoder (Key n)
fromKey = encodeSecret unKey

type DigestSized n = Between MinDigestBytes MaxDigestBytes n

newtype Digest (n :: Nat) = Digest
  { unDigest :: BytesN n } deriving (Eq, Show, Ord, NFData, ByteArrayAccess)

instance DigestSized n => Plaintext (Digest n) where
  toPlaintext bs = Digest <$> toPlaintext bs
  fromPlaintext (Digest d) = fromPlaintext d
  withPlaintext (Digest d) = withPlaintext d
  plaintextLength (Digest d) = plaintextLength d

asDigest :: DigestSized n => Decoder (Digest n)
asDigest = decodeWith Digest

fromDigest :: DigestSized n => Encoder (Digest n)
fromDigest = encodeWith unDigest


newKey :: KeySized n => IO (Key n)
newKey = Key <$> randomSecretN

{-

-}
genericHash :: forall a n k.
               ( ByteArrayAccess a
               , DigestSized n
               )
            => Maybe (Key k) -> a -> Digest n
genericHash key m = withLithium $
  let mlen = fromIntegral $ B.length m
      hashLength = theNat @n

      (_e, result) = unsafePerformIO $
        Sized.allocRet $ \pdigest ->
        withByteArray m $ \pmessage ->
        case key of
          Nothing ->
            sodium_generichash pdigest hashLength
                               pmessage mlen
                               nullPtr 0
          Just (Key k) ->
            withSecret k $ \pkey ->
            sodium_generichash pdigest hashLength
                               pmessage mlen
                               pkey (fromIntegral $ secretLengthN k)
  in (Digest result)

newtype State (n :: Nat) = State (BytesN StateBytes) deriving (Eq, Ord, ByteArrayAccess)

genericHashInit :: forall n k. DigestSized n => Maybe (Key k) -> State n
genericHashInit key = withLithium $
  let outLen = theNat @n
      (_e, result) = unsafePerformIO $
        Sized.allocRet $ \pstate ->
        case key of
          Nothing ->
            sodium_generichash_init pstate
                                    nullPtr 0
                                    outLen
          Just (Key k) ->
            withSecret k $ \pkey ->
            sodium_generichash_init pstate
                                    pkey (fromIntegral $ secretLengthN k)
                                    outLen
  in (State result)

genericHashUpdate :: forall n a. ByteArrayAccess a => State n -> a -> State n
genericHashUpdate (State state) chunk = withLithium $
  let clen = fromIntegral $ B.length chunk
      state' = unsafePerformIO $
        Sized.copy state $ \pstate' ->
        withByteArray chunk $ \pchunk ->
        sodium_generichash_update pstate' pchunk clen >> return ()
  in (State state')

genericHashFinal :: forall n. DigestSized n => State n -> Digest n
genericHashFinal (State state) = withLithium $
  let outLen = theNat @n
      (_state', digest) = unsafePerformIO $
        Sized.allocRet $ \pdigest ->
        Sized.copy state $ \pstate' ->
        sodium_generichash_final pstate' pdigest outLen >> return ()
  in (Digest digest)

streamingHash :: (Foldable t, DigestSized n, ByteArrayAccess a) => Maybe (Key k) -> t a -> Digest n
streamingHash key t =
  let state = genericHashInit key
  in genericHashFinal $ F.foldl' genericHashUpdate state t

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

type StateBytes = 384
stateBytes :: ByteSize StateBytes
stateBytes = ByteSize

stateSize :: Int
stateSize = fromIntegral sodium_generichash_statebytes
