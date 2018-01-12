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
  ( Key
  , asKey
  , fromKey

  , Digest
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
import Data.Foldable as F

type KeySized n = Between MinKeyBytes MaxKeyBytes n

newtype Key (n :: Nat) = Key (SecretN n) deriving (Eq, Show, NFData)

asKey :: KeySized n => SecretN n -> Key n
asKey = Key

fromKey :: KeySized n => Key n -> SecretN n
fromKey (Key k) = k

type DigestSized n = Between MinDigestBytes MaxDigestBytes n

newtype Digest (n :: Nat) = Digest (BytesN n) deriving (Eq, Show, Ord, NFData, ByteArrayAccess)

instance DigestSized n => Plaintext (Digest n) where
  toPlaintext bs = asDigest <$> toPlaintext bs
  fromPlaintext (Digest d) = fromPlaintext d
  withPlaintext (Digest d) = withPlaintext d
  plaintextLength (Digest d) = plaintextLength d

asDigest :: DigestSized n => BytesN n -> Digest n
asDigest = Digest

fromDigest :: DigestSized n => Digest n -> BytesN n
fromDigest (Digest d) = d


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
      hashLength = asNum (ByteSize @n)

      (_e, result) = unsafePerformIO $
        allocRetN $ \pdigest ->
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
  let outLen = asNum (ByteSize @n)
      (_e, result) = unsafePerformIO $
        allocRetN $ \pstate ->
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
        copyN state $ \pstate' ->
        withByteArray chunk $ \pchunk ->
        sodium_generichash_update pstate' pchunk clen >> return ()
  in (State state')

genericHashFinal :: forall n. DigestSized n => State n -> Digest n
genericHashFinal (State state) = withLithium $
  let outLen = asNum (ByteSize @n)
      (_state', digest) = unsafePerformIO $
        allocRetN $ \pdigest ->
        copyN state $ \pstate' ->
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
