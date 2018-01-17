{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.SecretStream
Description : XChaCha20Poly1305 stream encryption
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.SecretStream
  ( Key(..)
  , asKey
  , fromKey
  , newKey

  , Header(..)
  , asHeader
  , fromHeader

  , Tag(..)

  , State(..)
  , asState
  , fromState

  , secretStreamInitPush
  , secretStreamPush

  , secretStreamInitPull
  , secretStreamPull

  , secretStreamRekey

  , KeyBytes
  , keyBytes
  , keySize

  , MacBytes
  , macBytes
  , macSize

  , HeaderBytes
  , headerBytes
  , headerSize

  , StateBytes
  , stateBytes
  , stateSize
  ) where

import Crypto.Lithium.Internal.SecretStream
import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Unsafe.Types

import Data.ByteArray as B
import Data.ByteArray.Sized as Sized

import Control.DeepSeq
import Foundation hiding (splitAt)

{-|
Secretstream message tag
-}
data Tag = Message
         -- ^ Standard tag with no specific meaning
         | Push
         -- ^ Can be used to eg. denote the end of a chunk of related messages
         | Rekey
         -- ^ Switch the stream to a new key
         | Final
         -- ^ End of the stream
         deriving (Show, Eq, Enum)

newtype Key = Key (SecretN KeyBytes) deriving (Show, Eq, NFData)

asKey :: SecretN KeyBytes -> Key
asKey = Key

fromKey :: Key -> SecretN KeyBytes
fromKey (Key k) = k

{-|
Header for initializing a secret stream
-}
newtype Header = Header (BytesN HeaderBytes) deriving (Show, Eq, NFData, ByteArrayAccess)

asHeader :: BytesN HeaderBytes -> Header
asHeader = Header

fromHeader :: Header -> BytesN HeaderBytes
fromHeader (Header n) = n

{-|
Secret stream state, containing the necessary information to derive keys and
encrypt/decrypt+authenticate messages

A single state object should only ever be used once; otherwise leads to nonce
reuse vulnerabilities. This would be a perfect application for linear types if
we had them.
-}
newtype State = State (SecretN StateBytes) deriving (Show, Eq, NFData)

asState :: SecretN StateBytes -> State
asState = State

fromState :: State -> SecretN StateBytes
fromState (State s) = s

{-|
Generate a new 'secretStream' key
-}
newKey :: IO Key
newKey = withLithium $ do
  (_e, k) <-
    allocSecretN $ \pk ->
    sodium_secretstream_keygen pk
  return $ Key k


secretStreamInitPush :: Key -> IO (Header, State)
secretStreamInitPush (Key key) = withLithium $ do

  ((_, header), state) <-
        allocSecretN $ \pstate ->
        Sized.allocRet $ \pheader ->
        withSecret key $ \pkey ->
        sodium_secretstream_init_push pstate
                                      pheader
                                      pkey

  return (Header header, State state)

secretStreamPush :: ByteOps m a c => State -> Tag -> m -> a -> (c, State)
secretStreamPush (State state) tag message aad =
  withLithium $

  let mlen = B.length message
      clen = mlen + macSize
      alen = B.length aad
      ctag = fromIntegral $ fromEnum tag

      (state', ciphertext) = unsafePerformIO $
        B.allocRet clen $ \pctext ->
        copySecretN state $ \pstate' ->
        withByteArray message $ \pmessage ->
        withByteArray aad $ \paad ->
        sodium_secretstream_push pstate'
                                 pctext nullPtr
                                 pmessage (fromIntegral mlen)
                                 paad (fromIntegral alen)
                                 ctag >> return ()

  in (ciphertext, State state')

secretStreamInitPull :: Key -> Header -> Maybe State
secretStreamInitPull (Key key) (Header header) =
  withLithium $

  let (e, state) = unsafePerformIO $
        allocSecretN $ \pstate ->
        withSecret key $ \pkey ->
        withByteArray header $ \pheader ->
        sodium_secretstream_init_pull pstate
                                      pheader
                                      pkey
  in case e of
    0 -> Just (State state)
    _ -> Nothing

secretStreamPull :: ByteOps c a m => State -> c -> a -> Maybe ((Tag, m), State)
secretStreamPull (State state) ciphertext aad =
  withLithium $

  let clen = B.length ciphertext
      mlen = clen - macSize
      alen = B.length aad

      (((e, tag'), message), state') = unsafePerformIO $
        copySecretN' state $ \pstate ->
        B.allocRet mlen $ \pmessage ->
        B.allocRet 1 $ \ptag ->
        withByteArray ciphertext $ \pctext ->
        withByteArray aad $ \paad ->
        sodium_secretstream_pull pstate
                                 pmessage nullPtr ptag
                                 pctext (fromIntegral clen)
                                 paad (fromIntegral alen)
      -- HACK: behold the size of this hack
      tag = toEnum $ fromIntegral $ B.index (tag' :: Bytes) 0
  in case e of
    0 -> Just ((tag, message), State state')
    _ -> Nothing

{-|
Manually rekey the stream
-}
secretStreamRekey :: State -> State
secretStreamRekey (State state) = withLithium . State . unsafePerformIO $
  copySecretN state sodium_secretstream_rekey

-- | Length of a 'Key' as a type-level constant
type KeyBytes = 32
-- | Key length as a proxy value
keyBytes :: ByteSize KeyBytes
keyBytes = ByteSize
-- | Key length as a regular value
keySize :: Int
keySize = fromIntegral sodium_secretstream_keybytes

-- | Secretstream authentication tag size as a type-level constant
type MacBytes = 16
-- | Authentication tag length as a proxy value
macBytes :: ByteSize MacBytes
macBytes = ByteSize
-- | Authentication tag length as a regular value
macSize :: Int
macSize = fromIntegral sodium_secretstream_macbytes

-- | Length of a 'Header' as a type-level constant
type HeaderBytes = 24
-- | Header length as a proxy value
headerBytes :: ByteSize HeaderBytes
headerBytes = ByteSize
-- | Header length as a regular value
headerSize :: Int
headerSize = fromIntegral sodium_secretstream_headerbytes

-- | Length of a secretstream 'State' as a type-level constant
type StateBytes = 64
-- | State length as a proxy value
stateBytes :: ByteSize StateBytes
stateBytes = ByteSize
-- | State length as a regular value
stateSize :: Int
stateSize = fromIntegral sodium_secretstream_statebytes
