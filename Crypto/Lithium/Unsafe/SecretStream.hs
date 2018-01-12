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
Description : SECRETSTREAM made easy
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.SecretStream
  ( Key
  , asKey
  , fromKey
  , newKey

  , Header
  , asHeader
  , fromHeader

  , Tag(..)

  , State
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

import Control.DeepSeq
import Foundation hiding (splitAt)

data Tag = Message
         | Push
         | Rekey
         | Final
         deriving (Show, Eq, Enum)

newtype Key = Key (SecretN KeyBytes) deriving (Show, Eq, NFData)

asKey :: SecretN KeyBytes -> Key
asKey = Key

fromKey :: Key -> SecretN KeyBytes
fromKey (Key k) = k

newtype Header = Header (BytesN HeaderBytes) deriving (Show, Eq, NFData, ByteArrayAccess)

asHeader :: BytesN HeaderBytes -> Header
asHeader = Header

fromHeader :: Header -> BytesN HeaderBytes
fromHeader (Header n) = n

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
        allocRetN $ \pheader ->
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
        allocRet clen $ \pctext ->
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
        allocRet mlen $ \pmessage ->
        allocRet 1 $ \ptag ->
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

secretStreamRekey :: State -> State
secretStreamRekey (State state) = withLithium . State . unsafePerformIO $
  copySecretN state sodium_secretstream_rekey

type KeyBytes = 32
keyBytes :: ByteSize KeyBytes
keyBytes = ByteSize

keySize :: Int
keySize = fromIntegral sodium_secretstream_keybytes

type MacBytes = 16
macBytes :: ByteSize MacBytes
macBytes = ByteSize

macSize :: Int
macSize = fromIntegral sodium_secretstream_macbytes

type HeaderBytes = 24
headerBytes :: ByteSize HeaderBytes
headerBytes = ByteSize

headerSize :: Int
headerSize = fromIntegral sodium_secretstream_headerbytes

type StateBytes = 64
stateBytes :: ByteSize StateBytes
stateBytes = ByteSize

stateSize :: Int
stateSize = fromIntegral sodium_secretstream_statebytes
