{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# OPTIONS_HADDOCK hide #-}
{-|
Module      : Crypto.Lithium.Unsafe.OnetimeAuth
Description : Poly1305
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.OnetimeAuth
  ( Key(..)
  , asKey
  , fromKey
  , newKey

  , Mac(..)
  , asMac
  , fromMac

  , auth
  , verify

  , State(..)
  , asState
  , fromState

  , authInit
  , authUpdate
  , authFinal

  , streamingAuth

  , KeyBytes
  , keyBytes
  , keySize

  , MacBytes
  , macBytes
  , macSize

  , StateBytes
  , stateBytes
  , stateSize
  ) where

import Crypto.Lithium.Internal.OnetimeAuth
import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Unsafe.Types

import Data.ByteArray as B

import Control.DeepSeq
import Foundation hiding (Foldable)
import Data.Foldable as F

newtype Key = Key
  { unKey :: SecretN KeyBytes } deriving (Show, Eq, NFData)

asKey :: Decoder Key
asKey = decodeSecret Key

fromKey :: Encoder Key
fromKey = encodeSecret unKey

newtype Mac = Mac
  { unMac :: BytesN MacBytes } deriving (Show, Ord, Eq, ByteArrayAccess, NFData)

asMac :: Decoder Mac
asMac = decodeWith Mac

fromMac :: Encoder Mac
fromMac = encodeWith unMac

newtype State = State
  { unState :: SecretN StateBytes } deriving (Show, Eq, NFData)

asState :: Decoder State
asState = decodeSecret State

fromState :: Encoder State
fromState = encodeSecret unState

{-|
Generate a new 'auth' key
-}
newKey :: IO Key
newKey = withLithium $ do
  (_e, k) <-
    allocSecretN $ \pkey ->
    sodium_onetimeauth_keygen pkey
  return $ Key k

{-|
Calculate the authentication tag of a message
-}
auth :: ByteArrayAccess m => Key -> m -> Mac
auth (Key key) message =
  withLithium $

  let mlen = fromIntegral $ B.length message
      -- ^ Length of message

      (_e, mac) = unsafePerformIO $
        allocRetN $ \pmac ->
        withSecret key $ \pkey ->
        withByteArray message $ \pmessage ->
        sodium_onetimeauth pmac
                           pmessage mlen
                           pkey
  in (Mac mac)

{-|
Verify the authentication tag of a message
-}
verify :: ByteArrayAccess m => Key -> Mac -> m -> Bool
verify (Key key) (Mac mac) message =
  withLithium $ -- Ensure Sodium is initialized

  let mlen = fromIntegral $ B.length message

      e = unsafePerformIO $
        withByteArray mac $ \pmac ->
        withByteArray message $ \pmessage ->
        withSecret key $ \pkey ->
        sodium_onetimeauth_verify pmac
                                  pmessage mlen
                                  pkey
  in e == 0

authInit :: Key -> State
authInit (Key key) = withLithium $
  let (_e, state) = unsafePerformIO $
        allocSecretN $ \pstate ->
        withSecret key $ \pkey ->
        sodium_onetimeauth_init pstate
                                pkey
  in (State state)

authUpdate :: forall a. ByteArrayAccess a => State -> a -> State
authUpdate (State state) chunk =
  withLithium $
  let clen = fromIntegral $ B.length chunk
      state' = unsafePerformIO $
        copySecretN state $ \pstate' ->
        withByteArray chunk $ \pchunk ->
        sodium_onetimeauth_update pstate'
                                  pchunk clen
        >> return ()
  in (State state')

authFinal :: State -> Mac
authFinal (State state) = withLithium $
  let (_state', mac) = unsafePerformIO $
        allocRetN $ \pmac ->
        copySecretN state $ \pstate' ->
        sodium_onetimeauth_final pstate'
                                 pmac
        >> return ()
  in (Mac mac)

streamingAuth :: (Foldable t, ByteArrayAccess a) => Key -> t a -> Mac
streamingAuth key t =
  let state = authInit key
  in authFinal $ F.foldl' authUpdate state t

-- | Length of a 'Key' as a type-level constant
type KeyBytes = 32
-- | Key length as a proxy value
keyBytes :: ByteSize KeyBytes
keyBytes = ByteSize
-- | Key length as a regular value
keySize :: Int
keySize = fromIntegral sodium_onetimeauth_keybytes

-- | Length of a 'Mac' as a type-level constant
type MacBytes = 16
-- | Mac length as a proxy value
macBytes :: ByteSize MacBytes
macBytes = ByteSize
-- | Mac length as a regular value
macSize :: Int
macSize = fromIntegral sodium_onetimeauth_bytes

-- | Length of a 'State' as a type-level constant
type StateBytes = 256
-- | State length as a proxy value
stateBytes :: ByteSize StateBytes
stateBytes = ByteSize
-- | State length as a regular value
stateSize :: Int
stateSize = fromIntegral sodium_onetimeauth_statebytes
