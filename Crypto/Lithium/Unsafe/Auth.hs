{-# LANGUAGE TypeFamilies #-}
-- {-# LANGUAGE FlexibleContexts #-}
{-# OPTIONS_HADDOCK hide #-}
{-|
Module      : Crypto.Lithium.Unsafe.Auth
Description : HMAC-SHA512-256
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Auth
  ( Key(..)
  , asKey
  , fromKey
  , newKey

  , Mac(..)
  , asMac
  , fromMac

  , auth
  , verify

  , KeyBytes
  , keyBytes
  , keySize

  , MacBytes
  , macBytes
  , macSize
  ) where

import Crypto.Lithium.Internal.Auth
import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Unsafe.Types

import Data.ByteArray as B
import Data.ByteArray.Sized as Sized

import Control.DeepSeq
import Foundation

newtype Key = Key
  { unKey :: SecretN KeyBytes } deriving (Show, Eq, NFData)

asKey :: Decoder Key
asKey = decodeSecret Key

fromKey :: Encoder Key
fromKey = encodeSecret unKey

newtype Mac = Mac
  { unMac :: BytesN MacBytes } deriving (Show, Eq, Ord, ByteArrayAccess, NFData)

asMac :: Decoder Mac
asMac = decodeWith Mac

fromMac :: Encoder Mac
fromMac = encodeWith unMac

{-|
Generate a new 'auth' key
-}
newKey :: IO Key
newKey = withLithium $ do
  (_e, k) <-
    allocSecretN $ \pkey ->
    sodium_auth_keygen pkey
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
        Sized.allocRet $ \pmac ->
        withSecret key $ \pkey ->
        withByteArray message $ \pmessage ->
        sodium_auth pmac
                    pmessage mlen
                    pkey
  in Mac mac

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
        sodium_auth_verify pmac
                           pmessage mlen
                           pkey
  in e == 0

-- | Length of a 'Key' as a type-level constant
type KeyBytes = 32
-- | Key length as a proxy value
keyBytes :: ByteSize KeyBytes
keyBytes = ByteSize
-- | Key length as a regular value
keySize :: Int
keySize = fromIntegral sodium_auth_keybytes

-- | Length of a 'Mac' as a type-level constant
type MacBytes = 32
-- | Mac length as a proxy value
macBytes :: ByteSize MacBytes
macBytes = ByteSize
-- | Mac length as a regular value
macSize :: Int
macSize = fromIntegral sodium_auth_bytes
