{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# OPTIONS_HADDOCK hide #-}
{-|
Module      : Crypto.Lithium.Unsafe.Stream
Description : XChaCha20 stream cipher
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Stream
  ( Key(..)
  , asKey
  , fromKey
  , newKey

  , Nonce(..)
  , asNonce
  , fromNonce
  , newNonce

  , stream
  , streamXor

  , KeyBytes
  , keyBytes
  , keySize

  , NonceBytes
  , nonceBytes
  , nonceSize
  ) where

import Crypto.Lithium.Internal.Stream
import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Unsafe.Types

import Control.DeepSeq
import Data.ByteArray as B

import Foundation


newtype Key = Key
  { unKey :: SecretN KeyBytes } deriving (Show, Eq, NFData)

asKey :: Decoder Key
asKey = decodeSecret Key

fromKey :: Encoder Key
fromKey = encodeSecret unKey


newtype Nonce = Nonce
  { unNonce :: BytesN NonceBytes } deriving (Show, Eq, NFData)

asNonce :: Decoder Nonce
asNonce = decodeWith Nonce

fromNonce :: Encoder Nonce
fromNonce = encodeWith unNonce



{-|
Generate a new 'stream' key
-}
newKey :: IO Key
newKey = withLithium $ do
  (_e, k) <-
    allocSecretN $ \pk ->
    sodium_stream_xchacha20_keygen pk
  return $ Key k

newNonce :: IO Nonce
newNonce = Nonce <$> randomBytesN

stream :: ByteArray s
       => Key -> Nonce -> Int -> s
stream (Key key) (Nonce nonce) streamLength =
  withLithium $

  let (_e, streamBytes) = unsafePerformIO $
        B.allocRet streamLength $ \pStream ->
        withSecret key $ \pKey ->
        withByteArray nonce $ \pNonce ->
        sodium_stream_xchacha20 pStream (fromIntegral streamLength)
                                pNonce pKey
  in streamBytes

streamXor :: (ByteOp m c)
          => Key -> Nonce -> m -> c
streamXor (Key key) (Nonce nonce) message =
  withLithium $

  let messageLength = B.length message

      (_e, ciphertext) = unsafePerformIO $
        B.allocRet messageLength $ \pCiphertext ->
        withSecret key $ \pKey ->
        withByteArray nonce $ \pNonce ->
        withByteArray message $ \pMessage ->
        sodium_stream_xchacha20_xor pCiphertext
                                    pMessage (fromIntegral messageLength)
                                    pNonce pKey
  in ciphertext


type KeyBytes = 32
keyBytes :: ByteSize KeyBytes
keyBytes = ByteSize

keySize :: Int
keySize = fromInteger $ fromIntegral sodium_stream_xchacha20_keybytes

type NonceBytes = 24
nonceBytes :: ByteSize NonceBytes
nonceBytes = ByteSize

nonceSize :: Int
nonceSize = fromInteger $ fromIntegral sodium_stream_xchacha20_noncebytes
