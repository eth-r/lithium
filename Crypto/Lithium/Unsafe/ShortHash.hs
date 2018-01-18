{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.ShortHash
Description : SipHash-2-4
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.ShortHash
  ( Key(..)
  , asKey
  , fromKey

  , Digest(..)
  , asDigest
  , fromDigest

  , newKey

  , shortHash

  -- * Constants
  , DigestBytes
  , digestBytes
  , digestSize

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
import Data.ByteArray.Sized as Sized

newtype Key = Key (SecretN KeyBytes) deriving (Eq, Show, NFData)

asKey :: SecretN KeyBytes -> Key
asKey = Key

fromKey :: Key -> SecretN KeyBytes
fromKey (Key k) = k

newtype Digest = Digest (BytesN DigestBytes) deriving (Eq, Show, NFData)

instance ByteArrayAccess Digest where
  length _ = digestSize
  withByteArray (Digest bs) = withByteArray bs

instance Plaintext Digest where
  fromPlaintext (Digest bs) = fromPlaintext bs
  toPlaintext bs = Digest <$> toPlaintext bs
  withPlaintext (Digest bs) = withPlaintext bs
  plaintextLength _ = digestSize

asDigest :: BytesN DigestBytes -> Digest
asDigest = Digest

fromDigest :: Digest -> BytesN DigestBytes
fromDigest (Digest d) = d

newKey :: IO Key
newKey = Key <$> randomSecretN

{-

-}
shortHash :: ByteArrayAccess a => Key -> a -> Digest
shortHash (Key key) m = withLithium $
  let mlen = fromIntegral $ B.length m
      (_e, result) = unsafePerformIO $
        Sized.allocRet $ \pdigest ->
        withByteArray m $ \pmessage ->
        withSecret key $ \pkey ->
        sodium_shorthash pdigest
                         pmessage mlen
                         pkey
  in Digest result

type DigestBytes = 8
digestBytes :: ByteSize DigestBytes
digestBytes = ByteSize

digestSize :: Int
digestSize = fromIntegral sodium_shorthash_bytes

type KeyBytes = 16
keyBytes :: ByteSize KeyBytes
keyBytes = ByteSize

keySize :: Int
keySize = fromIntegral sodium_shorthash_keybytes
