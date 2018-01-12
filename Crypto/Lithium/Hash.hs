{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_HADDOCK show-extensions #-}
{-|
Module      : Crypto.Lithium.Hash
Description : Cryptographic hashing made easy and safe
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Hash
  ( Key
  , newKey

  , Digest
  , asDigest
  , fromDigest

  , hash
  , keyedHash

  , LongKey
  , newLongKey

  , LongDigest
  , asLongDigest
  , fromLongDigest

  , longHash
  , keyedLongHash

  , streamingHash
  , streamingLongHash

  , U.DigestBytes
  , U.digestBytes
  , U.digestSize

  , LongDigestBytes
  , longDigestBytes
  , longDigestSize

  , U.KeyBytes
  , U.keyBytes
  , U.keySize

  , LongKeyBytes
  , longKeyBytes
  , longKeySize
  ) where

import Foundation hiding (Foldable)

import Crypto.Lithium.Internal.Util
import qualified Crypto.Lithium.Unsafe.Hash as U
import Crypto.Lithium.Unsafe.Types

import Control.DeepSeq
import Data.ByteArray as B
import Data.ByteString as BS
import Data.Foldable as F

{-|
Opaque 'keyedHash' key
-}
type Key = U.Key U.KeyBytes

{-|
Digest resulting from 'genericHash' or 'keyedHash'
-}
newtype Digest t = Digest (U.Digest U.DigestBytes)
  deriving (Eq, Ord, Show, NFData, ByteArrayAccess)

instance Plaintext t => Plaintext (Digest t) where
  toPlaintext = asDigest
  fromPlaintext = fromDigest
  withPlaintext (Digest d) = withPlaintext d
  plaintextLength _ = U.digestSize

{-|
Interpret an arbitrary byte array as a 'Digest'
-}
asDigest :: (Plaintext p, ByteArrayAccess b)
         => b -> Maybe (Digest p)
asDigest b = Digest . U.asDigest <$> maybeToN (B.convert b :: Bytes)

{-|
Convert a digest into an arbitrary byte array
-}
fromDigest :: ByteArray b => Digest p -> b
fromDigest (Digest d) =
  convert $ fromN $ U.fromDigest d

{-|
Opaque 'keyedLongHash' key
-}
type LongKey = U.Key LongKeyBytes

{-|
512-bit digest resulting from 'genericHash' or 'keyedHash'
-}
newtype LongDigest t = LongDigest (U.Digest LongDigestBytes)
  deriving (Eq, Ord, Show, NFData, ByteArrayAccess)

instance Plaintext t => Plaintext (LongDigest t) where
  toPlaintext = asLongDigest
  fromPlaintext = fromLongDigest
  withPlaintext (LongDigest d) = withPlaintext d
  plaintextLength _ = longDigestSize

{-|
Interpret an arbitrary byte array as a long digest
-}
asLongDigest :: (Plaintext t, ByteArrayAccess b)
             => b -> Maybe (LongDigest t)
asLongDigest b = LongDigest . U.asDigest <$> maybeToN (B.convert b :: Bytes)

{-|
Convert a long digest into an arbitrary byte array
-}
fromLongDigest :: ByteArray b => LongDigest t -> b
fromLongDigest (LongDigest d) =
  convert $ fromN $ U.fromDigest d

{-|
Hash any data using unkeyed Blake2b-256
-}
hash :: Plaintext p => p -> Digest p
hash message = Digest $
  U.genericHash (Nothing :: Maybe Key) (fromPlaintext message :: ByteString)

{-|
Generate a new key usable with 'keyedHash'

The key is always 512 bits long
-}
newKey :: IO Key
newKey = U.newKey

{-|
Hash any data using keyed Blake2b-256 with 256-bit key
-}
keyedHash :: Plaintext p => Key -> p -> Digest p
keyedHash key message = Digest $
  U.genericHash (Just key) (fromPlaintext message :: ByteString)

{-|
Hash any data using unkeyed Blake2b-512
-}
longHash :: Plaintext p => p -> LongDigest p
longHash message = LongDigest $
  U.genericHash (Nothing :: Maybe LongKey) (fromPlaintext message :: ByteString)

newLongKey :: IO LongKey
newLongKey = U.newKey

{-|
Hash any data using keyed Blake2b-512 with 512-bit key
-}
keyedLongHash :: Plaintext p => LongKey -> p -> LongDigest p
keyedLongHash key message = LongDigest $
  U.genericHash (Just key) (fromPlaintext message :: ByteString)

{-|
Hash a list of bytestring chunks with a streaming API
-}
streamingHash :: (Foldable t, Plaintext p) => Maybe Key -> t p -> Digest (t p)
streamingHash key t =
  let state = U.genericHashInit key
      hasher state' item = U.genericHashUpdate state' (fromPlaintext item :: ByteString)
  in Digest $ U.genericHashFinal $ F.foldl' hasher state t

streamingLongHash :: (Foldable t, Plaintext p) => Maybe LongKey -> t p -> LongDigest (t p)
streamingLongHash key t =
  let state = U.genericHashInit key
      hasher state' item = U.genericHashUpdate state' (fromPlaintext item :: ByteString)
  in LongDigest $ U.genericHashFinal $ F.foldl' hasher state t

{-|
Length of a long key
-}
type LongKeyBytes = U.MaxKeyBytes
longKeyBytes :: ByteSize LongKeyBytes
longKeyBytes = ByteSize

longKeySize :: Int
longKeySize = U.maxKeySize

{-|
Length of a long digest
-}
type LongDigestBytes = U.MaxDigestBytes
longDigestBytes :: ByteSize LongDigestBytes
longDigestBytes = ByteSize

longDigestSize :: Int
longDigestSize = U.maxDigestSize
