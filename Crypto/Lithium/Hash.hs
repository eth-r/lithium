{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-|
Module      : Crypto.Lithium.Hash
Description : Secure general-purpose hash function
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Hash (
  -- * Blake-2b-256
    Key
  , newKey

  , Digest
  , asDigest
  , fromDigest

  , hash
  , keyedHash
  , streamingHash

  -- * Blake-2b-512
  , LongKey
  , newLongKey

  , LongDigest
  , asLongDigest
  , fromLongDigest

  , longHash
  , keyedLongHash
  , streamingLongHash

  -- * Constants
  , U.DigestBytes
  , U.digestBytes
  , U.digestSize

  , U.KeyBytes
  , U.keyBytes
  , U.keySize

  , LongDigestBytes
  , longDigestBytes
  , longDigestSize

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
512-bit digest resulting from 'longHash' or 'keyedLongHash'
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

The key is always 256 bits long
-}
newKey :: IO Key
newKey = U.newKey

{-|
Hash any data using keyed Blake2b-256
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

{-|
Generate a new key usable with 'keyedLongHash'

The key is always 512 bits long
-}
newLongKey :: IO LongKey
newLongKey = U.newKey

{-|
Hash any data using keyed Blake2b-512
-}
keyedLongHash :: Plaintext p => LongKey -> p -> LongDigest p
keyedLongHash key message = LongDigest $
  U.genericHash (Just key) (fromPlaintext message :: ByteString)

{-|
Hash a list of bytestring chunks with a streaming API

Gives the same output as calling 'hash' on the concatenation of the input chunks
-}
streamingHash :: (Foldable t, Plaintext p) => Maybe Key -> t p -> Digest (t p)
streamingHash key t =
  let state = U.genericHashInit key
      hasher state' item = U.genericHashUpdate state' (fromPlaintext item :: ByteString)
  in Digest $ U.genericHashFinal $ F.foldl' hasher state t

{-|
Hash a list of bytestring chunks with a streaming API

Gives the same output as calling 'longHash' on the concatenation of the input chunks
-}
streamingLongHash :: (Foldable t, Plaintext p) => Maybe LongKey -> t p -> LongDigest (t p)
streamingLongHash key t =
  let state = U.genericHashInit key
      hasher state' item = U.genericHashUpdate state' (fromPlaintext item :: ByteString)
  in LongDigest $ U.genericHashFinal $ F.foldl' hasher state t

-- | Length of a 'LongKey' as a type-level constant
type LongKeyBytes = 64
-- | Long key length as a proxy value
longKeyBytes :: ByteSize LongKeyBytes
longKeyBytes = ByteSize
-- | Long key length as a regular value
longKeySize :: Int
longKeySize = U.maxKeySize

-- | Length of a 'LongDigest' as a type-level constant
type LongDigestBytes = 64
-- | Long digest length as a proxy value
longDigestBytes :: ByteSize LongDigestBytes
longDigestBytes = ByteSize
-- | Long digest length as a regular value
longDigestSize :: Int
longDigestSize = U.maxDigestSize
