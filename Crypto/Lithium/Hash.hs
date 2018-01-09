{-# LANGUAGE NoImplicitPrelude #-}
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
  ( HashKey
  , newHashKey

  , Digest
  , asDigest
  , fromDigest

  , genericHash
  , keyedHash

  , DigestBytes
  , digestBytes
  , digestSize

  , HashKeyBytes
  , hashKeyBytes
  , hashKeySize
  ) where

import Foundation

import Crypto.Lithium.Internal.Util
import qualified Crypto.Lithium.Unsafe.Hash as U
import Crypto.Lithium.Unsafe.Types
import Data.ByteArray as B

{-|
Opaque 'keyedHash' key
-}
type HashKey = U.Key HashKeyBytes

{-|
Digest resulting from 'genericHash' or 'keyedHash'
-}
type Digest = U.Digest DigestBytes

{-|
Interpret an arbitrary byte array as a 'Digest'
-}
asDigest :: ByteArrayAccess b
         => b -> Maybe Digest
asDigest b = U.asDigest <$> maybeToN (B.convert b :: Bytes)

{-|
Convert a digest into an arbitrary byte array
-}
fromDigest :: ByteArray b => Digest -> b
fromDigest = convert . fromN . U.fromDigest

{-|
Hash any data using unkeyed Blake2b

Unlike the more complex API in "Crypto.Lithium.Unsafe.Hash", the length of the
output digest is always 512 bits
-}
genericHash :: ByteArrayAccess a
            => a
            -> Digest
genericHash message = U.genericHash (Nothing :: Maybe HashKey) message

{-|
Generate a new key usable with 'keyedHash'

The key is always 512 bits long
-}
newHashKey :: IO HashKey
newHashKey = U.newKey

{-|
Hash any data using keyed Blake2b

The key and the resulting digest are both 512 bits long
-}
keyedHash :: ByteArrayAccess a
          => HashKey
          -> a
          -> Digest
keyedHash key message = U.genericHash (Just key) message

{-|
Length of the digest
-}
type DigestBytes = U.MaxDigestBytes
digestBytes :: ByteSize DigestBytes
digestBytes = ByteSize

digestSize :: Int
digestSize = U.maxDigestSize

{-|
Length of a 'keyedHash' key
-}
type HashKeyBytes = U.MaxKeyBytes
hashKeyBytes :: ByteSize HashKeyBytes
hashKeyBytes = ByteSize

hashKeySize :: Int
hashKeySize = U.maxKeySize
