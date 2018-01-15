{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-|
Module      : Crypto.Lithium.Aead
Description : Authenticated encryption with associated data
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Aead
  ( U.Key
  , U.newKey

  , AeadBox(..)

  , aead
  , openAead

  -- * Constants
  , TagBytes
  , tagBytes
  , tagSize

  , U.KeyBytes
  , U.keyBytes
  , U.keySize
  ) where

import Crypto.Lithium.Unsafe.Aead (Key)
import qualified Crypto.Lithium.Unsafe.Aead as U
import Crypto.Lithium.Internal.Util
import Foundation
import Control.DeepSeq
import Data.ByteArray as B
import Data.ByteString as BS

{-|
Encrypt the plaintext into an 'AeadBox' which also authenticates the message and
its associated data upon decryption

The associated data is not encrypted or stored in the encrypted box.

If your protocol uses nonces for eg. replay protection, you should put the nonce
in the associated data field; due to the risk of nonce reuse compromising the
underlying cryptography, Lithium does not provide an interface using nonces in
the traditional sense. With 'aead', repeating the associated data will not harm
your security in any way.
-}
aead :: ( Plaintext message
        , ByteArrayAccess aad )
     => Key -> message -> aad -> IO (AeadBox aad message)
aead key message aad = do
  ciphertext <- U.aeadRandom key
    (fromPlaintext message :: ByteString) aad
  return $ AeadBox ciphertext

{-|
Open an 'AeadBox' and verify its associated data

This also calls the 'fromPlaintext' constructor of the encrypted type to provide
transparent encryption of arbitrary Haskell datatypes.
-}
openAead :: ( Plaintext message
            , ByteArrayAccess aad )
         => Key -> AeadBox aad message -> aad -> Maybe message
openAead key (AeadBox ciphertext) aad = do
  decrypted <- U.openAeadPrefix key ciphertext aad
  toPlaintext (decrypted :: ByteString)

{-|
Type-aware wrapper for 'aead' ciphertexts

The 'AeadBox' remembers what type its associated data and original plaintext
should be, and can transparently handle encryption of any type with an
'IsPlaintext' instance, and anything with 'ByteArrayAccess' as the associated
data.
-}
newtype AeadBox aad plaintext = AeadBox
  { getCiphertext :: ByteString } deriving (Eq, Show, NFData)

{-|
Size of the tag prepended to the ciphertext; the amount by which a 'aead'
ciphertext is longer than the corresponding plaintext. Consists of a nonce,
randomly generated to remove pitfalls for users, and a mac.
-}
type TagBytes = 40
-- | Size of a tag as a proxy value
tagBytes :: ByteSize TagBytes
tagBytes = ByteSize
-- | Size of a tag as a regular value
tagSize :: Int
tagSize = U.nonceSize + U.macSize
