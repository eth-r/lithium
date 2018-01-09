{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_HADDOCK show-extensions #-}
{-|
Module      : Crypto.Lithium.Aead
Description : AEAD made easy and safe
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Aead
  ( U.Key
  , newKey

  , AeadBox(..)
  , aead
  , openAead

  , TagBytes
  , tagBytes
  , tagSize

  , U.KeyBytes
  , U.keyBytes
  , U.keySize
  ) where

import Crypto.Lithium.Unsafe.Aead (Key)
import qualified Crypto.Lithium.Unsafe.Aead as U
import Crypto.Lithium.Internal.Aead
import Crypto.Lithium.Internal.Util
import Foreign.Ptr
import Foundation
import Control.DeepSeq

{-|
Generate a new 'aead' key
-}
newKey :: IO Key
newKey = unsafeLithiumWrap U.newKey

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
aead :: ( IsPlaintext message
        , ByteArrayAccess aad )
     => Key -> message -> aad -> IO (AeadBox aad message)
aead key message aad =
  unsafeLithiumWrap $ do -- ^ Ensure Sodium is initialized

  let mlen = plaintextLength message
      -- ^ Length of message
      clen = mlen + tagSize
      -- ^ Length of combined ciphertext to allocate:
      --   message + (nonce + mac)
      alen = bLength aad
      -- ^ Length of associated data

  (_e, ciphertext) <-
    allocRet clen $ \pc ->
    -- ^ Allocate ciphertext, including nonce and mac
    withSecretN (U.fromKey key) $ \pkey ->
    withPlaintext message $ \pmessage ->
    withByteArray aad $ \padata ->
    do
      let pnonce = pc
          -- ^ Nonce allocated at byte 0 of ciphertext
          pctext = plusPtr pc U.nonceSize
          -- ^ Mac and encrypted message after nonce
      sodium_randombytes pc (asNum U.nonceBytes)
      -- ^ Initialize with random nonce
      aead_encrypt pctext
                   pmessage mlen
                   padata alen
                   pnonce pkey
  return $ AeadBox ciphertext

{-|
Open an 'AeadBox' and verify its associated data

This also calls the 'fromPlaintext' constructor of the encrypted type to provide
transparent encryption of arbitrary Haskell datatypes.
-}
openAead :: ( IsPlaintext message
            , ByteArrayAccess aad )
         => Key -> AeadBox aad message -> aad -> Maybe message
openAead key (AeadBox ciphertext) aad =
  unsafeLithiumWrap $ -- ^ Ensure Sodium is initialized

  let clen = bLength ciphertext - U.nonceSize
      -- ^ Length of Aead ciphertext in C type:
      --   ciphertext - nonce
      mlen = bLength ciphertext - tagSize
      -- ^ Length of original plaintext:
      --   ciphertext - (nonce + mac)
      alen = bLength aad
      -- ^ Length of associated data in C type

      (e, message) = unsafePerformIO $
        allocRet mlen $ \pmessage ->
        -- ^ Allocate plaintext
        withSecretN (U.fromKey key) $ \pkey ->
        withByteArray ciphertext $ \pc ->
        withByteArray aad $ \padata ->
        do
          let pnonce = pc
              -- ^ Nonce begins at byte 0
              pctext = plusPtr pc U.nonceSize
              -- ^ Mac and encrypted message after nonce
          aead_decrypt pmessage
                       pctext clen
                       padata alen
                       pnonce pkey
  in case e of
    0 -> fromPlaintext message
    _ -> Nothing

{-|
Type-aware wrapper for 'aead' ciphertexts

The 'AeadBox' remembers what type its associated data and original plaintext
should be, and can transparently handle encryption of any type with an
'IsPlaintext' instance, and anything with 'ByteArrayAccess' as the associated
data.
-}
newtype AeadBox aad plaintext = AeadBox
  { unAeadBox :: Bytes } deriving (Eq, Show, NFData)

{-|
Size of the tag prepended to the ciphertext; the amount by which a 'aead'
ciphertext is longer than the corresponding plaintext. Consists of a nonce,
randomly generated to remove pitfalls for users, and a mac.
-}
type TagBytes = U.NonceBytes + U.MacBytes
tagBytes :: ByteSize TagBytes
tagBytes = ByteSize

tagSize :: Int
tagSize = U.nonceSize + U.macSize
