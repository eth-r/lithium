{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_HADDOCK show-extensions #-}
{-|
Module      : Crypto.Lithium.SecretBox
Description : Symmetrical encryption made easy and safe
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.SecretBox
  ( U.Key
  , U.newKey

  , SecretBox(..)
  , secretBox
  , openSecretBox

  , TagBytes
  , tagBytes
  , tagSize

  , U.KeyBytes
  , U.keyBytes
  , U.keySize
  ) where

import Crypto.Lithium.Unsafe.SecretBox (Key)
import qualified Crypto.Lithium.Unsafe.SecretBox as U
import Crypto.Lithium.Internal.SecretBox
import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Internal.Random
import Foundation
import Control.DeepSeq
import Data.ByteArray as B

{-|
Encrypt the plaintext into a 'SecretBox' which also verifies the authenticity of
the message upon decryption

Due to the risk of nonce reuse compromising the underlying cryptography, Lithium
does not provide a 'secretBox' interface using user-supplied nonces outside the
"Crypto.Lithium.Unsafe" API. If your protocol requires nonces for eg. replay
protection, you should use "Crypto.Lithium.Aead" instead.
-}
secretBox :: (Plaintext message, ByteArray bytes)
          => Key -> message -> IO (SecretBox message bytes)
secretBox key message =
  withLithium $ do -- Ensure Sodium is initialized

  let mlen = plaintextLength message
      -- ^ Length of message
      clen = mlen + tagSize
      -- ^ Length of combined ciphertext to allocate:
      --   message + (nonce + mac)
      mlenC = fromIntegral mlen
      -- ^ Length of message in C type

  (_e, ciphertext) <-
    allocRet clen $ \pc ->
    -- Allocate ciphertext, including nonce and mac
    withSecret (U.fromKey key) $ \pkey ->
    withPlaintext message $ \pmessage ->
    do
      let pnonce = pc
          -- ^ Nonce allocated at byte 0 of ciphertext
          pctext = plusPtr pc U.nonceSize
          -- ^ Mac and encrypted message after nonce
      sodium_randombytes pc (asNum U.nonceBytes)
      -- Initialize with random nonce
      sodium_secretbox_easy pctext
                            pmessage mlenC
                            pnonce pkey
  return $ SecretBox ciphertext

{-|
Decrypt the 'SecretBox' and verify it has not been tampered with
-}
openSecretBox :: forall message bytes. (Plaintext message, ByteArray bytes)
              => Key -> SecretBox message bytes -> Maybe message
openSecretBox key (SecretBox ciphertext) =
  withLithium $ -- Ensure Sodium is initialized
  let clenC = fromIntegral $ B.length ciphertext - U.nonceSize
      -- ^ Length of SecretBox ciphertext:
      --   ciphertext - nonce
      mlen = B.length ciphertext - tagSize
      -- ^ Length of original plaintext:
      --   ciphertext - (nonce + mac)

      (e, message) = unsafePerformIO $
        allocRet mlen $ \pmessage ->
        -- Allocate plaintext
        withSecret (U.fromKey key) $ \pkey ->
        withByteArray ciphertext $ \pc ->
        do
          let pnonce = pc
              -- ^ Nonce begins at byte 0
              pctext = plusPtr pc U.nonceSize
              -- ^ Mac and encrypted message after nonce
          sodium_secretbox_open_easy pmessage
                                     pctext clenC
                                     pnonce pkey
  in case e of
    0 -> toPlaintext (message :: bytes)
    _ -> Nothing

newtype SecretBox plaintext bytes = SecretBox
  { unSecretBox :: bytes } deriving (Eq, Show, NFData)

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
