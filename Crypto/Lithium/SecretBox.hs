{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-|
Module      : Crypto.Lithium.SecretBox
Description : Symmetrical encryption
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
import Crypto.Lithium.Internal.Util
import Foundation
import Control.DeepSeq
import Data.ByteString as BS

{-|
Encrypt the plaintext into a 'SecretBox' which also verifies the authenticity of
the message upon decryption

Due to the risk of nonce reuse compromising the underlying cryptography, Lithium
does not provide a 'secretBox' interface using user-supplied nonces outside the
"Crypto.Lithium.Unsafe" API. If your protocol requires nonces for eg. replay
protection, you should use "Crypto.Lithium.Aead" instead.
-}
secretBox :: (Plaintext p)
          => Key -> p -> IO (SecretBox p)
secretBox key message = do
  ciphertext <- U.secretBoxRandom key
    (fromPlaintext message :: ByteString)
  return $ SecretBox ciphertext

{-|
Decrypt the 'SecretBox' and verify it has not been tampered with
-}
openSecretBox :: Plaintext p
              => Key -> SecretBox p -> Maybe p
openSecretBox key (SecretBox ciphertext) = do
  decrypted <- U.openSecretBoxPrefix key ciphertext
  toPlaintext (decrypted :: ByteString)

newtype SecretBox plaintext = SecretBox
  { getCiphertext :: ByteString } deriving (Eq, Show, NFData)

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
