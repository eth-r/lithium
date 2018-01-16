{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-|
Module      : Crypto.Lithium.Box
Description : Curve25519 public-key encryption
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Box
  ( -- * Types
    U.Keypair(..)
  , U.newKeypair

  , U.SecretKey(..)

  , U.PublicKey(..)
  , U.asPublicKey
  , U.fromPublicKey

  , Box(..)
  , fromBox
  , asBox

  -- * Public-key encryption
  , box
  , openBox

  -- * Constants
  , TagBytes
  , tagBytes
  , tagSize

  , U.PublicKeyBytes
  , U.publicKeyBytes
  , U.publicKeySize

  , U.SecretKeyBytes
  , U.secretKeyBytes
  , U.secretKeySize
  ) where

import Crypto.Lithium.Unsafe.Box
  ( PublicKey
  , SecretKey
  )

import qualified Crypto.Lithium.Unsafe.Box as U
import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Types

import Data.ByteArray as B
import Data.ByteString as BS

import Foundation hiding (splitAt)
import Control.DeepSeq

{-|
Misuse-resistant form of @crypto_box@ from Libsodium

Nonce reuse vulnerability is removed by randomly generating a nonce on every
call, and prepending it to the ciphertext. Additionally, if Libsodium is not
initialized, @sodium_init@ is called before doing cryptographic operations; it
short-circuits out on every subsequent call so the overhead should not be
excessive.

Thanks to the 'IsPlaintext' typeclass, 'box' can keep track of what type the
ciphertext represents, and automatically convert it upon decryption, to ensure
transparent encryption of any serializable values.

In all relevant respects, 'box' should Just Encrypt.
-}
box :: Plaintext p => PublicKey -> SecretKey -> p -> IO (Box p)
box pk sk message = do
  ciphertext <- U.boxRandom pk sk (fromPlaintext message :: ByteString)
  return $ Box ciphertext

{-|
Misuse-resistant form of @crypto_box_open@ from Libsodium

Nonce reuse vulnerability is removed by reading a prepended nonce from the
ciphertext, and if it has not already been done, @sodium_init@ is called to
ensure no cryptographic operations happen with uninitialized Libsodium.

With the 'IsPlaintext' typeclass, 'openBox' will automatically convert the
decrypted byte array to your desired type, including non-trivial transformations
such as compression if so defined in the instance declaration.
-}
openBox :: Plaintext p => PublicKey -> SecretKey -> Box p -> Maybe p
openBox pk sk (Box ciphertext) = do
  decrypted <- U.openBoxPrefix pk sk ciphertext
  toPlaintext (decrypted :: ByteString)

newtype Box t = Box
  { unBox :: ByteString } deriving (Eq, Show, NFData)

fromBox :: Encoder (Box t)
fromBox = B.convert . unBox

asBox :: Decoder (Box t)
asBox = Just . Box . B.convert

{-|
Size of the tag prepended to the ciphertext; the amount by which a 'box'
ciphertext is longer than the corresponding plaintext. Consists of a nonce,
randomly generated to remove pitfalls for users, and a mac.
-}
type TagBytes = 40
-- | Tag length as a proxy value
tagBytes :: ByteSize TagBytes
tagBytes = ByteSize
-- | Tag length as a regular value
tagSize :: Int
tagSize = U.nonceSize + U.macSize
