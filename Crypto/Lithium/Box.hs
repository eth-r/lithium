{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_HADDOCK show-extensions #-}
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
    U.Keypair
  , U.newKeypair
  , U.publicKey
  , U.secretKey

  , U.SecretKey

  , U.PublicKey
  , U.asPublicKey
  , U.fromPublicKey

  , Box(..)

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
import Crypto.Lithium.Internal.Random
import Crypto.Lithium.Internal.Box
import Crypto.Lithium.Internal.Util

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
box :: forall p. (Plaintext p)
    => PublicKey -> SecretKey -> p -> IO (Box p)
box pk sk message =
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
    withByteArray (U.fromPublicKey pk) $ \ppk ->
    withSecret (U.fromSecretKey sk) $ \psk ->
    withPlaintext message $ \pmessage ->
    do
      let pnonce = pc
          -- ^ Nonce allocated at byte 0 of ciphertext
          pctext = plusPtr pc U.nonceSize
          -- ^ Mac and encrypted message after nonce
      sodium_randombytes pnonce (asNum U.nonceBytes)
      -- Initialize with random nonce
      sodium_box_easy pctext
                      pmessage mlenC
                      pnonce ppk psk

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
openBox :: forall p. (Plaintext p)
        => PublicKey -> SecretKey -> Box p -> Maybe p
openBox pk sk (Box ciphertext) =
  withLithium $ -- Ensure Sodium is initialized

  let clenC = fromIntegral $ B.length ciphertext - U.nonceSize
      -- ^ Length of SecretBox ciphertext in C type:
      --   ciphertext - nonce
      mlen = B.length ciphertext - tagSize
      -- ^ Length of original plaintext:
      --   ciphertext - (nonce + mac)

      (e, message) = unsafePerformIO $
        allocRet mlen $ \pmessage ->
        -- Allocate plaintext
        withByteArray (U.fromPublicKey pk) $ \ppk ->
        withSecret (U.fromSecretKey sk) $ \psk ->
        withByteArray ciphertext $ \pc ->
        do
          let pnonce = pc
              -- ^ Nonce begins at byte 0
              pctext = plusPtr pc U.nonceSize
              -- ^ Mac and encrypted message after nonce
          sodium_box_open_easy pmessage
                               pctext clenC
                               pnonce ppk psk
  in case e of
    0 -> toPlaintext (message :: ScrubbedBytes)
    _ -> Nothing

newtype Box t = Box
  { getCiphertext :: ByteString } deriving (Eq, Show, NFData)

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
