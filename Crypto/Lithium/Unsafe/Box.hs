{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.Box
Description : Curve25519 public-key encryption
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Box
  ( SecretKey(..)
  , asSecretKey
  , fromSecretKey

  , Nonce(..)
  , asNonce
  , fromNonce
  , newNonce

  , PublicKey(..)
  , asPublicKey
  , fromPublicKey

  , Keypair(..)
  , asKeypair
  , fromKeypair
  , newKeypair
  , seedKeypair

  , Seed(..)
  , asSeed
  , fromSeed

  , Mac(..)
  , asMac
  , fromMac

  , box
  , openBox

  , boxPrefix
  , boxRandom
  , openBoxPrefix

  , detachedBox
  , openDetachedBox

  , PublicKeyBytes
  , publicKeyBytes
  , publicKeySize

  , SecretKeyBytes
  , secretKeyBytes
  , secretKeySize

  , MacBytes
  , macBytes
  , macSize

  , NonceBytes
  , nonceBytes
  , nonceSize

  , SeedBytes
  , seedBytes
  , seedSize

  , SharedKeyBytes
  , sharedKeyBytes
  , sharedKeySize
  ) where

import Crypto.Lithium.Internal.Box
import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Unsafe.Types

import Control.DeepSeq
import Foundation
import Data.ByteArray as B

{-|
Opaque 'box' secret key type, wrapping the sensitive data in 'ScrubbedBytes' to
reduce exposure to dangers.
-}
newtype SecretKey = SecretKey
  { unSecretKey :: SecretN SecretKeyBytes } deriving (Show, Eq, NFData)

{-|
Function for interpreting arbitrary bytes as a 'SecretKey'

Note that this allows insecure handling of key material. This function is only
exported in the "Crypto.Lithium.Unsafe.Box" API.
-}
asSecretKey :: Decoder SecretKey
asSecretKey = decodeSecret SecretKey

{-|
Function for converting a 'SecretKey' into an arbitrary byte array

Note that this allows insecure handling of key material. This function is only
exported in the "Crypto.Lithium.Unsafe.Box" API.
-}
fromSecretKey :: Encoder SecretKey
fromSecretKey = encodeSecret unSecretKey


{-|
Opaque 'box' public key type
-}
newtype PublicKey = PublicKey
  { unPublicKey :: BytesN PublicKeyBytes } deriving (Show, Eq, ByteArrayAccess, NFData)

instance Plaintext PublicKey where
  fromPlaintext = fromPublicKey
  toPlaintext = asPublicKey

{-|
Function for interpreting an arbitrary byte array as a 'PublicKey'


-}
asPublicKey :: Decoder PublicKey
asPublicKey = decodeWith PublicKey

fromPublicKey :: Encoder PublicKey
fromPublicKey = encodeWith unPublicKey


data Keypair = Keypair
  { secretKey :: SecretKey
  , publicKey :: PublicKey } deriving (Show, Eq)

instance NFData Keypair where
  rnf (Keypair s p) = rnf s `seq` rnf p

makeKeypair :: SecretN (SecretKeyBytes + PublicKeyBytes) -> Keypair
makeKeypair s =
  let (sk, pk) = splitSecretN s
  in Keypair (SecretKey sk) (PublicKey $ revealN pk)

unKeypair :: Keypair -> SecretN (SecretKeyBytes + PublicKeyBytes)
unKeypair (Keypair (SecretKey sk) (PublicKey pk)) =
  appendN <$> sk <*> concealN pk

asKeypair :: Decoder Keypair
asKeypair = decodeSecret makeKeypair

fromKeypair :: Encoder Keypair
fromKeypair = encodeSecret unKeypair

newtype Seed = Seed
  { unSeed :: SecretN SeedBytes } deriving (Show, Eq, NFData)

asSeed :: Decoder Seed
asSeed = decodeSecret Seed

fromSeed :: Encoder Seed
fromSeed = encodeSecret unSeed

newtype Nonce = Nonce
  { unNonce :: BytesN NonceBytes } deriving (Show, Eq, ByteArrayAccess, NFData)

instance Plaintext Nonce where
  fromPlaintext = fromNonce
  toPlaintext = asNonce

asNonce :: Decoder Nonce
asNonce = decodeWith Nonce

fromNonce :: Encoder Nonce
fromNonce = encodeWith unNonce

newtype Mac = Mac
  { unMac :: BytesN MacBytes } deriving (Show, Eq, ByteArrayAccess, NFData)

instance Plaintext Mac where
  fromPlaintext = fromMac
  toPlaintext = asMac

asMac :: Decoder Mac
asMac = decodeWith Mac

fromMac :: Encoder Mac
fromMac = encodeWith unMac

newKeypair :: IO Keypair
newKeypair = withLithium $ do
  ((_e, sk), pk) <-
    allocRetN $ \ppk ->
    allocSecretN $ \psk ->
    sodium_box_keypair ppk psk
  let sk' = SecretKey sk
      pk' = PublicKey pk
  return $ Keypair sk' pk'

seedKeypair :: Seed -> Keypair
seedKeypair (Seed s) = withLithium $
  let ((_e, sk), pk) = unsafePerformIO $
        allocRetN $ \ppk ->
        allocSecretN $ \psk ->
        withSecret s $ \ps ->
        sodium_box_seed_keypair ppk psk ps
      sk' = SecretKey sk
      pk' = PublicKey pk
  in Keypair sk' pk'

newNonce :: IO Nonce
newNonce = withLithium $ Nonce <$> randomBytesN

box :: ByteOp m c
    => PublicKey -> SecretKey -> Nonce -> m -> c
box (PublicKey pk) (SecretKey sk) (Nonce n) message =
  withLithium $

  let mlen = B.length message
      clen = mlen + macSize

      (_e, ciphertext) = unsafePerformIO $
        allocRet clen $ \pctext ->
        withByteArray pk $ \ppk ->
        withSecret sk $ \psk ->
        withByteArray n $ \pnonce ->
        withByteArray message $ \pmessage ->
        sodium_box_easy pctext
                        pmessage (fromIntegral mlen)
                        pnonce ppk psk
  in ciphertext

openBox :: ByteOp c m
        => PublicKey -> SecretKey -> Nonce -> c -> Maybe m
openBox (PublicKey pk) (SecretKey sk) (Nonce n) ciphertext =
  withLithium $

  let clen = B.length ciphertext
      mlen = clen - macSize

      (e, message) = unsafePerformIO $
        allocRet mlen $ \pmessage ->
        withByteArray pk $ \ppk ->
        withSecret sk $ \psk ->
        withByteArray n $ \pnonce ->
        withByteArray ciphertext $ \pctext ->
        sodium_box_open_easy pmessage
                             pctext (fromIntegral clen)
                             pnonce ppk psk
  in case e of
    0 -> Just message
    _ -> Nothing

boxPrefix :: ByteOp m c => PublicKey -> SecretKey -> Nonce -> m -> c
boxPrefix pk sk nonce message =
  let nonceBs = fromNonce nonce
      ciphertext = box pk sk nonce message
  in B.append nonceBs ciphertext

boxRandom :: ByteOp m c => PublicKey -> SecretKey -> m -> IO c
boxRandom pk sk message = do
  nonce <- newNonce
  return $ boxPrefix pk sk nonce message

openBoxPrefix :: ByteOp c m
              => PublicKey -> SecretKey -> c -> Maybe m
openBoxPrefix (PublicKey pk) (SecretKey sk) ciphertext =
  withLithium $ -- Ensure Sodium is initialized

  let clen = B.length ciphertext - nonceSize
      -- ^ Length of Box ciphertext:
      --   ciphertext - nonce
      mlen = clen - macSize
      -- ^ Length of original plaintext:
      --   ciphertext - (nonce + mac)

      (e, message) = unsafePerformIO $
        allocRet mlen $ \pmessage ->
        -- Allocate plaintext
        withByteArray pk $ \ppk ->
        withSecret sk $ \psk ->
        withByteArray ciphertext $ \pc ->
        do
          let pnonce = pc
              -- ^ Nonce begins at byte 0
              pctext = plusPtr pc nonceSize
              -- ^ Mac and encrypted message after nonce
          sodium_box_open_easy pmessage
                               pctext (fromIntegral clen)
                               pnonce ppk psk
  in case e of
    0 -> Just message
    _ -> Nothing

detachedBox :: ByteOp m c
            => PublicKey -> SecretKey -> Nonce -> m -> (c, Mac)
detachedBox (PublicKey pk) (SecretKey sk) (Nonce n) message = withLithium $
  let ((_e, mac), ciphertext) = unsafePerformIO $
        allocRet (B.length message) $ \pc ->
        allocRetN $ \pmac ->
        withByteArray pk $ \ppk ->
        withSecret sk $ \psk ->
        withByteArray n $ \pn ->
        withByteArray message $ \pm ->
        sodium_box_detached pc pmac pm (fromIntegral $ B.length message) pn ppk psk
  in (ciphertext, Mac mac)

openDetachedBox :: ByteOp c m
                => PublicKey -> SecretKey -> Nonce -> Mac -> c -> Maybe m
openDetachedBox (PublicKey pk) (SecretKey sk) (Nonce n) (Mac mac) ciphertext = withLithium $
  let (e, message) = unsafePerformIO $
        allocRet (B.length ciphertext) $ \pm ->
        withByteArray mac $ \pmac ->
        withByteArray pk $ \ppk ->
        withSecret sk $ \psk ->
        withByteArray n $ \pn ->
        withByteArray ciphertext $ \pc ->
        sodium_box_open_detached pm pc pmac (fromIntegral $ B.length ciphertext) pn ppk psk
  in case e of
    0 -> Just message
    _ -> Nothing

type PublicKeyBytes = 32
publicKeyBytes :: ByteSize PublicKeyBytes
publicKeyBytes = ByteSize

publicKeySize :: Int
publicKeySize = fromIntegral sodium_box_publickeybytes

type SecretKeyBytes = 32
secretKeyBytes :: ByteSize SecretKeyBytes
secretKeyBytes = ByteSize

secretKeySize :: Int
secretKeySize = fromIntegral sodium_box_secretkeybytes

type MacBytes = 16
macBytes :: ByteSize MacBytes
macBytes = ByteSize

macSize :: Int
macSize = fromIntegral sodium_box_macbytes

type NonceBytes = 24
nonceBytes :: ByteSize NonceBytes
nonceBytes = ByteSize

nonceSize :: Int
nonceSize = fromIntegral sodium_box_noncebytes

type SeedBytes = 32
seedBytes :: ByteSize SeedBytes
seedBytes = ByteSize

seedSize :: Int
seedSize = fromIntegral sodium_box_seedbytes

type SharedKeyBytes = 32
sharedKeyBytes :: ByteSize SharedKeyBytes
sharedKeyBytes = ByteSize

sharedKeySize :: Int
sharedKeySize = fromIntegral sodium_box_beforenmbytes
