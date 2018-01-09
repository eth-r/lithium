{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.Box
Description : Curve25519 public-key encryption made easy
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Box
  ( SecretKey
  , asSecretKey
  , fromSecretKey

  , Nonce
  , asNonce
  , fromNonce
  , newNonce

  , PublicKey
  , asPublicKey
  , fromPublicKey

  , Keypair
  , asKeypair
  , fromKeypair
  , publicKey
  , secretKey
  , newKeypair
  , seedKeypair

  , Seed
  , asSeed
  , fromSeed

  , Mac
  , asMac
  , fromMac

  , box
  , openBox

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
newtype SecretKey = S (SecretN SecretKeyBytes) deriving (Show, Eq, NFData)

{-|
Function for interpreting arbitrary bytes as a 'SecretKey'

Note that this allows insecure handling of key material. This function is only
exported in the "Crypto.Lithium.Unsafe.Box" API.
-}
asSecretKey :: SecretN SecretKeyBytes -> SecretKey
asSecretKey = S

{-|
Function for converting a 'SecretKey' into an arbitrary byte array

Note that this allows insecure handling of key material. This function is only
exported in the "Crypto.Lithium.Unsafe.Box" API.
-}
fromSecretKey :: SecretKey -> SecretN SecretKeyBytes
fromSecretKey (S k) = k


{-|
Opaque 'box' public key type
-}
newtype PublicKey = P (BytesN PublicKeyBytes) deriving (Show, Eq, NFData)

{-|
Function for interpreting an arbitrary byte array as a 'PublicKey'


-}
asPublicKey :: BytesN PublicKeyBytes -> PublicKey
asPublicKey = P

fromPublicKey :: PublicKey -> BytesN PublicKeyBytes
fromPublicKey (P k) = k


newtype Keypair = KP (SecretKey, PublicKey) deriving (Show, Eq, NFData)

asKeypair :: SecretN (SecretKeyBytes + PublicKeyBytes) -> Keypair
asKeypair s =
  let (sk, pk) = splitSecretN s
  in KP (S sk, P (revealN pk))

fromKeypair :: Keypair -> SecretN (SecretKeyBytes + PublicKeyBytes)
fromKeypair (KP (S sk, P pk)) =
  appendN <$> sk <*> concealN pk

newtype Seed = Seed (SecretN SeedBytes) deriving (Show, Eq, NFData)

asSeed :: SecretN SeedBytes -> Seed
asSeed = Seed

fromSeed :: Seed -> SecretN SeedBytes
fromSeed (Seed s) = s

newtype Nonce = Nonce (BytesN NonceBytes) deriving (Show, Eq, NFData)

asNonce :: BytesN NonceBytes -> Nonce
asNonce = Nonce

fromNonce :: Nonce -> BytesN NonceBytes
fromNonce (Nonce n) = n

newtype Mac = Mac (BytesN MacBytes) deriving (Show, Eq, NFData)

asMac :: BytesN MacBytes -> Mac
asMac = Mac

fromMac :: Mac -> BytesN MacBytes
fromMac (Mac m) = m

publicKey :: Keypair -> PublicKey
publicKey (KP (_s, p)) = p
secretKey :: Keypair -> SecretKey
secretKey (KP (s, _p)) = s

newKeypair :: IO Keypair
newKeypair = withLithium $ do
  ((_e, sk), pk) <-
    allocRetN $ \ppk ->
    allocSecretN $ \psk ->
    sodium_box_keypair ppk psk
  let sk' = S sk
      pk' = P pk
  return $ KP (sk', pk')

seedKeypair :: Seed -> Keypair
seedKeypair (Seed s) = withLithium $
  let ((_e, sk), pk) = unsafePerformIO $
        allocRetN $ \ppk ->
        allocSecretN $ \psk ->
        withSecret s $ \ps ->
        sodium_box_seed_keypair ppk psk ps
      sk' = S sk
      pk' = P pk
  in KP (sk', pk')

newNonce :: IO Nonce
newNonce = withLithium $ Nonce <$> randomBytesN

box :: ByteOp m c
    => PublicKey -> SecretKey -> Nonce -> m -> c
box (P pk) (S sk) (Nonce n) message = withLithium $
  let (_e, ciphertext) = unsafePerformIO $
        allocRet (B.length message + macSize) $ \pc ->
        withByteArray pk $ \ppk ->
        withSecret sk $ \psk ->
        withByteArray n $ \pn ->
        withByteArray message $ \pm ->
        sodium_box_easy pc pm (fromIntegral $ B.length message) pn ppk psk
  in ciphertext

openBox :: ByteOp c m
        => PublicKey -> SecretKey -> Nonce -> c -> Maybe m
openBox (P pk) (S sk) (Nonce n) ciphertext = withLithium $
  let (e, message) = unsafePerformIO $
        allocRet (B.length ciphertext - macSize) $ \pm ->
        withByteArray pk $ \ppk ->
        withSecret sk $ \psk ->
        withByteArray n $ \pn ->
        withByteArray ciphertext $ \pc ->
        sodium_box_open_easy pm pc (fromIntegral $ B.length ciphertext) pn ppk psk
  in case e of
    0 -> Just message
    _ -> Nothing

detachedBox :: ByteOp m c
            => PublicKey -> SecretKey -> Nonce -> m -> (c, Mac)
detachedBox (P pk) (S sk) (Nonce n) message = withLithium $
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
openDetachedBox (P pk) (S sk) (Nonce n) (Mac mac) ciphertext = withLithium $
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
