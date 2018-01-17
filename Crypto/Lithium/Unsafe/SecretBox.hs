{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.SecretBox
Description : XSalsa20Poly1305 symmetric-key encryption
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.SecretBox
  ( Key(..)
  , asKey
  , fromKey
  , newKey

  , Nonce(..)
  , asNonce
  , fromNonce
  , newNonce

  , Mac(..)
  , asMac
  , fromMac

  , secretBox
  , openSecretBox

  , secretBoxPrefix
  , openSecretBoxPrefix

  , secretBoxRandom

  , secretBoxDetached
  , openSecretBoxDetached

  , secretBoxN
  , openSecretBoxN

  , secretBoxDetachedN
  , openSecretBoxDetachedN

  , KeyBytes
  , keyBytes
  , keySize

  , NonceBytes
  , nonceBytes
  , nonceSize

  , MacBytes
  , macBytes
  , macSize
  ) where

import Crypto.Lithium.Internal.SecretBox
import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Unsafe.Types

import Control.DeepSeq
import Data.ByteArray as B
import Data.ByteArray.Sized as Sized

import Foundation hiding (splitAt)


newtype Key = Key
  { unKey :: SecretN KeyBytes } deriving (Show, Eq, NFData)

asKey :: Decoder Key
asKey = decodeSecret Key

fromKey :: Encoder Key
fromKey = encodeSecret unKey


newtype Nonce = Nonce
  { unNonce :: BytesN NonceBytes } deriving (Show, Eq, NFData)

asNonce :: Decoder Nonce
asNonce = decodeWith Nonce

fromNonce :: Encoder Nonce
fromNonce = encodeWith unNonce


newtype Mac = Mac
  { unMac :: BytesN MacBytes } deriving (Show, Eq, NFData)

asMac :: Decoder Mac
asMac = decodeWith Mac

fromMac :: Encoder Mac
fromMac = encodeWith unMac


{-|
Generate a new 'secretBox' key
-}
newKey :: IO Key
newKey = withLithium $ do
  (_e, k) <-
    allocSecretN $ \pk ->
    sodium_secretbox_keygen pk
  return $ Key k

newNonce :: IO Nonce
newNonce = Nonce <$> randomBytesN

secretBox :: (ByteOp m c)
          => Key -> Nonce -> m -> c
secretBox (Key key) (Nonce nonce) message =
  withLithium $

  let (_e, ciphertext) = unsafePerformIO $
        B.allocRet (B.length message + macSize) $ \pc ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray message $ \pm ->
        sodium_secretbox_easy pc pm (fromIntegral $ B.length message) pn pk
  in ciphertext

openSecretBox :: (ByteOp c m)
              => Key -> Nonce -> c -> Maybe m
openSecretBox (Key k) (Nonce n) ciphertext =
  withLithium $

  let (e, message) = unsafePerformIO $
        B.allocRet (B.length ciphertext - macSize) $ \pm ->
        withSecret k $ \pk ->
        withByteArray n $ \pn ->
        withByteArray ciphertext $ \pc ->
        sodium_secretbox_open_easy pm pc (fromIntegral $ B.length ciphertext) pn pk
  in case e of
    0 -> Just message
    _ -> Nothing


secretBoxPrefix :: (ByteOp m c)
                => Key -> Nonce -> m -> c
secretBoxPrefix key nonce message =
  let nonceBs = fromNonce nonce
      ciphertext = secretBox key nonce message
  in B.append nonceBs ciphertext


secretBoxRandom :: (ByteOp m c)
                => Key -> m -> IO c
secretBoxRandom key message = do
  nonce <- newNonce
  return $ secretBoxPrefix key nonce message


openSecretBoxPrefix :: (ByteOp c m)
                    => Key -> c -> Maybe m
openSecretBoxPrefix (Key key) ciphertext =
  withLithium $ -- Ensure Sodium is initialized

  let clen = B.length ciphertext - nonceSize
      -- ^ Length of SecretBox ciphertext:
      --   ciphertext - nonce
      mlen = clen - macSize
      -- ^ Length of original plaintext:
      --   ciphertext - (nonce + mac)

      (e, message) = unsafePerformIO $
        B.allocRet mlen $ \pmessage ->
        -- Allocate plaintext
        withSecret key $ \pkey ->
        withByteArray ciphertext $ \pc ->
        do
          let pnonce = pc
              -- ^ Nonce begins at byte 0
              pctext = plusPtr pc nonceSize
              -- ^ Mac and encrypted message after nonce
          sodium_secretbox_open_easy pmessage
                                     pctext (fromIntegral clen)
                                     pnonce pkey
  in case e of
    0 -> Just message
    _ -> Nothing


secretBoxN :: forall l.
              ( KnownNats l (l + MacBytes) )
           => Key -> Nonce -> SecretN l -> BytesN (l + MacBytes)
secretBoxN (Key key) (Nonce nonce) secret = withLithium $
  let (_e, ciphertext) = unsafePerformIO $
        Sized.allocRet $ \pc ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withSecret secret $ \pm ->
        sodium_secretbox_easy pc pm (theNat @l) pn pk
  in ciphertext

openSecretBoxN :: forall l.
                  ( KnownNats l (l + MacBytes) )
               => Key -> Nonce -> BytesN (l + MacBytes) -> Maybe (SecretN l)
openSecretBoxN (Key k) (Nonce n) ciphertext = withLithium $
  let (e, message) = unsafePerformIO $
        allocSecretN $ \pm ->
        withSecret k $ \pk ->
        withByteArray n $ \pn ->
        withByteArray ciphertext $ \pc ->
        sodium_secretbox_open_easy pm pc (theNat @(l + MacBytes)) pn pk
  in case e of
    0 -> Just message
    _ -> Nothing


secretBoxDetached :: (ByteOp m c)
                  => Key -> Nonce -> m -> (c, Mac)
secretBoxDetached (Key key) (Nonce nonce) message = withLithium $
  let ((_e, mac), ciphertext) = unsafePerformIO $
        B.allocRet (B.length message) $ \pc ->
        Sized.allocRet $ \pmac ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray message $ \pm ->
        sodium_secretbox_detached pc pmac pm (fromIntegral $ B.length message) pn pk
  in (ciphertext, Mac mac)

openSecretBoxDetached :: (ByteOp c m)
                      => Key -> Nonce -> Mac -> c -> Maybe m
openSecretBoxDetached (Key key) (Nonce nonce) (Mac mac) ciphertext = withLithium $
  let (e, message) = unsafePerformIO $
        B.allocRet (B.length ciphertext) $ \pm ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray mac $ \pmac ->
        withByteArray ciphertext $ \pc ->
        sodium_secretbox_open_detached pm pc pmac (fromIntegral $ B.length ciphertext) pn pk
  in case e of
    0 -> Just message
    _ -> Nothing

secretBoxDetachedN :: forall l b. (KnownNat l, ByteArray b)
                   => Key -> Nonce -> SecretN l -> (Sized l b, Mac)
secretBoxDetachedN (Key key) (Nonce nonce) message = withLithium $
  let ((_e, mac), ciphertext) = unsafePerformIO $
        Sized.allocRet $ \pc ->
        Sized.allocRet $ \pmac ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withSecret message $ \pm ->
        sodium_secretbox_detached pc pmac pm (theNat @l) pn pk
  in (ciphertext, Mac mac)

openSecretBoxDetachedN :: forall l b. (KnownNat l, ByteArray b)
                       => Key -> Nonce -> Mac -> Sized l b -> Maybe (SecretN l)
openSecretBoxDetachedN (Key key) (Nonce nonce) (Mac mac) ciphertext = withLithium $
  let (e, message) = unsafePerformIO $
        allocSecretN $ \pm ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray mac $ \pmac ->
        withByteArray ciphertext $ \pc ->
        sodium_secretbox_open_detached pm pc pmac (theNat @l) pn pk
  in case e of
    0 -> Just message
    _ -> Nothing

{-
syntheticPersonal :: Bytes
syntheticPersonal = "sodium autononce"

syntheticNonce :: ByteArrayAccess a -> a -> a -> Nonce
syntheticNonce plaintext key =
  let hashKey = H.asKey $ fromKey key :: H.Key KeyBytes
      digest :: H.Digest NonceBytes
      digest = H.hashSaltPersonal plaintext
                                  (Just hashKey)
                                  Nothing
                                  (Just syntheticPersonal)
  in asNonce $ fromDigest digest


deterministicSecretBox :: ByteOp m c => Key -> m -> c
deterministicSecretBox (Key key) message =
  let nonce = syntheticNonce message $ fromSecretN key
      (_e, ciphertext) = unsafePerformIO $
        B.allocRet (B.length message + macSize) $ \pc ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray message $ \pm ->
        sodium_secretbox_easy pc pm (fromIntegral $ B.length message) pn pk
  in append (fromNonce nonce) ciphertext

openDeterministicSecretBox :: (ByteOp c m) => Key -> c -> Maybe m
openDeterministicSecretBox (Key k) ciphertext =
  let (nonceB, encrypted) = splitAt nonceSize ciphertext
      Just nonce = asNonce <$> asBytesN nonceBytes nonceB
      (e, message) = unsafePerformIO $
        B.allocRet (B.length ciphertext - macSize) $ \pm ->
        withSecret k $ \pk ->
        withByteArray n $ \pn ->
        withByteArray ciphertext $ \pc ->
        sodium_secretbox_open_easy pm pc (fromIntegral $ B.length ciphertext) pn pk
  in case e of
    0 -> Just message
    _ -> Nothing
-}

type KeyBytes = 32
keyBytes :: ByteSize KeyBytes
keyBytes = ByteSize

keySize :: Int
keySize = fromInteger $ fromIntegral sodium_secretbox_keybytes

type MacBytes = 16
macBytes :: ByteSize MacBytes
macBytes = ByteSize

macSize :: Int
macSize = fromInteger $ fromIntegral sodium_secretbox_macbytes

type NonceBytes = 24
nonceBytes :: ByteSize NonceBytes
nonceBytes = ByteSize

nonceSize :: Int
nonceSize = fromInteger $ fromIntegral sodium_secretbox_noncebytes
