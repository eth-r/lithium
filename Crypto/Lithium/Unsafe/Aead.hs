{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.Aead
Description : AEAD made easy
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Aead
  ( Key
  , asKey
  , fromKey
  , newKey

  , Nonce
  , asNonce
  , fromNonce
  , newNonce

  , Mac
  , asMac
  , fromMac

  , aead
  , openAead

  , aeadDetached
  , openAeadDetached

  , aeadN
  , openAeadN

  , aeadDetachedN
  , openAeadDetachedN

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

import Crypto.Lithium.Internal.Aead
import Crypto.Lithium.Internal.Util

import Control.DeepSeq
import Foundation hiding (splitAt)

newtype Key = Key (SecretN KeyBytes) deriving (Show, Eq, NFData)

asKey :: SecretN KeyBytes -> Key
asKey = Key

fromKey :: Key -> SecretN KeyBytes
fromKey (Key k) = k

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

newtype AeadBox m t = AeadBox { unAeadBox :: t } deriving (Show, Eq, NFData)

newKey :: IO Key
newKey = do
  (_e, k) <-
    allocSecretN keyBytes $ \pk ->
    sodium_aead_keygen pk
  return $ Key k

newNonce :: IO Nonce
newNonce = Nonce <$> randomBytesN nonceBytes

aead :: (ByteOps m a c)
     => Key -> Nonce -> m -> a -> c
aead (Key key) (Nonce nonce) message aad =
  let (_e, ciphertext) = unsafePerformIO $
        allocRet (bLength message + macSize) $ \pc ->
        withSecretN key $ \pk ->
        withBytesN nonce $ \pn ->
        withByteArray message $ \pm ->
        withByteArray aad $ \pa ->
        sodium_aead_encrypt pc nullPtr
                            pm (fromIntegral $ bLength message)
                            pa (fromIntegral $ bLength aad)
                            nullPtr pn pk
  in ciphertext

openAead :: (ByteOps c a m)
         => Key -> Nonce -> c -> a -> Maybe m
openAead (Key k) (Nonce n) ciphertext aad =
  let (e, message) = unsafePerformIO $
        allocRet (bLength ciphertext - macSize) $ \pm ->
        withSecretN k $ \pk ->
        withBytesN n $ \pn ->
        withByteArray ciphertext $ \pc ->
        withByteArray aad $ \pa ->
        sodium_aead_decrypt pm nullPtr nullPtr
                            pc (fromIntegral $ bLength ciphertext)
                            pa (fromIntegral $ bLength aad)
                            pn pk
  in case e of
    0 -> Just message
    _ -> Nothing


aeadN :: forall l a.
              ( KnownNats l (l + MacBytes)
              , ByteArrayAccess a)
           => Key -> Nonce -> SecretN l -> a -> BytesN (l + MacBytes)
aeadN (Key key) (Nonce nonce) secret aad =
  let len = ByteSize :: ByteSize l
      clen = ByteSize :: ByteSize (l + MacBytes)
      (_e, ciphertext) = unsafePerformIO $
        allocBytesN clen $ \pc ->
        withSecretN key $ \pk ->
        withBytesN nonce $ \pn ->
        withSecretN secret $ \pm ->
        withByteArray aad $ \pa ->
        sodium_aead_encrypt pc nullPtr
                            pm (asNum len)
                            pa (fromIntegral $ bLength aad)
                            nullPtr pn pk
  in ciphertext

openAeadN :: forall l a.
                  ( KnownNats l (l + MacBytes)
                  , ByteArrayAccess a)
               => Key -> Nonce -> BytesN (l + MacBytes) -> a -> Maybe (SecretN l)
openAeadN (Key k) (Nonce n) ciphertext aad =
  let len = ByteSize :: ByteSize l
      clen = ByteSize :: ByteSize (l + MacBytes)
      (e, message) = unsafePerformIO $
        allocSecretN len $ \pm ->
        withSecretN k $ \pk ->
        withBytesN n $ \pn ->
        withBytesN ciphertext $ \pc ->
        withByteArray aad $ \pa ->
        sodium_aead_decrypt pm nullPtr nullPtr
                            pc (asNum clen)
                            pa (fromIntegral $ bLength aad)
                            pn pk
  in case e of
    0 -> Just message
    _ -> Nothing


aeadDetached :: (ByteOps m a c)
             => Key -> Nonce -> m -> a -> (c, Mac)
aeadDetached (Key key) (Nonce nonce) message aad =
  let ((_e, mac), ciphertext) = unsafePerformIO $
        allocRet (bLength message) $ \pc ->
        allocBytesN macBytes $ \pmac ->
        withSecretN key $ \pk ->
        withBytesN nonce $ \pn ->
        withByteArray message $ \pm ->
        withByteArray aad $ \pa ->
        sodium_aead_detached pc pmac nullPtr
                             pm (fromIntegral $ bLength message)
                             pa (fromIntegral $ bLength aad)
                             nullPtr pn pk
  in (ciphertext, Mac mac)

openAeadDetached :: (ByteOps c a m)
                 => Key -> Nonce -> Mac -> c -> a -> Maybe m
openAeadDetached (Key key) (Nonce nonce) (Mac mac) ciphertext aad =
  let (e, message) = unsafePerformIO $
        allocRet (bLength ciphertext) $ \pm ->
        withSecretN key $ \pk ->
        withBytesN nonce $ \pn ->
        withBytesN mac $ \pmac ->
        withByteArray ciphertext $ \pc ->
        withByteArray aad $ \pa ->
        sodium_aead_open_detached pm nullPtr
                                  pc (fromIntegral $ bLength ciphertext)
                                  pmac pa (fromIntegral $ bLength aad)
                                  pn pk
  in case e of
    0 -> Just message
    _ -> Nothing

aeadDetachedN :: forall l a. (KnownNat l, ByteArrayAccess a)
              => Key -> Nonce -> SecretN l -> a -> (BytesN l, Mac)
aeadDetachedN (Key key) (Nonce nonce) message aad =
  let len = ByteSize :: ByteSize l
      ((_e, mac), ciphertext) = unsafePerformIO $
        allocBytesN len $ \pc ->
        allocBytesN macBytes $ \pmac ->
        withSecretN key $ \pk ->
        withBytesN nonce $ \pn ->
        withSecretN message $ \pm ->
        withByteArray aad $ \pa ->
        sodium_aead_detached pc pmac nullPtr
                             pm (asNum len)
                             pa (fromIntegral $ bLength aad)
                             nullPtr pn pk
  in (ciphertext, Mac mac)

openAeadDetachedN :: forall l a. (KnownNat l, ByteArrayAccess a)
                  => Key -> Nonce -> Mac -> BytesN l -> a -> Maybe (SecretN l)
openAeadDetachedN (Key key) (Nonce nonce) (Mac mac) ciphertext aad =
  let len = ByteSize :: ByteSize l
      (e, message) = unsafePerformIO $
        allocSecretN len $ \pm ->
        withSecretN key $ \pk ->
        withBytesN nonce $ \pn ->
        withBytesN mac $ \pmac ->
        withBytesN ciphertext $ \pc ->
        withByteArray aad $ \pa ->
        sodium_aead_open_detached pm nullPtr
                                  pc (asNum len)
                                  pmac pa (fromIntegral $ bLength aad)
                                  pn pk
  in case e of
    0 -> Just message
    _ -> Nothing

type KeyBytes = 32
keyBytes :: ByteSize KeyBytes
keyBytes = ByteSize

keySize :: Int
keySize = fromInteger $ fromIntegral sodium_aead_keybytes

type MacBytes = 16
macBytes :: ByteSize MacBytes
macBytes = ByteSize

macSize :: Int
macSize = fromInteger $ fromIntegral sodium_aead_macbytes

type NonceBytes = 24
nonceBytes :: ByteSize NonceBytes
nonceBytes = ByteSize

nonceSize :: Int
nonceSize = fromInteger $ fromIntegral sodium_aead_noncebytes
