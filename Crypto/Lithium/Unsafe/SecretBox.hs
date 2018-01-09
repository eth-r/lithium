{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
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
Description : Symmetric-key encryption made easy
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.SecretBox
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

  , secretBox
  , openSecretBox

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

import Foundation hiding (splitAt)


newtype Key = Key (SecretN KeyBytes) deriving (Show, Eq, NFData)

asKey :: SecretN KeyBytes -> Key
asKey = Key

fromKey :: Key -> SecretN KeyBytes
fromKey (Key k) = k

-- instance IsSecretN Key KeyBytes where
--   toSecretN = fromKey
--   fromSecretN = asKey


newtype Nonce = Nonce (BytesN NonceBytes) deriving (Show, Eq, NFData)

asNonce :: BytesN NonceBytes -> Nonce
asNonce = Nonce

fromNonce :: Nonce -> BytesN NonceBytes
fromNonce (Nonce n) = n

-- instance IsBytesN Nonce NonceBytes where
--   toBytesN = fromNonce
--   fromBytesN = asNonce
--   withByteArray (Nonce n) = withBytesN n


newtype Mac = Mac (BytesN MacBytes) deriving (Show, Eq, NFData)

asMac :: BytesN MacBytes -> Mac
asMac = Mac

fromMac :: Mac -> BytesN MacBytes
fromMac (Mac m) = m

-- instance IsBytesN Mac MacBytes where
--   toBytesN = fromMac
--   fromBytesN = asMac
--   withByteArray (Mac n) = withBytesN n


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
secretBox (Key key) (Nonce nonce) message = withLithium $
  let (_e, ciphertext) = unsafePerformIO $
        allocRet (B.length message + macSize) $ \pc ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray message $ \pm ->
        sodium_secretbox_easy pc pm (fromIntegral $ B.length message) pn pk
  in ciphertext

openSecretBox :: (ByteOp c m)
              => Key -> Nonce -> c -> Maybe m
openSecretBox (Key k) (Nonce n) ciphertext = withLithium $
  let (e, message) = unsafePerformIO $
        allocRet (B.length ciphertext - macSize) $ \pm ->
        withSecret k $ \pk ->
        withByteArray n $ \pn ->
        withByteArray ciphertext $ \pc ->
        sodium_secretbox_open_easy pm pc (fromIntegral $ B.length ciphertext) pn pk
  in case e of
    0 -> Just message
    _ -> Nothing


secretBoxN :: forall l.
              ( KnownNats l (l + MacBytes) )
           => Key -> Nonce -> SecretN l -> BytesN (l + MacBytes)
secretBoxN (Key key) (Nonce nonce) secret = withLithium $
  let len = ByteSize :: ByteSize l
      -- clen = ByteSize :: ByteSize (l + MacBytes)
      (_e, ciphertext) = unsafePerformIO $
        allocRetN $ \pc ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withSecret secret $ \pm ->
        sodium_secretbox_easy pc pm (asNum len) pn pk
  in ciphertext

openSecretBoxN :: forall l.
                  ( KnownNats l (l + MacBytes) )
               => Key -> Nonce -> BytesN (l + MacBytes) -> Maybe (SecretN l)
openSecretBoxN (Key k) (Nonce n) ciphertext = withLithium $
  let -- len = ByteSize :: ByteSize l
      clen = ByteSize :: ByteSize (l + MacBytes)
      (e, message) = unsafePerformIO $
        allocSecretN $ \pm ->
        withSecret k $ \pk ->
        withByteArray n $ \pn ->
        withByteArray ciphertext $ \pc ->
        sodium_secretbox_open_easy pm pc (asNum clen) pn pk
  in case e of
    0 -> Just message
    _ -> Nothing


secretBoxDetached :: (ByteOp m c)
                  => Key -> Nonce -> m -> (c, Mac)
secretBoxDetached (Key key) (Nonce nonce) message = withLithium $
  let ((_e, mac), ciphertext) = unsafePerformIO $
        allocRet (B.length message) $ \pc ->
        allocRetN $ \pmac ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray message $ \pm ->
        sodium_secretbox_detached pc pmac pm (fromIntegral $ B.length message) pn pk
  in (ciphertext, Mac mac)

openSecretBoxDetached :: (ByteOp c m)
                      => Key -> Nonce -> Mac -> c -> Maybe m
openSecretBoxDetached (Key key) (Nonce nonce) (Mac mac) ciphertext = withLithium $
  let (e, message) = unsafePerformIO $
        allocRet (B.length ciphertext) $ \pm ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray mac $ \pmac ->
        withByteArray ciphertext $ \pc ->
        sodium_secretbox_open_detached pm pc pmac (fromIntegral $ B.length ciphertext) pn pk
  in case e of
    0 -> Just message
    _ -> Nothing

secretBoxDetachedN :: forall l b. (KnownNat l, ByteArray b)
                   => Key -> Nonce -> SecretN l -> (N l b, Mac)
secretBoxDetachedN (Key key) (Nonce nonce) message = withLithium $
  let len = ByteSize :: ByteSize l
      ((_e, mac), ciphertext) = unsafePerformIO $
        allocRetN $ \pc ->
        allocRetN $ \pmac ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withSecret message $ \pm ->
        sodium_secretbox_detached pc pmac pm (asNum len) pn pk
  in (ciphertext, Mac mac)

openSecretBoxDetachedN :: forall l b. (KnownNat l, ByteArray b)
                       => Key -> Nonce -> Mac -> N l b -> Maybe (SecretN l)
openSecretBoxDetachedN (Key key) (Nonce nonce) (Mac mac) ciphertext = withLithium $
  let len = ByteSize :: ByteSize l
      (e, message) = unsafePerformIO $
        allocSecretN $ \pm ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray mac $ \pmac ->
        withByteArray ciphertext $ \pc ->
        sodium_secretbox_open_detached pm pc pmac (asNum len) pn pk
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
        allocRet (B.length message + macSize) $ \pc ->
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
        allocRet (B.length ciphertext - macSize) $ \pm ->
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
