{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE FlexibleContexts #-}
{-# OPTIONS_HADDOCK hide #-}
{-|
Module      : Crypto.Lithium.Unsafe.Aead
Description : XChaCha20Poly1305-IETF AEAD
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Aead
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

  , aead
  , openAead

  , aeadPrefix
  , openAeadPrefix
  , aeadRandom

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

import Crypto.Lithium.Internal.Aead as Aead
import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Unsafe.Types

import Data.ByteArray as B
import Data.ByteArray.Sized as Sized

import Control.DeepSeq
import Foundation

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

{-|
Generate a new 'aead' key
-}
newKey :: IO Key
newKey = withLithium $ do
  (_e, k) <-
    allocSecretN $ \pk ->
    keygen pk
  return $ Key k

newNonce :: IO Nonce
newNonce = Nonce <$> randomBytesN


aead :: (ByteOps m a c)
     => Key -> Nonce -> m -> a -> c
aead (Key key) (Nonce nonce) message aad =
  withLithium $

  let mlen = B.length message
      -- ^ Length of message
      clen = mlen + macSize
      -- ^ Length of ciphertext with mac
      alen = B.length aad
      -- ^ Length of associated data

      (_e, ciphertext) = unsafePerformIO $
        B.allocRet clen $ \pc ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray message $ \pm ->
        withByteArray aad $ \pa ->
        Aead.encrypt pc
                     pm mlen
                     pa alen
                     pn pk
  in ciphertext

openAead :: (ByteOps c a m)
         => Key -> Nonce -> c -> a -> Maybe m
openAead (Key k) (Nonce n) ciphertext aad =
  withLithium $ -- Ensure Sodium is initialized

  let (e, message) = unsafePerformIO $
        B.allocRet (B.length ciphertext - macSize) $ \pm ->
        withSecret k $ \pk ->
        withByteArray n $ \pn ->
        withByteArray ciphertext $ \pc ->
        withByteArray aad $ \pa ->
        Aead.decrypt pm
                     pc (fromIntegral $ B.length ciphertext)
                     pa (fromIntegral $ B.length aad)
                     pn pk
  in case e of
    0 -> Just message
    _ -> Nothing


aeadPrefix :: (ByteOps m a c)
           => Key -> Nonce -> m -> a -> c
aeadPrefix key nonce message aad =
  withLithium $ -- Ensure Sodium is initialized
  let nonceBs = B.convert $ fromNonce nonce
      ciphertext = aead key nonce message aad
  in B.append nonceBs ciphertext


openAeadPrefix :: (ByteOps ciphertext aad message)
               => Key -> ciphertext -> aad -> Maybe message
openAeadPrefix (Key key) ciphertext aad =
  withLithium $ -- Ensure Sodium is initialized

  let clen = B.length ciphertext - nonceSize
      -- ^ Length of Aead ciphertext:
      --   ciphertext - nonce
      mlen = clen - macSize
      -- ^ Length of original plaintext:
      --   ciphertext - (nonce + mac)
      alen = B.length aad
      -- ^ Length of associated data

      (e, message) = unsafePerformIO $
        B.allocRet mlen $ \pmessage ->
        withSecret key $ \pkey ->
        withByteArray ciphertext $ \pc ->
        withByteArray aad $ \padata ->
        do
          let pnonce = pc
              -- ^ Nonce begins at byte 0
              pctext = plusPtr pc nonceSize
              -- ^ Mac and encrypted message after nonce
          Aead.decrypt pmessage
                       pctext clen
                       padata alen
                       pnonce pkey
  in case e of
    0 -> Just message
    _ -> Nothing


aeadRandom :: (ByteOps m a c)
           => Key -> m -> a -> IO c
aeadRandom key message aad = do
  nonce <- newNonce
  return $ aeadPrefix key nonce message aad


aeadN :: forall l a.
         ( KnownNats l (l + MacBytes)
         , ByteArrayAccess a)
      => Key -> Nonce -> SecretN l -> a -> BytesN (l + MacBytes)
aeadN (Key key) (Nonce nonce) secret aad =
  withLithium $

  let mlen = theNat @l
      alen = B.length aad

      (_e, ciphertext) = unsafePerformIO $
        Sized.allocRet $ \pc ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withSecret secret $ \pm ->
        withByteArray aad $ \pa ->
        Aead.encrypt pc
                     pm mlen
                     pa alen
                     pn pk
  in ciphertext

openAeadN :: forall l a.
             ( KnownNats l (l + MacBytes)
             , ByteArrayAccess a)
          => Key -> Nonce -> BytesN (l + MacBytes) -> a -> Maybe (SecretN l)
openAeadN (Key k) (Nonce n) ciphertext aad =
  withLithium $

  let mlen = theNat @l
      clen = mlen + macSize
      alen = B.length aad
      (e, message) = unsafePerformIO $
        allocSecretN $ \pm ->
        withSecret k $ \pk ->
        withByteArray n $ \pn ->
        withByteArray ciphertext $ \pc ->
        withByteArray aad $ \pa ->
        Aead.decrypt pm
                     pc clen
                     pa alen
                     pn pk
  in case e of
    0 -> Just message
    _ -> Nothing


aeadDetached :: (ByteOps m a c)
             => Key -> Nonce -> m -> a -> (c, Mac)
aeadDetached (Key key) (Nonce nonce) message aad =
  withLithium $

  let mlen = B.length message
      alen = B.length aad

      ((_e, mac), ciphertext) = unsafePerformIO $
        B.allocRet (B.length message) $ \pc ->
        Sized.allocRet $ \pmac ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray message $ \pm ->
        withByteArray aad $ \pa ->
        Aead.detached pc pmac
                      pm mlen
                      pa alen
                      pn pk
  in (ciphertext, Mac mac)

openAeadDetached :: (ByteOps c a m)
                 => Key -> Nonce -> Mac -> c -> a -> Maybe m
openAeadDetached (Key key) (Nonce nonce) (Mac mac) ciphertext aad =
  withLithium $

  let clen = B.length ciphertext
      alen = B.length aad

      (e, message) = unsafePerformIO $
        B.allocRet clen $ \pm ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray mac $ \pmac ->
        withByteArray ciphertext $ \pc ->
        withByteArray aad $ \pa ->
        Aead.openDetached pm
                          pc clen
                          pmac pa alen
                          pn pk
  in case e of
    0 -> Just message
    _ -> Nothing

aeadDetachedN :: forall l a. (KnownNat l, ByteArrayAccess a)
              => Key -> Nonce -> SecretN l -> a -> (BytesN l, Mac)
aeadDetachedN (Key key) (Nonce nonce) message aad =
  withLithium $

  let mlen = theNat @l
      alen = B.length aad

      ((_e, mac), ciphertext) = unsafePerformIO $
        Sized.allocRet $ \pc ->
        Sized.allocRet $ \pmac ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withSecret message $ \pm ->
        withByteArray aad $ \pa ->
        Aead.detached pc pmac
                      pm mlen
                      pa alen
                      pn pk
  in (ciphertext, Mac mac)

openAeadDetachedN :: forall l a. (KnownNat l, ByteArrayAccess a)
                  => Key -> Nonce -> Mac -> BytesN l -> a -> Maybe (SecretN l)
openAeadDetachedN (Key key) (Nonce nonce) (Mac mac) ciphertext aad =
  withLithium $

  let clen = theNat @l
      alen = B.length aad

      (e, message) = unsafePerformIO $
        allocSecretN $ \pm ->
        withSecret key $ \pk ->
        withByteArray nonce $ \pn ->
        withByteArray mac $ \pmac ->
        withByteArray ciphertext $ \pc ->
        withByteArray aad $ \pa ->
        Aead.openDetached pm
                          pc clen
                          pmac pa alen
                          pn pk
  in case e of
    0 -> Just message
    _ -> Nothing

-- | Length of a 'Key' as a type-level constant
type KeyBytes = 32
-- | Key length as a proxy value
keyBytes :: ByteSize KeyBytes
keyBytes = ByteSize
-- | Key length as a regular value
keySize :: Int
keySize = fromIntegral sodium_aead_keybytes

-- | Length of a 'Mac' as a type-level constant
type MacBytes = 16
-- | Mac length as a proxy value
macBytes :: ByteSize MacBytes
macBytes = ByteSize
-- | Mac length as a regular value
macSize :: Int
macSize = fromIntegral sodium_aead_macbytes

-- | Length of a 'Nonce' as a type-level constant
type NonceBytes = 24
-- | Nonce length as a proxy value
nonceBytes :: ByteSize NonceBytes
nonceBytes = ByteSize
-- | Nonce length as a regular value
nonceSize :: Int
nonceSize = fromIntegral sodium_aead_noncebytes
