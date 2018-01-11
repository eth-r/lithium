{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.Sign
Description : Ed25519 signatures made easy
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Sign
  ( SecretKey
  , asSecretKey
  , fromSecretKey

  , PublicKey
  , asPublicKey
  , fromPublicKey

  , Seed
  , asSeed
  , fromSeed

  , Keypair
  , asKeypair
  , fromKeypair

  , secretKey
  , publicKey

  , newKeypair
  , seedKeypair

  , toPublicKey
  , toSeed

  , Signature
  , asSignature
  , fromSignature

  , sign
  , openSigned

  , signDetached
  , verifyDetached

  , SecretKeyBytes
  , secretKeyBytes
  , secretKeySize

  , PublicKeyBytes
  , publicKeyBytes
  , publicKeySize

  , KeypairBytes
  , keypairBytes
  , keypairSize

  , SeedBytes
  , seedBytes
  , seedSize

  , SignatureBytes
  , signatureBytes
  , signatureSize
  ) where

import Foundation hiding (Signed)

import Data.ByteArray as B

import Crypto.Lithium.Internal.Sign
import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Unsafe.Types

import Control.DeepSeq
{-|
Opaque 'sign' secret key type, wrapping the sensitive data in 'ScrubbedBytes' to
reduce exposure to dangers.
-}
newtype SecretKey = S (SecretN SecretKeyBytes) deriving (Show, Eq, NFData)

{-|
Function for interpreting arbitrary bytes as a 'SecretKey'

Note that this allows insecure handling of key material. This function is only
exported in the "Crypto.Lithium.Unsafe.Sign" API.
-}
asSecretKey :: SecretN SecretKeyBytes -> SecretKey
asSecretKey = S

{-|
Function for converting a 'SecretKey' into an arbitrary byte array

Note that this allows insecure handling of key material. This function is only
exported in the "Crypto.Lithium.Unsafe.Sign" API.
-}
fromSecretKey :: SecretKey -> SecretN SecretKeyBytes
fromSecretKey (S k) = k


{-|
Opaque 'sign' public key type
-}
newtype PublicKey = P (BytesN PublicKeyBytes) deriving (Show, Eq, NFData)

{-|
Function for interpreting an arbitrary byte array as a 'PublicKey'


-}
asPublicKey :: BytesN PublicKeyBytes -> PublicKey
asPublicKey = P

fromPublicKey :: PublicKey -> BytesN PublicKeyBytes
fromPublicKey (P k) = k


data Keypair = KP SecretKey PublicKey deriving (Show, Eq)
instance NFData Keypair where
  rnf (KP s p) = rnf s `seq` rnf p

publicKey :: Keypair -> PublicKey
publicKey (KP _ pk) = pk

secretKey :: Keypair -> SecretKey
secretKey (KP sk _) = sk

asKeypair :: SecretN KeypairBytes -> Keypair
asKeypair s =
  let (sk, pk) = splitSecretN s
  in KP (S sk) (P $ revealN pk)

fromKeypair :: Keypair -> SecretN KeypairBytes
fromKeypair (KP (S sk) (P pk)) =
  appendN <$> sk <*> concealN pk

newtype Seed = Seed (SecretN SeedBytes) deriving (Show, Eq)
instance NFData Seed where
  rnf (Seed s) = rnf s

asSeed :: SecretN SeedBytes -> Seed
asSeed = Seed

fromSeed :: Seed -> SecretN SeedBytes
fromSeed (Seed s) = s

newtype Signature = Signature
  { fromSignature :: BytesN SignatureBytes } deriving (Show, Eq)

instance NFData Signature where
  rnf (Signature s) = rnf s

instance ByteArrayAccess Signature where
  length = const signatureSize
  withByteArray (Signature s) = withByteArray s

asSignature :: (ByteArrayAccess b) => N SignatureBytes b -> Signature
asSignature = Signature . convertN

newKeypair :: IO Keypair
newKeypair = withLithium $ do
  ((_e, sk), pk) <-
    allocRetN $ \ppk ->
    allocSecretN $ \psk ->
    sodium_sign_keypair ppk psk
  let sk' = S sk
      pk' = P pk
  return $ KP sk' pk'

seedKeypair :: Seed -> Keypair
seedKeypair (Seed s) = withLithium $
  let ((_e, sk), pk) = unsafePerformIO $
        allocRetN $ \ppk ->
        allocSecretN $ \psk ->
        withSecret s $ \ps ->
        sodium_sign_seed_keypair ppk psk ps
      sk' = S sk
      pk' = P pk
  in (KP sk' pk')

toPublicKey :: SecretKey -> PublicKey
toPublicKey (S sk) = withLithium $
  let (_e, pk) = unsafePerformIO $
        allocRetN $ \ppk ->
        withSecret sk $ \psk ->
        sodium_sign_sk_to_pk ppk psk
  in (P pk)

toSeed :: SecretKey -> Seed
toSeed (S sk) = withLithium $
  let (_e, seed) = unsafePerformIO $
        allocSecretN $ \pSeed ->
        withSecret sk $ \pSk ->
        sodium_sign_sk_to_seed pSeed pSk
  in (Seed seed)

sign :: ( ByteOp m s )
     => SecretKey -> m -> s
sign (S sk) message = withLithium $
  let mlen = B.length message
      mlenC = fromIntegral mlen
      slen = mlen + signatureSize
      (_e, signed) = unsafePerformIO $
        allocRet slen $ \psigned ->
        withSecret sk $ \pkey ->
        withByteArray message $ \pmessage ->
        sodium_sign psigned
                    nullPtr
                    pmessage mlenC
                    pkey
  in signed

openSigned :: forall m s.
              ( ByteOp s m )
           => PublicKey -> s -> Maybe m
openSigned (P pk) signed = withLithium $
  let slen = B.length signed
      mlen = slen - signatureSize
      slenC = fromIntegral slen
      (e, message) = unsafePerformIO $
        allocRet mlen $ \pmessage ->
        withByteArray pk $ \pkey ->
        withByteArray signed $ \psigned ->
        sodium_sign_open pmessage nullPtr psigned slenC pkey
  in case e of
    0 -> Just message
    _ -> Nothing

signDetached :: ( ByteArrayAccess m )
             => SecretKey -> m -> Signature
signDetached (S k) message = withLithium $
  let mlenC = fromIntegral $ B.length message
      (_e, signature) = unsafePerformIO $
        allocRetN $ \psignature ->
        withSecret k $ \pkey ->
        withByteArray message $ \pmessage ->
        sodium_sign_detached psignature nullPtr
                             pmessage mlenC
                             pkey
  in (Signature signature)

verifyDetached :: ( ByteArrayAccess m )
               => PublicKey -> Signature -> m -> Bool
verifyDetached (P k) (Signature signature) message = withLithium $
  let mlenC = fromIntegral $ B.length message
      e = unsafePerformIO $
        withByteArray k $ \pkey ->
        withByteArray signature $ \psignature ->
        withByteArray message $ \pmessage ->
        sodium_sign_verify_detached psignature
                                    pmessage mlenC
                                    pkey
  in case e of
    0 -> True
    _ -> False

type PublicKeyBytes = 32
publicKeyBytes :: ByteSize PublicKeyBytes
publicKeyBytes = ByteSize

publicKeySize :: Int
publicKeySize = fromIntegral sodium_sign_publickeybytes

type SecretKeyBytes = 64
secretKeyBytes :: ByteSize SecretKeyBytes
secretKeyBytes = ByteSize

secretKeySize :: Int
secretKeySize = fromIntegral sodium_sign_secretkeybytes

type KeypairBytes = SecretKeyBytes + PublicKeyBytes
keypairBytes :: ByteSize KeypairBytes
keypairBytes = ByteSize

keypairSize :: Int
keypairSize = secretKeySize + publicKeySize

type SignatureBytes = 64
signatureBytes :: ByteSize SignatureBytes
signatureBytes = ByteSize

signatureSize :: Int
signatureSize = fromIntegral sodium_sign_bytes

type SeedBytes = 32
seedBytes :: ByteSize SeedBytes
seedBytes = ByteSize

seedSize :: Int
seedSize = fromIntegral sodium_sign_seedbytes
