{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.Sign
Description : Ed25519 signatures
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Sign
  ( SecretKey(..)
  , asSecretKey
  , fromSecretKey

  , PublicKey(..)
  , asPublicKey
  , fromPublicKey

  , Seed(..)
  , asSeed
  , fromSeed

  , newSeed

  , Keypair(..)
  , asKeypair
  , fromKeypair

  , newKeypair
  , seedKeypair

  , toPublicKey
  , toSeed

  , Signature(..)
  , asSignature
  , fromSignature

  , sign
  , openSigned

  , signDetached
  , verifyDetached

  -- * Constants
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
import Data.ByteArray.Sized as Sized

import Crypto.Lithium.Internal.Sign
import Crypto.Lithium.Internal.Util

import Control.DeepSeq
{-|
Opaque 'sign' secret key type, wrapping the sensitive data in 'ScrubbedBytes' to
reduce exposure to dangers.
-}
newtype SecretKey = SecretKey
  { unSecretKey :: SecretN SecretKeyBytes } deriving (Show, Eq, NFData)

{-|
Function for interpreting arbitrary bytes as a 'SecretKey'

Note that this allows insecure handling of key material. This function is only
exported in the "Crypto.Lithium.Unsafe.Sign" API.
-}
asSecretKey :: Decoder SecretKey
asSecretKey = decodeSecret SecretKey

{-|
Function for converting a 'SecretKey' into an arbitrary byte array

Note that this allows insecure handling of key material. This function is only
exported in the "Crypto.Lithium.Unsafe.Sign" API.
-}
fromSecretKey :: Encoder SecretKey
fromSecretKey = encodeSecret unSecretKey


{-|
Opaque 'sign' public key type
-}
newtype PublicKey = PublicKey
  { unPublicKey :: BytesN PublicKeyBytes } deriving (Show, Eq, Ord, NFData, ByteArrayAccess)

instance Plaintext PublicKey where
  toPlaintext bs = do
    bsN <- toPlaintext bs
    return $ PublicKey bsN
  fromPlaintext (PublicKey k) = fromPlaintext k
  withPlaintext (PublicKey k) = withPlaintext k
  plaintextLength _ = publicKeySize

{-|
Function for interpreting an arbitrary byte array as a 'PublicKey'
-}
asPublicKey :: Decoder PublicKey
asPublicKey = decodeWith PublicKey

{-|
Encode a public key as a byte array
-}
fromPublicKey :: Encoder PublicKey
fromPublicKey = encodeWith unPublicKey

{-|
Combined public and secret key
-}
data Keypair = Keypair
  { secretKey :: SecretKey
  , publicKey :: PublicKey
  } deriving (Show, Eq)

instance NFData Keypair where
  rnf (Keypair s p) = rnf s `seq` rnf p

makeKeypair :: SecretN KeypairBytes -> Keypair
makeKeypair s =
  let (sk, pk) = splitSecretN s
  in Keypair (SecretKey sk) (PublicKey $ revealN pk)

unKeypair :: Keypair -> SecretN KeypairBytes
unKeypair (Keypair (SecretKey sk) (PublicKey pk)) =
  Sized.append <$> sk <*> concealN pk

asKeypair :: Decoder Keypair
asKeypair = decodeSecret makeKeypair

fromKeypair :: Encoder Keypair
fromKeypair = encodeSecret unKeypair

{-|
Seed for deriving keypairs from
-}
newtype Seed = Seed
  { unSeed :: SecretN SeedBytes } deriving (Show, Eq)
instance NFData Seed where
  rnf (Seed s) = rnf s

{-|
Generate new seed for keypair derivation
-}
newSeed :: IO Seed
newSeed = Seed <$> randomSecretN

{-|
Convert a secret byte array to a seed
-}
asSeed :: Decoder Seed
asSeed = decodeSecret Seed

{-|
Convert a seed to a secret byte array
-}
fromSeed :: Encoder Seed
fromSeed = encodeSecret unSeed

newtype Signature = Signature
  { unSignature :: BytesN SignatureBytes } deriving (Show, Eq, Ord)

instance NFData Signature where
  rnf (Signature s) = rnf s

instance ByteArrayAccess Signature where
  length = const signatureSize
  withByteArray (Signature s) = withByteArray s

instance Plaintext Signature where
  toPlaintext bs = do
    bsN <- toPlaintext bs
    return $ Signature bsN
  fromPlaintext = fromPlaintext . unSignature

asSignature :: Decoder Signature
asSignature = decodeWith Signature

fromSignature :: Encoder Signature
fromSignature = encodeWith unSignature

{-|
Generate new keypair
-}
newKeypair :: IO Keypair
newKeypair = withLithium $ do
  ((_e, sk), pk) <-
    Sized.allocRet $ \ppk ->
    allocSecretN $ \psk ->
    sodium_sign_keypair ppk psk
  let sk' = SecretKey sk
      pk' = PublicKey pk
  return $ Keypair sk' pk'

{-|
Derive keypair from seed generated earlier
-}
seedKeypair :: Seed -> Keypair
seedKeypair (Seed s) = withLithium $
  let ((_e, sk), pk) = unsafePerformIO $
        Sized.allocRet $ \ppk ->
        allocSecretN $ \psk ->
        withSecret s $ \ps ->
        sodium_sign_seed_keypair ppk psk ps
      sk' = SecretKey sk
      pk' = PublicKey pk
  in Keypair sk' pk'

{-|
Derive the public key corresponding to a secret key
-}
toPublicKey :: SecretKey -> PublicKey
toPublicKey (SecretKey sk) = withLithium $
  let (_e, pk) = unsafePerformIO $
        Sized.allocRet $ \ppk ->
        withSecret sk $ \psk ->
        sodium_sign_sk_to_pk ppk psk
  in PublicKey pk

{-|
Derive the seed a given secret key can be generated from
-}
toSeed :: SecretKey -> Seed
toSeed (SecretKey sk) = withLithium $
  let (_e, seed) = unsafePerformIO $
        allocSecretN $ \pSeed ->
        withSecret sk $ \pSk ->
        sodium_sign_sk_to_seed pSeed pSk
  in Seed seed

{-|
Sign a message, attaching the signature to it
-}
sign :: ( ByteOp m s )
     => SecretKey -> m -> s
sign (SecretKey sk) message = withLithium $
  let mlen = B.length message
      mlenC = fromIntegral mlen
      slen = mlen + signatureSize
      (_e, signed) = unsafePerformIO $
        B.allocRet slen $ \psigned ->
        withSecret sk $ \pkey ->
        withByteArray message $ \pmessage ->
        sodium_sign psigned
                    nullPtr
                    pmessage mlenC
                    pkey
  in signed

{-|
Check the signature of a signed message, returning the message if valid
-}
openSigned :: forall m s.
              ( ByteOp s m )
           => PublicKey -> s -> Maybe m
openSigned (PublicKey pk) signed = withLithium $
  let slen = B.length signed
      mlen = slen - signatureSize
      slenC = fromIntegral slen
      (e, message) = unsafePerformIO $
        B.allocRet mlen $ \pmessage ->
        withByteArray pk $ \pkey ->
        withByteArray signed $ \psigned ->
        sodium_sign_open pmessage nullPtr psigned slenC pkey
  in case e of
    0 -> Just message
    _ -> Nothing

{-|
Sign a message, generating a 'Signature' separate from the message
-}
signDetached :: ( ByteArrayAccess m )
             => SecretKey -> m -> Signature
signDetached (SecretKey k) message = withLithium $
  let mlenC = fromIntegral $ B.length message
      (_e, signature) = unsafePerformIO $
        Sized.allocRet $ \psignature ->
        withSecret k $ \pkey ->
        withByteArray message $ \pmessage ->
        sodium_sign_detached psignature nullPtr
                             pmessage mlenC
                             pkey
  in Signature signature

{-|
Verify a detached signature
-}
verifyDetached :: ( ByteArrayAccess m )
               => PublicKey -> Signature -> m -> Bool
verifyDetached (PublicKey k) (Signature signature) message = withLithium $
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

-- | Length of a 'PublicKey' as a type-level constant
type PublicKeyBytes = 32
-- | Public key length as a proxy value
publicKeyBytes :: ByteSize PublicKeyBytes
publicKeyBytes = ByteSize
-- | Public key length as a regular value
publicKeySize :: Int
publicKeySize = fromIntegral sodium_sign_publickeybytes

-- | Length of a 'SecretKey' as a type-level constant
type SecretKeyBytes = 64
-- | Secret key length as a proxy value
secretKeyBytes :: ByteSize SecretKeyBytes
secretKeyBytes = ByteSize
-- | Secret key length as a regular value
secretKeySize :: Int
secretKeySize = fromIntegral sodium_sign_secretkeybytes

-- | Length of a combined 'Keypair' as a type-level constant
type KeypairBytes = SecretKeyBytes + PublicKeyBytes
-- | Keypair length as a proxy value
keypairBytes :: ByteSize KeypairBytes
keypairBytes = ByteSize
-- | Keypair length as a regular value
keypairSize :: Int
keypairSize = secretKeySize + publicKeySize

-- | Length of a 'Signature' as a type-level constant
type SignatureBytes = 64
-- | Signature length as a proxy value
signatureBytes :: ByteSize SignatureBytes
signatureBytes = ByteSize
-- | Signature length as a regular value
signatureSize :: Int
signatureSize = fromIntegral sodium_sign_bytes

-- | Length of a 'Seed' as a type-level constant
type SeedBytes = 32
-- | Seed length as a proxy value
seedBytes :: ByteSize SeedBytes
seedBytes = ByteSize
-- | Seed length as a regular value
seedSize :: Int
seedSize = fromIntegral sodium_sign_seedbytes
