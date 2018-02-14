{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Unsafe.KeyExchange
  ( SecretKey(..)
  , asSecretKey
  , fromSecretKey

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
  , newSeed

  , SessionKeys(..)
  , clientSessionKeys
  , serverSessionKeys

  -- * Constants

  , PublicKeyBytes
  , publicKeyBytes
  , publicKeySize

  , SecretKeyBytes
  , secretKeyBytes
  , secretKeySize

  , SeedBytes
  , seedBytes
  , seedSize

  , SessionKeyBytes
  , sessionKeyBytes
  , sessionKeySize
  ) where

import Crypto.Lithium.Internal.KeyExchange
import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Unsafe.Types

import Control.DeepSeq
import Foundation
import Data.ByteArray as B
import Data.ByteArray.Sized as Sized

{-|
Opaque 'kx' secret key type, wrapping the sensitive data in 'ScrubbedBytes' to
reduce exposure to dangers.
-}
newtype SecretKey = SecretKey
  { unSecretKey :: SecretN SecretKeyBytes } deriving (Show, Eq, NFData)

{-|
Function for interpreting arbitrary bytes as a 'SecretKey'

Note that this allows insecure handling of key material. This function is only
exported in the "Crypto.Lithium.Unsafe.Kx" API.
-}
asSecretKey :: Decoder SecretKey
asSecretKey = decodeSecret SecretKey

{-|
Function for converting a 'SecretKey' into an arbitrary byte array

Note that this allows insecure handling of key material. This function is only
exported in the "Crypto.Lithium.Unsafe.Kx" API.
-}
fromSecretKey :: Encoder SecretKey
fromSecretKey = encodeSecret unSecretKey


{-|
Opaque 'kx' public key type
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
  Sized.append <$> sk <*> concealN pk

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

newSeed :: IO Seed
newSeed = Seed <$> randomSecretN



newKeypair :: IO Keypair
newKeypair = withLithium $ do
  ((_e, sk), pk) <-
    Sized.allocRet $ \ppk ->
    allocSecretN $ \psk ->
    sodium_kx_keypair ppk psk
  let sk' = SecretKey sk
      pk' = PublicKey pk
  return $ Keypair sk' pk'

seedKeypair :: Seed -> Keypair
seedKeypair (Seed s) = withLithium $
  let ((_e, sk), pk) = unsafePerformIO $
        Sized.allocRet $ \ppk ->
        allocSecretN $ \psk ->
        withSecret s $ \ps ->
        sodium_kx_seed_keypair ppk psk ps
      sk' = SecretKey sk
      pk' = PublicKey pk
  in Keypair sk' pk'


data SessionKeys = SessionKeys
  { rxKey :: SecretN SessionKeyBytes
  , txKey :: SecretN SessionKeyBytes
  } deriving (Show, Eq)

instance NFData SessionKeys where
  rnf (SessionKeys rx tx) = rnf rx `seq` rnf tx


clientSessionKeys :: Keypair -> PublicKey -> SessionKeys
clientSessionKeys (Keypair (SecretKey csk) (PublicKey cpk)) (PublicKey spk) =
  withLithium $

  let ((_e, rx), tx) = unsafePerformIO $
        allocSecretN $ \ptx ->
        allocSecretN $ \prx ->
        withSecret csk $ \pcsk ->
        withByteArray cpk $ \pcpk ->
        withByteArray spk $ \pspk ->
        sodium_kx_client_session_keys prx ptx
                                      pcpk pcsk
                                      pspk
  in SessionKeys rx tx


serverSessionKeys :: Keypair -> PublicKey -> SessionKeys
serverSessionKeys (Keypair (SecretKey ssk) (PublicKey spk)) (PublicKey cpk) =
  withLithium $

  let ((_e, rx), tx) = unsafePerformIO $
        allocSecretN $ \ptx ->
        allocSecretN $ \prx ->
        withSecret ssk $ \pssk ->
        withByteArray spk $ \pspk ->
        withByteArray cpk $ \pcpk ->
        sodium_kx_server_session_keys prx ptx
                                      pspk pssk
                                      pcpk
  in SessionKeys rx tx



type PublicKeyBytes = 32
publicKeyBytes :: ByteSize PublicKeyBytes
publicKeyBytes = ByteSize

publicKeySize :: Int
publicKeySize = fromIntegral sodium_kx_publickeybytes

type SecretKeyBytes = 32
secretKeyBytes :: ByteSize SecretKeyBytes
secretKeyBytes = ByteSize

secretKeySize :: Int
secretKeySize = fromIntegral sodium_kx_secretkeybytes

type SeedBytes = 32
seedBytes :: ByteSize SeedBytes
seedBytes = ByteSize

seedSize :: Int
seedSize = fromIntegral sodium_kx_seedbytes

type SessionKeyBytes = 32
sessionKeyBytes :: ByteSize SessionKeyBytes
sessionKeyBytes = ByteSize

sessionKeySize :: Int
sessionKeySize = fromIntegral sodium_kx_sessionkeybytes
