{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_HADDOCK show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.Password
Description : Argon2 password hash
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Password
  ( Salt(..)
  , asSalt
  , fromSalt
  , newSalt

  -- * Password storage
  , PasswordString(..)
  , storePassword
  , verifyPassword
  , needsRehash

  -- * Key derivation from passwords
  , derive
  , deriveSecretN

  -- * Protecting secrets with passwords

  -- , PasswordProtected(..)
  -- , passwordProtect
  -- , passwordOpen

  -- * Hashing policy
  , Policy(..)
  , interactivePolicy
  , moderatePolicy
  , sensitivePolicy

  , Opslimit
  , opslimit
  , getOpslimit

  , minOpslimit
  , maxOpslimit

  , opslimitInteractive
  , opslimitModerate
  , opslimitSensitive

  , Memlimit
  , memlimit
  , getMemlimit

  , minMemlimit
  , maxMemlimit

  , memlimitInteractive
  , memlimitModerate
  , memlimitSensitive

  , Algorithm
  , algorithm
  , getAlgorithm

  , defaultAlgorithm

  , KnownAlgorithm(..)

  -- * Constants
  , SaltBytes
  , saltBytes
  , saltSize

  , PasswordStringBytes
  , passwordStringBytes
  , passwordStringSize

  , TagBytes
  , tagBytes
  , tagSize
  ) where

import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Internal.Password as I

import Crypto.Lithium.Unsafe.SecretBox as S
import Crypto.Lithium.Unsafe.Derive (Deriveable(..))
import Crypto.Lithium.Unsafe.Types
import Data.ByteArray.Sized as Sized

import Foundation
import Control.DeepSeq

-- import Data.Maybe (fromJust)
import Data.ByteArray as B
-- import Data.ByteString as BS

{-|
Salt for hashing passwords
-}
newtype Salt = Salt
  { unSalt :: BytesN SaltBytes } deriving (Eq, Ord, Show, ByteArrayAccess, NFData)

asSalt :: Decoder Salt
asSalt = decodeWith Salt

fromSalt :: Encoder Salt
fromSalt = encodeWith unSalt

newSalt :: IO Salt
newSalt = Salt <$> randomBytesN

{-$passwordStorage

Lithium provides a simple API for storing and verifying passwords.

-}

{-|
Verification string for stored passwords
-}
newtype PasswordString = PasswordString
  { unPasswordString :: BytesN PasswordStringBytes
  } deriving (Eq, Ord, Show, ByteArrayAccess, NFData)

storePassword :: ByteArrayAccess p => Policy -> p -> IO PasswordString
storePassword policy pw =
  withLithium $ do

  let (ops, mem, _alg) = unpackPolicy policy
      pwlen = fromIntegral $ B.length pw

  (e, pwString) <-
    Sized.allocRet $ \pstring ->
    withByteArray pw $ \ppw ->
    sodium_pwhash_str pstring
                      ppw pwlen
                      ops mem
  case e of
    0 -> return (PasswordString pwString)
    _ -> error "failure"

verifyPassword :: ByteArrayAccess p => PasswordString -> p -> Bool
verifyPassword (PasswordString str) pw =
  withLithium $

  let pwlen = fromIntegral $ B.length pw
      e = unsafePerformIO $
        withByteArray str $ \pstring ->
        withByteArray pw $ \ppw ->
        sodium_pwhash_str_verify pstring
                                 ppw pwlen
  in case e of
    0 -> True
    _ -> False

needsRehash :: Policy -> PasswordString -> Bool
needsRehash policy (PasswordString str) =
  withLithium $

  let (ops, mem, _alg) = unpackPolicy policy
      e = unsafePerformIO $
        withByteArray str $ \pstring ->
        sodium_pwhash_str_needs_rehash pstring
                                       ops mem
  in case e of
    0 -> False
    _ -> True


deriveSecretN :: forall l pw.
                 (KnownNat l, ByteArrayAccess pw)
              => pw -> Salt -> Policy -> SecretN l
deriveSecretN password (Salt salt) policy=
  withLithium $
  let keyLength = theNat @l
      (ops, mem, alg) = unpackPolicy policy
      (e, hashed) = unsafePerformIO $
        allocSecretN $ \pkey ->
        withByteArray password $ \ppassword ->
        withByteArray salt $ \psalt ->
        sodium_pwhash pkey keyLength
                      ppassword (fromIntegral $ B.length password)
                      psalt
                      (fromIntegral ops)
                      (fromIntegral mem)
                      (fromIntegral $ fromEnum alg)
  in case e of
    0 -> hashed
    -- TODO: make this not suck
    _ -> error "out of memory"

derive :: forall k l pw.
          (KnownNat l, Deriveable k l, ByteArrayAccess pw)
       => pw -> Salt -> Policy -> k
derive pw salt policy =
  fromSecretBytes $ deriveSecretN pw salt policy


















{--
data ProtectedN (length :: Nat) typeOf =
  ProtectedN { getCiphertextN :: BytesN length
             , getTagN :: Tag
             , getPolicyN :: Policy
             } deriving (Eq, Show)

data Protected typeof =
  Protected { getCiphertext :: Bytes
            , getTag :: Tag
            , getPolicy :: Policy
            } deriving (Eq, Show)

newtype Tag = Tag (BytesN TagBytes) deriving (Eq, Show, NFData)

instance PhantomFunctor Protected where
  pfmap _ (Protected p m l) = Protected p m l

instance PhantomFunctor (ProtectedN l) where
  pfmap _ (ProtectedN p m l) = ProtectedN p m l


class PasswordProtectableN t l | t -> l where
  protectWithN :: Policy -> Password -> t -> IO (ProtectedN l t)
  openWithN :: Password -> ProtectedN l t -> Maybe t

instance (ByteArray b, KnownNat l) => PasswordProtectableN (N l b) l where
  protectWithN policy password secret = do
    protected <- passwordProtectN policy password $ concealN secret
    return $ pfmap revealN protected
  openWithN password protected = do
    result <- passwordOpenN password $ pfmap concealN protected
    return $ revealN result

instance PasswordProtectableN t l => PasswordProtectableN (Secret t) l where
  protectWithN policy password secret = do
    protected <- protectWithN policy password $ reveal secret
    return $ pfmap conceal protected
  openWithN password protected = do
    result <- openWithN password $ pfmap reveal protected
    return $ conceal result

class PasswordProtectable s where
  protectWith :: Policy -> Password -> s -> IO (Protected s)
  default protectWith :: Plaintext s => Policy -> Password -> s -> IO (Protected s)
  protectWith policy password plaintext = do
    protected <- passwordProtect policy password
      (fromPlaintext plaintext :: ScrubbedBytes)
    return $ pfmap (fromJust . toPlaintext) protected

  openWith :: Password -> Protected s -> Maybe s
  default openWith :: Plaintext s => Password -> Protected s -> Maybe s
  openWith password protected = do
    let plain = pfmap fromPlaintext protected
    opened <- passwordOpen password plain
    toPlaintext (opened :: ScrubbedBytes)

instance PasswordProtectable s => PasswordProtectable (Secret s) where
  protectWith policy password (Conceal secret) = do
    protected <- protectWith policy password secret
    return $ pfmap Conceal protected
  openWith password protected = do
    let plain = pfmap reveal protected
    opened <- openWith password plain
    return $ Conceal opened

instance PasswordProtectable Bytes
instance PasswordProtectable ScrubbedBytes
instance PasswordProtectable ByteString
--}


{-|
Wrapper type for the operations used by password hashing
-}
newtype Opslimit = Opslimit { getOpslimit :: Int } deriving (Eq, Ord, Show, NFData)

{-|
Smart constructor for opslimit
-}
opslimit :: Int -> Opslimit
opslimit x
  | Opslimit x < minOpslimit = error $ show x <> " below minimum opslimit " <> show minOpslimit
  | Opslimit x > maxOpslimit = error $ show x <> " above maximum opslimit " <> show maxOpslimit
  | otherwise = Opslimit x

opslimitInteractive :: Opslimit
opslimitInteractive = Opslimit (fromIntegral sodium_pwhash_opslimit_interactive)

opslimitModerate :: Opslimit
opslimitModerate = Opslimit (fromIntegral sodium_pwhash_opslimit_moderate)

opslimitSensitive :: Opslimit
opslimitSensitive = Opslimit (fromIntegral sodium_pwhash_opslimit_sensitive)


{-|
Wrapper type for the memory used by password hashing
-}
newtype Memlimit = Memlimit { getMemlimit :: Int } deriving (Eq, Ord, Show, NFData)

{-|
Smart constructor for memlimit
-}
memlimit :: Int -> Memlimit
memlimit x
  | Memlimit x < minMemlimit = error $ show x <> " below minimum memlimit " <> show minMemlimit
  | Memlimit x > maxMemlimit = error $ show x <> " above maximum memlimit " <> show maxMemlimit
  | otherwise = Memlimit x

memlimitInteractive :: Memlimit
memlimitInteractive = Memlimit (fromIntegral sodium_pwhash_memlimit_interactive)

memlimitModerate :: Memlimit
memlimitModerate = Memlimit (fromIntegral sodium_pwhash_memlimit_moderate)

memlimitSensitive :: Memlimit
memlimitSensitive = Memlimit (fromIntegral sodium_pwhash_memlimit_sensitive)

{-|
Algorithms known to Libsodium, as an enum datatype
-}
data KnownAlgorithm
  = InvalidAlgorithm
  | Argon2i13
  | Argon2id13
  deriving (Eq, Enum, Ord, Show)

newtype Algorithm = Algorithm { getAlgorithm :: KnownAlgorithm } deriving (Eq, Ord, Show)

{-|
Smart constructor for algorithm
-}
algorithm :: KnownAlgorithm -> Algorithm
algorithm InvalidAlgorithm = error "invalid algorithm"
algorithm a = Algorithm a

defaultAlgorithm :: Algorithm
defaultAlgorithm = Algorithm $ toEnum (fromIntegral sodium_pwhash_alg_default)


{-|
Wrapper for opslimit, memlimit and algorithm
-}
data Policy = Policy
  { opsPolicy :: Opslimit
  , memPolicy :: Memlimit
  , algPolicy :: Algorithm
  } deriving (Eq, Ord, Show)

{-|
Get raw C types from a policy, suitable for passing to FFI functions
-}
unpackPolicy :: Policy -> (CULLong, CSize, CInt)
unpackPolicy (Policy ops mem alg) =
  ( fromIntegral (getOpslimit ops)
  , fromIntegral (getMemlimit mem)
  , fromIntegral (fromEnum $ getAlgorithm alg)
  )

{-|
Fast policy suitable for low-powered devices

Takes approximately 0.1 seconds on a typical desktop computer
and requires 64 MiB of dedicated RAM
-}
interactivePolicy :: Policy
interactivePolicy = Policy opslimitInteractive
                           memlimitInteractive
                           defaultAlgorithm

{-|
Moderate policy with a balance of speed and security

Takes approximately 1 second on a typical desktop computer
and requires 256 MiB of dedicated RAM
-}
moderatePolicy :: Policy
moderatePolicy = Policy opslimitModerate
                        memlimitModerate
                        defaultAlgorithm

{-|
High-security policy designed to make attacking the password extremely expensive

Takes several seconds on a typical desktop computer
and requires 1024 MiB of dedicated RAM
-}
sensitivePolicy :: Policy
sensitivePolicy = Policy opslimitSensitive
                         memlimitSensitive
                         defaultAlgorithm


{--


passwordProtect :: ByteArray b => Policy -> Password -> b -> IO (Protected b)
passwordProtect policy password plaintext =
  withLithium $ do
  salt <- newSalt
  nonce <- newNonce
  let key = derive password salt policy
  let (ciphertext, mac) =
        secretBoxDetached key nonce plaintext
  let tag = appendN (unSalt salt)
            $ appendN (unNonce nonce)
            $ unMac mac
  return $ Protected ciphertext (Tag tag) policy

passwordOpen :: ByteArray b => Password -> Protected b -> Maybe b
passwordOpen password (Protected ciphertext (Tag tag) policy) =
  withLithium $ do
  let (saltB, nonceB, macB) =
        splitN3 tag
  let key = derive password (Salt saltB) policy
  openSecretBoxDetached
    key (Nonce nonceB) (Mac macB) ciphertext

passwordProtectN :: forall l. (KnownNat l)
                 => Policy -> Password -> SecretN l -> IO (ProtectedN l (SecretN l))
passwordProtectN policy password secret =
  withLithium $ do
  salt <- newSalt
  nonce <- newNonce
  let key =
        derive password salt policy
  let (ciphertext, mac) =
        secretBoxDetachedN key nonce secret
  let tag = appendN (unSalt salt)
            $ appendN (unNonce nonce)
            $ unMac mac
  return $ ProtectedN ciphertext (Tag tag) policy

passwordOpenN :: forall l. (KnownNat l)
              => Password -> ProtectedN l (SecretN l) -> Maybe (SecretN l)
passwordOpenN password (ProtectedN ciphertext (Tag tag) policy) =
  withLithium $ do
  let (saltB, nonceB, macB) =
        splitN3 tag
  let key =
        derive password (Salt saltB) policy
  openSecretBoxDetachedN
    key (Nonce nonceB) (Mac macB) ciphertext
--}

type SaltBytes = 16
saltBytes :: ByteSize SaltBytes
saltBytes = ByteSize

saltSize :: Int
saltSize = fromIntegral sodium_pwhash_saltbytes

type TagBytes = SaltBytes + NonceBytes + MacBytes
tagBytes :: ByteSize TagBytes
tagBytes = ByteSize

tagSize :: Int
tagSize = saltSize + nonceSize + macSize


minOpslimit :: Opslimit
minOpslimit = Opslimit $ fromIntegral sodium_pwhash_opslimit_min

maxOpslimit :: Opslimit
maxOpslimit = Opslimit $ fromIntegral sodium_pwhash_opslimit_max

minMemlimit :: Memlimit
minMemlimit = Memlimit $ fromIntegral sodium_pwhash_memlimit_min

maxMemlimit :: Memlimit
maxMemlimit = Memlimit $ fromIntegral sodium_pwhash_memlimit_max


type PasswordStringBytes = 128

passwordStringBytes :: ByteSize PasswordStringBytes
passwordStringBytes = ByteSize

passwordStringSize :: Int
passwordStringSize = fromIntegral sodium_pwhash_strbytes
