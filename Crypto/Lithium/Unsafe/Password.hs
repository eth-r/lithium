{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.Password
Description : Password-protecting data made easy
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Password
  ( ProtectedN
  , getCiphertextN
  , getTagN
  , getPolicyN

  , Protected
  , getCiphertext
  , getTag
  , getPolicy

  , PasswordProtectableN(..)
  , PasswordProtectable(..)

  , DeriveableN(..)

  , Password(..)

  , Opslimit
  , opslimit
  , getOpslimit

  , opslimitInteractive
  , opslimitModerate
  , opslimitSensitive

  , Memlimit
  , memlimit
  , getMemlimit

  , memlimitInteractive
  , memlimitModerate
  , memlimitSensitive

  , Algorithm
  , algorithm
  , getAlgorithm

  , defaultAlgorithm

  , KnownAlgorithm(..)

  , Policy(..)

  , interactivePolicy
  , moderatePolicy
  , sensitivePolicy

  , Salt
  , asSalt
  , fromSalt
  , newSalt

  , passwordProtect
  , passwordOpen

  , passwordProtectN
  , passwordOpenN

  , SaltBytes
  , saltBytes
  , saltSize

  , TagBytes
  , tagBytes
  , tagSize

  , minOpslimit
  , maxOpslimit

  , minMemlimit
  , maxMemlimit
  ) where

import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Internal.Password as I

import Crypto.Lithium.Unsafe.SecretBox as S
import Crypto.Lithium.Unsafe.Types

import Foundation
import Control.DeepSeq

import Data.Maybe (fromJust)
import Data.ByteArray as B

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


newtype Password = Password ScrubbedBytes deriving (Eq, Show, NFData)


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
  openWith :: Password -> Protected s -> Maybe s

instance PasswordProtectable s => PasswordProtectable (Secret s) where
  protectWith policy password (Conceal secret) = do
    protected <- protectWith policy password secret
    return $ pfmap Conceal protected
  openWith password protected = do
    let plain = pfmap reveal protected
    opened <- openWith password plain
    return $ Conceal opened

instance Plaintext p => PasswordProtectable p where
  protectWith policy password plaintext = do
    protected <- passwordProtect policy password
      (fromPlaintext plaintext :: ScrubbedBytes)
    return $ pfmap (fromJust . toPlaintext) protected
  openWith password protected = do
    let plain = pfmap fromPlaintext protected
    opened <- passwordOpen password plain
    toPlaintext (opened :: ScrubbedBytes)


class DeriveableN b where
  deriveN :: Password -> Salt -> Policy -> b

instance KnownNat l => DeriveableN (SecretN l) where
  deriveN = deriveSeed

instance DeriveableN Key where
  deriveN password salt policy = asKey $ deriveN password salt policy


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
opslimitInteractive = Opslimit (fromIntegral sodium_pwhash_memlimit_interactive)

opslimitModerate :: Opslimit
opslimitModerate = Opslimit (fromIntegral sodium_pwhash_memlimit_moderate)

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
  , algPolicy :: Algorithm } deriving (Eq, Ord, Show)

interactivePolicy :: Policy
interactivePolicy = Policy opslimitInteractive
                           memlimitInteractive
                           defaultAlgorithm

moderatePolicy :: Policy
moderatePolicy = Policy opslimitModerate
                        memlimitModerate
                        defaultAlgorithm

sensitivePolicy :: Policy
sensitivePolicy = Policy opslimitSensitive
                         memlimitSensitive
                         defaultAlgorithm


newtype Salt = Salt (BytesN SaltBytes) deriving (Eq, Ord, Show, NFData)

asSalt :: BytesN SaltBytes -> Salt
asSalt = Salt

fromSalt :: Salt -> BytesN SaltBytes
fromSalt (Salt s) = s

newSalt :: IO Salt
newSalt = Salt <$> randomBytesN


deriveSeed :: forall l. KnownNat l
           => Password -> Salt -> Policy -> SecretN l
deriveSeed (Password password) (Salt salt) (Policy (Opslimit ops) (Memlimit mem) (Algorithm alg)) =
  withLithium $
  let len = ByteSize :: ByteSize l
      keyLength = asNum len
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


passwordProtect :: ByteArray b => Policy -> Password -> b -> IO (Protected b)
passwordProtect policy password plaintext =
  withLithium $ do
  salt <- newSalt
  nonce <- newNonce
  let key = deriveN password salt policy
  let (ciphertext, mac) =
        secretBoxDetached key nonce plaintext
  let tag = appendN (fromSalt salt) $
            appendN (fromNonce nonce) $
            fromMac mac
  return $ Protected ciphertext (Tag tag) policy

passwordOpen :: ByteArray b => Password -> Protected b -> Maybe b
passwordOpen password (Protected ciphertext (Tag tag) policy) =
  withLithium $ do
  let (saltB, remaining) =
        splitN tag
  let (nonceB, macB) =
        splitN remaining
  let key = deriveN password (asSalt saltB) policy
  openSecretBoxDetached
    key (asNonce nonceB) (asMac macB) ciphertext

passwordProtectN :: forall l. (KnownNat l)
                 => Policy -> Password -> SecretN l -> IO (ProtectedN l (SecretN l))
passwordProtectN policy password secret =
  withLithium $ do
  salt <- newSalt
  nonce <- newNonce
  let key =
        deriveN password salt policy
  let (ciphertext, mac) =
        secretBoxDetachedN key nonce secret
  let tag = appendN (fromSalt salt) $
            appendN (fromNonce nonce) $
            fromMac mac
  return $ ProtectedN ciphertext (Tag tag) policy

passwordOpenN :: forall l. (KnownNat l)
              => Password -> ProtectedN l (SecretN l) -> Maybe (SecretN l)
passwordOpenN password (ProtectedN ciphertext (Tag tag) policy) =
  withLithium $ do
  let (saltB, remaining) =
        splitN tag
  let (nonceB, macB) =
        splitN remaining
  let key =
        deriveN password (asSalt saltB) policy
  openSecretBoxDetachedN
    key (asNonce nonceB) (asMac macB) ciphertext


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
