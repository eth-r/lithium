{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}
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
  , Protected(..)
  , passwordProtect
  , passwordOpen

  , packProtected
  , unpackProtected

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

import Data.ByteArray.Mapping
import Data.ByteArray.Pack
import Data.ByteArray.Parse as P
import Data.ByteArray as B
import Data.ByteString as BS
import Data.Memory.Endian

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






newtype Protected typeof = Protected
  { getProtected :: ByteString } deriving (Eq, Show, Ord, ByteArrayAccess)

packProtected :: ByteString -> Salt -> Policy -> Protected t
packProtected ciphertext (Salt salt) policy =
  Protected $ B.append tag ciphertext
  where
    (Right tag) = fill (24 + theNat @SaltBytes) $ do
      putBytes @Bytes opsBytes
      putBytes @Bytes memBytes
      putBytes @Bytes algBytes
      putBytes salt
    opsBytes = fromW64BE $ fromIntegral ops
    memBytes = fromW64BE $ fromIntegral mem
    algBytes = fromW64BE $ fromIntegral alg
    (ops, mem, alg) = unpackPolicy policy

unpackProtected :: Protected t -> Maybe (ByteString, Salt, Policy)
unpackProtected (Protected p) = do
  let ParseOK ciphertext saltB =
        parse ((\_ s -> s)
               <$> P.skip 24
               <*> P.take (theNat @SaltBytes)) p
  ops <- opslimit $ fromIntegral $ fromBE $ toW64BE p 0
  mem <- memlimit $ fromIntegral $ fromBE $ toW64BE p 8
  let alg = algorithm $ toEnum $ fromIntegral $ fromBE $ toW64BE p 16
  let policy = Policy ops mem alg
  salt <- asSalt saltB
  return (ciphertext, salt, policy)

passwordProtect :: ByteArrayAccess a
                => Policy -> ScrubbedBytes -> a -> IO (Protected a)
passwordProtect policy pw plaintext = do
  salt <- newSalt
  let key = derive pw salt policy
  ciphertext <- S.secretBoxRandom key plaintext
  return $ packProtected ciphertext salt policy

passwordOpen :: ByteArray a
             => ScrubbedBytes -> Protected a -> Maybe a
passwordOpen pw p = do
  (ciphertext, salt, policy) <- unpackProtected p
  let key = derive pw salt policy
  S.openSecretBoxPrefix key ciphertext



{-|
Wrapper type for the operations used by password hashing
-}
newtype Opslimit = Opslimit { getOpslimit :: Int } deriving (Eq, Ord, Show, NFData)

{-|
Smart constructor for opslimit
-}
opslimit :: Int -> Maybe Opslimit
opslimit x
  | Opslimit x < minOpslimit = Nothing
  | Opslimit x > maxOpslimit = Nothing
  | otherwise = Just (Opslimit x)

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
memlimit :: Int -> Maybe Memlimit
memlimit x
  | Memlimit x < minMemlimit = Nothing
  | Memlimit x > maxMemlimit = Nothing
  | otherwise = Just (Memlimit x)

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
