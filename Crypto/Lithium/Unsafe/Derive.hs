{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.Derive
Description : Key derivation functions
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Derive
  ( Deriveable(..)
  , MasterKey(..)
  , Subkey(..)
  , Context(..)
  , SubkeyId(..)

  , proxyContext
  , makeContext

  , deriveSecretN

  , derive
  , derive'

  -- * Constants
  , MasterKeyBytes
  , masterKeyBytes
  , masterKeySize

  , ContextBytes
  , contextBytes
  , contextSize
  ) where

import Foundation
import Control.DeepSeq
import Data.ByteArray as B
import Data.ByteString.Char8 as BC
import Data.ByteArray.Sized as Sized

import Crypto.Lithium.Internal.Util
import Crypto.Lithium.Internal.Derive

-- deriveable types

import Crypto.Lithium.Unsafe.Aead as Aead
import Crypto.Lithium.Unsafe.Box  as Box
import Crypto.Lithium.Unsafe.Hash as Hash
import Crypto.Lithium.Unsafe.SecretBox as SecretBox
import Crypto.Lithium.Unsafe.SecretStream as SecretStream
import Crypto.Lithium.Unsafe.ShortHash as ShortHash
import Crypto.Lithium.Unsafe.Sign as Sign

-- | Class for deriving arbitrary secrets from a master key
class Deriveable t l | t -> l where
  fromSecretBytes :: SecretN l -> t

--  Derive 'Aead' key
instance Deriveable Aead.Key Aead.KeyBytes where
  fromSecretBytes = Aead.Key


--  Derive 'Box' keys
instance Deriveable Box.Seed Box.SeedBytes where
  fromSecretBytes = Box.Seed

instance Deriveable Box.Keypair Box.SeedBytes where
  fromSecretBytes = Box.seedKeypair . Box.Seed

instance Deriveable Box.SecretKey Box.SeedBytes where
  fromSecretBytes = Box.secretKey . Box.seedKeypair . Box.Seed

instance Deriveable Box.PublicKey Box.SeedBytes where
  fromSecretBytes = Box.publicKey . Box.seedKeypair . Box.Seed


--  Derive 'Hash' key
instance Hash.KeySized l => Deriveable (Hash.Key l) l where
  fromSecretBytes = Hash.Key


--  Derive 'SecretBox' key
instance Deriveable SecretBox.Key SecretBox.KeyBytes where
  fromSecretBytes = SecretBox.Key


--  Derive 'SecretStream' key
instance Deriveable SecretStream.Key SecretStream.KeyBytes where
  fromSecretBytes = SecretStream.Key


--  Derive 'ShortHash' key
instance Deriveable ShortHash.Key ShortHash.KeyBytes where
  fromSecretBytes = ShortHash.Key


-- Derive 'Sign' keys
instance Deriveable Sign.Seed Sign.SeedBytes where
  fromSecretBytes = Sign.Seed

instance Deriveable Sign.Keypair Sign.SeedBytes where
  fromSecretBytes = Sign.seedKeypair . Sign.Seed

instance Deriveable Sign.SecretKey Sign.SeedBytes where
  fromSecretBytes = Sign.secretKey . Sign.seedKeypair . Sign.Seed

instance Deriveable Sign.PublicKey Sign.SeedBytes where
  fromSecretBytes = Sign.publicKey . Sign.seedKeypair . Sign.Seed


{-|
Master key for key derivation
-}
newtype MasterKey = MasterKey
  { unMasterKey :: SecretN MasterKeyBytes } deriving (Eq, Show, NFData)

newtype SubkeyId = SubkeyId
  { unSubkeyId :: Word64 } deriving (Eq, Ord, Show, NFData)

data ContextSymbol (context :: Symbol) = ContextSymbol deriving (Eq, Show)

newtype Context = Context
  { unContext :: BytesN ContextBytes } deriving (Eq, Ord, Show, ByteArrayAccess, NFData)

{-|
Turns a given symbol proxy value to a context

Symbols longer than 8 bytes are truncated

Symbols shorter than 8 bytes have zeros appended to the value
-}
proxyContext :: forall c. KnownSymbol c => Context
proxyContext = makeContext $ BC.pack $ symbolVal $ ContextSymbol @c

{-|
Turns a given byte array to a context

Byte arrays longer than 8 bytes are truncated

Byte arrays shorter than 8 bytes have zeros appended to the value
-}
makeContext :: ByteArray a => a -> Context
makeContext bs = Context $ Sized.coerce $ B.convert bs

newtype Subkey (context :: Symbol) subkeyType = Subkey
  { unSubkey :: subkeyType } deriving (Eq, Ord, Show, NFData)

deriveSecretN :: forall l. (KnownNat l)
              => MasterKey -> SubkeyId -> Context -> SecretN l
deriveSecretN (MasterKey master) (SubkeyId i) context =
  withLithium $

  let slen = theNat @l
      (_e, subkey) = unsafePerformIO $
        allocSecretN $ \psubkey ->
        withSecret master $ \pmaster ->
        withByteArray context $ \pcontext ->
        sodium_kdf_derive psubkey slen
                          (fromIntegral i)
                          pcontext
                          pmaster
  in subkey

{-|
Function for deriving a subkey for a given subkey id and context
-}
derive :: forall k l. (KnownNat l, Deriveable k l)
       => MasterKey -> SubkeyId -> Context -> k
derive master subkeyId context = fromSecretBytes
  $ deriveSecretN master subkeyId context

{-|
Function for deriving a subkey for a type-level context

This can be used for extra type safety by ensuring only subkeys of a correct
context symbol are used for a specific purpose
-}
derive' :: forall c k l. (KnownNat l, KnownSymbol c, Deriveable k l)
        => MasterKey -> SubkeyId -> Subkey c k
derive' master subkeyId =
  Subkey $ derive master subkeyId (proxyContext @c)


-- | Length of a 'MasterKey' as a type-level constant
type MasterKeyBytes = 32
-- | Master key length as a proxy value
masterKeyBytes :: ByteSize MasterKeyBytes
masterKeyBytes = ByteSize
-- | Master key length as a regular value
masterKeySize :: Int
masterKeySize = fromIntegral sodium_kdf_keybytes

-- | Length of a 'Context' as a type-level constant
type ContextBytes = 8
-- | Context length as a proxy value
contextBytes :: ByteSize ContextBytes
contextBytes = ByteSize
-- | Context length as a regular value
contextSize :: Int
contextSize = fromIntegral sodium_kdf_contextbytes
