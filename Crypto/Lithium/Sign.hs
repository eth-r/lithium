{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-|
Module      : Crypto.Lithium.Sign
Description : Public-key signatures
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Sign (
  -- * Types
    U.SecretKey(..)
  , U.PublicKey(..)
  , U.asPublicKey
  , U.fromPublicKey

  , U.Seed
  , U.newSeed

  , U.Keypair(..)

  , U.newKeypair
  , U.seedKeypair

  , U.toPublicKey

  -- * Detached signatures
  , Signature
  , signature
  , unSignature

  , asSignature
  , fromSignature

  , sign
  , verify

  -- * Signed messages
  , Signed(..)
  , fromSigned
  , asSigned

  , sign'
  , openSigned

  -- * Constants
  , U.SecretKeyBytes
  , U.secretKeyBytes
  , U.secretKeySize

  , U.PublicKeyBytes
  , U.publicKeyBytes
  , U.publicKeySize

  , U.SignatureBytes
  , U.signatureBytes
  , U.signatureSize
  ) where

import qualified Crypto.Lithium.Unsafe.Sign as U
import Crypto.Lithium.Types

import Control.DeepSeq
import Data.ByteString
import Data.ByteArray as B

import Foundation hiding (Signed)

{-|
Wrapper for signed messages

Stores the original type as a phantom type to enable transparent conversion
-}
newtype Signed m = Signed
  { unSigned :: ByteString -- ^ Get the signed message as a 'ByteString'
  } deriving (Show, Eq, NFData)

{-|
Interpret a bytestring as a signed message
-}
asSigned :: Decoder (Signed m)
asSigned = Just . Signed . B.convert

fromSigned :: Encoder (Signed m)
fromSigned = B.convert . unSigned


{-|
Sign a plaintext message of type @p@ and turn it into a @'Signed' p@
-}
sign' :: ( Plaintext p ) => U.SecretKey -> p -> Signed p
sign' key plaintext = Signed $ U.sign key
  (fromPlaintext plaintext :: ByteString)

{-|
Open a signed message

Returns @Just message@ if the signature matches the public key, otherwise Nothing
-}
openSigned :: ( Plaintext p ) => U.PublicKey -> Signed p -> Maybe p
openSigned key (Signed signed) = do
  opened <- U.openSigned key signed :: Maybe ByteString
  toPlaintext opened

{-|
Typed signature

Uses a phantom type to store the type of the corresponding message
-}
newtype Signature m = Signature U.Signature deriving (Eq, Show, NFData)

signature :: BytesN U.SignatureBytes -> Signature m
signature bs = Signature $ U.Signature bs

unSignature :: Signature m -> BytesN U.SignatureBytes
unSignature (Signature s) = U.unSignature s

{-|
Interpret a byte array as a signature
-}
asSignature :: Decoder (Signature m)
asSignature = decodeWith signature

{-|
Encode a signature as a byte array
-}
fromSignature :: Encoder (Signature m)
fromSignature = encodeWith unSignature

{-|
Sign a message of type @m@ to produce a @'Signature' m@
-}
sign :: ( Plaintext p ) => U.SecretKey -> p -> Signature p
sign key plaintext = Signature $
  U.signDetached key (fromPlaintext plaintext :: ByteString)

{-|
Check a typed signature
-}
verify :: ( Plaintext p ) => U.PublicKey -> p -> Signature p -> Bool
verify key plaintext (Signature sig) =
  U.verifyDetached key sig (fromPlaintext plaintext :: ByteString)

{-
newtype SignedSecret m = SignedSecret
  { fromSignedSecret :: ScrubbedBytes } deriving (Show, Eq)

{-|
Sign a secret value such as an encryption key, while preserving its secrecy
-}
signSecret :: SecretBytes s => U.SecretKey -> s -> SignedSecret s
signSecret key secret = SignedSecret $ U.sign key $ toSecretBytes secret

{-|
Open a signed secret value
-}
openSignedSecret :: SecretBytes s => U.PublicKey -> SignedSecret s -> Maybe s
openSignedSecret key (SignedSecret s) = fromSecretBytes <$> U.openSigned key s
-}
