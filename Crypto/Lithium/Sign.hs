{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_HADDOCK show-extensions #-}
{-|
Module      : Crypto.Lithium.Sign
Description : Ed25519 signatures made easy and safe
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Sign
  ( U.SecretKey
  , U.PublicKey
  , U.asPublicKey
  , U.fromPublicKey

  , U.Seed
  , U.newSeed

  , U.Keypair

  , U.publicKey
  , U.secretKey

  , U.newKeypair
  , U.seedKeypair

  , U.toPublicKey

  , Signed
  , fromSigned
  , asSigned

  , sign'
  , openSigned

  , Signature
  , asSignature
  , fromSignature

  , sign
  , verify

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

import Foundation hiding (Signed)

newtype Signed m = Signed
  { fromSigned :: ByteString } deriving (Show, Eq, NFData)

asSigned :: ByteString -> Signed m
asSigned = Signed

{-|
Sign a plaintext message of type @m@ and turn it into a @'Signed' m@
-}
sign' :: ( Plaintext p ) => U.SecretKey -> p -> Signed p
sign' key plaintext = Signed $ U.sign key
  (fromPlaintext plaintext :: ByteString)

{-|
Open a signed message

Returns Just message if the signature matches the public key, otherwise Nothing
-}
openSigned :: ( Plaintext p ) => U.PublicKey -> Signed p -> Maybe p
openSigned key (Signed signed) = do
  opened <- U.openSigned key signed :: Maybe ByteString
  toPlaintext opened

newtype Signature m = Signature U.Signature deriving (Eq, Show, NFData)

asSignature :: BytesN U.SignatureBytes -> Signature m
asSignature bs = Signature $ U.asSignature bs

fromSignature :: Signature m -> BytesN U.SignatureBytes
fromSignature (Signature s) = U.fromSignature s

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
verify key plaintext (Signature signature) =
  U.verifyDetached key signature (fromPlaintext plaintext :: ByteString)

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
