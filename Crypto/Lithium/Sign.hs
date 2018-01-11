{-# LANGUAGE NoImplicitPrelude #-}
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

  , U.Keypair

  , U.publicKey
  , U.secretKey

  , U.newKeypair

  , U.toPublicKey

  , Signed
  , fromSigned
  , asSigned

  , sign
  , openSigned

  , Signature
  , asSignature
  , fromSignature

  , signDetached
  , verifyDetached

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

-- import Data.ByteArray
import Data.ByteString

import Foundation hiding (Signed)

newtype Signed m = Signed
  { fromSigned :: ByteString } deriving (Show, Eq)

asSigned :: ByteString -> Signed m
asSigned = Signed

sign :: ( Plaintext p ) => U.SecretKey -> p -> Signed p
sign key plaintext = Signed $ U.sign key (fromPlaintext plaintext :: ByteString)

openSigned :: ( Plaintext p ) => U.PublicKey -> Signed p -> Maybe p
openSigned key (Signed signed) = do
  opened <- U.openSigned key signed :: Maybe ByteString
  toPlaintext opened

newtype Signature m = Signature U.Signature deriving (Eq, Show)

asSignature :: BytesN U.SignatureBytes -> Signature m
asSignature bs = Signature $ U.asSignature bs

fromSignature :: Signature m -> BytesN U.SignatureBytes
fromSignature (Signature s) = U.fromSignature s

signDetached :: ( Plaintext p ) => U.SecretKey -> p -> Signature p
signDetached key plaintext = Signature $
  U.signDetached key (fromPlaintext plaintext :: ByteString)

verifyDetached :: ( Plaintext p ) => U.PublicKey -> Signature p -> p -> Bool
verifyDetached key (Signature signature) plaintext =
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
