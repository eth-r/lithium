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
  , sign
  , openSigned

  , Signature
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

import Data.ByteArray
import Data.ByteString

import Foundation hiding (Signed)

type Signed m = U.Signed m ByteString

sign :: ( Plaintext p ) => U.SecretKey -> p -> Signed p
sign key plaintext = U.sign key plaintext

openSigned :: ( Plaintext p ) => U.PublicKey -> Signed p -> Maybe p
openSigned key signed = U.openSigned key signed

type Signature m = U.Signature m Bytes

signDetached :: ( Plaintext p ) => U.SecretKey -> p -> Signature p
signDetached key plaintext = U.signDetached key plaintext

verifyDetached :: ( Plaintext p ) => U.PublicKey -> Signature p -> p -> Bool
verifyDetached key signature plaintext = U.verifyDetached key signature plaintext
