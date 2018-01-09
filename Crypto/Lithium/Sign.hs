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

  , U.Signed
  , U.sign
  , U.openSigned

  , U.Signature
  , U.signDetached
  , U.verifyDetached

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
