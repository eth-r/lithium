{-# LANGUAGE RankNTypes #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Unsafe.Types
Description : Various type utilities
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Unsafe.Types
  ( module Data.ByteArray.Sized
  , module Crypto.Lithium.Util.Secret
  , Encoder
  , Decoder
  , decodeWith
  , encodeWith
  , decodeSecret
  , encodeSecret
  ) where

import Data.ByteArray.Sized
import Data.ByteArray.Sized as Sized
import Crypto.Lithium.Util.Secret

import Foundation
import Data.ByteArray as B

type Encoder t = forall a. ByteArray a => t -> a
type Decoder t = forall a. ByteArrayAccess a => a -> Maybe t

decodeWith :: forall l t. KnownNat l => (BytesN l -> t) -> Decoder t
decodeWith f = fmap f . asSized . B.convert

encodeWith :: forall l t. KnownNat l => (t -> BytesN l) -> Encoder t
encodeWith f = unSized . Sized.convert . f

decodeSecret :: forall l t. KnownNat l => (SecretN l -> t) -> Decoder t
decodeSecret f = fmap f . maybeConcealN . B.convert

encodeSecret :: forall l t. KnownNat l => (t -> SecretN l) -> Encoder t
encodeSecret f = unSized . revealN . f
