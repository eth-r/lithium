{-# LANGUAGE ExplicitNamespaces #-}
{-|
Module      : Crypto.Lithium.Types
Description : Various type utilities
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Types
  ( ByteSize(..)

  , type Between
  , type AtLeast
  , type AtMost
  , type KnownNats
  , type ByteOp
  , type ByteOps
  , type Encoder
  , type Decoder

  , Sized
  , unSized

  , empty
  , allocRet

  , asSized
  , coerce
  , convert
  , append
  , append3
  , take
  , drop
  , tail
  , split
  , split3
  , xor

  , Secret

  , Plaintext(..)

  , BytesN

  , SecretN

  , emptySecretN
  , secretLengthN
  , splitSecretN

  , encodeWith
  , decodeWith

  , encodeSecret
  , decodeSecret
  ) where

import Crypto.Lithium.Unsafe.Types
