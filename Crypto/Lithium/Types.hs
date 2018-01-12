{-# LANGUAGE ExplicitNamespaces #-}
{-# OPTIONS_HADDOCK show-extensions #-}
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

  , N
  , fromN

  , emptyN
  , allocRetN

  , maybeToN
  , coerceToN
  , convertN

  , appendN

  , takeN'
  , takeN

  , dropN'
  , dropN

  , tailN'
  , tailN

  , splitN'
  , splitN

  , xorN

  , Secret
  , conceal

  , Plaintext(..)

  , BytesN

  , SecretN
  , concealN

  , maybeConcealN
  , emptySecretN
  , secretLengthN
  , splitSecretN
  ) where

import Crypto.Lithium.Unsafe.Types as U
