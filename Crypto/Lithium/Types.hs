{-# LANGUAGE ExplicitNamespaces #-}
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
