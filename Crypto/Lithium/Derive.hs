{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-|
Module      : Crypto.Lithium.Derive
Description : Key derivation functions
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Derive
  ( U.Deriveable(..)
  , U.MasterKey(..)
  , U.Subkey(..)
  , U.Context(..)
  , U.SubkeyId(..)

  , U.proxyContext
  , U.makeContext

  , U.deriveSecretN

  , U.derive
  , U.derive'

  -- * Constants
  , U.MasterKeyBytes
  , U.masterKeyBytes
  , U.masterKeySize

  , U.ContextBytes
  , U.contextBytes
  , U.contextSize
  ) where

import qualified Crypto.Lithium.Unsafe.Derive as U
