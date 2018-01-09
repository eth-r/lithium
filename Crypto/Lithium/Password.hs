{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_HADDOCK show-extensions #-}
{-|
Module      : Crypto.Lithium.Hash
Description : Cryptographic hashing made easy and safe
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Password
  ( U.passwordProtectN
  , U.passwordOpenN
  ) where


import qualified Crypto.Lithium.Unsafe.Password as U

-- import qualified Crypto.Lithium.Box as Box
-- import qualified Crypto.Lithium.SecretBox as SecretBox
-- import qualified Crypto.Lithium.Sign as Sign
-- import qualified Crypto.Lithium.Hash as Hash
