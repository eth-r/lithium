{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.ShortHash
Description : Cryptographic hashing made easy
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.ShortHash
  ( U.Key

  , Digest
  , asDigest
  , fromDigest

  , U.newKey

  , shortHash

  , U.DigestBytes
  , U.digestBytes
  , U.digestSize

  , U.KeyBytes
  , U.keyBytes
  , U.keySize
  ) where

import Crypto.Lithium.Internal.Util
import qualified Crypto.Lithium.Unsafe.ShortHash as U

import Foundation
import Control.DeepSeq
import Data.ByteArray as B
import Data.ByteString as BS

newtype Digest t = Digest U.Digest deriving (Eq, Show, NFData)

instance ByteArrayAccess (Digest t) where
  length _ = U.digestSize
  withByteArray (Digest bs) = withByteArray bs

asDigest :: BytesN U.DigestBytes -> Digest t
asDigest = Digest . U.asDigest

fromDigest :: Digest t -> BytesN U.DigestBytes
fromDigest (Digest d) = U.fromDigest d

{-

-}
shortHash :: Plaintext t => U.Key -> t -> Digest t
shortHash key m = Digest $
  U.shortHash key (fromPlaintext m :: ByteString)
