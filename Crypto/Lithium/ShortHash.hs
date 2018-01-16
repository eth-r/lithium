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
{-|
Module      : Crypto.Lithium.ShortHash
Description : Fast short hash function with reduced security
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.ShortHash (
  -- * Types
    U.Key

  , Digest
  , asDigest
  , fromDigest

  , U.newKey

  -- * ShortHash
  , shortHash

  -- * Constants
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

instance Plaintext (Digest t) where
  fromPlaintext (Digest d) = fromPlaintext d
  toPlaintext bs = Digest <$> toPlaintext bs
  withPlaintext (Digest d) = withPlaintext d
  plaintextLength _ = U.digestSize

asDigest :: BytesN U.DigestBytes -> Digest t
asDigest = Digest . U.asDigest

fromDigest :: Digest t -> BytesN U.DigestBytes
fromDigest (Digest d) = U.fromDigest d

{-|
Produces a short, quick hash of a given value

Not secure for cryptographic purposes
-}
shortHash :: Plaintext t => U.Key -> t -> Digest t
shortHash key m = Digest $
  U.shortHash key (fromPlaintext m :: ByteString)
