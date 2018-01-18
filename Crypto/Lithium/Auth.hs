{-# LANGUAGE FlexibleContexts #-}
{-|
Module      : Crypto.Lithium.Auth
Description : Symmetric-key message authentication
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Auth
  ( U.Key(..)
  , U.newKey

  , Mac
  , unMac
  , makeMac
  , asMac
  , fromMac

  , auth
  , verify

  , U.KeyBytes
  , U.keyBytes
  , U.keySize

  , U.MacBytes
  , U.macBytes
  , U.macSize
  ) where

import qualified Crypto.Lithium.Unsafe.Auth as U

import Foundation hiding (Foldable)

import Crypto.Lithium.Internal.Util

import Control.DeepSeq
import Data.ByteArray as B
import Data.ByteString as BS

newtype Mac t = Mac U.Mac deriving (Eq, Ord, Show, NFData, ByteArrayAccess)

unMac :: Mac t -> BytesN U.MacBytes
unMac (Mac m) = U.unMac m

makeMac :: BytesN U.MacBytes -> Mac t
makeMac bs = Mac $ U.Mac bs

asMac :: Decoder (Mac t)
asMac bs = Mac <$> U.asMac bs

fromMac :: Encoder (Mac t)
fromMac (Mac m) = U.fromMac m

auth :: Plaintext m => U.Key -> m -> Mac m
auth key message =
  Mac $ U.auth key (fromPlaintext message :: ByteString)

verify :: Plaintext m => U.Key -> Mac m -> m -> Bool
verify key (Mac mac) message =
  U.verify key mac (fromPlaintext message :: ByteString)
