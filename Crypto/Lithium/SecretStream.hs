{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_HADDOCK show-extensions #-}
{-|
Module      : Crypto.Lithium.SecretStream
Description : Stream of related messages
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.SecretStream
  ( U.Key
  , U.newKey

  , U.Header
  , U.asHeader
  , U.fromHeader

  , U.Tag(..)

  , U.State

  , U.secretStreamInitPush
  , U.secretStreamInitPull
  , U.secretStreamPush
  , U.secretStreamPull

  , U.secretStreamRekey

  , SecretStreamError(..)

  , secretStreamSend
  , secretStreamReceive

  , U.KeyBytes
  , U.keyBytes
  , U.keySize

  , U.MacBytes
  , U.macBytes
  , U.macSize

  , U.HeaderBytes
  , U.headerBytes
  , U.headerSize

  , U.StateBytes
  , U.stateBytes
  , U.stateSize
  ) where

import qualified Crypto.Lithium.Unsafe.SecretStream as U
import Crypto.Lithium.Internal.Util
import Foundation
import Data.ByteString as BS

{-|
Encrypt the plaintext into an 'SecretStreamBox' which also authenticates the message and
its associated data upon decryption

The associated data is not encrypted or stored in the encrypted box.

If your protocol uses nonces for eg. replay protection, you should put the nonce
in the associated data field; due to the risk of nonce reuse compromising the
underlying cryptography, Lithium does not provide an interface using nonces in
the traditional sense. With 'secretStream', repeating the associated data will not harm
your security in any way.
-}
secretStreamSend :: (Plaintext p, Plaintext a) => U.Key -> [(p, a)] -> IO (U.Header, [(ByteString, a)])
secretStreamSend key chunks = do
  (header, state) <- U.secretStreamInitPush key
  let chunks' = secretStreamSend' state chunks
  return (header, chunks')

secretStreamSend' :: (Plaintext p, Plaintext a) => U.State -> [(p, a)] -> [(ByteString, a)]
secretStreamSend' _ [] = []
secretStreamSend' state [(lastPlaintext, lastAAD)] =
  let (ctext, _) = U.secretStreamPush state U.Final
        (fromPlaintext lastPlaintext :: ByteString)
        (fromPlaintext lastAAD :: ByteString)
  in [(ctext, lastAAD)]
secretStreamSend' state ((plaintext, aad) : chunks) =
  let (ctext, state') = U.secretStreamPush state U.Message
        (fromPlaintext plaintext :: ByteString)
        (fromPlaintext aad :: ByteString)
  in (ctext, aad) : secretStreamSend' state' chunks

data SecretStreamError a
  = InitFailure
  | DecryptFailure { streamState :: U.State
                   , remaining :: [(ByteString, a)] }
  | DecodeFailure  { failed :: ByteString
                   , streamState :: U.State
                   , remaining :: [(ByteString, a)] }
  | EarlyFinalTag  { streamState :: U.State
                   , remaining :: [(ByteString, a)] }
  | StreamCutShort { streamState :: U.State }
  deriving (Eq, Show)

secretStreamReceive :: (Plaintext p, Plaintext a)
                    => U.Key -> U.Header -> [(ByteString, a)] -> [Either (SecretStreamError a) (p, a)]
secretStreamReceive key header chunks =
  case U.secretStreamInitPull key header of
    Nothing -> [Left InitFailure]
    Just state -> secretStreamReceive' state chunks

secretStreamReceive' :: (Plaintext p, Plaintext a)
                     => U.State -> [(ByteString, a)] -> [Either (SecretStreamError a) (p, a)]
secretStreamReceive' _ [] = []
secretStreamReceive' state chunks@((ctext, aad) : chunks') =
  case U.secretStreamPull state ctext (fromPlaintext aad :: ByteString) of
    Nothing ->
      Left (DecryptFailure state chunks) : []
    Just ((tag, message), state') ->
      case toPlaintext message of
        Nothing ->
          Left (DecodeFailure message state' chunks') : []
        Just plaintext ->
          Right (plaintext, aad) : secretStreamFinish tag state' chunks'

secretStreamFinish :: (Plaintext p, Plaintext a)
                   => U.Tag -> U.State -> [(ByteString, a)] -> [Either (SecretStreamError a) (p, a)]
secretStreamFinish U.Final _ [] = []
secretStreamFinish U.Final state chunks =
  Left (EarlyFinalTag state chunks) : []
secretStreamFinish _ state [] =
  Left (StreamCutShort state) : []
secretStreamFinish _ state chunks = secretStreamReceive' state chunks
