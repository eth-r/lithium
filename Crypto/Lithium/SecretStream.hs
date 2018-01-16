{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-|
Module      : Crypto.Lithium.SecretStream
Description : Symmetric-key encryption for stream of related messages
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
import qualified Data.ByteString as BS
-- import qualified Data.ByteString.Lazy as BL

-- import Control.Monad.State

-- type SecretStream b = State U.State b

{-|
Encrypt a list of message chunks + asssociated data
-}
secretStreamSend :: (Plaintext p, Plaintext a) => U.Key -> [(p, a)] -> IO (U.Header, [(BS.ByteString, a)])
secretStreamSend key chunks = do
  (header, state) <- U.secretStreamInitPush key
  let chunks' = secretStreamSend' state chunks
  return (header, chunks')

secretStreamSend' :: (Plaintext p, Plaintext a) => U.State -> [(p, a)] -> [(BS.ByteString, a)]
secretStreamSend' _ [] = []
secretStreamSend' state [(lastPlaintext, lastAAD)] =
  let (ctext, _) = U.secretStreamPush state U.Final
        (fromPlaintext lastPlaintext :: BS.ByteString)
        (fromPlaintext lastAAD :: BS.ByteString)
  in [(ctext, lastAAD)]
secretStreamSend' state ((plaintext, aad) : chunks) =
  let (ctext, state') = U.secretStreamPush state U.Message
        (fromPlaintext plaintext :: BS.ByteString)
        (fromPlaintext aad :: BS.ByteString)
  in (ctext, aad) : secretStreamSend' state' chunks

data SecretStreamError a
  = InitFailure
  | DecryptFailure { streamState :: U.State
                   , remaining :: [(BS.ByteString, a)] }
  | DecodeFailure  { failed :: BS.ByteString
                   , streamState :: U.State
                   , remaining :: [(BS.ByteString, a)] }
  | EarlyFinalTag  { streamState :: U.State
                   , remaining :: [(BS.ByteString, a)] }
  | StreamCutShort { streamState :: U.State }
  deriving (Eq, Show)

{-|
Decrypt a list of message chunks + associated data
-}
secretStreamReceive :: (Plaintext p, Plaintext a)
                    => U.Key -> U.Header -> [(BS.ByteString, a)] -> [Either (SecretStreamError a) (p, a)]
secretStreamReceive key header chunks =
  case U.secretStreamInitPull key header of
    Nothing -> [Left InitFailure]
    Just state -> secretStreamReceive' state chunks

secretStreamReceive' :: (Plaintext p, Plaintext a)
                     => U.State -> [(BS.ByteString, a)] -> [Either (SecretStreamError a) (p, a)]
secretStreamReceive' _ [] = []
secretStreamReceive' state chunks@((ctext, aad) : chunks') =
  case U.secretStreamPull state ctext (fromPlaintext aad :: BS.ByteString) of
    Nothing ->
      Left (DecryptFailure state chunks) : []
    Just ((tag, message), state') ->
      case toPlaintext message of
        Nothing ->
          Left (DecodeFailure message state' chunks') : []
        Just plaintext ->
          Right (plaintext, aad) : secretStreamFinish tag state' chunks'

secretStreamFinish :: (Plaintext p, Plaintext a)
                   => U.Tag -> U.State -> [(BS.ByteString, a)] -> [Either (SecretStreamError a) (p, a)]
secretStreamFinish U.Final _ [] = []
secretStreamFinish U.Final state chunks =
  Left (EarlyFinalTag state chunks) : []
secretStreamFinish _ state [] =
  Left (StreamCutShort state) : []
secretStreamFinish _ state chunks = secretStreamReceive' state chunks


-- secretStreamLongChunk :: U.State -> BL.BS.ByteString -> (U.State, [BS.ByteString])
-- secretStreamLongChunk state bytes =
--   let chunks = BL.toChunks
--   in secretStreamChunk' id state chunks

-- secretStreamChunk' :: ([BS.BS.ByteString] -> [BS.ByteString]) ->
