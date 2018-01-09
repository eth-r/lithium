module HashBench (benchHash) where

import Criterion

-- import Foundation

import Control.Monad
import Data.ByteArray

import Crypto.Lithium.Hash
import Crypto.Lithium.Random

hashEnv = do
  -- smols <- forM [1..100000] $ randomBytes 32
  -- tols <- forM [1..1000] $ randomBytes 65536
  -- supertols <- forM [1..100] $ randomBytes 1048576
  bytes32  <- randomBytes 32 :: IO Bytes
  bytes128 <- randomBytes 128 :: IO Bytes
  bytes512 <- randomBytes 512 :: IO Bytes
  kb2      <- randomBytes 2000 :: IO Bytes
  kb8      <- randomBytes 8000 :: IO Bytes
  kb32     <- randomBytes 32000 :: IO Bytes
  kb128    <- randomBytes 128000 :: IO Bytes
  kb512    <- randomBytes 512000 :: IO Bytes
  mb2      <- randomBytes 2000000 :: IO Bytes
  mb8      <- randomBytes 8000000 :: IO Bytes
  mb32     <- randomBytes 32000000 :: IO Bytes
  mb128    <- randomBytes 128000000 :: IO Bytes
  return [bytes32, bytes128, bytes512, kb2, kb8, kb32, kb128, kb512, mb2, mb8, mb32, mb128]

benchHash = env hashEnv $ \ ~[bytes32, bytes128, bytes512, kb2, kb8, kb32, kb128, kb512, mb2, mb8, mb32, mb128] ->
  bgroup "genericHash" $
  [ bench "32 B" $ nf genericHash (bytes32 :: Bytes)
  , bench "128 B" $ nf genericHash (bytes128 :: Bytes)
  , bench "512 B" $ nf genericHash (bytes512 :: Bytes)
  , bench "2 KB" $ nf genericHash (kb2 :: Bytes)
  , bench "8 KB" $ nf genericHash (kb8 :: Bytes)
  , bench "32 KB" $ nf genericHash (kb32 :: Bytes)
  , bench "128 KB" $ nf genericHash (kb128 :: Bytes)
  , bench "512 KB" $ nf genericHash (kb512 :: Bytes)
  , bench "2 MB" $ nf genericHash (mb2 :: Bytes)
  , bench "8 MB" $ nf genericHash (mb8 :: Bytes)
  , bench "32 MB" $ nf genericHash (mb32 :: Bytes)
  , bench "128 MB" $ nf genericHash (mb128 :: Bytes)
  ]
