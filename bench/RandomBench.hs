module RandomBench (benchRandom) where

import Criterion

import Data.ByteArray
import Crypto.Lithium.Random

benchRandom = bgroup "random"
  [ bench "32 B"   $ nfIO $ (randomBytes 32 :: IO Bytes)
  , bench "128 B"  $ nfIO $ (randomBytes 128 :: IO Bytes)
  , bench "512 B"  $ nfIO $ (randomBytes 512 :: IO Bytes)
  , bench "2 KB"   $ nfIO $ (randomBytes 2000 :: IO Bytes)
  , bench "8 KB"   $ nfIO $ (randomBytes 8000 :: IO Bytes)
  , bench "32 KB"  $ nfIO $ (randomBytes 32000 :: IO Bytes)
  , bench "128 KB" $ nfIO $ (randomBytes 128000 :: IO Bytes)
  , bench "512 KB" $ nfIO $ (randomBytes 512000 :: IO Bytes)
  , bench "2 MB"   $ nfIO $ (randomBytes 2000000 :: IO Bytes)
  , bench "8 MB"   $ nfIO $ (randomBytes 8000000 :: IO Bytes)
  , bench "32 MB"  $ nfIO $ (randomBytes 32000000 :: IO Bytes)
  , bench "128 MB" $ nfIO $ (randomBytes 128000000 :: IO Bytes)
  ]
