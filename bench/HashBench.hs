module HashBench (benchHash) where

import Criterion

-- import Foundation

import Control.Monad
import Data.ByteArray

import Crypto.Lithium.Hash
import Crypto.Lithium.Random

import BenchUtils

benchHash :: Benchmark
benchHash = do
  bgroup "Hash" $
    [ bgroup "genericHash" $
      [ bench "128 B" $ nf genericHash bs128
      , bench "1 MB" $ nf genericHash mb1
      , bench "5 MB" $ nf genericHash mb5
      ]
    ]
