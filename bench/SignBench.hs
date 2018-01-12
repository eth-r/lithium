module SignBench (benchSign, signEnv) where

import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteString as BS

import Crypto.Lithium.Sign as S

import BenchUtils

signEnv :: IO Keypair
signEnv = newKeypair

benchSign :: Keypair -> Benchmark
benchSign alice = do
  let sign :: ByteString -> (Signed ByteString)
      sign message = S.sign (secretKey alice) message

      verify :: ByteString -> Bool
      verify message =
        let signed = sign message
        in case S.openSigned (publicKey alice) signed of
          Nothing -> False
          Just ms -> True

  bgroup "Sign" $
    [ bench "newKeypair" $ nfIO newKeypair
    , bgroup "sign" $
      [ bench "128 B" $ nf sign bs128
      , bench "1 MB" $ nf sign mb1
      , bench "5 MB" $ nf sign mb5
      ]
    , bgroup "sign+verify" $
      [ bench "128 B" $ nf verify bs128
      , bench "1 MB" $ nf verify mb1
      , bench "5 MB" $ nf verify mb5
      ]
    ]
