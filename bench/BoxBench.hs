module BoxBench (benchBox, boxEnv) where

import Criterion.Main

-- import Foundation

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteString as BS

import Crypto.Lithium.Box

import BenchUtils


boxEnv :: IO (Keypair, Keypair)
boxEnv = do
  alice <- newKeypair
  bob <- newKeypair
  return (alice, bob)


benchBox :: (Keypair, Keypair) -> Benchmark
benchBox (alice, bob) = do
  let encrypt :: ByteString -> IO (Box ByteString)
      encrypt message = box (publicKey bob) (secretKey alice) message

      decrypt :: ByteString -> IO (Maybe ByteString)
      decrypt message = do
        ciphertext <- box (publicKey alice) (secretKey bob) message
        return $ openBox (publicKey bob) (secretKey alice) ciphertext

  bgroup "Box" $
    [ bench "newKeypair" $ nfIO newKeypair
    , bgroup "encrypt" $
      [ bench "128 B" $ nfIO $ encrypt bs128
      , bench "1 MB" $ nfIO $ encrypt mb1
      , bench "5 MB" $ nfIO $ encrypt mb5
      ]
    , bgroup "encrypt+decrypt" $
      [  bench "128 B" $ nfIO $ decrypt bs128
      , bench "1 MB" $ nfIO $ decrypt mb1
      , bench "5 MB" $ nfIO $ decrypt mb5
      ]
    ]
