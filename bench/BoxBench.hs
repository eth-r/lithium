module BoxBench (benchBox) where

import Criterion.Main

-- import Foundation

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteArray

import Crypto.Lithium.Box
import Crypto.Lithium.Random

boxEnv :: IO (Keypair, Keypair, [Bytes])
boxEnv = do
  alice <- newKeypair
  bob <- newKeypair
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
  return (alice, bob, [bytes32, bytes128, bytes512, kb2, kb8, kb32, kb128, kb512, mb2, mb8, mb32, mb128])

encrypt :: Keypair -> Keypair -> Bytes -> IO Bytes
encrypt to from message = box (publicKey to) (secretKey from) message
decrypt :: Keypair -> Keypair -> Bytes -> IO (Maybe Bytes)
decrypt to from message = do
  ciphertext <- box (publicKey to) (secretKey from) message
  return $ openBox (publicKey from) (secretKey to) ciphertext

benchBox :: IO ()
benchBox = do
  toEval <- boxEnv
  (alice, bob, [bytes32, bytes128, bytes512, kb2, kb8, kb32, kb128, kb512, mb2, mb8, mb32, mb128]) <- evaluate $ force toEval
  defaultMain $
    [ bgroup "encrypt" $
      [ bench "32 B" $ nfIO $ encrypt bob alice (bytes32 :: Bytes)
      , bench "128 B" $ nfIO $ encrypt bob alice (bytes128 :: Bytes)
      , bench "512 B" $ nfIO $ encrypt bob alice (bytes512 :: Bytes)
      , bench "2 KB" $ nfIO $ encrypt bob alice (kb2 :: Bytes)
      , bench "8 KB" $ nfIO $ encrypt bob alice (kb8 :: Bytes)
      , bench "32 KB" $ nfIO $ encrypt bob alice (kb32 :: Bytes)
      , bench "128 KB" $ nfIO $ encrypt bob alice (kb128 :: Bytes)
      , bench "512 KB" $ nfIO $ encrypt bob alice (kb512 :: Bytes)
      , bench "2 MB" $ nfIO $ encrypt bob alice (mb2 :: Bytes)
      , bench "8 MB" $ nfIO $ encrypt bob alice (mb8 :: Bytes)
      , bench "32 MB" $ nfIO $ encrypt bob alice (mb32 :: Bytes)
      , bench "128 MB" $ nfIO $ encrypt bob alice (mb128 :: Bytes)
      ]
    , bgroup "encrypt+decrypt" $
      [ bench "32 B" $ nfIO $ decrypt alice bob (bytes32 :: Bytes)
      , bench "128 B" $ nfIO $ decrypt alice bob (bytes128 :: Bytes)
      , bench "512 B" $ nfIO $ decrypt alice bob (bytes512 :: Bytes)
      , bench "2 KB" $ nfIO $ decrypt alice bob (kb2 :: Bytes)
      , bench "8 KB" $ nfIO $ decrypt alice bob (kb8 :: Bytes)
      , bench "32 KB" $ nfIO $ decrypt alice bob (kb32 :: Bytes)
      , bench "128 KB" $ nfIO $ decrypt alice bob (kb128 :: Bytes)
      , bench "512 KB" $ nfIO $ decrypt alice bob (kb512 :: Bytes)
      , bench "2 MB" $ nfIO $ decrypt alice bob (mb2 :: Bytes)
      , bench "8 MB" $ nfIO $ decrypt alice bob (mb8 :: Bytes)
      , bench "32 MB" $ nfIO $ decrypt alice bob (mb32 :: Bytes)
      , bench "128 MB" $ nfIO $ decrypt alice bob (mb128 :: Bytes)
      ]
    ]
