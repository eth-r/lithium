{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.Box
  ( sodium_box_keypair
  , sodium_box_seed_keypair

  , sodium_box_easy
  , sodium_box_open_easy
  , sodium_box_detached
  , sodium_box_open_detached

  , sodium_box_beforenm

  , sodium_box_easy_afternm
  , sodium_box_open_easy_afternm
  , sodium_box_detached_afternm
  , sodium_box_open_detached_afternm

  , sodium_box_seal
  , sodium_box_seal_open

  , sodium_box_publickeybytes
  , sodium_box_secretkeybytes
  , sodium_box_macbytes
  , sodium_box_noncebytes
  , sodium_box_seedbytes
  , sodium_box_beforenmbytes
  , sodium_box_sealbytes
  ) where

import Foundation

import Crypto.Lithium.Internal.Util

foreign import ccall "crypto_box_keypair"
  sodium_box_keypair :: Ptr CChar
                     -- ^ Public key output buffer
                     -> Ptr CChar
                     -- ^ Secret key output buffer
                     -> IO CInt

foreign import ccall "crypto_box_seed_keypair"
  sodium_box_seed_keypair :: Ptr CChar
                          -- ^ Public key output buffer
                          -> Ptr CChar
                          -- ^ Secret key output buffer
                          -> Ptr CChar
                          -- ^ Seed input buffer
                          -> IO CInt

foreign import ccall "crypto_box_easy"
  sodium_box_easy :: Ptr CChar
                  -- ^ Ciphertext output buffer
                  -> Ptr CChar
                  -- ^ Message input buffer
                  -> CULLong
                  -- ^ Message length
                  -> Ptr CChar
                  -- ^ Nonce input buffer
                  -> Ptr CChar
                  -- ^ Recipient public key input buffer
                  -> Ptr CChar
                  -- ^ Sender secret key input buffer
                  -> IO CInt

foreign import ccall "crypto_box_open_easy"
  sodium_box_open_easy :: Ptr CChar
                       -- ^ Message output buffer
                       -> Ptr CChar
                       -- ^ Ciphertext input buffer
                       -> CULLong
                       -- ^ Ciphertext length
                       -> Ptr CChar
                       -- ^ Nonce input buffer
                       -> Ptr CChar
                       -- ^ Sender public key input buffer
                       -> Ptr CChar
                       -- ^ Recipient secret key input buffer
                       -> IO CInt

foreign import ccall "crypto_box_detached"
  sodium_box_detached :: Ptr CChar
                      -- ^ Ciphertext output buffer
                      -> Ptr CChar
                      -- ^ Mac output buffer
                      -> Ptr CChar
                      -- ^ Message input buffer
                      -> CULLong
                      -- ^ Message length
                      -> Ptr CChar
                      -- ^ Nonce input buffer
                      -> Ptr CChar
                      -- ^ Recipient public key input buffer
                      -> Ptr CChar
                      -- ^ Sender secret key input buffer
                      -> IO CInt

foreign import ccall "crypto_box_open_detached"
  sodium_box_open_detached :: Ptr CChar
                           -- ^ Message output buffer
                           -> Ptr CChar
                           -- ^ Ciphertext input buffer
                           -> Ptr CChar
                           -- ^ Mac input buffer
                           -> CULLong
                           -- ^ Ciphertext length
                           -> Ptr CChar
                           -- ^ Nonce input buffer
                           -> Ptr CChar
                           -- ^ Sender public key input buffer
                           -> Ptr CChar
                           -- ^ Recipient secret key input buffer
                           -> IO CInt

foreign import ccall "crypto_box_beforenm"
  sodium_box_beforenm :: Ptr CChar
                      -- ^ Combined key output buffer
                      -> Ptr CChar
                      -- ^ Public key input buffer
                      -> Ptr CChar
                      -- ^ Secret key input buffer
                      -> IO CInt

foreign import ccall "crypto_box_easy_afternm"
  sodium_box_easy_afternm :: Ptr CChar
                          -- ^ Ciphertext output buffer
                          -> Ptr CChar
                          -- ^ Message input buffer
                          -> CULLong
                          -- ^ Message length
                          -> Ptr CChar
                          -- ^ Nonce input buffer
                          -> Ptr CChar
                          -- ^ Combined key input buffer
                          -> IO CInt

foreign import ccall "crypto_box_open_easy_afternm"
  sodium_box_open_easy_afternm :: Ptr CChar
                               -- ^ Message output buffer
                               -> Ptr CChar
                               -- ^ Ciphertext input buffer
                               -> CULLong
                               -- ^ Ciphertext length
                               -> Ptr CChar
                               -- ^ Nonce input buffer
                               -> Ptr CChar
                               -- ^ Combined key input buffer
                               -> IO CInt

foreign import ccall "crypto_box_detached_afternm"
  sodium_box_detached_afternm :: Ptr CChar
                              -- ^ Ciphertext output buffer
                              -> Ptr CChar
                              -- ^ Mac output buffer
                              -> Ptr CChar
                              -- ^ Message input buffer
                              -> CULLong
                              -- ^ Message length
                              -> Ptr CChar
                              -- ^ Nonce input buffer
                              -> Ptr CChar
                              -- ^ Combined key input buffer
                              -> IO CInt

foreign import ccall "crypto_box_open_detached_afternm"
  sodium_box_open_detached_afternm :: Ptr CChar
                                   -- ^ Message output buffer
                                   -> Ptr CChar
                                   -- ^ Ciphertext input buffer
                                   -> Ptr CChar
                                   -- ^ Mac input buffer
                                   -> CULLong
                                   -- ^ Ciphertext length
                                   -> Ptr CChar
                                   -- ^ Nonce input buffer
                                   -> Ptr CChar
                                   -- ^ Combined key input buffer
                                   -> IO CInt

foreign import ccall "crypto_box_seal"
  sodium_box_seal :: Ptr CChar
                  -- ^ Ciphertext output buffer
                  -> Ptr CChar
                  -- ^ Message input buffer
                  -> CULLong
                  -- ^ Message length
                  -> Ptr CChar
                  -- ^ Recipient public key input buffer
                  -> IO CInt

foreign import ccall "crypto_box_seal_open"
  sodium_box_seal_open :: Ptr CChar
                       -- ^ Message output buffer
                       -> Ptr CChar
                       -- ^ Ciphertext input buffer
                       -> CULLong
                       -- ^ Ciphertext length
                       -> Ptr CChar
                       -- ^ Recipient public key input buffer
                       -> Ptr CChar
                       -- ^ Recipient secret key input buffer
                       -> IO CInt

foreign import ccall "crypto_box_publickeybytes"
  sodium_box_publickeybytes :: CSize

foreign import ccall "crypto_box_secretkeybytes"
  sodium_box_secretkeybytes :: CSize

foreign import ccall "crypto_box_macbytes"
  sodium_box_macbytes :: CSize

foreign import ccall "crypto_box_noncebytes"
  sodium_box_noncebytes :: CSize

foreign import ccall "crypto_box_seedbytes"
  sodium_box_seedbytes :: CSize

foreign import ccall "crypto_box_beforenmbytes"
  sodium_box_beforenmbytes :: CSize

foreign import ccall "crypto_box_sealbytes"
  sodium_box_sealbytes :: CSize
