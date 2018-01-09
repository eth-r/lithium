{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.SecretBox
  ( sodium_secretbox_keygen
  , sodium_secretbox_easy
  , sodium_secretbox_open_easy
  , sodium_secretbox_detached
  , sodium_secretbox_open_detached

  , sodium_secretbox_keybytes
  , sodium_secretbox_macbytes
  , sodium_secretbox_noncebytes
  ) where

import Foundation

import Crypto.Lithium.Internal.Util

foreign import ccall "crypto_secretbox_keygen"
  sodium_secretbox_keygen :: Ptr CChar
                          -- ^ Key output buffer
                          -> IO CInt

foreign import ccall "crypto_secretbox_easy"
  sodium_secretbox_easy :: Ptr CChar
                        -- ^ Ciphertext output buffer
                        -> Ptr CChar
                        -- ^ Message input buffer
                        -> CULLong
                        -- ^ Message length
                        -> Ptr CChar
                        -- ^ Nonce input buffer
                        -> Ptr CChar
                        -- ^ Key input buffer
                        -> IO CInt

foreign import ccall "crypto_secretbox_open_easy"
  sodium_secretbox_open_easy :: Ptr CChar
                             -- ^ Message output buffer
                             -> Ptr CChar
                             -- ^ Ciphertext input buffer
                             -> CULLong
                             -- ^ Ciphertext length
                             -> Ptr CChar
                             -- ^ Nonce input buffer
                             -> Ptr CChar
                             -- ^ Key input buffer
                             -> IO CInt

foreign import ccall "crypto_secretbox_detached"
  sodium_secretbox_detached :: Ptr CChar
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
                            -- ^ Key input buffer
                            -> IO CInt

foreign import ccall "crypto_secretbox_open_detached"
  sodium_secretbox_open_detached :: Ptr CChar
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
                                 -- ^ Key input buffer
                                 -> IO CInt

foreign import ccall "crypto_secretbox_keybytes"
  sodium_secretbox_keybytes :: CSize

foreign import ccall "crypto_secretbox_macbytes"
  sodium_secretbox_macbytes :: CSize

foreign import ccall "crypto_secretbox_noncebytes"
  sodium_secretbox_noncebytes :: CSize
