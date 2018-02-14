{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.KeyExchange
  ( sodium_kx_keypair
  , sodium_kx_seed_keypair

  , sodium_kx_client_session_keys
  , sodium_kx_server_session_keys

  , sodium_kx_publickeybytes
  , sodium_kx_secretkeybytes
  , sodium_kx_seedbytes
  , sodium_kx_sessionkeybytes
  ) where

import Foundation

import Crypto.Lithium.Internal.Util

foreign import ccall "crypto_kx_keypair"
  sodium_kx_keypair :: Ptr CChar
                    -- ^ Public key output buffer
                    -> Ptr CChar
                    -- ^ Secret key output buffer
                    -> IO CInt

foreign import ccall "crypto_kx_seed_keypair"
  sodium_kx_seed_keypair :: Ptr CChar
                         -- ^ Public key output buffer
                         -> Ptr CChar
                         -- ^ Secret key output buffer
                         -> Ptr CChar
                         -- ^ Seed input buffer
                         -> IO CInt

foreign import ccall "crypto_kx_client_session_keys"
  sodium_kx_client_session_keys :: Ptr CChar
                                -- ^ RX key output buffer
                                -> Ptr CChar
                                -- ^ TX key output buffer
                                -> Ptr CChar
                                -- ^ Client public key input buffer
                                -> Ptr CChar
                                -- ^ Client secret key input buffer
                                -> Ptr CChar
                                -- ^ Server public key input buffer
                                -> IO CInt

foreign import ccall "crypto_kx_server_session_keys"
  sodium_kx_server_session_keys :: Ptr CChar
                                -- ^ RX key output buffer
                                -> Ptr CChar
                                -- ^ TX key output buffer
                                -> Ptr CChar
                                -- ^ Server public key input buffer
                                -> Ptr CChar
                                -- ^ Server secret key input buffer
                                -> Ptr CChar
                                -- ^ Client public key input buffer
                                -> IO CInt

foreign import ccall "crypto_kx_publickeybytes"
  sodium_kx_publickeybytes :: CSize

foreign import ccall "crypto_kx_secretkeybytes"
  sodium_kx_secretkeybytes :: CSize

foreign import ccall "crypto_kx_seedbytes"
  sodium_kx_seedbytes :: CSize

foreign import ccall "crypto_kx_sessionkeybytes"
  sodium_kx_sessionkeybytes :: CSize
