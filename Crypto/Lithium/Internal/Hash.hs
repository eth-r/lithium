{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.Hash
  ( sodium_generichash
  , sodium_generichash_init
  , sodium_generichash_update
  , sodium_generichash_final
  , sodium_generichash_salt_personal
  , sodium_shorthash

  , sodium_generichash_bytes_min
  , sodium_generichash_bytes_max
  , sodium_generichash_bytes
  , sodium_generichash_keybytes_min
  , sodium_generichash_keybytes_max
  , sodium_generichash_keybytes
  , sodium_generichash_statebytes
  , sodium_shorthash_bytes
  , sodium_shorthash_keybytes
  ) where

import Foundation

import Crypto.Lithium.Internal.Util

foreign import ccall "crypto_generichash"
  sodium_generichash :: Ptr CChar
                     -- ^ Hash output buffer
                     -> CSize
                     -- ^ Output hash length
                     -> Ptr CChar
                     -- ^ Message input buffer
                     -> CULLong
                     -- ^ Message length
                     -> Ptr CChar
                     -- ^ Key input buffer, or 'nullPtr'
                     -> CSize
                     -- ^ Key length, or 0
                     -> IO CInt

foreign import ccall "crypto_generichash_init"
  sodium_generichash_init :: Ptr CChar
                          -- ^ NOTE: mutable state buffer
                          -> Ptr CChar
                          -- ^ Key input buffer, or 'nullPtr'
                          -> CSize
                          -- ^ Key length, or 0
                          -> CSize
                          -- ^ Output hash length
                          -> IO CInt

foreign import ccall "crypto_generichash_update"
  sodium_generichash_update :: Ptr CChar
                            -- ^ NOTE: mutable state buffer
                            -> Ptr CChar
                            -- ^ Chunk input buffer
                            -> CULLong
                            -- ^ Chunk length
                            -> IO CInt

foreign import ccall "crypto_generichash_final"
  sodium_generichash_final :: Ptr CChar
                           -- ^ NOTE: mutable state buffer
                           -> Ptr CChar
                           -- ^ Hash output buffer
                           -> CSize
                           -- ^ Output hash length
                           -> IO CInt

foreign import ccall "crypto_generichash_blake2b_salt_personal"
  sodium_generichash_salt_personal :: Ptr CChar
                                   -- ^ Hash output buffer
                                   -> CSize
                                   -- ^ Output hash length
                                   -> Ptr CChar
                                   -- ^ Message input buffer
                                   -> CULLong
                                   -- ^ Message length
                                   -> Ptr CChar
                                   -- ^ Key input buffer, or 'nullPtr'
                                   -> CSize
                                   -- ^ Key length, or 0
                                   -> IO CInt

foreign import ccall "crypto_shorthash"
  sodium_shorthash :: Ptr CChar
                   -- ^ Hash output buffer
                   -> Ptr CChar
                   -- ^ Message input buffer
                   -> CULLong
                   -- ^ Message length
                   -> Ptr CChar
                   -- ^ Key input buffer, or 'nullPtr'
                   -> IO CInt

foreign import ccall "crypto_generichash_bytes_min"
  sodium_generichash_bytes_min :: CSize

foreign import ccall "crypto_generichash_bytes_max"
  sodium_generichash_bytes_max :: CSize

foreign import ccall "crypto_generichash_bytes"
  sodium_generichash_bytes :: CSize

foreign import ccall "crypto_generichash_keybytes_min"
  sodium_generichash_keybytes_min :: CSize

foreign import ccall "crypto_generichash_keybytes_max"
  sodium_generichash_keybytes_max :: CSize

foreign import ccall "crypto_generichash_keybytes"
  sodium_generichash_keybytes :: CSize

foreign import ccall "crypto_generichash_statebytes"
  sodium_generichash_statebytes :: CSize

foreign import ccall "crypto_shorthash_bytes"
  sodium_shorthash_bytes :: CSize

foreign import ccall "crypto_shorthash_keybytes"
  sodium_shorthash_keybytes :: CSize
