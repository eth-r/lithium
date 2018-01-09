{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.Hash
  ( sodium_generichash
  , sodium_generichash_salt_personal

  , sodium_generichash_bytes_min
  , sodium_generichash_bytes_max
  , sodium_generichash_bytes
  , sodium_generichash_keybytes_min
  , sodium_generichash_keybytes_max
  , sodium_generichash_keybytes
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
