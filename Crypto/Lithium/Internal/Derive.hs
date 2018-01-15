{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.Derive
  ( sodium_kdf_keygen
  , sodium_kdf_derive

  , sodium_kdf_primitive
  , sodium_kdf_bytes_min
  , sodium_kdf_bytes_max
  , sodium_kdf_contextbytes
  , sodium_kdf_keybytes
  ) where

import Foundation

import Crypto.Lithium.Internal.Util


foreign import ccall "crypto_kdf_keygen"
  sodium_kdf_keygen :: Ptr CChar
                    -- ^ Key output buffer
                    -> IO ()

foreign import ccall "crypto_kdf_derive_from_key"
  sodium_kdf_derive :: Ptr CChar
                    -- ^ Subkey output buffer
                    -> CSize
                    -- ^ Subkey length
                    -> CULLong
                    -- ^ Subkey id
                    -> Ptr CChar
                    -- ^ Context input buffer
                    -> Ptr CChar
                    -- ^ Key input buffer
                    -> IO CInt

foreign import ccall "crypto_kdf_primitive"
  sodium_kdf_primitive :: CSize

foreign import ccall "crypto_kdf_bytes_max"
  sodium_kdf_bytes_max :: CSize

foreign import ccall "crypto_kdf_bytes_min"
  sodium_kdf_bytes_min :: CSize

foreign import ccall "crypto_kdf_contextbytes"
  sodium_kdf_contextbytes :: CSize

foreign import ccall "crypto_kdf_keybytes"
  sodium_kdf_keybytes :: CSize
