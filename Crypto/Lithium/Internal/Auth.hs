{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.Auth
  ( sodium_auth_keygen
  , sodium_auth
  , sodium_auth_verify

  , sodium_auth_bytes
  , sodium_auth_keybytes
  ) where

import Foundation

import Crypto.Lithium.Internal.Util

foreign import ccall "crypto_auth_keygen"
  sodium_auth_keygen :: Ptr CChar
                     -- ^ Key output buffer
                     -> IO ()

foreign import ccall "crypto_auth"
  sodium_auth :: Ptr CChar
              -- ^ Mac output buffer
              -> Ptr CChar
              -- ^ Message input buffer
              -> CULLong
              -- ^ Message length
              -> Ptr CChar
              -- ^ Key input buffer
              -> IO CInt

foreign import ccall "crypto_auth_verify"
  sodium_auth_verify :: Ptr CChar
                     -- ^ Mac input buffer
                     -> Ptr CChar
                     -- ^ Message input buffer
                     -> CULLong
                     -- ^ Message length
                     -> Ptr CChar
                     -- ^ Key input buffer
                     -> IO CInt

foreign import ccall "crypto_auth_bytes"
  sodium_auth_bytes :: CSize

foreign import ccall "crypto_auth_keybytes"
  sodium_auth_keybytes :: CSize
