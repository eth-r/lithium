{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.OnetimeAuth
  ( sodium_onetimeauth_keygen
  , sodium_onetimeauth
  , sodium_onetimeauth_verify
  , sodium_onetimeauth_init
  , sodium_onetimeauth_update
  , sodium_onetimeauth_final

  , sodium_onetimeauth_bytes
  , sodium_onetimeauth_keybytes
  , sodium_onetimeauth_statebytes
  ) where

import Foundation

import Crypto.Lithium.Internal.Util

foreign import ccall "crypto_onetimeauth"
  sodium_onetimeauth :: Ptr CChar
                     -- ^ Mac output buffer
                     -> Ptr CChar
                     -- ^ Message input buffer
                     -> CULLong
                     -- ^ Message length
                     -> Ptr CChar
                     -- ^ Key input buffer
                     -> IO CInt

foreign import ccall "crypto_onetimeauth_verify"
  sodium_onetimeauth_verify :: Ptr CChar
                            -- ^ Mac input buffer
                            -> Ptr CChar
                            -- ^ Message input buffer
                            -> CULLong
                            -- ^ Message length
                            -> Ptr CChar
                            -- ^ Key input buffer
                            -> IO CInt

foreign import ccall "crypto_onetimeauth_keygen"
  sodium_onetimeauth_keygen :: Ptr CChar
                            -- ^ Key output buffer
                            -> IO ()

foreign import ccall "crypto_onetimeauth_init"
  sodium_onetimeauth_init :: Ptr CChar
                          -- ^ NOTE: mutable state buffer
                          -> Ptr CChar
                          -- ^ Key input buffer
                          -> IO CInt

foreign import ccall "crypto_onetimeauth_update"
  sodium_onetimeauth_update :: Ptr CChar
                            -- ^ NOTE: mutable state buffer
                            -> Ptr CChar
                            -- ^ Chunk input buffer
                            -> CULLong
                            -- ^ Chunk length
                            -> IO CInt

foreign import ccall "crypto_onetimeauth_final"
  sodium_onetimeauth_final :: Ptr CChar
                           -- ^ NOTE: mutable state buffer
                           -> Ptr CChar
                           -- ^ Mac output buffer
                           -> IO CInt

foreign import ccall "crypto_onetimeauth_bytes"
  sodium_onetimeauth_bytes :: CSize

foreign import ccall "crypto_onetimeauth_keybytes"
  sodium_onetimeauth_keybytes :: CSize

foreign import ccall "crypto_onetimeauth_statebytes"
  sodium_onetimeauth_statebytes :: CSize
