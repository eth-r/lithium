{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.Stream
  ( sodium_stream_xchacha20_keygen
  , sodium_stream_xchacha20
  , sodium_stream_xchacha20_xor

  , sodium_stream_xchacha20_keybytes
  , sodium_stream_xchacha20_noncebytes
  ) where

import Foundation

import Crypto.Lithium.Internal.Util

foreign import ccall "crypto_stream_xchacha20_keygen"
  sodium_stream_xchacha20_keygen :: Ptr CChar
                                 -- ^ Key output buffer
                                 -> IO CInt

foreign import ccall "crypto_stream_xchacha20"
  sodium_stream_xchacha20 :: Ptr CChar
                          -- ^ Stream output buffer
                          -> CULLong
                          -- ^ Stream length
                          -> Ptr CChar
                          -- ^ Nonce input buffer
                          -> Ptr CChar
                          -- ^ Key input buffer
                          -> IO CInt

foreign import ccall "crypto_stream_xchacha20_xor"
  sodium_stream_xchacha20_xor :: Ptr CChar
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

foreign import ccall "crypto_stream_xchacha20_keybytes"
  sodium_stream_xchacha20_keybytes :: CSize

foreign import ccall "crypto_stream_xchacha20_noncebytes"
  sodium_stream_xchacha20_noncebytes :: CSize
