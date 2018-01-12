{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.SecretStream
  ( sodium_secretstream_keygen
  , sodium_secretstream_init_push
  , sodium_secretstream_push
  , sodium_secretstream_init_pull
  , sodium_secretstream_pull
  , sodium_secretstream_rekey

  , sodium_secretstream_keybytes
  , sodium_secretstream_macbytes
  , sodium_secretstream_headerbytes
  , sodium_secretstream_statebytes
  , sodium_secretstream_messagebytes_max
  , sodium_secretstream_tag_message
  , sodium_secretstream_tag_push
  , sodium_secretstream_tag_rekey
  , sodium_secretstream_tag_final
  ) where

import Foundation

import Crypto.Lithium.Internal.Util

foreign import ccall "crypto_secretstream_xchacha20poly1305_keygen"
  sodium_secretstream_keygen :: Ptr CChar
                             -- ^ Key output buffer
                             -> IO ()

foreign import ccall "crypto_secretstream_xchacha20poly1305_init_push"
  sodium_secretstream_init_push :: Ptr CChar
                                -- ^ State output buffer
                                -> Ptr CChar
                                -- ^ Header output buffer
                                -> Ptr CChar
                                -- ^ Key input buffer
                                -> IO CInt

foreign import ccall "crypto_secretstream_xchacha20poly1305_push"
  sodium_secretstream_push :: Ptr CChar
                           -- ^ NOTE: mutable state buffer
                           -> Ptr CChar
                           -- ^ Ciphertext output buffer
                           -> Ptr CULLong
                           -- ^ Ciphertext length output buffer
                           -> Ptr CChar
                           -- ^ Message input buffer
                           -> CULLong
                           -- ^ Message length
                           -> Ptr CChar
                           -- ^ Additional data input buffer
                           -> CULLong
                           -- ^ Additional data length
                           -> CChar
                           -- ^ Tag
                           -> IO CInt

foreign import ccall "crypto_secretstream_xchacha20poly1305_init_pull"
  sodium_secretstream_init_pull :: Ptr CChar
                                -- ^ State output buffer
                                -> Ptr CChar
                                -- ^ Header input buffer
                                -> Ptr CChar
                                -- ^ Key input buffer
                                -> IO CInt
                                -- ^ 0 if successful, -1 if invalid header

foreign import ccall "crypto_secretstream_xchacha20poly1305_pull"
  sodium_secretstream_pull :: Ptr CChar
                           -- ^ NOTE: mutable state buffer
                           -> Ptr CChar
                           -- ^ Message output buffer
                           -> Ptr CULLong
                           -- ^ Message length output buffer
                           -> Ptr CChar
                           -- ^ Tag output buffer
                           -> Ptr CChar
                           -- ^ Ciphertext input buffer
                           -> CULLong
                           -- ^ Ciphertext length
                           -> Ptr CChar
                           -- ^ Additional data input buffer
                           -> CULLong
                           -- ^ Additional data length
                           -> IO CInt
                           -- ^ 0 if valid ciphertext, -1 if invalid

foreign import ccall "crypto_secretstream_xchacha20poly1305_rekey"
  sodium_secretstream_rekey :: Ptr CChar
                            -- ^ NOTE: mutable state buffer
                            -> IO ()

foreign import ccall "crypto_secretstream_xchacha20poly1305_keybytes"
  sodium_secretstream_keybytes :: CSize

foreign import ccall "crypto_secretstream_xchacha20poly1305_abytes"
  sodium_secretstream_macbytes :: CSize

foreign import ccall "crypto_secretstream_xchacha20poly1305_headerbytes"
  sodium_secretstream_headerbytes :: CSize

foreign import ccall "crypto_secretstream_xchacha20poly1305_statebytes"
  sodium_secretstream_statebytes :: CSize

foreign import ccall "crypto_secretstream_xchacha20poly1305_messagebytes_max"
  sodium_secretstream_messagebytes_max :: CSize

foreign import ccall "crypto_secretstream_xchacha20poly1305_tag_message"
  sodium_secretstream_tag_message :: CSize

foreign import ccall "crypto_secretstream_xchacha20poly1305_tag_push"
  sodium_secretstream_tag_push :: CSize

foreign import ccall "crypto_secretstream_xchacha20poly1305_tag_rekey"
  sodium_secretstream_tag_rekey :: CSize

foreign import ccall "crypto_secretstream_xchacha20poly1305_tag_final"
  sodium_secretstream_tag_final :: CSize
