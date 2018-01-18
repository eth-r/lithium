{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.Aead
  ( keygen
  , encrypt
  , decrypt
  , detached
  , openDetached

  , sodium_aead_keybytes
  , sodium_aead_macbytes
  , sodium_aead_noncebytes
  ) where

import Foundation

import Crypto.Lithium.Internal.Util

foreign import ccall "crypto_aead_xchacha20poly1305_ietf_keygen"
  sodium_aead_keygen :: Ptr CChar
                     -- ^ Key output buffer
                     -> IO CInt

keygen :: Ptr CChar -> IO ()
keygen key = void $ sodium_aead_keygen key

foreign import ccall "crypto_aead_xchacha20poly1305_ietf_encrypt"
  sodium_aead_encrypt :: Ptr CChar
                      -- ^ Ciphertext output buffer
                      -> Ptr CChar
                      -- ^ Ciphertext length output buffer
                      -> Ptr CChar
                      -- ^ Message input buffer
                      -> CULLong
                      -- ^ Message length
                      -> Ptr CChar
                      -- ^ Additional data input buffer
                      -> CULLong
                      -- ^ Additional data length
                      -> Ptr CChar
                      -- ^ Unused
                      -> Ptr CChar
                      -- ^ Nonce input buffer
                      -> Ptr CChar
                      -- ^ Key input buffer
                      -> IO CInt

encrypt :: Ptr CChar
        -> Ptr CChar
        -> Int
        -> Ptr CChar
        -> Int
        -> Ptr CChar
        -> Ptr CChar
        -> IO Int
encrypt ciphertext
        message mlen
        aad alen
        nonce key =
  fromIntegral <$> sodium_aead_encrypt ciphertext nullPtr
                                       message (fromIntegral mlen)
                                       aad (fromIntegral alen)
                                       nullPtr nonce key

foreign import ccall "crypto_aead_xchacha20poly1305_ietf_decrypt"
  sodium_aead_decrypt :: Ptr CChar
                      -- ^ Message output buffer
                      -> Ptr CChar
                      -- ^ Message length output buffer
                      -> Ptr CChar
                      -- ^ Unused
                      -> Ptr CChar
                      -- ^ Ciphertext input buffer
                      -> CULLong
                      -- ^ Ciphertext length
                      -> Ptr CChar
                      -- ^ Additional data input buffer
                      -> CULLong
                      -- ^ Additional data length
                      -> Ptr CChar
                      -- ^ Nonce input buffer
                      -> Ptr CChar
                      -- ^ Key input buffer
                      -> IO CInt

decrypt :: Ptr CChar
        -> Ptr CChar
        -> Int
        -> Ptr CChar
        -> Int
        -> Ptr CChar
        -> Ptr CChar
        -> IO Int
decrypt message
        ciphertext clen
        aad alen
        nonce key =
  fromIntegral <$> sodium_aead_decrypt message nullPtr nullPtr
                                       ciphertext (fromIntegral clen)
                                       aad (fromIntegral alen)
                                       nonce key

foreign import ccall "crypto_aead_xchacha20poly1305_ietf_encrypt_detached"
  sodium_aead_detached :: Ptr CChar
                       -- ^ Ciphertext output buffer
                       -> Ptr CChar
                       -- ^ Mac output buffer
                       -> Ptr CULLong
                       -- ^ Mac length output buffer
                       -> Ptr CChar
                       -- ^ Message input buffer
                       -> CULLong
                       -- ^ Message length
                       -> Ptr CChar
                       -- ^ Additional data input buffer
                       -> CULLong
                       -- ^ Additional data length
                       -> Ptr CChar
                       -- ^ Unused
                       -> Ptr CChar
                       -- ^ Nonce input buffer
                       -> Ptr CChar
                       -- ^ Key input buffer
                       -> IO CInt

detached :: Ptr CChar
         -> Ptr CChar
         -> Ptr CChar
         -> Int
         -> Ptr CChar
         -> Int
         -> Ptr CChar
         -> Ptr CChar
         -> IO Int
detached ciphertext mac
         message mlen
         aad alen
         nonce key =
  fromIntegral <$> sodium_aead_detached ciphertext
                                        mac nullPtr
                                        message (fromIntegral mlen)
                                        aad (fromIntegral alen)
                                        nullPtr
                                        nonce key

foreign import ccall "crypto_aead_xchacha20poly1305_ietf_decrypt_detached"
  sodium_aead_open_detached :: Ptr CChar
                            -- ^ Message output buffer
                            -> Ptr CChar
                            -- ^ Unused
                            -> Ptr CChar
                            -- ^ Ciphertext input buffer
                            -> CULLong
                            -- ^ Ciphertext length
                            -> Ptr CChar
                            -- ^ Mac input buffer
                            -> Ptr CChar
                            -- ^ Additional data input buffer
                            -> CULLong
                            -- ^ Additional data length
                            -> Ptr CChar
                            -- ^ Nonce input buffer
                            -> Ptr CChar
                            -- ^ Key input buffer
                            -> IO CInt

openDetached :: Ptr CChar
             -> Ptr CChar
             -> Int
             -> Ptr CChar
             -> Ptr CChar
             -> Int
             -> Ptr CChar
             -> Ptr CChar
             -> IO Int
openDetached message
              ciphertext clen
              mac
              aad alen
              nonce key =
  fromIntegral <$> sodium_aead_open_detached message nullPtr
                                             ciphertext (fromIntegral clen)
                                             mac
                                             aad (fromIntegral alen)
                                             nonce key

foreign import ccall "crypto_aead_xchacha20poly1305_ietf_keybytes"
  sodium_aead_keybytes :: CSize

foreign import ccall "crypto_aead_xchacha20poly1305_ietf_abytes"
  sodium_aead_macbytes :: CSize

foreign import ccall "crypto_aead_xchacha20poly1305_ietf_npubbytes"
  sodium_aead_noncebytes :: CSize
