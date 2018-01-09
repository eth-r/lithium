{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.Sign
  ( sodium_sign_keypair
  , sodium_sign_seed_keypair
  , sodium_sign
  , sodium_sign_open
  , sodium_sign_detached
  , sodium_sign_verify_detached
  , sodium_sign_sk_to_seed
  , sodium_sign_sk_to_pk

  , sodium_sign_publickeybytes
  , sodium_sign_secretkeybytes
  , sodium_sign_bytes
  , sodium_sign_seedbytes
  ) where

import Foundation

import Crypto.Lithium.Internal.Util

foreign import ccall "crypto_sign_keypair"
  sodium_sign_keypair :: Ptr CChar
                      -- ^ Public key output buffer
                      -> Ptr CChar
                      -- ^ Secret key output buffer
                      -> IO CInt

foreign import ccall "crypto_sign_seed_keypair"
  sodium_sign_seed_keypair :: Ptr CChar
                          -- ^ Public key output buffer
                          -> Ptr CChar
                          -- ^ Secret key output buffer
                          -> Ptr CChar
                          -- ^ Seed input buffer
                          -> IO CInt

foreign import ccall "crypto_sign_ed25519_sk_to_seed"
  sodium_sign_sk_to_seed :: Ptr CChar
                         -- ^ Seed output buffer
                         -> Ptr CChar
                         -- ^ Secret key input buffer
                         -> IO CInt

foreign import ccall "crypto_sign_ed25519_sk_to_pk"
  sodium_sign_sk_to_pk :: Ptr CChar
                       -- ^ Public key output buffer
                       -> Ptr CChar
                       -- ^ Secret key input buffer
                       -> IO CInt

foreign import ccall "crypto_sign"
  sodium_sign :: Ptr CChar
              -- ^ Signed message output buffer
              -> Ptr CULLong
              -- ^ Signed message length output buffer
              -> Ptr CChar
              -- ^ Message input buffer
              -> CULLong
              -- ^ Message length
              -> Ptr CChar
              -- ^ Signer secret key input buffer
              -> IO CInt

foreign import ccall "crypto_sign_open"
  sodium_sign_open :: Ptr CChar
                   -- ^ Message output buffer
                   -> Ptr CULLong
                   -- ^ Message length output buffer
                   -> Ptr CChar
                   -- ^ Signed message input buffer
                   -> CULLong
                   -- ^ Signed message length
                   -> Ptr CChar
                   -- ^ Signer public key input buffer
                   -> IO CInt

foreign import ccall "crypto_sign_detached"
  sodium_sign_detached :: Ptr CChar
                       -- ^ Signature output buffer
                       -> Ptr CULLong
                       -- ^ Signature length output buffer
                       -> Ptr CChar
                       -- ^ Message input buffer
                       -> CULLong
                       -- ^ Message length
                       -> Ptr CChar
                       -- ^ Signer secret key input buffer
                       -> IO CInt

foreign import ccall "crypto_sign_verify_detached"
  sodium_sign_verify_detached :: Ptr CChar
                              -- ^ Signature input buffer
                              -> Ptr CChar
                              -- ^ Signed message input buffer
                              -> CULLong
                              -- ^ Signed message length
                              -> Ptr CChar
                              -- ^ Signer public key input buffer
                              -> IO CInt

foreign import ccall "crypto_sign_publickeybytes"
  sodium_sign_publickeybytes :: CSize

foreign import ccall "crypto_sign_secretkeybytes"
  sodium_sign_secretkeybytes :: CSize

foreign import ccall "crypto_sign_bytes"
  sodium_sign_bytes :: CSize

foreign import ccall "crypto_sign_seedbytes"
  sodium_sign_seedbytes :: CSize
