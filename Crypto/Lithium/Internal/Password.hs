{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.Password
  ( sodium_pwhash
  , sodium_pwhash_str
  , sodium_pwhash_str_verify
  , sodium_pwhash_str_needs_rehash

  , sodium_pwhash_alg_argon2i13
  , sodium_pwhash_alg_argon2id13
  , sodium_pwhash_alg_default

  , sodium_pwhash_bytes_max
  , sodium_pwhash_bytes_min

  , sodium_pwhash_memlimit_interactive
  , sodium_pwhash_memlimit_moderate
  , sodium_pwhash_memlimit_sensitive
  , sodium_pwhash_memlimit_min
  , sodium_pwhash_memlimit_max

  , sodium_pwhash_opslimit_interactive
  , sodium_pwhash_opslimit_moderate
  , sodium_pwhash_opslimit_sensitive
  , sodium_pwhash_opslimit_min
  , sodium_pwhash_opslimit_max

  , sodium_pwhash_passwd_min
  , sodium_pwhash_passwd_max
  , sodium_pwhash_saltbytes
  , sodium_pwhash_strbytes
  , sodium_pwhash_strprefix
  ) where

import Foundation

import Crypto.Lithium.Internal.Util


foreign import ccall "crypto_pwhash"
  sodium_pwhash :: Ptr CChar
                -- ^ Derived key output buffer
                -> CULLong
                -- ^ Derived key length
                -> Ptr CChar
                -- ^ Password input buffer
                -> CULLong
                -- ^ Password length
                -> Ptr CChar
                -- ^ Salt input buffer
                -> CULLong
                -- ^ Operation limit
                -> CSize
                -- ^ Memory usage limit
                -> CInt
                -- ^ Algorithm
                -> IO CInt

foreign import ccall "crypto_pwhash_str"
  sodium_pwhash_str :: Ptr CChar
                    -- ^ Hashed password output buffer
                    -> Ptr CChar
                    -- ^ Password input buffer
                    -> CULLong
                    -- ^ Password length
                    -> CULLong
                    -- ^ Operation limit
                    -> CSize
                    -- ^ Memory usage limit
                    -> IO CInt

foreign import ccall "crypto_pwhash_str_verify"
  sodium_pwhash_str_verify :: Ptr CChar
                           -- ^ Hashed password input buffer
                           -> Ptr CChar
                           -- ^ Password input buffer
                           -> CULLong
                           -- ^ Password length
                           -> IO CInt

foreign import ccall "crypto_pwhash_str_needs_rehash"
  sodium_pwhash_str_needs_rehash :: Ptr CChar
                                 -- ^ Hashed password input buffer
                                 -> CULLong
                                 -- ^ Operation limit
                                 -> CSize
                                 -- ^ Memory usage limit
                                 -> IO CInt

foreign import ccall "crypto_pwhash_alg_argon2id13"
  sodium_pwhash_alg_argon2id13 :: CSize

foreign import ccall "crypto_pwhash_alg_argon2i13"
  sodium_pwhash_alg_argon2i13 :: CSize

foreign import ccall "crypto_pwhash_alg_default"
  sodium_pwhash_alg_default :: CSize

foreign import ccall "crypto_pwhash_bytes_max"
  sodium_pwhash_bytes_max :: CSize

foreign import ccall "crypto_pwhash_bytes_min"
  sodium_pwhash_bytes_min :: CSize

foreign import ccall "crypto_pwhash_memlimit_max"
  sodium_pwhash_memlimit_max :: CSize

foreign import ccall "crypto_pwhash_memlimit_min"
  sodium_pwhash_memlimit_min :: CSize

foreign import ccall "crypto_pwhash_memlimit_interactive"
  sodium_pwhash_memlimit_interactive :: CSize

foreign import ccall "crypto_pwhash_memlimit_moderate"
  sodium_pwhash_memlimit_moderate :: CSize

foreign import ccall "crypto_pwhash_memlimit_sensitive"
  sodium_pwhash_memlimit_sensitive :: CSize

foreign import ccall "crypto_pwhash_opslimit_max"
  sodium_pwhash_opslimit_max :: CSize

foreign import ccall "crypto_pwhash_opslimit_min"
  sodium_pwhash_opslimit_min :: CSize

foreign import ccall "crypto_pwhash_opslimit_interactive"
  sodium_pwhash_opslimit_interactive :: CSize

foreign import ccall "crypto_pwhash_opslimit_moderate"
  sodium_pwhash_opslimit_moderate :: CSize

foreign import ccall "crypto_pwhash_opslimit_sensitive"
  sodium_pwhash_opslimit_sensitive :: CSize

foreign import ccall "crypto_pwhash_passwd_max"
  sodium_pwhash_passwd_max :: CSize

foreign import ccall "crypto_pwhash_passwd_min"
  sodium_pwhash_passwd_min :: CSize

foreign import ccall "crypto_pwhash_saltbytes"
  sodium_pwhash_saltbytes :: CSize

foreign import ccall "crypto_pwhash_strbytes"
  sodium_pwhash_strbytes :: CSize

foreign import ccall "crypto_pwhash_strprefix"
  sodium_pwhash_strprefix :: CSize
