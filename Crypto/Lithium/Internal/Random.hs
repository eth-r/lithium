{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Lithium.Internal.Random
  ( sodium_randombytes
  , sodium_randomnumber
  ) where

import Foundation
import Foreign.Ptr
import Foreign.C.Types

foreign import ccall "randombytes_buf"
  sodium_randombytes :: Ptr CChar
                     -> CInt
                     -> IO ()

foreign import ccall "randombytes_uniform"
  sodium_randomnumber :: CUInt -> IO CUInt
