{-# LANGUAGE NoImplicitPrelude #-}
module Crypto.Lithium.Internal.Init
  ( sodium_init
  ) where

import Foundation
import Foreign.C.Types

foreign import ccall "sodium_init"
  sodium_init :: IO CInt
