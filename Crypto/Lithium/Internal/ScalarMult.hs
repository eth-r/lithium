module Crypto.Lithium.Internal.ScalarMult
  ( sodium_scalarmult_base
  ) where




foreign import ccall "crypto_scalarmult_base"
  sodium_scalarmult_base :: Ptr CChar
                         -- ^ Output buffer
                         -> Ptr CChar
                         -- ^ Input buffer
                         -> IO CInt
