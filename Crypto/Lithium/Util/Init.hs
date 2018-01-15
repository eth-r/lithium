{-|
Module      : Crypto.Lithium.Util.Init
Description : Lithium initialization
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Util.Init
  ( withLithium
  ) where

import Foundation
import System.IO.Unsafe ( unsafePerformIO )

import Crypto.Lithium.Internal.Init


{-|
'ensureInitialized' wrapper to ensure the library isn't called without
initialization.

As 'ensureInitialized' is constructed with 'unsafePerformIO' to fake referential
transparency, it will have certain funny properties, such as not being called
again if it has already been called. In this case this is precisely the desired
behavior: we want to ensure 'lithiumInit' is called one or more times before any
cryptographic operations happen. The short-circuiting nature of the Haskell
runtime should skip subsequent calls after the first one, to reduce the overhead
of calling @sodium_init@ on every operation from the less unsafe API.

Needless to say, this is a big hack and should be scrutinized appropriately.
-}
withLithium :: a -> a
-- HACK: use the funny properties of unsafePerformIO to our advantage
-- XXX:  relies on weird behavior
withLithium operation = ensureInitialized `seq` operation

{-|
Build a fake pure wrapper for 'lithiumInit' to initialize the library
-}
ensureInitialized :: ()
-- HACK: use the funny properties of unsafePerformIO to our advantage
-- XXX:  relies on weird behavior
ensureInitialized = unsafePerformIO sodiumInit
{-# NOINLINE ensureInitialized #-}

{-|
Raw library initialization
-}
sodiumInit :: IO ()
sodiumInit = do
  e <- sodium_init
  case e of
    1 -> return ()
    0 -> return ()
    _ -> error "sodium cannot be safely initialized"
