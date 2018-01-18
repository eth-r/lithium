module Crypto.Lithium.Internal.Util
  ( module Foundation.Foreign
  , module Crypto.Lithium.Util.Init
  , module Crypto.Lithium.Util.Phantom
  , module Crypto.Lithium.Util.Random
  , module Crypto.Lithium.Util.Secret
  , module Foreign.Ptr

  , System.IO.Unsafe.unsafePerformIO
  , void
  ) where

import Foreign.Ptr

import Foundation
import Foundation.Foreign

import System.IO.Unsafe ( unsafePerformIO )

import Crypto.Lithium.Util.Init
import Crypto.Lithium.Util.Phantom
import Crypto.Lithium.Util.Random
import Crypto.Lithium.Util.Secret

void :: IO e -> IO ()
void op = op >> return ()
