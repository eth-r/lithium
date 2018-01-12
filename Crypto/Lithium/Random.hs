{-|
Module      : Crypto.Lithium.Random
Description : Random number generators
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Random
  ( randomBytes
  , randomNumber
  , randomSecretN
  , randomBytesN
  ) where

import Crypto.Lithium.Util.Random (randomBytes, randomNumber, randomSecretN, randomBytesN)
