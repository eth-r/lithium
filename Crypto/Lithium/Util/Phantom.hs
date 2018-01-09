module Crypto.Lithium.Util.Phantom where

{-|
Phantom functor: change the phantom type without modifying contents

This allows us to construct easy cryptographic operations at high sophistication
on the type level.
-}
class PhantomFunctor p where
  pfmap :: (a -> b) -> p a -> p b
