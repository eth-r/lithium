{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ConstraintKinds #-}
module Crypto.Lithium.Util.Nat
  ( module GHC.TypeLits
  , ByteSize(..)
  , type Between
  , type AtLeast
  , type AtMost
  , type KnownNats
  , asNum

  , b4, b8, b12, b16, b24, b32, b40, b48, b56, b64
  ) where

import GHC.Num
import GHC.TypeLits

import Foundation

data ByteSize (n :: Nat) = ByteSize

type Between (atLeast :: Nat) (atMost :: Nat) (n :: Nat) =
  (KnownNat n, KnownNats atLeast atMost, atLeast <= n, n <= atMost)

type AtLeast (atLeast :: Nat) (n :: Nat) =
  (KnownNats n atLeast, atLeast <= n)

type AtMost (atMost :: Nat) (n :: Nat) =
  (KnownNats n atMost, n <= atMost)

type KnownNats (n :: Nat) (m :: Nat) =
  (KnownNat n, KnownNat m)

asNum :: (KnownNat n, Num w) => proxy n -> w
asNum = fromIntegral . natVal

{-|
Proxy constants for static byte sizes
-}
b4 :: ByteSize 4
b4 = ByteSize

b8 :: ByteSize 8
b8 = ByteSize

b12 :: ByteSize 12
b12 = ByteSize

b16 :: ByteSize 16
b16 = ByteSize

b24 :: ByteSize 24
b24 = ByteSize

b32 :: ByteSize 32
b32 = ByteSize

b40 :: ByteSize 40
b40 = ByteSize

b48 :: ByteSize 48
b48 = ByteSize

b56 :: ByteSize 56
b56 = ByteSize

b64 :: ByteSize 64
b64 = ByteSize
