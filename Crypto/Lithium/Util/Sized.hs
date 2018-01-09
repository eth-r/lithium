{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.Lithium.Util.Sized
  ( type ByteOp
  , type ByteOps

  , N
  , fromN

  , emptyN
  , allocRetN

  , maybeToN
  , coerceToN
  , convertN

  , appendN

  , takeN'
  , takeN

  , dropN'
  , dropN

  , tailN'
  , tailN

  , splitN'
  , splitN

  , xorN
  ) where

import Foundation
import Basement.Compat.Base

import Data.ByteArray
  ( ByteArray
  , ByteArrayAccess
  )
import qualified Data.ByteArray as B
import Control.DeepSeq
import Crypto.Lithium.Util.Nat

type ByteOp a b = (ByteArrayAccess a, ByteArray b)
type ByteOps a b c = (ByteArrayAccess a, ByteArrayAccess b, ByteArray c)

newtype N (l :: Nat) t = N t deriving (Eq, Ord, Show, NFData)

instance (ByteArray b, KnownNat l) => ByteArrayAccess (N l b) where
  length _ = asNum (ByteSize @l)
  withByteArray (N bs) = B.withByteArray bs


{-|
Return just the contents of a sized byte array
-}
fromN :: ByteArray a => N l a -> a
fromN (N a) = a


{-|
Empty sized byte array
-}
emptyN :: ByteArray a => N 0 a
emptyN = N B.empty

{-|
Allocate a sized byte array, run the initializer on it, and return
-}
allocRetN :: forall a x p e. (ByteArray a, KnownNat x)
          => (Ptr p -> IO e) -> IO (e, N x a)
allocRetN f = do
  let len = asNum (ByteSize @x)
  (e, bs) <- B.allocRet len f
  return (e, N bs)


{-|
Convert a byte array to a sized byte array

Returns 'Nothing' if the size doesn't match
-}
maybeToN :: forall a n. (ByteArray a, KnownNat n) => a -> Maybe (N n a)
maybeToN bs
  | B.length bs == asNum (ByteSize @n) = Just (N bs)
  | otherwise = Nothing

{-|
Force a byte array to be a sized byte array

If the byte array is longer, it will be truncated to the correct length

If the byte array is shorter, it will be padded with zeros
-}
coerceToN :: forall a n. (ByteArray a, KnownNat n) => a -> N n a
coerceToN bs =
  case compare len x of
    EQ -> N bs
    GT -> N $ B.take x bs
    LT -> N $ B.append bs $ B.replicate (x - len) 0
  where
    len = B.length bs
    x = asNum (ByteSize @n)

{-|
Convert between sized byte arrays of same length
-}
convertN :: forall bin bout n. (ByteOp bin bout, KnownNat n) => N n bin -> N n bout
convertN (N a) = N $ B.convert a


{-|
Append sized byte arrays
-}
appendN :: ByteArray a => N x a -> N y a -> N (x + y) a
appendN (N a) (N b) = N $ B.append a b

{-|
Take 'proxy' number of bytes from the sized byte array
-}
takeN' :: (ByteArray a, KnownNat x) => proxy x -> N (x + y) a -> N x a
takeN' proxy (N a) = N $ B.take (asNum proxy) a

{-|
Take the correct number of bytes from the sized byte array
-}
takeN :: forall a x y. (ByteArray a, KnownNat x) => N (x + y) a -> N x a
takeN = takeN' (ByteSize @x)


{-|
Drop 'proxy' number of bytes from the sized byte array
-}
dropN' :: (ByteArray a, KnownNat x) => proxy x -> N (x + y) a -> N y a
dropN' proxy (N a) = N $ B.drop (asNum proxy) a

{-|
Drop the correct number of bytes from the sized byte array
-}
dropN :: forall a x y. (ByteArray a, KnownNat x) => N (x + y) a -> N y a
dropN = dropN' (ByteSize @x)


{-|
Take the correct number of bytes from the end of the sized byte array
-}
tailN' :: (ByteArray a, KnownNat y) => proxy y -> N (x + y) a -> N y a
tailN' proxy (N a) = N $ B.drop toDrop a
  where
    toDrop = B.length a - asNum proxy

tailN :: forall a x y. (ByteArray a, KnownNat y) => N (x + y) a -> N y a
tailN = tailN' (ByteSize @y)


{-|
Split the byte array at a length defined by 'proxy'
-}
splitN' :: (ByteArray a, KnownNat x)
        => proxy x -> N (x + y) a -> (N x a, N y a)
splitN' proxy (N a) =
  let (b, c) = B.splitAt (asNum proxy) a
  in (N b, N c)

{-|
Split the byte array at the correct length without a proxy argument
-}
splitN :: forall a x y. (ByteArray a, KnownNat x)
       => N (x + y) a -> (N x a, N y a)
splitN = splitN' (ByteSize @x)


{-|
Xor two sized byte arrays together
-}
xorN :: ByteArray a => N x a -> N x a -> N x a
xorN (N a) (N b) = N $ a `B.xor` b
