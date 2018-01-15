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
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_HADDOCK hide, show-extensions #-}
{-|
Module      : Crypto.Lithium.Util.Sized
Description : Sized byte arrays
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Util.Sized
  ( type ByteOp
  , type ByteOps

  , N
  , fromN

  , emptyN
  , allocRetN
  , singletonN
  , replicateN
  , zerosN

  , copyN
  , copyN'

  , maybeToN
  , coerceToN
  , convertN

  , allZerosN
  , setN

  , appendN
  , appendN3

  , takeN'
  , takeN

  , dropN'
  , dropN

  , tailN'
  , tailN

  , splitN'
  , splitN
  , splitN3

  , xorN
  ) where

import Foundation
import Basement.Compat.Base
-- import Basement.Numerical.Multiplicative

-- import Data.Bits

import Data.ByteArray
  ( ByteArray
  , ByteArrayAccess
  )
import qualified Data.ByteArray as B
-- import Data.ByteString (ByteString)
-- import qualified Data.ByteString as BS
import Control.DeepSeq
import Crypto.Lithium.Util.Nat

{-|
Convenience wrapper for the common constraint of byte array access in,
one byte array out
-}
type ByteOp a b = (ByteArrayAccess a, ByteArray b)
{-|
Convenience wrapper for the common constraint of two byte array accesses in,
one byte array out
-}
type ByteOps a b c = (ByteArrayAccess a, ByteArrayAccess b, ByteArray c)

{-|
A type for representing byte arrays whose length is known on the type level
-}
newtype ByteArrayAccess t => N (l :: Nat) t = N t deriving (Eq, Ord, Show, NFData)

instance (ByteArray b) => ByteArrayAccess (N l b) where
  length (N bs) = B.length bs
  withByteArray (N bs) = B.withByteArray bs

{-- fun but dangerous for obscure memory reasons

instance (ByteArray b, KnownNat l) => Bits (N l b) where
  (.&.) = zipWithN (.&.)
  (.|.) = zipWithN (.|.)
  xor = xorN
  complement = mapN complement
  shiftL (N bs) by = N $ B.convert $ shiftBitsL (bitth by) $
    shiftBytesL (byteth by) $ B.convert bs
  shiftR (N bs) by = N $ B.convert $ shiftBitsR (bitth by) $
    shiftBytesR (byteth by) $ B.convert bs
  rotateL (N bs) by = N $ B.convert $ rotateBitsL (bitth by) $
    rotateBytesL (byteth by) $ B.convert bs
  rotateR (N bs) by = N $ B.convert $ rotateBitsR (bitth by) $
    rotateBytesR (byteth by) $ B.convert bs
  bitSizeMaybe bs = Just $ 8 * B.length bs
  isSigned _ = False
  testBit (N bs) i = testBit (B.index bs $ byteth i) $ bitth i
  bit i = coerceToN $ B.convert $ BS.snoc heads (bit i')
    where (ib, i') = bitByteth i
          heads = BS.replicate ib 0
  popCount (N bs) = BS.foldl' (\acc b -> acc + popCount b) 0 $ B.convert bs

bitth :: Int -> Int
bitth x = x `mod` 8

byteth :: Int -> Int
byteth x = x `div` 8

bitByteth :: Int -> (Int, Int)
bitByteth x = x `divMod` 8

shiftBytesL :: Int -> ByteString -> ByteString
shiftBytesL by bs
  | by >= blen = BS.replicate blen 0
  | by < 0 = shiftBytesR (-by) bs
  | otherwise = BS.append (BS.drop by bs) (BS.replicate by 0)
  where blen = BS.length bs

shiftBitsL :: Int -> ByteString -> ByteString
shiftBitsL by bs
  | by < 0 = shiftBitsR (-by) bs
  | otherwise = BS.pack $ BS.zipWith (.|.) shifted shifted'
  where shifted = BS.map (flip shiftL by') bs
        shifted' = shiftBytesL 1 $ BS.map (flip shiftL $ 8 - by') bs
        by' = bitth by

shiftBytesR :: Int -> ByteString -> ByteString
shiftBytesR by bs
  | by >= blen = BS.replicate blen 0
  | by < 0 = shiftBytesL (-by) bs
  | otherwise = BS.append (BS.replicate by 0) (BS.take (blen - by) bs)
  where blen = BS.length bs

shiftBitsR :: Int -> ByteString -> ByteString
shiftBitsR by bs
  | by < 0 = shiftBitsL (-by) bs
  | otherwise = BS.pack $ BS.zipWith (.|.) shifted shifted'
  where shifted = BS.map (flip shiftR by') bs
        shifted' = shiftBytesR 1 $ BS.map (flip shiftR $ 8 - by') bs
        by' = bitth by

rotateBytesL :: Int -> ByteString -> ByteString
rotateBytesL by bs =
  BS.append (BS.drop by' bs) (BS.take by' bs)
  where blen = BS.length bs
        by' = by `mod` blen

rotateBitsL :: Int -> ByteString -> ByteString
rotateBitsL by bs
  | by < 0 = rotateBitsR (-by) bs
  | otherwise = BS.pack $ BS.zipWith (.|.) rotated rotated'
  where rotated = BS.map (flip rotateL by') bs
        rotated' = rotateBytesL 1 $ BS.map (flip rotateL $ 8 - by') bs
        by' = bitth by

rotateBytesR :: Int -> ByteString -> ByteString
rotateBytesR by bs =
  BS.append (BS.drop by' bs) (BS.take by' bs)
  where blen = BS.length bs
        by' = blen - (by `mod` blen)

rotateBitsR :: Int -> ByteString -> ByteString
rotateBitsR by bs
  | by < 0 = rotateBitsL (-by) bs
  | otherwise = BS.pack $ BS.zipWith (.|.) rotated rotated'
  where rotated = BS.map (flip rotateR by') bs
        rotated' = rotateBytesR 1 $ BS.map (flip rotateR $ 8 - by') bs
        by' = bitth by

mapN :: ByteArray a => (Word8 -> Word8) -> N l a -> N l a
mapN f (N bs) = N $ B.convert $
  BS.map f (B.convert bs)

zipWithN :: ByteOps a b c => (Word8 -> Word8 -> Word8) -> N l a -> N l b -> N l c
zipWithN f (N as) (N bs) = N $ B.convert $
  BS.pack $ BS.zipWith f (B.convert as) (B.convert bs)

--}

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
Sized byte array of a single byte
-}
singletonN :: ByteArray a => Word8 -> N 1 a
singletonN x = N $ B.singleton x

{-|
Create sized byte array of specific byte
-}
replicateN :: forall a x. (ByteArray a, KnownNat x) => Word8 -> N x a
replicateN base = N $ B.replicate (asNum (ByteSize @x)) base

{-|
Create sized byte array of zeros
-}
zerosN :: forall a x. (ByteArray a, KnownNat x) => N x a
zerosN = replicateN 0

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
Copy a sized byte array, run the initializer on it, and return
-}
copyN :: forall a x p. (ByteArray a, KnownNat x)
      => N x a -> (Ptr p -> IO ()) -> IO (N x a)
copyN bs f = N <$> B.copy bs f

{-|
Copy a sized byte array, run the initializer on it, and return
-}
copyN' :: forall a x p e. (ByteArray a, KnownNat x)
      => N x a -> (Ptr p -> IO e) -> IO (e, N x a)
copyN' bs f = do
  (e, bs') <- B.copyRet bs f
  return (e, N bs')

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
Test whether the sized byte array is only zeros
-}
allZerosN :: ByteArray a => N x a -> Bool
allZerosN (N a) = B.all (== 0) a

{-|
Set a byte of the sized byte array to a specific value
-}
setN :: (ByteArray a, KnownNat i) => proxy i -> N (i + (1 + x)) a -> Word8 -> N (i + (1 + x)) a
setN proxy bs x =
  let (hd, tl) = splitN' proxy bs
      tl' = appendN (singletonN x) $ dropN tl
  in appendN hd tl'

{-|
Append sized byte arrays
-}
appendN :: ByteArray a => N x a -> N y a -> N (x + y) a
appendN (N a) (N b) = N $ B.append a b

{-|
Append three sized byte arrays
-}
appendN3 :: ByteArray a => N x a -> N y a -> N z a -> N (x + (y + z)) a
appendN3 as bs cs = appendN as $ appendN bs cs

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
Take /proxy/ number of bytes from the end of the sized byte array
-}
tailN' :: (ByteArray a, KnownNat y) => proxy y -> N (x + y) a -> N y a
tailN' proxy (N a) = N $ B.drop toDrop a
  where
    toDrop = B.length a - asNum proxy

{-|
Take the correct number of bytes from the end of the sized byte array
-}
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
Split the byte array to the correct lengths
-}
splitN3 :: forall a x y z. (ByteArray a, KnownNats x y, KnownNat (y + z))
        => N (x + (y + z)) a -> (N x a, N y a, N z a)
splitN3 as =
  let (a, bs) = splitN as
      (b, c) = splitN bs
  in (a, b, c)

{-|
Xor two sized byte arrays together
-}
xorN :: ByteArray a => N x a -> N x a -> N x a
xorN (N a) (N b) = N $ a `B.xor` b
