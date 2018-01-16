{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-|
Module      : Crypto.Lithium.Password
Description : Protect secrets with passwords
Copyright   : (c) Promethea Raschke 2018
License     : public domain
Maintainer  : eth.raschke@liminal.ai
Stability   : experimental
Portability : unknown
-}
module Crypto.Lithium.Password
  ( Password(..)

  , U.Salt(..)
  , U.asSalt
  , U.fromSalt
  , U.newSalt

  -- * Password storage
  , U.PasswordString(..)
  , storePassword
  , verifyPassword
  , needsRehash

  -- * Key derivation from passwords
  , derive

  -- * Protecting secrets with passwords

  -- * Hashing policy
  , U.Policy(..)
  , U.interactivePolicy
  , U.moderatePolicy
  , U.sensitivePolicy

  , U.Opslimit
  , U.opslimit
  , U.getOpslimit

  , U.minOpslimit
  , U.maxOpslimit

  , U.opslimitInteractive
  , U.opslimitModerate
  , U.opslimitSensitive

  , U.Memlimit
  , U.memlimit
  , U.getMemlimit

  , U.minMemlimit
  , U.maxMemlimit

  , U.memlimitInteractive
  , U.memlimitModerate
  , U.memlimitSensitive

  , U.Algorithm
  , U.algorithm
  , U.getAlgorithm

  , U.defaultAlgorithm

  , U.KnownAlgorithm(..)

  -- * Constants
  , U.SaltBytes
  , U.saltBytes
  , U.saltSize

  , U.PasswordStringBytes
  , U.passwordStringBytes
  , U.passwordStringSize

  , U.TagBytes
  , U.tagBytes
  , U.tagSize
  ) where


import qualified Crypto.Lithium.Unsafe.Password as U
import Crypto.Lithium.Derive (Deriveable(..))
import Crypto.Lithium.Unsafe.Types

import Foundation
import Control.DeepSeq

import Data.ByteArray as B

{-|
Password type wrapper which automatically zeroes out the memory
when the password goes out of scope
-}
newtype Password = Password
  { unPassword :: ScrubbedBytes
  } deriving (Eq, Ord, Show, IsString, ByteArrayAccess, NFData)

{-|
Hash a password with the given policy parameters into a 'U.PasswordString' suitable
for storage
-}
storePassword :: U.Policy -> Password -> IO U.PasswordString
storePassword policy (Password pw) =
  U.storePassword policy pw

{-|
Verifies a given password against a verification string

> > let pwstr = storePassword moderatePolicy (Password "hunter2")
> > verifyPassword pwstr (Password "hunter2")
> True
> > verifyPassword pwstr (Password "password")
> False

-}
verifyPassword :: U.PasswordString -> Password -> Bool
verifyPassword pwstr (Password pw) =
  U.verifyPassword pwstr pw

{-|
Tests if a given password verification string needs to be rehashed to match
current policy

> > let oldPolicy = moderatePolicy
> > let oldstr = storePassword oldPolicy (Password "hunter2")
> > let newPolicy = sensitivePolicy
> > let newstr = storePassword newPolicy (Password "password")
> > needsRehash newPolicy oldstr
> True
> > needsRehash newPolicy newstr
> False

Ignores the algorithm of the policy, instead always favoring the current
'defaultAlgorithm'.
-}
needsRehash :: U.Policy -> U.PasswordString -> Bool
needsRehash = U.needsRehash



{-|
Derive a key from a password
-}
derive :: (Deriveable k l, KnownNat l) => Password -> U.Salt -> U.Policy -> k
derive (Password pw) salt policy =
  U.derive pw salt policy
