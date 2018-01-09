{ mkDerivation
, base
, basement
, base16-bytestring
, bytestring
, deepseq
, foundation
, hspec
, libsodium
, memory
, stdenv
, tasty
, tasty-hspec
, QuickCheck
}:
mkDerivation {
  pname = "lithium";
  version = "0.0.0.1";
  src = ./.;
  libraryHaskellDepends = [
    base
    basement
    bytestring
    deepseq
    foundation
    memory
  ];
  libraryPkgconfigDepends = [ libsodium ];
  testHaskellDepends = [
    base
    base16-bytestring
    bytestring
    hspec
    memory
    tasty
    tasty-hspec
    QuickCheck
  ];
  description = "Cryptography that's slightly less likely to blow up on you";
  license = stdenv.lib.licenses.unlicense;
}
