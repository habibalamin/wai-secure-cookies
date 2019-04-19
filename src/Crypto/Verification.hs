{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.Verification (Signed(..)
                          , getSignable
                          , sign
                          , verify
                          , serialize
                          , deserialize
                          , deserializeSignable) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Crypto.Hash.Algorithms (SHA256)
import Crypto.MAC.HMAC (HMAC(..), hmac)
import Crypto.Hash (Digest, digestFromByteString)
import Data.ByteArray.Encoding (Base(..)
                              , convertToBase
                              , convertFromBase)
import Protolude (rightToMaybe)
import Data.Tuple (swap)

import Crypto.Encryption (Encrypted(..), getIV, getSecret)
import qualified Extension.ByteString as EBS

data Signed signable =
  Signed signable (Digest SHA256) deriving (Show, Eq)

class Eq signable => Signable signable where
  sign :: String -> signable -> Signed signable

  verify :: String -> Signed signable -> Bool
  verify key signed@(Signed message _) = sign key message == signed

  getSignable :: Signed signable -> signable
  getSignable (Signed signable _) = signable

  serializeSignable :: signable -> ByteString

  deserializeSignable :: ByteString -> Maybe signable

  serialize :: Signed signable -> ByteString
  serialize (Signed signable digest) =
    convertToBase Base64URLUnpadded (serializeSignable signable)
    `BS.append` "|signature." `BS.append`
    BS.pack (show digest)

  deserialize :: ByteString -> Maybe (Signed signable)
  deserialize bs = Signed
    <$> (rightToMaybe message >>= deserializeSignable)
    <*> (rightToMaybe signature >>= digestFromByteString)
      where
        (encodedMessage, base16Signature) =
          EBS.stripPrefix "|signature."
          <$> BS.span (/= '|') bs
        signature :: Either String ByteString
        signature = convertFromBase Base16 base16Signature
        message = convertFromBase Base64URLUnpadded encodedMessage

instance {-# OVERLAPPING #-} Signable String where
  sign key message = Signed message digest
    where
      digest = hmacGetDigest hmac'ed
      hmac'ed = hmac (BS.pack key) (BS.pack message) :: HMAC SHA256

  serializeSignable = convertToBase Base64URLUnpadded . BS.pack

  deserializeSignable bs = BS.unpack
    <$> rightToMaybe (convertFromBase Base64URLUnpadded bs)

instance Signable Encrypted where
  sign key message = Signed message digest
    where
      digest = hmacGetDigest hmac'ed
      hmac'ed =
        hmac (BS.pack key)
        (serializeSignable message) :: HMAC SHA256

  serializeSignable encrypted =
    "iv," `BS.append`
    convertToBase Base64URLUnpadded (BS.pack . getIV $ encrypted)
    `BS.append` "|" `BS.append`
    convertToBase Base64URLUnpadded (getSecret encrypted)

  deserializeSignable bs = Encrypted
    <$> (BS.unpack <$> rightToMaybe iv)
    <*> (rightToMaybe secret)
      where
        (base64Secret, base64IV) =
          EBS.stripPrefix "iv," . EBS.stripSuffix "|"
          <$> swap (BS.spanEnd (/= '|') bs)
        iv = convertFromBase Base64URLUnpadded base64IV
        secret = convertFromBase Base64URLUnpadded base64Secret
