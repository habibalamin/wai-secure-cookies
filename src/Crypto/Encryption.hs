module Crypto.Encryption (Encrypted(..)
                        , getIV
                        , getSecret
                        , encrypt
                        , decrypt) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Crypto.Error (CryptoFailable(..), CryptoError(..))
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (BlockCipher(..), Cipher(..), makeIV)

data Encrypted = Encrypted String ByteString deriving (Eq, Show)

encrypt :: String -> String -> ByteString -> CryptoFailable Encrypted
encrypt stringIV key secret =
  aes256Init key >>=
  \context -> case makeIV $ BS.pack stringIV of
    Nothing -> CryptoFailed CryptoError_IvSizeInvalid
    Just iv -> CryptoPassed
      . Encrypted stringIV
      . ctrCombine context iv
      $ secret

decrypt :: String -> Encrypted -> CryptoFailable ByteString
-- AES/CTR decrypt operation is identical to encrypt
decrypt key (Encrypted iv secret) = getSecret <$> encrypt iv key secret

getIV :: Encrypted -> String
getIV (Encrypted iv _) = iv

getSecret :: Encrypted -> ByteString
getSecret (Encrypted _ secret) = secret

aes256Init :: String -> CryptoFailable AES256
aes256Init = cipherInit . BS.pack
