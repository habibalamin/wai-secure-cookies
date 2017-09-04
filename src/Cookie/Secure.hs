module Cookie.Secure (encryptAndSign
                    , verifyAndDecrypt
                    , encryptAndSignIO
                    , verifyAndDecryptIO) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Crypto.Error (CryptoFailable, maybeCryptoError, throwCryptoErrorIO)
import System.Random (getStdRandom, randomR)
import Data.Char (chr)
import Control.Monad (replicateM)
import System.Environment (getEnv)

import Crypto.Encryption (encrypt, decrypt)
import Crypto.Verification (sign
                          , verify
                          , serialize
                          , deserialize
                          , getSignable)

encryptAndSign
  :: String
  -> String
  -> String
  -> ByteString
  -> CryptoFailable ByteString
encryptAndSign iv encryptKey authKey message = serialize <$> signed
  where
    signed = sign authKey <$> encrypted
    encrypted = encrypt iv encryptKey message

-- OPTIMIZE: wrap result in Either errorType, instead of Maybe.
-- Ideally, wrap it in a CryptoFailable, but that does not take
-- any error type except CryptoError, which has no constructors
-- for any signing/verification failures (/deserialization).
verifyAndDecrypt :: String -> String -> ByteString -> Maybe ByteString
verifyAndDecrypt authKey encryptKey message =
  deserialize message >>= verifyAndDecryptDeserialized
    where
      verifyAndDecryptDeserialized signed = 
        if verify authKey signed
        then maybeCryptoError $ decrypt encryptKey (getSignable signed)
        else Nothing

encryptAndSignIO :: ByteString -> IO ByteString
encryptAndSignIO message = do
  (iv, validationKey, encryptionKey) <- getIVAuthKeyEncryptKey

  throwCryptoErrorIO
    $ encryptAndSign iv encryptionKey validationKey message

verifyAndDecryptIO :: ByteString -> IO (Maybe ByteString)
verifyAndDecryptIO message = do
  (_, validationKey, encryptionKey) <- getIVAuthKeyEncryptKey

  return $ verifyAndDecrypt validationKey encryptionKey message

getIVAuthKeyEncryptKey :: IO (String, String, String)
getIVAuthKeyEncryptKey = (,,)
  -- The function takes a string for the IV, but the AES-256/CTR algorithm
  -- is just looking for bytes. Printability in ASCII, UTF-8, or any other
  -- encoding doesn't matter.
  <$> get16RandomBytes
  <*> getEnv "WAI_COOKIE_VALIDATION_KEY"
  <*> getEnv "WAI_COOKIE_ENCRYPTION_KEY"
    where
      get16RandomBytes =
        replicateM 16 . getStdRandom $ randomR (chr 0, chr 255)
