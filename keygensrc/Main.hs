module Main (main) where

import System.Environment (getArgs)
import System.IO (hPutStrLn, stderr)
import System.Exit (exitFailure)
import Control.Monad (unless)
import Data.List (intercalate)
import qualified Data.ByteString.Lazy.Char8 as BS
import Data.ByteString.Lazy (ByteString)
import Data.ByteString.Builder (toLazyByteString, byteStringHex)
import Crypto.Random.Types (getRandomBytes)
import Crypto.Hash (hashBlockSize, SHA256)
import Crypto.Cipher.Types (BlockCipher(..))
import Crypto.Cipher.AES (AES256)

main :: IO ()
main = getArgs >>= mainWithArgs

mainWithArgs :: [String] -> IO ()
mainWithArgs [] = do
  hPutStrLn stderr $ "usage: waicookie-genkey <key type> ...\n\n" ++
                     "key types: encryption\n" ++
                     "           validation"
  exitFailure
mainWithArgs xs = do
  unless (null invalidKeyTypes) $ do
    hPutStrLn stderr $
      "Unrecognised key types: " ++ intercalate ", " invalidKeyTypes
    exitFailure

  printRandomKeys xs

  where
      invalidKeyTypes = filter (not . isValidKeyType) xs

isValidKeyType :: String -> Bool
isValidKeyType "encryption" = True
isValidKeyType "validation" = True
isValidKeyType _ = False

printRandomKeys :: [String] -> IO ()
printRandomKeys = mapM_ printRandomKey

printRandomKey :: String -> IO ()
-- I know, partial functions suck, but it's only a tiny program.
printRandomKey "encryption" = BS.putStrLn =<< getRandomEncryptionKey
printRandomKey "validation" = BS.putStrLn =<< getRandomValidationKey

getRandomValidationKey :: IO ByteString
getRandomValidationKey = toLazyByteString . byteStringHex <$> rawKey
  where
    rawKey = getRandomBytes $ hashBlockSize (undefined :: SHA256)

getRandomEncryptionKey :: IO ByteString
getRandomEncryptionKey = toLazyByteString . byteStringHex <$> rawKey
  where
    rawKey = getRandomBytes $ blockSize (undefined :: AES256)
